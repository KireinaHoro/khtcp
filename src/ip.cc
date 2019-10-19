#include "ip.h"
#include "arp.h"
#include "core.h"
#include "device.h"
#include "rip.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <iomanip>
#include <iostream>
#include <list>

namespace khtcp {
namespace ip {

struct ip_holder {
  addr_t data;
};

std::vector<ip_holder> multicasts;

uint8_t *map_ip_multicast_to_eth(const addr_t ip) {

  auto eth_mult = (uint8_t *)malloc(sizeof(eth::addr_t));
  memset(eth_mult, 0, sizeof(eth::addr_t));
  eth_mult[0] = 0x01;
  (*(uint32_t *)&eth_mult[2]) = boost::endian::endian_reverse(
      0x5e000000 | (boost::endian::endian_reverse(*(uint32_t *)ip) & 0x7fffff));
  return eth_mult;
}

void join_multicast(const addr_t multicast) {
  BOOST_LOG_TRIVIAL(info) << "Joining IP multicast group "
                          << util::ip_to_string(multicast);
  multicasts.emplace_back();
  memcpy(multicasts[multicasts.size() - 1].data, multicast, sizeof(addr_t));

  auto eth_mult = map_ip_multicast_to_eth(multicast);
  eth::join_multicast(eth_mult);
  free(eth_mult);
}

uint16_t ip_checksum(const void *vdata, size_t length) {
  // Cast the data pointer to one that can be indexed.
  char *data = (char *)vdata;

  // Initialise the accumulator.
  uint64_t acc = 0xffff;

  // Handle any partial block at the start of the data.
  unsigned int offset = ((uintptr_t)data) & 3;
  if (offset) {
    size_t count = 4 - offset;
    if (count > length)
      count = length;
    uint32_t word = 0;
    memcpy(offset + (char *)&word, data, count);
    acc += ntohl(word);
    data += count;
    length -= count;
  }

  // Handle any complete 32-bit blocks.
  char *data_end = data + (length & ~3);
  while (data != data_end) {
    uint32_t word;
    memcpy(&word, data, 4);
    acc += ntohl(word);
    data += 4;
  }
  length &= 3;

  // Handle any partial block at the end of the data.
  if (length) {
    uint32_t word = 0;
    memcpy(&word, data, length);
    acc += ntohl(word);
  }

  // Handle deferred carries.
  acc = (acc & 0xffffffff) + (acc >> 32);
  while (acc >> 16) {
    acc = (acc & 0xffff) + (acc >> 16);
  }

  // If the data began at an odd byte address
  // then reverse the byte order to compensate.
  if (offset & 1) {
    acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
  }

  // Return the checksum in network byte order.
  return htons(~acc);
}

device::read_handler_t::first_type wrap_read_handler(int16_t proto,
                                                     read_handler_t handler) {
  return [=](int dev_id, uint16_t ethertype, const uint8_t *packet_ptr,
             int packet_len) -> bool {
    if (ethertype != ip::ethertype) {
      return false;
    }
    auto hdr_ptr = (ip_header_t *)packet_ptr;

    auto chksum = hdr_ptr->header_csum;
    hdr_ptr->header_csum = 0;
    hdr_ptr->header_csum = ip_checksum(hdr_ptr, sizeof(ip_header_t));

    if (hdr_ptr->header_csum != chksum) {
      BOOST_LOG_TRIVIAL(warning)
          << "Dropping IP packet with incorrect header checksum: expected 0x"
          << std::hex << std::setw(4) << std::setfill('0')
          << hdr_ptr->header_csum << ", got 0x" << std::hex << std::setw(4)
          << std::setfill('0') << chksum;
      return false;
    }

    BOOST_LOG_TRIVIAL(trace) << "Received IP packet on device "
                             << device::get_device_handle(dev_id).name
                             << " with proto " << (int)hdr_ptr->proto;
    auto unicast = false;
    auto multicast = false;
    auto self_sent = false;
    for (const auto &dev : core::get().devices) {
      for (const auto &ip : dev->ip_addrs) {
        BOOST_LOG_TRIVIAL(trace)
            << "Checking local address " << util::ip_to_string(ip);
        unicast = unicast || !memcmp(ip, hdr_ptr->dst_addr, sizeof(addr_t));
        self_sent = self_sent || !memcmp(ip, hdr_ptr->src_addr, sizeof(addr_t));
      }
    }
    for (const auto &m : multicasts) {
      multicast =
          multicast || !memcmp(hdr_ptr->dst_addr, m.data, sizeof(addr_t));
      if (multicast) {
        BOOST_LOG_TRIVIAL(trace) << "Received packet to multicast group "
                                 << util::ip_to_string(m.data);
        break;
      }
    }
    if (proto < 0 || hdr_ptr->proto == proto) {
      uint16_t hdr_len = hdr_ptr->ihl * sizeof(uint32_t);
      if (hdr_len != 20) {
        BOOST_LOG_TRIVIAL(warning)
            << "Ignoring IP packet options; total header length: " << hdr_len;
      }
      auto option_ptr = ((const uint8_t *)packet_ptr) + sizeof(ip_header_t);
      auto payload_ptr = ((const uint8_t *)packet_ptr) + hdr_len;
      auto payload_len =
          boost::endian::endian_reverse(hdr_ptr->total_length) - hdr_len;
      if (unicast || multicast) {
        return handler(payload_ptr, payload_len, hdr_ptr->src_addr,
                       hdr_ptr->dst_addr, hdr_ptr->dscp, option_ptr);
      } else if (self_sent) {
        // ignore packets sent by self, keeping the handler intact
        return false;
      } else {
        if (hdr_ptr->ttl == 0) {
          // TODO: send ICMP Time Exceeded Message back to src
        } else {
          // forward the packet, keeping the handler intact
          async_write_ip(hdr_ptr->src_addr, hdr_ptr->dst_addr, hdr_ptr->proto,
                         hdr_ptr->dscp, hdr_ptr->ttl - 1, payload_ptr,
                         payload_len, [hdr_ptr](auto ret) {
                           if (!ret) {
                             BOOST_LOG_TRIVIAL(trace) << "IP packet forwarded.";
                           } else if (ret == ECANCELED) {
                             // non-local broadcast
                             BOOST_LOG_TRIVIAL(debug)
                                 << "Not forwarding non-local broadcast.";
                           } else {
                             BOOST_LOG_TRIVIAL(error)
                                 << "IP packet forwarding from "
                                 << util::ip_to_string(hdr_ptr->src_addr)
                                 << " to "
                                 << util::ip_to_string(hdr_ptr->dst_addr)
                                 << " failed: Errno " << ret;
                           }
                         });
        }
        return false;
      }
    } else {
      return false;
    }
  };
}

// Used to print debug information for all packets.
bool default_handler(const void *payload_ptr, uint64_t payload_len,
                     const addr_t src, const addr_t dst, uint8_t dscp,
                     const void *opt) {
  auto ret = false;
  BOOST_LOG_TRIVIAL(trace) << "IP packet from " << util::ip_to_string(src)
                           << " to " << util::ip_to_string(dst)
                           << " with payload length " << payload_len;
  if (ret) {
    async_read_ip(-1, default_handler);
  }
  return ret;
}

void start() { async_read_ip(-1, default_handler); }

void async_read_ip(int proto, read_handler_t &&handler, int client_id) {
  boost::asio::post(core::get().read_handlers_strand, [=]() {
    core::get().read_handlers.emplace_back(wrap_read_handler(proto, handler),
                                           client_id);
    BOOST_LOG_TRIVIAL(trace) << "IP read handler queued";
  });
}

void test_multicast_broadcast(const ip::addr_t dst, route **r,
                              bool *is_multicast, bool *is_broadcast) {
  // reset the input value
  *is_multicast = false;
  *is_broadcast = false;

  route *r_;
  route **route = r ? r : &r_;
  bool has_route = lookup_route(dst, route);
  if (!has_route) {
    *r = nullptr;
  }
  if (has_route && !(*route)->has_router) {
    // check if is broadcast address
    uint32_t iform = boost::endian::endian_reverse(*(uint32_t *)dst);
    uint32_t subnet_mask = (*route)->prefix == 0
                               ? 0
                               : *(uint32_t *)IP_BROADCAST
                                     << (32 - (*route)->prefix);
    *is_broadcast = (iform | subnet_mask) == 0xffffffff;
  } else {
    *is_broadcast = false;
  }
  if (!*is_broadcast) {
    for (const auto &m : multicasts) {
      *is_multicast = *is_multicast || !memcmp(dst, m.data, sizeof(addr_t));
      if (*is_multicast) {
        break;
      }
    }
  }
}

void async_write_ip(const addr_t src, const addr_t dst, uint8_t proto,
                    uint8_t dscp, uint8_t ttl, const void *payload_ptr,
                    uint64_t payload_len, write_handler_t &&handler,
                    int client_id, uint16_t identification, bool df,
                    const void *option) {
  boost::asio::post(core::get().write_tasks_strand, [=]() {
    core::get().write_tasks.emplace_back(
        [=]() mutable {
          bool is_local = false;
          if (!src) {
            is_local = true;
          } else {
            for (const auto &dev : core::get().devices) {
              for (const auto &ip : dev->ip_addrs) {
                BOOST_LOG_TRIVIAL(trace)
                    << "Checking local address " << util::ip_to_string(ip);
                if (!memcmp(ip, src, sizeof(addr_t))) {
                  is_local = true;
                }
              }
            }
          }
          if (client_id != 0) {
            // enforce src to be local IP if request from client
            if (!is_local) {
              BOOST_LOG_TRIVIAL(error)
                  << "Client " << client_id << " tried to send from "
                  << util::ip_to_string(src)
                  << ", which is not a local address";
              handler(EINVAL);
              return;
            }
          }

          BOOST_LOG_TRIVIAL(trace)
              << "Sending IP packet with payload length " << payload_len;

          if (option) {
            BOOST_LOG_TRIVIAL(error)
                << "Requested to send non-null option IP packet";
            handler(EINVAL);
            return;
          }

          struct route *route;

          bool is_broadcast, is_multicast;
          test_multicast_broadcast(dst, &route, &is_multicast, &is_broadcast);

          const uint8_t *resolv_mac_ip;
          int dev_id;
          if (!is_broadcast && !is_multicast) {
            if (!route || route->metric >= rip::infinity) {
              // failed to get route for destination
              BOOST_LOG_TRIVIAL(warning)
                  << "No route to host " << util::ip_to_string(dst);
              // TODO: send ICMP Destination Unreachable Message
              // back to src
              handler(EHOSTUNREACH);
              return;
            }
            resolv_mac_ip = route->has_router ? route->router : dst;
            dev_id = route->dev_id;
          }

          auto packet_len = sizeof(ip_header_t) + payload_len;
          auto packet_ptr = (uint8_t *)malloc(packet_len);
          if (is_broadcast || is_multicast) {
            core::record_multicast_buffer(packet_ptr);
            ttl = 1;
          }
          auto hdr = (ip_header_t *)packet_ptr;
          auto packet_payload = ((uint8_t *)packet_ptr) + sizeof(ip_header_t);
          hdr->version = 4;
          hdr->ihl = 5;
          hdr->dscp = dscp;
          hdr->ecn = 0;
          hdr->total_length =
              boost::endian::endian_reverse((uint16_t)packet_len);
          hdr->identification = identification;
          hdr->flags = boost::endian::endian_reverse((uint16_t)(df << 14));
          hdr->ttl = ttl;
          hdr->proto = proto;

          if (src) {
            memcpy(hdr->src_addr, src, sizeof(addr_t));
          }
          memcpy(hdr->dst_addr, dst, sizeof(addr_t));

          hdr->header_csum = 0;
          hdr->header_csum = ip_checksum(hdr, sizeof(ip_header_t));

          memcpy(packet_payload, payload_ptr, payload_len);

          auto send_broadcast = [=](auto buf, auto dev_id) {
            if (is_broadcast) {
              eth::async_write_frame(
                  buf, packet_len, ip::ethertype, eth::ETH_BROADCAST, dev_id,
                  [=](int ret) {
                    if (ret) {
                      BOOST_LOG_TRIVIAL(error)
                          << "Failed to write IP packet: Errno " << ret;
                    }
                    handler(ret);
                    free(buf);
                  });
            } else {
              auto multi_dst = map_ip_multicast_to_eth(dst);
              eth::async_write_frame(
                  buf, packet_len, ip::ethertype, multi_dst, dev_id,
                  [=](int ret) {
                    if (ret) {
                      BOOST_LOG_TRIVIAL(error)
                          << "Failed to write IP packet: Errno " << ret;
                    }
                    handler(ret);
                    free(buf);
                    free(multi_dst);
                  });
            }
          };

          if (is_broadcast || is_multicast) {
            if (is_local) {
              if (!src) {
                for (int i = 0; i < core::get().devices.size(); ++i) {
                  uint8_t *dev_buf_ptr = (uint8_t *)malloc(packet_len);
                  memcpy(dev_buf_ptr, packet_ptr, packet_len);

                  auto hdr = (ip_header_t *)dev_buf_ptr;
                  memcpy(hdr->src_addr,
                         device::get_device_handle(i).ip_addrs[0],
                         sizeof(addr_t));
                  BOOST_LOG_TRIVIAL(trace)
                      << "Setting broadcast/multicast src to "
                      << util::ip_to_string(hdr->src_addr) << " for device"
                      << device::get_device_handle(i).name;
                  hdr->header_csum = 0;
                  hdr->header_csum = ip_checksum(hdr, sizeof(ip_header_t));
                  send_broadcast(dev_buf_ptr, i);
                }
                free(packet_ptr);
              } else {
                int dev_id;
                for (int i = 0; i < core::get().devices.size(); ++i) {
                  for (const auto &ip : device::get_device_handle(i).ip_addrs) {
                    if (!memcmp(src, ip, sizeof(ip::addr_t))) {
                      dev_id = i;
                    }
                  }
                }
                send_broadcast(packet_ptr, dev_id);
              }
            } else {
              BOOST_LOG_TRIVIAL(trace)
                  << "Non-local IP "
                  << (is_multicast ? "multicast" : "broadcast") << " to "
                  << util::ip_to_string(dst) << " not repeated";
              handler(ECANCELED);
              free(packet_ptr);
            }
          } else {
            auto mac_handler = [packet_ptr, packet_len, dev_id, resolv_mac_ip,
                                handler](int ret, const eth::addr_t addr) {
              if (ret) {
                BOOST_LOG_TRIVIAL(warning)
                    << "Failed to resolve MAC for "
                    << util::ip_to_string(resolv_mac_ip) << ": Errno " << ret;
                handler(ret);
                free(packet_ptr);
              } else {
                eth::async_write_frame(
                    packet_ptr, packet_len, ip::ethertype, addr, dev_id,
                    [=](int ret) {
                      if (ret) {
                        BOOST_LOG_TRIVIAL(error)
                            << "Failed to write IP packet: Errno " << ret;
                      }
                      handler(ret);
                      free(packet_ptr);
                    });
              }
            };
            arp::async_resolve_mac(dev_id, resolv_mac_ip, mac_handler);
          }
        },
        client_id);
  });
}

bool route::operator<(const struct route &a) const {
  if (prefix > a.prefix) {
    return true;
  } else if (prefix == a.prefix) {
    if (metric < a.metric) {
      return true;
    } else if (metric == a.metric) {
      return memcmp(dst, a.dst, sizeof(addr_t));
    } else {
      return false;
    }
  } else {
    return false;
  }
}

std::list<struct route> routing_table;

std::list<struct route> &get_routing_table() { return routing_table; }

bool add_route(struct route &&route) {
  if (route.has_router) {
    struct route *router_route;
    if (!lookup_route(route.router, &router_route)) {
      BOOST_LOG_TRIVIAL(error) << "Tried to add route with invalid router "
                               << util::ip_to_string(route.router);
      return false;
    }
    if (route.dev_id < 0) {
      // fill in device
      route.dev_id = router_route->dev_id;
    }
  }
  if (route.dev_id < 0) {
    BOOST_LOG_TRIVIAL(error)
        << "Tried to add route with invalid out device id " << route.dev_id;
    return false;
  }
  route.changed = true;
  routing_table.emplace_back(route);
  routing_table.sort();
  return true;
}

bool lookup_route(const addr_t dst, struct route **out_route, int prefix) {
  BOOST_LOG_TRIVIAL(trace) << "Looking up route " << util::ip_to_string(dst)
                           << "/" << prefix;
  uint32_t addr = boost::endian::endian_reverse(*(uint32_t *)dst);
  for (auto &r : routing_table) {
    BOOST_LOG_TRIVIAL(trace) << "Trying " << util::ip_to_string(r.dst);
    uint32_t route_dst = boost::endian::endian_reverse(*(uint32_t *)r.dst);
    if (!r.prefix || addr >> (32 - r.prefix) == route_dst >> (32 - r.prefix)) {
      if (prefix == -1 || r.prefix == prefix) {
        *out_route = &r;
        return true;
      }
    }
  }
  return false;
}

bool delete_route(const struct route *route) {
  auto it = routing_table.begin();
  while (it != routing_table.end()) {
    if (!memcmp(route->dst, it->dst, sizeof(ip::addr_t)) &&
        route->prefix == it->prefix) {
      BOOST_LOG_TRIVIAL(info) << "Route to " << util::ip_to_string(route->dst)
                              << "/" << (int)route->prefix << " deleted.";
      routing_table.erase(it++);
      return true;
    } else {
      ++it;
    }
  }
  return false;
}

void update_route() {
  BOOST_LOG_TRIVIAL(trace) << "Aging routes";
  for (auto ri = routing_table.begin(); ri != routing_table.end();) {
    if (ri->age < 0) {
      // manual route, don't age
      ++ri;
      continue;
    }
    ++ri->age;
    if (ri->age == rip::max_age) {
      // start deletion process
      BOOST_LOG_TRIVIAL(trace) << "Route to " << util::ip_to_string(ri->dst)
                               << " started deletion countdown";
      ri->metric = rip::infinity;
      ri->changed = true;
      rip::trigger_update();
    } else if (ri->age > rip::max_age + rip::deletion_timeout) {
      // the deletion timer has also expired
      BOOST_LOG_TRIVIAL(info) << "Route to " << util::ip_to_string(ri->dst)
                              << " deleted due to timeout.";
      routing_table.erase(ri++);
      continue;
    }
    ++ri;
  }
  routing_table.sort();
}

void print_route() {
  std::cout << "\nGlobal Routing Table\n====================\n";
  for (const auto &r : routing_table) {
    std::cout << util::ip_to_string(r.dst) << "/" << (int)r.prefix << " ";
    if (r.has_router) {
      std::cout << "via " << util::ip_to_string(r.router) << " ";
    }
    std::cout << "dev " << device::get_device_handle(r.dev_id).name
              << " metric " << r.metric;
    if (r.age != -1) {
      std::cout << " age " << r.age;
    }
    std::cout << std::endl;
  }
}
} // namespace ip
} // namespace khtcp