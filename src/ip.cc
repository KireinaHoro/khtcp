#include "ip.h"
#include "arp.h"
#include "core.h"
#include "device.h"
#include "util.h"

#include <boost/container/flat_set.hpp>
#include <boost/endian/conversion.hpp>
#include <iostream>

namespace khtcp {
namespace ip {
device::read_handler_t wrap_read_handler(int16_t proto,
                                         read_handler_t handler) {
  return [=](int dev_id, uint16_t ethertype, const uint8_t *packet_ptr,
             int packet_len) -> bool {
    if (ethertype != ip::ethertype) {
      return false;
    }
    auto hdr_ptr = (const ip_header_t *)packet_ptr;

    auto &device = device::get_device_handle(dev_id);
    BOOST_LOG_TRIVIAL(trace) << "Received IP packet on device " << device.name
                             << " with proto " << (int)hdr_ptr->proto;
    auto unicast = false;
    auto self_sent = false;
    for (const auto &ip : device.ip_addrs) {
      unicast = unicast || !memcmp(ip, hdr_ptr->dst_addr, sizeof(addr_t));
      self_sent = self_sent || !memcmp(ip, hdr_ptr->src_addr, sizeof(addr_t));
    }
    if (proto < 0 || hdr_ptr->proto == proto) {
      uint16_t hdr_len = hdr_ptr->ihl * sizeof(uint32_t);
      if (hdr_len != 20) {
        BOOST_LOG_TRIVIAL(warning)
            << "Dropping IP packet with unsupported header length " << hdr_len;
        return false;
      }
      auto option_ptr = ((const uint8_t *)packet_ptr) + sizeof(ip_header_t);
      auto payload_ptr = ((const uint8_t *)packet_ptr) + hdr_len;
      auto payload_len =
          boost::endian::endian_reverse(hdr_ptr->total_length) - hdr_len;
      if (unicast) {
        return handler(payload_ptr, payload_len, hdr_ptr->src_addr,
                       hdr_ptr->dst_addr, hdr_ptr->dscp, option_ptr);
      } else if (self_sent) {
        // ignore packets sent by self, keeping the handler intact
        return false;
      } else {
        // forward the packet, keeping the handler intact
        async_write_ip(hdr_ptr->src_addr, hdr_ptr->dst_addr, hdr_ptr->proto,
                       hdr_ptr->dscp, hdr_ptr->ttl, payload_ptr, payload_len,
                       [hdr_ptr](auto ret) {
                         if (!ret) {
                           BOOST_LOG_TRIVIAL(trace) << "IP packet forwarded.";
                         } else {
                           BOOST_LOG_TRIVIAL(error)
                               << "IP packet forwarding from "
                               << util::ip_to_string(hdr_ptr->src_addr)
                               << " to "
                               << util::ip_to_string(hdr_ptr->dst_addr)
                               << " failed: Errno " << ret;
                         }
                       });
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

void async_read_ip(int proto, read_handler_t &&handler) {
  boost::asio::post(core::get().read_handlers_strand, [=]() {
    core::get().read_handlers.push_back(wrap_read_handler(proto, handler));
    BOOST_LOG_TRIVIAL(trace) << "IP read handler queued";
  });
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

void async_write_ip(const addr_t src, const addr_t dst, uint8_t proto,
                    uint8_t dscp, uint8_t ttl, const void *payload_ptr,
                    uint64_t payload_len, write_handler_t &&handler,
                    uint16_t identification, bool df, const void *option) {
  BOOST_LOG_TRIVIAL(trace) << "Sending IP packet with payload length "
                           << payload_len;

  if (option) {
    BOOST_LOG_TRIVIAL(error) << "Requested to send non-null option IP packet";
    handler(-1);
    return;
  }

  const struct route *route;
  auto got_route = lookup_route(dst, &route);
  if (!got_route) {
    // failed to get route for destination
    BOOST_LOG_TRIVIAL(warning)
        << "No route to host " << util::ip_to_string(dst);
    handler(EHOSTUNREACH);
    return;
  }
  if (route->type != route::DEV && route->type != route::VIA) {
    BOOST_LOG_TRIVIAL(error) << "Unknown route type " << route->type;
    handler(EINVAL);
    return;
  }

  const uint8_t *resolv_mac_ip = dst;
  while (route->type != route::DEV) {
    // lookup gateway address in routing table
    resolv_mac_ip = route->nexthop.ip;
    got_route = lookup_route(resolv_mac_ip, &route);
    if (!got_route) {
      BOOST_LOG_TRIVIAL(warning)
          << "No route to host " << util::ip_to_string(resolv_mac_ip);
      handler(EHOSTUNREACH);
      return;
    }
  }
  // we have a DEV route now
  auto dev_id = route->nexthop.dev_id;

  auto packet_len = sizeof(ip_header_t) + payload_len;
  auto packet_ptr = new uint8_t[packet_len];
  auto hdr = (ip_header_t *)packet_ptr;
  auto packet_payload = ((uint8_t *)packet_ptr) + sizeof(ip_header_t);
  hdr->version = 4;
  hdr->ihl = 5;
  hdr->dscp = dscp;
  hdr->ecn = 0;
  hdr->total_length = boost::endian::endian_reverse((uint16_t)packet_len);
  hdr->identification = identification;
  hdr->flags = boost::endian::endian_reverse((uint16_t)(df << 14));
  hdr->ttl = ttl;
  hdr->proto = proto;
  memcpy(hdr->src_addr, src, sizeof(addr_t));
  memcpy(hdr->dst_addr, dst, sizeof(addr_t));

  hdr->header_csum = 0;
  hdr->header_csum = ip_checksum(hdr, sizeof(ip_header_t));

  memcpy(packet_payload, payload_ptr, payload_len);

  auto mac_handler = [packet_ptr, packet_len, dev_id, dst,
                      handler](int ret, const eth::addr_t addr) {
    if (ret) {
      BOOST_LOG_TRIVIAL(warning)
          << "Failed to resolve MAC for " << util::ip_to_string(dst)
          << ": Errno " << ret;
      handler(ret);
      delete[] packet_ptr;
    } else {
      eth::async_write_frame(
          packet_ptr, packet_len, ip::ethertype, addr, dev_id, [=](int ret) {
            if (ret) {
              BOOST_LOG_TRIVIAL(error)
                  << "Failed to write IP packet: Errno " << ret;
            }
            handler(ret);
            delete[] packet_ptr;
          });
    }
  };
  arp::async_resolve_mac(dev_id, resolv_mac_ip, mac_handler);
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

boost::container::flat_set<struct route> routing_table;

void add_route(struct route &&route) { routing_table.emplace(route); }

bool lookup_route(const addr_t dst, const struct route **out_route) {
  uint32_t addr = *(uint32_t *)dst;
  for (const auto &r : routing_table) {
    uint32_t route_dst = *(uint32_t *)r.dst;
    if (addr >> (32 - r.prefix) == route_dst >> (32 - r.prefix)) {
      *out_route = &r;
      return true;
    }
  }
  return false;
}

void print_route() {
  for (const auto &r : routing_table) {
    std::cout << util::ip_to_string(r.dst) << "/" << (int)r.prefix << " ";
    if (r.type == route::DEV) {
      std::cout << "dev " << device::get_device_handle(r.nexthop.dev_id).name;
    } else if (r.type == route::VIA) {
      std::cout << "via " << util::ip_to_string(r.nexthop.ip);
    }
    std::cout << " metric " << r.metric << std::endl;
  }
}
} // namespace ip
} // namespace khtcp