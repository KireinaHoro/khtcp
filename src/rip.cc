#include "rip.h"
#include "core.h"
#include "ip.h"
#include "socket.h"
#include "udp.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <queue>

namespace khtcp {
namespace rip {
void send_fulltable(const uint8_t *src_, uint16_t src_port, const uint8_t *dst_,
                    uint16_t dst_port) {
  uint8_t *src, *dst;
  dst = (uint8_t *)malloc(sizeof(ip::addr_t));
  memcpy(dst, dst_, sizeof(ip::addr_t));
  if (src_) {
    src = (uint8_t *)malloc(sizeof(ip::addr_t));
    memcpy(src, src_, sizeof(ip::addr_t));
  } else {
    src = nullptr;
    core::record_multicast_buffer(dst);
  }
  auto &table = ip::get_routing_table();
  auto it = table.begin();
  auto rte_count = table.size();
  while (rte_count) {
    int rc;
    if (rte_count > 25) {
      rte_count -= 25;
      rc = 25;
    } else {
      rc = rte_count;
      rte_count = 0;
    }
    auto packet_len = sizeof(rip_header_t) + rc * sizeof(rte_t);
    auto packet_ptr = (uint8_t *)malloc(packet_len);

    if (!src) {
      core::record_multicast_buffer(packet_ptr);
    }
    auto hdr = (rip_header_t *)packet_ptr;
    auto rte_ptr = (rte_t *)(packet_ptr + sizeof(rip_header_t));
    hdr->command = response;
    hdr->version = version;

    for (int i = 0; i < rc; ++i, ++it) {
      rte_ptr[i].afi = boost::endian::endian_reverse((uint16_t)AF_INET);
      memcpy(rte_ptr[i].address, it->dst, sizeof(ip::addr_t));
      uint32_t mask = util::cidr_to_mask(it->prefix);
      memcpy(rte_ptr[i].mask, &mask, sizeof(ip::addr_t));
      uint32_t src_uint = *(uint32_t *)src;
      uint32_t router_uint = *(uint32_t *)it->router;
      if (src_port == rip::port && mask &&
          (src_uint & mask) == (router_uint & mask)) {
        // Split Horizon
        // If A thinks it can get to D via C, its messages to C should indicate
        // that D is unreachable.
        // mask nonzero to make sure default route not poisoned
        rte_ptr[i].metric = boost::endian::endian_reverse(rip::infinity);
        BOOST_LOG_TRIVIAL(trace)
            << "Poisoning route to " << util::ip_to_string(it->dst) << "/"
            << (int)it->prefix << " in RIP response sent on "
            << util::ip_to_string(src) << " due to Split Horizon";
      } else {
        rte_ptr[i].metric = boost::endian::endian_reverse(it->metric);
        BOOST_LOG_TRIVIAL(trace)
            << "Adding route to " << util::ip_to_string(it->dst) << "/"
            << (int)it->prefix << " to RIP response sent on "
            << util::ip_to_string(src);
      }
      // FIXME: nexthop is Advisory: not implemented here
      memset(rte_ptr[i].nexthop, 0, sizeof(ip::addr_t));
      // route tag is not used here
      rte_ptr[i].route_tag = 0;
    }

    udp::async_write_udp(
        src, src_port, dst, dst_port, packet_ptr, packet_len, [=](auto ret) {
          if (!ret) {
            BOOST_LOG_TRIVIAL(trace) << "Written full table RIP packet on "
                                     << util::ip_to_string(src);
          } else {
            BOOST_LOG_TRIVIAL(warning)
                << "Failed to write full table RIP packet on "
                << util::ip_to_string(src);
          }
          if (!src) {
            if (!--core::get().multicast_buffers.at(packet_ptr)) {
              core::get().multicast_buffers.erase(packet_ptr);
              free(packet_ptr);
            }
            if (!--core::get().multicast_buffers.at(dst)) {
              core::get().multicast_buffers.erase(dst);
              free(dst);
            }
          } else {
            free(src);
            free(dst);
            free(packet_ptr);
          }
        });
  }
}

bool rip_default_handler(const void *payload_ptr, uint16_t payload_len,
                         const ip::addr_t src, uint16_t src_port,
                         const ip::addr_t dst, uint16_t dst_port) {
  if (dst_port != rip::port) {
    BOOST_LOG_TRIVIAL(trace) << "Received UDP on non-RIP port " << dst_port;
    return false;
  }
  auto hdr = (rip_header_t *)payload_ptr;
  auto rte_len = payload_len - sizeof(rip_header_t);
  if (hdr->version != rip::version || rte_len % sizeof(rte_t) != 0) {
    BOOST_LOG_TRIVIAL(warning) << "Dropping unrecognized RIP packet";
    return false;
  }
  auto rte_count = rte_len / sizeof(rte_t);
  auto rte_ptr = (rte_t *)(((uint8_t *)payload_ptr) + sizeof(rip_header_t));
  switch (hdr->command) {
  case request:
    if (!rte_count) {
      // "If there are no entries, no response is given"
      BOOST_LOG_TRIVIAL(trace) << "Ignoring empty RIP request";
      return false;
    }
    const uint8_t *response_addr;
    uint16_t response_port;
    socket::socket(0, SOCK_DGRAM).get_src(src, &response_addr, &response_port);
    if (!memcmp(RIP_MULTICAST, dst, sizeof(ip::addr_t))) {
      // multicast
      response_port = rip::port;
    }
    if (rte_count == 1 && rte_ptr->afi == 0 &&
        boost::endian::endian_reverse(rte_ptr->metric) == 16) {
      // "...then this is a request to send the entire routing table"
      BOOST_LOG_TRIVIAL(trace)
          << "Sending full table to " << util::ip_to_string(src) << " from "
          << util::ip_to_string(response_addr);
      send_fulltable(response_addr, response_port, src, src_port);
      return false;
    }
    for (int i = 0; i < rte_count; ++i) {
      struct ip::route *r;
      if (ip::lookup_route(rte_ptr[i].address, &r)) {
        // a route is present
        rte_ptr[i].metric = boost::endian::endian_reverse(r->metric);
      } else {
        rte_ptr[i].metric = boost::endian::endian_reverse(rip::infinity);
      }
    }
    hdr->command = response;
    udp::async_write_udp(response_addr, response_port, src, src_port,
                         payload_ptr, payload_len, [](auto ret) {
                           if (!ret) {
                             BOOST_LOG_TRIVIAL(trace)
                                 << "Successfully written RIP response";
                           } else {
                             BOOST_LOG_TRIVIAL(warning)
                                 << "Failed to write RIP response, Errno: "
                                 << ret;
                           }
                         });
    return false;
    break;
  case response: {
    struct ip::route *r;
    BOOST_LOG_TRIVIAL(trace)
        << "Received RIP response from " << util::ip_to_string(src);
    // check directly connected
    if (!ip::lookup_route(src, &r) || r->has_router) {
      BOOST_LOG_TRIVIAL(warning) << "Received RIP response from invalid source "
                                 << util::ip_to_string(src);
      return false;
    }
    // check self
    for (const auto &dev : core::get().devices) {
      for (const auto &ip : dev->ip_addrs) {
        if (!memcmp(src, ip, sizeof(ip::addr_t))) {
          BOOST_LOG_TRIVIAL(trace) << "Ignoring RIP response from self address "
                                   << util::ip_to_string(ip);
          return false;
        }
      }
    }
    for (int i = 0; i < rte_count; ++i) {
      uint32_t metric = boost::endian::endian_reverse(rte_ptr[i].metric);
      if (metric > rip::infinity || metric < 1) {
        BOOST_LOG_TRIVIAL(trace)
            << "Ignoring RIP RTE with invalid metric " << metric;
        continue;
      }
      uint32_t zero = 0;
      if (metric < rip::infinity &&
          !memcmp(rte_ptr[i].address, &zero, sizeof(ip::addr_t)) &&
          *(uint32_t *)rte_ptr[i].mask != 0) {
        BOOST_LOG_TRIVIAL(trace)
            << "Ignoring RIP RTE with zero net destination and nonzero mask "
            << util::ip_to_string(rte_ptr[i].mask);
        continue;
      }
      metric = std::min(metric + cost, infinity);
      auto cidr = util::mask_to_cidr(*(uint32_t *)rte_ptr[i].mask);
      bool has_route = ip::lookup_route(rte_ptr[i].address, &r, cidr);
      if (!has_route) {
        BOOST_LOG_TRIVIAL(trace)
            << "Previous route for " << util::ip_to_string(rte_ptr[i].address)
            << "/" << cidr << " not found...";
        if (metric < infinity) {
          struct ip::route new_route;
          new_route.prefix = cidr;
          new_route.metric = metric;
          new_route.has_router = true;
          memcpy(new_route.dst, rte_ptr[i].address, sizeof(ip::addr_t));
          memcpy(new_route.router, src, sizeof(ip::addr_t));
          new_route.changed = true;

          BOOST_LOG_TRIVIAL(info)
              << "Adding route nexthop " << util::ip_to_string(src)
              << " metric " << metric << " for destination "
              << util::ip_to_string(rte_ptr[i].address) << "/" << cidr;
          ip::add_route(std::move(new_route));
          trigger_update();
        }
      } else {
        bool need_action = false;
        if (r->has_router && !memcmp(r->router, src, sizeof(ip::addr_t)) &&
            r->age >= 0) {
          r->age = 0; // as specified in RFC; however, this may cause delayed
                      // deletion of expired routes
          if (metric != r->metric) {
            need_action = true;
          }
        }
        if (metric < r->metric ||
            (metric == r->metric && r->age >= rip::max_age / 2)) {
          need_action = true;
        }
        if (need_action) {
          // adopt the route from the datagram
          BOOST_LOG_TRIVIAL(info)
              << "Adopting new nexthop " << util::ip_to_string(src)
              << ", metric " << metric << " for destination "
              << util::ip_to_string(r->dst) << "/" << (int)r->prefix;
          r->metric = metric;
          memcpy(r->router, src, sizeof(ip::addr_t));
          // trigger an update
          r->changed = true;
          trigger_update();
          // timeout update
          if (metric == infinity) {
            if (r->age < rip::max_age) {
              BOOST_LOG_TRIVIAL(trace)
                  << "Route to " << util::ip_to_string(r->dst)
                  << " started deletion countdown";
              r->age = rip::max_age;
            }
          } else {
            r->age = 0;
          }
        }
      }
    }
    return false;
    break;
  }
  default:
    BOOST_LOG_TRIVIAL(warning) << "Dropping unrecognized RIP packet";
    return false;
  }
}

void start() {
  // Send full table request on all interfaces
  // We assume that no two devices belong to the same Ethernet network
  request_fulltable();

  // start the default handler.  The handler will always return false so that
  // it will stay on the receive queue
  udp::async_read_udp(rip_default_handler);
}

void trigger_update() {
  static bool blocked = false;
  static bool pending = false;
  static boost::asio::deadline_timer t(core::get().io_context);
  // if timer still working, wait till timer expires
  if (blocked) {
    pending = true;
    return;
  }

  blocked = true;
  auto &table = ip::get_routing_table();
  for (int i = 0; i < core::get().devices.size(); ++i) {
    std::queue<decltype(table.begin())> updated_routes;
    auto &device = device::get_device_handle(i);
    for (auto it = table.begin(); it != table.end(); ++it) {
      // Split Horizon
      // If A thinks it can get to D via C, its messages to C should indicate
      // that D is unreachable.
      uint32_t src_uint = *(uint32_t *)device.ip_addrs[0];
      uint32_t router_uint = *(uint32_t *)it->router;
      uint32_t mask = util::cidr_to_mask(it->prefix);
      if (it->changed && ((src_uint & mask) != (router_uint & mask) || !mask)) {
        updated_routes.push(it);
        it->changed = false;
      }
    }

    auto rte_count = updated_routes.size();
    while (rte_count) {
      int rc;
      if (rte_count > 25) {
        rte_count -= 25;
        rc = 25;
      } else {
        rc = rte_count;
        rte_count = 0;
      }
      auto packet_len = sizeof(rip_header_t) + rc * sizeof(rte_t);
      auto packet_ptr = (uint8_t *)malloc(packet_len);
      auto hdr = (rip_header_t *)packet_ptr;
      auto rte_ptr = (rte_t *)(packet_ptr + sizeof(rip_header_t));
      hdr->command = response;
      hdr->version = version;

      for (int i = 0; i < rc; ++i) {
        auto &route = *updated_routes.front();
        rte_ptr[i].afi = boost::endian::endian_reverse((uint16_t)AF_INET);
        memcpy(rte_ptr[i].address, route.dst, sizeof(ip::addr_t));
        rte_ptr[i].metric = boost::endian::endian_reverse(route.metric);
        BOOST_LOG_TRIVIAL(trace)
            << "Adding route to " << util::ip_to_string(route.dst) << "/"
            << (int)route.prefix << " to RIP response during Triggered Updates";
        // FIXME: nexthop is Advisory: not implemented here
        memset(rte_ptr[i].nexthop, 0, sizeof(ip::addr_t));
        // route tag is not used here
        rte_ptr[i].route_tag = 0;
      }

      udp::async_write_udp(
          device.ip_addrs[0], rip::port, rip::RIP_MULTICAST, rip::port,
          packet_ptr, packet_len, [=](auto ret) {
            if (!ret) {
              BOOST_LOG_TRIVIAL(trace)
                  << "Written Triggered Updates RIP packet";
            } else {
              BOOST_LOG_TRIVIAL(warning)
                  << "Failed to Triggered Updates table RIP packet";
            }
            pending = false;
            free(packet_ptr);
          });
    }
  }

  // hold the process
  t.expires_from_now(boost::posix_time::seconds(rand() % 5 + 1));
  t.async_wait([](const auto &ec) {
    if (!ec) {
      blocked = false;
      if (pending) {
        trigger_update();
      }
    } else {
      BOOST_LOG_TRIVIAL(error)
          << "RIP Triggered Updates timer failed with message: "
          << ec.message();
    }
  });
}

void request_fulltable() {
  auto packet_len = sizeof(rip_header_t) + sizeof(rte_t);
  auto packet_ptr = (uint8_t *)malloc(packet_len);
  memset(packet_ptr, 0, packet_len);
  core::record_multicast_buffer(packet_ptr);
  auto hdr = (rip_header_t *)packet_ptr;
  auto rte_ptr = (rte_t *)(packet_ptr + sizeof(rip_header_t));

  hdr->command = request;
  hdr->version = version;

  rte_ptr->afi = 0;
  rte_ptr->metric = boost::endian::endian_reverse(16);

  udp::async_write_udp(nullptr, rip::port, RIP_MULTICAST, port, packet_ptr,
                       packet_len, [=](auto ret) {
                         if (ret) {
                           BOOST_LOG_TRIVIAL(warning)
                               << "Full table RIP request failed";
                         } else {
                           BOOST_LOG_TRIVIAL(trace)
                               << "Full table RIP request sent";
                         }
                         if (!--core::get().multicast_buffers.at(packet_ptr)) {
                           core::get().multicast_buffers.erase(packet_ptr);
                           free(packet_ptr);
                         }
                       });
}
} // namespace rip
} // namespace khtcp