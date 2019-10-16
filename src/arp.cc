#include "arp.h"
#include "core.h"
#include "device.h"
#include "util.h"

#include <boost/endian/conversion.hpp>

namespace khtcp {
namespace arp {

struct eth_holder {
  eth::addr_t data;
};
// IP -> <MAC, timeout>
std::map<uint32_t, std::pair<eth_holder, int>> neighbor_map;

device::read_handler_t::first_type wrap_read_handler(int dev_id_,
                                                     read_handler_t handler) {
  return [=](int dev_id, uint16_t ethertype, const uint8_t *packet_ptr,
             int packet_len) -> bool {
    if (dev_id_ != dev_id || ethertype != arp::ethertype) {
      return false;
    }
    auto hdr = (arp_header_t *)packet_ptr;
    auto &name = device::get_device_handle(dev_id).name;
    BOOST_LOG_TRIVIAL(trace) << "Received ARP packet on device " << name;
    auto opcode = boost::endian::endian_reverse(hdr->opcode);
    auto hw_type = boost::endian::endian_reverse(hdr->hardware_type);
    auto proto_type = boost::endian::endian_reverse(hdr->protocol_type);
    if (hw_type != 0x1) { // Ethernet
      BOOST_LOG_TRIVIAL(warning) << "Unsupported ARP hardware type " << hw_type
                                 << " on device " << name;
      return false;
    }
    if (proto_type != 0x0800) { // IPv4
      BOOST_LOG_TRIVIAL(warning) << "Unsupported ARP protocol type "
                                 << proto_type << " on device " << name;
      return false;
    }
    if (hdr->hardware_size != sizeof(eth::addr_t)) {
      BOOST_LOG_TRIVIAL(warning) << "ARP hardware size mismatch";
      return false;
    }
    if (hdr->protocol_size != sizeof(ip::addr_t)) {
      BOOST_LOG_TRIVIAL(warning) << "ARP protocol size mismatch";
      return false;
    }
    auto sender_mac = (uint8_t *)packet_ptr + sizeof(arp_header_t);
    auto sender_ip = sender_mac + sizeof(eth::addr_t);
    auto target_mac = sender_ip + sizeof(ip::addr_t);
    auto target_ip = target_mac + sizeof(eth::addr_t);

    // record mapping in global ARP table
    BOOST_LOG_TRIVIAL(trace)
        << "Recording neighbor " << util::ip_to_string(sender_ip)
        << " with MAC " << util::mac_to_string(sender_mac) << " and timeout "
        << NEIGHBOR_TIMEOUT;
    memcpy(&neighbor_map[*((uint32_t *)sender_ip)].first.data, sender_mac,
           sizeof(eth::addr_t));
    neighbor_map[*((uint32_t *)sender_ip)].second = NEIGHBOR_TIMEOUT;

    return handler(dev_id, opcode, sender_mac, sender_ip, target_mac,
                   target_ip);
  };
}

// reply ARP on receiving request
bool default_handler(int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                     ip::addr_t sender_ip, eth::addr_t target_mac,
                     ip::addr_t target_ip) {
  bool ret = false;
  auto &device = device::get_device_handle(dev_id);
  if (opcode == 0x1) { // request
    for (const auto &ip : device.ip_addrs) {
      if (!memcmp(ip, target_ip, sizeof(ip::addr_t))) {
        async_write_arp(dev_id, 0x2, device.addr, ip, sender_mac, sender_ip,
                        [](int dev_id, int ret) {
                          if (ret != PCAP_ERROR) {
                            BOOST_LOG_TRIVIAL(trace)
                                << "Sent ARP reply on device "
                                << device::get_device_handle(dev_id).name;
                          }
                        });
        ret = true;
      }
    }
  }
  if (ret) {
    async_read_arp(dev_id, default_handler);
  }
  return ret;
}

// runs per second.  decreases entry's ttl and purges aging ones.
void scan_arp_table() {
  int counter = 0;
  auto it = neighbor_map.begin();
  while (it != neighbor_map.end()) {
    if (it->second.second == 0) {
      neighbor_map.erase(it++);
      ++counter;
    } else {
      --(it++)->second.second;
    }
  }
  BOOST_LOG_TRIVIAL(trace) << "Purged " << counter
                           << " entries during ARP table cleanup";

  // fire a new round
  auto &timer = core::get().arp_table_timer;
  timer.expires_from_now(boost::posix_time::seconds(1));
  timer.async_wait([&](auto ec) { scan_arp_table(); });
}

void start(int dev_id) { async_read_arp(dev_id, default_handler); }

void async_read_arp(int dev_id, read_handler_t &&handler, int client_id) {
  boost::asio::post(core::get().read_handlers_strand, [=]() {
    core::get().read_handlers.emplace_back(wrap_read_handler(dev_id, handler),
                                           client_id);
    BOOST_LOG_TRIVIAL(trace) << "ARP read handler queued for device "
                             << device::get_device_handle(dev_id).name;
  });
}

void async_write_arp(int dev_id, uint16_t opcode, const eth::addr_t sender_mac,
                     const ip::addr_t sender_ip, const eth::addr_t target_mac,
                     const ip::addr_t target_ip, write_handler_t &&handler,
                     int client_id) {
  boost::asio::post(core::get().write_tasks_strand, [=]() {
    core::get().write_tasks.emplace_back(
        [=]() {
          auto packet_len = sizeof(arp_header_t) + 2 * sizeof(eth::addr_t) +
                            2 * sizeof(ip::addr_t);
          auto packet_buf = new uint8_t[packet_len];
          auto hdr = (arp_header_t *)packet_buf;
          hdr->hardware_type = boost::endian::endian_reverse((uint16_t)0x1);
          hdr->protocol_type = boost::endian::endian_reverse((uint16_t)0x0800);
          hdr->opcode = boost::endian::endian_reverse(opcode);
          hdr->hardware_size = sizeof(eth::addr_t);
          hdr->protocol_size = sizeof(ip::addr_t);

          auto smac = packet_buf + sizeof(arp_header_t);
          auto sip = smac + sizeof(eth::addr_t);
          auto tmac = sip + sizeof(ip::addr_t);
          auto tip = tmac + sizeof(eth::addr_t);

          memcpy(tmac, target_mac, sizeof(eth::addr_t));
          memcpy(smac, sender_mac, sizeof(eth::addr_t));
          memcpy(tip, target_ip, sizeof(ip::addr_t));
          memcpy(sip, sender_ip, sizeof(ip::addr_t));

          BOOST_LOG_TRIVIAL(trace) << "Sending ARP packet on device "
                                   << device::get_device_handle(dev_id).name;

          eth::async_write_frame(packet_buf, packet_len, arp::ethertype, tmac,
                                 dev_id, [=](int ret) {
                                   handler(dev_id, ret);
                                   delete[] packet_buf;
                                 });
        },
        client_id);
  });
}

void async_resolve_mac(int dev_id, const ip::addr_t dst,
                       resolve_mac_handler_t &&handler) {
  BOOST_LOG_TRIVIAL(trace) << "Resolving MAC for " << util::ip_to_string(dst);
  auto t = new boost::asio::deadline_timer(core::get().io_context);
  static std::function<void(int, int, resolve_mac_handler_t,
                            boost::asio::deadline_timer *, const uint8_t *)>
      check_mac = [](int n, int dev_id, auto handler, auto t, auto dst) {
        if (neighbor_map.find(*(uint32_t *)dst) == neighbor_map.end()) {
          // send ARP query.
          auto &device = device::get_device_handle(dev_id);
          BOOST_LOG_TRIVIAL(trace)
              << "Sending ARP query for " << util::ip_to_string(dst);
          async_write_arp(
              dev_id, 0x1, device.addr, device.ip_addrs[0], eth::ETH_BROADCAST,
              dst, [=](int dev_id, int ret) {
                if (ret != PCAP_ERROR) {
                  if (n < 50) {
                    t->expires_from_now(boost::posix_time::milliseconds(20));
                    t->async_wait([=](auto ec) {
                      if (!ec) {
                        check_mac(n + 1, dev_id, handler, t, dst);
                      } else {
                        BOOST_LOG_TRIVIAL(warning)
                            << "Resolve MAC timer failed: " << ec.message();
                        delete t;
                      }
                    });
                  } else {
                    handler(EHOSTUNREACH, nullptr);
                    delete t;
                  }
                } else {
                  BOOST_LOG_TRIVIAL(error) << "Failed to do ARP resolution";
                }
              });
        } else {
          BOOST_LOG_TRIVIAL(trace)
              << "ARP table hit for IP " << util::ip_to_string(dst);
          handler(0, neighbor_map[*(uint32_t *)dst].first.data);
          delete t;
        }
      };
  check_mac(0, dev_id, handler, t, dst);
}

} // namespace arp
} // namespace khtcp