#include "packetio.h"
#include "arp.h"
#include "core.h"
#include "device.h"
#include "ip.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <cstdlib>
#include <iomanip>
#include <iostream>

namespace khtcp {
namespace eth {

std::pair<uint8_t *, size_t> construct_frame(const void *buf, int len,
                                             int ethtype, const void *destmac,
                                             int id) {
  auto &device = device::get_device_handle(id);
  BOOST_LOG_TRIVIAL(trace) << "Constructing outgoing frame from "
                           << util::mac_to_string((const uint8_t *)destmac)
                           << " to " << util::mac_to_string(device.addr)
                           << " with payload length " << len << ", EtherType 0x"
                           << std::setw(4) << std::setfill('0') << std::hex
                           << ethtype << " on device " << device.name;

  auto frame_len = len + sizeof(eth_header_t) + 4;
  auto frame_buf = new uint8_t[frame_len];

  auto eth_hdr = (eth_header_t *)frame_buf;
  memcpy(eth_hdr->dst, destmac, sizeof(eth::addr_t));
  memcpy(eth_hdr->src, device.addr, sizeof(eth::addr_t));
  eth_hdr->ethertype = boost::endian::endian_reverse((uint16_t)ethtype);

  auto payload_ptr = frame_buf + sizeof(eth_header_t);
  memcpy(payload_ptr, buf, len);

  // TODO: calculate frame checksum
  // auto csum_ptr = payload_ptr + len;

  return {frame_buf, frame_len};
}

int send_frame(const void *buf, int len, int ethtype, const void *destmac,
               int id) {
  auto [frame_buf, frame_len] = construct_frame(buf, len, ethtype, destmac, id);
  auto ret = device::get_device_handle(id).inject_frame(frame_buf, frame_len);
  delete[] frame_buf;
  return ret;
}

void async_read_frame(int id, read_handler_t &&handler, int client_id) {
  boost::asio::post(core::get().read_handlers_strand, [=]() {
    core::get().read_handlers.emplace_back(
        [id, handler](int dev_id, uint16_t ethertype, const uint8_t *payload,
                      int len) -> bool {
          if (id != dev_id) {
            return false;
          } else {
            return handler(dev_id, ethertype, payload, len);
          }
        },
        client_id);
    BOOST_LOG_TRIVIAL(trace) << "Ethernet read handler queued for device "
                             << device::get_device_handle(id).name;
  });
}

void async_write_frame(const void *buf, int len, int ethtype,
                       const void *destmac, int id, write_handler_t &&handler,
                       int client_id) {
  boost::asio::post(core::get().write_tasks_strand, [=]() {
    core::get().write_tasks.emplace_back(
        [=]() {
          auto p = construct_frame(buf, len, ethtype, destmac, id);
          auto frame_buf = p.first;
          auto frame_len = p.second;

          device::get_device_handle(id).async_inject_frame(frame_buf, frame_len,
                                                           [=](int ret) {
                                                             handler(ret);
                                                             delete[] frame_buf;
                                                           });
        },
        client_id);
  });
}

int set_frame_receive_callback(frame_receive_callback callback) {
  core::get().eth_callback = callback;
  return 0;
}

frame_receive_callback get_frame_receive_callback() {
  return core::get().eth_callback;
}

int print_eth_frame_callback(const void *frame, int len, int dev_id) {
  auto eth_hdr = (eth_header_t *)frame;
  std::cout << util::mac_to_string(eth_hdr->src) << " > "
            << util::mac_to_string(eth_hdr->dst) << " (on "
            << device::get_device_handle(dev_id).name << "), type 0x"
            << std::setfill('0') << std::setw(4) << std::hex
            << boost::endian::endian_reverse(eth_hdr->ethertype) << ", length "
            << std::dec << len << std::endl;

  return 0;
}

std::vector<device::eth_holder> multicasts;

void join_multicast(const addr_t multicast) {
  BOOST_LOG_TRIVIAL(warning)
      << "Joining Ethernet multicast group " << util::mac_to_string(multicast);
  multicasts.emplace_back();
  memcpy(multicasts[multicasts.size() - 1].data, multicast, sizeof(addr_t));
}

int ethertype_broker_callback(const void *frame, int len, int dev_id) {
  auto eth_hdr = (eth_header_t *)frame;
  auto payload_ptr = (const uint8_t *)frame + sizeof(eth_header_t);
  auto payload_len = len - sizeof(eth_header_t) - 4; // checksum
  auto &device = device::get_device_handle(dev_id);
  auto ethertype = boost::endian::endian_reverse(eth_hdr->ethertype);
  bool pass_up = false;
  pass_up = !memcmp(eth_hdr->dst, device.addr, sizeof(addr_t)) ||
            !memcmp(eth_hdr->dst, ETH_BROADCAST, sizeof(addr_t));
  if (!pass_up) {
    for (const auto &m : multicasts) {
      pass_up = pass_up || !memcmp(eth_hdr->dst, m.data, sizeof(addr_t));
      if (pass_up) {
        break;
      }
    }
  }
  if (pass_up) {
    BOOST_LOG_TRIVIAL(trace) << "Received frame for device " << device.name;
    boost::asio::post(core::get().read_handlers_strand, [=]() {
      auto it = core::get().read_handlers.begin();
      while (it != core::get().read_handlers.end()) {
        if (it->first(dev_id, ethertype, payload_ptr, payload_len)) {
          // payload consumed
          core::get().read_handlers.erase(it);
          break;
        }
        ++it;
      }
    });
  }
  return 0;
}

} // namespace eth
} // namespace khtcp