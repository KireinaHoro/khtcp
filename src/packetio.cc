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
  auto dmac = core::make_shared<eth::addr>();
  memcpy(dmac->data, destmac, sizeof(eth::addr));
  auto &device = device::get_device_handle(id);
  BOOST_LOG_TRIVIAL(trace) << "Constructing outgoing frame from "
                           << util::mac_to_string(*dmac) << " to "
                           << util::mac_to_string(*device.addr)
                           << " with payload length " << len << ", EtherType 0x"
                           << std::setw(4) << std::setfill('0') << std::hex
                           << ethtype << " on device " << device.name;

  auto frame_len = len + sizeof(eth_header_t) + 4;
  auto frame_buf = core::get_allocator<uint8_t>().allocate(frame_len);

  auto eth_hdr = (eth_header_t *)frame_buf;
  memcpy(&eth_hdr->dst, destmac, sizeof(eth::addr));
  memcpy(&eth_hdr->src, device.addr->data, sizeof(eth::addr));
  eth_hdr->ethertype = boost::endian::endian_reverse((uint16_t)ethtype);

  auto payload_ptr = frame_buf + sizeof(eth_header_t);
  memcpy(payload_ptr, buf, len);

  // TODO: calculate frame checksum
  // auto csum_ptr = payload_ptr + len;

  return {frame_buf, frame_len};
}

int send_frame(const void *buf, int len, int ethtype, const eth::addr *destmac,
               int id) {
  auto [frame_buf, frame_len] = construct_frame(buf, len, ethtype, destmac, id);
  auto ret = device::get_device_handle(id).inject_frame(frame_buf, frame_len);
  core::get_allocator<uint8_t>().deallocate(frame_buf, frame_len);
  return ret;
}

void async_send_frame(const void *buf, int len, int ethtype,
                      const eth::addr *destmac, int id,
                      write_handler_t &&handler) {
  auto p = construct_frame(buf, len, ethtype, destmac, id);
  auto frame_buf = p.first;
  auto frame_len = p.second;
  device::get_device_handle(id).async_inject_frame(
      frame_buf, frame_len, [=](int ret) {
        core::get_allocator<uint8_t>().deallocate(frame_buf, frame_len);
        handler(ret);
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

int ethertype_broker_callback(const void *frame, int len, int dev_id) {
  auto eth_hdr = (eth_header_t *)frame;
  auto payload_ptr = (const uint8_t *)frame + sizeof(eth_header_t);
  auto payload_len = len - sizeof(eth_header_t) - 4; // checksum
  auto &device = device::get_device_handle(dev_id);
  auto ethertype = boost::endian::endian_reverse(eth_hdr->ethertype);
  if (!memcmp(&eth_hdr->dst, device.addr.get(), sizeof(eth::addr)) ||
      !memcmp(&eth_hdr->dst, ETH_BROADCAST, sizeof(eth::addr))) {
    BOOST_LOG_TRIVIAL(trace) << "Received frame for device " << device.name;
    boost::asio::post(
        device::get_device_handle(dev_id).read_handlers_strand, [=]() {
          auto &device = device::get_device_handle(dev_id);
          auto it = device.read_handlers.begin();
          while (it != device.read_handlers.end()) {
            if ((*it)(dev_id, ethertype, payload_ptr, payload_len)) {
              // payload consumed
              device.read_handlers.erase(it);
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