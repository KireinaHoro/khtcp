#include "packetio.h"
#include "device.h"
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
  auto device = device::get_device_handle(id);
  BOOST_LOG_TRIVIAL(trace) << "Constructing outgoing frame from "
                           << util::mac_to_string((const uint8_t *)destmac,
                                                  sizeof(eth::addr_t))
                           << " to "
                           << util::mac_to_string(device.addr,
                                                  sizeof(eth::addr_t))
                           << " with payload length " << len << ", EtherType "
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

void async_send_frame(const void *buf, int len, int ethtype,
                      const void *destmac, int id, write_handler_t &&handler) {
  auto p = construct_frame(buf, len, ethtype, destmac, id);
  auto frame_buf = p.first;
  auto frame_len = p.second;
  device::get_device_handle(id).async_inject_frame(frame_buf, frame_len,
                                                   [=](int ret) {
                                                     delete[] frame_buf;
                                                     handler(ret);
                                                   });
}

static frame_receive_callback _eth_callback;

int set_frame_receive_callback(frame_receive_callback callback) {
  _eth_callback = callback;
  return 0;
}

frame_receive_callback get_frame_receive_callback() { return _eth_callback; }

int print_eth_frame_callback(const void *frame, int len, int dev_id) {
  auto eth_hdr = (eth_header_t *)frame;
  std::cout << util::mac_to_string(eth_hdr->src, sizeof(eth::addr_t)) << " > "
            << util::mac_to_string(eth_hdr->dst, sizeof(eth::addr_t)) << " (on "
            << device::get_device_handle(dev_id).name << "), type 0x"
            << std::setfill('0') << std::setw(4) << std::hex
            << boost::endian::endian_reverse(eth_hdr->ethertype) << ", length "
            << std::dec << len << std::endl;

  return 0;
}

} // namespace eth
} // namespace khtcp