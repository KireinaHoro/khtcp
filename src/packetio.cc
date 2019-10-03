#include "packetio.h"
#include "device.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <iomanip>
#include <iostream>

namespace khtcp {
namespace eth {

static frame_receive_callback _eth_callback;

int set_frame_receive_callback(frame_receive_callback callback) {
  _eth_callback = callback;
  return 0;
}

frame_receive_callback get_frame_receive_callback() { return _eth_callback; }

int print_eth_frame_callback(const void *frame, int len, int dev_id) {
  auto eth_hdr = (eth_header_t *)frame;
  std::cout << util::mac_to_string(eth_hdr->src, 6) << " > "
            << util::mac_to_string(eth_hdr->dst, 6) << " (on "
            << device::get_device_handle(dev_id).name << "), type 0x"
            << std::setfill('0') << std::setw(4) << std::hex
            << boost::endian::endian_reverse(eth_hdr->ethertype) << ", length "
            << std::dec << len << std::endl;

  return 0;
}

} // namespace eth
} // namespace khtcp