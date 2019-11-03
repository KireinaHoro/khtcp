#include "udp.h"
#include "core.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <iomanip>
#include <iostream>

namespace khtcp {
namespace udp {

void async_read_udp(read_handler_t &&handler, int client_id) {
  ip::async_read_ip(
      proto,
      [=](const void *payload_ptr, uint64_t payload_len, const ip::addr_t src,
          const ip::addr_t dst, uint8_t dscp, const void *opt) -> bool {
        auto hdr = (udp_header_t *)payload_ptr;
        auto packet_payload = ((uint8_t *)payload_ptr) + sizeof(udp_header_t);

        // FIXME: we do not verify UDP checksum here.
        return handler(packet_payload,
                       boost::endian::endian_reverse(hdr->length) -
                           sizeof(udp_header_t),
                       src, boost::endian::endian_reverse(hdr->src_port), dst,
                       boost::endian::endian_reverse(hdr->dst_port));
      },
      client_id);
}

void async_write_udp(const ip::addr_t src, uint16_t src_port,
                     const ip::addr_t dst, uint16_t dst_port,
                     const void *payload_ptr, uint16_t payload_len,
                     write_handler_t &&handler, int client_id) {
  boost::asio::post(core::get().write_tasks_strand, [=]() {
    core::get().write_tasks.emplace_back(
        [=]() {
          BOOST_LOG_TRIVIAL(trace)
              << "Sending UDP packet with payload length " << payload_len << " "
              << (src ? util::ip_to_string(src) : "(multicast)") << ":"
              << src_port << " > " << util::ip_to_string(dst) << ":"
              << dst_port;
          auto packet_len = sizeof(udp_header_t) + payload_len;
          auto packet_ptr = new uint8_t[packet_len];

          if (!src) {
            core::record_multicast_buffer(packet_ptr);
          }
          auto hdr = (udp_header_t *)packet_ptr;
          auto packet_payload = ((uint8_t *)packet_ptr) + sizeof(udp_header_t);
          hdr->src_port = boost::endian::endian_reverse(src_port);
          hdr->dst_port = boost::endian::endian_reverse(dst_port);
          hdr->length = boost::endian::endian_reverse((uint16_t)packet_len);
          // FIXME: we do not calculate checksum here.

          memcpy(packet_payload, payload_ptr, payload_len);
          hdr->checksum = 0;
          ip::async_write_ip(
              src, dst, proto, 0, default_ttl, packet_ptr, packet_len,
              [=](int ret) {
                if (ret) {
                  BOOST_LOG_TRIVIAL(error)
                      << "Failed to write UDP packet: Errno " << ret;
                }
                handler(ret);
                if (!src && !--core::get().multicast_buffers.at(packet_ptr)) {
                  core::get().multicast_buffers.erase(packet_ptr);
                  delete[] packet_ptr;
                } else if (src) {
                  delete[] packet_ptr;
                }
              },
              client_id);
        },
        client_id);
  });
} // namespace udp
} // namespace udp
} // namespace khtcp