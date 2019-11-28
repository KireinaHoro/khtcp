#include "tcp.h"
#include "core.h"
#include "util.h"

#include <boost/endian/conversion.hpp>

namespace khtcp {
namespace tcp {
void async_send_segment(const ip::addr_t src, uint16_t src_port,
                        const ip::addr_t dst, uint16_t dst_port,
                        uint32_t seq_num, uint32_t ack_num, bool ack, bool psh,
                        bool rst, bool syn, bool fin, uint16_t window,
                        const void *segment_ptr, uint16_t segment_len,
                        send_segment_handler_t &&handler) {
  boost::asio::post(core::get().write_tasks_strand, [=]() {
    core::get().write_tasks.emplace_back(
        [=]() {
          BOOST_LOG_TRIVIAL(warning)
              << "Sending TCP segment with segment length " << segment_len
              << " " << util::ip_to_string(src) << ":" << src_port << " > "
              << util::ip_to_string(dst) << ":" << dst_port
              << ", SEQ=" << seq_num << " ACK=" << ack_num << " ["
              << (ack ? 'A' : '.') << (psh ? 'P' : '.') << (rst ? 'R' : '.')
              << (syn ? 'S' : '.') << (fin ? 'F' : '.') << "]";

          uint16_t packet_len = sizeof(tcp_header_t) + segment_len;
          auto packet_len_bigendian = boost::endian::endian_reverse(packet_len);
          auto packet_csum_len = packet_len + 12; // pseudo-header
          auto phdr = new uint8_t[packet_csum_len];
          auto pseudo_header = phdr;
          auto hdr = (tcp_header_t *)((uint8_t *)phdr + 12);
          auto packet_payload = ((uint8_t *)hdr) + sizeof(tcp_header_t);
          hdr->src_port = boost::endian::endian_reverse(src_port);
          hdr->dst_port = boost::endian::endian_reverse(dst_port);
          hdr->seq = boost::endian::endian_reverse(seq_num);
          hdr->ack = boost::endian::endian_reverse(ack_num);
          // we don't support any TCP option here
          hdr->data_offset = 5 << 4;
          hdr->flags = fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4);
          hdr->window = boost::endian::endian_reverse(window);
          // wait for checksum calculation
          hdr->checksum = 0;
          hdr->urgent_pointer = 0;

          memcpy(packet_payload, segment_ptr, segment_len);
          memcpy(pseudo_header, src, sizeof(ip::addr_t));
          pseudo_header += sizeof(ip::addr_t);
          memcpy(pseudo_header, dst, sizeof(ip::addr_t));
          pseudo_header += sizeof(ip::addr_t);
          memset(pseudo_header, 0, sizeof(uint8_t));
          pseudo_header += sizeof(uint8_t);
          memcpy(pseudo_header, &proto, sizeof(proto));
          pseudo_header += sizeof(proto);
          memcpy(pseudo_header, &packet_len_bigendian,
                 sizeof(packet_len_bigendian));

          hdr->checksum = ip::ip_checksum(phdr, packet_csum_len);

          ip::async_write_ip(
              src, dst, proto, 0, default_ttl, hdr, packet_len, [=](int ret) {
                if (ret) {
                  BOOST_LOG_TRIVIAL(error)
                      << "Failed to write TCP packet: Errno " << ret;
                }
                handler(ret);
                delete[] phdr;
              });
        },
        0);
  });
}
} // namespace tcp
} // namespace khtcp