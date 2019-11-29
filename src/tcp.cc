#include "tcp.h"
#include "core.h"
#include "util.h"

#include <boost/endian/conversion.hpp>
#include <random>
#include <unordered_map>
#include <unordered_set>

namespace khtcp {
namespace tcp {

std::mt19937 eng;
std::uniform_int_distribution<uint32_t> distribution;

struct hash_fn {
  std::size_t operator()(const conn_key &k) const {
    return std::hash<uint32_t>()(*(uint32_t *)(k.src)) ^
           std::hash<uint32_t>()(*(uint32_t *)(k.dst)) ^
           std::hash<uint16_t>()(k.src_port) ^
           std::hash<uint16_t>()(k.dst_port);
  }
};

std::unordered_map<conn_key, tcb, hash_fn> conns;
std::unordered_set<conn_key, hash_fn> listening;

bool conn_key::operator==(const conn_key &a) const {
  return src_port == a.src_port && dst_port == a.dst_port &&
         !memcmp(src, a.src, sizeof(ip::addr_t)) &&
         !memcmp(dst, a.dst, sizeof(ip::addr_t));
}

std::string conn_key::to_string() const {
  return "(" + util::ip_to_string(src) + ":" + std::to_string(src_port) + "|" +
         util::ip_to_string(dst) + ":" + std::to_string(dst_port) + ")";
}

void async_recv_segment(const ip::addr_t src, uint16_t src_port,
                        const ip::addr_t dst, uint16_t dst_port,
                        recv_segment_handler_t &&handler, int client_id) {
  // We cannot use the normal ip::async_read_ip as we need a timeout to revoke
  // request handlers
  boost::asio::post(core::get().read_handlers_strand, [=]() {
    auto t =
        std::make_shared<boost::asio::deadline_timer>(core::get().io_context);
    t->expires_from_now(timeout);
    core::get().read_handlers.emplace_back(
        ip::wrap_read_handler(
            proto,
            [=](const void *payload_ptr, uint64_t payload_len,
                const ip::addr_t s, const ip::addr_t d, uint8_t dscp,
                const void *opt) -> bool {
              if (memcmp(src, s, sizeof(ip::addr_t)) ||
                  memcmp(dst, d, sizeof(ip::addr_t))) {
                // IP mismatch
                t->cancel();
                return false;
              }
              auto hdr = (struct tcp_header_t *)payload_ptr;
              auto hdr_len = (hdr->data_offset >> 4) << 2;
              auto segment_data = (uint8_t *)hdr + hdr_len;
              auto segment_len = payload_len - hdr_len;
              if (src_port != boost::endian::endian_reverse(hdr->src_port) ||
                  dst_port != boost::endian::endian_reverse(hdr->dst_port)) {
                // port mismatch
                t->cancel();
                return false;
              }
              handler(0, boost::endian::endian_reverse(hdr->seq),
                      boost::endian::endian_reverse(hdr->ack), ACK(hdr->flags),
                      PSH(hdr->flags), RST(hdr->flags), SYN(hdr->flags),
                      FIN(hdr->flags),
                      boost::endian::endian_reverse(hdr->window), segment_data,
                      segment_len);
              t->cancel();
              return true;
            }),
        client_id);
    auto last = core::get().read_handlers.end();
    --last;
    t->async_wait([=](auto ec) {
      if (!ec) {
        BOOST_LOG_TRIVIAL(warning)
            << "TCP read operation time out, cancelling read handler...";
        core::get().read_handlers.erase(last);
        handler(ETIMEDOUT, 0, 0, 0, 0, 0, 0, 0, 0, nullptr, 0);
      }
    });
  });
}

bool default_handler(const void *payload_ptr, uint64_t payload_len,
                     const ip::addr_t src, const ip::addr_t dst, uint8_t dscp,
                     const void *opt) {
  auto hdr = (struct tcp_header_t *)payload_ptr;
  struct conn_key k;
  // reverse src/dst
  memcpy(k.src, dst, sizeof(ip::addr_t));
  memcpy(k.dst, src, sizeof(ip::addr_t));
  k.src_port = boost::endian::endian_reverse(hdr->dst_port);
  k.dst_port = boost::endian::endian_reverse(hdr->src_port);
  auto it = conns.find(k);
  if (it == conns.end() || !it->second.up) {
    // completely no record or not up (opening)
    if (!SYN(hdr->flags) || ((it == conns.end() && ACK(hdr->flags)) ||
                             RST(hdr->flags) || FIN(hdr->flags))) {
      // untracked/malformed connection: RST
      auto seq = boost::endian::endian_reverse(hdr->seq);
      BOOST_LOG_TRIVIAL(warning) << "Sending RST for unknown connection";
      async_send_segment(
          dst, k.src_port, src, k.dst_port, 0, seq + 1, false, false, true,
          false, false, 0, nullptr, 0, [=](int ret) {
            if (!ret) {
              BOOST_LOG_TRIVIAL(info)
                  << "Sent RST to unknown connection " << k.to_string();
            } else {
              BOOST_LOG_TRIVIAL(error) << "Failed to send RST: Errno " << ret;
            }
          });
    } else if (it == conns.end()) {
      // plain SYN: check if listening
      memset(k.dst, 0, sizeof(ip::addr_t));
      k.dst_port = 0;
      if (listening.find(k) == listening.end()) {
        // closed port: ACK+RST
        auto seq = boost::endian::endian_reverse(hdr->seq);
        BOOST_LOG_TRIVIAL(warning) << "Sending RSTACK for closed port";
        async_send_segment(
            dst, k.src_port, src, boost::endian::endian_reverse(hdr->src_port),
            0, seq + 1, true, false, true, false, false, 0, nullptr, 0,
            [=](int ret) {
              if (!ret) {
                BOOST_LOG_TRIVIAL(info)
                    << "Sent RST due to closed port " << k.src_port;
              } else {
                BOOST_LOG_TRIVIAL(error) << "Failed to send RST: Errno " << ret;
              }
            });
      }
    }
    // we have the connection in record; do nothing
  }
  return false;
}

void start() { ip::async_read_ip(proto, default_handler); }

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