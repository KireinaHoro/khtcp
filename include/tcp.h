/**
 * @file tcp.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief The Transmission Control Protocol (TCP, RFC793)
 * @version 0.1
 * @date 2019-10-04
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_TCP_H_
#define __KHTCP_TCP_H_

#include "ip.h"

#include <boost/asio.hpp>
#include <queue>

namespace khtcp {
namespace tcp {

static const uint8_t default_ttl = 64;
static const uint8_t proto = 6;

void start();

/**
 * @brief The TCP header, without the TCP options.
 */
struct __attribute__((packed)) tcp_header_t {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

// hdr->flags = fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4)
#define FIN(x) (bool)((x)&0b1)
#define SYN(x) (bool)((x)&0b10)
#define RST(x) (bool)((x)&0b100)
#define PSH(x) (bool)((x)&0b1000)
#define ACK(x) (bool)((x)&0b10000)

using send_segment_handler_t = std::function<void(int)>;
void async_send_segment(const ip::addr_t src, uint16_t src_port,
                        const ip::addr_t dst, uint16_t dst_port,
                        uint32_t seq_num, uint32_t ack_num, bool ack, bool psh,
                        bool rst, bool syn, bool fin, uint16_t window,
                        const void *payload_ptr, uint16_t payload_len,
                        send_segment_handler_t &&handler, int client_id = 0);

using recv_segment_handler_t =
    std::function<void(int, uint32_t, uint32_t, bool, bool, bool, bool, bool,
                       uint16_t, const void *, uint16_t)>;
void async_recv_segment(const ip::addr_t src, uint16_t src_port,
                        const ip::addr_t dst, uint16_t dst_port,
                        recv_segment_handler_t &&handler, int client_id = 0);

struct tcb {
  // is connection established? (for passive open)
  bool established;
  // SEGMENTED buffer pending send
  std::queue<boost::asio::const_buffer> pending_send;
  // receive buffer
  boost::asio::mutable_buffer pending_receive;
  // send_unack < seg.ack <= send_next
  uint32_t send_unack;
  uint32_t send_next;
  // recv_next <= seg.seq < recv_next + recv_window OR
  // recv_next <= seg.seq + seg.len - 1 < recv_next + recv_window
  uint32_t recv_next;
  uint32_t recv_window;
};

using open_handler_t = std::function<void(std::unique_ptr<struct tcb>)>;
void async_open(const ip::addr_t src, uint16_t src_port, const ip::addr_t dst,
                uint16_t dst_port, bool active, open_handler_t &&handler);

} // namespace tcp
} // namespace khtcp

#endif