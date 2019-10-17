/**
 * @file udp.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief The User Datagram Protocol (UDP, RFC768)
 * @version 0.1
 * @date 2019-10-04
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_UDP_H_
#define __KHTCP_UDP_H_

#include "ip.h"

namespace khtcp {
namespace udp {

static const uint8_t default_ttl = 114;
static const uint8_t proto = 17;

struct __attribute__((packed)) udp_header_t {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

/**
 * @brief The read handler type.
 *
 * consumed(payload_ptr, payload_len, src, src_port, dst, dst_port)
 */
using read_handler_t =
    std::function<bool(const void *, uint16_t, const ip::addr_t, uint16_t,
                       const ip::addr_t, uint16_t)>;

/**
 * @brief The write handler type.
 *
 * (ret)
 */
using write_handler_t = std::function<void(int)>;

/**
 * @brief Asynchronously read a UDP packet.
 *
 * @param handler handler to call once packet has been received.
 * @param client_id id for calling client, 0 for local (a server call).
 */
void async_read_udp(read_handler_t &&handler, int client_id = 0);

/**
 * @brief Asynchronously write a UDP packet.
 *
 * @param src source IP address
 * @param src_port source port
 * @param dst destination IP address
 * @param dst_port destination port
 * @param payload_ptr pointer to payload data
 * @param payload_len payload data length
 * @param handler handler to call once packet has been sent
 * @param client_id id for calling client, 0 for local (a server call).
 */
void async_write_udp(const ip::addr_t src, uint16_t src_port,
                     const ip::addr_t dst, uint16_t dst_port,
                     const void *payload_ptr, uint16_t payload_len,
                     write_handler_t &&handler, int client_id = 0);

} // namespace udp
} // namespace khtcp

#endif