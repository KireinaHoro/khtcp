/**
 * @file ip.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief The Internet Protocol.
 * @version 0.1
 * @date 2019-10-04
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_IP_H_
#define __KHTCP_IP_H_

#include "device.h"

#include <cstdint>
#include <functional>
#include <string>

namespace khtcp {
namespace ip {
using addr_t = uint8_t[4];

/**
 * @brief The IP header.
 *
 * Options are not included in the header; instead, they're counted as part of
 * the payload.  Note the bitfield endianness problem: fields that share the
 * same word are placed as in little endian.
 */
struct __attribute__((packed)) ip_header_t {
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t ecn : 2;
  uint8_t dscp : 6;
  uint16_t total_length;
  uint16_t identification;
  uint16_t flags;
  uint8_t ttl;
  uint8_t proto;
  uint16_t header_csum;
  addr_t src_addr;
  addr_t dst_addr;
};

/**
 * @brief The read handler type.
 *
 * consumed(dev_id, payload_ptr, payload_len, src, dst, dscp, opt)
 *
 * As recommended in https://tools.ietf.org/html/rfc791#section-3.3
 */
using read_handler_t =
    std::function<bool(int, const void *, uint64_t, const addr_t, const addr_t,
                       uint8_t, const void *)>;

/**
 * @brief The write handler type.
 *
 * (dev_id, ret)
 */
using write_handler_t = std::function<void(int, int)>;

// The header shall be of just 5*4=20 octets
static_assert(sizeof(ip_header_t) == 5 * 4, "IP header size mismatch");

static const uint16_t ethertype = 0x0800;

/**
 * @brief Wrap IP read handler for posting on global read handler queue.
 *
 * This function shall be used to implement auto answering for protocols on top
 * of IP, such as ICMP.
 *
 * @param proto protocol code.  If proto < 0, catch all protocols.
 * @param handler handler to wrap
 * @return device::read_handler_t
 */
device::read_handler_t wrap_read_handler(int proto, read_handler_t handler);

/**
 * @brief Asynchronously read an IP packet.
 *
 * As recommended in https://tools.ietf.org/html/rfc791#section-3.3
 *
 * @param dev_id device id to receive IP packet from.
 * @param proto protocol code
 * @param handler handler to call once packet has been received.
 */
void async_read_ip(int dev_id, int proto, read_handler_t &&handler);

/**
 * @brief Asynchronously write an IP packet.
 *
 * As recommended in https://tools.ietf.org/html/rfc791#section-3.3
 *
 * @param dev_id device to write to
 * @param src source IP address
 * @param dst destination IP address
 * @param proto protocol code
 * @param dscp DSCP field
 * @param ttl Time To Live
 * @param payload_ptr pointer to payload data
 * @param payload_len payload data length
 * @param handler handler to call once packet has been sent
 * @param identification Identification field, default = 0
 * @param df DF flag, default = true
 * @param option Option pointer, default = nullptr
 */
void async_write_ip(int dev_id, const addr_t src, const addr_t dst,
                    uint8_t proto, uint8_t dscp, uint8_t ttl,
                    const void *payload_ptr, uint64_t payload_len,
                    write_handler_t &&handler, uint16_t identification = 0,
                    bool df = true, const void *option = nullptr);

/**
 * @brief Start IP auto answering.
 *
 * @param dev_id
 */
void start(int dev_id);

/**
 * @brief An entry in the routing table.  Resembles the Linux routing table
 * entry.
 */
struct route {
  enum type { DEV, VIA } type;
  union {
    int dev_id;
    addr_t ip;
  } nexthop;
  addr_t dst;
  uint8_t prefix;
  uint64_t metric;

  bool operator<(const struct route &a) const;
};

/**
 * @brief Add a route to the global routing table.
 *
 * @param route the route object to add
 */
void add_route(struct route &&route);

/**
 * @brief Lookup a destination in the global routing table.
 *
 * @param dst destination
 * @param out_route pointer to the route entry
 * @return true a valid route has been found
 * @return false otherwise
 */
bool lookup_route(const addr_t dst, const struct route **out_route);

/**
 * @brief Print the routing table.
 */
void print_route();

} // namespace ip
} // namespace khtcp

#endif