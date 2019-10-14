/**
 * @file arp.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief The Address Resolution Protocol.
 * @version 0.1
 * @date 2019-10-04
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_ARP_H_
#define __KHTCP_ARP_H_

#include "device.h"
#include "ip.h"
#include "packetio.h"

#include <cstdint>
#include <functional>

namespace khtcp {
namespace arp {
const int NEIGHBOR_TIMEOUT = 20;

/**
 * @brief The read handler type.
 *
 * consumed(dev_id, opcode, sender_mac, sender_ip, target_mac, target_ip)
 */
using read_handler_t = std::function<bool(int, uint16_t, eth::addr_t,
                                          ip::addr_t, eth::addr_t, ip::addr_t)>;

/**
 * @brief The write handler type.
 *
 * (dev_id, ret)
 */
using write_handler_t = std::function<void(int, int)>;

/**
 * @brief The resolve MAC handler type.
 *
 * (ret, MAC)
 *
 * When a resolution fails (perhaps due to an unanswered ARP), ret
 * will carry the errno.
 */
using resolve_mac_handler_t = std::function<void(int, const eth::addr_t)>;

/**
 * @brief Start ARP auto answering.
 *
 * @param dev_id
 */
void start(int dev_id);

/**
 * @brief The ARP header.
 */
struct __attribute__((packed)) arp_header_t {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_size;
  uint8_t protocol_size;
  uint16_t opcode;
};

static const uint16_t ethertype = 0x0806;

/**
 * @brief Asynchronously read an ARP packet.
 *
 * This ARP stack only supports Ethernet/IP.
 *
 * @param dev_id device id to receive ARP packet from.
 * @param handler handler to call once packet has been received.
 */
void async_read_arp(int dev_id, read_handler_t &&handler);

/**
 * @brief Asynchronously write an ARP packet.
 *
 * @param dev_id device id to send ARP packet to.
 * @param opcode ARP opcode.
 * @param sender_mac sender MAC.
 * @param sender_ip sender IP.
 * @param target_mac target MAC.
 * @param target_ip target IP.
 * @param handler handler to call once packet has been received.
 */
void async_write_arp(int dev_id, uint16_t opcode, const eth::addr_t sender_mac,
                     const ip::addr_t sender_ip, const eth::addr_t target_mac,
                     const ip::addr_t target_ip, write_handler_t &&handler);

/**
 * @brief Asynchronously resolve MAC address for given IP destination.
 *
 * Note that if the MAC has already been resolved and has not expired, this
 * function will call the handler synchronously.
 *
 * @param dev_id device ID to send resolving ARP on.
 * @param dst destination IP.
 * @param handler handler to call when MAC resolving is done.
 */
void async_resolve_mac(int dev_id, const ip::addr_t dst,
                       resolve_mac_handler_t &&handler);

} // namespace arp
} // namespace khtcp

#endif