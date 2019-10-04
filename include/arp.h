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

#include "ip.h"
#include "packetio.h"

#include <cstdint>
#include <functional>

namespace khtcp {
namespace arp {
/**
 * @brief The read handler type.
 *
 * (dev_id, opcode, sender_mac, sender_ip, target_mac, target_ip)
 */
using read_handler_t = std::function<void(int, uint16_t, eth::addr_t,
                                          ip::addr_t, eth::addr_t, ip::addr_t)>;

/**
 * @brief The write handler type.
 *
 * (dev_id, ret)
 */
using write_handler_t = std::function<void(int, int)>;

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
void async_write_arp(int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                     ip::addr_t sender_ip, eth::addr_t target_mac,
                     ip::addr_t target_ip, write_handler_t &&handler);

/**
 * @brief Broker for incoming ARP packets.
 *
 * This function should be called within the arp_handlers_strand for thread
 * safety when accessing the arp_handlers.
 *
 * @param dev_id
 * @param packet_ptr
 */
void broker(int dev_id, const uint8_t *packet_ptr);

} // namespace arp
} // namespace khtcp

#endif