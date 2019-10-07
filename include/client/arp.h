/**
 * @file arp.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Client APIs for ARP.
 * @version 0.1
 * @date 2019-10-06
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef __KHTCP_CLIENT_ARP_H_
#define __KHTCP_CLIENT_ARP_H_

#include "../arp.h"
#include "core.h"
#include "types.h"

namespace khtcp {
namespace client {
namespace arp {

void async_read_arp(int dev_id, ::khtcp::arp::read_handler_t &&handler);

void async_write_arp(int dev_id, uint16_t opcode,
                     core::ptr<const ::khtcp::eth::addr> sender_mac,
                     core::ptr<const ::khtcp::ip::addr> sender_ip,
                     core::ptr<const ::khtcp::eth::addr> target_mac,
                     core::ptr<const ::khtcp::ip::addr> target_ip,
                     ::khtcp::arp::write_handler_t &&handler);
} // namespace arp
} // namespace client
} // namespace khtcp

#endif