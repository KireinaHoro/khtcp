/**
 * @file rip.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief The Routing Information Protocol (RIPv2, RFC2453)
 * @version 0.1
 * @date 2019-10-04
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_RIP_H_
#define __KHTCP_RIP_H_

#include "ip.h"

namespace khtcp {
namespace rip {
static const ip::addr_t RIP_MULTICAST = {0xe0, 0x00, 0x00, 0x09};
static const uint16_t port = 520;
static const uint8_t version = 2;
static const uint32_t infinity = 16; // to represent unreachable routes
static const uint32_t cost = 1;      // for simple hop-based
static const int max_age = 180;
static const int deletion_timeout = 120;

struct __attribute__((packed)) rip_header_t {
  uint8_t command;
  uint8_t version;
  uint16_t zero;
};

static const uint8_t request = 1;
static const uint8_t response = 2;

struct __attribute__((packed)) rte_t {
  uint16_t afi;
  uint16_t route_tag;
  ip::addr_t address;
  ip::addr_t mask;
  ip::addr_t nexthop;
  uint32_t metric;
};

/**
 * @brief Start the RIP protocol.
 */
void start();

/**
 * @brief Trigger a update.
 */
void trigger_update();

/**
 * @brief Send a full-table request.
 */
void request_fulltable();

/**
 * @brief Send full routing table.
 *
 * Note: this will perform Split Horizon src_port is the RIP port (520).
 */
void send_fulltable(const uint8_t *src_, uint16_t src_port, const uint8_t *dst_,
                    uint16_t dst_port);
} // namespace rip
} // namespace khtcp

#endif