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
}
} // namespace khtcp

#endif