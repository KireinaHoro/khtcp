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

#include <cstdint>

namespace khtcp {
namespace ip {
using addr_t = uint8_t[4];

static const uint16_t ethertype = 0x0800;
} // namespace ip
} // namespace khtcp

#endif