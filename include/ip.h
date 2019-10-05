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

#include "types.h"

#include <cstdint>
#include <memory>

namespace khtcp {
namespace ip {

struct addr {
  uint8_t data[4];
};
using addr_t = core::shared_ptr<addr>;

static const uint16_t ethertype = 0x0800;
} // namespace ip
} // namespace khtcp

#endif