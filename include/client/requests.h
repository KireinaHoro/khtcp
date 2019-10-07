/**
 * @file requests.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Request types.
 * @version 0.1
 * @date 2019-10-07
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_CLIENT_REQUEST_H_
#define __KHTCP_CLIENT_REQUEST_H_

#include "../arp.h"
#include "core.h"
#include "types.h"

#include <functional>

namespace khtcp {
namespace client {

/**
 * @brief The request object for a request from client to server.
 *
 * Different API calls have different request object subclasses.
 */
struct req {
  int req_type;
  core::client_handle client_handle;
  /**
   * @brief This function will be ran on client when request completes.
   */
  std::function<void(void)> complete;
};

namespace arp {
struct read_req : req, core::enable_shared_from_this<read_req, req> {
  struct {
    int dev_id;
  } param;
  struct {
    int dev_id;
    uint16_t opcode;
    core::ptr<const ::khtcp::eth::addr> sender_mac;
    core::ptr<const ::khtcp::ip::addr> sender_ip;
    core::ptr<const ::khtcp::eth::addr> target_mac;
    core::ptr<const ::khtcp::ip::addr> target_ip;
  } ret;

  static void exec(core::ptr<req> self);
};

struct write_req : req, core::enable_shared_from_this<write_req, req> {
  struct {
    int dev_id;
    uint16_t opcode;
    core::ptr<const ::khtcp::eth::addr> sender_mac;
    core::ptr<const ::khtcp::ip::addr> sender_ip;
    core::ptr<const ::khtcp::eth::addr> target_mac;
    core::ptr<const ::khtcp::ip::addr> target_ip;
  } param;
  struct {
    int dev_id;
    int ret;
  } ret;

  static void exec(core::ptr<req> self);
};
} // namespace arp
} // namespace client
} // namespace khtcp

#endif