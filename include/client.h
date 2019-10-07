/**
 * @file client.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Client APIs.
 * @version 0.1
 * @date 2019-10-06
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef __KHTCP_CLIENT_H_
#define __KHTCP_CLIENT_H_

// include all client headers for convenience.
#include "client/requests.h"
#include "types.h"

#include <boost/asio.hpp>
#include <thread>

namespace khtcp {
namespace core {
struct core;
}
namespace client {

using void_f = void (*)(core::ptr<::khtcp::client::req>);
static const void_f req_map[] = {&::khtcp::client::arp::read_req::exec,
                                 &::khtcp::client::arp::write_req::exec};
/**
 * @brief Initialize the client.
 *
 * @return true Succeeded in initializing the client.
 * @return false otherwise.
 */
bool init();

core::client_handle get_client_handle();

std::thread &get_polling_thread();

/**
 * @brief Returns the global core object reference.
 *
 * @return core&
 */
core::core &get();
} // namespace client
} // namespace khtcp

#endif