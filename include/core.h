/**
 * @file core.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Core logic for maintaining the ASIO context.
 * @version 0.1
 * @date 2019-10-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_CORE_H_
#define __KHTCP_CORE_H_

#include "device.h"
#include "packetio.h"
#include "types.h"

#include <boost/asio.hpp>
#include <memory>

namespace khtcp {
namespace core {

/**
 * @brief The core class stores the main io_context as well as queues for
 * communication between layers.
 */
struct core {
  boost::asio::io_context io_context;

  vector<std::shared_ptr<device::device_t>> devices;

  eth::frame_receive_callback eth_callback;

  /**
   * @brief Run the core.
   */
  int run();
};

/**
 * @brief Initialize the core object.
 *
 * @param is_server true if current instance is the server.
 * @return true if core init succeeded.
 * @return false otherwise.
 */
bool init(bool is_server);

/**
 * @brief Returns the global core object reference.
 *
 * @return core&
 */
core &get();
} // namespace core
} // namespace khtcp

#endif