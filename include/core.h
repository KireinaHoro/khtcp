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

#include "client_request.h"
#include "device.h"
#include "packetio.h"

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>

namespace khtcp {
namespace core {
/**
 * @brief The core class stores the main io_context as well as queues for
 * communication between layers.
 */
struct core {
  boost::asio::io_context io_context;

  std::vector<std::shared_ptr<device::device_t>> devices;

  eth::frame_receive_callback eth_callback;

  /**
   * @brief Payload handler list.
   */
  std::list<device::read_handler_t> read_handlers;
  /**
   * @brief Strand to prevent concurrent access to the payload handler list.
   */
  boost::asio::io_context::strand read_handlers_strand;

  boost::asio::local::stream_protocol::acceptor acceptor;

  std::unordered_map<
      int,
      std::pair<std::unique_ptr<boost::asio::local::stream_protocol::socket>,
                struct request>>
      clients;

  boost::asio::deadline_timer arp_table_timer;

  core();

  /**
   * @brief Run the core.
   */
  int run();
};

/**
 * @brief Returns the global core object reference.
 *
 * @return core&
 */
core &get();
} // namespace core
} // namespace khtcp

#endif