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
#include <map>
#include <unordered_map>

#define CLEANUP_BUF(resp, req)                                                 \
  {                                                                            \
    free(resp);                                                                \
    free(req);                                                                 \
    auto it = get().outstanding_buffers.begin();                               \
    while (it != get().outstanding_buffers.end()) {                            \
      if (it->second == resp || it->second == req) {                           \
        get().outstanding_buffers.erase(it++);                                 \
      } else {                                                                 \
        ++it;                                                                  \
      }                                                                        \
    }                                                                          \
  }

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
  /**
   * @brief Outstanding buffers that are not yet freed.
   *
   * client_id -> [buffer]
   *
   * Buffers here will be freed when client request is finished or cancelled
   * (due to disconnection).
   */
  std::multimap<int, void *> outstanding_buffers;

  /**
   * @brief Write handler list.
   */
  std::list<device::write_task_t> write_tasks;
  /**
   * @brief Strand to prevent concurrent access to the write handler list.
   */
  boost::asio::io_context::strand write_tasks_strand;

  boost::asio::local::stream_protocol::acceptor acceptor;

  std::unordered_map<int, std::pair<boost::asio::local::stream_protocol::socket,
                struct request *>>
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

/**
 * @brief Cleans up the client with id once we discover that it has
 * disconnected.
 *
 * @param client_id
 */
void cleanup_client(int client_id);
} // namespace core
} // namespace khtcp

#endif