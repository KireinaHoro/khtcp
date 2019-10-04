/**
 * @file device.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Library supporting network device management.
 * @version 0.1
 * @date 2019-10-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_DEVICE_H_
#define __KHTCP_DEVICE_H_

#include "arp.h"
#include "ip.h"
#include "packetio.h"

#include <boost/asio.hpp>
#include <cstdint>
#include <functional>
#include <pcap.h>
#include <queue>
#include <string>
#include <vector>

namespace khtcp {
namespace device {

/**
 * @brief The write handler type.
 *
 * (ret)
 */
using write_handler_t = std::function<void(int)>;

const size_t CAPTURE_BUFSIZ = 8192;
const size_t PACKET_TIMEOUT = 2;

/**
 * @brief Device handle for an Ethernet interface.
 *
 * Note that this structure assumes a 6-octet (i.e. Ethernet) address format.
 */
struct device_t {
  std::string name;
  eth::addr_t addr;
  int id;
  pcap_t *pcap_handle;

  // L3 addresses
  std::vector<uint8_t *> ip_addrs;

  /**
   * @brief A trampoline queue for ARP.
   */
  std::queue<arp::read_handler_t> arp_handlers;
  /**
   * @brief Strand to prevent concurrent access to the ARP queue.
   */
  boost::asio::io_context::strand arp_handlers_strand;

  /**
   * @brief Wraps the injection operation for thread safety.
   *
   * We do not know if pcap_inject is thread safe, and the inject handler may be
   * posted from different threads, so post through a strand instead of the
   * global io_context.
   *
   * @see khtcp::device::device_t::handle_inject
   */
  boost::asio::io_context::strand inject_strand;

  /**
   * @brief The trigger fd from pcap_get_selectable_fd.
   *
   * A null_buffers() read will be performed; once triggered, some data are to
   * be captured via pcap_next.
   *
   * @see khtcp::device::device_t::handle_sniff
   */
  boost::asio::posix::stream_descriptor *trigger;

  /**
   * @brief Register the device's capture task in the core io_context.
   */
  int start_capture();

  /**
   * @brief Do actual pcap sniff (pcap_next) and recharge the task.
   */
  void handle_sniff();

  /**
   * @brief Synchronously inject frame into device via pcap_inject.
   *
   * @param buf The buffer to inject.
   * @param len Length of the buffer.
   */
  int inject_frame(const uint8_t *buf, size_t len);

  /**
   * @brief Asynchronously inject frame into device via pcap_inject.
   *
   * @param buf The buffer to inject.
   * @param len Length of the buffer.
   * @param handler handler to call after completion.
   */
  void async_inject_frame(const uint8_t *buf, size_t len,
                          write_handler_t &&handler);

  device_t();
  device_t(const device_t &) = delete;
  device_t(device_t &&) = delete;
  ~device_t();
};

/**
 * @brief Add a device to the library for sending/receiving packets.
 *
 * @param device Name of network device to send/receive packet on.
 * @return int A non-negative _device-ID_ on success, -1 on error.
 */
int add_device(const char *device);

/**
 * @brief Find a device added by `khtcp::mgmt::add_device`.
 *
 * @param device Name of the network device.
 * @return int A non-negative _device-ID_ on success, -1 if no such device was
 * found.
 */
int find_device(const char *device);

/**
 * @brief Get the device handle object from global store registered by
 * `khtcp::mgmt::add_device`.
 *
 * @param id
 * @return device_t
 *&
 */
device_t &get_device_handle(int id);

} // namespace device
} // namespace khtcp

#endif