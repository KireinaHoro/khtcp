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
#include <boost/asio.hpp>
#include <cstdint>
#include <pcap.h>
#include <string>

namespace khtcp {
namespace device {

const size_t CAPTURE_BUFSIZ = 8192;
const size_t PACKET_TIMEOUT = 2;

/**
 * @brief Device handle for an Ethernet interface.
 *
 * Note that this structure assumes a 6-octet (i.e. Ethernet) address format.
 */
struct device_t {
  std::string name;
  uint8_t addr[6];
  int id;
  boost::asio::posix::stream_descriptor *trigger;
  pcap_t *pcap_handle;

  /**
   * @brief Register the device's capture task in the core io_context.
   */
  int start_capture();

  /**
   * @brief Do actual pcap sniff (pcap_next) and recharge the task.
   */
  void handle_sniff();

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