/**
 * @file packetio.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Library supporting sending/receiving Ethernet II frames.
 * @version 0.1
 * @date 2019-10-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_PACKETIO_H_
#define __KHTCP_PACKETIO_H_
#include "types.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <netinet/ether.h>
#include <utility>

namespace khtcp {
namespace eth {
struct addr {
  uint8_t data[6];
};
using addr_t = core::shared_ptr<addr>;

static core::ptr<addr> _broadcast;

core::ptr<addr> &get_broadcast();

/**
 * @brief The Ethernet II header type.
 */
struct __attribute__((packed)) eth_header_t {
  addr dst;
  addr src;
  uint16_t ethertype;
};

/**
 * @brief The write handler type.
 *
 * (ret)
 */
using write_handler_t = std::function<void(int)>;

/**
 * @brief Construct Ethernet II frame for sending.
 *
 * The caller has the responsibility to delete the buffer returned.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by `khtcp::mgmt::add_device`) to send
 * on.
 * @return std::pair<uint8_t *, size_t> the frame constructed.
 */
std::pair<uint8_t *, size_t> construct_frame(const void *buf, int len,
                                             int ethtype, const void *destmac,
                                             int id);

/**
 * @brief Asynchronously ncapsulate some data into an Ethernet II frame and send
 * it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by `khtcp::mgmt::add_device`) to send
 * on.
 * @param handler The handler to call on after send completes.
 * @see khtcp::mgmt::add_device
 */
void async_send_frame(const void *buf, int len, int ethtype,
                      const eth::addr *destmac, int id,
                      write_handler_t &&handler);

/**
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame.
 * @param len Length of the frame.
 * @param id ID of the device (returned by `khtcp::mgmt::add_device`) receiving
 * current frame.
 * @return 0 on success, -1 on error.
 * @see khtcp::mgmt::add_device
 */
using frame_receive_callback = int (*)(const void *, int, int);

/**
 * @brief Register a callback function to be called each time an Ethernet II
 * frame was received.
 *
 * @param callback the callback function.
 * @return 0 on success, -1 on error.
 * @see khtcp::eth::frame_receive_callback
 */
int set_frame_receive_callback(frame_receive_callback callback);

/**
 * @brief Get the frame receive callback object
 *
 * @return frame_receive_callback
 */
frame_receive_callback get_frame_receive_callback();

/**
 * @brief Simple callback to print Ethernet header of received packet.
 *
 * @param frame pointer to frame.
 * @param len length of the frame.
 * @param dev_id id of device from which the frame is received from.
 * @return int
 */
int print_eth_frame_callback(const void *frame, int len, int dev_id);

/**
 * @brief Callback to traverse the device receive handler queue.
 *
 * The broker will discard frames with MAC address that does not match the
 * current device.
 *
 * @param frame pointer to frame.
 * @param len length of the frame.
 * @param dev_id id of device from which the frame is received from.
 * @return int
 */
int ethertype_broker_callback(const void *frame, int len, int dev_id);

} // namespace eth
} // namespace khtcp

#endif