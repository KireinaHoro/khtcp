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
#include <cstdint>
#include <functional>
#include <netinet/ether.h>
#include <utility>

namespace khtcp {
namespace eth {
using addr_t = uint8_t[6];

static const addr_t ETH_BROADCAST = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * @brief The Ethernet II header type.
 */
struct __attribute__((packed)) eth_header_t {
  addr_t dst;
  addr_t src;
  uint16_t ethertype;
};

/**
 * @brief The read handler type.
 *
 * consumed(dev_id, ethertype, payload, len)
 */
using read_handler_t = std::function<bool(int, uint16_t, const uint8_t *, int)>;

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
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by `khtcp::mgmt::add_device`) to send
 * on.
 * @return 0 on success, -1 on error.
 * @see khtcp::mgmt::add_device
 */
int send_frame(const void *buf, int len, int ethtype, const void *destmac,
               int id);

/**
 * @brief Asynchronously read an Ethernet frmae.
 *
 * @param id The device to operate on.
 * @param handler handler to call when the read operation is done.
 * @param client_id id for calling client, 0 for local (a server call).
 */
void async_read_frame(int id, read_handler_t &&handler, int client_id = 0);

/**
 * @brief Asynchronously encapsulate some data into an Ethernet II frame and
 * send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device (returned by `khtcp::mgmt::add_device`) to
 * send on.
 * @param handler The handler to call on after send completes.
 * @param client_id id for calling client, 0 for local (a server call).
 * @see khtcp::mgmt::add_device
 */
void async_write_frame(const void *buf, int len, int ethtype,
                       const void *destmac, int id, write_handler_t &&handler,
                       int client_id = 0);

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

/**
 * @brief Join Ethernet multicast group.
 *
 * Joining a multicast group will result in receiving all frames sent to this
 * multicast address.
 *
 * @param multicast The multicast group to join.
 */
void join_multicast(const addr_t multicast);

} // namespace eth
} // namespace khtcp

#endif