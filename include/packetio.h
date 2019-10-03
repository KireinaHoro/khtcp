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
#include <netinet/ether.h>

namespace khtcp {
namespace eth {
/**
 * @brief The Ethernet II header type.
 */
struct __attribute__((packed)) eth_header_t {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t ethertype;
};
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

} // namespace eth
} // namespace khtcp

#endif