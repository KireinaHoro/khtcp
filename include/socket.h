/**
 * @file socket.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Common data structure for maintaining a socket structure.
 * @version 0.1
 * @date 2019-10-17
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_SOCKET_H_
#define __KHTCP_SOCKET_H_

#include "ip.h"

#include <netinet/in.h>

namespace khtcp {
namespace socket {
struct socket {
  int fd;
  int type; // SOCK_STREAM or SOCK_DGRAM
  struct sockaddr_in bind_addr;

  void get_src(const ip::addr_t dst, const uint8_t **src_out,
               uint16_t *port_out);

  socket(int client_id, int type);
};
} // namespace socket
} // namespace khtcp

#endif