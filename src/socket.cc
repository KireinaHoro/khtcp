#include "socket.h"
#include "core.h"
#include "util.h"

namespace khtcp {
namespace socket {

socket::socket(int client_id, int type) : type(type) {
  for (int i = core::core::MIN_FD; i > 0; ++i) {
    if (core::get().client_sockets.find({client_id, i}) ==
        core::get().client_sockets.end()) {
      fd = i;
      // bind_addr.sin_family != AF_INET, an unbound socket
      memset(&bind_addr, 0, sizeof(bind_addr));
      return;
    }
  }
  BOOST_LOG_TRIVIAL(error) << "Failed to assign socket fd for client "
                           << client_id;
}

void socket::get_src(const ip::addr_t dst, const uint8_t **src_out,
                     uint16_t *port_out) {
  if (bind_addr.sin_family == AF_INET) {
    // we're bound
    *src_out = (const uint8_t *)&bind_addr.sin_addr;
    *port_out = bind_addr.sin_port;
  } else {
    struct ip::route *route;
    if (!ip::lookup_route(dst, &route)) {
      // failed to get route for destination
      BOOST_LOG_TRIVIAL(warning)
          << "No route to host " << util::ip_to_string(dst);
      *src_out = nullptr;
      return;
    }

    // take the first address and a random, > 1024 port
    // Ephemeral port definition according to RFC6056
    *src_out = device::get_device_handle(route->dev_id).ip_addrs[0];
    *port_out = rand() % 65535;
    if (*port_out <= 1024) {
      *port_out = 65535 - *port_out;
    }
  }
}
} // namespace socket
} // namespace khtcp