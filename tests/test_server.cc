/**
 * @file test_server.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test server that accepts connections from clients.
 *
 * For ARP answering to work properly, switch off kernel ARP stack:
 *
 * ```
 * ip link set arp off <interface>
 * ```
 *
 * Note that this may cause you to lose connection on the interface; use
 * vnetUtils that comes with the lab and test in a netns.
 *
 * @version 0.1
 * @date 2019-10-05
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "core.h"
#include "device.h"
#include "util.h"

#include <iostream>

int main(int argc, char **argv) {
  khtcp::util::init_logging(boost::log::trivial::info);

  // add all devices
  if (khtcp::device::add_device(nullptr) < 0) {
    std::cerr << "Failed to add all devices" << std::endl;
    return -1;
  }

  khtcp::eth::set_frame_receive_callback(khtcp::eth::ethertype_broker_callback);
  if (argc > 2) {
    std::cerr << "usage: " << argv[0] << " [default-route]\n";
    return -1;
  } else if (argc != 1) {
    // we have a default route
    khtcp::ip::route r;
    khtcp::util::string_to_ip("0", r.dst);
    r.prefix = 0;
    r.has_router = true;
    khtcp::util::string_to_ip(argv[1], r.router);
    r.age = -1; // never expires
    if (!khtcp::ip::add_route(std::move(r))) {
      std::cerr << "Failed to add default route" << std::endl;
      return -1;
    }
  }

  return khtcp::core::get().run();
}
