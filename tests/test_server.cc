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
  char *device = nullptr;
  if (argc > 3 || argc < 2) {
    std::cerr << "usage: " << argv[0] << " <default-route> [interface]\n";
    return -1;
  } else if (argc == 3) {
    device = argv[2];
  }
  khtcp::util::init_logging(boost::log::trivial::warning);

  khtcp::device::add_device(device);

  khtcp::eth::set_frame_receive_callback(khtcp::eth::ethertype_broker_callback);

  khtcp::ip::route r;
  r.type = khtcp::ip::route::VIA;
  khtcp::util::string_to_ip("0", r.dst);
  r.prefix = 0;
  khtcp::util::string_to_ip(argv[1], r.nexthop.ip);
  r.metric = 100;
  khtcp::ip::add_route(std::move(r));

  std::cout << "Global Routing Table" << std::endl;
  khtcp::ip::print_route();

  return khtcp::core::get().run();
}
