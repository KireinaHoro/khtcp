/**
 * @file test_auto_answer.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test for protocols with auto answering, e.g. ARP, ICMP echo
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
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " <interface>\n";
    return -1;
  }

  if (!khtcp::core::init(true)) {
    std::cerr << "core init failed\n";
    return -1;
  }

  khtcp::device::add_device(argv[1]);

  return khtcp::core::get().run();
}
