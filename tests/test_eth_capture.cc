/**
 * @file test_eth_capture.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test for basic Ethernet capture.
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
  if (!khtcp::core::init()) {
    std::cerr << "core init failed\n";
    return -1;
  }

  khtcp::device::add_device(argv[1]);

  khtcp::eth::set_frame_receive_callback(khtcp::eth::print_eth_frame_callback);
  return khtcp::core::get().run();
}