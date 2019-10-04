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

int main() {
  // khtcp::util::init_logging(boost::log::trivial::trace);
  khtcp::util::init_logging();

  khtcp::device::add_device("eth0");

  khtcp::eth::set_frame_receive_callback(khtcp::eth::print_eth_frame_callback);
  return khtcp::core::get().run();
}