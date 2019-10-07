/**
 * @file test_mgmt_device.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test for device initialization.
 * @version 0.1
 * @date 2019-10-05
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "core.h"
#include "device.h"

#include <iostream>

int main() {
  if (!khtcp::core::init()) {
    std::cerr << "core init failed\n";
    return -1;
  }

  auto id = khtcp::device::add_device("eth0");
  if (id >= 0) {
    std::cout << "Found requested device as id=" << id << std::endl;
  }
  auto fid = khtcp::device::find_device("eth0");
  if (fid == id) {
    std::cout << "Device id matched in find_device" << std::endl;
  }
}