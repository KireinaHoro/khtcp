#include "device.h"

#include <iostream>

int main() {
  auto id = khtcp::device::add_device("eth0");
  if (id >= 0) {
    std::cout << "Found requested device as id=" << id << std::endl;
  }
  auto fid = khtcp::device::find_device("eth0");
  if (fid == id) {
    std::cout << "Device id matched in find_device" << std::endl;
  }
}