/**
 * @file test_arping.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test for sending/receiving ARP packets.  Mimics the arping utility.
 * @version 0.1
 * @date 2019-10-05
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "arp.h"
#include "core.h"
#include "device.h"
#include "util.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>

using namespace khtcp;

ip::addr_t dst;

void req_once(int dev_id) {
  auto &device = device::get_device_handle(dev_id);
  arp::async_write_arp(
      dev_id, 0x1, device.addr.get().get(), device.ip_addrs[0].get().get(),
      eth::ETH_BROADCAST, dst.get().get(), [](int dev_id, int ret) {
        if (ret != PCAP_ERROR) {
          std::cout << "Broadcast sent for " << util::ip_to_string(*dst)
                    << " on device " << device::get_device_handle(dev_id).name
                    << "\n";
        } else {
          std::cerr << "Failed to send ARP packet on device "
                    << device::get_device_handle(dev_id).name << "\n";
        }
      });
  arp::async_read_arp(
      dev_id,
      [](int dev_id, uint16_t opcode, const eth::addr *sender_mac,
         const ip::addr *sender_ip, const eth::addr *target_mac,
         const ip::addr *starget_ip) -> bool {
        if (opcode == 0x2) {
          std::cout << "Unicast reply from " << util::ip_to_string(*sender_ip)
                    << " [" << util::mac_to_string(*sender_mac) << "]\n";
          return true;
        } else {
          return false;
        }
      });
}

void timer_handler(int dev_id, boost::system::error_code ec,
                   boost::asio::deadline_timer &timer) {
  if (!ec) {
    req_once(dev_id);
    timer.expires_from_now(boost::posix_time::seconds(1));
    timer.async_wait(boost::bind(timer_handler, dev_id,
                                 boost::asio::placeholders::error,
                                 boost::ref(timer)));
  } else {
    std::cerr << "timer: " << ec.message() << "\n";
  }
}

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cout << "usage: " << argv[0] << " <interface> <destination>\n";
    return -1;
  }

  if (!core::init(false)) {
    std::cerr << "core init failed\n";
    return -1;
  }

  dst = core::make_shared<ip::addr>();

  auto id = device::find_device(argv[1]);
  auto &device = device::get_device_handle(id);
  if (device.ip_addrs.empty()) {
    std::cerr << "No IP addresses on device " << device.name << "\n";
    return -1;
  }

  if (!util::string_to_ip(core::string(argv[2], core::get_allocator<char>()),
                          *dst)) {
    std::cerr << "Failed to parse destination IP\n";
    return -1;
  }

  std::cout << "ARPING " << util::ip_to_string(*dst) << " from "
            << util::ip_to_string(*device.ip_addrs[0]) << " " << device.name
            << "\n";

  req_once(id);
  boost::asio::deadline_timer timer(core::get().io_context);
  timer.expires_from_now(boost::posix_time::seconds(1));
  timer.async_wait([&](auto ec) { timer_handler(id, ec, timer); });

  return 0;
}