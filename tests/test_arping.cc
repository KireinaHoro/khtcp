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
ip::addr_t src;

void req_once(int dev_id) {
  auto &device = device::get_device_handle(dev_id);
  arp::async_write_arp(dev_id, 0x1, device.addr, src, eth::ETH_BROADCAST, dst,
                       [](int dev_id, int ret) {
                         if (ret != PCAP_ERROR) {
                           std::cout << "Broadcast sent for "
                                     << util::ip_to_string(dst) << " on device "
                                     << device::get_device_handle(dev_id).name
                                     << "\n";
                         } else {
                           std::cerr << "Failed to send ARP packet on device "
                                     << device::get_device_handle(dev_id).name
                                     << "\n";
                         }
                       });
  arp::async_read_arp(dev_id,
                      [](int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                         ip::addr_t sender_ip, eth::addr_t target_mac,
                         ip::addr_t target_ip) -> bool {
                        if (opcode == 0x2) {
                          std::cout << "Unicast reply from "
                                    << util::ip_to_string(sender_ip) << " ["
                                    << util::mac_to_string(sender_mac) << "]\n";
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

  util::init_logging(boost::log::trivial::warning);

  int id = device::add_device(argv[1]);
  if (id == -1) {
    std::cerr << "Failed to add device\n";
    return -1;
  }

  auto &device = device::get_device_handle(id);
  if (device.ip_addrs.empty()) {
    std::cerr << "No IP addresses on device " << device.name << "\n";
    return -1;
  }

  memcpy(src, device.ip_addrs[0], sizeof(ip::addr_t));
  if (!util::string_to_ip(std::string(argv[2]), dst)) {
    std::cerr << "Failed to parse destination IP\n";
    return -1;
  }

  std::cout << "ARPING " << util::ip_to_string(dst) << " from "
            << util::ip_to_string(src) << " " << device.name << "\n";

  req_once(id);
  boost::asio::deadline_timer timer(core::get().io_context);
  timer.expires_from_now(boost::posix_time::seconds(1));
  timer.async_wait([&](auto ec) { timer_handler(id, ec, timer); });

  eth::set_frame_receive_callback(eth::ethertype_broker_callback);
  return core::get().run();
}