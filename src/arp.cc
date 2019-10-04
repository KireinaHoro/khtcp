#include "arp.h"
#include "device.h"
#include "util.h"

#include <boost/endian/conversion.hpp>

namespace khtcp {
namespace arp {

// reply ARP on receiving request
void default_handler(int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                     ip::addr_t sender_ip, eth::addr_t target_mac,
                     ip::addr_t target_ip) {
  if (opcode == 0x1) { // request
    auto &device = device::get_device_handle(dev_id);
    for (const auto &ip : device.ip_addrs) {
      if (!memcmp(ip, target_ip, sizeof(ip::addr_t))) {
        async_write_arp(dev_id, 0x2, device.addr, ip, sender_mac, sender_ip,
                        [](int dev_id, int ret) {
                          if (ret != PCAP_ERROR) {
                            BOOST_LOG_TRIVIAL(trace)
                                << "Sent ARP reply on device "
                                << device::get_device_handle(dev_id).name;
                          }
                        });
        return;
      }
    }
  }
}

void broker(int dev_id, const uint8_t *packet_ptr) {
  auto hdr = (arp_header_t *)packet_ptr;
  auto &name = device::get_device_handle(0).name;
  BOOST_LOG_TRIVIAL(trace) << "Received ARP packet on device " << name;
  auto opcode = boost::endian::endian_reverse(hdr->opcode);
  auto hw_type = boost::endian::endian_reverse(hdr->hardware_type);
  auto proto_type = boost::endian::endian_reverse(hdr->protocol_type);
  if (hw_type != 0x1) { // Ethernet
    BOOST_LOG_TRIVIAL(warning)
        << "Unsupported ARP hardware type " << hw_type << " on device " << name;
    return;
  }
  if (proto_type != 0x0800) { // IPv4
    BOOST_LOG_TRIVIAL(warning) << "Unsupported ARP protocol type " << proto_type
                               << " on device " << name;
    return;
  }
  if (hdr->hardware_size != sizeof(eth::addr_t)) {
    BOOST_LOG_TRIVIAL(warning) << "ARP hardware size mismatch";
    return;
  }
  if (hdr->protocol_size != sizeof(ip::addr_t)) {
    BOOST_LOG_TRIVIAL(warning) << "ARP protocol size mismatch";
    return;
  }
  auto sender_mac = (uint8_t *)packet_ptr + sizeof(arp_header_t);
  auto sender_ip = sender_mac + sizeof(eth::addr_t);
  auto target_mac = sender_ip + sizeof(ip::addr_t);
  auto target_ip = target_mac + sizeof(eth::addr_t);

  // run all handlers
  auto &handler_queue = device::get_device_handle(dev_id).arp_handlers;
  while (!handler_queue.empty()) {
    handler_queue.front()(dev_id, opcode, sender_mac, sender_ip, target_mac,
                          target_ip);
    handler_queue.pop();
  }
  // default behavior
  default_handler(dev_id, opcode, sender_mac, sender_ip, target_mac, target_ip);
}

void async_read_arp(int dev_id, read_handler_t &&handler) {
  boost::asio::post(
      device::get_device_handle(dev_id).arp_handlers_strand, [=]() {
  auto &device = device::get_device_handle(dev_id);
    device.arp_handlers.push(handler);
    BOOST_LOG_TRIVIAL(trace)
        << "ARP read handler queued on device " << device.name;
  });
}

void async_write_arp(int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                     ip::addr_t sender_ip, eth::addr_t target_mac,
                     ip::addr_t target_ip, write_handler_t &&handler) {
  auto packet_len =
      sizeof(arp_header_t) + 2 * sizeof(eth::addr_t) + 2 * sizeof(ip::addr_t);
  auto packet_buf = new uint8_t[packet_len];
  auto hdr = (arp_header_t *)packet_buf;
  hdr->hardware_type = boost::endian::endian_reverse(0x1);
  hdr->protocol_type = boost::endian::endian_reverse(0x0800);
  hdr->opcode = boost::endian::endian_reverse(opcode);
  hdr->hardware_size = sizeof(eth::addr_t);
  hdr->protocol_size = sizeof(ip::addr_t);

  auto smac = packet_buf + sizeof(eth::addr_t);
  auto sip = smac + sizeof(eth::addr_t);
  auto tmac = sip + sizeof(ip::addr_t);
  auto tip = tmac + sizeof(eth::addr_t);

  memcpy(tmac, target_mac, sizeof(eth::addr_t));
  memcpy(smac, sender_mac, sizeof(eth::addr_t));
  memcpy(tip, target_ip, sizeof(ip::addr_t));
  memcpy(sip, sender_ip, sizeof(ip::addr_t));

  eth::async_send_frame(packet_buf, packet_len, arp::ethertype, target_mac,
                        dev_id, [=](int ret) { handler(dev_id, ret); });
}

} // namespace arp
} // namespace khtcp