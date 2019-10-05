#include "arp.h"
#include "core.h"
#include "device.h"
#include "util.h"

#include <boost/endian/conversion.hpp>

namespace khtcp {
namespace arp {

device::read_handler_t wrap_read_handler(read_handler_t handler) {
  return [=](int dev_id, uint16_t ethertype, const uint8_t *packet_ptr,
             int packet_len) -> bool {
    if (ethertype != arp::ethertype) {
      return false;
    }
    auto hdr = (arp_header_t *)packet_ptr;
    auto &name = device::get_device_handle(0).name;
    BOOST_LOG_TRIVIAL(trace) << "Received ARP packet on device " << name;
    auto opcode = boost::endian::endian_reverse(hdr->opcode);
    auto hw_type = boost::endian::endian_reverse(hdr->hardware_type);
    auto proto_type = boost::endian::endian_reverse(hdr->protocol_type);
    if (hw_type != 0x1) { // Ethernet
      BOOST_LOG_TRIVIAL(warning) << "Unsupported ARP hardware type " << hw_type
                                 << " on device " << name;
      return false;
    }
    if (proto_type != 0x0800) { // IPv4
      BOOST_LOG_TRIVIAL(warning) << "Unsupported ARP protocol type "
                                 << proto_type << " on device " << name;
      return false;
    }
    if (hdr->hardware_size != sizeof(eth::addr)) {
      BOOST_LOG_TRIVIAL(warning) << "ARP hardware size mismatch";
      return false;
    }
    if (hdr->protocol_size != sizeof(ip::addr)) {
      BOOST_LOG_TRIVIAL(warning) << "ARP protocol size mismatch";
      return false;
    }
    auto sender_mac = (uint8_t *)packet_ptr + sizeof(arp_header_t);
    auto sender_ip = sender_mac + sizeof(eth::addr);
    auto target_mac = sender_ip + sizeof(ip::addr);
    auto target_ip = target_mac + sizeof(eth::addr);

    return handler(dev_id, opcode, (eth::addr *)sender_mac,
                   (ip::addr *)sender_ip, (eth::addr *)target_mac,
                   (ip::addr *)target_ip);
  };
}

// reply ARP on receiving request
bool default_handler(int dev_id, uint16_t opcode, const eth::addr *sender_mac,
                     const ip::addr *sender_ip, const eth::addr *target_mac,
                     const ip::addr *target_ip) {
  bool ret = false;
  auto &device = device::get_device_handle(dev_id);
  if (opcode == 0x1) { // request
    for (const auto &ip : device.ip_addrs) {
      if (!memcmp(ip->data, target_ip->data, sizeof(ip::addr))) {
        async_write_arp(dev_id, 0x2, device.addr.get().get(), ip.get().get(),
                        sender_mac, sender_ip, [](int dev_id, int ret) {
                          if (ret != PCAP_ERROR) {
                            BOOST_LOG_TRIVIAL(trace)
                                << "Sent ARP reply on device "
                                << device::get_device_handle(dev_id).name;
                          }
                        });
        ret = true;
      }
    }
  }
  boost::asio::post(core::get().io_context, [=]() {
    device::get_device_handle(dev_id).read_handlers.push_back(
        wrap_read_handler(default_handler));
  });
  return ret;
}

void start(int dev_id) {
  boost::asio::post(device::get_device_handle(dev_id).read_handlers_strand,
                    [=]() {
                      device::get_device_handle(dev_id).read_handlers.push_back(
                          wrap_read_handler(default_handler));
                    });
}

void async_read_arp(int dev_id, read_handler_t &&handler) {
  boost::asio::post(
      device::get_device_handle(dev_id).read_handlers_strand, [=]() {
        auto &device = device::get_device_handle(dev_id);
        device.read_handlers.push_back(wrap_read_handler(handler));
        BOOST_LOG_TRIVIAL(trace)
            << "ARP read handler queued on device " << device.name;
      });
}

void async_write_arp(int dev_id, uint16_t opcode, const eth::addr *sender_mac,
                     const ip::addr *sender_ip, const eth::addr *target_mac,
                     const ip::addr *target_ip, write_handler_t &&handler) {
  auto packet_len =
      sizeof(arp_header_t) + 2 * sizeof(eth::addr) + 2 * sizeof(ip::addr);
  auto packet_buf = core::get_allocator<uint8_t>().allocate(packet_len);
  auto hdr = (arp_header_t *)packet_buf.get();
  hdr->hardware_type = boost::endian::endian_reverse((uint16_t)0x1);
  hdr->protocol_type = boost::endian::endian_reverse((uint16_t)0x0800);
  hdr->opcode = boost::endian::endian_reverse(opcode);
  hdr->hardware_size = sizeof(eth::addr);
  hdr->protocol_size = sizeof(ip::addr);

  auto smac = packet_buf + sizeof(arp_header_t);
  auto sip = smac + sizeof(eth::addr);
  auto tmac = sip + sizeof(ip::addr);
  auto tip = tmac + sizeof(eth::addr);

  memcpy(tmac.get(), target_mac->data, sizeof(eth::addr));
  memcpy(smac.get(), sender_mac->data, sizeof(eth::addr));
  memcpy(tip.get(), target_ip->data, sizeof(ip::addr));
  memcpy(sip.get(), sender_ip->data, sizeof(ip::addr));

  BOOST_LOG_TRIVIAL(trace) << "Sending ARP packet on device "
                           << device::get_device_handle(dev_id).name;
  eth::async_send_frame(packet_buf.get(), packet_len, arp::ethertype,
                        target_mac, dev_id, [=](int ret) {
                          handler(dev_id, ret);
                          core::get_allocator<uint8_t>().deallocate(packet_buf,
                                                                    packet_len);
                        });
}

} // namespace arp
} // namespace khtcp