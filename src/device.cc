#include "device.h"
#include "arp.h"
#include "core.h"
#include "packetio.h"
#include "util.h"

#include <boost/assert.hpp>
#include <cerrno>
#include <cstdio>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <vector>

namespace khtcp {
namespace device {

int device_t::start_capture() {
  char error_buffer[PCAP_ERRBUF_SIZE];
  BOOST_LOG_TRIVIAL(info) << "Opening capture on " << name;
  pcap_handle = pcap_open_live(name.c_str(), CAPTURE_BUFSIZ, false,
                               PACKET_TIMEOUT, error_buffer);
  if (!pcap_handle) {
    delete trigger;
    trigger = nullptr;
    BOOST_LOG_TRIVIAL(error) << "Failed to open device: " << error_buffer;
    return -1;
  }
  if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
    BOOST_LOG_TRIVIAL(error)
        << "Device " << name << " does not support EN10MB capturing";
    return -1;
  }

  trigger = new boost::asio::posix::stream_descriptor(
      core::get().io_context, dup(pcap_get_selectable_fd(pcap_handle)));

  // start the task
  trigger->async_read_some(boost::asio::null_buffers(),
                           [this](auto ec, auto s) { this->handle_sniff(); });

  return 0;
}

device_t::device_t() : inject_strand(core::get().io_context) {}

device_t::~device_t() {
  for (auto &ip : ip_addrs) {
    delete[] ip;
  }
  if (trigger) {
    trigger->close();
    delete trigger;
  }
  if (pcap_handle) {
    pcap_close(pcap_handle);
  }
}

void device_t::handle_sniff() {
  pcap_pkthdr hdr;
  auto pkt = pcap_next(pcap_handle, &hdr);
  BOOST_LOG_TRIVIAL(trace) << "Captured frame of length " << hdr.len
                           << " from device " << name << ", caplen "
                           << hdr.caplen;

  // invoke upper handler
  auto callback = eth::get_frame_receive_callback();
  if (callback) {
    if ((*callback)(pkt, hdr.len, id)) {
      BOOST_LOG_TRIVIAL(error) << "Frame receive callback failed";
      return;
    }

    // recharge the task
    trigger->async_read_some(boost::asio::null_buffers(),
                             [this](auto ec, auto s) { this->handle_sniff(); });
  } else {
    BOOST_LOG_TRIVIAL(fatal) << "Frame receive callback unset";
  }
}

int device_t::inject_frame(const uint8_t *buf, size_t len) {
  BOOST_LOG_TRIVIAL(trace) << "Sending frame with length " << len
                           << " on device " << name;
  return pcap_sendpacket(pcap_handle, buf, len);
}

void device_t::async_inject_frame(const uint8_t *buf, size_t len,
                                  write_handler_t &&handler) {
  boost::asio::post(inject_strand,
                    [=]() { handler(this->inject_frame(buf, len)); });
}

int add_device(const char *device) {
  int ret = -1;
  ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == -1) {
    BOOST_LOG_TRIVIAL(error) << "getifaddrs failed: " << strerror(errno);
    return ret;
  } else {
    for (ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr)
        continue;
      if ((!device && strcmp(ifa->ifa_name, "lo")) ||
          (device && !strcmp(ifa->ifa_name, device))) {
        // add all devices except lo if device==nullptr
        switch (ifa->ifa_addr->sa_family) {
        case AF_PACKET: {
          auto s = (sockaddr_ll *)ifa->ifa_addr;
          auto new_device = std::make_shared<device_t>();
          new_device->name = std::string(ifa->ifa_name);
          BOOST_ASSERT_MSG(s->sll_halen == 6, "Unexpected addr length");
          memcpy(new_device->addr, s->sll_addr, sizeof(eth::addr_t));
          new_device->id = core::get().devices.size();
          core::get().devices.push_back(new_device);
          BOOST_LOG_TRIVIAL(info)
              << "Found requested device " << ifa->ifa_name << "("
              << util::mac_to_string(new_device->addr)
              << ") as id=" << new_device->id;

          if (new_device->start_capture() == 0) {
            ret = new_device->id;

            // start the per-device auto-answering protocol stacks.
            arp::start(ret);
          }
          break;
        }
        case AF_INET: {
          auto s = (sockaddr_in *)ifa->ifa_addr;
          if (ret == -1) {
            continue;
          }
          int dev_id = find_device(ifa->ifa_name);
          auto &device = get_device_handle(dev_id);
          auto ip = new uint8_t[sizeof(ip::addr_t)];
          memcpy(ip, &s->sin_addr.s_addr, sizeof(ip::addr_t));
          device.ip_addrs.push_back(ip);
          BOOST_LOG_TRIVIAL(info)
              << "Added IP address " << util::ip_to_string(ip) << " to device "
              << device.name;

          // add route for subnet
          ip::route r;
          r.dev_id = dev_id;
          r.prefix = util::mask_to_cidr(
              ((const struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr);
          r.age = -1; // never expires
          memset(r.dst, 0, sizeof(ip::addr_t));
          memcpy(r.dst, &s->sin_addr.s_addr, r.prefix / 8);

          BOOST_LOG_TRIVIAL(info)
              << "Added device route " << util::ip_to_string(r.dst) << "/"
              << (int)r.prefix << " dev " << device.name << " metric "
              << r.metric;
          ip::add_route(std::move(r));
          break;
        }
        }
      }
    }
  }
  if (ret == -1) {
    BOOST_LOG_TRIVIAL(error) << "Device " << device << " not found";
  }
  freeifaddrs(ifaddr);
  return ret;
}

int find_device(const char *device) {
  for (int i = 0; i < core::get().devices.size(); ++i) {
    if (core::get().devices[i]->name == device) {
      return i;
    }
  }
  BOOST_LOG_TRIVIAL(error) << "Device " << device << " not found";
  return -1;
}

device_t &get_device_handle(int id) { return *core::get().devices.at(id); }
} // namespace device
} // namespace khtcp