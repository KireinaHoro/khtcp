#include "device.h"
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
  trigger = new boost::asio::posix::stream_descriptor(core::get().io_context);

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

  trigger->assign(dup(pcap_get_selectable_fd(pcap_handle)));

  // start the task
  trigger->async_read_some(boost::asio::null_buffers(),
                           [this](auto ec, auto s) { this->handle_sniff(); });

  return 0;
}

device_t::device_t() : inject_strand(core::get().io_context) {}

device_t::~device_t() {
  trigger->close();
  delete trigger;
  pcap_close(pcap_handle);
}

void device_t::handle_sniff() {
  pcap_pkthdr hdr;
  auto pkt = pcap_next(pcap_handle, &hdr);
  BOOST_LOG_TRIVIAL(trace) << "Captured frame of length " << hdr.len
                           << " from device " << name;

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
  return pcap_inject(pcap_handle, buf, len);
}

template <typename InjectHandler>
void device_t::async_inject_frame(const uint8_t *buf, size_t len,
                                  InjectHandler &&handler) {
  boost::asio::post(inject_strand,
                    [&]() { handler(this->inject_frame(buf, len)); });
}

static std::vector<std::shared_ptr<device_t>> devices;

int add_device(const char *device) {
  ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == -1) {
    BOOST_LOG_TRIVIAL(error) << "getifaddrs failed: " << strerror(errno);
    return -1;
  } else {
    for (ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
      auto s = (sockaddr_ll *)ifa->ifa_addr;
      auto addr_s = util::mac_to_string(s->sll_addr, s->sll_halen);
      BOOST_LOG_TRIVIAL(trace)
          << "Found device: " << ifa->ifa_name << "(" << addr_s << ")";
      if (!strcmp(ifa->ifa_name, device)) {
        auto new_device = std::make_shared<device_t>();
        new_device->name = std::string(ifa->ifa_name);
        BOOST_ASSERT_MSG(s->sll_halen == 6, "Unexpected addr length");
        memcpy(new_device->addr, s->sll_addr, 6);
        new_device->id = devices.size();
        devices.push_back(new_device);
        BOOST_LOG_TRIVIAL(info)
            << "Found requested device " << ifa->ifa_name << "(" << addr_s
            << ") as id=" << new_device->id;

        if (new_device->start_capture() == 0) {
          BOOST_LOG_TRIVIAL(info) << "Started new device";
          return new_device->id;
        } else {
          return -1;
        }
      }
    }
  }
  BOOST_LOG_TRIVIAL(error) << "Device " << device << " not found";
  return -1;
}

int find_device(const char *device) {
  for (int i = 0; i < devices.size(); ++i) {
    if (devices[i]->name == device) {
      return i;
    }
  }
  BOOST_LOG_TRIVIAL(error) << "Device " << device << " not found";
  return -1;
}

device_t &get_device_handle(int id) { return *devices.at(id); }
} // namespace device
} // namespace khtcp