#include <boost/asio.hpp>
#include <ifaddrs.h>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <netpacket/packet.h>

struct request {
  enum {
    ARP_READ,
    ARP_WRITE,
  } type;
  union {
    struct {
      int dev_id;
    } arp_read;
    struct {
      int dev_id;
      int opcode;
      struct sockaddr_ll sender_mac;
      struct sockaddr_in sender_ip;
      struct sockaddr_ll target_mac;
      struct sockaddr_in target_ip;
    } arp_write;
  };
};

void print_ll(struct sockaddr_ll &a) {
  for (int i = 0; i < a.sll_halen; ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)a.sll_addr[i];
    if (i != a.sll_halen - 1) {
      std::cout << ":";
    }
  }
}

#define ENDPOINT "/tmp/foobar.sock"

int main(int argc, char **argv) {
  using namespace boost::asio;
  io_context io;
  struct request req;
  if (argc == 1) {
    struct d {
      d() { ::unlink(ENDPOINT); }
      ~d() { ::unlink(ENDPOINT); }
    } dd;
    local::stream_protocol::endpoint ep(ENDPOINT);
    local::stream_protocol::acceptor acceptor(io, ep);
    acceptor.async_accept([&](auto ec, auto &&sock) {
      if (!ec) {
        async_read(sock, buffer(&req, sizeof(struct request)),
                   [&](auto ec, auto b) {
                     char str[INET_ADDRSTRLEN];
                     std::cout << "Sender MAC: ";
                     print_ll(req.arp_write.sender_mac);
                     std::cout << std::endl;
                     std::cout << "Sender IP: ";
                     inet_ntop(AF_INET, &req.arp_write.sender_ip, str,
                               INET_ADDRSTRLEN);
                     std::cout << str << std::endl;
                     std::cout << "Target MAC: ";
                     print_ll(req.arp_write.target_mac);
                     std::cout << std::endl;
                     std::cout << "Target IP: ";
                     inet_ntop(AF_INET, &req.arp_write.target_ip, str,
                               INET_ADDRSTRLEN);
                     std::cout << str << std::endl;
                   });
      } else {
        std::cerr << ec.message() << std::endl;
      }
    });
    io.run();
  } else {
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
      perror("getifaddrs");
      return -1;
    } else {
      char str[INET_ADDRSTRLEN];
      for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
          continue;
        if (!strcmp(ifa->ifa_name, "eth0")) {
          switch (ifa->ifa_addr->sa_family) {
          case AF_PACKET:
            memcpy(&req.arp_write.sender_mac, ifa->ifa_addr,
                   sizeof(struct sockaddr_ll));
            memcpy(&req.arp_write.target_mac, ifa->ifa_addr,
                   sizeof(struct sockaddr_ll));
            break;
          case AF_INET:
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
                      str, INET_ADDRSTRLEN);
            std::cout << str << std::endl;
            memcpy(&req.arp_write.sender_ip, ifa->ifa_addr,
                   sizeof(struct sockaddr_in));
            memcpy(&req.arp_write.target_ip, ifa->ifa_addr,
                   sizeof(struct sockaddr_in));
            break;
          }
        }
      }
      std::cout << "Sender MAC: ";
      print_ll(req.arp_write.sender_mac);
      std::cout << std::endl;
      std::cout << "Sender IP: ";
      inet_ntop(AF_INET, &req.arp_write.sender_ip, str, INET_ADDRSTRLEN);
      std::cout << str << std::endl;
      std::cout << "Target MAC: ";
      print_ll(req.arp_write.target_mac);
      std::cout << std::endl;
      std::cout << "Target IP: ";
      inet_ntop(AF_INET, &req.arp_write.target_ip, str, INET_ADDRSTRLEN);
      std::cout << str << std::endl;
      local::stream_protocol::endpoint ep(ENDPOINT);
      local::stream_protocol::socket sock(io);
      sock.async_connect(ep, [&](const auto &ec) {
        async_write(sock, buffer(&req, sizeof(struct request)),
                    [](auto ec, auto b) {
                      if (!ec) {
                        std::cout << "Request written." << std::endl;
                      } else {
                        std::cerr << ec.message() << std::endl;
                      }
                    });
      });
      io.run();
    }
  }
}