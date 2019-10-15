#include <boost/bind.hpp>
#include <csignal>
#include <memory>

#include "arp.h"
#include "core.h"
#include "packetio.h"
#include "util.h"

namespace khtcp {
namespace core {
static core _core;

void signal_handler(int sig) { get().io_context.stop(); }

core::core()
    : acceptor(io_context,
               boost::asio::local::stream_protocol::endpoint(SERVER_ENDPOINT)),
      arp_table_timer(io_context) {
  std::signal(SIGTERM, signal_handler);
  std::signal(SIGINT, signal_handler);
}

core &get() { return _core; }

void client_request_handler(const boost::system::error_code &ec,
                            int bytes_transferred, int client_id) try {
  if (!ec) {
    auto &client = get().clients.at(client_id);
    auto &sock = *client.first;
    auto &req = client.second;
    struct response *resp = (struct response *)malloc(sizeof(struct response));
    auto buf = boost::asio::buffer(resp, sizeof(*resp));

    resp->type = req.type;
    resp->id = req.id;

    BOOST_LOG_TRIVIAL(trace) << "Received request #" << req.id << " of type "
                             << req.type << " from client id " << client_id;

    switch (req.type) {
    case FIND_DEVICE:
      resp->payload_len = 0;
      resp->find_device.dev_id = device::find_device(req.find_device.name);
      boost::asio::write(sock, buf);
      free(resp);
      break;
    case GET_DEVICE_MAC:
      resp->payload_len = 0;
      resp->get_device_mac.mac.sll_halen = 6;
      memcpy(&resp->get_device_mac.mac.sll_addr,
             device::get_device_handle(req.get_device_mac.dev_id).addr,
             sizeof(eth::addr_t));
      boost::asio::write(sock, buf);
      free(resp);
      break;
    case GET_DEVICE_IP: {
      auto &device = device::get_device_handle(req.get_device_ip.dev_id);
      resp->get_device_ip.count = device.ip_addrs.size();
      resp->payload_len =
          resp->get_device_ip.count * sizeof(struct sockaddr_in);
      struct sockaddr_in *payload_ptr =
          (struct sockaddr_in *)malloc(resp->payload_len);
      for (int i = 0; i < resp->get_device_ip.count; ++i) {
        memcpy(&payload_ptr[i].sin_addr, device.ip_addrs[i],
               sizeof(ip::addr_t));
        payload_ptr[i].sin_family = AF_INET;
      }
      boost::asio::write(sock, buf);
      boost::asio::write(sock,
                         boost::asio::buffer(payload_ptr, resp->payload_len));
      free(payload_ptr);
      free(resp);
      break;
    }
    case ETHERNET_READ:
      eth::async_read_frame(
          req.eth_read.dev_id,
          [buf, resp, &sock](int dev_id, uint16_t ethertype,
                             const uint8_t *packet_ptr, int len) -> bool {
            resp->payload_len = len;
            resp->eth_read.dev_id = dev_id;
            resp->eth_read.ethertype = ethertype;
            try {
              boost::asio::write(sock, buf);
              boost::asio::write(sock, boost::asio::buffer(packet_ptr, len));
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }

            free(resp);
            return true;
          });
      break;
    case ETHERNET_WRITE: {
      int dev_id = req.eth_read.dev_id;
      void *payload_ptr = malloc(req.payload_len);
      boost::asio::read(sock,
                        boost::asio::buffer(payload_ptr, req.payload_len));
      eth::async_write_frame(payload_ptr, req.payload_len,
                             req.eth_write.ethertype,
                             req.eth_write.mac.sll_addr, req.eth_write.dev_id,
                             [buf, resp, payload_ptr, dev_id, &sock](int ret) {
                               resp->payload_len = 0;
                               resp->eth_write.dev_id = dev_id;
                               try {
                                 boost::asio::write(sock, buf);
                               } catch (const std::exception &e) {
                                 BOOST_LOG_TRIVIAL(error)
                                     << "Exception in client handler: "
                                     << e.what();
                               }
                               free(payload_ptr);
                               free(resp);
                             });
      break;
    }
    case ARP_READ:
      arp::async_read_arp(
          req.arp_read.dev_id,
          [buf, resp, &sock](int dev_id, uint16_t opcode,
                             eth::addr_t sender_mac, ip::addr_t sender_ip,
                             eth::addr_t target_mac,
                             ip::addr_t target_ip) -> bool {
            resp->payload_len = 0;
            resp->arp_read.dev_id = dev_id;
            resp->arp_read.opcode = opcode;
            memcpy(resp->arp_read.sender_mac.sll_addr, sender_mac, 6);
            resp->arp_read.sender_mac.sll_halen = 6;
            memcpy(resp->arp_read.target_mac.sll_addr, target_mac, 6);
            resp->arp_read.target_mac.sll_halen = 6;
            memcpy(&resp->arp_read.sender_ip.sin_addr, sender_ip, 4);
            resp->arp_read.sender_ip.sin_family = AF_INET;
            memcpy(&resp->arp_read.target_ip.sin_addr, target_ip, 4);
            resp->arp_read.target_ip.sin_family = AF_INET;
            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }
            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            free(resp);
            return true;
          });
      break;
    case ARP_WRITE:
      arp::async_write_arp(req.arp_write.dev_id, req.arp_write.opcode,
                           req.arp_write.sender_mac.sll_addr,
                           (uint8_t *)&req.arp_write.sender_ip.sin_addr,
                           req.arp_write.target_mac.sll_addr,
                           (uint8_t *)&req.arp_write.target_ip.sin_addr,
                           [buf, resp, &sock](int dev_id, int ret) {
                             resp->payload_len = 0;
                             resp->arp_write.dev_id = dev_id;

                             try {
                               boost::asio::write(sock, buf);
                             } catch (const std::exception &e) {
                               BOOST_LOG_TRIVIAL(error)
                                   << "Exception in client handler: "
                                   << e.what();
                             }

                             BOOST_LOG_TRIVIAL(trace)
                                 << "Sent response #" << resp->id;
                             free(resp);
                           });
      break;
    case IP_READ:
      ip::async_read_ip(
          req.ip_read.dev_id, req.ip_read.proto,
          [buf, resp, &sock](int dev_id, const void *payload_ptr,
                             uint64_t payload_len, const khtcp::ip::addr_t src,
                             const khtcp::ip::addr_t dst, uint8_t dscp,
                             const void *opt) -> bool {
            resp->payload_len = payload_len;
            resp->ip_read.dev_id = dev_id;
            resp->ip_read.dscp = dscp;
            memcpy(&resp->ip_read.dst.sin_addr, dst, 4);
            resp->ip_read.dst.sin_family = AF_INET;
            memcpy(&resp->ip_read.src.sin_addr, src, 4);
            resp->ip_read.src.sin_family = AF_INET;

            try {
              boost::asio::write(sock, buf);
              BOOST_LOG_TRIVIAL(trace)
                  << "Sending payload with length " << payload_len;

              boost::asio::write(sock,
                                 boost::asio::buffer(payload_ptr, payload_len));
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }
            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            free(resp);
            return true;
          });
      break;
    case IP_WRITE: {
      void *payload_ptr = malloc(req.payload_len);
      boost::asio::read(sock,
                        boost::asio::buffer(payload_ptr, req.payload_len));
      ip::async_write_ip(
          req.ip_write.dev_id, (uint8_t *)&req.ip_write.src.sin_addr,
          (uint8_t *)&req.ip_write.dst.sin_addr, req.ip_write.proto,
          req.ip_write.dscp, req.ip_write.ttl, payload_ptr, req.payload_len,
          [buf, resp, payload_ptr, &sock](int dev_id, int ret) {
            resp->payload_len = 0;
            resp->ip_write.dev_id = dev_id;
            resp->ip_write.ret = ret;

            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }

            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            free(resp);
            free(payload_ptr);
          });
      break;
    }
    default:
      BOOST_LOG_TRIVIAL(warning)
          << "Unknown request " << req.type << " from client " << client_id;
    }
    BOOST_LOG_TRIVIAL(trace) << "Written response to client " << client_id;
    // fire the handler again
    boost::asio::async_read(
        *client.first,
        boost::asio::buffer(&client.second, sizeof(client.second)),
        boost::bind(client_request_handler, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred, client_id));
  } else {
    if (ec == boost::asio::error::eof) {
      BOOST_LOG_TRIVIAL(info) << "Client " << client_id << " disconnected.";
    } else {
      BOOST_LOG_TRIVIAL(warning) << "Client handler failed: " << ec.message();
    }
  }
} catch (const std::exception &e) {
  BOOST_LOG_TRIVIAL(error) << "Exception in client handler: " << e.what();
}

void new_client_handler(const boost::system::error_code &ec,
                        boost::asio::local::stream_protocol::socket &&sock) {
  auto id = rand();
  while (get().clients.find(id) != get().clients.end()) {
    id = rand();
  }

  BOOST_LOG_TRIVIAL(info) << "Accpeted new client with id " << id;
  get().clients[id].first =
      std::make_unique<boost::asio::local::stream_protocol::socket>(
          std::move(sock));

  auto &client = get().clients[id];
  // start reading of the client
  boost::asio::async_read(
      *client.first, boost::asio::buffer(&client.second, sizeof(client.second)),
      boost::bind(client_request_handler, boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred, id));

  // start accepting new client
  get().acceptor.async_accept(new_client_handler);
}

int core::run() {
  srand((unsigned)time(nullptr));
  acceptor.async_accept(new_client_handler);

  io_context.run();
  // should never reach here
  return -1;
}
} // namespace core
} // namespace khtcp