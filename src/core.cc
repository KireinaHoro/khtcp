#include <boost/bind.hpp>
#include <csignal>
#include <iomanip>
#include <iostream>

#include "arp.h"
#include "core.h"
#include "packetio.h"
#include "rip.h"
#include "tcp.h"
#include "udp.h"
#include "util.h"

namespace khtcp {
namespace core {
static core _core;

void signal_handler(int sig) { get().io_context.stop(); }

using namespace std::string_literals;

core::core()
    : acceptor(io_context, boost::asio::local::stream_protocol::endpoint(
                               "\0khtcp-server"s)),
      per_second_timer(io_context), read_handlers_strand(io_context),
      write_tasks_strand(io_context) {
  std::signal(SIGTERM, signal_handler);
  std::signal(SIGINT, signal_handler);
}

core &get() { return _core; }

void client_request_handler(const boost::system::error_code &ec,
                            int bytes_transferred, int client_id) try {
  if (!ec) {
    auto &client = get().clients.at(client_id);
    auto &sock = client.first;
    auto &req = client.second;
    struct response *resp = (struct response *)malloc(sizeof(struct response));
    get().outstanding_buffers.emplace(client_id, resp);
    auto buf = boost::asio::buffer(resp, sizeof(*resp));

    resp->type = req->type;
    resp->id = req->id;

    BOOST_LOG_TRIVIAL(trace) << "Received request #" << req->id << " of type "
                             << req->type << " from client id " << client_id;

    switch (req->type) {
    case FIND_DEVICE: {
      resp->payload_len = 0;
      resp->find_device.dev_id = device::find_device(req->find_device.name);
      boost::asio::write(sock, buf);
      CLEANUP_BUF(resp, req)
      break;
    }
    case GET_DEVICE_MAC: {
      resp->payload_len = 0;
      resp->get_device_mac.mac.sll_halen = 6;
      memcpy(&resp->get_device_mac.mac.sll_addr,
             device::get_device_handle(req->get_device_mac.dev_id).addr,
             sizeof(eth::addr_t));
      boost::asio::write(sock, buf);
      CLEANUP_BUF(resp, req)
      break;
    }
    case GET_DEVICE_IP: {
      auto &device = device::get_device_handle(req->get_device_ip.dev_id);
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
      CLEANUP_BUF(resp, req)
      break;
    }
    case ETHERNET_READ:
      eth::async_read_frame(
          req->eth_read.dev_id,
          [buf, resp, req, &sock, client_id](int dev_id, uint16_t ethertype,
                                             const uint8_t *packet_ptr,
                                             int len) -> bool {
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
            CLEANUP_BUF(resp, req)
            return true;
          },
          client_id);
      break;
    case ETHERNET_WRITE: {
      int dev_id = req->eth_read.dev_id;
      void *payload_ptr = malloc(req->payload_len);
      boost::asio::read(sock,
                        boost::asio::buffer(payload_ptr, req->payload_len));
      eth::async_write_frame(
          payload_ptr, req->payload_len, req->eth_write.ethertype,
          req->eth_write.mac.sll_addr, req->eth_write.dev_id,
          [buf, resp, req, payload_ptr, dev_id, &sock, client_id](int ret) {
            resp->payload_len = 0;
            resp->eth_write.dev_id = dev_id;
            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }
            free(payload_ptr);
            CLEANUP_BUF(resp, req)
          },
          client_id);
      break;
    }
    case ARP_READ:
      arp::async_read_arp(
          req->arp_read.dev_id,
          [buf, resp, req, &sock,
           client_id](int dev_id, uint16_t opcode, eth::addr_t sender_mac,
                      ip::addr_t sender_ip, eth::addr_t target_mac,
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
            CLEANUP_BUF(resp, req)
            return true;
          },
          client_id);
      break;
    case ARP_WRITE:
      arp::async_write_arp(
          req->arp_write.dev_id, req->arp_write.opcode,
          req->arp_write.sender_mac.sll_addr,
          (uint8_t *)&req->arp_write.sender_ip.sin_addr,
          req->arp_write.target_mac.sll_addr,
          (uint8_t *)&req->arp_write.target_ip.sin_addr,
          [buf, resp, req, &sock, client_id](int dev_id, int ret) {
            resp->payload_len = 0;
            resp->arp_write.dev_id = dev_id;

            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }

            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            CLEANUP_BUF(resp, req)
          },
          client_id);
      break;
    case IP_READ:
      ip::async_read_ip(
          req->ip_read.proto,
          [buf, resp, req, &sock,
           client_id](const void *payload_ptr, uint64_t payload_len,
                      const khtcp::ip::addr_t src, const khtcp::ip::addr_t dst,
                      uint8_t dscp, const void *opt) -> bool {
            resp->payload_len = payload_len;
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
            CLEANUP_BUF(resp, req)
            return true;
          },
          client_id);
      break;
    case IP_WRITE: {
      void *payload_ptr = malloc(req->payload_len);
      boost::asio::read(sock,
                        boost::asio::buffer(payload_ptr, req->payload_len));
      ip::async_write_ip(
          (uint8_t *)&req->ip_write.src.sin_addr,
          (uint8_t *)&req->ip_write.dst.sin_addr, req->ip_write.proto,
          req->ip_write.dscp, req->ip_write.ttl, payload_ptr, req->payload_len,
          [buf, resp, req, payload_ptr, &sock, client_id](int ret) {
            resp->payload_len = 0;
            resp->ip_write.ret = ret;

            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }

            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            CLEANUP_BUF(resp, req)
            free(payload_ptr);
          },
          client_id);
      break;
    }
    case SOCKET: {
      socket::socket s(client_id, req->socket.type);
      resp->payload_len = 0;
      if (s.type == SOCK_DGRAM) {
        resp->socket.fd = s.fd;
        BOOST_LOG_TRIVIAL(trace)
            << "Opened DGRAM socket fd " << s.fd << " for client " << client_id;
        get().client_sockets.emplace(std::piecewise_construct,
                                     std::forward_as_tuple(client_id, s.fd),
                                     std::forward_as_tuple(std::move(s)));
      } else if (s.type == SOCK_STREAM) {
        resp->socket.fd = -ENOTSUP;
        BOOST_LOG_TRIVIAL(error)
            << "Client " << client_id
            << " tried to open STREAM socket, which is currently not supported";
      } else {
        resp->socket.fd = -EINVAL;
        BOOST_LOG_TRIVIAL(error)
            << "Client " << client_id << " tried to open unknown socket type "
            << s.type;
      }
      boost::asio::write(sock, buf);
      CLEANUP_BUF(resp, req)
      break;
    }
    case CLOSE: {
      resp->payload_len = 0;
      // https://pubs.opengroup.org/onlinepubs/9699919799/functions/close.html
      // FIXME: note that close may fail
      resp->close.ret = 0;

      get().client_sockets.erase({client_id, req->close.fd});
      BOOST_LOG_TRIVIAL(trace) << "Closed socket fd " << req->close.fd
                               << " for client " << client_id;
      boost::asio::write(sock, buf);
      CLEANUP_BUF(resp, req)
      break;
    }
    case BIND: {
      resp->payload_len = 0;
      // https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html

      bool ok = true;
      if (get().client_sockets.find({client_id, req->bind.fd}) ==
          get().client_sockets.end()) {
        BOOST_LOG_TRIVIAL(error)
            << "Client " << client_id
            << " tried to bind to non-existent socket fd " << req->bind.fd;
        ok = false;
        resp->bind.ret = ENOTSOCK;
      }
      for (const auto &[k, v] : get().client_sockets) {
        if (k.first == client_id) {
          if (v.bind_addr.sin_addr.s_addr == req->bind.addr.sin_addr.s_addr &&
              v.bind_addr.sin_port == req->bind.addr.sin_port) {
            BOOST_LOG_TRIVIAL(error)
                << "Client " << client_id
                << " tried to bind to address already in use ("
                << util::ip_to_string((const uint8_t *)&req->bind.addr.sin_addr)
                << ":" << ntohs(req->bind.addr.sin_port) << ") for socket fd "
                << req->bind.fd;
            ok = false;
            resp->bind.ret = EADDRINUSE;
          }
        }
      }
      if (ok) {
        memcpy(&get().client_sockets.at({client_id, req->bind.fd}).bind_addr,
               &req->bind.addr, sizeof(struct sockaddr_in));
        resp->bind.ret = 0;

        BOOST_LOG_TRIVIAL(trace)
            << "Client " << client_id << " binded "
            << util::ip_to_string((const uint8_t *)&req->bind.addr.sin_addr)
            << ":" << ntohs(req->bind.addr.sin_port) << " to socket fd "
            << req->bind.fd;
      }
      boost::asio::write(sock, buf);
      CLEANUP_BUF(resp, req)
      break;
    }
    case SENDTO: {
      void *payload_ptr = malloc(req->payload_len);
      boost::asio::read(sock,
                        boost::asio::buffer(payload_ptr, req->payload_len));

      resp->payload_len = 0;
      auto it = get().client_sockets.find({client_id, req->sendto.fd});
      if (it == get().client_sockets.end() || it->second.type != SOCK_DGRAM) {
        resp->sendto.ret = -ENOTSOCK;
        BOOST_LOG_TRIVIAL(error)
            << "Client " << client_id
            << " tried to send to invalid DGRAM socket fd " << req->sendto.fd;
        boost::asio::write(sock, buf);
        CLEANUP_BUF(resp, req);
        break;
      }
      const uint8_t *src;
      uint16_t port;
      it->second.get_src((const uint8_t *)&req->sendto.dst.sin_addr, &src,
                         &port);
      udp::async_write_udp(
          src, port, (const uint8_t *)&req->sendto.dst.sin_addr,
          ntohs(req->sendto.dst.sin_port), payload_ptr, req->payload_len,
          [buf, resp, req, payload_ptr, &sock](int ret) {
            resp->sendto.ret = req->payload_len;
            try {
              boost::asio::write(sock, buf);
            } catch (const std::exception &e) {
              BOOST_LOG_TRIVIAL(error)
                  << "Exception in client handler: " << e.what();
            }
            BOOST_LOG_TRIVIAL(trace) << "Sent response #" << resp->id;
            CLEANUP_BUF(resp, req)
            free(payload_ptr);
          },
          client_id);
      break;
    }
    case RECVFROM: {
      auto it = get().client_sockets.find({client_id, req->recvfrom.fd});
      if (it == get().client_sockets.end() || it->second.type != SOCK_DGRAM) {
        resp->recvfrom.ret = -ENOTSOCK;
        BOOST_LOG_TRIVIAL(error)
            << "Client " << client_id
            << " tried to recv from invalid DGRAM socket fd " << req->sendto.fd;
        boost::asio::write(sock, buf);
        CLEANUP_BUF(resp, req);
        break;
      }
      BOOST_LOG_TRIVIAL(trace)
          << "Received recvfrom request from client with ID " << req->id;
      udp::async_read_udp(
          [it, buf, resp, req, &sock,
           client_id](const void *payload_ptr, uint64_t payload_len,
                      const khtcp::ip::addr_t src, uint16_t src_port,
                      const khtcp::ip::addr_t dst, uint16_t dst_port) -> bool {
            BOOST_LOG_TRIVIAL(trace) << "Got UDP packet from port " << src_port
                                     << " to port " << dst_port;
            if (it->second.bind_addr.sin_family == AF_INET &&
                (memcmp(&it->second.bind_addr.sin_addr, dst,
                        sizeof(ip::addr_t)) ||
                 dst_port != ntohs(it->second.bind_addr.sin_port))) {
              BOOST_LOG_TRIVIAL(trace)
                  << "Bound socket mismatch with destination: expected "
                  << util::ip_to_string(
                         (uint8_t *)&it->second.bind_addr.sin_addr)
                  << ":" << ntohs(it->second.bind_addr.sin_port) << ", got "
                  << util::ip_to_string(dst) << ":" << dst_port;
              return false;
            }
            resp->payload_len = payload_len;
            resp->recvfrom.ret = payload_len;
            resp->recvfrom.src.sin_family = AF_INET;
            memcpy(&resp->recvfrom.src.sin_addr, src, sizeof(ip::addr_t));
            resp->recvfrom.src.sin_port = htons(src_port);

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
            CLEANUP_BUF(resp, req)
            return true;
          },
          client_id);
      break;
    }
    default:
      BOOST_LOG_TRIVIAL(warning)
          << "Unknown request " << req->type << " from client " << client_id;
      CLEANUP_BUF(resp, req)
    }
    BOOST_LOG_TRIVIAL(trace) << "Written response to client " << client_id;
    // fire the handler again

    client.second = (struct request *)malloc(sizeof(struct request));
    get().outstanding_buffers.emplace(client_id, client.second);
    boost::asio::async_read(
        client.first,
        boost::asio::buffer(client.second, sizeof(struct request)),
        boost::bind(client_request_handler, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred, client_id));
  } else {
    if (ec == boost::asio::error::eof) {
      BOOST_LOG_TRIVIAL(debug) << "Client " << client_id << " disconnected.";
    } else {
      BOOST_LOG_TRIVIAL(warning) << "Client handler failed: " << ec.message();
    }
    BOOST_LOG_TRIVIAL(trace) << "Cleaning up client " << client_id;
    cleanup_client(client_id);
  }
} catch (const std::exception &e) {
  BOOST_LOG_TRIVIAL(error) << "Exception in client handler: " << e.what();
}

void new_client_handler(const boost::system::error_code &ec,
                        boost::asio::local::stream_protocol::socket &&sock) {
  auto id = rand();
  // ensure that the id is non-zero - 0 is for local call
  while (!id) {
    id = rand();
  }
  while (get().clients.find(id) != get().clients.end()) {
    id = rand();
  }

  BOOST_LOG_TRIVIAL(debug) << "Accpeted new client with id " << id;
  get().clients.emplace(std::piecewise_construct, std::forward_as_tuple(id),
                        std::forward_as_tuple(std::move(sock), nullptr));

  auto &client = get().clients.at(id);
  client.second = (struct request *)malloc(sizeof(struct request));
  get().outstanding_buffers.emplace(id, client.second);
  // start reading of the client
  boost::asio::async_read(
      client.first, boost::asio::buffer(client.second, sizeof(struct request)),
      boost::bind(client_request_handler, boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred, id));

  // start accepting new client
  get().acceptor.async_accept(new_client_handler);
}

void cleanup_client(int client_id) {
  auto &wq = get().write_tasks;
  auto it = wq.begin();
  while (it != wq.end()) {
    if (it->second == client_id) {
      wq.erase(it++);
      BOOST_LOG_TRIVIAL(trace)
          << "Removed pending write task for client " << client_id;
    } else {
      ++it;
    }
  }
  auto &rq = get().read_handlers;
  auto rit = rq.begin();
  while (rit != rq.end()) {
    if (rit->second == client_id) {
      rq.erase(rit++);
      BOOST_LOG_TRIVIAL(trace)
          << "Removed pending read handler for client " << client_id;
    } else {
      ++rit;
    }
  }
  auto bit = get().outstanding_buffers.find(client_id);
  while (bit != get().outstanding_buffers.end()) {
    free(bit->second);
    get().outstanding_buffers.erase(bit);
    bit = get().outstanding_buffers.find(client_id);
  }
  get().clients.erase(client_id);

  // close all client sockets
  auto sit = get().client_sockets.begin();
  while (sit != get().client_sockets.end()) {
    if (sit->first.first == client_id) {
      get().client_sockets.erase(sit++);
    } else {
      ++sit;
    }
  }
}

void per_second_tasks(const boost::system::error_code &ec) {
  static uint32_t counter = 0;
  if (!ec) {
    arp::scan_arp_table();
    ip::update_route();
    if (counter % 30 == 0) {
      for (int i = 0; i < get().devices.size(); ++i) {
        rip::send_fulltable(device::get_device_handle(i).ip_addrs[0], rip::port,
                            rip::RIP_MULTICAST, rip::port);
      }
    }
    if (counter % 30 == 2) {
      // shift from the unsolicited response of RIP
      ip::print_route();
    }
    ++counter;
    // fire a new round
    auto &timer = get().per_second_timer;
    timer.expires_from_now(boost::posix_time::seconds(1));
    timer.async_wait(per_second_tasks);
  } else {
    BOOST_LOG_TRIVIAL(error)
        << "Per-second timer for periodic tasks failed with message: "
        << ec.message();
  }
}

void record_multicast_buffer(void *buf) {
  get().multicast_buffers[buf] = get().devices.size();
}

int core::run() {
  srand((unsigned)time(nullptr));
  acceptor.async_accept(new_client_handler);

  // start the write tasks handler
  std::function<void()> write_task_executor = [&]() {
    auto &wq = get().write_tasks;
    auto it = wq.begin();
    if (wq.empty()) {
      static boost::asio::deadline_timer t(get().io_context);
      t.expires_from_now(boost::posix_time::milliseconds(1));
      t.async_wait([&](const auto &ec) {
        boost::asio::post(get().write_tasks_strand, write_task_executor);
      });
    } else {
      while (it != wq.end()) {
        it->first();
        wq.erase(it);
        break;
        ++it;
      }
      boost::asio::post(get().write_tasks_strand, write_task_executor);
    }
  };
  boost::asio::post(get().write_tasks_strand, write_task_executor);

  // start the tasks that are run per second
  auto &timer = get().per_second_timer;
  timer.expires_from_now(boost::posix_time::seconds(1));
  timer.async_wait(per_second_tasks);

  ip::start();
  rip::start();
  tcp::start();

  // Join RIPv2 multicast group
  ip::join_multicast(rip::RIP_MULTICAST);

  io_context.run();
  // should never reach here
  return -1;
} // namespace core
} // namespace core
} // namespace khtcp