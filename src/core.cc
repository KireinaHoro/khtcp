#include "core.h"
#include "packetio.h"
#include "types.h"
#include "util.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <thread>

namespace khtcp {
namespace core {

core *_core;

core &get() { return *_core; }

std::atomic_bool server_running = false;

static boost::interprocess::managed_shared_memory segment;

boost::interprocess::managed_shared_memory &get_segment() { return segment; }

void exit_handler(int) {
  BOOST_LOG_TRIVIAL(warning) << "Exiting on signal";
  get().io_context.stop();
  server_running = false;
}

bool init(bool standalone) {
  static struct deleter_t {
    // delete the shmem on init and exit
    deleter_t() {
      boost::interprocess::shared_memory_object::remove(SHMEM_NAME);
    }
    ~deleter_t() {
      boost::interprocess::shared_memory_object::remove(SHMEM_NAME);
    }
  } deleter;
  segment = boost::interprocess::managed_shared_memory(
      boost::interprocess::create_only, SHMEM_NAME, SHMEM_SIZE);

  // init logging
  util::init_logging(boost::log::trivial::info);
  // set signal handler
  std::signal(SIGINT, exit_handler);
  std::signal(SIGTERM, exit_handler);

  _core = segment.construct<core>("server_core")();

  if (standalone) {
    // refuse client connecting
    BOOST_LOG_TRIVIAL(warning) << "Server running in standalone mode.";
    segment.construct<bool>("server_standalone")(true);
  } else {
    // start client request queue poll thread
    BOOST_LOG_TRIVIAL(warning) << "Server running in listen mode.";
    server_running = true;
    std::thread poll([]() {
      while (server_running) {
        for (auto &qp : get().client_qps) {
          scoped_lock l(qp.mutex_);
          if (!qp.request_queue.empty()) {
            BOOST_LOG_TRIVIAL(info) << "Got request from client, queue length "
                                    << qp.request_queue.size();
            auto req = qp.request_queue.front();
            client::req_map[req->req_type](req);
          }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    });
    poll.detach();
  }

  // init ethernet broadcast addr
  eth::get_broadcast() = get_allocator<eth::addr>().allocate_one();
  memcpy(eth::get_broadcast()->data, "\xff\xff\xff\xff\xff\xff",
         sizeof(eth::addr));

  // set default eth callback
  eth::set_frame_receive_callback(eth::ethertype_broker_callback);
  return segment.get_size() == SHMEM_SIZE;
}

int core::run() {
  io_context.run();
  // should never reach here
  return -1;
}

core::core()
    : devices(get_allocator<shared_ptr<device::device_t>>()),
      client_qps(get_allocator<client_qp>()) {}

client_qp::client_qp()
    : request_queue(get_allocator<shared_ptr<client::req>>()),
      completion_queue(get_allocator<shared_ptr<client::req>>()) {}
} // namespace core
} // namespace khtcp