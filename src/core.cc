#include "core.h"
#include "packetio.h"
#include "types.h"
#include "util.h"

#include <csignal>

namespace khtcp {
namespace core {

static boost::interprocess::managed_shared_memory segment;
static shared_ptr<core> _core;
static bool role;

core &get() { return *_core; }

boost::interprocess::managed_shared_memory &get_segment() { return segment; }

void exit_handler(int) {
  BOOST_LOG_TRIVIAL(warning) << "Exiting on signal";
  get().io_context.stop();
}

bool init(bool is_server) {
  // init logging
  util::init_logging(boost::log::trivial::warning);
  // set role
  role = is_server;
  // set signal handler
  std::signal(SIGINT, exit_handler);
  std::signal(SIGTERM, exit_handler);

  if (is_server) {
    boost::interprocess::shared_memory_object::remove(SHMEM_NAME);
    segment = boost::interprocess::managed_shared_memory(
        boost::interprocess::create_only, SHMEM_NAME, SHMEM_SIZE);

    // mark the server as running
    segment.construct<bool>("server_running")(true);

    _core = make_shared<core>();

  } else {
    segment = boost::interprocess::managed_shared_memory(
        boost::interprocess::open_only, SHMEM_NAME);

    auto p = segment.find<bool>("server_running");
    if (p.second != 1) {
      BOOST_LOG_TRIVIAL(error) << "The server is not running";
      return false;
    }
  }
  return segment.get_size() == SHMEM_SIZE;
}

bool get_role() { return role; }

int core::run() {
  io_context.run();
  // should never reach here
  return -1;
}

core::core() : devices(get_allocator<shared_ptr<device::device_t>>()) {}
core::~core() {
  if (get_role()) {
    *segment.find<bool>("server_running").first = false;
  }
}
} // namespace core
} // namespace khtcp