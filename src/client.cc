#include "client.h"
#include "core.h"
#include "util.h"

namespace khtcp {
namespace client {

static core::client_handle handle;
static bool init_success = false;
static std::thread polling_thread;

core::client_handle get_client_handle() { return handle; }
core::core &get() { return *core::_core; }
std::thread &get_polling_thread() { return polling_thread; }

bool init() {
  static struct global_dtor {
    ~global_dtor() {
      if (init_success) {
        get().client_qps.erase(get_client_handle());
      }
    }
  } dtor;
  try {
    core::get_segment() = boost::interprocess::managed_shared_memory(
        boost::interprocess::open_only, core::SHMEM_NAME);
  } catch (std::exception) {
    BOOST_LOG_TRIVIAL(fatal) << "Server not found.";
    return false;
  }
  init_success = core::get_segment().get_size() == core::SHMEM_SIZE;

  if (init_success) {
    auto [flag, count] = core::get_segment().find<bool>("server_standalone");
    if (count != 0 && flag) {
      BOOST_LOG_TRIVIAL(fatal)
          << "Server in standalone mode, not accepting clients.";
      return false;
    }

    core::_core = core::get_segment().find<core::core>("server_core").first;
    get().client_qps.emplace_front();
    handle = get().client_qps.begin();

    // init ethernet broadcast addr
    eth::get_broadcast() = core::get_allocator<eth::addr>().allocate_one();
    memcpy(eth::get_broadcast()->data, "\xff\xff\xff\xff\xff\xff",
           sizeof(eth::addr));

    // start completion queue poll thread
    polling_thread = std::thread([]() {
      while (true) {
        for (auto &qp : get().client_qps) {
          core::scoped_lock l(qp.mutex_);
          if (!qp.completion_queue.empty()) {
            qp.completion_queue.front()->complete();
          }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    });
  } else {
    BOOST_LOG_TRIVIAL(fatal) << "Server not found.";
  }
  return init_success;
} // namespace client
} // namespace client
} // namespace khtcp