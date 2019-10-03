#include "core.h"
#include "packetio.h"

namespace khtcp {
namespace core {
static core _core;

core &get() { return _core; }

int core::run() {
  eth::set_frame_receive_callback(eth::print_eth_frame_callback);
  io_context.run();
  // should never reach here
  return -1;
}
} // namespace core
} // namespace khtcp