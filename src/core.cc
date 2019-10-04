#include "core.h"
#include "packetio.h"

namespace khtcp {
namespace core {
static core _core;

core &get() { return _core; }

int core::run() {
  io_context.run();
  // should never reach here
  return -1;
}
} // namespace core
} // namespace khtcp