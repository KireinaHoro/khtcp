#include "core.h"
#include "packetio.h"

namespace khtcp {
namespace core {

core &get() {
  static core c;
  return c;
}

int core::run() {
  io_context.run();
  // should never reach here
  return -1;
}
} // namespace core
} // namespace khtcp