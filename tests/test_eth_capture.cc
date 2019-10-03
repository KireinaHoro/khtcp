#include "core.h"
#include "device.h"
#include "util.h"

int main() {
  // khtcp::util::init_logging(boost::log::trivial::trace);
  khtcp::util::init_logging();

  khtcp::device::add_device("eth0");

  return khtcp::core::get().run();
}