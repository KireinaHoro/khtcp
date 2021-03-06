#include "util.h"

#include <arpa/inet.h>
#include <boost/endian/conversion.hpp>
#include <boost/log/attributes/attribute_value.hpp>
#include <boost/log/attributes/value_extraction.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace khtcp {
namespace util {

#define RED "\x1B[0;31m"
#define BOLD_RED "\x1B[1;31m"
#define GRN "\x1B[0;32m"
#define YEL "\x1B[0;33m"
#define BLU "\x1B[0;34m"
#define MAG "\x1B[0;35m"
#define CYN "\x1B[0;36m"
#define WHT "\x1B[0;37m"
#define RESET "\x1B[0m"

const char *get_color(boost::log::trivial::severity_level level) {
  switch (level) {
  case boost::log::trivial::trace:
    return RESET;
  case boost::log::trivial::debug:
    return WHT;
  case boost::log::trivial::info:
    return GRN;
  case boost::log::trivial::warning:
    return YEL;
  case boost::log::trivial::error:
    return RED;
  case boost::log::trivial::fatal:
    return BOLD_RED;
  default:
    return RESET;
  }
}

void colored_console_sink::consume(boost::log::record_view const &rec,
                                   string_type const &formatted_string) {
  auto level = rec.attribute_values()["Severity"]
                   .extract<boost::log::trivial::severity_level>();

  std::cout << get_color(level.get()) << formatted_string << RESET << std::endl;
}

void init_logging(boost::log::trivial::severity_level level) {
  auto colored_console_sink = boost::make_shared<colored_console_sink_t>();
  boost::log::core::get()->add_sink(colored_console_sink);
  boost::log::core::get()->set_filter(boost::log::trivial::severity >= level);
}

std::string mac_to_string(const eth::addr_t addr) {
  auto len = sizeof(eth::addr_t);
  std::ostringstream os;
  for (int i = 0; i < len; ++i) {
    os << std::setfill('0') << std::hex << std::setw(2) << (int)addr[i];
    if (i < len - 1) {
      os << ":";
    }
  }
  return os.str();
}

std::string ip_to_string(const ip::addr_t addr) {
  in_addr in;
  memcpy(&in.s_addr, addr, sizeof(ip::addr_t));
  return std::string(inet_ntoa(in));
}

int string_to_ip(const std::string &str, ip::addr_t addr) {
  return inet_aton(str.c_str(), (in_addr *)addr);
}

int mask_to_cidr(uint32_t n) {
  unsigned int count = 0;
  while (n) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

uint32_t cidr_to_mask(int prefix) {
  return boost::endian::endian_reverse(
      prefix == 0 ? 0 : (0xffffffff << (32 - prefix)));
}

void hexdump(const char *note, const void *data, size_t size) {
  printf(">> %s\n", note);
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}
} // namespace util
} // namespace khtcp