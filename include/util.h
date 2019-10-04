/**
 * @file util.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Various utilities.
 * @version 0.1
 * @date 2019-10-03
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_UTIL_H_
#define __KHTCP_UTIL_H_
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/trivial.hpp>
#include <cstdint>
#include <string>

namespace khtcp {
namespace util {

class colored_console_sink
    : public boost::log::sinks::basic_formatted_sink_backend<
          char, boost::log::sinks::synchronized_feeding> {
public:
  static void consume(boost::log::record_view const &rec,
                      string_type const &formatted_string);
};
using colored_console_sink_t =
    boost::log::sinks::synchronous_sink<colored_console_sink>;

void init_logging(
    boost::log::trivial::severity_level level = boost::log::trivial::info);

std::string mac_to_string(const uint8_t *addr, uint8_t len);

} // namespace util
} // namespace khtcp
#endif