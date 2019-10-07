/**
 * @file test_logging.cc
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Test for logging facility.
 * @version 0.1
 * @date 2019-10-05
 *
 * @copyright Copyright (c) 2019
 *
 */

#include "core.h"
#include "util.h"

#include <iostream>

int main() {
  if (!khtcp::core::init()) {
    std::cerr << "core init failed\n";
    return -1;
  }

  BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
  BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
  BOOST_LOG_TRIVIAL(info) << "An informational severity message";
  BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
  BOOST_LOG_TRIVIAL(error) << "An error severity message";
  BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
}