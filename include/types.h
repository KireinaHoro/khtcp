/**
 * @file types.h
 * @author Pengcheng Xu <jsteward@pku.edu.cn>
 * @brief Type wrappers for use in the stack.
 * @version 0.1
 * @date 2019-10-05
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef __KHTCP_TYPES_H_
#define __KHTCP_TYPES_H_

#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/containers/list.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/smart_ptr/shared_ptr.hpp>
#include <list>
#include <string>
#include <vector>

namespace khtcp {
namespace core {
/**
 * @brief The core allocator.
 *
 * All memory regions that interact with the protocol stack shall be allocated
 * with this allocator; if not, then a new region shall be allocated and the
 * original contents copied over.
 *
 * @tparam T
 */
template <typename T>
using allocator = boost::interprocess::allocator<
    T, boost::interprocess::managed_shared_memory::segment_manager>;

boost::interprocess::managed_shared_memory &get_segment();

/**
 * @brief Get the core allocator instance.
 *
 * @return allocator&
 */
template <typename T> allocator<T> &get_allocator() {
  static allocator<T> alloc = allocator<T>(get_segment().get_segment_manager());
  return alloc;
}

// utility aliases with the core allocator
using string = boost::interprocess::basic_string<char, std::char_traits<char>,
                                                 allocator<char>>;
template <typename T>
using vector = boost::interprocess::vector<T, allocator<T>>;
template <typename T> using list = boost::interprocess::list<T, allocator<T>>;
template <typename T>
using shared_ptr = typename boost::interprocess::managed_shared_ptr<
    T, boost::interprocess::managed_shared_memory>::type;
template <typename T, typename... Args>
shared_ptr<T> make_shared(Args &&... args) {
  // return std::allocate_shared<T, allocator<T>>(get_allocator<T>(), args...);
  return boost::interprocess::make_managed_shared_ptr(
      get_segment().construct<T>(boost::interprocess::anonymous_instance)(
          args...),
      get_segment());
}

} // namespace core
} // namespace khtcp

#endif