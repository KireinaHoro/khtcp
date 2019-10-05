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
template <typename T> using allocator = std::allocator<T>;

/**
 * @brief Get the core allocator instance.
 *
 * @return allocator&
 */
template <typename T> allocator<T> &get_allocator() {
  static allocator<T> alloc = allocator<T>();
  return alloc;
}

// utility aliases with the core allocator
using string = std::basic_string<char, std::char_traits<char>, allocator<char>>;
template <typename T> using vector = std::vector<T, allocator<T>>;
template <typename T> using list = std::list<T, allocator<T>>;
template <typename T, typename... Args>
std::shared_ptr<T> make_shared(Args &&... args) {
  return std::allocate_shared<T, allocator<T>>(get_allocator<T>(), args...);
}

} // namespace core
} // namespace khtcp

#endif