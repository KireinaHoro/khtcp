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
#include <boost/interprocess/containers/deque.hpp>
#include <boost/interprocess/containers/list.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/offset_ptr.hpp>
#include <boost/interprocess/smart_ptr/enable_shared_from_this.hpp>
#include <boost/interprocess/smart_ptr/shared_ptr.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

#include <list>
#include <string>
#include <type_traits>
#include <vector>

namespace khtcp {
namespace client {
struct req;
}
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
template <typename T> using deque = boost::interprocess::deque<T, allocator<T>>;
template <typename T> using list = boost::interprocess::list<T, allocator<T>>;

// shared_ptr related
using void_allocator =
    typename boost::interprocess::managed_shared_memory::allocator<void>::type;
template <typename T>
using deleter =
    typename boost::interprocess::managed_shared_memory::deleter<T>::type;
template <typename T, typename DT = T>
using shared_ptr =
    boost::interprocess::shared_ptr<T, void_allocator, deleter<DT>>;
template <typename T, typename DT = T>
using enable_shared_from_this =
    boost::interprocess::enable_shared_from_this<T, void_allocator,
                                                 deleter<DT>>;
template <typename T, typename U>
const auto dynamic_pointer_cast =
    boost::interprocess::dynamic_pointer_cast<T, void_allocator, deleter<T>, U>;

template <typename T, typename DT = T, typename... Args>
shared_ptr<T, DT> make_shared(Args &&... args) {
  return *get_segment().construct<shared_ptr<T, DT>>(
      boost::interprocess::anonymous_instance)(
      get_segment().construct<T>(boost::interprocess::anonymous_instance)(
          args...),
      void_allocator(get_segment().get_segment_manager()),
      deleter<DT>(get_segment().get_segment_manager()));
}

template <typename T> using ptr = boost::interprocess::offset_ptr<T>;

using mutex = boost::interprocess::interprocess_mutex;
using scoped_lock = boost::interprocess::scoped_lock<mutex>;

/**
 * @brief Holds request queue and completion queue.
 *
 */
struct client_qp {
  mutex mutex_;
  deque<ptr<client::req>> request_queue;
  deque<ptr<client::req>> completion_queue;

  client_qp();
};
// client queue iterator
using client_handle = list<client_qp>::iterator;

} // namespace core
} // namespace khtcp

#endif