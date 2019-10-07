#include "arp.h"
#include "client/arp.h"
#include "core.h"

namespace khtcp {
namespace client {
namespace arp {
void read_req::exec(core::ptr<req> self) {
  auto param = &((read_req *)self.get())->param;
  auto ret = &((read_req *)self.get())->ret;
  ::khtcp::arp::async_read_arp(
      param->dev_id,
      [self, ret](int dev_id, uint16_t opcode,
                  core::ptr<const ::khtcp::eth::addr> sender_mac,
                  core::ptr<const ::khtcp::ip::addr> sender_ip,
                  core::ptr<const ::khtcp::eth::addr> target_mac,
                  core::ptr<const ::khtcp::ip::addr> target_ip) -> bool {
        ret->dev_id = dev_id;
        ret->opcode = opcode;
        ret->sender_mac = sender_mac;
        ret->sender_ip = sender_ip;
        ret->target_mac = target_mac;
        ret->target_ip = target_ip;
        self->client_handle->completion_queue.push_back(self);
        self->client_handle->request_queue.pop_front();

        return true;
      });
}

void async_read_arp(int dev_id, ::khtcp::arp::read_handler_t &&handler) {
  auto req_ = core::get_allocator<read_req>().allocate_one();
  req_->req_type = 0; // arp::read
  req_->complete = [=]() {
    handler(req_->ret.dev_id, req_->ret.opcode, req_->ret.sender_mac,
            req_->ret.sender_ip, req_->ret.target_mac, req_->ret.target_ip);
    core::get_allocator<read_req>().deallocate_one(req_);
  };

  // params
  req_->param.dev_id = dev_id;

  req_->client_handle = client::get_client_handle();

  client::get_client_handle()->request_queue.push_back(req_);
}

void write_req::exec(core::ptr<req> self) {
  auto param = &((write_req *)self.get())->param;
  auto ret = &((write_req *)self.get())->ret;
  ::khtcp::arp::async_write_arp(
      param->dev_id, param->opcode, param->sender_mac, param->sender_ip,
      param->target_mac, param->target_ip, [self, ret](int dev_id, int r) {
        ret->dev_id = dev_id;
        ret->ret = r;
        self->client_handle->completion_queue.push_back(self);
        self->client_handle->request_queue.pop_front();
      });
}

void async_write_arp(int dev_id, uint16_t opcode,
                     core::ptr<const ::khtcp::eth::addr> sender_mac,
                     core::ptr<const ::khtcp::ip::addr> sender_ip,
                     core::ptr<const ::khtcp::eth::addr> target_mac,
                     core::ptr<const ::khtcp::ip::addr> target_ip,
                     ::khtcp::arp::write_handler_t &&handler) {
  auto req_ = core::get_allocator<write_req>().allocate_one();
  req_->req_type = 1; // arp::write
  req_->complete = [=]() {
    handler(req_->ret.dev_id, req_->ret.ret);
    core::get_allocator<write_req>().deallocate_one(req_);
  };

  // test call
  req_->complete();

  // param
  req_->param.dev_id = dev_id;
  req_->param.opcode = opcode;
  req_->param.sender_mac = sender_mac;
  req_->param.sender_ip = sender_ip;
  req_->param.target_mac = target_mac;
  req_->param.target_ip = target_ip;

  req_->client_handle = client::get_client_handle();

  client::get_client_handle()->request_queue.push_back(req_);
}

} // namespace arp
} // namespace client
} // namespace khtcp