#include "oqueue.h"

#include <cassert>
#include <memory>
#include <utility>

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_oqueue {

OQueue::OQueue(size_t n) : capacity_(n), oram_(std::make_shared<PathORam>(n, false, true)) {
  head_ = BlockPointer(oram_->NextKey(), oram_->GeneratePos());
  tail_ = head_;
}

OQueue::OQueue(size_t n, std::shared_ptr<PathORam> oram) : capacity_(n), oram_(std::move(oram)) {
  assert(n <= oram_->Capacity());
  head_ = BlockPointer(oram_->NextKey(), oram_->GeneratePos());
  tail_ = head_;
}

void OQueue::Enqueue(Val val, crypto::Key enc_key) {
  assert(size_ < capacity_);
  assert(oram_->Size() < oram_->Capacity());

  BlockPointer new_head = BlockPointer(oram_->NextKey(), oram_->GeneratePos());
  auto new_block = Block(val, new_head);
  auto ov = bytes::ToBytes(new_block);
  oram_->Insert({head_.pos_, head_.key_, ov}, enc_key);
  head_ = new_head;
  ++size_;
}

Val OQueue::Dequeue(crypto::Key enc_key) {
  if (size_ == 0) {
    oram_->DummyAccess(enc_key);
    return 0;
  }

  assert(tail_.key_ && tail_.pos_);
  auto res_ob = oram_->ReadAndRemove({tail_.pos_, tail_.key_}, enc_key);
  oram_->AddFreedKey(tail_.key_);
  Block res;
  bytes::FromBytes(res_ob.val_, res);
  --size_;
  tail_ = res.next_;
  return res.val_;
}

void OQueue::FillWithDummies(crypto::Key enc_key) {
  oram_->FillWithDummies(enc_key);
}
} // namespace dyno::static_path_oqueue
