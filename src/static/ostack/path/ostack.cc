#include "ostack.h"

#include <cassert>

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_ostack {

void OStack::Push(Val val, crypto::Key enc_key) {
  assert(size_ < capacity_);
  ++size_;

  auto new_head = BlockPointer(head_.key_ + 1, oram_.GeneratePos());
  auto new_block = Block(val, head_);
  head_ = new_head;

  auto ov = bytes::ToBytes(new_block);
  oram_.Insert({head_.pos_, head_.key_, ov}, enc_key);
}

Val OStack::Pop(crypto::Key enc_key) {
  if (!head_.key_) { // empty
    oram_.DummyAccess(enc_key);
    return 0;
  }

  --size_;
  auto res_ob = oram_.ReadAndRemove({head_.pos_, head_.key_}, enc_key);
  Block res;
  bytes::FromBytes(res_ob.val_, res);
  head_ = res.next_;
  return res.val_;
}

Val OStack::Peek(crypto::Key enc_key) {
  if (!head_.key_) { // empty
    oram_.DummyAccess(enc_key);
    return 0;
  }

  auto res_ob = oram_.Read({head_.pos_, head_.key_}, enc_key);
  Block res;
  bytes::FromBytes(res_ob.val_, res);
  return res.val_;
}

// Should only be called after allocation.
void OStack::FillWithDummies(crypto::Key enc_key) {
  oram_.FillWithDummies(enc_key);
}

} // namespace dyno::static_path_ostack