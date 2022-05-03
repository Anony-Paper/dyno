#ifndef DYNO_STATIC_OSTACK_PATH_OSTACK_H_
#define DYNO_STATIC_OSTACK_PATH_OSTACK_H_

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_ostack {

using Val = unsigned int;

using ORamPos = static_path_oram::Pos;
using ORamKey = static_path_oram::Key;

class BlockPointer {
 public:
  ORamKey key_;
  ORamPos pos_;

  BlockPointer() = default;
  BlockPointer(ORamKey key, ORamPos pos) : key_(key), pos_(pos) {}
};

class Block {
 public:
  Val val_;
  BlockPointer next_;

  Block() = default;
  Block(unsigned int val, BlockPointer next)
      : val_(val), next_(next) {}
  explicit Block(unsigned int val)
      : val_(val), next_(0, 0) {}
};

constexpr size_t kBlockSize = sizeof(Block);

using PathORam = static_path_oram::ORam<kBlockSize>;
using ORamBlock = static_path_oram::Block<kBlockSize>;

class OStack {
 public:
  explicit OStack(size_t n) : capacity_(n), oram_(n) {}
  void Push(Val val, crypto::Key enc_key);
  Val Pop(crypto::Key enc_key);
  Val Peek(crypto::Key enc_key);
  size_t Capacity() const { return capacity_; };
  size_t Size() const { return size_; };
  void FillWithDummies(crypto::Key enc_key);
  unsigned long long MemoryAccessCount() { return oram_.MemoryAccessCount(); }
  unsigned long long MemoryBytesMovedTotal() { return oram_.MemoryBytesMovedTotal(); }

 private:
  const size_t capacity_;
  size_t size_ = 0;
  PathORam oram_;
  BlockPointer head_ = BlockPointer(0, 0);
};

} // namespace dyno::static_path_ostack

#endif //DYNO_STATIC_OSTACK_PATH_OSTACK_H_
