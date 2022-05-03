#ifndef DYNO_STATIC_OQUEUE_PATH_OQUEUE_H_
#define DYNO_STATIC_OQUEUE_PATH_OQUEUE_H_

#include <memory>

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_oqueue {

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

class OQueue {
 public:
  explicit OQueue(size_t n);
  OQueue(size_t n, std::shared_ptr<PathORam> oram);
  void Enqueue(Val val, crypto::Key enc_key);
  Val Dequeue(crypto::Key enc_key);
  size_t Capacity() const { return capacity_; };
  size_t Size() const { return size_; };
  void FillWithDummies(crypto::Key enc_key);
  unsigned long long MemoryAccessCount() { return oram_->MemoryAccessCount(); }
  unsigned long long MemoryBytesMovedTotal() { return oram_->MemoryBytesMovedTotal(); }

 private:
  const size_t capacity_;
  size_t size_ = 0;
  std::shared_ptr<PathORam> oram_;
  // Where to put the next enqueued element:
  BlockPointer head_ = BlockPointer(0, 0);
  // Where to take the next dequeued element from:
  BlockPointer tail_ = BlockPointer(0, 0);
};

} // namespace dyno::static_path_oqueue

#endif //DYNO_STATIC_OQUEUE_PATH_OQUEUE_H_
