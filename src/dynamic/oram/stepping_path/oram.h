#ifndef DYNO_DYNAMIC_ORAM_STEPPING_PATH_ORAM_H_
#define DYNO_DYNAMIC_ORAM_STEPPING_PATH_ORAM_H_

#include <array>
#include <cassert>
#include <vector>

#include "../../../static/oram/path/oram.h"
#include "../../../utils/crypto.h"

namespace dyno::dynamic_stepping_path_oram {

template<size_t val_len>
using PathORam = static_path_oram::ORam<val_len>;
template<size_t val_len>
using PathORamBlock = static_path_oram::Block<val_len>;

using Key = static_path_oram::Key;
template<size_t val_len>
using Val = static_path_oram::Val<val_len>;

template<size_t val_len>
class Block {
 public:
  Key key_;
  Val<val_len> val_;

  Block() = default;
  Block(Key key, Val<val_len> val) : key_(key), val_(val) {}
  explicit Block(PathORamBlock<val_len> b) : key_(b.key_), val_(b.val_) {}
};

// Assumes 1-based positions ([1, N]).
template<size_t val_len>
class ORam {
 public:
  ORam() = default;
  // Only implemented for benchmarks.
  ORam(int starting_size_power_of_two);
  void Grow(crypto::Key enc_key);
  Block<val_len> ReadAndRemove(Key key, crypto::Key enc_key);
  Block<val_len> Read(Key key, crypto::Key enc_key);
  void Insert(Key key, Val<val_len> val, crypto::Key enc_key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const { return size_; }
  unsigned long long MemoryAccessCount() { return memory_access_count_; }
  unsigned long long MemoryBytesMovedTotal() { return memory_bytes_moved_total_; }

 private:
  size_t capacity_ = 0;
  size_t size_ = 0;
  std::array<PathORam<val_len> *, 2> sub_orams_{};
  unsigned int SubOramIndex(Key key);
  unsigned long long memory_access_count_ = 0;
  unsigned long long memory_bytes_moved_total_ = 0;
  unsigned long long SubORamsMemoryAccessCountSum();
  unsigned long long SubORamsMemoryBytesMovedTotalSum();
};

// Implementations

template<size_t val_len>
ORam<val_len>::ORam(int starting_size_power_of_two)
    : capacity_(1 << starting_size_power_of_two), size_(1 << (starting_size_power_of_two)) {
  for (int i = 0; i < 2; ++i)
    sub_orams_[i] = new PathORam<val_len>(capacity_ << i, true);
}

bool IsPowerOfTwo(size_t x) {
  return !(x & (x - 1));
}

template<size_t val_len>
void ORam<val_len>::Grow(crypto::Key enc_key) {
  if (capacity_ == 0) {
    sub_orams_[1] = new PathORam<val_len>(1, true);
    ++capacity_;
    return;
  }

  if (IsPowerOfTwo(capacity_)) {
    assert(sub_orams_[1] != nullptr);
    delete sub_orams_[0];
    sub_orams_[0] = sub_orams_[1];
    sub_orams_[1] = new PathORam<val_len>(2 * capacity_, true);
  }

  assert(sub_orams_[0] != nullptr && sub_orams_[1] != nullptr);
  Key move_idx = (capacity_ % sub_orams_[0]->Capacity()) + 1;
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  auto move_bl = sub_orams_[0]->ReadAndRemove({0, move_idx}, enc_key);
  if (!move_bl.key_) {
    sub_orams_[1]->DummyAccess(enc_key);
  } else {
    sub_orams_[1]->Insert(move_bl, enc_key);
  }
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  ++capacity_;
}

// Returns 0-value of Val if nothing found.
template<size_t val_len>
Block<val_len> ORam<val_len>::ReadAndRemove(Key key, crypto::Key enc_key) {
  assert(1 <= key && key <= capacity_);
  Block<val_len> res;
  unsigned int idx = SubOramIndex(key);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or 2. it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_orams_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;

    if (i == idx) {
      auto bl = sub_orams_[i]->ReadAndRemove({0, key}, enc_key);
      res = Block(bl);
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  if (res.key_)
    --size_;
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

// Returns 0-value of Val if nothing found.
template<size_t val_len>
Block<val_len> ORam<val_len>::Read(Key key, crypto::Key enc_key) {
  assert(1 <= key && key <= capacity_);
  Block<val_len> res;
  unsigned int idx = SubOramIndex(key);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or 2. it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_orams_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;

    if (i == idx) {
      auto bl = sub_orams_[i]->Read({0, key}, enc_key);
      res = Block(bl);
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

template<size_t val_len>
void ORam<val_len>::Insert(Key key, Val<val_len> val, crypto::Key enc_key) {
  assert(1 <= key && key <= capacity_);
  unsigned int idx = SubOramIndex(key);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    if (sub_orams_[i] == nullptr)
      continue;

    if (i == idx) {
      sub_orams_[i]->Insert({0, key, val}, enc_key);
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  ++size_;
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
}

template<size_t val_len>
unsigned int ORam<val_len>::SubOramIndex(Key key) {
  assert(1 <= key && key <= capacity_);
  if (capacity_ == 1)
    return 1;
  if (key > sub_orams_[0]->Capacity() ||
      key <= (capacity_ - sub_orams_[0]->Capacity()))
    return 1;
  return 0;
}

template<size_t val_len>
unsigned long long ORam<val_len>::SubORamsMemoryAccessCountSum() {
  unsigned long long res = 0;
  for (auto &so : sub_orams_) {
    if (so != nullptr) {
      res += so->MemoryAccessCount();
    }
  }
  return res;
}

template<size_t val_len>
unsigned long long ORam<val_len>::SubORamsMemoryBytesMovedTotalSum() {
  unsigned long long res = 0;
  for (auto &so : sub_orams_) {
    if (so != nullptr) {
      res += so->MemoryBytesMovedTotal();
    }
  }
  return res;
}
} // dyno::dynamic_stepping_path_oram

#endif //DYNO_DYNAMIC_ORAM_STEPPING_PATH_ORAM_H_
