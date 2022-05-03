#ifndef DYNO_STATIC_ORAM_PATH_ORAM_H
#define DYNO_STATIC_ORAM_PATH_ORAM_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <map>
#include <memory>
#include <vector>

#include "openssl/rand.h"

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"

#define max(a, b) ((a)>(b)?(a):(b))

namespace dyno::static_path_oram {

using Pos = unsigned int;
using Key = unsigned int;
template<size_t val_len>
using Val = std::array<uint8_t, val_len>;

template<size_t val_len>
class Block {
 public:
  Pos pos_;
  Key key_;
  Val<val_len> val_;

  explicit Block(bool zero_fill = false);
  Block(Pos pos, Key key) : pos_(pos), key_(key) {}
  Block(Pos pos, Key key, Val<val_len> val) : pos_(pos), key_(key), val_(val) {}
};

//namespace {
static const unsigned int kBucketSize = 4; // Z in PathORAM paper

template<size_t val_len>
class Bucket {
 public:
  std::array<Block<val_len>, kBucketSize> blocks_;

  explicit Bucket(bool zero_fill = false);
  explicit Bucket(std::array<Block<val_len>, kBucketSize> blocks) : blocks_(blocks) {}
};

template<size_t val_len>
static constexpr size_t kEncryptedBucketCipherLen = crypto::CiphertextLen(sizeof(Bucket<val_len>));

template<size_t val_len>
class EncryptedBucket {
 public:
  std::array<uint8_t, kEncryptedBucketCipherLen<val_len>> cipher_text_;
  // Instead of storing a bit in the buckets per each child, we use hash digests.
  // Note that this is slower and more space-expensive.
  std::array<uint8_t, crypto::kDigestSize> digest_;

  EncryptedBucket() = default;
  EncryptedBucket(Bucket<val_len> b, crypto::Key key);
  EncryptedBucket(std::array<uint8_t, kEncryptedBucketCipherLen<val_len>> cipher_text);

  Bucket<val_len> ToBucket(crypto::Key key);
  void SetDigest();
  bool HasValidDigest();

 private:
  std::array<uint8_t, crypto::kDigestSize> CalculateDigest();
};

// Assumes 1-based positions ([1, N]) and power-of-two sizes.
template<size_t val_len>
class ORam {
 public:
  explicit ORam(size_t n, bool with_pos_map = false, bool with_key_gen = false);
  ORam(size_t n, std::vector<Block<val_len>> data, crypto::Key enc_key, bool with_pos_map = false);

  Block<val_len> ReadAndRemove(Block<val_len> query, crypto::Key enc_key);
  Block<val_len> Read(Block<val_len> query, crypto::Key enc_key);
  void Insert(Block<val_len> block, crypto::Key enc_key);
  std::vector<Block<val_len>> DecryptAll(crypto::Key enc_key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const { return size_; }
  Pos GeneratePos() const;
  void DummyAccess(crypto::Key enc_key);
  void FillWithDummies(crypto::Key enc_key);
  unsigned long long MemoryAccessCount() { return memory_access_count_; }
  unsigned long long MemoryBytesMovedTotal() { return memory_access_bytes_total_; };

  // A client should either always use these or never use them.
  // Doing both leads to undefined behavior.
  // They only work when `with_key_gen = true`.
  Key NextKey();
  void AddFreedKey(Key key);

 private:
  size_t capacity_;
  size_t size_ = 0;
  unsigned int depth_;
  size_t num_buckets_;
  std::unique_ptr<EncryptedBucket<val_len>[]> buckets_;
  std::vector<Block<val_len>> stash_;
  bool with_pos_map_;
  std::map<Key, Pos> pos_map_{};
  bool with_key_gen_ = false;
  Key next_key_ = 1;
  std::vector<Key> freed_keys_;
  unsigned long long memory_access_count_ = 0;
  unsigned long long memory_access_bytes_total_ = 0;

  std::vector<unsigned int> Path(Pos pos) const;
  Block<val_len> ReadPath(Block<val_len> query, crypto::Key enc_key);
  void Evict(Pos pos, crypto::Key enc_key);
  unsigned int PathAtLevel(Pos pos, unsigned int level) const;
};

// Implementations:

template<size_t val_len>
Block<val_len>::Block(bool zero_fill) {
  if (zero_fill) {
    pos_ = 0;
    key_ = 0;
    val_.fill(0);
  }
}

template<size_t val_len>
Bucket<val_len>::Bucket(bool zero_fill) {
  for (int i = 0; i < kBucketSize; i++)
    blocks_[i] = Block<val_len>(zero_fill);
}

template<size_t val_len>
EncryptedBucket<val_len>::EncryptedBucket(const Bucket<val_len> b, const crypto::Key key) {
  const auto data = bytes::ToBytes(b);
  bool success = crypto::Encrypt(data.data(), sizeof(Bucket<val_len>), key, cipher_text_.data());
  assert(success);
  SetDigest();
}

template<size_t val_len>
EncryptedBucket<val_len>::EncryptedBucket(std::array<uint8_t, kEncryptedBucketCipherLen<val_len>> cipher_text)
    : cipher_text_(cipher_text) {
  SetDigest();
}

template<size_t val_len>
bool EncryptedBucket<val_len>::HasValidDigest() {
  auto valid_digest = CalculateDigest();
  return digest_ == valid_digest;
}

template<size_t val_len>
void EncryptedBucket<val_len>::SetDigest() {
  digest_ = CalculateDigest();
}

template<size_t val_len>
std::array<uint8_t, crypto::kDigestSize> EncryptedBucket<val_len>::CalculateDigest() {
  std::array<uint8_t, crypto::kDigestSize> res;
  bool success = crypto::Hash(cipher_text_.data(), kEncryptedBucketCipherLen<val_len>, res.data());
  assert(success);
  return res;
}

template<size_t val_len>
Bucket<val_len> EncryptedBucket<val_len>::ToBucket(crypto::Key key) {
  if (!HasValidDigest()) { // uninitialized
    Bucket<val_len> empty(true);
    return empty;
  }

  std::vector<uint8_t> plain_text(cipher_text_.size());
  int plain_text_len = crypto::Decrypt(cipher_text_.data(), kEncryptedBucketCipherLen<val_len>,
                                       key, plain_text.data());
  assert(plain_text_len == sizeof(Bucket<val_len>));
  Bucket<val_len> res;
  auto res_bytes = reinterpret_cast<uint8_t *>(std::addressof(res));
  std::move(plain_text.begin(), plain_text.begin() + sizeof(Bucket<val_len>), res_bytes);

  return res;
}

template<size_t val_len>
ORam<val_len>::ORam(size_t n, bool with_pos_map, bool with_key_gen)
    : capacity_(n),
      num_buckets_(max(1, n - 1)),
      buckets_(new EncryptedBucket<val_len>[max(1, n - 1)]),
      depth_(max(0, ceil(log2(n)) - 1)),
      with_pos_map_(with_pos_map),
      with_key_gen_(with_key_gen) {}

template<size_t val_len>
ORam<val_len>::ORam(size_t n, std::vector<Block<val_len>> data,
                    crypto::Key enc_key, bool with_pos_map)
    : capacity_(n),
      depth_(max(0, ceil(log2(n)) - 1)),
      num_buckets_(max(1, n - 1)),
      buckets_(new EncryptedBucket<val_len>[max(1, n - 1)]),
      size_(data.size()),
      with_pos_map_(with_pos_map) {

  std::vector<bool> should_evict(n);

  for (auto bl : data) {
    if (with_pos_map_) {
      bl.pos_ = GeneratePos();
      pos_map_[bl.key_] = bl.pos_;
    }

    stash_.push_back(bl);
    should_evict[bl.pos_ - 1] = true;
  }

  for (Pos p = 1; p <= n; ++p) {
    if (should_evict[p - 1]) {
      ReadPath(Block<val_len>(p, 0), enc_key); // To ensure nothing is over-written.
      Evict(p, enc_key);
    }
  }
}

template<size_t val_len>
Block<val_len> ORam<val_len>::ReadAndRemove(Block<val_len> query, crypto::Key enc_key) {
  if (with_pos_map_) {
    if (pos_map_.find(query.key_) != pos_map_.end()) {
      query.pos_ = pos_map_[query.key_];
      pos_map_.erase(query.key_);
    } else {
      DummyAccess(enc_key);
      auto empty = Block<val_len>(true);
      return empty;
    }
  }

  Block<val_len> res = ReadPath(query, enc_key);
  Evict(query.pos_, enc_key);
  for (Block<val_len> b : stash_) // The requested block may be in stash.
    if (b.pos_ == query.pos_ && b.key_ == query.key_)
      res = b;
  if (res.key_)
    --size_;
  return res;
}

template<size_t val_len>
Block<val_len> ORam<val_len>::Read(Block<val_len> query, crypto::Key enc_key) {
  if (with_pos_map_) {
    if (pos_map_.find(query.key_) != pos_map_.end()) {
      query.pos_ = pos_map_[query.key_];
      pos_map_.erase(query.key_);
    } else {
      DummyAccess(enc_key);
      auto empty = Block<val_len>(true);
      return empty;
    }
  }

  Block<val_len> res = ReadPath(query, enc_key);
  if (res.key_) {
    stash_.push_back(res);
  }
  Evict(query.pos_, enc_key);
  for (Block<val_len> b : stash_) // The requested block may be in stash.
    if (b.pos_ == query.pos_ && b.key_ == query.key_)
      res = b;
  return res;
}

template<size_t val_len>
void ORam<val_len>::Insert(Block<val_len> block, crypto::Key enc_key) {
  if (with_pos_map_) {
    block.pos_ = GeneratePos();
    pos_map_[block.key_] = block.pos_;
  }

  // Shouldn't deterministically be the same as block.pos_
  auto write_pos = GeneratePos();
  ReadPath({write_pos, 0}, enc_key);
  stash_.push_back(block);
  Evict(write_pos, enc_key);
  ++size_;
}

template<size_t val_len>
std::vector<Block<val_len>> ORam<val_len>::DecryptAll(crypto::Key enc_key) {
  ++memory_access_count_;
  memory_access_bytes_total_ += num_buckets_ * sizeof(EncryptedBucket<val_len>);
  std::vector<Block<val_len>> res(stash_);
  for (EncryptedBucket<val_len> eb : buckets_) {
    Bucket<val_len> bu = eb.ToBucket(enc_key);
    for (Block<val_len> bl : bu.blocks_)
      if (bl.key_) // Not dummy
        res.push_back(bl);
  }
  return res;
}

template<size_t val_len>
Pos ORam<val_len>::GeneratePos() const {
  Pos res;
  RAND_bytes(reinterpret_cast<unsigned char *>(&res), sizeof(Pos));
  res = (res % capacity_) + 1;
  return res;
}

template<size_t val_len>
unsigned int ORam<val_len>::PathAtLevel(Pos pos, unsigned int level) const {
  unsigned int base = capacity_ - 1 + pos;
  if (capacity_ > 1) base /= 2;
  return (base / (1 << (depth_ - level))) - 1;
}

template<size_t val_len>
std::vector<unsigned int> ORam<val_len>::Path(Pos pos) const {
  assert(1 <= pos && pos <= capacity_);
  std::vector<unsigned int> res(depth_ + 1);
  unsigned int i = 0;
  unsigned int index = capacity_ - 1 + pos;
  if (capacity_ > 1) // Corner case
    index /= 2; // Skip last level
  while (index > 0) {
    res[i++] = index - 1; // index is 1-based but we need 0-based array indexes.
    index /= 2;
  }
  return res;
}

template<size_t val_len>
Block<val_len> ORam<val_len>::ReadPath(Block<val_len> query, crypto::Key enc_key) {
  Block<val_len> res(true);
  auto path = Path(query.pos_);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * sizeof(EncryptedBucket<val_len>);
  for (unsigned int idx : path) {
    Bucket<val_len> bucket = buckets_[idx].ToBucket(enc_key);
    for (int i = 0; i < kBucketSize; i++) {
      Block<val_len> b = bucket.blocks_[i];
      if (b.key_ == query.key_) {
        res = b;
      } else if (b.key_) {
        stash_.push_back(b);
      }
    }
  }
  return res;
}

// Evict takes Pos as input as we can evict a different path than the path read.
template<size_t val_len>
void ORam<val_len>::Evict(Pos pos, crypto::Key enc_key) {
  auto path = Path(pos);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * sizeof(EncryptedBucket<val_len>);
  std::vector<bool> deleted_from_stash(stash_.size());
  unsigned int level = depth_;
  for (unsigned int idx : path) {
    Bucket<val_len> bucket;
    int bucket_index = 0;

    for (int i = 0; i < stash_.size() && bucket_index < kBucketSize; i++) {
      if (deleted_from_stash[i])
        continue;
      if (PathAtLevel(stash_[i].pos_, level) == idx) {
        bucket.blocks_[bucket_index++] = stash_[i];
        deleted_from_stash[i] = true;
      }
    }

    while (bucket_index < kBucketSize)
      bucket.blocks_[bucket_index++] = Block<val_len>(true); // Dummy

    buckets_[idx] = EncryptedBucket<val_len>(bucket, enc_key);
    level--;
  }

  auto it = deleted_from_stash.begin();
  stash_.erase(
      std::remove_if(stash_.begin(), stash_.end(), [&](Block<val_len>) { return *it++; }),
      stash_.end()
  );
}

template<size_t val_len>
void ORam<val_len>::DummyAccess(crypto::Key enc_key) {
  auto query = Block<val_len>(GeneratePos(), 0);
  ReadPath(query, enc_key);
  Evict(query.pos_, enc_key);
}

// Should only be called after allocation.
template<size_t val_len>
void ORam<val_len>::FillWithDummies(crypto::Key enc_key) {
  ++memory_access_count_;
  memory_access_bytes_total_ += num_buckets_ * sizeof(EncryptedBucket<val_len>);
  Bucket empty = Bucket<val_len>(true);
  for (unsigned int i = 0; i < num_buckets_; ++i) {
    buckets_[i] = EncryptedBucket<val_len>(empty, enc_key);
  }
}

template<size_t val_len>
Key ORam<val_len>::NextKey() {
  assert(with_key_gen_);
  if (!freed_keys_.empty()) {
    Key res = freed_keys_.back();
    freed_keys_.pop_back();
    return res;
  }
  return next_key_++;
}

template<size_t val_len>
void ORam<val_len>::AddFreedKey(Key key) {
  assert(with_key_gen_);
  if (key == next_key_ - 1)
    --next_key_;
  else
    freed_keys_.push_back(key);
}
} // namespace dyno::static_path_oram

#endif //DYNO_STATIC_ORAM_PATH_ORAM_H
