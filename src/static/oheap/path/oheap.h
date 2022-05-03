#ifndef DYNO_STATIC_OHEAP_PATH_OHEAP_H
#define DYNO_STATIC_OHEAP_PATH_OHEAP_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <memory>
#include <vector>

#include "openssl/rand.h"

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"

namespace dyno::static_path_oheap {

using Pos = unsigned int;
using Key = unsigned int;
using Val = unsigned int;

class Block {
 public:
  Pos pos_;
  Key key_;
  Val val_;

  explicit Block(bool zero_fill = false);
  Block(Pos pos, Key key, Val val) : pos_(pos), key_(key), val_(val) {}

  bool operator==(Block rhs) const;
  bool operator!=(Block rhs) const;
};

static const unsigned int kBucketSize = 3;

class Bucket {
 public:
  std::array<Block, kBucketSize> blocks_;
  Block min_block_;

  explicit Bucket(bool zero_fill = false);
  explicit Bucket(std::array<Block, kBucketSize> blocks);
  Bucket(std::array<Block, kBucketSize> blocks, Block children_min_block);
  void UpdateMins();
};

static constexpr size_t kEncryptedBucketCipherLen = crypto::CiphertextLen(sizeof(Bucket));

class EncryptedBucket {
 public:
  std::array<uint8_t, kEncryptedBucketCipherLen> cipher_text_;
  std::array<uint8_t, crypto::kDigestSize> digest_;

  EncryptedBucket() = default;
  EncryptedBucket(Bucket b, crypto::Key key);
  EncryptedBucket(std::array<uint8_t, kEncryptedBucketCipherLen> cipher_text);

  Bucket ToBucket(crypto::Key key);
  void SetDigest();
  bool HasValidDigest();

 private:
  std::array<uint8_t, crypto::kDigestSize> CalculateDigest();
};

// Assumes 1-based positions ([1, N]) and power-of-two sizes.
class OHeap {
 public:
  explicit OHeap(size_t n);

  Block FindMin(crypto::Key enc_key, bool pad = true);
  Block ExtractMin(crypto::Key enc_key);
  void Insert(Block block, crypto::Key enc_key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const { return size_; }
  Pos GeneratePos() const;
  void DummyAccess(crypto::Key enc_key, bool with_find_min = true);
  void FillWithDummies(crypto::Key enc_key);
  unsigned long long MemoryAccessCount() { return memory_access_count_; }
  unsigned long long MemoryBytesMovedTotal() { return memory_access_bytes_total_; };

 private:
  size_t capacity_;
  size_t size_ = 0;
  unsigned int depth_;
  size_t num_buckets_;
  std::unique_ptr<EncryptedBucket[]> buckets_;
  std::vector<Block> stash_;
  unsigned long long memory_access_count_ = 0;
  unsigned long long memory_access_bytes_total_ = 0;

  Block ReadPath(Block query, bool return_if_found, crypto::Key enc_key);
  void UpdateMinAndEvict(Pos pos, crypto::Key enc_key);
  Block SiblingMin(unsigned int idx, crypto::Key enc_key);
  std::vector<unsigned int> Path(Pos pos) const;
  unsigned int PathAtLevel(Pos pos, unsigned int level) const;
  std::pair<Pos, Pos> GeneratePathPair();
  Pos GenerateSecondPos(Pos p);
};
} // namespace dyno::static_path_oheap

#endif //DYNO_STATIC_OHEAP_PATH_OHEAP_H
