#include "oheap.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <memory>
#include <utility>
#include <vector>

#include "openssl/rand.h"

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"

namespace dyno::static_path_oheap {
OHeap::OHeap(size_t n)
    : capacity_(n),
      depth_(ceil(log2(n))),
      num_buckets_((2 * n) - 1),
      buckets_(new EncryptedBucket[(2 * n) - 1]) {}

Block OHeap::FindMin(crypto::Key enc_key, bool pad) {
  ++memory_access_count_;
  memory_access_bytes_total_ += sizeof(EncryptedBucket);
  auto eb = buckets_[0];
  auto bu = eb.ToBucket(enc_key);
  auto res = bu.min_block_;
  // No need to re-encrypt; the algorithm doesn't update the root here.
  if (pad)
    DummyAccess(enc_key, false);
  return res;
}

Block OHeap::ExtractMin(crypto::Key enc_key) {
  Block min_block = FindMin(enc_key, false);
  if (!min_block.pos_) {
    DummyAccess(enc_key, false);
    return min_block;
  }

  Pos second_pos = GenerateSecondPos(min_block.pos_);
  ReadPath(min_block, true, enc_key);
  UpdateMinAndEvict(min_block.pos_, enc_key);
  ReadPath({second_pos, 0, 0}, true, enc_key);
  UpdateMinAndEvict(second_pos, enc_key);

  if (min_block.pos_)
    --size_;

  return min_block;
}

void OHeap::Insert(Block block, crypto::Key enc_key) {
  FindMin(enc_key, false); // To maintain obliviousness
  block.pos_ = GeneratePos();
  auto paths_to_evict = GeneratePathPair();
  stash_.push_back(block);
  ReadPath({paths_to_evict.first, 0, 0}, false, enc_key);
  UpdateMinAndEvict(paths_to_evict.first, enc_key);
  ReadPath({paths_to_evict.second, 0, 0}, false, enc_key);
  UpdateMinAndEvict(paths_to_evict.second, enc_key);
  ++size_;
}

Pos OHeap::GeneratePos() const {
  Pos res;
  RAND_bytes(reinterpret_cast<unsigned char *>(&res), sizeof(Pos));
  res = (res % capacity_) + 1;
  return res;
}

void OHeap::DummyAccess(crypto::Key enc_key, bool with_find_min) {
  if (with_find_min)
    FindMin(enc_key, false);
  auto positions = GeneratePathPair();
  ReadPath({positions.first, 0, 0}, false, enc_key);
  UpdateMinAndEvict(positions.first, enc_key);
  ReadPath({positions.second, 0, 0}, false, enc_key);
  UpdateMinAndEvict(positions.second, enc_key);
}

// Should only be called after allocation.
void OHeap::FillWithDummies(crypto::Key enc_key) {
  ++memory_access_count_;
  memory_access_bytes_total_ += num_buckets_ * sizeof(EncryptedBucket);
  auto empty = Bucket(true);
  for (size_t i = 0; i < num_buckets_; ++i) {
    buckets_[i] = EncryptedBucket(empty, enc_key);
  }
}

Block OHeap::ReadPath(Block query, bool return_if_found, crypto::Key enc_key) {
  bool found_res = false; // Duplicates are allowed
  Block res(true);
  auto path = Path(query.pos_);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * sizeof(EncryptedBucket);
  for (unsigned int idx : path) {
    Bucket bucket = buckets_[idx].ToBucket(enc_key);
    for (int i = 0; i < kBucketSize; i++) {
      Block b = bucket.blocks_[i];
      if (!found_res && return_if_found && (b == query)) {
        res = b;
        found_res = true;
      } else if (b.pos_) {
        stash_.push_back(b);
      }
    }
  }
  return res;
}

void OHeap::UpdateMinAndEvict(Pos pos, crypto::Key enc_key) {
  auto path = Path(pos);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * sizeof(EncryptedBucket);
  std::vector<bool> deleted_from_stash(stash_.size());
  unsigned int level = depth_;
  Block children_min_block(true);
  for (unsigned int idx : path) {
    std::array<Block, kBucketSize> blocks;
    int bucket_index = 0;
    for (int i = 0; i < stash_.size() && bucket_index < kBucketSize; i++) {
      if (deleted_from_stash[i])
        continue;
      if (PathAtLevel(stash_[i].pos_, level) == idx) {
        blocks[bucket_index++] = stash_[i];
        deleted_from_stash[i] = true;
      }
    }

    while (bucket_index < kBucketSize) {
      blocks[bucket_index] = Block(true); // Dummy
      ++bucket_index;
    }

    auto bucket = Bucket(blocks, children_min_block);
    buckets_[idx] = EncryptedBucket(bucket, enc_key);

    auto current_min_block = bucket.min_block_;
    auto sibling_min_block = SiblingMin(idx, enc_key);
    if (sibling_min_block.pos_
        && (!current_min_block.pos_
            || (sibling_min_block.key_ < current_min_block.key_)))
      children_min_block = sibling_min_block;
    else
      children_min_block = current_min_block;

    --level;
  }

  auto it = deleted_from_stash.begin();
  stash_.erase(
      std::remove_if(stash_.begin(), stash_.end(), [&](Block) { return *it++; }),
      stash_.end()
  );
}

Block OHeap::SiblingMin(unsigned int idx, crypto::Key enc_key) {
  if (idx == 0)
    return Block(true);

//  ++memory_access_count_; // No need, assuming all siblings are returned during path fetch.
  memory_access_bytes_total_ += sizeof(EncryptedBucket);

  unsigned int sibling_idx = idx % 2 ? idx + 1 : idx - 1;
  auto eb = buckets_[sibling_idx];
  auto bu = eb.ToBucket(enc_key);
  // No need to re-encrypt; the algorithm doesn't update the sibling.
  return bu.min_block_;
}

std::vector<unsigned int> OHeap::Path(Pos pos) const {
  assert(1 <= pos && pos <= capacity_);
  std::vector<unsigned int> res(depth_ + 1);
  unsigned int i = 0;
  unsigned int index = capacity_ - 1 + pos;
  while (index > 0) {
    res[i++] = index - 1; // index is 1-based but we need 0-based array indexes.
    index /= 2;
  }
  return res;
}

unsigned int OHeap::PathAtLevel(Pos pos, unsigned int level) const {
  return ((capacity_ - 1 + pos) / (1 << (depth_ - level))) - 1;
}

std::pair<Pos, Pos> OHeap::GeneratePathPair() {
  // 1 .. 2^{k-1}
  Pos pos1 = 1 + ((GeneratePos() - 1) >> 1);
  // 2^{k-1}+1 .. 2^k
  Pos pos2 = 1 + (((GeneratePos() - 1) >> 1) | (capacity_ >> 1));
  return std::make_pair(pos1, pos2);
}

Pos OHeap::GenerateSecondPos(Pos p) {
  // 2^{k-1} if p >= 2^{k-1}; else 0
  Pos base = ((capacity_ >> 1) & (p - 1)) ^ (capacity_ >> 1);
  return (base | ((GeneratePos() - 1) >> 1)) + 1;
}

EncryptedBucket::EncryptedBucket(const Bucket b, const crypto::Key key) {
  const auto data = bytes::ToBytes(b);
  bool success = crypto::Encrypt(data.data(), sizeof(Bucket), key, cipher_text_.data());
  assert(success);
  SetDigest();
}

EncryptedBucket::EncryptedBucket(std::array<uint8_t, kEncryptedBucketCipherLen> cipher_text)
    : cipher_text_(cipher_text) {
  SetDigest();
}

bool EncryptedBucket::HasValidDigest() {
  auto valid_digest = CalculateDigest();
  return digest_ == valid_digest;
}

void EncryptedBucket::SetDigest() {
  digest_ = CalculateDigest();
}

std::array<uint8_t, crypto::kDigestSize> EncryptedBucket::CalculateDigest() {
  std::array<uint8_t, crypto::kDigestSize> res;
  bool success = crypto::Hash(cipher_text_.data(), kEncryptedBucketCipherLen, res.data());
  assert(success);
  return res;
}

Bucket EncryptedBucket::ToBucket(crypto::Key key) {
  if (!HasValidDigest()) { // uninitialized
    Bucket empty(true);
    return empty;
  }

  std::vector<uint8_t> plain_text(cipher_text_.size());
  int plain_text_len = crypto::Decrypt(cipher_text_.data(), kEncryptedBucketCipherLen,
                                       key, plain_text.data());
  assert(plain_text_len == sizeof(Bucket));
  Bucket res;
  auto res_bytes = reinterpret_cast<uint8_t *>(std::addressof(res));
  std::move(plain_text.begin(), plain_text.begin() + sizeof(Bucket), res_bytes);

  return res;
}

Bucket::Bucket(bool zero_fill) {
  for (int i = 0; i < kBucketSize; i++)
    blocks_[i] = Block(zero_fill);
  min_block_ = Block(zero_fill);
}

Bucket::Bucket(std::array<Block, kBucketSize> blocks)
    : blocks_(blocks), min_block_(0, 0, 0) {
  UpdateMins();
}

Bucket::Bucket(std::array<Block, kBucketSize> blocks, Block children_min_block)
    : blocks_(blocks), min_block_(children_min_block) {
  UpdateMins();
}

void Bucket::UpdateMins() {
  for (auto bl : blocks_) {
    if (bl.pos_
        && (!min_block_.pos_
            || (bl.key_ < min_block_.key_))) {
      min_block_ = bl;
    }
  }
}

Block::Block(bool zero_fill) {
  if (zero_fill) {
    pos_ = 0;
    key_ = 0;
    val_ = 0;
  }
}

bool Block::operator==(const Block rhs) const {
  return pos_ == rhs.pos_ &&
      key_ == rhs.key_ &&
      val_ == rhs.val_;
}

bool Block::operator!=(const Block rhs) const {
  return !(rhs == *this);
}
} // namespace dyno::static_path_oheap
