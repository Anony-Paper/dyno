#ifndef DYNO_STATIC_OMAP_PATH_AVL_H
#define DYNO_STATIC_OMAP_PATH_AVL_H

#include <map>
#include <vector>

#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_omap {

using Key = unsigned int;
using Val = unsigned int;
class KeyValPair {
 public:
  Key key_;
  Val val_;

  KeyValPair() = default;
  KeyValPair(unsigned int key, unsigned int val) : key_(key), val_(val) {}
};

//namespace { // Internal use only

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
  Key key_;
  Val val_;
  BlockPointer lc_pointer_, rc_pointer_; // lc := left child; rc := right child
  unsigned int height_;

  Block() = default;
  Block(Key key, Val val)
      : key_(key), val_(val), lc_pointer_(0, 0), rc_pointer_(0, 0), height_(0) {}
  Block(Key key, Val val, unsigned int height)
      : key_(key), val_(val), lc_pointer_(0, 0), rc_pointer_(0, 0), height_(height) {}
  Block(Key key, Val val, BlockPointer lc_pointer, BlockPointer rc_pointer, unsigned int height)
      : key_(key), val_(val), lc_pointer_(lc_pointer), rc_pointer_(rc_pointer), height_(height) {}
};

constexpr size_t kBlockSize = sizeof(Block);

using ORamVal = static_path_oram::Val<kBlockSize>;
using ORamBlock = static_path_oram::Block<kBlockSize>;
using PathORam = static_path_oram::ORam<kBlockSize>;
//} // namespace

class OMap {
 public:
  explicit OMap(size_t n);
  OMap(size_t n, std::vector<KeyValPair> data, crypto::Key enc_key);
  void Insert(Key key, Val val, crypto::Key enc_key);
  Val ReadAndRemove(Key key, crypto::Key enc_Key);
  Val Read(Key key, crypto::Key enc_Key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const { return size_; }
  std::vector<KeyValPair> DecryptAll(crypto::Key enc_key);
  KeyValPair TakeOne(crypto::Key enc_key);
  void FillWithDummies(crypto::Key enc_key);
  unsigned long long MemoryAccessCount() { return oram_.MemoryAccessCount(); }
  unsigned long long MemoryBytesMovedTotal() { return oram_.MemoryBytesMovedTotal(); }

 private:
  const size_t capacity_;
  const unsigned int max_depth_;
  const unsigned int pad_val_;
  size_t size_ = 0;
  PathORam oram_;
  BlockPointer root_ = BlockPointer(0, 0); // Can and will change.
  unsigned int accesses_before_finalize_ = 0;
  std::map<ORamKey, Block> cache_;
  Val delete_res_ = 0;
  bool delete_successful_ = false;

  BlockPointer Insert(Key key, Val val, BlockPointer root, crypto::Key enc_key);
  BlockPointer Delete(Key key, BlockPointer root, crypto::Key enc_key);
  Block *Fetch(BlockPointer bp, crypto::Key enc_key);
  BlockPointer Balance(BlockPointer root, crypto::Key enc_key);
  int BalanceFactor(BlockPointer bp, crypto::Key enc_key);
  unsigned int GetHeight(BlockPointer bp, crypto::Key enc_key);
  BlockPointer RotateLeft(BlockPointer root, crypto::Key enc_key);
  BlockPointer RotateRight(BlockPointer root, crypto::Key enc_key);
  void Finalize(crypto::Key enc_key);
  BlockPointer Find(Key key, BlockPointer root, crypto::Key enc_key);
  void DecryptAll(BlockPointer root_bp, std::vector<KeyValPair> *res, crypto::Key enc_key);
};
} // namespace dyno::static_path_omap

#endif //DYNO_STATIC_OMAP_PATH_AVL_H
