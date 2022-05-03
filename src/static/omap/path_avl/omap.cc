#include "omap.h"

#include <cassert>
#include <cmath>
#include <map>
#include <vector>

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

#define max(a, b) ((a)>(b)?(a):(b))

namespace dyno::static_path_omap {

OMap::OMap(size_t n)
    : capacity_(n),
      oram_(n, false, true),
      max_depth_(ceil(1.44 * log2(n))),
      pad_val_(ceil(1.44 * 3.0 * log2(n))) {}

OMap::OMap(size_t n, std::vector<KeyValPair> data, crypto::Key enc_key)
    : capacity_(n),
      oram_(n, false, true),
      max_depth_(ceil(1.44 * log2(n))),
      pad_val_(ceil(1.44 * 3.0 * log2(n))) {
  for (KeyValPair kv : data) {
    Insert(kv.key_, kv.val_, enc_key);
  }
}

void OMap::Insert(Key key, Val val, crypto::Key enc_key) {
  auto replacement = Insert(key, val, root_, enc_key);
  root_ = replacement;
  Finalize(enc_key);
}

Val OMap::ReadAndRemove(Key key, crypto::Key enc_Key) {
  auto replacement = Delete(key, root_, enc_Key);
  root_ = replacement;
  Val res = 0;
  if (delete_successful_) {
    --size_;
    res = delete_res_;
    delete_res_ = 0;
    delete_successful_ = false;
  }
  Finalize(enc_Key);
  return res;
}

Val OMap::Read(Key key, crypto::Key enc_Key) {
  BlockPointer bp = Find(key, root_, enc_Key);
  Val res = 0;
  if (bp.key_) // Found
    res = cache_[bp.key_].val_;
  Finalize(enc_Key);
  return res;
}

BlockPointer OMap::Insert(Key key, Val val, BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) {
    root_bp.key_ = oram_.NextKey();
    cache_[root_bp.key_] = Block(key, val, 1);
    ++size_;
    return root_bp;
  }

  Block *current_block = Fetch(root_bp, enc_key);

  if (key == current_block->key_) {
    current_block->val_ = val;
    return root_bp;
  }

  // key != current_block->key_
  if (key < current_block->key_) {
    BlockPointer replacement = Insert(key, val, current_block->lc_pointer_, enc_key);
    current_block->lc_pointer_ = replacement;
  } else { // key > current_block->key_
    BlockPointer replacement = Insert(key, val, current_block->rc_pointer_, enc_key);
    current_block->rc_pointer_ = replacement;
  }

  // Adjust height
  unsigned int l_height = GetHeight(current_block->lc_pointer_, enc_key);
  unsigned int r_height = GetHeight(current_block->rc_pointer_, enc_key);
  unsigned int new_height = max(l_height, r_height) + 1;
  current_block->height_ = new_height;

  // Finally, balance
  return Balance(root_bp, enc_key);
}

BlockPointer OMap::Delete(Key key, BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) // Empty subtree
    return root_bp;

  Block *current_block = Fetch(root_bp, enc_key);

  // First, handle key != current_block->key_
  if (key < current_block->key_) {
    BlockPointer replacement = Delete(key, cache_[root_bp.key_].lc_pointer_, enc_key);
    cache_[root_bp.key_].lc_pointer_ = replacement;
    return Balance(root_bp, enc_key);
  } else if (key > current_block->key_) {
    BlockPointer replacement = Delete(key, cache_[root_bp.key_].rc_pointer_, enc_key);
    cache_[root_bp.key_].rc_pointer_ = replacement;
    return Balance(root_bp, enc_key);
  }

  // key == current_block->key_
  if (!delete_successful_) {
    delete_res_ = current_block->val_;
    delete_successful_ = true;
  } // Else the actual node had two children, and we're deleting the successor.
  auto lc_oram_key = current_block->lc_pointer_.key_;
  auto rc_oram_key = current_block->rc_pointer_.key_;

  // - No children
  if (!lc_oram_key && !rc_oram_key) {
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return {0, 0};
  }

  // - One child
  if (lc_oram_key && !rc_oram_key) { // Has left child
    BlockPointer res = current_block->lc_pointer_;
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return res;
  }
  if (!lc_oram_key && rc_oram_key) { // Has right child
    BlockPointer res = current_block->rc_pointer_;
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return res;
  }

  // - Two children
  //   1. Find the successor
  unsigned int max_search_time = max_depth_;
  BlockPointer it = current_block->rc_pointer_;
  Block *replacement;
  while (max_search_time--) {
    replacement = Fetch(it, enc_key);
    if (!replacement->lc_pointer_.key_)
      break;
    it = replacement->lc_pointer_;
  }

  //   2. Set current node's value to the successor's
  current_block->key_ = replacement->key_;
  current_block->val_ = replacement->val_;

  //   3. Delete the successor
  // This is done like this because the balancing of the replacement node may
  // cascade to its parents.
  current_block->rc_pointer_ = Delete(replacement->key_, current_block->rc_pointer_, enc_key);
  return Balance(root_bp, enc_key);
}

Block empty;
Block *OMap::Fetch(BlockPointer bp, crypto::Key enc_key) {
  if (!bp.key_) {
    empty = Block(0, 0);
    return &empty;
  }

  if (cache_.find(bp.key_) == cache_.end()) { // Not found in cache
    assert(bp.pos_);
    ++accesses_before_finalize_;
    auto oram_block = oram_.ReadAndRemove(ORamBlock(bp.pos_, bp.key_), enc_key);
    Block res;
    bytes::FromBytes(oram_block.val_, res);
    cache_[bp.key_] = res;
  }

  return &cache_[bp.key_];
}

BlockPointer OMap::Balance(BlockPointer root_bp, crypto::Key enc_key) {
  int bf = BalanceFactor(root_bp, enc_key);
  if (-1 <= bf && bf <= 1) // No rebalance necessary.
    return root_bp;

  Block current_block = cache_[root_bp.key_];
  if (bf < -1) { //           Left-heavy
    int l_bf = BalanceFactor(current_block.lc_pointer_, enc_key);
    if (l_bf > 0) { //        left-right
      BlockPointer new_lc_pointer = RotateLeft(current_block.lc_pointer_, enc_key);
      cache_[root_bp.key_].lc_pointer_ = new_lc_pointer;
      root_bp = RotateRight(root_bp, enc_key);
    } else { // l_bf <= 0 --> left-left // It may be = 0 too!
      root_bp = RotateRight(root_bp, enc_key);
    }
    return root_bp;
  }
  //                        Right-heavy
  int r_bf = BalanceFactor(current_block.rc_pointer_, enc_key);
  if (r_bf < 0) { //        right-left
    BlockPointer new_rc_pointer = RotateRight(current_block.rc_pointer_, enc_key);
    cache_[root_bp.key_].rc_pointer_ = new_rc_pointer;
    root_bp = RotateLeft(root_bp, enc_key);
  } else { // r_bf >= 0 --> right-right // It may be = 0 too!
    root_bp = RotateLeft(root_bp, enc_key);
  }

  return root_bp;
}

int OMap::BalanceFactor(BlockPointer bp, crypto::Key enc_key) {
  auto current_node = Fetch(bp, enc_key);
  unsigned int l_height = GetHeight(current_node->lc_pointer_, enc_key);
  unsigned int r_height = GetHeight(current_node->rc_pointer_, enc_key);
  return r_height - l_height;
}

unsigned int OMap::GetHeight(BlockPointer bp, crypto::Key enc_key) {
  if (!bp.key_)
    return 0;
  return Fetch(bp, enc_key)->height_;
}

BlockPointer OMap::RotateLeft(BlockPointer root_bp, crypto::Key enc_key) {
  Block *parent = Fetch(root_bp, enc_key);
  Block *rc = Fetch(parent->rc_pointer_, enc_key);
  Block *lc = Fetch(parent->lc_pointer_, enc_key);
  Block *rrc = Fetch(rc->rc_pointer_, enc_key);
  Block *rlc = Fetch(rc->lc_pointer_, enc_key);

  Block new_rc = *rrc;
  Block new_lc = Block(parent->key_, parent->val_,
                       parent->lc_pointer_, rc->lc_pointer_,
                       1 + max(lc->height_, rlc->height_));
  Block new_parent = Block(rc->key_, rc->val_,
                           root_bp, rc->rc_pointer_,
                           1 + max(new_lc.height_, new_rc.height_));
  BlockPointer new_parent_bp = parent->rc_pointer_;

  cache_[parent->rc_pointer_.key_] = new_parent;
  cache_[root_bp.key_] = new_lc;

  return new_parent_bp;
}

BlockPointer OMap::RotateRight(BlockPointer root_bp, crypto::Key enc_key) {
  Block *parent = Fetch(root_bp, enc_key);
  Block *rc = Fetch(parent->rc_pointer_, enc_key);
  Block *lc = Fetch(parent->lc_pointer_, enc_key);
  Block *lrc = Fetch(lc->rc_pointer_, enc_key);
  Block *llc = Fetch(lc->lc_pointer_, enc_key);

  Block new_lc = *llc;
  Block new_rc = Block(parent->key_, parent->val_,
                       lc->rc_pointer_, parent->rc_pointer_,
                       1 + max(lrc->height_, rc->height_));
  Block new_parent = Block(lc->key_, lc->val_,
                           lc->lc_pointer_, root_bp,
                           1 + max(new_lc.height_, new_rc.height_));
  BlockPointer new_parent_bp = parent->lc_pointer_;

  cache_[parent->lc_pointer_.key_] = new_parent;
  cache_[root_bp.key_] = new_rc;

  return new_parent_bp;
}

void OMap::Finalize(crypto::Key enc_key) {
  // Pad reads
  for (unsigned int i = accesses_before_finalize_; i < pad_val_; ++i)
    oram_.DummyAccess(enc_key);
  accesses_before_finalize_ = 0;

  // Re-position and re-write all cached
  std::map<ORamKey, ORamPos> pos_map;
  for (auto map_pair : cache_) {
    ORamKey ok = map_pair.first;
    pos_map[ok] = oram_.GeneratePos();
  }

  if (pos_map.find(root_.key_) != pos_map.end())
    root_.pos_ = pos_map[root_.key_];

  for (auto map_pair : cache_) {
    ORamKey ok = map_pair.first;
    ORamPos op = pos_map[ok];
    Block b = map_pair.second;
    if (pos_map.find(b.lc_pointer_.key_) != pos_map.end())
      b.lc_pointer_.pos_ = pos_map[b.lc_pointer_.key_];
    if (pos_map.find(b.rc_pointer_.key_) != pos_map.end())
      b.rc_pointer_.pos_ = pos_map[b.rc_pointer_.key_];
    ORamVal ov = bytes::ToBytes(b);
    oram_.Insert(ORamBlock(op, ok, ov), enc_key);
  }
  auto writes_done = cache_.size();
  cache_.clear();

  // Pad writes
  while (writes_done++ < pad_val_)
    oram_.DummyAccess(enc_key);
}

BlockPointer OMap::Find(Key key, BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) // Not found;
    return root_bp;
  Block *current_block = Fetch(root_bp, enc_key);
  if (key == current_block->key_)
    return root_bp;
  if (key < current_block->key_)
    return Find(key, current_block->lc_pointer_, enc_key);
  return Find(key, current_block->rc_pointer_, enc_key);
}

std::vector<KeyValPair> OMap::DecryptAll(crypto::Key enc_key) {
  std::vector<KeyValPair> res;
  DecryptAll(root_, &res, enc_key);
  Finalize(enc_key);
  return res;
}

void OMap::DecryptAll(BlockPointer root_bp, std::vector<KeyValPair> *res, crypto::Key enc_key) {
  if (!root_bp.key_)
    return;

  Block *b = Fetch(root_bp, enc_key);
  res->emplace_back(b->key_, b->val_);
  DecryptAll(b->lc_pointer_, res, enc_key);
  DecryptAll(b->rc_pointer_, res, enc_key);
}

KeyValPair OMap::TakeOne(crypto::Key enc_key) {
  Block *root_block = Fetch(root_, enc_key);
  auto key = root_block->key_;
  auto val = ReadAndRemove(root_block->key_, enc_key);
  return {key, val};
}

// Should only be called after allocation.
void OMap::FillWithDummies(crypto::Key enc_key) {
  oram_.FillWithDummies(enc_key);
}
} // namespace dyno::static_path_omap
