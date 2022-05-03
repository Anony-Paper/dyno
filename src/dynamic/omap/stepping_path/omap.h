#ifndef DYNO_DYNAMIC_OMAP_STEPPING_PATH_OMAP_H_
#define DYNO_DYNAMIC_OMAP_STEPPING_PATH_OMAP_H_

#include <array>
#include <vector>

#include "../../../static/omap/path_avl/omap.h"
#include "../../../utils/crypto.h"

namespace dyno::dynamic_stepping_path_omap {

using Key = static_path_omap::Key;
using Val = static_path_omap::Val;
using KeyValPair = static_path_omap::KeyValPair;

//namespace {
using PathOMap = static_path_omap::OMap;
//} // namespace

class OMap {
 public:
  OMap() = default;
  // Only implemented for benchmarks.
  OMap(int starting_size_power_of_two);
  void Grow(crypto::Key enc_key);
  void Shrink(crypto::Key enc_key);
  void Insert(Key key, Val val, crypto::Key enc_key);
  Val Read(Key key, crypto::Key enc_key);
  Val ReadAndRemove(Key key, crypto::Key enc_key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const;
  unsigned long long MemoryAccessCount() { return memory_access_count_; }
  unsigned long long MemoryBytesMovedTotal() { return memory_bytes_moved_total_; }

 private:
  size_t capacity_ = 0;
  size_t size_ = 0;
  std::array<PathOMap *, 2> sub_omaps_{};
  size_t TotalSizeOfSubOmaps() const;
  unsigned long long memory_access_count_ = 0;
  unsigned long long memory_bytes_moved_total_ = 0;
  unsigned long long SubOMapsMemoryAccessCountSum();
  unsigned long long SubOMapsMemoryBytesMovedTotalSum();
};
} // dyno::dynamic_stepping_path_omap

#endif //DYNO_DYNAMIC_OMAP_STEPPING_PATH_OMAP_H_
