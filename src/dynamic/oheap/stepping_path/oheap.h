#ifndef DYNO_DYNAMIC_OHEAP_STEPPING_PATH_O_HEAP_H_
#define DYNO_DYNAMIC_OHEAP_STEPPING_PATH_O_HEAP_H_

#include <array>
#include <vector>

#include "../../../static/oheap/path/oheap.h"
#include "../../../utils/crypto.h"

namespace dyno::dynamic_stepping_path_oheap {

using PathOHeap = static_path_oheap::OHeap;
using Block = static_path_oheap::Block;
using Key = static_path_oheap::Key;
using Val = static_path_oheap::Val;

class OHeap {
 public:
  OHeap() = default;
  // Only implemented for benchmarks.
  OHeap(int starting_size_power_of_two);
  void Grow(crypto::Key enc_key);
  void Shrink(crypto::Key enc_key);
  void Insert(Block block, crypto::Key enc_key, bool pad = true);
  Block FindMin(crypto::Key enc_key, bool pad = true);
  Block ExtractMin(crypto::Key enc_key);
  size_t Capacity() const { return capacity_; }
  size_t Size() const { return size_; }
  unsigned long long MemoryAccessCount() { return memory_access_count_; }
  unsigned long long MemoryBytesMovedTotal() { return memory_bytes_moved_total_; }

 private:
  size_t capacity_ = 0;
  size_t size_ = 0;
  std::array<PathOHeap *, 2> sub_oheaps_{};
  unsigned long long memory_access_count_ = 0;
  unsigned long long memory_bytes_moved_total_ = 0;
  unsigned long long SubOHeapsMemoryAccessCountSum();
  unsigned long long SubOHeapsMemoryBytesMovedTotalSum();
};
} // namespace dyno::dynamic_stepping_path_oheap

#endif //DYNO_DYNAMIC_OHEAP_STEPPING_PATH_O_HEAP_H_
