#include <chrono>
#include <iostream>
#include <string>

#include "../../../dynamic/oheap/stepping_path/oheap.h"
#include "../../../utils/crypto.h"

using namespace dyno;
auto now = std::chrono::high_resolution_clock::now;

int main(int argc, char **argv) {
  if (argc != 3)
    return 1;

  const int num_runs = 4;
  unsigned int min_po2 = std::stoi(argv[1]);
  unsigned int max_po2 = std::stoi(argv[2]);
  if (max_po2 < min_po2)
    return 1;

  std::cout << "n,"
               "alloc,"
               "insert,insert_accesses,insert_bytes,"
               "search,search_accesses,search_bytes,"
               "delete,delete_accesses,delete_bytes" << std::endl;

  for (unsigned int po2 = min_po2; po2 <= max_po2; ++po2) {
    std::chrono::duration<double> alloc_time{0};
    std::chrono::duration<double> insert_time{0};
    unsigned long long insert_bytes = 0;
    unsigned long long insert_accesses = 0;
    std::chrono::duration<double> search_time{0};
    unsigned long long search_bytes = 0;
    unsigned long long search_accesses = 0;
    std::chrono::duration<double> delete_time{0};
    unsigned long long delete_bytes = 0;
    unsigned long long delete_accesses = 0;

    for (int run = 0; run < num_runs; ++run) {
      auto enc_key = crypto::GenerateKey();

      auto start = now();

      auto oheap_p = new dynamic_stepping_path_oheap::OHeap(po2);
      auto oheap = *oheap_p;
      auto alloc_done = now();
      alloc_time += alloc_done - start;

      oheap.Grow(enc_key);
      oheap.Insert({1, 1, 1}, enc_key);
      auto insert_done = now();
      auto insert_done_accesses = oheap.MemoryAccessCount();
      auto insert_done_bytes = oheap.MemoryBytesMovedTotal();
      insert_time += insert_done - start;
      insert_accesses += insert_done_accesses;
      insert_bytes += insert_done_bytes;

      oheap.FindMin(enc_key);
      auto search_done = now();
      auto search_done_accesses = oheap.MemoryAccessCount();
      auto search_done_bytes = oheap.MemoryBytesMovedTotal();
      search_time += search_done - insert_done;
      search_accesses += search_done_accesses - insert_done_accesses;
      search_bytes += search_done_bytes - insert_done_bytes;

      oheap.ExtractMin(enc_key);
      auto delete_done = now();
      auto delete_done_accesses = oheap.MemoryAccessCount();
      auto delete_done_bytes = oheap.MemoryBytesMovedTotal();
      delete_time += delete_done - search_done;
      delete_accesses += delete_done_accesses - search_done_accesses;
      delete_bytes += delete_done_bytes - search_done_bytes;

      delete oheap_p;
    }

    std::cout << po2 << ","
              << alloc_time.count() / num_runs << ","
              << insert_time.count() / num_runs << ","
              << insert_accesses / num_runs << ","
              << insert_bytes / num_runs << ","
              << search_time.count() / num_runs << ","
              << search_accesses / num_runs << ","
              << search_bytes / num_runs << ","
              << delete_time.count() / num_runs << ","
              << delete_accesses / num_runs << ","
              << delete_bytes / num_runs << std::endl;
  }

  return 0;
}
