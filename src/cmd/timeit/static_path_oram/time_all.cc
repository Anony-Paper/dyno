#include <chrono>
#include <iostream>
#include <memory>
#include <string>

#include "../../../static/oram/path/oram.h"
#include "../../../utils/crypto.h"

#ifndef VAL_LEN
#define VAL_LEN 4
#endif

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
               "init,init_accesses,init_bytes,"
               "insert,insert_accesses,insert_bytes,"
               "search,search_accesses,search_bytes,"
               "delete,delete_accesses,delete_bytes" << std::endl;

  for (unsigned int po2 = min_po2; po2 <= max_po2; ++po2) {
    size_t size = 1 << po2;

    std::chrono::duration<double> alloc_time{0};
    std::chrono::duration<double> init_time{0};
    unsigned long long init_bytes = 0;
    unsigned long long init_accesses = 0;
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

      auto oram_p = std::make_shared<static_path_oram::ORam<VAL_LEN>>(size);
      auto alloc_done = now();
      alloc_time += alloc_done - start;

      oram_p->FillWithDummies(enc_key);
      auto init_done = now();
      auto init_done_accesses = oram_p->MemoryAccessCount();
      auto init_done_bytes = oram_p->MemoryBytesMovedTotal();
      init_time += init_done - alloc_done;
      init_accesses += init_done_accesses;
      init_bytes += init_done_bytes;

      oram_p->Insert({1, 1}, enc_key);
      auto insert_done = now();
      auto insert_done_accesses = oram_p->MemoryAccessCount();
      auto insert_done_bytes = oram_p->MemoryBytesMovedTotal();
      insert_time += insert_done - init_done;
      insert_accesses += insert_done_accesses - init_done_accesses;
      insert_bytes += insert_done_bytes - init_done_bytes;

      oram_p->Read({1, 1}, enc_key);
      auto search_done = now();
      auto search_done_accesses = oram_p->MemoryAccessCount();
      auto search_done_bytes = oram_p->MemoryBytesMovedTotal();
      search_time += search_done - insert_done;
      search_accesses += search_done_accesses - insert_done_accesses;
      search_bytes += search_done_bytes - insert_done_bytes;

      oram_p->ReadAndRemove({1, 1}, enc_key);
      auto delete_done = now();
      auto delete_done_accesses = oram_p->MemoryAccessCount();
      auto delete_done_bytes = oram_p->MemoryBytesMovedTotal();
      delete_time += delete_done - search_done;
      delete_accesses += delete_done_accesses - search_done_accesses;
      delete_bytes += delete_done_bytes - search_done_bytes;
    }

    std::cout << po2 << ","
              << alloc_time.count() / num_runs << ","
              << init_time.count() / num_runs << ","
              << init_accesses / num_runs << ","
              << init_bytes / num_runs << ","
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
