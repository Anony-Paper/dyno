#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "../../../utils/crypto.h"

using namespace dyno;
auto now = std::chrono::high_resolution_clock::now;

constexpr size_t kValLen = 4;
constexpr size_t kEncValLen = crypto::CiphertextLen(kValLen);

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

  auto val = std::array<uint8_t, 4>{};
  std::array<uint8_t, kEncValLen> ev{};
  for (unsigned int po2 = min_po2; po2 <= max_po2; ++po2) {
    size_t size = 1 << po2;

    std::chrono::duration<double> alloc_time{0};
    std::chrono::duration<double> insert_time{0};
    unsigned long long insert_bytes = kEncValLen;
    unsigned long long insert_accesses = 1;
    std::chrono::duration<double> search_time{0};
    unsigned long long search_bytes = kEncValLen;
    unsigned long long search_accesses = 1;
    std::chrono::duration<double> delete_time{0};
    unsigned long long delete_bytes = kEncValLen;
    unsigned long long delete_accesses = 1;

    for (int run = 0; run < num_runs; ++run) {
      auto enc_key = crypto::GenerateKey();

      auto start = now();

      auto stack_p = new std::vector<std::array<uint8_t, kEncValLen>>(size);
      auto stack = *stack_p;
      auto alloc_done = now();
      alloc_time += alloc_done - start;

      crypto::Encrypt(val.data(), kValLen, enc_key, ev.data());
      stack.push_back(ev);
      auto insert_done = now();
      insert_time += insert_done - start;

      stack.back();
      auto search_done = now();
      search_time += search_done - insert_done;

      stack.pop_back();
      auto delete_done = now();
      delete_time += delete_done - search_done;

      delete stack_p;
    }

    std::cout << po2 << ","
              << alloc_time.count() / num_runs << ","
              << insert_time.count() / num_runs << ","
              << insert_accesses << ","
              << insert_bytes << ","
              << search_time.count() / num_runs << ","
              << search_accesses << ","
              << search_bytes << ","
              << delete_time.count() / num_runs << ","
              << delete_accesses << ","
              << delete_bytes << std::endl;
  }

  return 0;
}
