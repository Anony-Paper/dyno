#ifndef DYNO_UTILS_CRYPTO_H
#define DYNO_UTILS_CRYPTO_H

#include <array>
#include <cassert>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace dyno::crypto {

const auto kDigest = EVP_sha256;
const auto kCipher = EVP_aes_256_cbc;
const unsigned int kKeySize = 32;
static const int kDigestSize = 32; // EVP_MD_size(kDigest());
static const unsigned int kBlockSize = AES_BLOCK_SIZE;
static const unsigned int kIvSize = AES_BLOCK_SIZE;

using Key = std::array<uint8_t, kKeySize>;
using Iv = std::array<uint8_t, kIvSize>;

template<size_t n>
inline std::array<uint8_t, n> GenRandBytes() {
  std::array<uint8_t, n> res;
  RAND_bytes(res.data(), n);
  return res;
}

inline auto GenerateKey = GenRandBytes<sizeof(Key)>;
inline auto GenerateIv = GenRandBytes<sizeof(Iv)>;

inline bool Hash(const uint8_t *val, const size_t val_len, uint8_t *res) {
  EVP_MD_CTX *ctx;

  if ((ctx = EVP_MD_CTX_new()) == nullptr)
    return false;

  if (EVP_DigestInit_ex(ctx, kDigest(), nullptr) != 1)
    return false;

  if (EVP_DigestUpdate(ctx, val, val_len) != 1)
    return false;

  unsigned int res_len = 0;
  if (EVP_DigestFinal_ex(ctx, res, &res_len) != 1)
    return false;
  assert(res_len == kDigestSize);

  EVP_MD_CTX_free(ctx);
  return true;
}

constexpr inline size_t CiphertextLen(size_t plaintext_len) {
  return (((plaintext_len + kBlockSize) / kBlockSize) * kBlockSize) + kIvSize;
}

// Chooses a random IV, and returns the ciphertext with the IV appended to the end of it.
inline bool Encrypt(const uint8_t *val, const size_t val_len, const Key key, uint8_t *res) {
  EVP_CIPHER_CTX *ctx;
  Iv iv = GenerateIv();
  Iv iv_copy = Iv(iv); // Because OpenSSL may mess with the IV passed to it.
  int len, ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (1 != EVP_EncryptInit_ex(ctx, kCipher(), nullptr, key.data(), iv_copy.data())) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (1 != EVP_EncryptUpdate(ctx, res, &len, val, val_len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, res + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  ciphertext_len += len;
  assert(ciphertext_len == (CiphertextLen(val_len) - kIvSize));

  // Append IV to the end of the ciphertext.
  std::copy(iv.begin(), iv.end(), res + ciphertext_len);

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// Assumes the last bytes of val are the IV.
// Returns plaintext len.
inline int Decrypt(const uint8_t *val, const size_t val_len, const Key key, uint8_t *res) {
  EVP_CIPHER_CTX *ctx;
  int plen, len;
  int clen = val_len - kIvSize;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  if (1 != EVP_DecryptInit_ex(ctx, kCipher(), nullptr, key.data(), val + clen)) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  if (1 != EVP_DecryptUpdate(ctx, res, &len, val, clen)) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  plen = len;

  if (1 != EVP_DecryptFinal_ex(ctx, res + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  plen += len;

  EVP_CIPHER_CTX_free(ctx);

  return plen;
}
} // namespace dyno::crypto

#endif //DYNO_UTILS_CRYPTO_H
