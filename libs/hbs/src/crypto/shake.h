#pragma once

#include "crypto/keccak.h"
#include <cstdint>
#include <cstring>
#include <vector>

#ifdef PQC_HAS_OPENSSL
#include <openssl/evp.h>
#endif

/* Incremental SHAKE256. OpenSSL EVP_shake256 when PQC_HAS_OPENSSL, else scalar
 * Keccak. */
class Shake256 {
#ifdef PQC_HAS_OPENSSL
  EVP_MD_CTX *ctx_ = nullptr;
#else
  Keccak k_;
#endif

public:
  Shake256();
  Shake256(const Shake256 &other);
  Shake256 &operator=(const Shake256 &other);
  ~Shake256();

  void absorb(const uint8_t *in, size_t len);
  void absorb(const std::vector<uint8_t> &in) {
    if (!in.empty())
      absorb(in.data(), in.size());
  }

  void squeeze(uint8_t *out, size_t out_len);

  static void hash(const uint8_t *in, size_t in_len, uint8_t *out,
                   size_t out_len);
  static void hash(const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
    if (!out.empty())
      hash(in.empty() ? nullptr : in.data(), in.size(), out.data(), out.size());
  }
};
