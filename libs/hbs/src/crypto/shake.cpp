#include "crypto/shake.h"
#include <stdexcept>

#ifdef PQC_HAS_OPENSSL

Shake256::Shake256() {
  ctx_ = EVP_MD_CTX_new();
  if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_shake256(), nullptr) != 1)
    throw std::runtime_error("OpenSSL SHAKE256 init failed");
}

Shake256::Shake256(const Shake256 &other) {
  ctx_ = EVP_MD_CTX_new();
  if (!ctx_ || EVP_MD_CTX_copy_ex(ctx_, other.ctx_) != 1)
    throw std::runtime_error("OpenSSL SHAKE256 copy failed");
}

Shake256 &Shake256::operator=(const Shake256 &other) {
  if (this == &other)
    return *this;
  EVP_MD_CTX *next = EVP_MD_CTX_new();
  if (!next || EVP_MD_CTX_copy_ex(next, other.ctx_) != 1) {
    EVP_MD_CTX_free(next);
    throw std::runtime_error("OpenSSL SHAKE256 copy failed");
  }
  EVP_MD_CTX_free(ctx_);
  ctx_ = next;
  return *this;
}

Shake256::~Shake256() { EVP_MD_CTX_free(ctx_); }

void Shake256::absorb(const uint8_t *in, size_t len) {
  if (len && EVP_DigestUpdate(ctx_, in, len) != 1)
    throw std::runtime_error("OpenSSL SHAKE256 absorb failed");
}

void Shake256::squeeze(uint8_t *out, size_t out_len) {
  if (EVP_DigestFinalXOF(ctx_, out, out_len) != 1)
    throw std::runtime_error("OpenSSL SHAKE256 squeeze failed");
}

void Shake256::hash(const uint8_t *in, size_t in_len, uint8_t *out,
                    size_t out_len) {
  Shake256 s;
  s.absorb(in, in_len);
  s.squeeze(out, out_len);
}

#else

Shake256::Shake256() = default;
Shake256::Shake256(const Shake256 &other) = default;
Shake256 &Shake256::operator=(const Shake256 &other) = default;
Shake256::~Shake256() = default;

void Shake256::absorb(const uint8_t *in, size_t len) {
  if (len)
    k_.absorb(in, len);
}

void Shake256::squeeze(uint8_t *out, size_t out_len) {
  k_.finalize_and_squeeze(out, out_len);
}

void Shake256::hash(const uint8_t *in, size_t in_len, uint8_t *out,
                    size_t out_len) {
  Keccak k;
  if (in_len)
    k.absorb(in, in_len);
  k.finalize_and_squeeze(out, out_len);
}

#endif
