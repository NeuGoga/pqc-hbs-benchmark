#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

class Keccak {
private:
  uint64_t state[25];
  uint8_t buffer[136];
  int buf_off;
  const int rate = 136;

  uint64_t rotl(uint64_t x, int s) { return (x << s) | (x >> (64 - s)); }

  void keccak_f1600();

public:
  Keccak() {
    std::memset(state, 0, sizeof(state));
    std::memset(buffer, 0, sizeof(buffer));
    buf_off = 0;
  }

  Keccak(const Keccak &other) {
    std::memcpy(state, other.state, sizeof(state));
    std::memcpy(buffer, other.buffer, sizeof(buffer));
    buf_off = other.buf_off;
  }

  Keccak &operator=(const Keccak &other) {
    if (this != &other) {
      std::memcpy(state, other.state, sizeof(state));
      std::memcpy(buffer, other.buffer, sizeof(buffer));
      buf_off = other.buf_off;
    }
    return *this;
  }

  void absorb(const std::vector<uint8_t> &in) {
    if (!in.empty())
      absorb(in.data(), in.size());
  }

  void absorb(const uint8_t *in, size_t len);

  void finalize_and_squeeze(std::vector<uint8_t> &out) {
    if (!out.empty())
      finalize_and_squeeze(out.data(), out.size());
  }

  void finalize_and_squeeze(uint8_t *out, size_t out_len);

  static void shake256(const std::vector<uint8_t> &input,
                       std::vector<uint8_t> &output) {
    Keccak k;
    k.absorb(input);
    k.finalize_and_squeeze(output);
  }
};
