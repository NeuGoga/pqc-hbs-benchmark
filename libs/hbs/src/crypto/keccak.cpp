#include "crypto/keccak.h"
#include <algorithm>
#include <cstring>


void Keccak::keccak_f1600() {
  static const uint64_t RC[24] = {
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
      0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
      0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
      0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

  static const int rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                              27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

  static const int pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                             15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

  for (int round = 0; round < 24; round++) {
    uint64_t C[5], D[5];
    for (int i = 0; i < 5; i++)
      C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^
             state[i + 20];
    for (int i = 0; i < 5; i++)
      D[i] = C[(i + 4) % 5] ^ rotl(C[(i + 1) % 5], 1);
    for (int i = 0; i < 25; i++)
      state[i] ^= D[i % 5];

    uint64_t current = state[1], temp;
    for (int i = 0; i < 24; i++) {
      int j = pi[i];
      temp = state[j];
      state[j] = rotl(current, rho[i]);
      current = temp;
    }

    for (int j = 0; j < 25; j += 5) {
      uint64_t t[5];
      for (int i = 0; i < 5; i++)
        t[i] = state[j + i];
      for (int i = 0; i < 5; i++)
        state[j + i] ^= (~t[(i + 1) % 5]) & t[(i + 2) % 5];
    }
    state[0] ^= RC[round];
  }
}

void Keccak::absorb(const uint8_t *in, size_t len) {
  size_t in_off = 0;
  while (in_off < len) {
    size_t chunk = std::min(len - in_off, (size_t)(rate - buf_off));
    std::memcpy(buffer + buf_off, in + in_off, chunk);
    buf_off += chunk;
    in_off += chunk;

    if (buf_off == rate) {
      for (int i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int k = 0; k < 8; k++)
          lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
        state[i] ^= lane;
      }
      keccak_f1600();
      buf_off = 0;
    }
  }
}

void Keccak::finalize_and_squeeze(uint8_t *out, size_t out_len) {
  buffer[buf_off++] = 0x1F;
  while (buf_off < rate)
    buffer[buf_off++] = 0;
  buffer[rate - 1] ^= 0x80;

  for (int i = 0; i < rate / 8; i++) {
    uint64_t lane = 0;
    for (int k = 0; k < 8; k++)
      lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
    state[i] ^= lane;
  }
  keccak_f1600();

  size_t out_off = 0;

  while (out_len > 0) {
    size_t chunk = std::min(out_len, (size_t)rate);
    for (size_t i = 0; i < chunk; i++) {
      out[out_off + i] = (uint8_t)((state[i / 8] >> (8 * (i % 8))) & 0xFF);
    }
    out_off += chunk;
    out_len -= chunk;
    if (out_len > 0)
      keccak_f1600();
  }
}
