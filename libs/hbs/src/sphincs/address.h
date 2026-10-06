#pragma once

#include "crypto/shake.h"
#include <cstdint>
#include <cstring>
#include <vector>

const uint32_t ADDR_TYPE_WOTS = 0;
const uint32_t ADDR_TYPE_WOTS_PK = 1;
const uint32_t ADDR_TYPE_TREE = 2;
const uint32_t ADDR_TYPE_FORS_TREE = 3;
const uint32_t ADDR_TYPE_FORS_PK = 4;
const uint32_t ADDR_TYPE_WOTS_PRF = 5;
const uint32_t ADDR_TYPE_FORS_PRF = 6;

using Bytes = std::vector<uint8_t>;

struct Address {
  uint32_t words[8];
  Address() { memset(words, 0, sizeof(words)); }

  void set_layer(uint32_t l) { words[0] = l; }

  void set_tree(uint64_t t) {
    words[1] = 0;
    words[2] = (uint32_t)(t >> 32);
    words[3] = (uint32_t)t;
  }

  void set_type(uint32_t t) {
    words[4] = t;
    words[5] = 0;
    words[6] = 0;
    words[7] = 0;
  }

  void set_keypair(uint32_t k) { words[5] = k; }

  void set_chain(uint32_t c) { words[6] = c; }
  void set_hash(uint32_t h) { words[7] = h; }

  void set_tree_height(uint32_t h) { words[6] = h; }
  void set_tree_index(uint32_t i) { words[7] = i; }

  void sanitize_for_role(uint32_t role) {
    uint32_t kp = words[5];
    set_type(role);

    if (role == ADDR_TYPE_WOTS || role == ADDR_TYPE_WOTS_PK ||
        role == ADDR_TYPE_FORS_TREE || role == ADDR_TYPE_FORS_PK ||
        role == ADDR_TYPE_WOTS_PRF || role == ADDR_TYPE_FORS_PRF) {
      words[5] = kp;
    }
  }

  void write_bytes(uint8_t out[32]) const {
    for (int i = 0; i < 8; i++) {
      out[i * 4 + 0] = (uint8_t)((words[i] >> 24) & 0xFF);
      out[i * 4 + 1] = (uint8_t)((words[i] >> 16) & 0xFF);
      out[i * 4 + 2] = (uint8_t)((words[i] >> 8) & 0xFF);
      out[i * 4 + 3] = (uint8_t)((words[i] >> 0) & 0xFF);
    }
  }

  Bytes to_bytes() const {
    Bytes out(32);
    write_bytes(out.data());
    return out;
  }

  void absorb_into(Shake256 &k) const {
    uint8_t temp[32];
    write_bytes(temp);
    k.absorb(temp, 32);
  }
};
