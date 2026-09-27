#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>


#include "crypto/keccak.h"
#include "crypto/rng.h"
#include "sphincs/address.h"
#include "sphincs/params.h"


uint32_t extract_fors_idx(const std::vector<uint8_t> &msg, int idx, int a);
Bytes extract_bytes(const std::vector<uint8_t> &src, size_t &offset,
                    size_t len);
uint64_t get_bits_from_stream(const std::vector<uint8_t> &bytes,
                              size_t bit_offset, int num_bits);
std::vector<uint32_t> base_w(const std::vector<uint8_t> &in, int w,
                             int out_len);
