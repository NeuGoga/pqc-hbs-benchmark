#include "internal/types.h"

Bytes extract_bytes(const std::vector<uint8_t> &src, size_t &offset,
                    size_t len) {
  if (offset + len > src.size()) {
    throw std::runtime_error("Signature too short");
  }
  Bytes out(src.begin() + offset, src.begin() + offset + len);
  offset += len;
  return out;
}

/* This function takes the message digest and extracts a specific
 *  sequence of bits of size a to use as an inder for a FORS tree.
 *  It reads the bits out of the byte array in a order of
 *  least-significant bit first.
 */
uint32_t extract_fors_idx(const std::vector<uint8_t> &msg, int idx, int a) {
  uint32_t res = 0;
  int frm_idx = idx * a;
  int to_idx = frm_idx + a - 1;
  for (int i = frm_idx; i <= to_idx; i++) {
    int byte_off = i >> 3;
    int bit_off = i & 7;
    uint8_t bit = (msg[byte_off] >> bit_off) & 1;
    res |= (bit << (i - frm_idx));
  }
  return res;
}

uint64_t get_bits_from_stream(const std::vector<uint8_t> &bytes,
                              size_t bit_offset, int num_bits) {
  if (num_bits == 0)
    return 0;

  uint64_t out = 0;
  for (int i = 0; i < num_bits; ++i) {
    size_t bit_pos = bit_offset + i;
    size_t byte_idx = bit_pos / 8;
    if (byte_idx >= bytes.size())
      return out << (num_bits - i);

    int bit_in_byte = 7 - (bit_pos % 8);
    uint8_t bit = (bytes[byte_idx] >> bit_in_byte) & 1;
    out = (out << 1) | bit;
  }
  return out;
}

std::vector<uint32_t> base_w(const std::vector<uint8_t> &in, int w,
                             int out_len) {
  int log_w = 0;
  while ((1 << log_w) < w)
    ++log_w;

  std::vector<uint32_t> out;
  out.reserve(out_len);

  size_t bit_cursor = 0;
  for (int i = 0; i < out_len; ++i) {
    uint32_t val = (uint32_t)get_bits_from_stream(in, bit_cursor, log_w);
    out.push_back(val);
    bit_cursor += log_w;
  }
  return out;
}
