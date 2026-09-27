#include "sphincs/params.h"
#include <stdexcept>

SphincsPlus::Params::Params(SphexVariant v) {
  W = 16;
  switch (v) {
  case SphexVariant::SHAKE_128F_SIMPLE:
    N = 16;
    H = 66;
    D = 22;
    A = 6;
    K = 33;
    break;
  case SphexVariant::SHAKE_192F_SIMPLE:
    N = 24;
    H = 66;
    D = 22;
    A = 8;
    K = 33;
    break;
  case SphexVariant::SHAKE_256F_SIMPLE:
    N = 32;
    H = 68;
    D = 17;
    A = 9;
    K = 35;
    break;

  case SphexVariant::SHAKE_128S_SIMPLE:
    N = 16;
    H = 63;
    D = 7;
    A = 12;
    K = 14;
    break;
  case SphexVariant::SHAKE_192S_SIMPLE:
    N = 24;
    H = 63;
    D = 7;
    A = 14;
    K = 17;
    break;
  case SphexVariant::SHAKE_256S_SIMPLE:
    N = 32;
    H = 64;
    D = 8;
    A = 14;
    K = 22;
    break;
  default:
    throw std::invalid_argument("Unknown Variant");
  }

  H_PRIME = H / D;

  int log_w = 0;
  while ((1 << log_w) < W)
    ++log_w;

  this->len1 = (8 * N + log_w - 1) / log_w;

  uint64_t csum_max = (uint64_t)this->len1 * (W - 1);
  int csum_bits = 0;
  while (csum_max) {
    csum_max >>= 1;
    csum_bits++;
  }

  this->len2 = (csum_bits + log_w - 1) / log_w;
  this->WOTS_LEN = this->len1 + this->len2;
}
