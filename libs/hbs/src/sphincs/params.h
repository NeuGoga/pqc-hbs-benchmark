#pragma once

#include "hbs/sphincs.h"

struct SphincsPlus::Params {
  int N;
  int W;
  int H;
  int D;
  int A;
  int K;
  int H_PRIME;
  int WOTS_LEN;
  int len1;
  int len2;

  explicit Params(SphexVariant v);
};
