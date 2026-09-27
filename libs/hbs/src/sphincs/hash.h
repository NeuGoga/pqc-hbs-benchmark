#pragma once
#include "internal/types.h"

void thash(const Keccak &state_seeded, const uint8_t *in, size_t in_len,
           const Address &addr, int N, uint8_t *out);
void prf(const Keccak &state_seeded, const uint8_t *sk_seed,
         const Address &addr, int N, uint8_t *out);
Bytes prf_msg(const Bytes &sk_prf, const Bytes &optrand, const Bytes &msg,
              int N);
