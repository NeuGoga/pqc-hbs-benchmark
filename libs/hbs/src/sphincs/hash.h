#pragma once
#include "internal/types.h"

void thash(const Shake256 &state_seeded, const uint8_t *in, size_t in_len,
           const Address &addr, int N, uint8_t *out);
void prf(const Shake256 &state_seeded, const uint8_t *sk_seed,
         const Address &addr, int N, uint8_t *out);
void prf_msg(const uint8_t *sk_prf, const uint8_t *optrand, size_t n,
             const uint8_t *msg, size_t msg_len, uint8_t *out);
