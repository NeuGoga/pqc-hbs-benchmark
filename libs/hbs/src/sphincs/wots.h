#pragma once
#include "internal/types.h"
#include "sphincs/hash.h"

void gen_chain(const Keccak &state_seeded, const uint8_t *in, int start,
               int steps, Address addr, int N, uint8_t *out);
void wots_chain(const Keccak &state_seeded, const uint8_t *in, int start,
                int steps, Address &addr, int N, uint8_t *out);
Bytes wots_pkgen(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                 SphincsPlus::Params *p);
Bytes wots_sign(const Bytes &msg, const Bytes &sk_seed, const Bytes &pub_seed,
                Address addr, SphincsPlus::Params *p);
Bytes wots_pk_from_sig(const Bytes &sig, const Bytes &msg,
                       const Bytes &pub_seed, Address addr,
                       SphincsPlus::Params *p);
