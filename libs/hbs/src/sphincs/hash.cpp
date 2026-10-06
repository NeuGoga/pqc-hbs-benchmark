#include "sphincs/hash.h"

void thash(const Shake256 &state_seeded, const uint8_t *in, size_t in_len,
           const Address &addr, int N, uint8_t *out) {
  Shake256 k = state_seeded;
  addr.absorb_into(k);
  if (in_len)
    k.absorb(in, in_len);
  k.squeeze(out, (size_t)N);
}

void prf(const Shake256 &state_seeded, const uint8_t *sk_seed,
         const Address &addr, int N, uint8_t *out) {
  Shake256 k = state_seeded;
  addr.absorb_into(k);
  k.absorb(sk_seed, (size_t)N);
  k.squeeze(out, (size_t)N);
}

void prf_msg(const uint8_t *sk_prf, const uint8_t *optrand, size_t n,
             const uint8_t *msg, size_t msg_len, uint8_t *out) {
  Shake256 k;
  k.absorb(sk_prf, n);
  k.absorb(optrand, n);
  if (msg_len)
    k.absorb(msg, msg_len);
  k.squeeze(out, n);
}
