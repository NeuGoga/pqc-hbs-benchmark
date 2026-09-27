#include "sphincs/hash.h"

void thash(const Keccak &state_seeded, const uint8_t *in, size_t in_len,
           const Address &addr, int N, uint8_t *out) {
  Keccak k = state_seeded;
  addr.absorb_into(k);
  k.absorb(in, in_len);
  k.finalize_and_squeeze(out, N);
}

/*  This function takes secret key seed, public key seed,
 *   and a specific Address, and generates N pseudo-random bytes.
 *   It is used to deteremenistically generate teh secret key material
 *   for the WOTS+ and FORS leaves without storing them.
 */
void prf(const Keccak &state_seeded, const uint8_t *sk_seed,
         const Address &addr, int N, uint8_t *out) {
  Keccak k = state_seeded;
  addr.absorb_into(k);
  k.absorb(sk_seed, N);
  k.finalize_and_squeeze(out, N);
}

/* This function takes secret PRF key, a randomizer, and the
 *   message being signed, and hashes them together.
 *   It returns N random bytes that are attached to the start
 *   of the signature.
 */
Bytes prf_msg(const Bytes &sk_prf, const Bytes &optrand, const Bytes &msg,
              int N) {
  Keccak k;
  k.absorb(sk_prf);
  k.absorb(optrand);
  k.absorb(msg);
  Bytes out(N);
  k.finalize_and_squeeze(out);
  return out;
}
