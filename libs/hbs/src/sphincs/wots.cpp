#include "sphincs/wots.h"

void gen_chain(const Keccak &state_seeded, const uint8_t *in, int start,
               int steps, Address addr, int N, uint8_t *out) {
  std::memcpy(out, in, N);
  for (int i = start; i < start + steps; i++) {
    addr.set_hash(i);
    thash(state_seeded, out, N, addr, N, out);
  }
}

/*  This function used in WOTS+ verification.
 *   It hashes the input buffer and hashes it for the number
 *   of steps. It increments the Address hash index on every step.
 *   Write results into the out pointer.
 */
void wots_chain(const Keccak &state_seeded, const uint8_t *in, int start,
                int steps, Address &addr, int N, uint8_t *out) {
  std::memcpy(out, in, N);
  for (int i = start; i < start + steps; i++) {
    addr.set_hash(i);
    thash(state_seeded, out, N, addr, N, out);
  }
}

/*  This function genereates a WOTS+ public key.
 *   It generates all of the secret key leaves using the PRF,
 *   hashes each leaf to the very top of its chain, and then hashes
 *   all of those into a single N-byte public key.
 */
Bytes wots_pkgen(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                 SphincsPlus::Params *p) {
  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  addr.sanitize_for_role(ADDR_TYPE_WOTS);
  addr.set_hash(0);

  Bytes pk_accum(p->WOTS_LEN * p->N);

  for (int i = 0; i < p->WOTS_LEN; i++) {
    addr.set_chain(i);

    Address prf_addr = addr;
    prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
    prf_addr.set_keypair(addr.words[5]);
    prf_addr.set_chain(i);
    prf_addr.set_hash(0);

    Bytes sk(p->N);

    prf(state_seeded, sk_seed.data(), prf_addr, p->N, sk.data());

    gen_chain(state_seeded, sk.data(), 0, p->W - 1, addr, p->N,
              pk_accum.data() + i * p->N);

    secure_wipe(sk);
  }

  addr.set_chain(0);
  addr.set_hash(0);

  uint32_t original_keypair = addr.words[5];
  addr.set_type(ADDR_TYPE_WOTS_PK);
  addr.set_keypair(original_keypair);

  Bytes pk(p->N);
  thash(state_seeded, pk_accum.data(), pk_accum.size(), addr, p->N, pk.data());
  return pk;
}

static std::vector<uint32_t> compute_wots_digits(const Bytes &msg_hash,
                                                 SphincsPlus::Params *p) {
  int log_w = 0;
  while ((1 << log_w) < p->W)
    ++log_w;

  int len1 = p->len1;
  int len2 = p->len2;

  std::vector<uint32_t> digits = base_w(msg_hash, p->W, len1);

  uint64_t csum = 0;
  for (uint32_t v : digits)
    csum += (uint64_t)(p->W - 1 - v);

  if ((len2 * log_w) % 8 != 0) {
    csum <<= (8 - ((len2 * log_w) % 8));
  }

  int csum_bytes_len = (len2 * log_w + 7) / 8;
  std::vector<uint8_t> csum_bytes(csum_bytes_len);

  for (int i = 0; i < csum_bytes_len; i++) {
    int shift = (csum_bytes_len - 1 - i) * 8;
    csum_bytes[i] = (uint8_t)((csum >> shift) & 0xFF);
  }

  std::vector<uint32_t> csum_digits = base_w(csum_bytes, p->W, len2);

  // std::vector<uint32_t> csum_digits(len2);
  // uint64_t mask = ((uint64_t)1 << log_w) -1;
  // for (int i = 0; i < len2; ++i) {
  //     int shift = (len2 - 1 - i) * log_w;
  //     csum_digits[i] = (uint32_t)((csum >> shift) & mask);
  // }

  digits.insert(digits.end(), csum_digits.begin(), csum_digits.end());
  return digits;
}

Bytes wots_sign(const Bytes &msg, const Bytes &sk_seed, const Bytes &pub_seed,
                Address addr, SphincsPlus::Params *p) {
  Bytes msg_hash = msg;
  if (msg_hash.size() != (size_t)p->N) {
    Bytes tmp(p->N);
    Keccak::shake256(msg, tmp);
    msg_hash = tmp;
  }

  std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

  if ((int)lengths.size() != p->WOTS_LEN) {
    throw std::runtime_error("WOTS: lengths mismatch");
  }

  addr.sanitize_for_role(ADDR_TYPE_WOTS);

  Bytes sig(p->WOTS_LEN * p->N);

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (int i = 0; i < p->WOTS_LEN; i++) {
    addr.set_chain(i);

    Address prf_addr = addr;
    prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
    prf_addr.set_keypair(addr.words[5]);
    prf_addr.set_chain(i);
    prf_addr.set_hash(0);

    Bytes sk_component(p->N);
    prf(state_seeded, sk_seed.data(), prf_addr, p->N, sk_component.data());

    gen_chain(state_seeded, sk_component.data(), 0, lengths[i], addr, p->N,
              sig.data() + i * p->N);

    secure_wipe(sk_component);
  }
  return sig;
}

/*  This function reconstructs a WOTS+ public keu from a given signature.
 *   It calculates the expected base-W digits for the signed messgae, takes
 *   nodes provided in the signature, and hashes them the rest of the way
 *   to the top of each chain. It then hashes all of the top nodes together to
 *   get WOTS+ public key.
 */
Bytes wots_pk_from_sig(const Bytes &sig, const Bytes &msg,
                       const Bytes &pub_seed, Address addr,
                       SphincsPlus::Params *p) {
  Bytes msg_hash = msg;
  if (msg_hash.size() != (size_t)p->N) {
    Bytes tmp(p->N);
    Keccak::shake256(msg, tmp);
    msg_hash = tmp;
  }

  std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

  if ((int)lengths.size() != p->WOTS_LEN) {
    throw std::runtime_error("WOTS: length mismatch in pk_from_sig");
  }

  Address wots_addr = addr;
  wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);

  Bytes pk_accum(p->WOTS_LEN * p->N);
  int sig_offset = 0;

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (int i = 0; i < p->WOTS_LEN; i++) {
    wots_addr.set_chain(i);

    if (sig_offset + p->N > (int)sig.size()) {
      throw std::runtime_error("Signature too short in wots_pk_from_sig");
    }

    wots_chain(state_seeded, sig.data() + sig_offset, lengths[i],
               (p->W - 1) - lengths[i], wots_addr, p->N,
               pk_accum.data() + i * p->N);
    sig_offset += p->N;
  }

  Address pk_addr = addr;
  pk_addr.set_type(ADDR_TYPE_WOTS_PK);
  pk_addr.set_keypair(addr.words[5]);
  pk_addr.set_chain(0);
  pk_addr.set_hash(0);

  Bytes pk(p->N);
  thash(state_seeded, pk_accum.data(), pk_accum.size(), pk_addr, p->N,
        pk.data());
  return pk;
}