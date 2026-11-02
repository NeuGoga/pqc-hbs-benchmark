#include "sphincs/wots.h"
#include "crypto/threads.h"

#ifdef _OPENMP
#include <omp.h>
#endif

void gen_chain(const Shake256 &state_seeded, const uint8_t *in, int start,
               int steps, Address addr, int N, uint8_t *out) {
  if (out != in)
    std::memcpy(out, in, (size_t)N);
  for (int i = start; i < start + steps; i++) {
    addr.set_hash((uint32_t)i);
    thash(state_seeded, out, (size_t)N, addr, N, out);
  }
}

static std::vector<uint32_t> compute_wots_digits(const uint8_t *msg_hash,
                                                 size_t msg_len,
                                                 SphincsPlus::Params *p) {
  Bytes msg(msg_hash, msg_hash + msg_len);
  int log_w = 0;
  while ((1 << log_w) < p->W)
    ++log_w;

  int len1 = p->len1;
  int len2 = p->len2;

  std::vector<uint32_t> digits = base_w(msg, p->W, len1);

  uint64_t csum = 0;
  for (uint32_t v : digits)
    csum += (uint64_t)(p->W - 1 - v);

  if ((len2 * log_w) % 8 != 0)
    csum <<= (8 - ((len2 * log_w) % 8));

  int csum_bytes_len = (len2 * log_w + 7) / 8;
  std::vector<uint8_t> csum_bytes((size_t)csum_bytes_len);
  for (int i = 0; i < csum_bytes_len; i++) {
    int shift = (csum_bytes_len - 1 - i) * 8;
    csum_bytes[i] = (uint8_t)((csum >> shift) & 0xFF);
  }
  std::vector<uint32_t> csum_digits = base_w(csum_bytes, p->W, len2);
  digits.insert(digits.end(), csum_digits.begin(), csum_digits.end());
  return digits;
}

/* One sponge per worker. Shake256 is not safe to copy from several threads
   at once (OpenSSL's EVP_MD_CTX_copy_ex, and a C++ data race on the scalar
   Keccak). Nested teams are refused: a Merkle leaf that is itself a WOTS
   keygen must not fan out again or the process goes to N^2 threads. */
#ifdef _OPENMP
static int wots_team(int work) {
  if (omp_in_parallel())
    return 1;
  return hbs_threads_for(work);
}
#endif

Bytes wots_pkgen(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                 SphincsPlus::Params *p) {
  addr.sanitize_for_role(ADDR_TYPE_WOTS);
  addr.set_hash(0);

  Bytes pk_accum((size_t)p->WOTS_LEN * p->N);
  const int n = p->N;
  const int wots_len = p->WOTS_LEN;
  const int w_minus = p->W - 1;
  const uint32_t keypair = addr.words[5];
#ifdef _OPENMP
  const int nt = wots_team(wots_len);
#pragma omp parallel num_threads(nt) if (nt > 1)
#endif
  {
    Shake256 state_seeded;
    state_seeded.absorb(pub_seed.data(), pub_seed.size());
#ifdef _OPENMP
#pragma omp for schedule(static)
#endif
    for (int i = 0; i < wots_len; i++) {
      Address chain_addr = addr;
      chain_addr.set_chain((uint32_t)i);

      Address prf_addr = chain_addr;
      prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
      prf_addr.set_keypair(keypair);
      prf_addr.set_chain((uint32_t)i);
      prf_addr.set_hash(0);

      uint8_t sk[32];
      prf(state_seeded, sk_seed.data(), prf_addr, n, sk);
      gen_chain(state_seeded, sk, 0, w_minus, chain_addr, n,
                pk_accum.data() + i * n);
      std::memset(sk, 0, sizeof(sk));
    }
  }

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  Address pk_addr = addr;
  pk_addr.set_type(ADDR_TYPE_WOTS_PK);
  pk_addr.set_keypair(keypair);
  pk_addr.set_chain(0);
  pk_addr.set_hash(0);

  Bytes pk((size_t)n);
  thash(state_seeded, pk_accum.data(), pk_accum.size(), pk_addr, n, pk.data());
  return pk;
}

Bytes wots_sign(const Bytes &msg, const Bytes &sk_seed, const Bytes &pub_seed,
                Address addr, SphincsPlus::Params *p) {
  uint8_t msg_hash[32];
  const uint8_t *mh = msg.data();
  if (msg.size() != (size_t)p->N) {
    Shake256::hash(msg.data(), msg.size(), msg_hash, (size_t)p->N);
    mh = msg_hash;
  }

  std::vector<uint32_t> lengths = compute_wots_digits(mh, (size_t)p->N, p);
  if ((int)lengths.size() != p->WOTS_LEN)
    throw std::runtime_error("WOTS: lengths mismatch");

  addr.sanitize_for_role(ADDR_TYPE_WOTS);

  Bytes sig((size_t)p->WOTS_LEN * p->N);
  const int n = p->N;
  const int wots_len = p->WOTS_LEN;
  const uint32_t keypair = addr.words[5];
#ifdef _OPENMP
  const int nt = wots_team(wots_len);
#pragma omp parallel num_threads(nt) if (nt > 1)
#endif
  {
    Shake256 state_seeded;
    state_seeded.absorb(pub_seed.data(), pub_seed.size());
#ifdef _OPENMP
#pragma omp for schedule(static)
#endif
    for (int i = 0; i < wots_len; i++) {
      Address chain_addr = addr;
      chain_addr.set_chain((uint32_t)i);

      Address prf_addr = chain_addr;
      prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
      prf_addr.set_keypair(keypair);
      prf_addr.set_chain((uint32_t)i);
      prf_addr.set_hash(0);

      uint8_t sk_component[32];
      prf(state_seeded, sk_seed.data(), prf_addr, n, sk_component);
      gen_chain(state_seeded, sk_component, 0, (int)lengths[i], chain_addr, n,
                sig.data() + i * n);
      std::memset(sk_component, 0, sizeof(sk_component));
    }
  }
  return sig;
}

Bytes wots_pk_from_sig(const Bytes &sig, const Bytes &msg,
                       const Bytes &pub_seed, Address addr,
                       SphincsPlus::Params *p) {
  uint8_t msg_hash[32];
  const uint8_t *mh = msg.data();
  if (msg.size() != (size_t)p->N) {
    Shake256::hash(msg.data(), msg.size(), msg_hash, (size_t)p->N);
    mh = msg_hash;
  }

  std::vector<uint32_t> lengths = compute_wots_digits(mh, (size_t)p->N, p);
  if ((int)lengths.size() != p->WOTS_LEN)
    throw std::runtime_error("WOTS: length mismatch in pk_from_sig");
  if (sig.size() < (size_t)p->WOTS_LEN * (size_t)p->N)
    throw std::runtime_error("WOTS: signature too short");

  Address wots_addr = addr;
  wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);

  Bytes pk_accum((size_t)p->WOTS_LEN * p->N);
  const int n = p->N;
  const int wots_len = p->WOTS_LEN;
  const int w_minus = p->W - 1;
#ifdef _OPENMP
  const int nt = wots_team(wots_len);
#pragma omp parallel num_threads(nt) if (nt > 1)
#endif
  {
    Shake256 state_seeded;
    state_seeded.absorb(pub_seed.data(), pub_seed.size());
#ifdef _OPENMP
#pragma omp for schedule(static)
#endif
    for (int i = 0; i < wots_len; i++) {
      Address chain_addr = wots_addr;
      chain_addr.set_chain((uint32_t)i);
      gen_chain(state_seeded, sig.data() + i * n, (int)lengths[i],
                w_minus - (int)lengths[i], chain_addr, n,
                pk_accum.data() + i * n);
    }
  }

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  Address pk_addr = addr;
  pk_addr.set_type(ADDR_TYPE_WOTS_PK);
  pk_addr.set_keypair(addr.words[5]);
  pk_addr.set_chain(0);
  pk_addr.set_hash(0);

  Bytes pk((size_t)n);
  thash(state_seeded, pk_accum.data(), pk_accum.size(), pk_addr, n, pk.data());
  return pk;
}
