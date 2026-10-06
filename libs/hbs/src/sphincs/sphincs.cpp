#include "hbs/sphincs.h"
#include "internal/types.h"
#include "merkle/merkle.h"
#include "sphincs/fors.h"
#include "sphincs/hash.h"
#include "sphincs/wots.h"

#ifdef _OPENMP
#include <omp.h>
#endif

SphincsPlus::SphincsPlus(SphexVariant variant) { p = new Params(variant); }

SphincsPlus::~SphincsPlus() { delete p; }

std::vector<uint8_t> SphincsPlus::keygen(std::vector<uint8_t> &sk_out) {
  Bytes seeds((size_t)(3 * p->N));
  if (!generate_random_bytes(seeds)) {
    std::cerr << "Error: Failed to CSPRNG.\n";
    sk_out.clear();
    return {};
  }
  std::vector<uint8_t> pk = keygen_from_seed(seeds, sk_out);
  secure_wipe(seeds);
  return pk;
}

std::vector<uint8_t>
SphincsPlus::keygen_from_seed(const std::vector<uint8_t> &seed,
                              std::vector<uint8_t> &sk_out) {
  if (seed.size() != (size_t)(3 * p->N)) {
    std::cerr << "Error: seed must be 3N bytes.\n";
    sk_out.clear();
    return {};
  }

  Bytes sk_seed(seed.begin(), seed.begin() + p->N);
  Bytes sk_prf(seed.begin() + p->N, seed.begin() + 2 * p->N);
  Bytes pub_seed(seed.begin() + 2 * p->N, seed.begin() + 3 * p->N);

  Address addr;
  addr.set_layer((uint32_t)(p->D - 1));
  addr.set_type(ADDR_TYPE_TREE);
  Bytes root = treehash_authpath(sk_seed, pub_seed, addr, p->N, 0, 0,
                                 p->H_PRIME, p, nullptr);

  sk_out = sk_seed;
  sk_out.insert(sk_out.end(), sk_prf.begin(), sk_prf.end());
  sk_out.insert(sk_out.end(), pub_seed.begin(), pub_seed.end());
  sk_out.insert(sk_out.end(), root.begin(), root.end());

  Bytes pk = pub_seed;
  pk.insert(pk.end(), root.begin(), root.end());

  secure_wipe(sk_seed);
  secure_wipe(sk_prf);
  return pk;
}

int SphincsPlus::n() const { return p->N; }

std::vector<uint8_t> SphincsPlus::sign(const std::vector<uint8_t> &msg,
                                       const std::vector<uint8_t> &sk) {
  const int n = p->N;
  Bytes sk_seed(sk.begin(), sk.begin() + n);
  Bytes sk_prf(sk.begin() + n, sk.begin() + 2 * n);
  Bytes pub_seed(sk.begin() + 2 * n, sk.begin() + 3 * n);
  Bytes pk_root(sk.begin() + 3 * n, sk.end());

  uint8_t R[32];
  prf_msg(sk_prf.data(), pub_seed.data(), (size_t)n, msg.data(), msg.size(), R);

  Bytes buf;
  buf.insert(buf.end(), R, R + n);
  buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
  buf.insert(buf.end(), pk_root.begin(), pk_root.end());
  buf.insert(buf.end(), msg.begin(), msg.end());

  size_t fors_bytes = (size_t)(p->K * p->A + 7) / 8;
  size_t tree_bytes = (size_t)((p->H - p->H_PRIME) + 7) / 8;
  size_t leaf_bytes = (size_t)(p->H_PRIME + 7) / 8;
  size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;
  if (digest_bytes < (size_t)n)
    digest_bytes = (size_t)n;

  Bytes msg_digest_full(digest_bytes);
  Shake256::hash(buf.data(), buf.size(), msg_digest_full.data(), digest_bytes);

  size_t bit_cursor = fors_bytes * 8;
  uint64_t tree_idx =
      get_bits_from_stream(msg_digest_full, bit_cursor, (int)(tree_bytes * 8));
  if ((p->H - p->H_PRIME) < 64)
    tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
  bit_cursor += tree_bytes * 8;
  uint32_t leaf_idx = (uint32_t)get_bits_from_stream(
      msg_digest_full, bit_cursor, (int)(leaf_bytes * 8));
  leaf_idx &= ((1u << p->H_PRIME) - 1);

  Bytes signature;
  signature.reserve(get_sig_size());
  signature.insert(signature.end(), R, R + n);

  Address fors_addr;
  fors_addr.set_layer(0);
  fors_addr.set_tree(tree_idx);
  fors_addr.set_type(ADDR_TYPE_FORS_TREE);
  fors_addr.set_keypair(leaf_idx);

  const int k = p->K;
  const int a = p->A;
  Bytes fors_pk_value((size_t)k * (size_t)n);
  std::vector<Bytes> fors_sk((size_t)k);
  std::vector<std::vector<Bytes>> fors_paths((size_t)k);

#ifdef _OPENMP
#pragma omp parallel
#endif
  {
    Shake256 state_seeded;
    state_seeded.absorb(pub_seed.data(), pub_seed.size());
#ifdef _OPENMP
#pragma omp for schedule(dynamic)
#endif
    for (int i = 0; i < k; i++) {
      uint32_t actual_fors_idx = extract_fors_idx(msg_digest_full, i, a);
      uint32_t global_fors_idx = (uint32_t)i * (1u << a) + actual_fors_idx;

      Address prf_addr = fors_addr;
      prf_addr.set_type(ADDR_TYPE_FORS_PRF);
      prf_addr.set_keypair(leaf_idx);
      prf_addr.set_tree_height(0);
      prf_addr.set_tree_index(global_fors_idx);

      Bytes sk_leaf((size_t)n);
      prf(state_seeded, sk_seed.data(), prf_addr, n, sk_leaf.data());

      Address leaf_addr = fors_addr;
      leaf_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
      leaf_addr.set_tree_height(0);
      leaf_addr.set_tree_index(global_fors_idx);

      uint8_t leaf[32];
      thash(state_seeded, sk_leaf.data(), (size_t)n, leaf_addr, n, leaf);

      std::vector<Bytes> path;
      treehash_authpath(sk_seed, pub_seed, fors_addr, n,
                        (uint32_t)i * (1u << a), global_fors_idx, a, p, &path,
                        leaf);

      Address tree_addr = fors_addr;
      tree_addr.set_keypair(leaf_idx);
      Bytes tree_root = compute_root_from_path(
          Bytes(leaf, leaf + n), global_fors_idx, path, pub_seed, tree_addr, n);

      fors_sk[(size_t)i] = std::move(sk_leaf);
      fors_paths[(size_t)i] = std::move(path);
      std::memcpy(fors_pk_value.data() + (size_t)i * (size_t)n,
                  tree_root.data(), (size_t)n);
    }
  }

  for (int i = 0; i < k; i++) {
    signature.insert(signature.end(), fors_sk[i].begin(), fors_sk[i].end());
    secure_wipe(fors_sk[i]);
    for (auto &node : fors_paths[i])
      signature.insert(signature.end(), node.begin(), node.end());
  }

  Address fors_pk_addr = fors_addr;
  fors_pk_addr.set_type(ADDR_TYPE_FORS_PK);
  fors_pk_addr.set_keypair(leaf_idx);

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());
  Bytes fors_root((size_t)n);
  thash(state_seeded, fors_pk_value.data(), fors_pk_value.size(), fors_pk_addr,
        n, fors_root.data());

  Bytes current_root = fors_root;

  for (int i = 0; i < p->D; i++) {
    Address ht_addr;
    ht_addr.set_layer((uint32_t)i);
    ht_addr.set_tree(tree_idx);

    Address wots_addr = ht_addr;
    wots_addr.set_type(ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);

    Bytes wots_sig = wots_sign(current_root, sk_seed, pub_seed, wots_addr, p);
    signature.insert(signature.end(), wots_sig.begin(), wots_sig.end());

    Bytes wots_pk =
        wots_pk_from_sig(wots_sig, current_root, pub_seed, wots_addr, p);

    Address tree_addr = ht_addr;
    tree_addr.set_type(ADDR_TYPE_TREE);

    std::vector<Bytes> path;
    treehash_authpath(sk_seed, pub_seed, tree_addr, n, 0, leaf_idx, p->H_PRIME,
                      p, &path, wots_pk.data());
    for (auto &node : path)
      signature.insert(signature.end(), node.begin(), node.end());

    current_root =
        compute_root_from_path(wots_pk, leaf_idx, path, pub_seed, tree_addr, n);

    leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
    tree_idx = (tree_idx >> p->H_PRIME);
  }

  if (signature.size() != get_sig_size())
    throw std::runtime_error("Signature size mismatch in sign()");

  secure_wipe(sk_seed);
  secure_wipe(sk_prf);
  return signature;
}

bool SphincsPlus::verify(const std::vector<uint8_t> &msg,
                         const std::vector<uint8_t> &sig,
                         const std::vector<uint8_t> &pk) {
  if (sig.size() != get_sig_size())
    return false;
  if (pk.size() != (size_t)(2 * p->N))
    return false;

  const int n = p->N;
  Bytes pub_seed(pk.begin(), pk.begin() + n);
  Bytes pk_root(pk.begin() + n, pk.end());
  Bytes R(sig.begin(), sig.begin() + n);

  Bytes buf_for_digest;
  buf_for_digest.insert(buf_for_digest.end(), R.begin(), R.end());
  buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
  buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
  buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());

  size_t fors_bytes = (size_t)(p->K * p->A + 7) / 8;
  size_t tree_bytes = (size_t)((p->H - p->H_PRIME) + 7) / 8;
  size_t leaf_bytes = (size_t)(p->H_PRIME + 7) / 8;
  size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;
  if (digest_bytes < (size_t)n)
    digest_bytes = (size_t)n;

  Bytes msg_digest_full(digest_bytes);
  Shake256::hash(buf_for_digest.data(), buf_for_digest.size(),
                 msg_digest_full.data(), digest_bytes);

  size_t bit_cursor = fors_bytes * 8;
  uint64_t tree_idx =
      get_bits_from_stream(msg_digest_full, bit_cursor, (int)(tree_bytes * 8));
  if ((p->H - p->H_PRIME) < 64)
    tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
  bit_cursor += tree_bytes * 8;
  uint32_t leaf_idx = (uint32_t)get_bits_from_stream(
      msg_digest_full, bit_cursor, (int)(leaf_bytes * 8));
  leaf_idx &= ((1u << p->H_PRIME) - 1);

  size_t sig_offset = (size_t)n;

  Address fors_addr;
  fors_addr.set_layer(0);
  fors_addr.set_tree(tree_idx);
  fors_addr.set_type(ADDR_TYPE_FORS_TREE);
  fors_addr.set_keypair(leaf_idx);

  Bytes fors_root = fors_pk_from_sig(sig, sig_offset, msg_digest_full, pub_seed,
                                     fors_addr, p);
  Bytes current_root = fors_root;

  for (int i = 0; i < p->D; i++) {
    Address ht_addr;
    ht_addr.set_layer((uint32_t)i);
    ht_addr.set_tree(tree_idx);

    Address wots_addr = ht_addr;
    wots_addr.set_type(ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);

    size_t wots_len = (size_t)p->WOTS_LEN * (size_t)n;
    if (sig_offset + wots_len > sig.size())
      return false;

    Bytes wots_sig(sig.begin() + sig_offset,
                   sig.begin() + sig_offset + wots_len);
    sig_offset += wots_len;

    Bytes wots_pk =
        wots_pk_from_sig(wots_sig, current_root, pub_seed, wots_addr, p);

    if (sig_offset + (size_t)p->H_PRIME * (size_t)n > sig.size())
      return false;
    Bytes path_flat(sig.begin() + sig_offset,
                    sig.begin() + sig_offset + (size_t)p->H_PRIME * (size_t)n);
    sig_offset += (size_t)p->H_PRIME * (size_t)n;

    Address tree_addr = ht_addr;
    tree_addr.set_type(ADDR_TYPE_TREE);

    current_root =
        compute_root_from_path(wots_pk.data(), leaf_idx, path_flat.data(),
                               p->H_PRIME, pub_seed, tree_addr, n);

    leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
    tree_idx >>= p->H_PRIME;
  }
  return (crypto_memcmp(current_root.data(), pk_root.data(), (size_t)n) == 0);
}

size_t SphincsPlus::get_pk_size() const { return (size_t)(2 * p->N); }
size_t SphincsPlus::get_sk_size() const { return (size_t)(4 * p->N); }
size_t SphincsPlus::get_sig_size() const {
  size_t fors_sig_size =
      (size_t)p->K * ((size_t)p->N + (size_t)p->A * (size_t)p->N);
  size_t ht_sig_size = (size_t)p->D * ((size_t)p->WOTS_LEN * (size_t)p->N +
                                       (size_t)p->H_PRIME * (size_t)p->N);
  return (size_t)p->N + fors_sig_size + ht_sig_size;
}
