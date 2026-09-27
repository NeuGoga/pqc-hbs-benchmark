#include "hbs/sphincs.h"
#include "internal/types.h"
#include "merkle/merkle.h"
#include "sphincs/fors.h"
#include "sphincs/hash.h"
#include "sphincs/wots.h"

SphincsPlus::SphincsPlus(SphexVariant variant) { p = new Params(variant); }

SphincsPlus::~SphincsPlus() { delete p; }

/*  This function generates WOTS+. It takes an N-byte message,
 *   determines the required hash steps using compute_wots_digits,
 *   and deterministically generates the secret key for each chain.
 *   It then hashes each chain up to the specific step and returns the result.
 */

std::vector<uint8_t> SphincsPlus::keygen(std::vector<uint8_t> &sk_out) {
  Bytes seeds(3 * p->N);
  if (!generate_random_bytes(seeds)) {
    std::cerr << "Error: Failed to CSPRNG.\n";
    sk_out.clear();
    return {};
  }

  Bytes sk_seed(seeds.begin(), seeds.begin() + p->N);
  Bytes sk_prf(seeds.begin() + p->N, seeds.begin() + 2 * p->N);
  Bytes pub_seed(seeds.begin() + 2 * p->N, seeds.begin() + 3 * p->N);

  // if(!generate_random_bytes(sk_seed) ||
  //     !generate_random_bytes(sk_prf) ||
  //     !generate_random_bytes(pub_seed)) {
  //         std::cerr << "Error: Failed to CSPRNG.\n";
  //         sk_out.clear();
  //         return {};
  //     }

  Address addr;
  addr.set_layer(p->D - 1);
  addr.set_type(ADDR_TYPE_TREE);
  Bytes root = treehash_authpath(sk_seed, pub_seed, addr, p->N, 0, 0,
                                 p->H_PRIME, p, nullptr);

  sk_out = sk_seed;
  sk_out.insert(sk_out.end(), sk_prf.begin(), sk_prf.end());
  sk_out.insert(sk_out.end(), pub_seed.begin(), pub_seed.end());
  sk_out.insert(sk_out.end(), root.begin(), root.end());

  Bytes pk = pub_seed;
  pk.insert(pk.end(), root.begin(), root.end());

  secure_wipe(seeds);
  secure_wipe(sk_seed);
  secure_wipe(sk_prf);

  return pk;
}

/*  This is the main signing function. It create SPHINCS+ signature
 *   for a given message the provided secret key. It first generate a
 *   randomizer R and hashes the message. It then signs the digest using the
 *   FORS trees. Then it hashes up the Hypertree, using WOTS+ to sign the root
 *   of each lower tree and generating the Merkle authentication paths to the
 * top layer.
 */

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
  addr.set_layer(p->D - 1);
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
  Bytes sk_seed(sk.begin(), sk.begin() + p->N);
  Bytes sk_prf(sk.begin() + p->N, sk.begin() + 2 * p->N);
  Bytes pub_seed(sk.begin() + 2 * p->N, sk.begin() + 3 * p->N);
  Bytes pk_root(sk.begin() + 3 * p->N, sk.end());

  // Bytes optrand(p->N);
  // generate_random_bytes(optrand);

  // Bytes optrand = prf_msg(sk_prf, pub_seed, msg, p->N);
  Bytes R = prf_msg(sk_prf, pub_seed, msg, p->N);

  Bytes buf;
  buf.insert(buf.end(), R.begin(), R.end());
  buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
  buf.insert(buf.end(), pk_root.begin(), pk_root.end());
  buf.insert(buf.end(), msg.begin(), msg.end());

  // size_t digest_bits = p->K * p->A + (p->H - p->H_PRIME) + p->H_PRIME;
  size_t fors_bytes = (p->K * p->A + 7) / 8;
  size_t tree_bytes = ((p->H - p->H_PRIME) + 7) / 8;
  size_t leaf_bytes = (p->H_PRIME + 7) / 8;
  size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;

  if (digest_bytes < (size_t)p->N)
    digest_bytes = p->N;

  Bytes msg_digest_full(digest_bytes);
  Keccak::shake256(buf, msg_digest_full);

  size_t bit_cursor = fors_bytes * 8;

  uint64_t tree_idx =
      get_bits_from_stream(msg_digest_full, bit_cursor, tree_bytes * 8);

  if ((p->H - p->H_PRIME) < 64) {
    tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
  }

  bit_cursor += tree_bytes * 8;

  uint32_t leaf_idx = (uint32_t)get_bits_from_stream(
      msg_digest_full, bit_cursor, leaf_bytes * 8);
  leaf_idx &= ((1ULL << p->H_PRIME) - 1);

  Bytes signature = R;

  Address fors_addr;
  fors_addr.set_layer(0);
  fors_addr.set_tree(tree_idx);
  fors_addr.set_type(ADDR_TYPE_FORS_TREE);
  fors_addr.set_keypair(leaf_idx);

  Bytes fors_pk_value;

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (int i = 0; i < p->K; i++) {
    uint32_t actual_fors_idx = extract_fors_idx(msg_digest_full, i, p->A);
    uint32_t global_fors_idx = i * (1 << p->A) + actual_fors_idx;

    Address prf_addr = fors_addr;
    prf_addr.set_type(ADDR_TYPE_FORS_PRF);
    prf_addr.set_keypair(leaf_idx);
    prf_addr.set_tree_height(0);
    prf_addr.set_tree_index(global_fors_idx);

    Bytes sk_leaf(p->N);
    prf(state_seeded, sk_seed.data(), prf_addr, p->N, sk_leaf.data());
    signature.insert(signature.end(), sk_leaf.begin(), sk_leaf.end());

    Address leaf_addr = fors_addr;
    leaf_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
    leaf_addr.set_tree_height(0);
    leaf_addr.set_tree_index(global_fors_idx);

    Bytes leaf(p->N);
    thash(state_seeded, sk_leaf.data(), p->N, leaf_addr, p->N, leaf.data());
    secure_wipe(sk_leaf);

    std::vector<Bytes> path;
    treehash_authpath(sk_seed, pub_seed, fors_addr, p->N, i * (1 << p->A),
                      global_fors_idx, p->A, p, &path);
    for (auto &node : path) {
      signature.insert(signature.end(), node.begin(), node.end());
    }

    Address tree_addr = fors_addr;
    tree_addr.set_keypair(leaf_idx);
    Bytes tree_root = compute_root_from_path(leaf, global_fors_idx, path,
                                             pub_seed, tree_addr, p->N);
    fors_pk_value.insert(fors_pk_value.end(), tree_root.begin(),
                         tree_root.end());
  }

  Address fors_pk_addr = fors_addr;
  fors_pk_addr.set_type(ADDR_TYPE_FORS_PK);
  fors_pk_addr.set_keypair(leaf_idx);
  Bytes fors_root(p->N);
  thash(state_seeded, fors_pk_value.data(), fors_pk_value.size(), fors_pk_addr,
        p->N, fors_root.data());

  // uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H
  // - p->H_PRIME)); bit_cursor += (p->H - p->H_PRIME);

  // uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full,
  // bit_cursor, p->H_PRIME);

  Bytes current_root = fors_root;

  for (int i = 0; i < p->D; i++) {
    Address ht_addr;
    ht_addr.set_layer(i);
    ht_addr.set_tree(tree_idx);

    Address wots_addr = ht_addr;
    wots_addr.set_type(ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);

    Bytes wots_sig = wots_sign(current_root, sk_seed, pub_seed, wots_addr, p);
    signature.insert(signature.end(), wots_sig.begin(), wots_sig.end());

    Address tree_addr = ht_addr;
    tree_addr.set_type(ADDR_TYPE_TREE);

    Address leaf_wots_addr = wots_addr;
    Bytes wots_pk = wots_pkgen(sk_seed, pub_seed, leaf_wots_addr, p);

    std::vector<Bytes> path;
    treehash_authpath(sk_seed, pub_seed, tree_addr, p->N, 0, leaf_idx,
                      p->H_PRIME, p, &path);
    for (auto &node : path)
      signature.insert(signature.end(), node.begin(), node.end());

    current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed,
                                          tree_addr, p->N);

    leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
    tree_idx = (tree_idx >> p->H_PRIME);
  }

  if (signature.size() != get_sig_size()) {
    throw std::runtime_error("Signature size mismatch in sign()");
  }

  secure_wipe(sk_seed);
  secure_wipe(sk_prf);
  return signature;
}

/*  This helper function compares two blocks of memory in "constant time".
 *   I made this to try preventing timing attacks, so it checks every single
 * byte, compared to standard memcmp which stops at the first difference.
 */

bool SphincsPlus::verify(const std::vector<uint8_t> &msg,
                         const std::vector<uint8_t> &sig,
                         const std::vector<uint8_t> &pk) {
  if (sig.size() != get_sig_size())
    return false;
  if (pk.size() != 2 * p->N)
    return false;

  Bytes pub_seed(pk.begin(), pk.begin() + p->N);
  Bytes pk_root(pk.begin() + p->N, pk.end());

  Bytes R(sig.begin(), sig.begin() + p->N);

  Bytes buf_for_digest;
  buf_for_digest.insert(buf_for_digest.end(), R.begin(), R.end());
  buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
  buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
  buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());

  size_t fors_bytes = (p->K * p->A + 7) / 8;
  size_t tree_bytes = ((p->H - p->H_PRIME) + 7) / 8;
  size_t leaf_bytes = (p->H_PRIME + 7) / 8;
  size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;

  if (digest_bytes < (size_t)p->N)
    digest_bytes = p->N;

  Bytes msg_digest_full(digest_bytes);
  Keccak::shake256(buf_for_digest, msg_digest_full);

  size_t bit_cursor = fors_bytes * 8;

  uint64_t tree_idx =
      get_bits_from_stream(msg_digest_full, bit_cursor, tree_bytes * 8);

  if ((p->H - p->H_PRIME) < 64) {
    tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
  }

  bit_cursor += tree_bytes * 8;

  uint32_t leaf_idx = (uint32_t)get_bits_from_stream(
      msg_digest_full, bit_cursor, leaf_bytes * 8);
  leaf_idx &= ((1ULL << p->H_PRIME) - 1);

  size_t sig_offset = p->N;

  Address fors_addr;
  fors_addr.set_layer(0);
  fors_addr.set_tree(tree_idx);
  fors_addr.set_type(ADDR_TYPE_FORS_TREE);
  fors_addr.set_keypair(leaf_idx);

  Bytes fors_root = fors_pk_from_sig(sig, sig_offset, msg_digest_full, pub_seed,
                                     fors_addr, p);

  // size_t bit_cursor = p->K * p->A;

  // uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H
  // - p->H_PRIME)); bit_cursor += (p->H - p->H_PRIME);

  // uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full,
  // bit_cursor, p->H_PRIME);

  Bytes current_root = fors_root;

  for (int i = 0; i < p->D; i++) {
    Address ht_addr;
    ht_addr.set_layer(i);
    ht_addr.set_tree(tree_idx);

    Address wots_addr = ht_addr;
    wots_addr.set_type(ADDR_TYPE_WOTS);
    wots_addr.set_keypair(leaf_idx);

    size_t wots_len = p->WOTS_LEN * p->N;
    if (sig_offset + wots_len > sig.size())
      return false;

    Bytes wots_sig(sig.begin() + sig_offset,
                   sig.begin() + sig_offset + wots_len);
    sig_offset += wots_len;

    Bytes wots_pk =
        wots_pk_from_sig(wots_sig, current_root, pub_seed, wots_addr, p);

    std::vector<Bytes> path;
    for (int j = 0; j < p->H_PRIME; j++) {
      if (sig_offset + p->N > sig.size())
        return false;
      Bytes node(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
      path.push_back(node);
      sig_offset += p->N;
    }

    Address tree_addr = ht_addr;
    tree_addr.set_type(ADDR_TYPE_TREE);

    current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed,
                                          tree_addr, p->N);

    leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
    tree_idx >>= p->H_PRIME;
  }
  return (crypto_memcmp(current_root.data(), pk_root.data(), p->N) == 0);
}

size_t SphincsPlus::get_pk_size() const { return 2 * p->N; }
size_t SphincsPlus::get_sk_size() const { return 4 * p->N; }
size_t SphincsPlus::get_sig_size() const {
  size_t fors_sig_size = p->K * (p->N + p->A * p->N);
  size_t ht_sig_size = p->D * (p->WOTS_LEN * p->N + p->H_PRIME * p->N);
  return p->N + fors_sig_size + ht_sig_size;
}
