#include "merkle/merkle.h"
#include "sphincs/hash.h"
#include "sphincs/wots.h"

#ifdef _OPENMP
#include <omp.h>
#endif

struct StackNodeAuth {
  uint8_t node[32];
  int height;
  uint32_t start_idx;
};

static void generate_leaf(uint8_t *out, const Bytes &sk_seed,
                          const Bytes &pub_seed, Address addr, int N,
                          uint32_t idx, SphincsPlus::Params *p,
                          bool is_hypertree, const Shake256 &state_seeded) {
  Address leaf_addr = addr;
  leaf_addr.set_tree_height(0);
  leaf_addr.set_tree_index(idx);

  if (is_hypertree) {
    Address wots_addr = leaf_addr;
    wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);
    wots_addr.set_keypair(idx);
    Bytes pk = wots_pkgen(sk_seed, pub_seed, wots_addr, p);
    std::memcpy(out, pk.data(), (size_t)N);
    return;
  }

  Address prf_addr = leaf_addr;
  prf_addr.set_type(ADDR_TYPE_FORS_PRF);
  prf_addr.set_keypair(leaf_addr.words[5]);
  prf_addr.set_tree_height(0);
  prf_addr.set_tree_index(idx);

  uint8_t sk_leaf[32];
  prf(state_seeded, sk_seed.data(), prf_addr, N, sk_leaf);
  thash(state_seeded, sk_leaf, (size_t)N, leaf_addr, N, out);
  std::memset(sk_leaf, 0, sizeof(sk_leaf));
}

Bytes treehash_authpath(const Bytes &sk_seed, const Bytes &pub_seed,
                        Address addr, int N, uint32_t start_idx,
                        uint32_t target_leaf_idx, int tree_height,
                        SphincsPlus::Params *p, std::vector<Bytes> *auth_path,
                        const uint8_t *known_target_leaf) {
  uint32_t nleaves = 1u << tree_height;
  bool is_hypertree = (addr.words[4] == ADDR_TYPE_TREE);

  if (auth_path)
    auth_path->assign((size_t)tree_height, Bytes((size_t)N, 0));

  std::vector<uint8_t> leaf_buf((size_t)nleaves * (size_t)N);

#ifdef _OPENMP
#pragma omp parallel
#endif
  {
    Shake256 seeded;
    seeded.absorb(pub_seed.data(), pub_seed.size());
#ifdef _OPENMP
#pragma omp for schedule(static)
#endif
    for (int i = 0; i < (int)nleaves; ++i) {
      uint32_t idx = start_idx + (uint32_t)i;
      uint8_t *slot = leaf_buf.data() + (size_t)i * (size_t)N;
      if (known_target_leaf && idx == target_leaf_idx)
        std::memcpy(slot, known_target_leaf, (size_t)N);
      else
        generate_leaf(slot, sk_seed, pub_seed, addr, N, idx, p, is_hypertree,
                      seeded);
    }
  }

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  StackNodeAuth stack[32];
  int sp = 0;

  for (uint32_t i = 0; i < nleaves; ++i) {
    uint32_t idx = start_idx + i;
    StackNodeAuth cur;
    std::memcpy(cur.node, leaf_buf.data() + (size_t)i * (size_t)N, (size_t)N);
    cur.height = 0;
    cur.start_idx = idx;

    while (sp > 0 && stack[sp - 1].height == cur.height) {
      StackNodeAuth left = stack[--sp];
      StackNodeAuth right = cur;

      if (auth_path) {
        uint32_t current_subtree_size = 1u << left.height;
        uint32_t relative_idx = target_leaf_idx - left.start_idx;
        if (relative_idx < current_subtree_size)
          (*auth_path)[left.height].assign(right.node, right.node + N);
        else if (relative_idx < (2 * current_subtree_size))
          (*auth_path)[right.height].assign(left.node, left.node + N);
      }

      Address parent_addr = addr;
      parent_addr.set_tree_height((uint32_t)(left.height + 1));
      parent_addr.set_tree_index(left.start_idx >> (left.height + 1));

      uint8_t combined[64];
      std::memcpy(combined, left.node, (size_t)N);
      std::memcpy(combined + N, right.node, (size_t)N);
      thash(state_seeded, combined, (size_t)(2 * N), parent_addr, N, cur.node);
      cur.height = left.height + 1;
      cur.start_idx = left.start_idx;
    }
    stack[sp++] = cur;
  }

  if (sp == 0)
    return Bytes((size_t)N, 0);
  return Bytes(stack[sp - 1].node, stack[sp - 1].node + N);
}

Bytes compute_root(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                   int N, uint32_t idx_offset, int height,
                   SphincsPlus::Params *p) {
  return treehash_authpath(sk_seed, pub_seed, addr, N, idx_offset, idx_offset,
                           height, p, nullptr, nullptr);
}

Bytes compute_root_from_path(const uint8_t *leaf, uint32_t leaf_idx,
                             const uint8_t *auth_path, int path_len,
                             const Bytes &pub_seed, Address addr, int N) {
  uint8_t current[32];
  std::memcpy(current, leaf, (size_t)N);
  uint8_t combined[64];

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (int h = 0; h < path_len; ++h) {
    addr.set_tree_height((uint32_t)(h + 1));
    addr.set_tree_index(leaf_idx >> 1);
    const uint8_t *sib = auth_path + (size_t)h * (size_t)N;
    if (leaf_idx & 1) {
      std::memcpy(combined, sib, (size_t)N);
      std::memcpy(combined + N, current, (size_t)N);
    } else {
      std::memcpy(combined, current, (size_t)N);
      std::memcpy(combined + N, sib, (size_t)N);
    }
    thash(state_seeded, combined, (size_t)(2 * N), addr, N, current);
    leaf_idx >>= 1;
  }
  return Bytes(current, current + N);
}

std::vector<Bytes> gen_auth_path(const Bytes &sk_seed, const Bytes &pub_seed,
                                 Address addr, int N, uint32_t leaf_idx,
                                 int h_total, SphincsPlus::Params *p) {
  std::vector<Bytes> auth;
  treehash_authpath(sk_seed, pub_seed, addr, N, 0, leaf_idx, h_total, p, &auth,
                    nullptr);
  return auth;
}
