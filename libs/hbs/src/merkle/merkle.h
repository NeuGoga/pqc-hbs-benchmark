#pragma once
#include "internal/types.h"

Bytes treehash_authpath(const Bytes &sk_seed, const Bytes &pub_seed,
                        Address addr, int N, uint32_t start_idx,
                        uint32_t target_leaf_idx, int tree_height,
                        SphincsPlus::Params *p, std::vector<Bytes> *auth_path,
                        const uint8_t *known_target_leaf = nullptr);

Bytes compute_root(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                   int N, uint32_t idx_offset, int height,
                   SphincsPlus::Params *p);

Bytes compute_root_from_path(const uint8_t *leaf, uint32_t leaf_idx,
                             const uint8_t *auth_path, int path_len,
                             const Bytes &pub_seed, Address addr, int N);

inline Bytes compute_root_from_path(const Bytes &leaf, uint32_t leaf_idx,
                                    const std::vector<Bytes> &auth_path,
                                    const Bytes &pub_seed, Address addr,
                                    int N) {
  Bytes flat;
  flat.reserve(auth_path.size() * (size_t)N);
  for (const auto &n : auth_path)
    flat.insert(flat.end(), n.begin(), n.end());
  return compute_root_from_path(leaf.data(), leaf_idx,
                                flat.empty() ? nullptr : flat.data(),
                                (int)auth_path.size(), pub_seed, addr, N);
}

std::vector<Bytes> gen_auth_path(const Bytes &sk_seed, const Bytes &pub_seed,
                                 Address addr, int N, uint32_t leaf_idx,
                                 int h_total, SphincsPlus::Params *p);
