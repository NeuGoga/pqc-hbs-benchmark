#include "merkle/merkle.h"
#include "sphincs/hash.h"
#include "sphincs/wots.h"


struct StackNodeAuth {
  Bytes node;
  int height;
  uint32_t start_idx;
};

/*  This function computes the root of a Merkle tree of a tree_height height.
 *   It generates the leaves and hashes them together to reach the top.
 *   If a target leaf index is provided, it also saves the sibling nodes
 *   along the way to build the authentication path.
 */
Bytes treehash_authpath(const Bytes &sk_seed, const Bytes &pub_seed,
                        Address addr, int N, uint32_t start_idx,
                        uint32_t target_leaf_idx, int tree_height,
                        SphincsPlus::Params *p, std::vector<Bytes> *auth_path) {
  std::vector<StackNodeAuth> stack;
  stack.reserve(tree_height + 1);

  uint32_t leaves = 1u << tree_height;

  if (auth_path) {
    auth_path->assign(tree_height, Bytes(N, 0));
  }

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (uint32_t i = 0; i < leaves; ++i) {
    uint32_t idx = start_idx + i;

    Address leaf_addr = addr;

    leaf_addr.set_tree_height(0);
    leaf_addr.set_tree_index(idx);

    Bytes node(N);
    if (addr.words[4] == ADDR_TYPE_TREE) {
      Address wots_addr = leaf_addr;
      wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);
      wots_addr.set_keypair(idx);
      node = wots_pkgen(sk_seed, pub_seed, wots_addr, p);
    } else {
      Address prf_addr = leaf_addr;
      prf_addr.set_type(ADDR_TYPE_FORS_PRF);
      prf_addr.set_keypair(leaf_addr.words[5]);
      prf_addr.set_tree_height(0);
      prf_addr.set_tree_index(idx);

      Bytes sk_leaf(N);
      prf(state_seeded, sk_seed.data(), prf_addr, N, sk_leaf.data());
      thash(state_seeded, sk_leaf.data(), N, leaf_addr, N, node.data());
      secure_wipe(sk_leaf);
    }

    StackNodeAuth cur{node, 0, idx};

    while (!stack.empty() && stack.back().height == cur.height) {
      StackNodeAuth left = stack.back();
      stack.pop_back();
      StackNodeAuth right = cur;

      if (auth_path) {
        uint32_t current_subtree_size = 1u << left.height;
        uint32_t relative_idx = target_leaf_idx - left.start_idx;

        if (relative_idx < current_subtree_size) {
          (*auth_path)[left.height] = right.node;
        } else if (relative_idx < (2 * current_subtree_size)) {
          (*auth_path)[right.height] = left.node;
        }
      }

      Address parent_addr = addr;
      parent_addr.set_tree_height(left.height + 1);
      parent_addr.set_tree_index(left.start_idx >> (left.height + 1));

      Bytes combined(2 * N);
      std::memcpy(combined.data(), left.node.data(), N);
      std::memcpy(combined.data() + N, right.node.data(), N);

      Bytes parent(N);
      thash(state_seeded, combined.data(), 2 * N, parent_addr, N,
            parent.data());

      cur.node = parent;
      cur.height = left.height + 1;
      cur.start_idx = left.start_idx;
    }
    stack.push_back(cur);
  }

  if (stack.empty())
    return Bytes(N, 0);
  return stack.back().node;
}

struct StackNode {
  Bytes node;
  int height;
};

/*  This function computes the root of a Merkle tree of a specified height.
 *   Unlike treehash_authpath, it does not save any sibling nodes for a
 * signature. It simply generates the leaves deterministiaclly from the secret
 * seed and hashes them together to find the top root node.
 */
Bytes compute_root(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                   int N, uint32_t idx_offset, int height,
                   SphincsPlus::Params *p) {
  std::vector<StackNode> stack;
  stack.reserve(height + 1);

  uint32_t leaves = 1 << height;
  bool is_hypertree = (addr.words[4] == ADDR_TYPE_TREE);

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (uint32_t i = 0; i < leaves; i++) {
    Address leaf_addr = addr;
    uint32_t current_idx = idx_offset + i;

    Bytes node(N);

    if (is_hypertree) {
      leaf_addr.set_keypair(current_idx);
      node = wots_pkgen(sk_seed, pub_seed, leaf_addr, p);
    } else {
      leaf_addr.set_tree_height(0);
      leaf_addr.set_tree_index(current_idx);

      Address prf_addr = leaf_addr;
      prf_addr.set_type(ADDR_TYPE_FORS_PRF);
      prf_addr.set_keypair(leaf_addr.words[5]);
      prf_addr.set_tree_height(0);
      prf_addr.set_tree_index(current_idx);

      Bytes sk_leaf(N);
      prf(state_seeded, sk_seed.data(), prf_addr, N, sk_leaf.data());
      thash(state_seeded, sk_leaf.data(), N, leaf_addr, N, node.data());
      secure_wipe(sk_leaf);
    }

    int h = 0;

    while (!stack.empty() && stack.back().height == h) {
      Bytes right = node;
      Bytes left = stack.back().node;
      stack.pop_back();

      Address parent_addr = addr;
      parent_addr.set_tree_height(h + 1);
      parent_addr.set_tree_index(current_idx >> (h + 1));

      Bytes combined(2 * N);
      std::memcpy(combined.data(), left.data(), N);
      std::memcpy(combined.data() + N, right.data(), N);

      node.assign(N, 0);
      thash(state_seeded, combined.data(), 2 * N, parent_addr, N, node.data());
      h++;
    }
    stack.push_back({node, h});
  }
  return stack.back().node;
}

/*  This function rebuilds the roof of a Merkle tree using a single leaf
 *   and its authentication path. It uses the leaf's index to determine whether
 *   each sibling belongs on the left or the right during the pairwise hashing.
 *   This is used for signature verification.
 */
Bytes compute_root_from_path(const Bytes &leaf, uint32_t leaf_idx,
                             const std::vector<Bytes> &auth_path,
                             const Bytes &pub_seed, Address addr, int N) {
  Bytes current_node = leaf;
  Bytes combined(2 * N);

  Keccak state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (size_t h = 0; h < auth_path.size(); ++h) {
    addr.set_tree_height(h + 1);
    addr.set_tree_index(leaf_idx >> 1);

    if (leaf_idx & 1) {
      std::memcpy(combined.data(), auth_path[h].data(), N);
      std::memcpy(combined.data() + N, current_node.data(), N);
    } else {
      std::memcpy(combined.data(), current_node.data(), N);
      std::memcpy(combined.data() + N, auth_path[h].data(), N);
    }

    thash(state_seeded, combined.data(), 2 * N, addr, N, current_node.data());

    leaf_idx >>= 1;
  }
  return current_node;
}

/* This function extract a specific number of bits from a byte vector,
 *   starting at any bit offset, and returns them as an integer.
 *   It is used to parse randomized message digest into numbers.
 */

std::vector<Bytes> gen_auth_path(const Bytes &sk_seed, const Bytes &pub_seed,
                                 Address addr, int N, uint32_t leaf_idx,
                                 int h_total, SphincsPlus::Params *p) {
  std::vector<Bytes> auth;

  uint32_t start = 0;
  treehash_authpath(sk_seed, pub_seed, addr, N, start, leaf_idx, h_total, p,
                    &auth);
  return auth;
}
