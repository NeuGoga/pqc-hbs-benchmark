#include "sphincs/fors.h"
#include "merkle/merkle.h"
#include "sphincs/hash.h"

Bytes fors_pk_from_sig(const Bytes &sig, size_t &sig_offset,
                       const Bytes &msg_digest, const Bytes &pub_seed,
                       Address addr, SphincsPlus::Params *p) {
  Bytes fors_pk_values;

  for (int i = 0; i < p->K; i++) {
    uint32_t actual_fors_idx = extract_fors_idx(msg_digest, i, p->A);
    uint32_t global_fors_idx = i * (1 << p->A) + actual_fors_idx;

    Bytes sk = extract_bytes(sig, sig_offset, p->N);

    Address leaf_addr = addr;
    leaf_addr.set_type(ADDR_TYPE_FORS_TREE);
    leaf_addr.set_keypair(addr.words[5]);
    leaf_addr.set_tree_height(0);
    leaf_addr.set_tree_index(global_fors_idx);

    Keccak state_seeded;
    state_seeded.absorb(pub_seed.data(), pub_seed.size());

    Bytes leaf(p->N);
    thash(state_seeded, sk.data(), p->N, leaf_addr, p->N, leaf.data());

    std::vector<Bytes> path;
    for (int j = 0; j < p->A; j++) {
      path.push_back(extract_bytes(sig, sig_offset, p->N));
    }

    Address tree_addr = addr;
    tree_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
    tree_addr.set_keypair(addr.words[5]);

    Bytes tree_root = compute_root_from_path(leaf, global_fors_idx, path,
                                             pub_seed, tree_addr, p->N);
    fors_pk_values.insert(fors_pk_values.end(), tree_root.begin(),
                          tree_root.end());
  }
  Address root_addr = addr;
  root_addr.set_type(ADDR_TYPE_FORS_PK);
  root_addr.set_keypair(addr.words[5]);

  Keccak state_seeded_root;
  state_seeded_root.absorb(pub_seed.data(), pub_seed.size());

  Bytes root(p->N);
  thash(state_seeded_root, fors_pk_values.data(), fors_pk_values.size(),
        root_addr, p->N, root.data());
  return root;
}

/*  This function is a wrapper for treehash_authpath.
 *   It returns authentication path.
 */
