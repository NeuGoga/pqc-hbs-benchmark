#include "sphincs/fors.h"
#include "merkle/merkle.h"
#include "sphincs/hash.h"

Bytes fors_pk_from_sig(const Bytes &sig, size_t &sig_offset,
                       const Bytes &msg_digest, const Bytes &pub_seed,
                       Address addr, SphincsPlus::Params *p) {
  Bytes fors_pk_values((size_t)p->K * (size_t)p->N);
  const int n = p->N;

  Shake256 state_seeded;
  state_seeded.absorb(pub_seed.data(), pub_seed.size());

  for (int i = 0; i < p->K; i++) {
    uint32_t actual_fors_idx = extract_fors_idx(msg_digest, i, p->A);
    uint32_t global_fors_idx = i * (1u << p->A) + actual_fors_idx;

    Bytes sk = extract_bytes(sig, sig_offset, (size_t)n);

    Address leaf_addr = addr;
    leaf_addr.set_type(ADDR_TYPE_FORS_TREE);
    leaf_addr.set_keypair(addr.words[5]);
    leaf_addr.set_tree_height(0);
    leaf_addr.set_tree_index(global_fors_idx);

    uint8_t leaf[32];
    thash(state_seeded, sk.data(), (size_t)n, leaf_addr, n, leaf);

    Bytes path_flat((size_t)p->A * (size_t)n);
    for (int j = 0; j < p->A; j++) {
      Bytes node = extract_bytes(sig, sig_offset, (size_t)n);
      std::memcpy(path_flat.data() + (size_t)j * (size_t)n, node.data(),
                  (size_t)n);
    }

    Address tree_addr = addr;
    tree_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
    tree_addr.set_keypair(addr.words[5]);

    Bytes tree_root = compute_root_from_path(
        leaf, global_fors_idx, path_flat.data(), p->A, pub_seed, tree_addr, n);
    std::memcpy(fors_pk_values.data() + (size_t)i * (size_t)n, tree_root.data(),
                (size_t)n);
  }

  Address root_addr = addr;
  root_addr.set_type(ADDR_TYPE_FORS_PK);
  root_addr.set_keypair(addr.words[5]);

  Bytes root((size_t)n);
  thash(state_seeded, fors_pk_values.data(), fors_pk_values.size(), root_addr,
        n, root.data());
  return root;
}
