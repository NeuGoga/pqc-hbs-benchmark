# libhbs

Reusable hash-based signature library. SPHINCS+ (SHAKE simple) is the first
scheme. WOTS+, FORS, Merkle treehash and SHAKE256 live in separate files so
XMSS / LMS can share them later.

## Layout

```
include/hbs/hbs.h          list_schemes() / open(name)
include/hbs/sphincs.h      SphincsPlus class (original API + keygen_from_seed)
src/crypto/                SHAKE256, CSPRNG, wipe, bit helpers
src/merkle/                treehash + authentication path
src/sphincs/               address, WOTS+, FORS, hypertree, keygen/sign/verify
src/registry.cpp           scheme names
```

Add a new custom scheme by implementing `hbs::Scheme` and registering it in
`registry.cpp`. The tester/UI do not need to change.

## Verify

From the repo root (g++):

```
make -C ../.. test    # or: see top-level Makefile
```

`tests/test_hbs` checks:

1. SHAKE256 against NIST / hashlib vectors
2. SPHINCS+-SHAKE-128f-simple known-answer test generated from the official
   [sphincsplus](https://github.com/sphincs/sphincsplus) reference
   (`THASH=simple`), including a byte-for-byte signature match with
   `optrand = PK.seed`
3. keygen/sign/verify roundtrips for the 128f/192f/256f parameter sets
