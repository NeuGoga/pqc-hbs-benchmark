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
2. SPHINCS+-SHAKE simple known-answer tests against the official
   [sphincsplus](https://github.com/sphincs/sphincsplus) reference
   (`THASH=simple`). Signatures match byte for byte with `optrand = PK.seed`
   for 128f, 128s, 192f and 256f. Public keys match for 192s and 256s.
   A 128f signature produced with `optrand = 0xA5…` must still verify.
3. keygen/sign/verify roundtrips for the 128f parameter set

## Threads and hash backend

The hash and the parallelism are chosen independently, and both are optional:

1. **SHAKE256** — OpenSSL `EVP_shake256` if the library was built with
   OpenSSL (`PQC_HAS_OPENSSL`). Otherwise the bundled scalar Keccak in
   `src/crypto`. Results are the same either way.
2. **OpenMP** — if the compiler enables it, WOTS chains and Merkle leaves
   run in parallel on top of that hash. Without OpenMP the same loops are
   single-threaded.

By default the OpenMP team does **not** grab every logical CPU (that pinned
machines at about 99%, and hyperthreads barely help Keccak). The default is
the number of physical cores, or one less when the CPU has no SMT, so a core
stays free for the OS and the GUI. Override it with:

* `HBS_THREADS=4` — use exactly 4 threads
* `HBS_THREADS=all` — every logical CPU (the old full-speed behaviour)
* `OMP_NUM_THREADS` — honored when `HBS_THREADS` is not set

The desktop window has a Threads box. `0` means this default. A positive
number is also exported as `OMP_NUM_THREADS` so liboqs is capped the same way.
