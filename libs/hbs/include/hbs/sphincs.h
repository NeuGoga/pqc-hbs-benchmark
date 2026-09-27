#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>


#if defined(_WIN32)
#define SPHINCS_API __declspec(dllexport)
#else
#define SPHINCS_API
#endif

enum class SphexVariant {
  SHAKE_128F_SIMPLE,
  SHAKE_192F_SIMPLE,
  SHAKE_256F_SIMPLE,
  SHAKE_128S_SIMPLE,
  SHAKE_192S_SIMPLE,
  SHAKE_256S_SIMPLE,
};

class SPHINCS_API SphincsPlus {
public:
  static constexpr size_t ADDRESS_BYTES = 32;

  SphincsPlus(SphexVariant variant);
  ~SphincsPlus();

  SphincsPlus(const SphincsPlus &) = delete;
  SphincsPlus &operator=(const SphincsPlus &) = delete;

  std::vector<uint8_t> keygen(std::vector<uint8_t> &sk_out);

  /* Deterministic keygen from a 3N-byte seed: SK.seed || SK.prf || PK.seed.
     Used for known-answer tests against the SPHINCS+ reference. */
  std::vector<uint8_t> keygen_from_seed(const std::vector<uint8_t> &seed,
                                        std::vector<uint8_t> &sk_out);

  std::vector<uint8_t> sign(const std::vector<uint8_t> &message,
                            const std::vector<uint8_t> &sk);

  bool verify(const std::vector<uint8_t> &message,
              const std::vector<uint8_t> &sig, const std::vector<uint8_t> &pk);

  size_t get_pk_size() const;
  size_t get_sk_size() const;
  size_t get_sig_size() const;

  int n() const;

  struct Params;

private:
  Params *p;
};
