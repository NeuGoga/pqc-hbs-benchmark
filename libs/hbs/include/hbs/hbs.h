#pragma once

#include "hbs/sphincs.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace hbs {

struct SchemeInfo {
  std::string name;
  std::string family;
  bool stateful = false;
  uint64_t max_signatures = std::numeric_limits<uint64_t>::max();
  size_t pk_size = 0;
  size_t sk_size = 0;
  size_t sig_size = 0;
};

std::vector<SchemeInfo> list_schemes();

class Scheme {
public:
  virtual ~Scheme() = default;
  virtual const SchemeInfo &info() const = 0;
  virtual std::vector<uint8_t> keygen(std::vector<uint8_t> &sk) = 0;
  virtual std::vector<uint8_t>
  keygen_from_seed(const std::vector<uint8_t> &seed,
                   std::vector<uint8_t> &sk) = 0;
  virtual std::vector<uint8_t> sign(const std::vector<uint8_t> &msg,
                                    const std::vector<uint8_t> &sk) = 0;
  virtual bool verify(const std::vector<uint8_t> &msg,
                      const std::vector<uint8_t> &sig,
                      const std::vector<uint8_t> &pk) = 0;
};

std::unique_ptr<Scheme> open(const std::string &name);

/* SHAKE256 (FIPS 202) — exposed so tests can check the sponge against NIST. */
void shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
void shake256(const std::vector<uint8_t> &in, std::vector<uint8_t> &out);

} // namespace hbs
