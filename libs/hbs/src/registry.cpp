#include "crypto/shake.h"
#include "hbs/hbs.h"


#include <array>
#include <stdexcept>

namespace hbs {
namespace {

struct NamedVariant {
  const char *name;
  SphexVariant variant;
};

const NamedVariant kVariants[] = {
    {"MY_SPHINCS-128f", SphexVariant::SHAKE_128F_SIMPLE},
    {"MY_SPHINCS-128s", SphexVariant::SHAKE_128S_SIMPLE},
    {"MY_SPHINCS-192f", SphexVariant::SHAKE_192F_SIMPLE},
    {"MY_SPHINCS-192s", SphexVariant::SHAKE_192S_SIMPLE},
    {"MY_SPHINCS-256f", SphexVariant::SHAKE_256F_SIMPLE},
    {"MY_SPHINCS-256s", SphexVariant::SHAKE_256S_SIMPLE},
};

class SphincsScheme final : public Scheme {
  SchemeInfo info_;
  SphincsPlus impl_;

public:
  SphincsScheme(const NamedVariant &v) : impl_(v.variant) {
    info_.name = v.name;
    info_.family = "sphincs+";
    info_.stateful = false;
    info_.max_signatures = std::numeric_limits<uint64_t>::max();
    info_.pk_size = impl_.get_pk_size();
    info_.sk_size = impl_.get_sk_size();
    info_.sig_size = impl_.get_sig_size();
  }

  const SchemeInfo &info() const override { return info_; }

  std::vector<uint8_t> keygen(std::vector<uint8_t> &sk) override {
    return impl_.keygen(sk);
  }

  std::vector<uint8_t> keygen_from_seed(const std::vector<uint8_t> &seed,
                                        std::vector<uint8_t> &sk) override {
    return impl_.keygen_from_seed(seed, sk);
  }

  std::vector<uint8_t> sign(const std::vector<uint8_t> &msg,
                            const std::vector<uint8_t> &sk) override {
    return impl_.sign(msg, sk);
  }

  bool verify(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig,
              const std::vector<uint8_t> &pk) override {
    return impl_.verify(msg, sig, pk);
  }
};

const NamedVariant *find_variant(const std::string &name) {
  for (const auto &v : kVariants)
    if (name == v.name)
      return &v;
  return nullptr;
}

} // namespace

std::vector<SchemeInfo> list_schemes() {
  std::vector<SchemeInfo> out;
  out.reserve(6);
  for (const auto &v : kVariants) {
    SphincsPlus sp(v.variant);
    SchemeInfo info;
    info.name = v.name;
    info.family = "sphincs+";
    info.stateful = false;
    info.max_signatures = std::numeric_limits<uint64_t>::max();
    info.pk_size = sp.get_pk_size();
    info.sk_size = sp.get_sk_size();
    info.sig_size = sp.get_sig_size();
    out.push_back(info);
  }
  return out;
}

std::unique_ptr<Scheme> open(const std::string &name) {
  const NamedVariant *v = find_variant(name);
  if (!v)
    return nullptr;
  return std::make_unique<SphincsScheme>(*v);
}

void shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  Shake256::hash(in, in_len, out, out_len);
}

void shake256(const std::vector<uint8_t> &in, std::vector<uint8_t> &out) {
  Shake256::hash(in, out);
}

} // namespace hbs
