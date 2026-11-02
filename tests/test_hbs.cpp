#include "hbs/hbs.h"
#include "hbs/sphincs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::string hex(const uint8_t *p, size_t n) {
  static const char *d = "0123456789abcdef";
  std::string s;
  s.resize(n * 2);
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = d[p[i] >> 4];
    s[2 * i + 1] = d[p[i] & 0xf];
  }
  return s;
}

static int fail(const std::string &msg) {
  std::fprintf(stderr, "FAIL: %s\n", msg.c_str());
  return 1;
}

static std::vector<uint8_t> unhex(const std::string &s) {
  std::vector<uint8_t> o;
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i + 1 < s.size(); i += 2) {
    int hi = nyb(s[i]), lo = nyb(s[i + 1]);
    if (hi < 0 || lo < 0)
      break;
    o.push_back((uint8_t)((hi << 4) | lo));
  }
  return o;
}

static bool parse_variant(const std::string &s, SphexVariant &out) {
  if (s == "SHAKE_128F_SIMPLE")
    out = SphexVariant::SHAKE_128F_SIMPLE;
  else if (s == "SHAKE_192F_SIMPLE")
    out = SphexVariant::SHAKE_192F_SIMPLE;
  else if (s == "SHAKE_256F_SIMPLE")
    out = SphexVariant::SHAKE_256F_SIMPLE;
  else if (s == "SHAKE_128S_SIMPLE")
    out = SphexVariant::SHAKE_128S_SIMPLE;
  else if (s == "SHAKE_192S_SIMPLE")
    out = SphexVariant::SHAKE_192S_SIMPLE;
  else if (s == "SHAKE_256S_SIMPLE")
    out = SphexVariant::SHAKE_256S_SIMPLE;
  else
    return false;
  return true;
}

static std::string kat_root() {
  const char *cands[] = {"tests/kat", "../tests/kat", "kat"};
  for (const char *c : cands) {
    std::ifstream in(std::string(c) + "/shake-128f-simple.txt");
    if (in)
      return c;
  }
  return {};
}

/* Official sphincsplus (THASH=simple) vectors.
   mode match  — keygen_from_seed and sign(optrand = PK.seed) must be identical
   mode verify — signature was produced with a different optrand; verify only */
static int check_kats() {
  const std::string root = kat_root();
  if (root.empty())
    return fail("known-answer files not found (run from the repo root)");

  const char *files[] = {
      "shake-128f-simple.txt", "shake-128s-simple.txt",
      "shake-192f-simple.txt", "shake-256f-simple.txt",
      "shake-192s-simple.txt", "shake-256s-simple.txt",
      "shake-128f-optrand-a5.txt"};
  for (const char *name : files) {
    std::ifstream in(root + "/" + name);
    if (!in)
      return fail(std::string("missing ") + name);
    std::string mode, variant, seed_h, msg_h, pk_h, sig_h, line;
    while (std::getline(in, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      auto sp = line.find(' ');
      if (sp == std::string::npos)
        continue;
      auto key = line.substr(0, sp);
      auto val = line.substr(sp + 1);
      if (key == "mode")
        mode = val;
      else if (key == "variant")
        variant = val;
      else if (key == "seed")
        seed_h = val;
      else if (key == "msg")
        msg_h = val;
      else if (key == "pk")
        pk_h = val;
      else if (key == "sig")
        sig_h = val;
    }
    SphexVariant v;
    if (!parse_variant(variant, v))
      return fail(std::string(name) + " bad variant");
    auto seed = unhex(seed_h);
    auto msg = unhex(msg_h);
    auto ref_pk = unhex(pk_h);
    auto ref_sig = unhex(sig_h);
    SphincsPlus sp(v);
    std::vector<uint8_t> sk;
    auto pk = sp.keygen_from_seed(seed, sk);
    if (pk != ref_pk)
      return fail(std::string(name) + " public key != official reference");
    if (mode == "keygen") {
      std::printf("ok  kat %s (keygen)\n", name);
      continue;
    }
    if (ref_sig.empty())
      return fail(std::string(name) + " missing signature");
    if (!sp.verify(msg, ref_sig, ref_pk))
      return fail(std::string(name) + " rejected official signature");
    auto bad = ref_sig;
    bad.back() ^= 1;
    if (sp.verify(msg, bad, ref_pk))
      return fail(std::string(name) + " accepted a flipped signature");
    if (mode == "match") {
      auto sig = sp.sign(msg, sk);
      if (sig != ref_sig)
        return fail(std::string(name) + " signature != official reference");
    } else if (mode != "verify") {
      return fail(std::string(name) + " unknown mode");
    }
    std::printf("ok  kat %s (%s)\n", name, mode.c_str());
  }
  return 0;
}

int main() {
  uint8_t out[32];
  hbs::shake256(nullptr, 0, out, 32);
  if (hex(out, 32) !=
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
    return fail("SHAKE256 empty");

  const uint8_t abc[] = {'a', 'b', 'c'};
  hbs::shake256(abc, 3, out, 32);
  if (hex(out, 32) !=
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
    return fail("SHAKE256 abc");

  std::vector<uint8_t> seed(48);
  for (int i = 0; i < 48; i++)
    seed[(size_t)i] = (uint8_t)i;

  SphincsPlus a(SphexVariant::SHAKE_128F_SIMPLE);
  SphincsPlus b(SphexVariant::SHAKE_128F_SIMPLE);
  std::vector<uint8_t> sk1, sk2;
  auto pk1 = a.keygen_from_seed(seed, sk1);
  auto pk2 = b.keygen_from_seed(seed, sk2);
  if (pk1 != pk2 || sk1 != sk2)
    return fail("keygen_from_seed not deterministic");

  std::vector<uint8_t> msg(32, 0xA0);
  auto sig1 = a.sign(msg, sk1);
  auto sig2 = b.sign(msg, sk2);
  if (sig1 != sig2)
    return fail("sign not deterministic");
  if (!a.verify(msg, sig1, pk1))
    return fail("verify 128f own sig");
  if (!b.verify(msg, sig2, pk2))
    return fail("verify 128f other instance");

  std::vector<uint8_t> short_sk(3, 1);
  if (!a.sign(msg, short_sk).empty())
    return fail("short secret key should be rejected");

  std::vector<uint8_t> junk(a.get_sig_size(), 0);
  if (a.verify(msg, junk, pk1))
    return fail("verify accepted an all-zero signature");

  msg[0] ^= 1;
  if (a.verify(msg, sig1, pk1))
    return fail("verify accepted flipped message");

  if (int rc = check_kats())
    return rc;

  std::printf("ok  SHAKE256 + official SPHINCS+ KATs + negative verify\n");
  std::printf("threads %d\n", hbs::thread_budget());
  return 0;
}
