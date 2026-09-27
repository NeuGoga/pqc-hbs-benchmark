#include "hbs/hbs.h"

#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static int g_fails = 0;

static void check(bool cond, const std::string &msg) {
  if (!cond) {
    std::cerr << "FAIL: " << msg << "\n";
    ++g_fails;
  } else {
    std::cout << "  ok  " << msg << "\n";
  }
}

static std::vector<uint8_t> from_hex(const std::string &hex) {
  if (hex.size() % 2 != 0)
    throw std::runtime_error("odd hex length");
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    unsigned int v = 0;
    if (sscanf(hex.c_str() + 2 * i, "%2x", &v) != 1)
      throw std::runtime_error("bad hex");
    out[i] = static_cast<uint8_t>(v);
  }
  return out;
}

static std::string to_hex(const std::vector<uint8_t> &b) {
  static const char *k = "0123456789abcdef";
  std::string s;
  s.resize(b.size() * 2);
  for (size_t i = 0; i < b.size(); ++i) {
    s[2 * i] = k[b[i] >> 4];
    s[2 * i + 1] = k[b[i] & 0xf];
  }
  return s;
}

static std::map<std::string, std::string> load_kat(const std::string &path) {
  std::ifstream in(path);
  if (!in)
    throw std::runtime_error("cannot open " + path);
  std::map<std::string, std::string> kv;
  std::string line;
  while (std::getline(in, line)) {
    auto eq = line.find('=');
    if (eq == std::string::npos)
      continue;
    kv[line.substr(0, eq)] = line.substr(eq + 1);
  }
  return kv;
}

static void test_shake256() {
  std::cout << "SHAKE256 (FIPS 202 / hashlib)\n";

  std::vector<uint8_t> out(32);
  hbs::shake256(nullptr, 0, out.data(), out.size());
  check(to_hex(out) ==
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
        "empty message, 32-byte digest (NIST)");

  const uint8_t abc[] = {'a', 'b', 'c'};
  hbs::shake256(abc, 3, out.data(), out.size());
  check(to_hex(out) ==
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
        "message 'abc', 32-byte digest");
}

static void test_registry() {
  std::cout << "scheme registry\n";
  auto schemes = hbs::list_schemes();
  check(schemes.size() == 6, "six SPHINCS+ variants registered");

  bool found_128f = false;
  for (const auto &s : schemes) {
    check(!s.name.empty(), "scheme has a name");
    check(s.family == "sphincs+", s.name + " family");
    check(!s.stateful, s.name + " is stateless");
    check(s.pk_size == 2 * (s.name.find("128") != std::string::npos   ? 16
                            : s.name.find("192") != std::string::npos ? 24
                                                                      : 32),
          s.name + " pk size");
    auto opened = hbs::open(s.name);
    check(static_cast<bool>(opened), "open(" + s.name + ")");
    if (s.name == "MY_SPHINCS-128f")
      found_128f = true;
  }
  check(found_128f, "MY_SPHINCS-128f is listed");
  check(hbs::open("not-a-scheme") == nullptr, "unknown name returns null");
}

static void test_kat_128f(const std::string &kat_path) {
  std::cout << "SPHINCS+-SHAKE-128f-simple vs official reference KAT\n";
  auto kat = load_kat(kat_path);

  auto seed = from_hex(kat["seed"]);
  auto pk_ref = from_hex(kat["pk"]);
  auto sk_ref = from_hex(kat["sk"]);
  auto msg = from_hex(kat["msg"]);
  auto sig_ref = from_hex(kat["sig"]);

  auto scheme = hbs::open("MY_SPHINCS-128f");
  check(static_cast<bool>(scheme), "open MY_SPHINCS-128f");
  if (!scheme)
    return;

  check(scheme->info().pk_size == pk_ref.size(), "pk size matches KAT");
  check(scheme->info().sk_size == sk_ref.size(), "sk size matches KAT");
  check(scheme->info().sig_size == sig_ref.size(), "sig size matches KAT");

  std::vector<uint8_t> sk;
  auto pk = scheme->keygen_from_seed(seed, sk);
  check(pk == pk_ref, "keygen_from_seed pk matches official ref");
  check(sk == sk_ref, "keygen_from_seed sk matches official ref");

  auto sig = scheme->sign(msg, sk);
  check(sig.size() == sig_ref.size(), "sign produced expected length");
  check(sig == sig_ref,
        "deterministic sign matches official ref (optrand=PK.seed)");

  check(scheme->verify(msg, sig_ref, pk_ref), "verify official signature");
  check(scheme->verify(msg, sig, pk), "verify our signature");

  auto bad = msg;
  if (!bad.empty())
    bad[0] ^= 0x01;
  check(!scheme->verify(bad, sig, pk), "verify rejects tampered message");
}

static void test_roundtrip(const std::string &name) {
  std::cout << "roundtrip " << name << "\n";
  auto scheme = hbs::open(name);
  if (!scheme) {
    check(false, "open " + name);
    return;
  }
  std::vector<uint8_t> sk;
  auto pk = scheme->keygen(sk);
  check(pk.size() == scheme->info().pk_size, name + " pk size");
  check(sk.size() == scheme->info().sk_size, name + " sk size");

  std::vector<uint8_t> msg(100, 0x5A);
  auto sig = scheme->sign(msg, sk);
  check(sig.size() == scheme->info().sig_size, name + " sig size");
  check(scheme->verify(msg, sig, pk), name + " verify");

  auto msg2 = msg;
  msg2.back() ^= 0xff;
  check(!scheme->verify(msg2, sig, pk), name + " reject bad msg");
}

int main(int argc, char **argv) {
  std::string kat = "tests/vectors/sphincs-shake-128f-simple.kat";
  if (argc > 1)
    kat = argv[1];

  try {
    test_shake256();
    test_registry();
    test_kat_128f(kat);
    test_roundtrip("MY_SPHINCS-128f");
    test_roundtrip("MY_SPHINCS-192f");
    test_roundtrip("MY_SPHINCS-256f");
  } catch (const std::exception &ex) {
    std::cerr << "EXCEPTION: " << ex.what() << "\n";
    return 1;
  }

  if (g_fails) {
    std::cerr << g_fails << " check(s) failed\n";
    return 1;
  }
  std::cout << "all checks passed\n";
  return 0;
}
