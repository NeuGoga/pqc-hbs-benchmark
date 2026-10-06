#include "hbs/hbs.h"
#include "hbs/sphincs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

static int fail(const char *msg) {
  std::fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
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

  msg[0] ^= 1;
  if (a.verify(msg, sig1, pk1))
    return fail("verify accepted flipped message");

  std::printf("ok  SHAKE256 + SPHINCS+ 128f roundtrip + negative verify\n");
  std::printf("pk128f %s\n", hex(pk1.data(), pk1.size()).c_str());
  return 0;
}
