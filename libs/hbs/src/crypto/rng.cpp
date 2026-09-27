#include "crypto/rng.h"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#else
#include <cstring>
#include <fstream>

#endif

bool generate_random_bytes(std::vector<uint8_t> &buffer) {
  if (buffer.empty())
    return true;

#ifdef _WIN32
  NTSTATUS status = BCryptGenRandom(NULL, buffer.data(), (ULONG)buffer.size(),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status != 0) {
    std::cerr << "CSPRNG Error (Windows): BCryptGenRandom failed with status "
              << std::hex << status << std::endl;
    return false;
  }
  return true;
#else
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (!urandom) {
    std::cerr << "CSPRNG Error (Unix): Could not open /dev/urandom.\n";
    return false;
  }
  urandom.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
  if (!urandom) {
    std::cerr << "CSPRNG Error (Unix): Could not read enough bytes form "
                 "/dev/urandom.\n";
    return false;
  }
  return true;
#endif
}

/*  This function takes in a byte vector with data
 *   and overwrites its contents with zero in memory.
 */

void secure_wipe(std::vector<uint8_t> &data) {
  if (data.empty())
    return;

#ifdef _WIN32
  SecureZeroMemory(data.data(), data.size());
#else
  volatile uint8_t *p = data.data();
  size_t len = data.size();
  while (len--)
    *p++ = 0;
#endif
  data.clear();
}

int crypto_memcmp(const void *a, const void *b, size_t size) {
  const unsigned char *p1 = (const unsigned char *)a;
  const unsigned char *p2 = (const unsigned char *)b;
  unsigned char result = 0;

  for (size_t i = 0; i < size; i++) {
    result |= p1[i] ^ p2[i];
  }

  return result;
}
