#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

bool generate_random_bytes(std::vector<uint8_t> &buffer);
void secure_wipe(std::vector<uint8_t> &data);
int crypto_memcmp(const void *a, const void *b, size_t size);
