#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef PQC_HAS_OQS
#include <oqs/oqs.h>
#endif

#ifdef PQC_HAS_CUSTOM_SPHINCS
#include "hbs/hbs.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>

#else
#include <sys/resource.h>
#endif

const int TYPE_OQS_STATELESS = 0;
const int TYPE_OQS_STATEFUL = 1;
const int TYPE_CUSTOM = 2;

static int skip(const std::string &reason) {
  std::cerr << "SKIP: " << reason << std::endl;
  std::cout << "SKIP";
  return 2;
}

static void emit_progress(const char *phase, int i, int n) {
  std::cerr << "PROGRESS " << phase << " " << i << " " << n << std::endl;
}

static std::string sanitize_filename(const std::string &name) {
  std::string out = name;
  for (char &c : out) {
    if (c == '/' || c == '\\' || c == ':' || c == ' ')
      c = '_';
  }
  return out;
}

void write_file(const std::string &filename, const std::vector<uint8_t> &data) {
  std::ofstream file(filename, std::ios::binary);
  if (!file)
    return;
  file.write(reinterpret_cast<const char *>(data.data()),
             static_cast<std::streamsize>(data.size()));
}

std::vector<uint8_t> read_file(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary | std::ios::ate);
  if (!file)
    return {};
  auto size = file.tellg();
  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> buffer(static_cast<size_t>(size));
  file.read(reinterpret_cast<char *>(buffer.data()), size);
  return buffer;
}

long get_peak_memory_kb() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS_EX pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc,
                           sizeof(pmc)))
    return static_cast<long>(pmc.PeakWorkingSetSize / 1024);
  return -1;
#else
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0)
    return usage.ru_maxrss;
  return -1;
#endif
}

#ifdef PQC_HAS_OQS
struct stfl_key_storage {
  std::vector<uint8_t> key_data;
};

OQS_STATUS my_secure_store_sk(uint8_t *sk_buf, size_t sk_buf_len,
                              void *context) {
  if (context == NULL)
    return OQS_ERROR;
  auto *storage = static_cast<stfl_key_storage *>(context);
  storage->key_data.assign(sk_buf, sk_buf + sk_buf_len);
  return OQS_SUCCESS;
}

int benchmark_oqs_stateless(const std::string &alg_name, int mode,
                            int iterations, long baseline_mem,
                            const std::string &pk_file,
                            const std::string &sk_file,
                            const std::string &sig_file) {
  OQS_SIG *sig = OQS_SIG_new(alg_name.c_str());
  if (!sig)
    return skip("OQS could not create '" + alg_name + "'");

  if (mode == 0) {
    std::vector<uint8_t> pk(sig->length_public_key), sk(sig->length_secret_key);
    emit_progress("keygen", 0, 1);
    auto start = std::chrono::high_resolution_clock::now();
    if (OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
      OQS_SIG_free(sig);
      return skip("OQS keygen failed for " + alg_name);
    }
    auto end = std::chrono::high_resolution_clock::now();
    emit_progress("keygen", 1, 1);
    write_file(pk_file, pk);
    write_file(sk_file, sk);
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count())
              << "," << (get_peak_memory_kb() - baseline_mem) << ","
              << sig->length_public_key << "," << sig->length_secret_key << ","
              << sig->length_signature;
  } else if (mode == 1) {
    std::vector<uint8_t> sk = read_file(sk_file);
    if (sk.empty()) {
      OQS_SIG_free(sig);
      return 1;
    }
    std::vector<uint8_t> msg(100);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      if (OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(),
                       sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return skip("OQS sign failed for " + alg_name);
      }
      emit_progress("sign", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();
    signature.resize(sig_len);
    write_file(sig_file, signature);
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
  } else if (mode == 2) {
    std::vector<uint8_t> pk = read_file(pk_file);
    std::vector<uint8_t> signature = read_file(sig_file);
    if (pk.empty() || signature.empty()) {
      OQS_SIG_free(sig);
      return 1;
    }
    std::vector<uint8_t> msg(100);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      if (OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(),
                         signature.size(), pk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return skip("OQS verify failed for " + alg_name);
      }
      emit_progress("verify", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
  }
  OQS_SIG_free(sig);
  return 0;
}

int benchmark_oqs_stateful(const std::string &alg_name, int mode,
                           int iterations, long baseline_mem,
                           const std::string &pk_file,
                           const std::string &sk_file,
                           const std::string &sig_file) {
  OQS_SIG_STFL *sig = OQS_SIG_STFL_new(alg_name.c_str());
  if (!sig)
    return skip("OQS could not create stateful '" + alg_name + "'");

  if (mode == 0) {
    std::vector<uint8_t> pk(sig->length_public_key);
    OQS_SIG_STFL_SECRET_KEY *sk_obj =
        OQS_SIG_STFL_SECRET_KEY_new(alg_name.c_str());
    stfl_key_storage store;
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk_obj, my_secure_store_sk, &store);

    emit_progress("keygen", 0, 1);
    auto start = std::chrono::high_resolution_clock::now();
    if (OQS_SIG_STFL_keypair(sig, pk.data(), sk_obj) != OQS_SUCCESS) {
      OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
      OQS_SIG_STFL_free(sig);
      return skip("OQS stateful keygen failed for " + alg_name);
    }
    auto end = std::chrono::high_resolution_clock::now();
    emit_progress("keygen", 1, 1);

    write_file(pk_file, pk);
    uint8_t *sk_bytes = nullptr;
    size_t sk_len = 0;
    OQS_SIG_STFL_SECRET_KEY_serialize(&sk_bytes, &sk_len, sk_obj);
    std::vector<uint8_t> sk_vec(sk_bytes, sk_bytes + sk_len);
    write_file(sk_file, sk_vec);
    OQS_MEM_secure_free(sk_bytes, sk_len);

    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count())
              << "," << (get_peak_memory_kb() - baseline_mem) << ","
              << sig->length_public_key << "," << sk_len << ","
              << sig->length_signature;
    OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
  } else if (mode == 1) {
    std::vector<uint8_t> sk_data = read_file(sk_file);
    if (sk_data.empty()) {
      OQS_SIG_STFL_free(sig);
      return 1;
    }

    OQS_SIG_STFL_SECRET_KEY *sk_obj =
        OQS_SIG_STFL_SECRET_KEY_new(alg_name.c_str());
    stfl_key_storage store;
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk_obj, my_secure_store_sk, &store);
    OQS_SIG_STFL_SECRET_KEY_deserialize(sk_obj, sk_data.data(), sk_data.size(),
                                        &store);

    std::vector<uint8_t> msg(100);
    std::vector<uint8_t> signature(sig->length_signature);
    size_t sig_len = 0;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      if (OQS_SIG_STFL_sign(sig, signature.data(), &sig_len, msg.data(),
                            msg.size(), sk_obj) != OQS_SUCCESS) {
        OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
        OQS_SIG_STFL_free(sig);
        return skip("OQS stateful sign failed for " + alg_name +
                    " (key exhausted?)");
      }
      emit_progress("sign", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();

    uint8_t *sk_bytes = nullptr;
    size_t sk_len = 0;
    OQS_SIG_STFL_SECRET_KEY_serialize(&sk_bytes, &sk_len, sk_obj);
    write_file(sk_file, std::vector<uint8_t>(sk_bytes, sk_bytes + sk_len));
    OQS_MEM_secure_free(sk_bytes, sk_len);

    signature.resize(sig_len);
    write_file(sig_file, signature);
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
    OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
  } else if (mode == 2) {
    std::vector<uint8_t> pk = read_file(pk_file);
    std::vector<uint8_t> signature = read_file(sig_file);
    if (pk.empty() || signature.empty()) {
      OQS_SIG_STFL_free(sig);
      return 1;
    }
    std::vector<uint8_t> msg(100);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      if (OQS_SIG_STFL_verify(sig, msg.data(), msg.size(), signature.data(),
                              signature.size(), pk.data()) != OQS_SUCCESS) {
        OQS_SIG_STFL_free(sig);
        return skip("OQS stateful verify failed for " + alg_name);
      }
      emit_progress("verify", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
  }
  OQS_SIG_STFL_free(sig);
  return 0;
}
#else
int benchmark_oqs_stateless(const std::string &, int, int, long,
                            const std::string &, const std::string &,
                            const std::string &) {
  return skip("built without liboqs");
}
int benchmark_oqs_stateful(const std::string &, int, int, long,
                           const std::string &, const std::string &,
                           const std::string &) {
  return skip("built without liboqs");
}
#endif

int benchmark_custom(const std::string &alg_name, int mode, int iterations,
                     long baseline_mem, const std::string &pk_file,
                     const std::string &sk_file, const std::string &sig_file) {
#ifndef PQC_HAS_CUSTOM_SPHINCS
  (void)alg_name;
  (void)mode;
  (void)iterations;
  (void)baseline_mem;
  (void)pk_file;
  (void)sk_file;
  (void)sig_file;
  return skip("custom library (libhbs) was not built");
#else
  auto scheme = hbs::open(alg_name);
  if (!scheme)
    return skip("unknown custom scheme '" + alg_name + "'");

  if (mode == 0) {
    std::vector<uint8_t> sk;
    emit_progress("keygen", 0, 1);
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> pk = scheme->keygen(sk);
    auto end = std::chrono::high_resolution_clock::now();
    emit_progress("keygen", 1, 1);
    if (pk.empty() || sk.empty())
      return skip("custom keygen failed for " + alg_name);
    write_file(pk_file, pk);
    write_file(sk_file, sk);
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count())
              << "," << (get_peak_memory_kb() - baseline_mem) << ","
              << scheme->info().pk_size << "," << scheme->info().sk_size << ","
              << scheme->info().sig_size;
  } else if (mode == 1) {
    std::vector<uint8_t> sk = read_file(sk_file);
    std::vector<uint8_t> msg(100, 0);
    std::vector<uint8_t> signature;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      signature = scheme->sign(msg, sk);
      if (signature.empty())
        return skip("custom sign failed for " + alg_name);
      emit_progress("sign", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();
    write_file(sig_file, signature);
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
  } else if (mode == 2) {
    std::vector<uint8_t> pk = read_file(pk_file);
    std::vector<uint8_t> signature = read_file(sig_file);
    std::vector<uint8_t> msg(100, 0);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      if (!scheme->verify(msg, signature, pk))
        return skip("custom verify failed for " + alg_name);
      emit_progress("verify", i + 1, iterations);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(
                              end - start)
                              .count()) /
                     iterations
              << "," << (get_peak_memory_kb() - baseline_mem);
  }
  return 0;
#endif
}

static int print_list() {
  std::cout << "name,type,family,stateful,pk_size,sk_size,sig_size\n";
#ifdef PQC_HAS_OQS
  for (int i = 0; i < OQS_SIG_alg_count(); ++i) {
    const char *id = OQS_SIG_alg_identifier(i);
    if (!id || !OQS_SIG_alg_is_enabled(id))
      continue;
    OQS_SIG *sig = OQS_SIG_new(id);
    if (!sig)
      continue;
    std::cout << id << ",oqs_stateless,oqs,0," << sig->length_public_key << ","
              << sig->length_secret_key << "," << sig->length_signature << "\n";
    OQS_SIG_free(sig);
  }
  for (int i = 0; i < OQS_SIG_STFL_alg_count(); ++i) {
    const char *id = OQS_SIG_STFL_alg_identifier(i);
    if (!id || !OQS_SIG_STFL_alg_is_enabled(id))
      continue;
    OQS_SIG_STFL *sig = OQS_SIG_STFL_new(id);
    if (!sig)
      continue;
    std::cout << id << ",oqs_stateful,oqs,1," << sig->length_public_key << ",,"
              << sig->length_signature << "\n";
    OQS_SIG_STFL_free(sig);
  }
#endif
#ifdef PQC_HAS_CUSTOM_SPHINCS
  for (const auto &s : hbs::list_schemes()) {
    std::cout << s.name << ",custom," << s.family << "," << (s.stateful ? 1 : 0)
              << "," << s.pk_size << "," << s.sk_size << "," << s.sig_size
              << "\n";
  }
#endif
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc >= 2 && std::string(argv[1]) == "--list")
    return print_list();

  if (argc < 6) {
    std::cerr
        << "usage: benchmark <alg> <type> <mode> <iterations> <baseline>\n"
        << "       benchmark --list\n";
    return 3;
  }

  std::string alg_name = argv[1];
  int algo_type = std::stoi(argv[2]);
  int mode = std::stoi(argv[3]);
  int iterations = std::stoi(argv[4]);
  bool use_baseline = std::stoi(argv[5]) == 1;

  long baseline_mem = use_baseline ? get_peak_memory_kb() : 0;
  std::string safe_name = sanitize_filename(alg_name);
  std::string pk_file = safe_name + ".pk";
  std::string sk_file = safe_name + ".sk";
  std::string sig_file = safe_name + ".sig";

  if (algo_type == TYPE_OQS_STATELESS)
    return benchmark_oqs_stateless(alg_name, mode, iterations, baseline_mem,
                                   pk_file, sk_file, sig_file);
  if (algo_type == TYPE_OQS_STATEFUL)
    return benchmark_oqs_stateful(alg_name, mode, iterations, baseline_mem,
                                  pk_file, sk_file, sig_file);
  if (algo_type == TYPE_CUSTOM)
    return benchmark_custom(alg_name, mode, iterations, baseline_mem, pk_file,
                            sk_file, sig_file);
  return skip("unknown type");
}
