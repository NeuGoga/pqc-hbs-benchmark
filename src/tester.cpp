#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
const std::string BENCHMARK_CMD_PREFIX = "benchmark.exe";
#else
const std::string BENCHMARK_CMD_PREFIX = "./benchmark";
#endif

const int TYPE_OQS_STATELESS = 0;
const int TYPE_OQS_STATEFUL = 1;
const int TYPE_CUSTOM = 2;
const int ITERATIONS_STATELESS = 1000;
const int ITERATIONS_STATELESS_MINE = 8;
const int ITERATIONS_STATEFUL = 16;
const int ITERATIONS_LATTICE = 1000;
const bool USE_BASELINE_MEMORY = true;

static std::string exec(const char *cmd) {
  std::string result;
#ifdef _WIN32
  FILE *pipe = _popen(cmd, "r");
#else
  FILE *pipe = popen(cmd, "r");
#endif
  if (!pipe)
    return "ERROR";
  char buffer[512];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    result += buffer;
#ifdef _WIN32
  _pclose(pipe);
#else
  pclose(pipe);
#endif
  return result;
}

static std::vector<std::string> split_string(const std::string &s,
                                             char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  for (char c : s) {
    if (c == delimiter) {
      tokens.push_back(token);
      token.clear();
    } else if (c != '\n' && c != '\r')
      token += c;
  }
  tokens.push_back(token);
  return tokens;
}

static std::string sanitize_filename(const std::string &name) {
  std::string out = name;
  for (char &c : out)
    if (c == '/' || c == '\\' || c == ':')
      c = '_';
  return out;
}

static void run_suite(std::ofstream &output_file,
                      const std::string &arg_baseline,
                      const std::string &alg_name, int type, int iterations) {
  std::cout << "Starting " << alg_name << "..." << std::endl;
  std::string t = std::to_string(type);

  std::string cmd_kg = BENCHMARK_CMD_PREFIX + " \"" + alg_name + "\" " + t +
                       " 0 1" + arg_baseline;
  std::string res_kg = exec(cmd_kg.c_str());
  auto kg_data = split_string(res_kg, ',');
  if (kg_data.size() < 5) {
    if (res_kg.find("SKIP") != std::string::npos)
      std::cout << "Skipped " << alg_name << "." << std::endl;
    else
      std::cout << "Failed keygen." << std::endl;
    return;
  }

  std::string cmd_sg = BENCHMARK_CMD_PREFIX + " \"" + alg_name + "\" " + t +
                       " 1 " + std::to_string(iterations) + arg_baseline;
  std::string res_sg = exec(cmd_sg.c_str());
  auto sg_data = split_string(res_sg, ',');

  std::string cmd_vf = BENCHMARK_CMD_PREFIX + " \"" + alg_name + "\" " + t +
                       " 2 " + std::to_string(iterations) + arg_baseline;
  std::string res_vf = exec(cmd_vf.c_str());
  auto vf_data = split_string(res_vf, ',');

  output_file << alg_name << "," << kg_data[2] << "," << kg_data[3] << ","
              << kg_data[4] << "," << kg_data[0] << ","
              << (sg_data.size() > 0 ? sg_data[0] : "") << ","
              << (vf_data.size() > 0 ? vf_data[0] : "") << "," << kg_data[1]
              << "," << (sg_data.size() > 1 ? sg_data[1] : "") << ","
              << (vf_data.size() > 1 ? vf_data[1] : "") << std::endl;

  std::string safe_name = sanitize_filename(alg_name);
  std::remove((safe_name + ".pk").c_str());
  std::remove((safe_name + ".sk").c_str());
  std::remove((safe_name + ".sig").c_str());
  std::cout << "Finished benchmarking " << alg_name << "." << std::endl;
}

int main(int argc, char **argv) {
  if (argc >= 2 && std::string(argv[1]) == "--list") {
    std::cout << exec((BENCHMARK_CMD_PREFIX + " --list").c_str());
    return 0;
  }

  std::vector<std::string> algorithms_stateless = {
      "SLH_DSA_PURE_SHA2_128S",  "SLH_DSA_PURE_SHA2_128F",
      "SLH_DSA_PURE_SHA2_192S",  "SLH_DSA_PURE_SHA2_192F",
      "SLH_DSA_PURE_SHA2_256S",  "SLH_DSA_PURE_SHA2_256F",
      "SLH_DSA_PURE_SHAKE_128S", "SLH_DSA_PURE_SHAKE_128F",
      "SLH_DSA_PURE_SHAKE_192S", "SLH_DSA_PURE_SHAKE_192F",
      "SLH_DSA_PURE_SHAKE_256S", "SLH_DSA_PURE_SHAKE_256F"};
  std::vector<std::string> algorithms_lattice = {"ML-DSA-44", "ML-DSA-65",
                                                 "ML-DSA-87"};
  std::vector<std::string> algorithms_mine_stateless = {
      "MY_SPHINCS-128s", "MY_SPHINCS-128f", "MY_SPHINCS-192s",
      "MY_SPHINCS-192f", "MY_SPHINCS-256s", "MY_SPHINCS-256f"};
  std::vector<std::string> algorithms_stateful = {
      "XMSSMT-SHA2_20/2_256", "XMSSMT-SHA2_20/4_256", "LMS_SHA256_H5_W8"};

  std::ofstream output_file("results.csv");
  if (!output_file) {
    std::cerr << "Error opening results.csv\n";
    return 1;
  }
  output_file << "Algorithm,PK Size (B),SK Size (B),Sig Size (B),Keygen Time "
                 "(us),Sign Time (us),Verify Time (us),Keygen Peak Mem "
                 "(KB),Sign Peak Mem (KB), Verify Peak Mem (KB)\n";
  std::string arg_baseline = USE_BASELINE_MEMORY ? " 1 " : " 0 ";

  for (const auto &a : algorithms_stateless)
    run_suite(output_file, arg_baseline, a, TYPE_OQS_STATELESS,
              ITERATIONS_STATELESS);
  for (const auto &a : algorithms_stateful)
    run_suite(output_file, arg_baseline, a, TYPE_OQS_STATEFUL,
              ITERATIONS_STATEFUL);
  for (const auto &a : algorithms_mine_stateless)
    run_suite(output_file, arg_baseline, a, TYPE_CUSTOM,
              ITERATIONS_STATELESS_MINE);
  for (const auto &a : algorithms_lattice)
    run_suite(output_file, arg_baseline, a, TYPE_OQS_STATELESS,
              ITERATIONS_LATTICE);

  std::cout << "All tests finished. Results saved to results.csv\n";
  return 0;
}
