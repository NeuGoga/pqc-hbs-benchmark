#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <array>
#include <sstream>
#include <stdexcept>
#include <cstdio>
#include <filesystem>
#include <memory>

#ifdef _WIN32
	#define POPEN _popen
	#define PCLOSE _pclose
	const std::string BENCHMARK_CMD_PREFIX = "benchmark.exe";
#else
	#include <unistd.h>
	#define POPEN popen
	#define PCLOSE pclose
	const std::string BENCHMARK_CMD_PREFIX = "./benchmark";
#endif

const bool USE_BASELINE_MEMORY = true;
const int ITERATIONS_STATELESS = 1;
const int ITERATIONS_STATEFUL = 1;

std::string exec(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&PCLOSE)> pipe(POPEN(cmd, "r"), PCLOSE);
	if (!pipe) return "";
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	if (!result.empty() && result.back() == '\n') result.pop_back();
	return result;
}

std::string sanitize_filename(std::string name) {
	for (char& c : name) {
		if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
			c = '_';
		}
	}
	return name;
}

std::vector<std::string> split_string(const std::string& s, char delimeter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimeter)) {
		tokens.push_back(token);
	}
	return tokens;
}

int main() {
	std::vector<std::string> algorithms_stateless = {
		"SPHINCS+-SHA2-128s-simple",
		"SPHINCS+-SHA2-128f-simple",
		"SPHINCS+-SHA2-192s-simple",
		"SPHINCS+-SHA2-192f-simple",
		"SPHINCS+-SHA2-256s-simple",
		"SPHINCS+-SHA2-256f-simple"
	};

	std::vector<std::string> algorithms_stateful = {
		"XMSSMT-SHA2_20/2_256",
		"XMSSMT-SHA2_20/4_256",
		"LMS_SHA256_H5_W1"
	};

	const std::string output_filename = "results.csv";
	std::ofstream output_file(output_filename, std::ios::out);

	if (!output_file.is_open()) {
		std::cerr << "Error opening file.";
		return 1;
	}

	output_file << "Algorithm,PK Size (B),SK Size (B),Sig Size (B),Keygen Time (us),Sign Time (us),Verify Time (us),Keygen Peak Mem (KB),Sign Peak Mem (KB), Verify Peak Mem (KB)" << std::endl;

	std::string arg_baseline = USE_BASELINE_MEMORY ? " 1 " : " 0 ";	

	auto run_suite = [&](const std::string& alg_name, bool is_stateful, int iterations) {
		std::cout << "Benchmarking " << alg_name << "..." << std::endl;

		std::string flags = is_stateful ? " 1 " : " 0 ";

		//Keygen benchmarking
		std::string cmd_kg = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "0 " + std::to_string(iterations) + " " + arg_baseline;
		std::string res_kg = exec(cmd_kg.c_str());
		std::vector<std::string> kg_data = split_string(res_kg, ',');


		if (kg_data.size() < 5) {
			std::cout << "Failed keygen." << std::endl;
			return;
		}

		std::string cmd_sign = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "1 " + std::to_string(iterations) + " " + arg_baseline;
		std::string res_sign = exec(cmd_sign.c_str());
		std::vector<std::string> sign_data = split_string(res_sign, ',');

		if (sign_data.size() < 2) {
			sign_data = { "0", "0", };
		}

		std::string cmd_ver = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "2 " + std::to_string(iterations) + " " + arg_baseline;
		std::string res_ver = exec(cmd_ver.c_str());
		std::vector<std::string> ver_data = split_string(res_ver, ',');

		if (ver_data.size() < 2) {
			ver_data = { "0", "0", };
		}

		output_file << alg_name << ","
			<< kg_data[2] << "," << kg_data[3] << ","
			<< kg_data[4] << "," << kg_data[0] << ","
			<< sign_data[0] << "," << ver_data[0] << ","
			<< kg_data[1] << "," << sign_data[1] << ","
			<< ver_data[1] << std::endl;
		

		std::cout << "Finished benchmarking " << alg_name << "." << std::endl;

		//Removing benchmarking files
		std::string safe_name = sanitize_filename(alg_name);
		std::remove((safe_name + ".pk").c_str());
		std::remove((safe_name + ".sk").c_str());
		std::remove((safe_name + ".sig").c_str());
		};

	for (const auto& alg_name : algorithms_stateless) run_suite(alg_name, false, ITERATIONS_STATELESS);
	for (const auto& alg_name : algorithms_stateful) run_suite(alg_name, true, ITERATIONS_STATEFUL);

	std::cout << "All tests finished. Results saved to " << output_filename << std::endl;
	return 0;
}