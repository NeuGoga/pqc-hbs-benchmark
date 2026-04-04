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
const int ITERATIONS_STATELESS = 5;
const int ITERATIONS_STATEFUL = 5;
const int ITERATIONS_STATELESS_MINE = 5;
const int ITERATIONS_LATTICE = 5000;

const int TYPE_OQS_STATELESS = 0;
const int TYPE_OQS_STATEFUL = 1;
const int TYPE_CUSTOM = 2;

/*	This function executes a shell command and captures its standard output.
 *	It is used to run external benchmark process and retieve the
 *	comma-separated data.
 */
std::string exec(const char *cmd)
{
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&PCLOSE)> pipe(POPEN(cmd, "r"), PCLOSE);
	if (!pipe)
		return "";
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}
	if (!result.empty() && result.back() == '\n')
		result.pop_back();
	return result;
}

/*	This function sanitizes input string with underscores,
 *	so there is no erros when saving files.
 */
std::string sanitize_filename(std::string name)
{
	for (char &c : name)
	{
		if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
		{
			c = '_';
		}
	}
	return name;
}

/*	This function splits a string into vector of substrings based on
 *	a specified delimiter. Used to parse the comma-separated data returned
 *	by benchmark.
 */
std::vector<std::string> split_string(const std::string &s, char delimeter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimeter))
	{
		tokens.push_back(token);
	}
	return tokens;
}

/*	This function manages execution of all 3 modes for a single algorithm.
 *	It runs the benchmark process with following arguments:
 *	[benchmark_executable] [alg_name] [type] [mode] [iterations] [use_baseline]
 *
 *	Example: ./benchmark MY_SPHINCS-128f 2 0 100 1
 *
 *	The suite runs in order Keygen (mode 0), Sign (mode 1), and Verify (mode 2).
 *	It collecets all timing, memory, and size data from standard outputs, and
 *	logs combined row into "results.csv" file, and then deletes
 *	leftover .pk, .sk, .sig files.
 */
void run_suite(std::ofstream &output_file, const std::string &arg_baseline, const std::string &alg_name, int type, int iterations)
{
	std::cout << "Benchmarking " << alg_name << "..." << std::endl;

	std::string flags = " " + std::to_string(type) + " ";

	std::string cmd_kg = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "0 " + std::to_string(iterations) + " " + arg_baseline;
	std::string res_kg = exec(cmd_kg.c_str());
	std::vector<std::string> kg_data = split_string(res_kg, ',');

	if (kg_data.size() < 5)
	{
		std::cout << "Failed keygen." << std::endl;
		return;
	}

	std::string cmd_sign = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "1 " + std::to_string(iterations) + " " + arg_baseline;
	std::string res_sign = exec(cmd_sign.c_str());
	std::vector<std::string> sign_data = split_string(res_sign, ',');

	if (sign_data.size() < 2)
	{
		sign_data = {
			"0",
			"0",
		};
	}

	std::string cmd_ver = BENCHMARK_CMD_PREFIX + " " + alg_name + flags + "2 " + std::to_string(iterations) + " " + arg_baseline;
	std::string res_ver = exec(cmd_ver.c_str());
	std::vector<std::string> ver_data = split_string(res_ver, ',');

	if (ver_data.size() < 2)
	{
		ver_data = {
			"0",
			"0",
		};
	}

	output_file << alg_name << ","
				<< kg_data[2] << "," << kg_data[3] << ","
				<< kg_data[4] << "," << kg_data[0] << ","
				<< sign_data[0] << "," << ver_data[0] << ","
				<< kg_data[1] << "," << sign_data[1] << ","
				<< ver_data[1] << std::endl;

	std::cout << "Finished benchmarking " << alg_name << "." << std::endl;

	std::string safe_name = sanitize_filename(alg_name);
	std::remove((safe_name + ".pk").c_str());
	std::remove((safe_name + ".sk").c_str());
	std::remove((safe_name + ".sig").c_str());
};

/* Main function.
 *	Iterates through lists of algorithms and runs run_suite function
 *	with each algorithm name until all tests are completed.
 */
int main()
{
	std::vector<std::string> algorithms_stateless = {
		"SLH_DSA_PURE_SHA2_128S",
		"SLH_DSA_PURE_SHA2_128F",
		"SLH_DSA_PURE_SHA2_192S",
		"SLH_DSA_PURE_SHA2_192F",
		"SLH_DSA_PURE_SHA2_256S",
		"SLH_DSA_PURE_SHA2_256F",
		"SLH_DSA_PURE_SHAKE_128S",
		"SLH_DSA_PURE_SHAKE_128F",
		"SLH_DSA_PURE_SHAKE_192S",
		"SLH_DSA_PURE_SHAKE_192F",
		"SLH_DSA_PURE_SHAKE_256S",
		"SLH_DSA_PURE_SHAKE_256F"
	};

	std::vector<std::string> algorithms_lattice = {
		"ML-DSA-44",
		"ML-DSA-65",
		"ML-DSA-87"
	};

	std::vector<std::string> algorithms_mine_stateless = {
		"MY_SPHINCS-128s",
		"MY_SPHINCS-128f",
		"MY_SPHINCS-192s",
		"MY_SPHINCS-192f",
		"MY_SPHINCS-256s",
		"MY_SPHINCS-256f"
	};

	std::vector<std::string> algorithms_stateful = {
		"XMSSMT-SHA2_20/2_256",
		"XMSSMT-SHA2_20/4_256",
		"LMS_SHA256_H5_W8"
	};

	const std::string output_filename = "results.csv";
	std::ofstream output_file(output_filename, std::ios::out);

	if (!output_file.is_open())
	{
		std::cerr << "Error opening file.";
		return 1;
	}

	output_file << "Algorithm,PK Size (B),SK Size (B),Sig Size (B),Keygen Time (us),Sign Time (us),Verify Time (us),Keygen Peak Mem (KB),Sign Peak Mem (KB), Verify Peak Mem (KB)" << std::endl;

	std::string arg_baseline = USE_BASELINE_MEMORY ? " 1 " : " 0 ";

	for (const auto &alg_name : algorithms_stateless)
		run_suite(output_file, arg_baseline, alg_name, TYPE_OQS_STATELESS, ITERATIONS_STATELESS);

	for (const auto &alg_name : algorithms_stateful)
		run_suite(output_file, arg_baseline, alg_name, TYPE_OQS_STATEFUL, ITERATIONS_STATEFUL);

	for (const auto &alg_name : algorithms_mine_stateless)
		run_suite(output_file, arg_baseline, alg_name, TYPE_CUSTOM, ITERATIONS_STATELESS_MINE);

	for (const auto &alg_name : algorithms_lattice)
		run_suite(output_file, arg_baseline, alg_name, TYPE_OQS_STATELESS, ITERATIONS_LATTICE);

	std::cout << "All tests finished. Results saved to " << output_filename << std::endl;
	std::cout << "Press Enter to exit...";
	std::cin.get();
	return 0;
}