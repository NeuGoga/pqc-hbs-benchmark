#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <numeric>
#include <fstream>
#include <filesystem>

#include <oqs/oqs.h>
#include "sphincs.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

const int TYPE_OQS_STATELESS = 0;
const int TYPE_OQS_STATEFUL = 1;
const int TYPE_CUSTOM = 2;

/*	This function takes a filename and a byte vector,
 *	and writes the contents of the vector to the specified
 *	file in binary mode.
 */
void write_file(const std::string &filename, const std::vector<uint8_t> &data)
{
	std::ofstream file(filename, std::ios::binary);
	file.write(reinterpret_cast<const char *>(data.data()), data.size());
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

/*	This function opens a binary file and reads its contents
 *	into byte vector. If the file cannot be opened, it returns
 *	an empty vector.
 */
std::vector<uint8_t> read_file(const std::string &filename)
{
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	if (!file.is_open())
		return {};
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<uint8_t> buffer(size);
	file.read(reinterpret_cast<char *>(buffer.data()), size);
	return buffer;
}

struct stfl_key_storage
{
	std::vector<uint8_t> key_data;
};

/*	This callback function is requried by liboqs stateful API.
 *	It handles the updated secret key buffer after a signature
 *	is generated
 */
OQS_STATUS my_secure_store_sk(uint8_t *sk_buf, size_t sk_buf_len, void *context)
{
	if (context == NULL)
	{
		return OQS_ERROR;
	}

	stfl_key_storage *storage = static_cast<stfl_key_storage *>(context);

	storage->key_data.assign(sk_buf, sk_buf + sk_buf_len);

	return OQS_SUCCESS;
}

/*	This function gets the pea memory usage of the current process.
 *	It uses Windows Process Memory Counters or Linux rusage.
 *	Returns memory in Kilobytes.
 */
long get_peak_memory_kb()
{
#ifdef _WIN32
	PROCESS_MEMORY_COUNTERS_EX pmc;
	if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc)))
	{
		return pmc.PeakWorkingSetSize / 1024;
	}
	return -1;
#else
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) == 0)
	{
		return usage.ru_maxrss;
	}
	return -1;
#endif
}

/*	This function benchmarks stateless liboqs algorithms.
 *
 *	alg_name:		Name of the algorithm.
 *	mode:			0 for Key Generation, 1 for Signing, 2 for Verification.
 *	iterations:		Number of times to run the operation.
 *	baseline_mem:	Process memory usage before the operation.
 *	pk_file:		Path to read/write the public key.
 *	sk_file:		Path to read/write the secret key.
 *	sig_file:		Path to read/write the signature.
 */
int benchmark_oqs_stateless(const std::string &alg_name, int mode, int iterations, long baseline_mem, const std::string &pk_file, const std::string &sk_file, const std::string &sig_file)
{
	OQS_SIG *sig = OQS_SIG_new(alg_name.c_str());
	if (!sig)
		return 1;

	if (mode == 0)
	{
		std::vector<uint8_t> pk(sig->length_public_key), sk(sig->length_secret_key);
		auto start = std::chrono::high_resolution_clock::now();
		OQS_SIG_keypair(sig, pk.data(), sk.data());
		auto end = std::chrono::high_resolution_clock::now();

		write_file(pk_file, pk);
		write_file(sk_file, sk);
		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) << ","
				  << (get_peak_memory_kb() - baseline_mem) << ","
				  << sig->length_public_key << ","
				  << sig->length_secret_key << ","
				  << sig->length_signature;
	}
	else if (mode == 1)
	{
		std::vector<uint8_t> sk = read_file(sk_file);
		if (sk.empty())
			return 1;
		std::vector<uint8_t> msg(100);
		std::vector<uint8_t> signature(sig->length_signature);
		size_t sig_len;

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			OQS_SIG_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk.data());
		}
		auto end = std::chrono::high_resolution_clock::now();

		write_file(sig_file, signature);
		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
	}
	else if (mode == 2)
	{
		std::vector<uint8_t> pk = read_file(pk_file);
		std::vector<uint8_t> signature = read_file(sig_file);
		if (pk.empty() || signature.empty())
			return 1;
		std::vector<uint8_t> msg(100);

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			OQS_SIG_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pk.data());
		}
		auto end = std::chrono::high_resolution_clock::now();

		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
	}
	OQS_SIG_free(sig);
	return 0;
}

/*	This function benchmarks stateful liboqs algorithms.
 *
 *	alg_name:		Name of the algorithm.
 *	mode:			0 for Key Generation, 1 for Signing, 2 for Verification.
 *	iterations:		Number of times to run the operation.
 *	baseline_mem:	Process memory usage before the operation.
 *	pk_file:		Path to read/write the public key.
 *	sk_file:		Path to read/write the secret key.
 *	sig_file:		Path to read/write the signature.
 */
int benchmark_oqs_stateful(const std::string &alg_name, int mode, int iterations, long baseline_mem, const std::string &pk_file, const std::string &sk_file, const std::string &sig_file)
{
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(alg_name.c_str());
	if (!sig)
		return 1;

	if (mode == 0)
	{
		std::vector<uint8_t> pk(sig->length_public_key);
		OQS_SIG_STFL_SECRET_KEY *sk_obj = OQS_SIG_STFL_SECRET_KEY_new(alg_name.c_str());
		stfl_key_storage store;
		OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk_obj, my_secure_store_sk, &store);

		auto start = std::chrono::high_resolution_clock::now();
		OQS_SIG_STFL_keypair(sig, pk.data(), sk_obj);
		auto end = std::chrono::high_resolution_clock::now();

		write_file(pk_file, pk);

		uint8_t *sk_bytes = nullptr;
		size_t sk_len = 0;
		OQS_SIG_STFL_SECRET_KEY_serialize(&sk_bytes, &sk_len, sk_obj);
		std::vector<uint8_t> sk_vec(sk_bytes, sk_bytes + sk_len);
		write_file(sk_file, sk_vec);
		OQS_MEM_secure_free(sk_bytes, sk_len);

		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) << ","
				  << (get_peak_memory_kb() - baseline_mem) << ","
				  << sig->length_public_key << ","
				  << sk_len << ","
				  << sig->length_signature;
		OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
	}
	else if (mode == 1)
	{
		std::vector<uint8_t> sk_data = read_file(sk_file);
		if (sk_data.empty())
			return 1;

		OQS_SIG_STFL_SECRET_KEY *sk_obj = OQS_SIG_STFL_SECRET_KEY_new(alg_name.c_str());
		stfl_key_storage store;
		OQS_SIG_STFL_SECRET_KEY_SET_store_cb(sk_obj, my_secure_store_sk, &store);
		OQS_SIG_STFL_SECRET_KEY_deserialize(sk_obj, sk_data.data(), sk_data.size(), &store);

		std::vector<uint8_t> msg(100);
		std::vector<uint8_t> signature(sig->length_signature);
		size_t sig_len;

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			OQS_SIG_STFL_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk_obj);
		}
		auto end = std::chrono::high_resolution_clock::now();

		write_file(sig_file, signature);
		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
		OQS_SIG_STFL_SECRET_KEY_free(sk_obj);
	}
	else if (mode == 2)
	{
		std::vector<uint8_t> pk = read_file(pk_file);
		std::vector<uint8_t> signature = read_file(sig_file);
		if (pk.empty() || signature.empty())
			return 1;

		std::vector<uint8_t> msg(100);

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			OQS_SIG_STFL_verify(sig, msg.data(), msg.size(), signature.data(), signature.size(), pk.data());
		}
		auto end = std::chrono::high_resolution_clock::now();

		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
	}
	OQS_SIG_STFL_free(sig);
	return 0;
}

/*	This function benchmarks my SPHINCS+ implementation.
 *
 *	alg_name:		Name of the algorithm.
 *	mode:			0 for Key Generation, 1 for Signing, 2 for Verification.
 *	iterations:		Number of times to run the operation.
 *	baseline_mem:	Process memory usage before the operation.
 *	pk_file:		Path to read/write the public key.
 *	sk_file:		Path to read/write the secret key.
 *	sig_file:		Path to read/write the signature.
 */
int benchmark_custom(const std::string &alg_name, int mode, int iterations, long baseline_mem, const std::string &pk_file, const std::string &sk_file, const std::string &sig_file)
{
	SphexVariant variant;

	if (alg_name == "MY_SPHINCS-128f")
		variant = SphexVariant::SHAKE_128F_SIMPLE;
	else if (alg_name == "MY_SPHINCS-128s")
		variant = SphexVariant::SHAKE_128S_SIMPLE;
	else if (alg_name == "MY_SPHINCS-192f")
		variant = SphexVariant::SHAKE_192F_SIMPLE;
	else if (alg_name == "MY_SPHINCS-192s")
		variant = SphexVariant::SHAKE_192S_SIMPLE;
	else if (alg_name == "MY_SPHINCS-256f")
		variant = SphexVariant::SHAKE_256F_SIMPLE;
	else if (alg_name == "MY_SPHINCS-256s")
		variant = SphexVariant::SHAKE_256S_SIMPLE;
	else
		return 1;

	SphincsPlus sp(variant);

	if (mode == 0)
	{
		std::vector<uint8_t> sk;
		auto start = std::chrono::high_resolution_clock::now();
		std::vector<uint8_t> pk = sp.keygen(sk);
		auto end = std::chrono::high_resolution_clock::now();

		write_file(pk_file, pk);
		write_file(sk_file, sk);

		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) << ","
				  << (get_peak_memory_kb() - baseline_mem) << ","
				  << sp.get_pk_size() << ","
				  << sp.get_sk_size() << ","
				  << sp.get_sig_size();
	}
	else if (mode == 1)
	{
		std::vector<uint8_t> sk = read_file(sk_file);
		std::vector<uint8_t> msg(100, 0);
		std::vector<uint8_t> signature;

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			signature = sp.sign(msg, sk);
			if (signature.empty())
			{
				std::cout << "Signature empty" << std::endl;
			}
		}
		auto end = std::chrono::high_resolution_clock::now();

		write_file(sig_file, signature);
		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
	}
	else if (mode == 2)
	{
		std::vector<uint8_t> pk = read_file(pk_file);
		std::vector<uint8_t> signature = read_file(sig_file);
		std::vector<uint8_t> msg(100, 0);

		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < iterations; i++)
		{
			sp.verify(msg, signature, pk);
		}
		auto end = std::chrono::high_resolution_clock::now();

		std::cout << (double)(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()) / iterations << ","
				  << (get_peak_memory_kb() - baseline_mem);
	}
	return 0;
}

/*	Main function.
 *
 *	Arguments:
 *	argv[1] (Algorithm name):	Sting name of the algorithm.
 *	argv[2] (Type):				The type of the algorithm (0 = OQS stateless, 1 = OQS stateful, 2 = Custom).
 *	argv[3] (Mode):				The operation to perform (0 = keygen, 1 = sign, 2 = verify).
 *	argv[4] (Iterations):		The number of times to perfomr operation.
 *	argv[5]	(Baseline):			Flag to use baseline memory (0 = absolute memory, 1 = substract baseline memory).
 */
int main(int argc, char *argv[])
{
	if (argc < 6)
		return 1;

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
	{
		return benchmark_oqs_stateless(alg_name, mode, iterations, baseline_mem, pk_file, sk_file, sig_file);
	}
	else if (algo_type == TYPE_OQS_STATEFUL)
	{
		return benchmark_oqs_stateful(alg_name, mode, iterations, baseline_mem, pk_file, sk_file, sig_file);
	}
	else if (algo_type == TYPE_CUSTOM)
	{
		return benchmark_custom(alg_name, mode, iterations, baseline_mem, pk_file, sk_file, sig_file);
	}

	return 1;
}