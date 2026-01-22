#include "sphincs.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <stdexcept>

// CSPRNG

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fstream>
    #include <iostream>
#endif

bool generate_random_bytes(std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return true;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer.data(), (ULONG)buffer.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        std::cerr << "CSPRNG Error (Windows): BCryptGenRandom failed with status " << std::hex << status << std::endl;
        return false;
    }
    return true;
#else
    std::ifstream urandom("dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom) {
        std::cerr << "CSPRNG Error (Unix): Could not open /dev/urandom.\n";
        return false;
    }
    urandom.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    if (!urandom) {
        std::cerr << "CSPRNG Error (Unix): Could not read enough bytes form /dev/urandom.\n";
        return false;
    }
    return true;
#endif
}

// KECCAK and SHAKE256 implementations

class Keccak 
{
private:
    uint64_t state[25];
    const int rate = 136;

    uint64_t rotl(uint64_t x, int s) {
        return (x << s) | (x >> (64 - s));
    }

    void keccak_f1600() {
        static const uint64_t RC[24] = {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        static const int r[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        static const int pi[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        };

        for (int round = 0; round < 24; round++) {
            uint64_t C[5], D[5];
            for (int i = 0; i < 5; i++) C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            for (int i = 0; i < 5; i++) D[i] = C[(i + 4) % 5] ^ rotl(C[(i + 1) % 5], 1);
            for (int i = 0; i < 5; i++) state[i] ^= D[i % 5];

            uint64_t current = state[1], temp;
            for (int i = 0; i < 24; i++) {
                int j = pi[i];
                temp = state[j];
                state[j] = rotl(current, r[i]);
                current = temp;
            }

            for (int j = 0; j < 25; j += 5) {
                uint64_t t[5];
                for (int i = 0; i < 5; i++)
                    t[i] = state[j + 1];
                for (int i = 0; i < 5; i++)
                    state[j + 1] ^= (~t[(i + 5) % 5]) & t[(i + 2) % 5];
            }
            state[0] ^= RC[round];
        }
    }

public:
    Keccak() { std::memset(state, 0, sizeof(state)); }

    static void shake256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
        Keccak k;
        size_t in_off = 0;
        size_t n = input.size();

        while (n >= k.rate) {
            for (int i = 0; i < k.rate; i++) k.state[i / 8] ^= (uint64_t)input[in_off + i] << (8 * (i % 8));
            k.keccak_f1600();
            in_off += k.rate;
            n -= k.rate;
        }

        for (size_t i = 0; i < n; i++) k.state[i / 8] ^= (uint64_t)input[in_off + i] << (8 * (i % 8));
        k.state[n / 8] ^= (uint64_t)0x1F << (8 * (n % 8));
        k.state[(k.rate - 1) / 8] ^= (uint64_t)0x80 << (56);
        k.keccak_f1600();

        size_t out_len = output.size();
        size_t out_off = 0;
        while (out_len > 0) {
            size_t chunk = (out_len < k.rate) ? out_len : k.rate;
            for (size_t i = 0; i < chunk; i++) output[out_off + i] = (k.state[i / 8] >> (8 * (i % 8))) & 0xFF;
            out_off += chunk;
            out_len -= chunk;
            if (out_len > 0) k.keccak_f1600();
        }
    }
};

// Parameters and address

struct SphincsPlus::Params
{
    int N; int W; int H; int D; int A; int K;
    int H_PRIME; int WOTS_LEN;

    Params(SphexVariant v) {
        W = 16;
        switch(v) {
            // fast versions
            case SphexVariant::SHAKE_128F_SIMPLE:
                N = 16; H = 66; D = 22; A = 6; K = 33; break;
            case SphexVariant::SHAKE_192F_SIMPLE:
                N = 24; H = 66; D = 22; A = 8; K = 33; break;
            case SphexVariant::SHAKE_256F_SIMPLE:
                N = 32; H = 68; D = 17; A = 9; K = 35; break;

            // small versions
            case SphexVariant::SHAKE_128S_SIMPLE:
                N = 16; H = 63; D = 7; A = 12; K = 14; break;
            case SphexVariant::SHAKE_192S_SIMPLE:
                N = 24; H = 63; D = 7; A = 14; K = 17; break;
            case SphexVariant::SHAKE_256S_SIMPLE:
                N = 32; H = 64; D = 8; A = 14; K = 22; break;
        }

        H_PRIME = H / D;

        // WOTS length calculation
        int len1 = (8 * N) / 4;
        int len2 = 0;
        int csum = len1 * (W - 1);
        while (csum > 0) { csum >>= 4; len2++; }
        WOTS_LEN = len1 + len2;
    }
};

using Bytes = std::vector<uint8_t>;

struct Address
{
    uint32_t words[8];
    Address() { memset(words, 0, sizeof(words)); }
    void set_layer(uint32_t l) { words[0] = l; }
    void set_tree(uint64_t t) { words[1] = (uint32_t)(t >> 32); words[2] = (uint32_t)t; }
    void set_type(uint32_t t) { words[3] = t; }
    void set_keypair(uint32_t k) { words[5] = k; }
    void set_chain(uint32_t c) { words[6] = c; }
    void set_hash(uint32_t h) { words[7] = h; }
    void set_tree_height(uint32_t h) { words[6] = h; }
    void set_tree_index(uint32_t i) { words[7] = i; }
    Bytes to_bytes() const {
        Bytes out(32);
        for (int i = 0; i < 8; i++) {
            out[i * 4] = words[i] >> 24; out[i * 4 + 1] = words[i] >> 16;
            out[i * 4 + 2] = words[i] >> 8; out[i * 4 + 3] = words[i];
        }
        return out;
    }
};

// Helper functions

Bytes thash(const Bytes& in, const Bytes& pub_seed, const Address& addr, int N) {
    Bytes buf; buf.reserve(pub_seed.size() + 32 + in.size());
    buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
    Bytes a = addr.to_bytes();
    buf.insert(buf.end(), a.begin(), a.end());
    buf.insert(buf.end(), in.begin(), in.end());
    Bytes out(N);
    Keccak::shake256(buf, out);
    return out;
}

// pseudo-random function
Bytes prf(const Bytes& seed, const Address& addr, int N) {
    Bytes buf; buf.reserve(seed.size() + 32);
    buf.insert(buf.end(), seed.begin(), seed.end());
    Bytes a = addr.to_bytes();
    buf.insert(buf.end(), a.begin(), a.end());
    Bytes out(N);
    Keccak::shake256(buf, out);
    return out;
}

// Treehash and merkle gen

// recursive function to find the root of a subtree
Bytes compute_root(const Bytes& sk_seed, const Bytes& pub_seed, Address addr,
                    int N, uint32_t leaf_idx, int height) {
    if (height == 0) {
        addr.set_tree_index(leaf_idx);
        Bytes sk = prf(sk_seed, addr, N);
        addr.set_type(4);
        return thash(sk, pub_seed, addr, N);
    }
    // left
    addr.set_tree_height(height - 1);
    Bytes left = compute_root(sk_seed, pub_seed, addr, N, leaf_idx, height - 1);

    //right
    addr.set_tree_index(leaf_idx + (1 << (height - 1)));
    Bytes right = compute_root(sk_seed, pub_seed, addr, N, leaf_idx + (1 << (height - 1)), height - 1);

    //hash together
    addr.set_tree_height(height);
    addr.set_tree_index(leaf_idx >> height);
    Bytes combined = left;
    combined.insert(combined.end(), right.begin(), right.end());
    return thash(combined, pub_seed, addr, N);
}

Bytes compute_root_from_path(const Bytes& leaf, uint32_t leaf_idx, const std::vector<Bytes>& auth_path,
                            const Bytes& pub_seed, Address addr, int N) {
    Bytes current_node = leaf;

    uint32_t current_height = addr.words[6];

    for (const auto& neighbor_node : auth_path) {
        current_height++;
        addr.set_tree_height(current_height);

        Bytes left, right;
        if (leaf_idx & 1) {
            left = neighbor_node;
            right = current_node;
        } else {
            left = current_node;
            right = neighbor_node;
        }

        addr.set_tree_index(leaf_idx >> 1);

        Bytes combined = left;
        combined.insert(combined.end(), right.begin(), right.end());
        current_node = thash(combined, pub_seed, addr, N);

        leaf_idx >>= 1;
    }
    return current_node;    
}

Bytes fors_pk_from_sig(const Bytes& sig, const Bytes& msg_digest, const Bytes& pub_seed, 
                        Address addr, SphincsPlus::Params* p) {
    Bytes fors_pk_values;
    int sig_offset = 0;

    for (int i = 0; i < p->K; i++) {
        uint32_t actual_fors_idx = (uint32_t)(msg_digest[i % msg_digest.size()] & ((1 << p->A) - 1));

        Bytes sk(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
        sig_offset += p->N;

        Address leaf_addr = addr;
        leaf_addr.set_keypair(i);
        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(actual_fors_idx);
        leaf_addr.set_type(4);

        Bytes leaf = thash(sk, pub_seed, leaf_addr, p->N);

        std::vector<Bytes> path;
        for (int j = 0; j < p->A; j++) {
            Bytes node(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
            path.push_back(node);
            sig_offset += p->N;
        }

        Address tree_addr = addr;
        tree_addr.set_keypair(i);
        tree_addr.set_tree_height(0);
        tree_addr.set_type(4);

        Bytes tree_root = compute_root_from_path(leaf, actual_fors_idx, path, pub_seed, tree_addr, p->N);
        fors_pk_values.insert(fors_pk_values.end(), tree_root.begin(), tree_root.end());
    }
    Address root_addr = addr;
    root_addr.set_type(3);
    return thash(fors_pk_values, pub_seed, root_addr, p->N);
}

std::vector<Bytes> gen_auth_path(const Bytes& sk_seed, const Bytes& pub_seed, Address addr,
                                int N, uint32_t leaf_idx, int h_total) {
    std::vector<Bytes> path;
    for (int h = 0; h < h_total; h++) {
        uint32_t neighbour_idx = (leaf_idx >> h) ^ 1;
        uint32_t base_leaf = neighbour_idx << h;

        Address node_addr = addr;
        node_addr.set_tree_height(h);
        Bytes node = compute_root(sk_seed, pub_seed, addr, N, base_leaf, h);
        path.push_back(node);
    }
    return path;
}

// class implementation

SphincsPlus::SphincsPlus(SphexVariant variant) {
    p = new Params(variant);
}

SphincsPlus::~SphincsPlus() {
    delete p;
}

Bytes gen_chain(Bytes in, int start, int steps, const Bytes& pub_seed, Address addr, int N) {
    for (int i = start; i < start + steps; i++) {
        addr.set_hash(i);
        in = thash(in, pub_seed, addr, N);
    }
    return in;
}

Bytes wots_sign(const Bytes& msg, const Bytes& sk_seed, const Bytes& pub_seed,
                Address addr, SphincsPlus::Params* p) {
    std::vector<int> lens;
    int total = 0;
    for (auto b : msg) {
        lens.push_back(b >> 4);
        lens.push_back(b & 0xF);
        total += (p->W - 1) - (b >> 4);
        total += (p->W - 1) - (b & 0xF);
    }

    // checksum
    int csum_val = total;
    int len2 = p->WOTS_LEN - (2 * p->N);

    for (int i = 0; i < len2; i++) {
        lens.push_back(csum_val & (p->W - 1));
        csum_val >>= 4;
    }

    Address sk_addr = addr;
    sk_addr.set_type(1);

    Bytes sig;
    for (int i = 0; i < p->WOTS_LEN; i++) {
        sk_addr.set_chain(i);
        sk_addr.set_hash(0);
        Bytes sk_component = prf(sk_seed, sk_addr, p->N);
        Bytes sig_part = gen_chain(sk_component, 0, lens[i], pub_seed, sk_addr, p->N);
        sig.insert(sig.end(), sig_part.begin(), sig_part.end());
    }
    return sig;
}

Bytes wots_pk_from_sig(const Bytes& sig, const Bytes& msg, const Bytes& pub_seed,
                Address addr, SphincsPlus::Params* p) {
    std::vector<int> lens;
    int total = 0;
    
    for (auto b : msg) {
        lens.push_back(b >> 4);
        lens.push_back(b & 0xF);
        total += (p->W - 1) - (b >> 4);
        total += (p->W - 1) - (b & 0xF);
    }

    int csum_val = total;
    int len2 = p->WOTS_LEN - (2 * p->N);

    for (int i = 0; i < len2; i++) {
        lens.push_back(csum_val & (p->W - 1));
        csum_val >>= 4;
    }

    Address sk_addr = addr;
    sk_addr.set_type(1);

    Bytes pk_accum;
    int sig_offset = 0;

    for (int i = 0; i < p->WOTS_LEN; i++) {
        sk_addr.set_chain(i);
        Bytes sig_part(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
        sig_offset += p->N;

        Bytes leaf = gen_chain(sig_part, lens[i], (p->W - 1) - lens[i], pub_seed, sk_addr, p->N);
        pk_accum.insert(pk_accum.end(), leaf.begin(), leaf.end());
    }

    Address pk_addr = addr;
    pk_addr.set_type(2);
    return thash(pk_accum, pub_seed, pk_addr, p->N);
}

std::vector<uint8_t> SphincsPlus::keygen(std::vector<uint8_t>& sk_out) {
    Bytes sk_seed(p->N);
    Bytes sk_prf(p->N);
    Bytes pub_seed(p->N);

    if(!generate_random_bytes(sk_seed) ||
        !generate_random_bytes(sk_prf) ||
        !generate_random_bytes(pub_seed)) {
            std::cerr << "Error: Failed to CSPRNG.\n";
            sk_out.clear();
            return {};
        }
    
    Address addr;
    addr.set_layer(p->D - 1);
    Bytes root = compute_root(sk_seed, pub_seed, addr, p->N, 0, p->H_PRIME);

    sk_out = sk_seed;
    sk_out.insert(sk_out.end(), sk_prf.begin(), sk_prf.end());
    sk_out.insert(sk_out.end(), pub_seed.begin(), pub_seed.end());
    sk_out.insert(sk_out.end(), root.begin(), root.end());

    Bytes pk = pub_seed;
    pk.insert(pk.end(), root.begin(), root.end());
    return pk;
}

std::vector<uint8_t> SphincsPlus::sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk) {
    Bytes sk_seed(sk.begin(), sk.begin() + p->N);
    Bytes sk_prf(sk.begin() + p->N, sk.begin() + 2 * p->N);
    Bytes pub_seed(sk.begin() + 2 * p->N, sk.begin() + 3 * p->N);
    Bytes pk_root(sk.begin() + 3 * p->N, sk.end());

    Bytes R(p->N);
    if (!generate_random_bytes(R)) {
        std::cerr << "Error: Failed to CSPRNG for R. \n";
        return {};
    }

    Bytes buf_for_digest = R;

    buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
    buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
    buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());
    
    int msg_digest_len_bits = p->K * p->A + p->H + p->H_PRIME;
    int msg_digest_len_bytes = (msg_digest_len_bits + 7) / 8;
    if (msg_digest_len_bytes < p->N) msg_digest_len_bytes = p->N;

    Bytes msg_digest_full(msg_digest_len_bytes);
    Keccak::shake256(buf_for_digest, msg_digest_full);

    Bytes fors_msg_digest(msg_digest_full.begin(), msg_digest_full.begin() + p->N);

    Bytes signature;
    signature.insert(signature.end(), R.begin(), R.end());

    Address fors_addr;
    fors_addr.set_type(3);

    Bytes fors_pk_value;
    for(int i = 0; i < p->K; i++) {
        uint32_t actual_fors_idx = (uint32_t)(fors_msg_digest[i % fors_msg_digest.size()] & ((1 << p->A) -1));

        Address fors_leaf_addr = fors_addr;
        fors_leaf_addr.set_keypair(i);
        fors_leaf_addr.set_tree_height(0);
        fors_leaf_addr.set_tree_index(actual_fors_idx);

        Bytes sk_leaf = prf(sk_seed, fors_leaf_addr, p->N);
        signature.insert(signature.end(), sk_leaf.begin(), sk_leaf.end());

        auto path = gen_auth_path(sk_seed, pub_seed, fors_leaf_addr, p->N, actual_fors_idx, p->A);
        for (auto& node : path) {
            signature.insert(signature.end(), node.begin(), node.end());
        }

        Bytes tree_root = compute_root(sk_seed, pub_seed, fors_leaf_addr, p->N, 0, p->A);
        fors_pk_value.insert(fors_pk_value.end(), tree_root.begin(), tree_root.end());
    }
    Bytes fors_root = thash(fors_pk_value, pub_seed, fors_addr, p->N);

    Bytes current_message_for_tree = fors_root;

    for (int i = 0; i < p->D; i++) {
        Address ht_addr;
        ht_addr.set_layer(i);

        ht_addr.set_tree(0);

        Bytes wots_sig = wots_sign(current_message_for_tree, sk_seed, pub_seed, ht_addr, p);
        signature.insert(signature.end(), wots_sig.begin(), wots_sig.end());

        uint32_t leaf_idx_in_tree = 0;
        
        auto path = gen_auth_path(sk_seed, pub_seed, ht_addr, p->N, leaf_idx_in_tree, p->H_PRIME);
        for (auto& node : path) signature.insert(signature.end(), node.begin(), node.end());

        current_message_for_tree = compute_root(sk_seed, pub_seed, ht_addr, p->N, leaf_idx_in_tree, p->H_PRIME);
    }
    return signature;
}

bool SphincsPlus::verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk) {
    if (sig.size() != get_sig_size()) return false;

    Bytes pub_seed(pk.begin(), pk.begin() + p->N);
    Bytes pk_root(pk.begin() + p->N, pk.end());
    
    Bytes R(sig.begin(), sig.begin() + p->N);

    Bytes buf_for_digest = R;
    buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
    buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
    buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());
    
    int msg_digest_len_bits = p->K * p->A + p->H + p->H_PRIME;
    int msg_digest_len_bytes = (msg_digest_len_bits + 7) / 8;
    if (msg_digest_len_bytes < p->N) msg_digest_len_bytes = p->N;

    Bytes msg_digest_full(msg_digest_len_bytes);
    Keccak::shake256(buf_for_digest, msg_digest_full);

    Bytes fors_msg_digest(msg_digest_full.begin(), msg_digest_full.begin() + p->N);

    int sig_offset = p->N;

    size_t fors_sig_len = p->K * (p->N + p->A * p->N);
    Bytes fors_sig(sig.begin() + sig_offset, sig.begin() + sig_offset + fors_sig_len);
    sig_offset += fors_sig_len;

    Address fors_addr;
    fors_addr.set_type(3);

    Bytes fors_root = fors_pk_from_sig(fors_sig, fors_msg_digest, pub_seed, fors_addr, p);
    Bytes current_root = fors_root;

    for (int i = 0; i < p->D; i++) {
        Address ht_addr;
        ht_addr.set_layer(i);
        ht_addr.set_tree(0);

        size_t wots_len = p->WOTS_LEN * p->N;
        Bytes wots_sig(sig.begin() + sig_offset, sig.begin() + sig_offset + wots_len);
        sig_offset += wots_len;

        Bytes wots_pk = wots_pk_from_sig(wots_sig, current_root, pub_seed, ht_addr, p);

        std::vector<Bytes> path;
        for (int j = 0; j < p->H_PRIME; j++) {
            Bytes node(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
            path.push_back(node);
            sig_offset += p->N;
        }

        uint32_t leaf_idx = 0;

        Address tree_addr = ht_addr;
        tree_addr.set_type(4);
        tree_addr.set_tree_height(0);

        current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed, tree_addr, p->N);
    }
    return (current_root == pk_root);
}

size_t SphincsPlus::get_pk_size() const { return 2 * p->N; }
size_t SphincsPlus::get_sk_size() const { return 4 * p->N; }
size_t SphincsPlus::get_sig_size() const {
    size_t fors_sig_size = p->K * (p->N + p->A * p->N);
    size_t ht_sig_size = p->D * (p->WOTS_LEN * p->N + p->H_PRIME * p->N);
    return p->N + fors_sig_size + ht_sig_size;
}
