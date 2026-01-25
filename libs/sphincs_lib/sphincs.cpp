#include "sphincs.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <stdexcept>

// Constants for Address types (FIPS 205)
const uint32_t ADDR_TYPE_WOTS = 0;
const uint32_t ADDR_TYPE_WOTS_PK = 1;
const uint32_t ADDR_TYPE_TREE = 2;
const uint32_t ADDR_TYPE_FORS_TREE = 3;
const uint32_t ADDR_TYPE_FORS_PK = 4;

// CSPRNG

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fstream>
    #include <iostream>
    #include <string.h>
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
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
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

void secure_wipe(std::vector<uint8_t>& data) {
    if (data.empty()) return;

#ifdef _WIN32
    SecureZeroMemory(data.data(), data.size());
#else
    volatile uint8_t* p = data.data();
    size_t len = data.size();
    while (len--) *p++ = 0;
#endif
    data.clear();
}

// KECCAK and SHAKE256 implementations

class Keccak 
{
private:
    uint64_t state[25];
    uint8_t buffer[136];
    int buf_off;
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

        static const int rho[24] = {
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
                state[j] = rotl(current, rho[i]);
                current = temp;
            }

            for (int j = 0; j < 25; j += 5) {
                uint64_t t[5];
                for (int i = 0; i < 5; i++)
                    t[i] = state[j + i];
                for (int i = 0; i < 5; i++)
                    state[j + i] ^= (~t[(i + 5) % 5]) & t[(i + 2) % 5];
            }
            state[0] ^= RC[round];
        }
    }

public:
    Keccak() { 
        std::memset(state, 0, sizeof(state)); 
        std::memset(buffer, 0, sizeof(buffer));
        buf_off = 0;
    }

    void absorb(const std::vector<uint8_t>& in) {
        for (uint8_t b : in) {
            buffer[buf_off++] = b;
            if (buf_off == rate) {
                for (int i = 0; i < rate / 8; i++) {
                    uint64_t lane = 0;
                    for (int k = 0; k < 8; k++) lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
                    state[i] ^= lane;
                }
                keccak_f1600();
                buf_off = 0;
            }
        }
    }

    void finalize_and_squeeze(std::vector<uint8_t>& out) {
        buffer[buf_off++] = 0x1F;
        while (buf_off < rate) buffer[buf_off++] = 0;
        buffer[rate - 1] ^= 0x80;

        for (int i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int k = 0; k < 8; k++) lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
            state[i] ^= lane;
        }
        keccak_f1600();

        size_t out_len = out.size();
        size_t out_off = 0;

        while (out_len > 0) {
            size_t chunk = (out_len < (size_t)rate) ? out_len : (size_t)rate;
            for (size_t i = 0; i < chunk; i++) {
                out[out_off + i] = (uint8_t)((state[i / 8] >> (8 * (i % 8))) & 0xFF);
            }
            out_off += chunk;
            out_len -= chunk;
            if (out_len > 0) keccak_f1600();
        }
    }

    static void shake256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output) {
        Keccak k;
        k.absorb(input);
        k.finalize_and_squeeze(output);
    }
};

// Parameters and address

struct SphincsPlus::Params
{
    int N; int W; int H; int D; int A; int K;
    int H_PRIME; int WOTS_LEN;
    int len1;
    int len2;

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
            default: throw std::invalid_argument("Unknown Variant");
        }

        H_PRIME = H / D;

        // FIPS 205 WOTS+ len math
        int log_w = 0;
        while ((1 << log_w) < W) ++log_w;

        this->len1 = (8 * N + log_w - 1) / log_w;

        uint64_t csum_max = (uint64_t)this->len1 * (W - 1);
        int csum_bits = 0;
        while (csum_max ) { csum_max >>= 1; csum_bits++; }

        this->len2 = (csum_bits + log_w - 1) / log_w;
        this->WOTS_LEN = this->len1 + this->len2;
    }
};

using Bytes = std::vector<uint8_t>;

struct Address
{
    uint32_t words[8];
    Address() { memset(words, 0, sizeof(words)); }
    
    // layer address
    void set_layer(uint32_t l) { words[0] = l; }

    // tree address
    void set_tree(uint64_t t) { 
        words[1] = (uint32_t)(t >> 32); 
        words[2] = (uint32_t)t; 
    }

    // type
    void set_type(uint32_t t) { words[3] = t; }
    
    // FORS / Tree Address (type 3 , 2)
    // height is byte 28
    void set_tree_height(uint32_t h) { words[7] = (words[7] & 0x00FFFFFFu) | ((h & 0xFF) << 24); }

    // index is byte 29-31
    void set_tree_index(uint32_t i) { words[7] = (words[7] & 0xFF000000u) | (i & 0x00FFFFFFu); }

    // WOTS Keypair
    void set_keypair(uint32_t k) { words[4] = k; }
    void set_chain(uint32_t c) { words[5] = c; }
    void set_hash(uint32_t h) { words[6] = h; }

    void sanitize_for_role(uint32_t role) {
        if (role == ADDR_TYPE_WOTS || role == ADDR_TYPE_WOTS_PK) {
            words[7] = 0;
        } else if (role == ADDR_TYPE_TREE || role == ADDR_TYPE_FORS_TREE) {
            words[4] = words[5] = words[6] = 0;
        }

        set_type(role);
    }

    Bytes to_bytes() const {
        Bytes out(32);
        for (int i = 0; i < 8; i++) {
            out[i * 4 + 0] = (words[i] >> 24) & 0xFF;
            out[i * 4 + 1] = (words[i] >> 16) & 0xFF;
            out[i * 4 + 2] = (words[i] >> 8) & 0xFF;
            out[i * 4 + 3] = (words[i] >> 0) & 0xFF;
        }
        return out;
    }
};

// Helper functions

Bytes extract_bytes(const std::vector<uint8_t>& src, size_t& offset, size_t len) {
    if (offset + len > src.size()) {
        throw std::runtime_error("Signature too short");
    }
    Bytes out(src.begin() + offset, src.begin() + offset + len);
    offset += len;
    return out;
}

Bytes thash(const Bytes& in, const Bytes& pub_seed, const Address& addr, int N) {
    Keccak k;
    k.absorb(pub_seed);
    k.absorb(addr.to_bytes());
    k.absorb(in);
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

// pseudo-random function
Bytes prf(const Bytes& seed, const Address& addr, int N) {
    Keccak k;
    k.absorb(seed);
    k.absorb(addr.to_bytes());
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

// deterministic R generation
Bytes prf_msg(const Bytes& sk_prf, const Bytes& optrand, const Bytes& msg, int N) {
    Keccak k;
    k.absorb(sk_prf);
    k.absorb(optrand);
    k.absorb(msg);
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

Bytes gen_chain(Bytes in, int start, int steps, const Bytes& pub_seed, Address addr, int N) {
    for (int i = start; i < start + steps; i++) {
        addr.set_hash(i);
        in = thash(in, pub_seed, addr, N);
    }
    return in;
}


Bytes wots_chain(const Bytes& in, int start, int steps, const Bytes& pub_seed, Address& addr, int N) {
    Bytes out = in;
    for (int i = start; i < start + steps; i++) {
        addr.set_hash(i);
        out = thash(out, pub_seed, addr, N);
    }
    return out;
}

Bytes wots_pkgen(const Bytes& sk_seed, const Bytes& pub_seed, Address addr, SphincsPlus::Params* p) {
    addr.set_type(ADDR_TYPE_WOTS);
    addr.set_hash(0);

    Bytes pk_accum;

    pk_accum.reserve(p->WOTS_LEN * p->N);

    for (int i = 0; i < p->WOTS_LEN; i++) {
        addr.set_chain(i);

        Bytes sk = prf(sk_seed, addr, p->N);

        Bytes leaf = gen_chain(sk, 0, p->W - 1, pub_seed, addr, p->N);

        pk_accum.insert(pk_accum.end(), leaf.begin(), leaf.end());

        secure_wipe(sk);
    }

    uint32_t original_keypair = addr.words[4];
    addr.set_type(ADDR_TYPE_WOTS_PK);
    addr.set_keypair(original_keypair);

    return thash(pk_accum, pub_seed, addr, p->N);
}

// Treehash and merkle gen
struct StackNodeAuth {
    Bytes node;
    int height;
    uint32_t start_idx;
};

Bytes treehash_authpath(const Bytes& sk_seed, const Bytes& pub_seed, Address addr,
                        int N, uint32_t start_idx, uint32_t target_leaf_idx,
                        int tree_height, SphincsPlus::Params* p, std::vector<Bytes>* auth_path) {
    std::vector<StackNodeAuth> stack;
    stack.reserve(tree_height + 1);

    uint32_t leaves = 1u << tree_height;

    if (auth_path) {
        auth_path->assign(tree_height, Bytes());
    }

    for (uint32_t i = 0; i < leaves; ++i) {
        uint32_t idx = start_idx + i;

        Address leaf_addr = addr;


        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(idx);

        Bytes node;
        if (addr.words[3] == ADDR_TYPE_TREE) {
            Address wots_addr = leaf_addr;
            wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);
            wots_addr.set_keypair(idx);
            node = wots_pkgen(sk_seed, pub_seed, wots_addr, p);
        } else {
            Bytes sk_leaf = prf(sk_seed, leaf_addr, N);
            node = thash(sk_leaf, pub_seed, leaf_addr, N);
            secure_wipe(sk_leaf);
        }

        StackNodeAuth cur{ node, 0 , idx };

        while (!stack.empty() && stack.back().height == cur.height) {
            StackNodeAuth left = stack.back();
            stack.pop_back();
            StackNodeAuth right = cur;


            if (auth_path) {
                uint32_t current_subtree_size = 1u << left.height;
                uint32_t relative_idx = target_leaf_idx - left.start_idx;

                if (relative_idx < current_subtree_size) {
                    (*auth_path)[left.height] = right.node;
                } else if (relative_idx < (2 * current_subtree_size)) {
                    (*auth_path)[right.height] = left.node;
                }
            }

            Address parent_addr = addr;
            parent_addr.set_tree_height(left.height + 1);
            parent_addr.set_tree_index(left.start_idx >> (left.height + 1));

            Bytes combined = left.node;
            combined.insert(combined.end(), right.node.begin(), right.node.end());
            Bytes parent = thash(combined, pub_seed, parent_addr, N);

            cur.node = parent;
            cur.height = left.height + 1;
            cur.start_idx = left.start_idx;
        }
        stack.push_back(cur);
    }

    if (stack.empty()) return Bytes();
    return stack.back().node;
}


struct StackNode {
    Bytes node;
    int height;
};

Bytes compute_root(const Bytes& sk_seed, const Bytes& pub_seed, Address addr,
                    int N, uint32_t idx_offset, int height, SphincsPlus::Params* p) {
    std::vector<StackNode> stack;
    stack.reserve(height + 1);

    uint32_t leaves = 1 << height;

    bool is_hypertree = (addr.words[3] == ADDR_TYPE_TREE);
    
    for (uint32_t i = 0; i < leaves; i++) {
        Address leaf_addr = addr;
        uint32_t current_idx = idx_offset + i;

        Bytes node;
        
        if (is_hypertree) {
            leaf_addr.set_keypair(current_idx);
            node = wots_pkgen(sk_seed, pub_seed, leaf_addr, p);
        } else {
            leaf_addr.set_tree_height(0);
            leaf_addr.set_tree_index(current_idx);

            Bytes sk_leaf = prf(sk_seed, leaf_addr, N);
            node = thash(sk_leaf, pub_seed, leaf_addr, N);
            secure_wipe(sk_leaf);
        }

        int h = 0;

        while (!stack.empty() && stack.back().height == h) {
            Bytes right = node;
            Bytes left = stack.back().node;
            stack.pop_back();

            Address parent_addr = addr;
            parent_addr.set_tree_height(h + 1);
            parent_addr.set_tree_index(current_idx >> (h + 1));

            Bytes combined = left;
            combined.insert(combined.end(), right.begin(), right.end());

            node = thash(combined, pub_seed, parent_addr, N);
            h++;
        }
        stack.push_back({node, h});
    }
    return stack.back().node;
}

Bytes compute_root_from_path(const Bytes& leaf, uint32_t leaf_idx, const std::vector<Bytes>& auth_path,
                            const Bytes& pub_seed, Address addr, int N) {
    Bytes current_node = leaf;

    for (size_t h = 0; h < auth_path.size(); ++h) {
        addr.set_tree_height(h + 1);
        addr.set_tree_index(leaf_idx >> 1);

        Bytes left, right;
        if (leaf_idx & 1) {
            left = auth_path[h];
            right = current_node;
        } else {
            left = current_node;
            right = auth_path[h];
        }

        Bytes combined = left;
        combined.insert(combined.end(), right.begin(), right.end());
        current_node = thash(combined, pub_seed, addr, N);

        leaf_idx >>= 1;
    }
    return current_node;    
}

uint64_t get_bits_from_stream(const std::vector<uint8_t>& bytes, size_t bit_offset, int num_bits) {
    if (num_bits == 0) return 0;

    uint64_t out = 0;
    for (int i = 0; i < num_bits; ++i) {
        size_t bit_pos = bit_offset + i;
        size_t byte_idx = bit_pos / 8;
        if (byte_idx >= bytes.size()) return out << (num_bits - i);

        int bit_in_byte = 7 - (bit_pos % 8);
        uint8_t bit = (bytes[byte_idx] >> bit_in_byte) & 1;
        out = (out << 1) | bit;
    }
    return out;
}

std::vector<uint32_t> base_w(const std::vector<uint8_t>& in, int w, int out_len) {
    int log_w = 0;
    while ((1 << log_w) < w) ++log_w;

    std::vector<uint32_t> out;
    out.reserve(out_len);

    size_t bit_cursor = 0;
    for (int i = 0; i < out_len; ++i) {
        uint32_t val = (uint32_t)get_bits_from_stream(in, bit_cursor, log_w);
        out.push_back(val);
        bit_cursor += log_w;
    }
    return out;
}

Bytes fors_pk_from_sig(const Bytes& sig, size_t& sig_offset, const Bytes& msg_digest, const Bytes& pub_seed, 
                        Address addr, SphincsPlus::Params* p) {
    Bytes fors_pk_values;

    size_t bit_cursor = 0;

    for (int i = 0; i < p->K; i++) {
        uint32_t actual_fors_idx = (uint32_t)get_bits_from_stream(msg_digest, bit_cursor, p->A);
        bit_cursor += p->A;

        Bytes sk = extract_bytes(sig, sig_offset, p->N);

        Address leaf_addr = addr;
        leaf_addr.set_type(ADDR_TYPE_FORS_TREE);
        leaf_addr.set_keypair(i);
        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(actual_fors_idx);

        Bytes leaf = thash(sk, pub_seed, leaf_addr, p->N);

        std::vector<Bytes> path;
        for (int j = 0; j < p->A; j++) {
            path.push_back(extract_bytes(sig, sig_offset, p->N));
        }

        Address tree_addr = addr;
        tree_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
        tree_addr.set_keypair(i);

        Bytes tree_root = compute_root_from_path(leaf, actual_fors_idx, path, pub_seed, tree_addr, p->N);
        fors_pk_values.insert(fors_pk_values.end(), tree_root.begin(), tree_root.end());
    }
    Address root_addr = addr;
    root_addr.set_type(ADDR_TYPE_FORS_PK);
    root_addr.set_keypair(0);
    return thash(fors_pk_values, pub_seed, root_addr, p->N);
}

std::vector<Bytes> gen_auth_path(const Bytes& sk_seed, const Bytes& pub_seed, Address addr,
                                int N, uint32_t leaf_idx, int h_total, SphincsPlus::Params* p) {
    std::vector<Bytes> auth;

    uint32_t start = 0;
    treehash_authpath(sk_seed, pub_seed, addr, N, start, leaf_idx, h_total, p, &auth);
    return auth;
}

static std::vector<uint32_t> compute_wots_digits(const Bytes &msg_hash, SphincsPlus::Params* p) {
    int log_w = 0;
    while ((1 << log_w) < p->W) ++log_w;
    
    int len1 = p->len1;
    int len2 = p->len2;

    std::vector<uint32_t> digits = base_w(msg_hash, p->W, len1);

    uint64_t csum = 0;
    for (uint32_t v : digits) csum += (uint64_t)(p->W - 1 - v);

    std::vector<uint32_t> csum_digits(len2);
    uint64_t mask = ((uint64_t)1 << log_w) -1;
    for (int i = 0; i < len2; ++i) {
        int shift = (len2 - 1 - i) * log_w;
        csum_digits[i] = (uint32_t)((csum >> shift) & mask);
    }

    digits.insert(digits.end(), csum_digits.begin(), csum_digits.end());
    return digits;
}

// class implementation

SphincsPlus::SphincsPlus(SphexVariant variant) {
    p = new Params(variant);
}

SphincsPlus::~SphincsPlus() {
    delete p;
}

Bytes wots_sign(const Bytes& msg, const Bytes& sk_seed, const Bytes& pub_seed,
                Address addr, SphincsPlus::Params* p) {
    Bytes msg_hash = msg;
    if (msg_hash.size() != (size_t)p->N) {
        Bytes tmp(p->N);
        Keccak::shake256(msg, tmp);
        msg_hash = tmp;
    }

    std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

    if ((int)lengths.size() != p->WOTS_LEN) {
        throw std::runtime_error("WOTS: lengths mismatch");
    }

    addr.sanitize_for_role(ADDR_TYPE_WOTS);

    Bytes sig;
    sig.reserve(p->WOTS_LEN * p->N); //pre-allocate

    for (int i = 0; i < p->WOTS_LEN; i++) {
        addr.set_chain(i);
        addr.set_hash(0);

        Bytes sk_component = prf(sk_seed, addr, p->N);
        Bytes sig_part = gen_chain(sk_component, 0, lengths[i], pub_seed, addr, p->N);
        
        sig.insert(sig.end(), sig_part.begin(), sig_part.end());
        secure_wipe(sk_component);
    }
    return sig;
}

Bytes wots_pk_from_sig(const Bytes& sig, const Bytes& msg, const Bytes& pub_seed,
                Address addr, SphincsPlus::Params* p) {
    Bytes msg_hash = msg;
    if (msg_hash.size() != (size_t)p->N) {
        Bytes tmp(p->N);
        Keccak::shake256(msg, tmp);
        msg_hash = tmp;
    }

    std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

    if ((int)lengths.size() != p->WOTS_LEN) {
        throw std::runtime_error("WOTS: length mismatch in pk_from_sig");
    }

    Address wots_addr = addr;
    wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);

    Bytes pk_accum;
    pk_accum.reserve(p->WOTS_LEN * p->N);
    int sig_offset = 0;

    for (int i = 0; i < p->WOTS_LEN; i++) {
        wots_addr.set_chain(i);

        if (sig_offset + p->N > (int)sig.size()) {
            throw std::runtime_error("Signature too short in wots_pk_from_sig");
        }

        Bytes sig_part(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
        sig_offset += p->N;

        Bytes leaf = wots_chain(sig_part, lengths[i], (p->W - 1) - lengths[i], pub_seed, wots_addr, p->N);
        pk_accum.insert(pk_accum.end(), leaf.begin(), leaf.end());
    }

    Address pk_addr = addr;
    pk_addr.set_type(ADDR_TYPE_WOTS_PK);
    pk_addr.set_keypair(0);
    
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
    addr.set_type(ADDR_TYPE_TREE);
    Bytes root = treehash_authpath(sk_seed, pub_seed, addr, p->N, 0, 0, p->H_PRIME, p, nullptr);

    sk_out = sk_seed;
    sk_out.insert(sk_out.end(), sk_prf.begin(), sk_prf.end());
    sk_out.insert(sk_out.end(), pub_seed.begin(), pub_seed.end());
    sk_out.insert(sk_out.end(), root.begin(), root.end());

    Bytes pk = pub_seed;
    pk.insert(pk.end(), root.begin(), root.end());

    secure_wipe(sk_seed);
    secure_wipe(sk_prf);
    
    return pk;
}

std::vector<uint8_t> SphincsPlus::sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk) {
    Bytes sk_seed(sk.begin(), sk.begin() + p->N);
    Bytes sk_prf(sk.begin() + p->N, sk.begin() + 2 * p->N);
    Bytes pub_seed(sk.begin() + 2 * p->N, sk.begin() + 3 * p->N);
    Bytes pk_root(sk.begin() + 3 * p->N, sk.end());

    // Bytes optrand(p->N);
    // generate_random_bytes(optrand);

    Bytes optrand = prf_msg(sk_prf, pub_seed, msg, p->N);
    Bytes R = prf_msg(sk_prf, optrand, msg, p->N);

    Bytes buf;
    buf.insert(buf.end(), R.begin(), R.end());
    buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
    buf.insert(buf.end(), pk_root.begin(), pk_root.end());
    buf.insert(buf.end(), msg.begin(), msg.end());

    size_t digest_bits = p->K * p->A + (p->H - p->H_PRIME) + p->H_PRIME;
    size_t digest_bytes = (digest_bits + 7) / 8;

    if (digest_bytes < (size_t)p->N) digest_bytes = p->N;
    
    Bytes msg_digest_full(digest_bytes);
    Keccak::shake256(buf, msg_digest_full);

    Bytes signature = R;

    size_t bit_cursor = 0;

    Address fors_addr;
    fors_addr.set_type(ADDR_TYPE_FORS_TREE);
    fors_addr.set_layer(0);

    Bytes fors_pk_value;

    for(int i = 0; i < p->K; i++) {
        uint32_t actual_fors_idx = (uint32_t)(get_bits_from_stream(msg_digest_full, bit_cursor, p->A));
        bit_cursor += p->A;

        Address fors_leaf_addr = fors_addr;
        fors_leaf_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
        fors_leaf_addr.set_keypair(i);
        fors_leaf_addr.set_tree_height(0);
        fors_leaf_addr.set_tree_index(actual_fors_idx);

        Bytes sk_leaf = prf(sk_seed, fors_leaf_addr, p->N);
        signature.insert(signature.end(), sk_leaf.begin(), sk_leaf.end());

        Bytes leaf = thash(sk_leaf, pub_seed, fors_leaf_addr, p->N);
        secure_wipe(sk_leaf);

        std::vector<Bytes> path;
        treehash_authpath(sk_seed, pub_seed, fors_leaf_addr, p->N, 0, actual_fors_idx, p->A, p, &path);
        for (auto& node : path) {
            signature.insert(signature.end(), node.begin(), node.end());
        }

        Address tree_addr = fors_addr;
        tree_addr.set_keypair(i);
        Bytes tree_root = compute_root_from_path(leaf, actual_fors_idx, path, pub_seed, tree_addr, p->N);
        fors_pk_value.insert(fors_pk_value.end(), tree_root.begin(), tree_root.end());
    }

    Address fors_pk_addr = fors_addr;
    fors_pk_addr.set_type(ADDR_TYPE_FORS_PK);
    Bytes fors_root = thash(fors_pk_value, pub_seed, fors_pk_addr, p->N);

    uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H - p->H_PRIME));
    bit_cursor += (p->H - p->H_PRIME);

    uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, p->H_PRIME);

    Bytes current_root = fors_root;

    for (int i = 0; i < p->D; i++) {
        Address ht_addr;
        ht_addr.set_layer(i);
        ht_addr.set_tree(tree_idx);

        Address wots_addr = ht_addr;
        wots_addr.set_type(ADDR_TYPE_WOTS);
        wots_addr.set_keypair(leaf_idx);

        Bytes wots_sig = wots_sign(current_root, sk_seed, pub_seed, wots_addr, p);
        signature.insert(signature.end(), wots_sig.begin(), wots_sig.end());

        Address tree_addr = ht_addr;
        tree_addr.set_type(ADDR_TYPE_TREE);

        Address leaf_wots_addr = wots_addr;
        Bytes wots_pk = wots_pkgen(sk_seed, pub_seed, leaf_wots_addr, p);
        
        std::vector<Bytes> path;
        treehash_authpath(sk_seed, pub_seed, tree_addr, p->N, 0, leaf_idx, p->H_PRIME, p, &path);
        for (auto& node : path) signature.insert(signature.end(), node.begin(), node.end());

        current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed, tree_addr, p->N);

        if (i < p->D - 1) {
            leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
            tree_idx = (tree_idx >> p->H_PRIME);
        }
    }

    if (signature.size() != get_sig_size()) {
        throw std::runtime_error("Signature size mismatch in sign()");
    }

    secure_wipe(sk_seed);
    secure_wipe(sk_prf);
    return signature;
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

bool SphincsPlus::verify(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pk) {
    if (sig.size() != get_sig_size()) return false;
    if (pk.size() != 2 * p->N) return false;

    Bytes pub_seed(pk.begin(), pk.begin() + p->N);
    Bytes pk_root(pk.begin() + p->N, pk.end());
    
    Bytes R(sig.begin(), sig.begin() + p->N);

    Bytes buf_for_digest;
    buf_for_digest.insert(buf_for_digest.end(), R.begin(), R.end());
    buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
    buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
    buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());

    size_t digest_bytes = (p->K * p->A + p->H + 7) / 8;
    if (digest_bytes < (size_t)p->N) digest_bytes = p->N;
    
    Bytes msg_digest_full(digest_bytes);
    Keccak::shake256(buf_for_digest, msg_digest_full);

    size_t sig_offset = p->N;

    Address fors_addr;
    fors_addr.set_type(ADDR_TYPE_FORS_TREE);

    Bytes fors_root = fors_pk_from_sig(sig, sig_offset, msg_digest_full, pub_seed, fors_addr, p);
    
    size_t bit_cursor = p->K * p->A;

    uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H - p->H_PRIME));
    bit_cursor += (p->H - p->H_PRIME);

    uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, p->H_PRIME);
        
    Bytes current_root = fors_root;

    for (int i = 0; i < p->D; i++) {
        Address ht_addr;
        ht_addr.set_layer(i);
        ht_addr.set_tree(tree_idx);

        size_t wots_len = p->WOTS_LEN * p->N;
        if (sig_offset + wots_len > sig.size()) return false;

        Bytes wots_sig(sig.begin() + sig_offset, sig.begin() + sig_offset + wots_len);
        sig_offset += wots_len;

        Bytes wots_pk = wots_pk_from_sig(wots_sig, current_root, pub_seed, ht_addr, p);

        std::vector<Bytes> path;
        for (int j = 0; j < p->H_PRIME; j++) {
            if (sig_offset + p->N > sig.size()) return false;
            Bytes node(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
            path.push_back(node);
            sig_offset += p->N;
        }

        Address tree_addr = ht_addr;
        tree_addr.set_type(ADDR_TYPE_TREE);

        current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed, tree_addr, p->N);


        leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
        tree_idx >>= p->H_PRIME;
    }
    return (crypto_memcmp(current_root.data(), pk_root.data(), p->N) == 0);
}

size_t SphincsPlus::get_pk_size() const { return 2 * p->N; }
size_t SphincsPlus::get_sk_size() const { return 4 * p->N; }
size_t SphincsPlus::get_sig_size() const {
    size_t fors_sig_size = p->K * (p->N + p->A * p->N);
    size_t ht_sig_size = p->D * (p->WOTS_LEN * p->N + p->H_PRIME * p->N);
    return p->N + fors_sig_size + ht_sig_size;
}
