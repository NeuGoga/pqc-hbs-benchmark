#include "sphincs.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <stdexcept>

const uint32_t ADDR_TYPE_WOTS = 0;
const uint32_t ADDR_TYPE_WOTS_PK = 1;
const uint32_t ADDR_TYPE_TREE = 2;
const uint32_t ADDR_TYPE_FORS_TREE = 3;
const uint32_t ADDR_TYPE_FORS_PK = 4;
const uint32_t ADDR_TYPE_WOTS_PRF = 5;
const uint32_t ADDR_TYPE_FORS_PRF = 6;

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#include <iostream>
#include <string.h>
#endif

/*  This function takes in a byte vector
 *   and fills it with random numbers using
 *   system's random number generator.
 *   It returns true if successful and false if an error.
 */
bool generate_random_bytes(std::vector<uint8_t> &buffer)
{
    if (buffer.empty())
        return true;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer.data(), (ULONG)buffer.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0)
    {
        std::cerr << "CSPRNG Error (Windows): BCryptGenRandom failed with status " << std::hex << status << std::endl;
        return false;
    }
    return true;
#else
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom)
    {
        std::cerr << "CSPRNG Error (Unix): Could not open /dev/urandom.\n";
        return false;
    }
    urandom.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    if (!urandom)
    {
        std::cerr << "CSPRNG Error (Unix): Could not read enough bytes form /dev/urandom.\n";
        return false;
    }
    return true;
#endif
}

/*  This function takes in a byte vector with data
 *   and overwrites its contents with zero in memory.
 */
void secure_wipe(std::vector<uint8_t> &data)
{
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

class Keccak
{
private:
    uint64_t state[25];
    uint8_t buffer[136];
    int buf_off;
    const int rate = 136;

    uint64_t rotl(uint64_t x, int s)
    {
        return (x << s) | (x >> (64 - s));
    }

    void keccak_f1600()
    {
        static const uint64_t RC[24] = {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

        static const int rho[24] = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

        static const int pi[24] = {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

        for (int round = 0; round < 24; round++)
        {
            uint64_t C[5], D[5];
            for (int i = 0; i < 5; i++)
                C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            for (int i = 0; i < 5; i++)
                D[i] = C[(i + 4) % 5] ^ rotl(C[(i + 1) % 5], 1);
            for (int i = 0; i < 25; i++)
                state[i] ^= D[i % 5];

            uint64_t current = state[1], temp;
            for (int i = 0; i < 24; i++)
            {
                int j = pi[i];
                temp = state[j];
                state[j] = rotl(current, rho[i]);
                current = temp;
            }

            for (int j = 0; j < 25; j += 5)
            {
                uint64_t t[5];
                for (int i = 0; i < 5; i++)
                    t[i] = state[j + i];
                for (int i = 0; i < 5; i++)
                    state[j + i] ^= (~t[(i + 1) % 5]) & t[(i + 2) % 5];
            }
            state[0] ^= RC[round];
        }
    }

public:
    Keccak()
    {
        std::memset(state, 0, sizeof(state));
        std::memset(buffer, 0, sizeof(buffer));
        buf_off = 0;
    }

    void absorb(const std::vector<uint8_t> &in)
    {
        for (uint8_t b : in)
        {
            buffer[buf_off++] = b;
            if (buf_off == rate)
            {
                for (int i = 0; i < rate / 8; i++)
                {
                    uint64_t lane = 0;
                    for (int k = 0; k < 8; k++)
                        lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
                    state[i] ^= lane;
                }
                keccak_f1600();
                buf_off = 0;
            }
        }
    }

    void finalize_and_squeeze(std::vector<uint8_t> &out)
    {
        buffer[buf_off++] = 0x1F;
        while (buf_off < rate)
            buffer[buf_off++] = 0;
        buffer[rate - 1] ^= 0x80;

        for (int i = 0; i < rate / 8; i++)
        {
            uint64_t lane = 0;
            for (int k = 0; k < 8; k++)
                lane |= ((uint64_t)buffer[i * 8 + k]) << (8 * k);
            state[i] ^= lane;
        }
        keccak_f1600();

        size_t out_len = out.size();
        size_t out_off = 0;

        while (out_len > 0)
        {
            size_t chunk = (out_len < (size_t)rate) ? out_len : (size_t)rate;
            for (size_t i = 0; i < chunk; i++)
            {
                out[out_off + i] = (uint8_t)((state[i / 8] >> (8 * (i % 8))) & 0xFF);
            }
            out_off += chunk;
            out_len -= chunk;
            if (out_len > 0)
                keccak_f1600();
        }
    }

    static void shake256(const std::vector<uint8_t> &input, std::vector<uint8_t> &output)
    {
        Keccak k;
        k.absorb(input);
        k.finalize_and_squeeze(output);
    }
};

/*  This struct has all of the parameters for SPHINCS+.
 *
 *   N: Security paramet in bytes.
 *   W: Winternitz parameter.
 *   H: Total height of the Merkle tree.
 *   D: Number of layers the Hypertree is divided into.
 *   A: Height of a single FORS tree.
 *   K: Number if FORS trees used to sign message
 *
 *   H_PRIME: Height of one single Merkle tree layer (H divided by D).
 *   len1: Number of WOTS+ hash chains needed to sing the main data.
 *   len2: Numbber of WOTS+ hash chains needed to sign the checksum.
 *   WOTS_LEN: Total number of WOTS+ chains.
 */
struct SphincsPlus::Params
{
    int N;
    int W;
    int H;
    int D;
    int A;
    int K;
    int H_PRIME;
    int WOTS_LEN;
    int len1;
    int len2;

    Params(SphexVariant v)
    {
        W = 16;
        switch (v)
        {
        case SphexVariant::SHAKE_128F_SIMPLE:
            N = 16;
            H = 66;
            D = 22;
            A = 6;
            K = 33;
            break;
        case SphexVariant::SHAKE_192F_SIMPLE:
            N = 24;
            H = 66;
            D = 22;
            A = 8;
            K = 33;
            break;
        case SphexVariant::SHAKE_256F_SIMPLE:
            N = 32;
            H = 68;
            D = 17;
            A = 9;
            K = 35;
            break;

        case SphexVariant::SHAKE_128S_SIMPLE:
            N = 16;
            H = 63;
            D = 7;
            A = 12;
            K = 14;
            break;
        case SphexVariant::SHAKE_192S_SIMPLE:
            N = 24;
            H = 63;
            D = 7;
            A = 14;
            K = 17;
            break;
        case SphexVariant::SHAKE_256S_SIMPLE:
            N = 32;
            H = 64;
            D = 8;
            A = 14;
            K = 22;
            break;
        default:
            throw std::invalid_argument("Unknown Variant");
        }

        H_PRIME = H / D;

        int log_w = 0;
        while ((1 << log_w) < W)
            ++log_w;

        this->len1 = (8 * N + log_w - 1) / log_w;

        uint64_t csum_max = (uint64_t)this->len1 * (W - 1);
        int csum_bits = 0;
        while (csum_max)
        {
            csum_max >>= 1;
            csum_bits++;
        }

        this->len2 = (csum_bits + log_w - 1) / log_w;
        this->WOTS_LEN = this->len1 + this->len2;
    }
};

using Bytes = std::vector<uint8_t>;

/*  Visual representation of the 8 words (32 bits / 4 bytes each):
 *
 *   +-------+---------------------------+----------+
 *   | Words | Description               | Size     |
 *   +-------+---------------------------+----------+
 *   |   0   | Layer Address             | 4 bytes  |
 *   |  1-3  | Tree Address              | 12 bytes |
 *   |   4   | Type                      | 4 bytes  |
 *   |   5   | Keypair Address           | 4 bytes  |
 *   |   6   | Chain Index / Tree Height | 4 bytes  |
 *   |   7   | Hash Index / Tree Index   | 4 bytes  |
 *   +-------+---------------------------+----------+
 */
struct Address
{
    uint32_t words[8];
    Address() { memset(words, 0, sizeof(words)); }

    void set_layer(uint32_t l) { words[0] = l; }

    void set_tree(uint64_t t)
    {
        words[1] = 0;
        words[2] = (uint32_t)(t >> 32);
        words[3] = (uint32_t)t;
    }

    void set_type(uint32_t t)
    {
        words[4] = t;
        words[5] = 0;
        words[6] = 0;
        words[7] = 0;
    }

    void set_keypair(uint32_t k) { words[5] = k; }

    void set_chain(uint32_t c) { words[6] = c; }
    void set_hash(uint32_t h) { words[7] = h; }

    void set_tree_height(uint32_t h) { words[6] = h; }
    void set_tree_index(uint32_t i) { words[7] = i; }

    void sanitize_for_role(uint32_t role)
    {
        uint32_t kp = words[5];
        set_type(role);

        if (role == ADDR_TYPE_WOTS || role == ADDR_TYPE_WOTS_PK ||
            role == ADDR_TYPE_FORS_TREE || role == ADDR_TYPE_FORS_PK ||
            role == ADDR_TYPE_WOTS_PRF || role == ADDR_TYPE_FORS_PRF)
        {
            words[5] = kp;
        }
    }

    Bytes to_bytes() const
    {
        Bytes out(32);
        for (int i = 0; i < 8; i++)
        {
            out[i * 4 + 0] = (words[i] >> 24) & 0xFF;
            out[i * 4 + 1] = (words[i] >> 16) & 0xFF;
            out[i * 4 + 2] = (words[i] >> 8) & 0xFF;
            out[i * 4 + 3] = (words[i] >> 0) & 0xFF;
        }
        return out;
    }
};

/* This function takes in a byte vector and reads
 *   a specific length opf bytes starting from input offset.
 *   It returns read bytes as a new vector and increases offest.
 */
Bytes extract_bytes(const std::vector<uint8_t> &src, size_t &offset, size_t len)
{
    if (offset + len > src.size())
    {
        throw std::runtime_error("Signature too short");
    }
    Bytes out(src.begin() + offset, src.begin() + offset + len);
    offset += len;
    return out;
}

/* This function takes the message digest and extracts a specific
 *  sequence of bits of size a to use as an inder for a FORS tree.
 *  It reads the bits out of the byte array in a order of
 *  least-significant bit first.
 */
uint32_t extract_fors_idx(const std::vector<uint8_t> &msg, int idx, int a)
{
    uint32_t res = 0;
    int frm_idx = idx * a;
    int to_idx = frm_idx + a - 1;
    for (int i = frm_idx; i <= to_idx; i++)
    {
        int byte_off = i >> 3;
        int bit_off = i & 7;
        uint8_t bit = (msg[byte_off] >> bit_off) & 1;
        res |= (bit << (i - frm_idx));
    }
    return res;
}

/* This function takes an input byte vector and a specific Address,
 *  and hashes them together with public key using Keccak.
 *  It returns randomized output of N bytes.
 */
Bytes thash(const Bytes &in, const Bytes &pub_seed, const Address &addr, int N)
{
    Keccak k;
    k.absorb(pub_seed);
    k.absorb(addr.to_bytes());
    k.absorb(in);
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

/*  This function takes secret key seed, public key seed,
 *   and a specific Address, and generates N pseudo-random bytes.
 *   It is used to deteremenistically generate teh secret key material
 *   for the WOTS+ and FORS leaves without storing them.
 */
Bytes prf(const Bytes &pub_seed, const Bytes &sk_seed, const Address &addr, int N)
{
    Keccak k;
    k.absorb(pub_seed);
    k.absorb(addr.to_bytes());
    k.absorb(sk_seed);
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

/* This function takes secret PRF key, a randomizer, and the
 *   message being signed, and hashes them together.
 *   It returns N random bytes that are attached to the start
 *   of the signature.
 */
Bytes prf_msg(const Bytes &sk_prf, const Bytes &optrand, const Bytes &msg, int N)
{
    Keccak k;
    k.absorb(sk_prf);
    k.absorb(optrand);
    k.absorb(msg);
    Bytes out(N);
    k.finalize_and_squeeze(out);
    return out;
}

/*  This function takes an input byte vector and repeatedly hashes it
 *   steps times using thash.
 *   It increments the Address hash index on every step so that
 *   every hash in the chain is bound to a specific position.
 */
Bytes gen_chain(Bytes in, int start, int steps, const Bytes &pub_seed, Address addr, int N)
{
    for (int i = start; i < start + steps; i++)
    {
        addr.set_hash(i);
        in = thash(in, pub_seed, addr, N);
    }
    return in;
}

/*  This function used in WOTS+ verification.
 *   It hashes the input byte vector and hashes it for the number
 *   of steps.
 */
Bytes wots_chain(const Bytes &in, int start, int steps, const Bytes &pub_seed, Address &addr, int N)
{
    Bytes out = in;
    for (int i = start; i < start + steps; i++)
    {
        addr.set_hash(i);
        out = thash(out, pub_seed, addr, N);
    }
    return out;
}

/*  This function genereates a WOTS+ public key.
 *   It generates all of the secret key leaves using the PRF,
 *   hashes each leaf to the very top of its chain, and then hashes
 *   all of those into a single N-byte public key.
 */
Bytes wots_pkgen(const Bytes &sk_seed, const Bytes &pub_seed, Address addr, SphincsPlus::Params *p)
{
    addr.sanitize_for_role(ADDR_TYPE_WOTS);
    addr.set_hash(0);

    Bytes pk_accum;

    pk_accum.reserve(p->WOTS_LEN * p->N);

    for (int i = 0; i < p->WOTS_LEN; i++)
    {
        addr.set_chain(i);

        Address prf_addr = addr;
        prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
        prf_addr.set_keypair(addr.words[5]);
        prf_addr.set_chain(i);
        prf_addr.set_hash(0);

        Bytes sk = prf(pub_seed, sk_seed, prf_addr, p->N);

        Bytes leaf = gen_chain(sk, 0, p->W - 1, pub_seed, addr, p->N);

        pk_accum.insert(pk_accum.end(), leaf.begin(), leaf.end());

        secure_wipe(sk);
    }

    addr.set_chain(0);
    addr.set_hash(0);

    uint32_t original_keypair = addr.words[5];
    addr.set_type(ADDR_TYPE_WOTS_PK);
    addr.set_keypair(original_keypair);

    return thash(pk_accum, pub_seed, addr, p->N);
}

struct StackNodeAuth
{
    Bytes node;
    int height;
    uint32_t start_idx;
};

/*  This function computes the root of a Merkle tree of a tree_height height.
 *   It generates the leaves and hashes them together to reach the top.
 *   If a target leaf index is provided, it also saves the sibling nodes
 *   along the way to build the authentication path.
 */
Bytes treehash_authpath(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                        int N, uint32_t start_idx, uint32_t target_leaf_idx,
                        int tree_height, SphincsPlus::Params *p, std::vector<Bytes> *auth_path)
{
    std::vector<StackNodeAuth> stack;
    stack.reserve(tree_height + 1);

    uint32_t leaves = 1u << tree_height;

    if (auth_path)
    {
        auth_path->assign(tree_height, Bytes(N, 0));
    }

    for (uint32_t i = 0; i < leaves; ++i)
    {
        uint32_t idx = start_idx + i;

        Address leaf_addr = addr;

        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(idx);

        Bytes node;
        if (addr.words[4] == ADDR_TYPE_TREE)
        {
            Address wots_addr = leaf_addr;
            wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);
            wots_addr.set_keypair(idx);
            node = wots_pkgen(sk_seed, pub_seed, wots_addr, p);
        }
        else
        {
            Address prf_addr = leaf_addr;
            prf_addr.set_type(ADDR_TYPE_FORS_PRF);
            prf_addr.set_keypair(leaf_addr.words[5]);
            prf_addr.set_tree_height(0);
            prf_addr.set_tree_index(idx);

            Bytes sk_leaf = prf(pub_seed, sk_seed, prf_addr, N);
            node = thash(sk_leaf, pub_seed, leaf_addr, N);
            secure_wipe(sk_leaf);
        }

        StackNodeAuth cur{node, 0, idx};

        while (!stack.empty() && stack.back().height == cur.height)
        {
            StackNodeAuth left = stack.back();
            stack.pop_back();
            StackNodeAuth right = cur;

            if (auth_path)
            {
                uint32_t current_subtree_size = 1u << left.height;
                uint32_t relative_idx = target_leaf_idx - left.start_idx;

                if (relative_idx < current_subtree_size)
                {
                    (*auth_path)[left.height] = right.node;
                }
                else if (relative_idx < (2 * current_subtree_size))
                {
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

    if (stack.empty())
        return Bytes(N, 0);
    return stack.back().node;
}

struct StackNode
{
    Bytes node;
    int height;
};

/*  This function computes the root of a Merkle tree of a specified height.
 *   Unlike treehash_authpath, it does not save any sibling nodes for a signature.
 *   It simply generates the leaves deterministiaclly from the secret seed and hashes
 *   them together to find the top root node.
 */
Bytes compute_root(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                   int N, uint32_t idx_offset, int height, SphincsPlus::Params *p)
{
    std::vector<StackNode> stack;
    stack.reserve(height + 1);

    uint32_t leaves = 1 << height;

    bool is_hypertree = (addr.words[4] == ADDR_TYPE_TREE);

    for (uint32_t i = 0; i < leaves; i++)
    {
        Address leaf_addr = addr;
        uint32_t current_idx = idx_offset + i;

        Bytes node;

        if (is_hypertree)
        {
            leaf_addr.set_keypair(current_idx);
            node = wots_pkgen(sk_seed, pub_seed, leaf_addr, p);
        }
        else
        {
            leaf_addr.set_tree_height(0);
            leaf_addr.set_tree_index(current_idx);

            Address prf_addr = leaf_addr;
            prf_addr.set_type(ADDR_TYPE_FORS_PRF);
            prf_addr.set_keypair(leaf_addr.words[5]);
            prf_addr.set_tree_height(0);
            prf_addr.set_tree_index(current_idx);

            Bytes sk_leaf = prf(pub_seed, sk_seed, prf_addr, N);

            node = thash(sk_leaf, pub_seed, leaf_addr, N);
            secure_wipe(sk_leaf);
        }

        int h = 0;

        while (!stack.empty() && stack.back().height == h)
        {
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

/*  This function rebuilds the roof of a Merkle tree using a single leaf
 *   and its authentication path. It uses the leaf's index to determine whether
 *   each sibling belongs on the left or the right during the pairwise hashing.
 *   This is used for signature verification.
 */
Bytes compute_root_from_path(const Bytes &leaf, uint32_t leaf_idx, const std::vector<Bytes> &auth_path,
                             const Bytes &pub_seed, Address addr, int N)
{
    Bytes current_node = leaf;

    for (size_t h = 0; h < auth_path.size(); ++h)
    {
        addr.set_tree_height(h + 1);
        addr.set_tree_index(leaf_idx >> 1);

        Bytes left, right;
        if (leaf_idx & 1)
        {
            left = auth_path[h];
            right = current_node;
        }
        else
        {
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

/* This function extract a specific number of bits from a byte vector,
 *   starting at any bit offset, and returns them as an integer.
 *   It is used to parse randomized message digest into numbers.
 */
uint64_t get_bits_from_stream(const std::vector<uint8_t> &bytes, size_t bit_offset, int num_bits)
{
    if (num_bits == 0)
        return 0;

    uint64_t out = 0;
    for (int i = 0; i < num_bits; ++i)
    {
        size_t bit_pos = bit_offset + i;
        size_t byte_idx = bit_pos / 8;
        if (byte_idx >= bytes.size())
            return out << (num_bits - i);

        int bit_in_byte = 7 - (bit_pos % 8);
        uint8_t bit = (bytes[byte_idx] >> bit_in_byte) & 1;
        out = (out << 1) | bit;
    }
    return out;
}

/*  This function takes a byte array and converts it into an array
 *   of smaller integers in base W.
 *   It reads input bits in small chunks and outputs it as a
 *   series of numbers. These numbers tell how many hash steps are
 *   required for each individual WOTS+ chain.
 */
std::vector<uint32_t> base_w(const std::vector<uint8_t> &in, int w, int out_len)
{
    int log_w = 0;
    while ((1 << log_w) < w)
        ++log_w;

    std::vector<uint32_t> out;
    out.reserve(out_len);

    size_t bit_cursor = 0;
    for (int i = 0; i < out_len; ++i)
    {
        uint32_t val = (uint32_t)get_bits_from_stream(in, bit_cursor, log_w);
        out.push_back(val);
        bit_cursor += log_w;
    }
    return out;
}

/*  This function reconstructs the FORS public key from a given signature.
 *   It reads the revealed secret leaves and authentication paths from
 *   signature, calculates the root of each of the K FORS trees,
 *   and then hashes all K roots together to find the final FORS root.
 */
Bytes fors_pk_from_sig(const Bytes &sig, size_t &sig_offset, const Bytes &msg_digest, const Bytes &pub_seed,
                       Address addr, SphincsPlus::Params *p)
{
    Bytes fors_pk_values;

    for (int i = 0; i < p->K; i++)
    {
        uint32_t actual_fors_idx = extract_fors_idx(msg_digest, i, p->A);
        uint32_t global_fors_idx = i * (1 << p->A) + actual_fors_idx;

        Bytes sk = extract_bytes(sig, sig_offset, p->N);

        Address leaf_addr = addr;
        leaf_addr.set_type(ADDR_TYPE_FORS_TREE);
        leaf_addr.set_keypair(addr.words[5]);
        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(global_fors_idx);

        Bytes leaf = thash(sk, pub_seed, leaf_addr, p->N);

        std::vector<Bytes> path;
        for (int j = 0; j < p->A; j++)
        {
            path.push_back(extract_bytes(sig, sig_offset, p->N));
        }

        Address tree_addr = addr;
        tree_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
        tree_addr.set_keypair(addr.words[5]);

        Bytes tree_root = compute_root_from_path(leaf, global_fors_idx, path, pub_seed, tree_addr, p->N);
        fors_pk_values.insert(fors_pk_values.end(), tree_root.begin(), tree_root.end());
    }
    Address root_addr = addr;
    root_addr.set_type(ADDR_TYPE_FORS_PK);
    root_addr.set_keypair(addr.words[5]);
    return thash(fors_pk_values, pub_seed, root_addr, p->N);
}

/*  This function is a wrapper for treehash_authpath.
 *   It returns authentication path.
 */
std::vector<Bytes> gen_auth_path(const Bytes &sk_seed, const Bytes &pub_seed, Address addr,
                                 int N, uint32_t leaf_idx, int h_total, SphincsPlus::Params *p)
{
    std::vector<Bytes> auth;

    uint32_t start = 0;
    treehash_authpath(sk_seed, pub_seed, addr, N, start, leaf_idx, h_total, p, &auth);
    return auth;
}

/*  This function calculates the number of hash steps needed
 *   for each WOTS+ chain based on the message digest. It converts the
 *   message into base-W numbers, computes a required checksum, and
 *   appends the checksum's base-W digits to the end of the array.
 */
static std::vector<uint32_t> compute_wots_digits(const Bytes &msg_hash, SphincsPlus::Params *p)
{
    int log_w = 0;
    while ((1 << log_w) < p->W)
        ++log_w;

    int len1 = p->len1;
    int len2 = p->len2;

    std::vector<uint32_t> digits = base_w(msg_hash, p->W, len1);

    uint64_t csum = 0;
    for (uint32_t v : digits)
        csum += (uint64_t)(p->W - 1 - v);

    if ((len2 * log_w) % 8 != 0)
    {
        csum <<= (8 - ((len2 * log_w) % 8));
    }

    int csum_bytes_len = (len2 * log_w + 7) / 8;
    std::vector<uint8_t> csum_bytes(csum_bytes_len);

    for (int i = 0; i < csum_bytes_len; i++)
    {
        int shift = (csum_bytes_len - 1 - i) * 8;
        csum_bytes[i] = (uint8_t)((csum >> shift) & 0xFF);
    }

    std::vector<uint32_t> csum_digits = base_w(csum_bytes, p->W, len2);

    // std::vector<uint32_t> csum_digits(len2);
    // uint64_t mask = ((uint64_t)1 << log_w) -1;
    // for (int i = 0; i < len2; ++i) {
    //     int shift = (len2 - 1 - i) * log_w;
    //     csum_digits[i] = (uint32_t)((csum >> shift) & mask);
    // }

    digits.insert(digits.end(), csum_digits.begin(), csum_digits.end());
    return digits;
}

SphincsPlus::SphincsPlus(SphexVariant variant)
{
    p = new Params(variant);
}

SphincsPlus::~SphincsPlus()
{
    delete p;
}

/*  This function generates WOTS+. It takes an N-byte message,
 *   determines the required hash steps using compute_wots_digits,
 *   and deterministically generates the secret key for each chain.
 *   It then hashes each chain up to the specific step and returns the result.
 */
Bytes wots_sign(const Bytes &msg, const Bytes &sk_seed, const Bytes &pub_seed,
                Address addr, SphincsPlus::Params *p)
{
    Bytes msg_hash = msg;
    if (msg_hash.size() != (size_t)p->N)
    {
        Bytes tmp(p->N);
        Keccak::shake256(msg, tmp);
        msg_hash = tmp;
    }

    std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

    if ((int)lengths.size() != p->WOTS_LEN)
    {
        throw std::runtime_error("WOTS: lengths mismatch");
    }

    addr.sanitize_for_role(ADDR_TYPE_WOTS);

    Bytes sig;
    sig.reserve(p->WOTS_LEN * p->N); // pre-allocate

    for (int i = 0; i < p->WOTS_LEN; i++)
    {
        addr.set_chain(i);

        Address prf_addr = addr;
        prf_addr.set_type(ADDR_TYPE_WOTS_PRF);
        prf_addr.set_keypair(addr.words[5]);
        prf_addr.set_chain(i);
        prf_addr.set_hash(0);

        Bytes sk_component = prf(pub_seed, sk_seed, prf_addr, p->N);
        Bytes sig_part = gen_chain(sk_component, 0, lengths[i], pub_seed, addr, p->N);

        sig.insert(sig.end(), sig_part.begin(), sig_part.end());
        secure_wipe(sk_component);
    }
    return sig;
}

/*  This function reconstructs a WOTS+ public keu from a given signature.
 *   It calculates the expected base-W digits for the signed messgae, takes
 *   nodes provided in the signature, and hashes them the rest of the way
 *   to the top of each chain. It then hashes all of the top nodes together to
 *   get WOTS+ public key.
 */
Bytes wots_pk_from_sig(const Bytes &sig, const Bytes &msg, const Bytes &pub_seed,
                       Address addr, SphincsPlus::Params *p)
{
    Bytes msg_hash = msg;
    if (msg_hash.size() != (size_t)p->N)
    {
        Bytes tmp(p->N);
        Keccak::shake256(msg, tmp);
        msg_hash = tmp;
    }

    std::vector<uint32_t> lengths = compute_wots_digits(msg_hash, p);

    if ((int)lengths.size() != p->WOTS_LEN)
    {
        throw std::runtime_error("WOTS: length mismatch in pk_from_sig");
    }

    Address wots_addr = addr;
    wots_addr.sanitize_for_role(ADDR_TYPE_WOTS);

    Bytes pk_accum;
    pk_accum.reserve(p->WOTS_LEN * p->N);
    int sig_offset = 0;

    for (int i = 0; i < p->WOTS_LEN; i++)
    {
        wots_addr.set_chain(i);

        if (sig_offset + p->N > (int)sig.size())
        {
            throw std::runtime_error("Signature too short in wots_pk_from_sig");
        }

        Bytes sig_part(sig.begin() + sig_offset, sig.begin() + sig_offset + p->N);
        sig_offset += p->N;

        Bytes leaf = wots_chain(sig_part, lengths[i], (p->W - 1) - lengths[i], pub_seed, wots_addr, p->N);
        pk_accum.insert(pk_accum.end(), leaf.begin(), leaf.end());
    }

    Address pk_addr = addr;
    pk_addr.set_type(ADDR_TYPE_WOTS_PK);
    pk_addr.set_keypair(addr.words[5]);
    pk_addr.set_chain(0);
    pk_addr.set_hash(0);

    return thash(pk_accum, pub_seed, pk_addr, p->N);
}

/*  This function generates new SPHINCS+ public and secret keypair.
 *   It generates the secret seed, PRF, and public seed. With this it builds
 *   entire top layer of the Hypertree to find the public root.
 */
std::vector<uint8_t> SphincsPlus::keygen(std::vector<uint8_t> &sk_out)
{
    Bytes seeds(3 * p->N);
    if (!generate_random_bytes(seeds))
    {
        std::cerr << "Error: Failed to CSPRNG.\n";
        sk_out.clear();
        return {};
    }

    Bytes sk_seed(seeds.begin(), seeds.begin() + p->N);
    Bytes sk_prf(seeds.begin() + p->N, seeds.begin() + 2 * p->N);
    Bytes pub_seed(seeds.begin() + 2 * p->N, seeds.begin() + 3 * p->N);

    // if(!generate_random_bytes(sk_seed) ||
    //     !generate_random_bytes(sk_prf) ||
    //     !generate_random_bytes(pub_seed)) {
    //         std::cerr << "Error: Failed to CSPRNG.\n";
    //         sk_out.clear();
    //         return {};
    //     }

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

    secure_wipe(seeds);
    secure_wipe(sk_seed);
    secure_wipe(sk_prf);

    return pk;
}

/*  This is the main signing function. It create SPHINCS+ signature
 *   for a given message the provided secret key. It first generate a
 *   randomizer R and hashes the message. It then signs the digest using the
 *   FORS trees. Then it hashes up the Hypertree, using WOTS+ to sign the root
 *   of each lower tree and generating the Merkle authentication paths to the top layer.
 */
std::vector<uint8_t> SphincsPlus::sign(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sk)
{
    Bytes sk_seed(sk.begin(), sk.begin() + p->N);
    Bytes sk_prf(sk.begin() + p->N, sk.begin() + 2 * p->N);
    Bytes pub_seed(sk.begin() + 2 * p->N, sk.begin() + 3 * p->N);
    Bytes pk_root(sk.begin() + 3 * p->N, sk.end());

    // Bytes optrand(p->N);
    // generate_random_bytes(optrand);

    // Bytes optrand = prf_msg(sk_prf, pub_seed, msg, p->N);
    Bytes R = prf_msg(sk_prf, pub_seed, msg, p->N);

    Bytes buf;
    buf.insert(buf.end(), R.begin(), R.end());
    buf.insert(buf.end(), pub_seed.begin(), pub_seed.end());
    buf.insert(buf.end(), pk_root.begin(), pk_root.end());
    buf.insert(buf.end(), msg.begin(), msg.end());

    // size_t digest_bits = p->K * p->A + (p->H - p->H_PRIME) + p->H_PRIME;
    size_t fors_bytes = (p->K * p->A + 7) / 8;
    size_t tree_bytes = ((p->H - p->H_PRIME) + 7) / 8;
    size_t leaf_bytes = (p->H_PRIME + 7) / 8;
    size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;

    if (digest_bytes < (size_t)p->N)
        digest_bytes = p->N;

    Bytes msg_digest_full(digest_bytes);
    Keccak::shake256(buf, msg_digest_full);

    size_t bit_cursor = fors_bytes * 8;

    uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, tree_bytes * 8);

    if ((p->H - p->H_PRIME) < 64)
    {
        tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
    }

    bit_cursor += tree_bytes * 8;

    uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, leaf_bytes * 8);
    leaf_idx &= ((1ULL << p->H_PRIME) - 1);

    Bytes signature = R;

    Address fors_addr;
    fors_addr.set_layer(0);
    fors_addr.set_tree(tree_idx);
    fors_addr.set_type(ADDR_TYPE_FORS_TREE);
    fors_addr.set_keypair(leaf_idx);

    Bytes fors_pk_value;

    for (int i = 0; i < p->K; i++)
    {
        uint32_t actual_fors_idx = extract_fors_idx(msg_digest_full, i, p->A);
        uint32_t global_fors_idx = i * (1 << p->A) + actual_fors_idx;

        Address prf_addr = fors_addr;
        prf_addr.set_type(ADDR_TYPE_FORS_PRF);
        prf_addr.set_keypair(leaf_idx);
        prf_addr.set_tree_height(0);
        prf_addr.set_tree_index(global_fors_idx);

        Bytes sk_leaf = prf(pub_seed, sk_seed, prf_addr, p->N);
        signature.insert(signature.end(), sk_leaf.begin(), sk_leaf.end());

        Address leaf_addr = fors_addr;
        leaf_addr.sanitize_for_role(ADDR_TYPE_FORS_TREE);
        leaf_addr.set_tree_height(0);
        leaf_addr.set_tree_index(global_fors_idx);

        Bytes leaf = thash(sk_leaf, pub_seed, leaf_addr, p->N);
        secure_wipe(sk_leaf);

        std::vector<Bytes> path;
        treehash_authpath(sk_seed, pub_seed, fors_addr, p->N, i * (1 << p->A), global_fors_idx, p->A, p, &path);
        for (auto &node : path)
        {
            signature.insert(signature.end(), node.begin(), node.end());
        }

        Address tree_addr = fors_addr;
        tree_addr.set_keypair(leaf_idx);
        Bytes tree_root = compute_root_from_path(leaf, global_fors_idx, path, pub_seed, tree_addr, p->N);
        fors_pk_value.insert(fors_pk_value.end(), tree_root.begin(), tree_root.end());
    }

    Address fors_pk_addr = fors_addr;
    fors_pk_addr.set_type(ADDR_TYPE_FORS_PK);
    fors_pk_addr.set_keypair(leaf_idx);
    Bytes fors_root = thash(fors_pk_value, pub_seed, fors_pk_addr, p->N);

    // uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H - p->H_PRIME));
    // bit_cursor += (p->H - p->H_PRIME);

    // uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, p->H_PRIME);

    Bytes current_root = fors_root;

    for (int i = 0; i < p->D; i++)
    {
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
        for (auto &node : path)
            signature.insert(signature.end(), node.begin(), node.end());

        current_root = compute_root_from_path(wots_pk, leaf_idx, path, pub_seed, tree_addr, p->N);

        leaf_idx = (uint32_t)(tree_idx & ((1ULL << p->H_PRIME) - 1));
        tree_idx = (tree_idx >> p->H_PRIME);
    }

    if (signature.size() != get_sig_size())
    {
        throw std::runtime_error("Signature size mismatch in sign()");
    }

    secure_wipe(sk_seed);
    secure_wipe(sk_prf);
    return signature;
}

/*  This helper function compares two blocks of memory in "constant time".
 *   I made this to try preventing timing attacks, so it checks every single byte,
 *   compared to standard memcmp which stops at the first difference.
 */
int crypto_memcmp(const void *a, const void *b, size_t size)
{
    const unsigned char *p1 = (const unsigned char *)a;
    const unsigned char *p2 = (const unsigned char *)b;
    unsigned char result = 0;

    for (size_t i = 0; i < size; i++)
    {
        result |= p1[i] ^ p2[i];
    }

    return result;
}

/*  This is verification function. It takes a message, a signature and a public key,
 *   and returns true if the signature is valid. It recreates the message digest, uses
 *   the signature to recontruct the FORS public key, and verifies the WOTS+ signatures
 *   and Merkle paths up to the top layer of the Hypertree where it compares the root to
 *   the public key.
 */
bool SphincsPlus::verify(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig, const std::vector<uint8_t> &pk)
{
    if (sig.size() != get_sig_size())
        return false;
    if (pk.size() != 2 * p->N)
        return false;

    Bytes pub_seed(pk.begin(), pk.begin() + p->N);
    Bytes pk_root(pk.begin() + p->N, pk.end());

    Bytes R(sig.begin(), sig.begin() + p->N);

    Bytes buf_for_digest;
    buf_for_digest.insert(buf_for_digest.end(), R.begin(), R.end());
    buf_for_digest.insert(buf_for_digest.end(), pub_seed.begin(), pub_seed.end());
    buf_for_digest.insert(buf_for_digest.end(), pk_root.begin(), pk_root.end());
    buf_for_digest.insert(buf_for_digest.end(), msg.begin(), msg.end());

    size_t fors_bytes = (p->K * p->A + 7) / 8;
    size_t tree_bytes = ((p->H - p->H_PRIME) + 7) / 8;
    size_t leaf_bytes = (p->H_PRIME + 7) / 8;
    size_t digest_bytes = fors_bytes + tree_bytes + leaf_bytes;

    if (digest_bytes < (size_t)p->N)
        digest_bytes = p->N;

    Bytes msg_digest_full(digest_bytes);
    Keccak::shake256(buf_for_digest, msg_digest_full);

    size_t bit_cursor = fors_bytes * 8;

    uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, tree_bytes * 8);

    if ((p->H - p->H_PRIME) < 64)
    {
        tree_idx &= ((1ULL << (p->H - p->H_PRIME)) - 1);
    }

    bit_cursor += tree_bytes * 8;

    uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, leaf_bytes * 8);
    leaf_idx &= ((1ULL << p->H_PRIME) - 1);

    size_t sig_offset = p->N;

    Address fors_addr;
    fors_addr.set_layer(0);
    fors_addr.set_tree(tree_idx);
    fors_addr.set_type(ADDR_TYPE_FORS_TREE);
    fors_addr.set_keypair(leaf_idx);

    Bytes fors_root = fors_pk_from_sig(sig, sig_offset, msg_digest_full, pub_seed, fors_addr, p);

    // size_t bit_cursor = p->K * p->A;

    // uint64_t tree_idx = get_bits_from_stream(msg_digest_full, bit_cursor, (p->H - p->H_PRIME));
    // bit_cursor += (p->H - p->H_PRIME);

    // uint32_t leaf_idx = (uint32_t)get_bits_from_stream(msg_digest_full, bit_cursor, p->H_PRIME);

    Bytes current_root = fors_root;

    for (int i = 0; i < p->D; i++)
    {
        Address ht_addr;
        ht_addr.set_layer(i);
        ht_addr.set_tree(tree_idx);

        Address wots_addr = ht_addr;
        wots_addr.set_type(ADDR_TYPE_WOTS);
        wots_addr.set_keypair(leaf_idx);

        size_t wots_len = p->WOTS_LEN * p->N;
        if (sig_offset + wots_len > sig.size())
            return false;

        Bytes wots_sig(sig.begin() + sig_offset, sig.begin() + sig_offset + wots_len);
        sig_offset += wots_len;

        Bytes wots_pk = wots_pk_from_sig(wots_sig, current_root, pub_seed, wots_addr, p);

        std::vector<Bytes> path;
        for (int j = 0; j < p->H_PRIME; j++)
        {
            if (sig_offset + p->N > sig.size())
                return false;
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
size_t SphincsPlus::get_sig_size() const
{
    size_t fors_sig_size = p->K * (p->N + p->A * p->N);
    size_t ht_sig_size = p->D * (p->WOTS_LEN * p->N + p->H_PRIME * p->N);
    return p->N + fors_sig_size + ht_sig_size;
}
