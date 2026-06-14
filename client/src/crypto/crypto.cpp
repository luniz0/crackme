// path: RankGateInsane/client/src/crypto/crypto.cpp
#include "crypto.hpp"

#include <sodium.h>

#include <cstring>

namespace rg::crypto {

// ===========================================================================
// Self-contained BLAKE2b (RFC 7693), keyed + arbitrary digest length 1..64.
//
// We do NOT use libsodium's crypto_generichash here: it rejects digests
// shorter than 16 bytes, and the challenge derives 3/4/8-byte BLAKE2b values
// (license fragment / vm_seed / vm input). The digest length is folded into
// the BLAKE2b parameter block, so a short digest is not a truncation of a
// long one -- it must be computed with the correct parameter block to match
// Python's hashlib.blake2b. This implementation does exactly that.
// ===========================================================================
namespace {

constexpr uint64_t kIV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

constexpr uint8_t kSigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

struct Blake2b {
    uint64_t h[8];
    uint64_t t[2] = {0, 0};
    uint8_t buf[128];
    size_t buflen = 0;
    size_t outlen;

    void compress(const uint8_t* block, bool last) {
        uint64_t v[16], m[16];
        for (int i = 0; i < 8; ++i) v[i] = h[i];
        for (int i = 0; i < 8; ++i) v[8 + i] = kIV[i];
        v[12] ^= t[0];
        v[13] ^= t[1];
        if (last) v[14] ^= 0xFFFFFFFFFFFFFFFFULL;
        for (int i = 0; i < 16; ++i) {
            uint64_t w = 0;
            for (int b = 7; b >= 0; --b) w = (w << 8) | block[i * 8 + b];
            m[i] = w;  // little-endian load
        }
        auto G = [&](int a, int b, int c, int d, uint64_t x, uint64_t y) {
            v[a] = v[a] + v[b] + x;
            v[d] = rotr64(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = rotr64(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = rotr64(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = rotr64(v[b] ^ v[c], 63);
        };
        for (int r = 0; r < 12; ++r) {
            const uint8_t* s = kSigma[r];
            G(0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[8 + i];
    }

    void inc(uint64_t n) {
        t[0] += n;
        if (t[0] < n) t[1]++;
    }

    void init(size_t out, size_t keylen) {
        outlen = out;
        for (int i = 0; i < 8; ++i) h[i] = kIV[i];
        h[0] ^= 0x01010000ULL ^ (static_cast<uint64_t>(keylen) << 8) ^ out;
    }

    void update(const uint8_t* in, size_t inlen) {
        for (size_t i = 0; i < inlen; ++i) {
            if (buflen == 128) {
                inc(128);
                compress(buf, false);
                buflen = 0;
            }
            buf[buflen++] = in[i];
        }
    }

    void final(uint8_t* out) {
        inc(buflen);
        while (buflen < 128) buf[buflen++] = 0;
        compress(buf, true);
        for (size_t i = 0; i < outlen; ++i)
            out[i] = static_cast<uint8_t>(h[i / 8] >> (8 * (i % 8)));  // little-endian
    }
};

}  // namespace

Bytes blake2b(const Bytes& data, const Bytes& key, size_t out_len) {
    if (out_len < 1 || out_len > 64) throw std::runtime_error("blake2b out_len");
    if (key.size() > 64) throw std::runtime_error("blake2b key too long");
    Blake2b st;
    st.init(out_len, key.size());
    if (!key.empty()) {
        uint8_t block[128] = {0};
        std::memcpy(block, key.data(), key.size());
        st.update(block, 128);  // key occupies one full block
    }
    if (!data.empty()) st.update(data.data(), data.size());
    Bytes out(out_len);
    st.final(out.data());
    return out;
}

// ===========================================================================
// libsodium-backed primitives
// ===========================================================================
void init() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

Bytes sha256(const Bytes& data) {
    Bytes out(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(out.data(), data.data(), data.size());
    return out;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    crypto_auth_hmacsha256_update(&st, data.data(), data.size());
    crypto_auth_hmacsha256_final(&st, out.data());
    return out;
}

X25519Keypair x25519_keypair() {
    Bytes priv = random_bytes(crypto_scalarmult_SCALARBYTES);
    return {priv, x25519_base(priv)};
}

Bytes x25519_base(const Bytes& priv) {
    Bytes pub(crypto_scalarmult_BYTES);
    if (crypto_scalarmult_base(pub.data(), priv.data()) != 0)
        throw std::runtime_error("x25519_base failed");
    return pub;
}

Bytes x25519_shared(const Bytes& priv, const Bytes& peer_pub) {
    Bytes out(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(out.data(), priv.data(), peer_pub.data()) != 0)
        throw std::runtime_error("x25519 shared failed (low-order point?)");
    return out;
}

bool ed25519_verify(const Bytes& pub, const Bytes& msg, const Bytes& sig) {
    if (pub.size() != crypto_sign_PUBLICKEYBYTES || sig.size() != crypto_sign_BYTES)
        return false;
    return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(),
                                       pub.data()) == 0;
}

Bytes aead_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& plaintext,
                   const Bytes& aad, Bytes& out_tag) {
    Bytes combined(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long clen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        combined.data(), &clen, plaintext.data(), plaintext.size(),
        aad.data(), aad.size(), nullptr, nonce.data(), key.data());
    combined.resize(static_cast<size_t>(clen));
    const size_t taglen = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    out_tag.assign(combined.end() - taglen, combined.end());
    return Bytes(combined.begin(), combined.end() - taglen);
}

Bytes aead_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext,
                   const Bytes& tag, const Bytes& aad) {
    Bytes combined = ciphertext;
    append(combined, tag);
    Bytes out(ciphertext.size());
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.data(), &mlen, nullptr, combined.data(), combined.size(),
            aad.data(), aad.size(), nonce.data(), key.data()) != 0)
        throw std::runtime_error("aead decrypt: authentication failed");
    out.resize(static_cast<size_t>(mlen));
    return out;
}

Bytes blake2b_ctr_keystream(const Bytes& key, size_t length, const Bytes& domain) {
    Bytes out;
    out.reserve(length + 64);
    uint64_t counter = 0;
    while (out.size() < length) {
        Bytes in = domain;
        append(in, be64(counter));
        append(out, blake2b(in, key, 64));
        counter++;
    }
    out.resize(length);
    return out;
}

Bytes stream_xor(const Bytes& key, const Bytes& data, const Bytes& domain) {
    Bytes ks = blake2b_ctr_keystream(key, data.size(), domain);
    Bytes out(data.size());
    for (size_t i = 0; i < data.size(); ++i) out[i] = data[i] ^ ks[i];
    return out;
}

bool ct_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

Bytes random_bytes(size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), n);
    return out;
}

}  // namespace rg::crypto
