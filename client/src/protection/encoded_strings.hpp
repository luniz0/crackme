// path: RankGateInsane/client/src/protection/encoded_strings.hpp
//
// Compile-time string encryption. RG_OBF("literal") encrypts the literal during
// constant evaluation and stores only ciphertext in the binary; the plaintext
// is reconstructed at runtime. Used to keep the domain-separation labels
// (which are NOT on the wire -- they live inside HMAC/HKDF) out of a static
// `strings` dump of the client.
//
// This is harmless obfuscation: the keystream is a simple position-dependent
// XOR, fully documented, and exists only to raise the bar for static analysis.
#pragma once

#include <array>
#include <cstddef>
#include <string>

namespace rg::obf {

template <std::size_t N>
struct Enc {
    std::array<unsigned char, N> data{};
    unsigned char seed;

    // Position-dependent keystream: mixes the per-string seed with the index.
    static constexpr unsigned char ks(unsigned char s, std::size_t i) {
        return static_cast<unsigned char>(s + 0x37u * static_cast<unsigned char>(i) +
                                          static_cast<unsigned char>(i << 1) + 0x5Au);
    }

    constexpr explicit Enc(const char (&lit)[N], unsigned char s) : seed(s) {
        for (std::size_t i = 0; i < N; ++i)
            data[i] = static_cast<unsigned char>(static_cast<unsigned char>(lit[i]) ^
                                                 ks(s, i));
    }

    std::string decode() const {
        std::string out;
        out.resize(N - 1);  // drop the trailing NUL
        for (std::size_t i = 0; i + 1 < N; ++i)
            out[i] = static_cast<char>(data[i] ^ ks(seed, i));
        return out;
    }
};

}  // namespace rg::obf

// The `static constexpr` object forces compile-time evaluation, so the binary
// holds ciphertext only; decode() runs once at first use.
#define RG_OBF(lit)                                                            \
    ([]() -> std::string {                                                     \
        static constexpr ::rg::obf::Enc<sizeof(lit)> _e(                       \
            lit, static_cast<unsigned char>(0xB7u ^ (sizeof(lit) * 5u)));      \
        return _e.decode();                                                    \
    }())
