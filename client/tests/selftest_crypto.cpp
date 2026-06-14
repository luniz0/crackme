// path: RankGateInsane/client/tests/selftest_crypto.cpp
//
// Byte-parity self-test: proves the C++ crypto layer reproduces the Python
// server's primitives exactly. Vectors come from tools/_gen_crypto_vectors.py
// (which runs the server's own crypto_box). If any check fails, the native
// client and the server would disagree on transcript bytes and no proof could
// ever validate -- so this gate must stay green.
#include <cstdio>
#include <string>

#include "../src/crypto/base64.hpp"
#include "../src/crypto/crypto.hpp"
#include "../src/crypto/kdf.hpp"
#include "crypto_vectors.h"

using namespace rg;
using namespace rg::crypto;

static int g_fail = 0;

static std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) {
        s += d[x >> 4];
        s += d[x & 15];
    }
    return s;
}

static void check(const char* name, const Bytes& got, const Bytes& want) {
    if (got == want) {
        std::printf("  [ok] %s\n", name);
    } else {
        std::printf("  [FAIL] %s\n        got : %s\n        want: %s\n", name,
                    hex(got).c_str(), hex(want).c_str());
        ++g_fail;
    }
}

static void check_true(const char* name, bool cond) {
    if (cond) {
        std::printf("  [ok] %s\n", name);
    } else {
        std::printf("  [FAIL] %s\n", name);
        ++g_fail;
    }
}

int main() {
    init();
    using namespace rg::vectors;
    std::printf("RankGate crypto self-test (byte-parity vs Python server)\n");

    check("sha256(TRANSCRIPT_SEED)", sha256(str_bytes("RG6-TRANSCRIPT/v6")), kSha256_T0);
    check("sha256(msg)", sha256(kMsg), kSha256_Msg);

    check("blake2b unkeyed/32", blake2b(kMsg, 32), kBlake_Unkeyed32);
    check("blake2b keyed/4", blake2b(kMsg, kKey32, 4), kBlake_Keyed4);
    check("blake2b keyed/64", blake2b(kMsg, kKey32, 64), kBlake_Keyed64);

    check("hmac-sha256", hmac_sha256(kKey32, kMsg), kHmac);
    check("hkdf 48", hkdf(kSalt32, kIkm32, kInfo, 48), kHkdf48);

    check("blake2b-ctr keystream 80", blake2b_ctr_keystream(kKey32, 80, kDomain), kKeystream80);
    check("stream_xor", stream_xor(kKey32, kMsg, kDomain), kStreamXor);

    check("x25519 base(privB)", x25519_base(kPrivB), kPubB);
    check("x25519 shared(privA,pubB)", x25519_shared(kPrivA, kPubB), kShared);

    Bytes tag;
    Bytes ct = aead_encrypt(kAeadKey, kAeadNonce, kAeadPlain, kAeadAad, tag);
    check("aead ciphertext", ct, kAeadCt);
    check("aead tag", tag, kAeadTag);
    check("aead decrypt", aead_decrypt(kAeadKey, kAeadNonce, kAeadCt, kAeadTag, kAeadAad),
          kAeadPlain);

    check_true("ed25519 verify", ed25519_verify(kEdPk, kEdMsg, kEdSig));

    // base64 round-trip against a known Python value: b64encode(b"RankGate!") .
    check_true("base64 encode", b64encode(str_bytes("RankGate!")) == "UmFua0dhdGUh");
    check("base64 decode", b64decode("UmFua0dhdGUh"), str_bytes("RankGate!"));

    std::printf("%s (%d failures)\n", g_fail ? "SELFTEST FAILED" : "ALL CHECKS PASSED",
                g_fail);
    return g_fail ? 1 : 0;
}
