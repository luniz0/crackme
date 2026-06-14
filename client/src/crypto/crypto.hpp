// path: RankGateInsane/client/src/crypto/crypto.hpp
//
// Cryptographic primitives for the RankGate Insane client. Every function here
// is chosen to compute byte-identical results to server/app/crypto_box.py so
// the native client and the Python server agree on every transcript byte.
//
//   * SHA-256                 -> libsodium crypto_hash_sha256
//   * HMAC-SHA256             -> libsodium crypto_auth_hmacsha256 (any key len)
//   * HKDF-SHA256 (RFC 5869)  -> built on HMAC-SHA256 (see kdf.hpp)
//   * BLAKE2b keyed/var-len   -> self-contained (libsodium rejects <16-byte
//                                digests; the challenge uses 3/4/8-byte ones,
//                                and the digest length is mixed into BLAKE2b's
//                                parameter block, so they are NOT truncations)
//   * X25519 ECDH             -> libsodium crypto_scalarmult[_base]
//   * Ed25519 verify          -> libsodium crypto_sign_verify_detached
//   * XChaCha20-Poly1305 IETF -> libsodium crypto_aead_xchacha20poly1305_ietf
//   * BLAKE2b-CTR keystream   -> obfuscates the VM bytecode blob at rest
#pragma once

#include <array>
#include <string>

#include "../common.hpp"

namespace rg::crypto {

// Must be called once at startup. Throws on libsodium init failure.
void init();

// -- hashing ----------------------------------------------------------------
Bytes sha256(const Bytes& data);

// Keyed, variable-length BLAKE2b (1..64 byte digest). key may be empty.
Bytes blake2b(const Bytes& data, const Bytes& key, size_t out_len);
inline Bytes blake2b(const Bytes& data, size_t out_len) {
    return blake2b(data, Bytes{}, out_len);
}

// -- MAC / KDF primitive ----------------------------------------------------
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// -- X25519 -----------------------------------------------------------------
struct X25519Keypair {
    Bytes priv;  // 32
    Bytes pub;   // 32
};
X25519Keypair x25519_keypair();              // random ephemeral
Bytes x25519_base(const Bytes& priv);        // priv -> public
Bytes x25519_shared(const Bytes& priv, const Bytes& peer_pub);

// -- Ed25519 ----------------------------------------------------------------
bool ed25519_verify(const Bytes& verify_pub, const Bytes& msg, const Bytes& sig);

// -- XChaCha20-Poly1305 IETF AEAD (24-byte nonce) ---------------------------
// Returns ciphertext; tag (16) is written to out_tag, matching the split
// authentication_tag field on the wire.
Bytes aead_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& plaintext,
                   const Bytes& aad, Bytes& out_tag);
// Throws std::runtime_error on authentication failure.
Bytes aead_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext,
                   const Bytes& tag, const Bytes& aad);

// -- BLAKE2b-CTR keystream + stream xor -------------------------------------
Bytes blake2b_ctr_keystream(const Bytes& key, size_t length, const Bytes& domain);
Bytes stream_xor(const Bytes& key, const Bytes& data, const Bytes& domain);

// -- misc -------------------------------------------------------------------
bool ct_equal(const Bytes& a, const Bytes& b);
Bytes random_bytes(size_t n);

}  // namespace rg::crypto
