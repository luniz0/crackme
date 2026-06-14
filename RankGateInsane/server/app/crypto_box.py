"""Cryptographic primitives for RankGate Insane (server side).

Every primitive here is chosen so the C++ client (which links libsodium) and
this Python server (which links libsodium via PyNaCl) compute byte-identical
results. Where libsodium has no standard construction (HKDF-SHA256, HMAC over
arbitrary key lengths) we implement it explicitly so both languages agree.

Primitives
----------
  * X25519 ECDH                  -> nacl.bindings.crypto_scalarmult
  * Ed25519 detached sign/verify -> nacl.signing
  * XChaCha20-Poly1305 IETF AEAD -> nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*
  * BLAKE2b (keyed/unkeyed)      -> hashlib.blake2b  (== libsodium generichash)
  * SHA-256                      -> hashlib.sha256
  * HMAC-SHA256                  -> hmac (RFC 2104)
  * HKDF-SHA256                  -> RFC 5869, built on HMAC-SHA256
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

from nacl import bindings as _b
from nacl import signing as _signing


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake2b(data: bytes, *, key: bytes = b"", size: int = 32) -> bytes:
    return hashlib.blake2b(data, key=key, digest_size=size).digest()


# ---------------------------------------------------------------------------
# HMAC-SHA256 and HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# X25519 key agreement
# ---------------------------------------------------------------------------
def x25519_keypair(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (private, public). If seed is given, the private key is its
    clamped form for deterministic test vectors; otherwise random."""
    if seed is None:
        priv = _b.randombytes(_b.crypto_scalarmult_SCALARBYTES)
    else:
        if len(seed) != 32:
            raise ValueError("x25519 seed must be 32 bytes")
        priv = seed
    pub = _b.crypto_scalarmult_base(priv)
    return priv, pub


def x25519_shared(priv: bytes, peer_pub: bytes) -> bytes:
    return _b.crypto_scalarmult(priv, peer_pub)


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------
def ed25519_sign(signing_key: _signing.SigningKey, message: bytes) -> bytes:
    return signing_key.sign(message).signature  # 64-byte detached signature


def ed25519_verify(verify_pub: bytes, message: bytes, signature: bytes) -> bool:
    try:
        _signing.VerifyKey(verify_pub).verify(message, signature)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# XChaCha20-Poly1305 IETF AEAD (24-byte nonce)
#
# libsodium returns ciphertext||tag in combined mode. To match the explicit
# `authentication_tag` frame field we split the trailing 16 bytes out, and
# recombine on decrypt.
# ---------------------------------------------------------------------------
def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
                 ) -> tuple[bytes, bytes]:
    """Return (ciphertext, tag16)."""
    combined = _b.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key)
    return combined[:-16], combined[-16:]


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                 aad: bytes) -> bytes:
    """Inverse of aead_encrypt. Raises on auth failure."""
    combined = ciphertext + tag
    return _b.crypto_aead_xchacha20poly1305_ietf_decrypt(
        combined, aad, nonce, key)


# ---------------------------------------------------------------------------
# BLAKE2b-CTR keystream
#
# Used to obfuscate the VM bytecode blob at rest. Deterministic, keyed, and
# trivially identical between Python and C++ (both call BLAKE2b in a counter
# loop), so we avoid depending on a specific stream-cipher binding.
# ---------------------------------------------------------------------------
def blake2b_ctr_keystream(key: bytes, length: int, *, domain: bytes) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        block = blake2b(domain + counter.to_bytes(8, "big"), key=key, size=64)
        out += block
        counter += 1
    return out[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def stream_xor(key: bytes, data: bytes, *, domain: bytes) -> bytes:
    ks = blake2b_ctr_keystream(key, len(data), domain=domain)
    return xor_bytes(data, ks)


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------
def ct_equal(a: bytes, b: bytes) -> bool:
    return _hmac.compare_digest(a, b)
