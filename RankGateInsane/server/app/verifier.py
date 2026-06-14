"""License format + the 7-stage server-side validation for RankGate Insane.

Every check raises errors.ProofError on failure; the handler layer collapses
ALL of them into the single generic {"ok": false, "error": "invalid proof"}.

License string format (see docs/protocol.md, spec section 9):

    RG6-{B1}-{B2}-{B3}-{B4}-{B5}

Each block is RFC4648 base32 (no padding) of 5 bytes -> 8 chars, so the five
blocks decode to a 25-byte binary license structure:

    off size field
    --- ---- -----------------------------------------------------------
    0    1   version (== 6)
    1    4   username_hash_fragment  BLAKE2b(username_norm, key=FRAGMENT)[:4]
    5    8   proof_seed              (author-chosen; bound only via checksum)
    13   4   vm_seed                 (feeds the VM via MEM)
    17   1   parity                  XOR of payload[0:17]
    18   3   pseudo_timestamp        (decorative; NOT real-time dependent)
    21   4   checksum                BLAKE2b(payload[0:21], key=LICENSE_SECRET)[:4]

The checksum binds the license to the SERVER-ONLY LICENSE_SECRET; the fragment
binds it to the username. The same license therefore does not validate for a
different username.
"""

from __future__ import annotations

import base64
import unicodedata
from dataclasses import dataclass

from . import config
from . import crypto_box as cb
from . import vm_reference
from .errors import ProofError


# ===========================================================================
# Stage 1 -- username normalization / canonical encoding (ASCII-only)
# ===========================================================================
def normalize_username(raw: str) -> bytes:
    """Canonicalize a username. ASCII-only so the C++ client reproduces it
    without an ICU dependency: NFC, trim ASCII whitespace, lowercase A-Z."""
    s = unicodedata.normalize("NFC", raw).strip(" \t\r\n")
    if not (1 <= len(s) <= config.VM_USERNAME_CAP):
        raise ProofError("stage1", "username length out of range")
    out = bytearray()
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o > 0x7E:
            raise ProofError("stage1", "non-printable-ASCII username char")
        if 0x41 <= o <= 0x5A:       # A-Z -> a-z
            o += 0x20
        out.append(o)
    return bytes(out)


# ===========================================================================
# License build / encode / decode  (build is reused by tools/generate_license)
# ===========================================================================
@dataclass
class License:
    version: int
    fragment: bytes      # 4
    proof_seed: bytes    # 8
    vm_seed: bytes       # 4
    parity: int
    timestamp: bytes     # 3
    checksum: bytes      # 4
    raw: bytes           # full 25-byte struct

    def to_struct(self) -> bytes:
        return self.raw


def _fragment(username_norm: bytes) -> bytes:
    return cb.blake2b(username_norm, key=config.LICENSE_FRAGMENT_DOMAIN, size=4)


def _checksum(payload21: bytes) -> bytes:
    return cb.blake2b(config.LICENSE_CHECKSUM_DOMAIN + payload21,
                      key=config.LICENSE_SECRET, size=4)


def build_license_struct(username_norm: bytes) -> bytes:
    """Deterministically build a valid 25-byte license for a username, using
    the SERVER-ONLY LICENSE_SECRET. (Author tool path.)"""
    version = bytes([config.LICENSE_VERSION])
    fragment = _fragment(username_norm)
    proof_seed = cb.blake2b(b"proof-seed" + username_norm,
                            key=config.LICENSE_SECRET, size=8)
    vm_seed = cb.blake2b(b"vm-seed" + username_norm,
                         key=config.LICENSE_SECRET, size=4)
    payload17 = version + fragment + proof_seed + vm_seed
    parity = 0
    for b in payload17:
        parity ^= b
    timestamp = cb.blake2b(b"ts" + username_norm, size=3)  # decorative
    payload21 = payload17 + bytes([parity]) + timestamp
    checksum = _checksum(payload21)
    struct = payload21 + checksum
    assert len(struct) == config.LICENSE_STRUCT_SIZE
    return struct


def encode_license(struct: bytes) -> str:
    if len(struct) != config.LICENSE_STRUCT_SIZE:
        raise ValueError("license struct must be 25 bytes")
    blocks = []
    for i in range(0, 25, 5):
        blocks.append(base64.b32encode(struct[i:i + 5]).decode("ascii"))
    return config.LICENSE_PREFIX + "-" + "-".join(blocks)


def decode_license(license_str: str) -> bytes:
    parts = license_str.strip().split("-")
    if len(parts) != 6 or parts[0] != config.LICENSE_PREFIX:
        raise ProofError("stage2", "bad license layout")
    struct = bytearray()
    for blk in parts[1:]:
        if len(blk) != 8:
            raise ProofError("stage2", "bad license block length")
        try:
            struct += base64.b32decode(blk)
        except Exception as exc:  # noqa: BLE001
            raise ProofError("stage2", f"base32 decode: {exc}") from exc
    if len(struct) != config.LICENSE_STRUCT_SIZE:
        raise ProofError("stage2", "bad decoded length")
    return bytes(struct)


def parse_license(struct: bytes) -> License:
    return License(
        version=struct[0],
        fragment=struct[1:5],
        proof_seed=struct[5:13],
        vm_seed=struct[13:17],
        parity=struct[17],
        timestamp=struct[18:21],
        checksum=struct[21:25],
        raw=struct,
    )


# ===========================================================================
# Stage 2 -- license format + embedded checksum + username binding
# ===========================================================================
def validate_license(username_norm: bytes, struct: bytes) -> License:
    lic = parse_license(struct)
    if lic.version != config.LICENSE_VERSION:
        raise ProofError("stage2", "bad version")
    if not cb.ct_equal(lic.fragment, _fragment(username_norm)):
        raise ProofError("stage2", "username fragment mismatch")
    parity = 0
    for b in struct[0:17]:
        parity ^= b
    if parity != lic.parity:
        raise ProofError("stage2", "parity mismatch")
    if not cb.ct_equal(lic.checksum, _checksum(struct[0:21])):
        raise ProofError("stage2", "checksum mismatch")
    return lic


# ===========================================================================
# Stage 3 -- nonce-bound client proof #1
# ===========================================================================
def proof1_input(username_norm: bytes, license_struct: bytes,
                 vm_digest: bytes, vm_state_hash: bytes,
                 vm_path_id: int, vm_halt_code: int,
                 server_random: bytes, session_id: bytes,
                 transcript_prefix: bytes) -> bytes:
    return (
        b"RG6-PROOF1/v6"
        + len(username_norm).to_bytes(2, "big") + username_norm
        + license_struct
        + vm_digest + vm_state_hash
        + vm_path_id.to_bytes(4, "big") + vm_halt_code.to_bytes(4, "big")
        + server_random + session_id + transcript_prefix
    )


def compute_proof1(k_proof1: bytes, *args) -> bytes:
    return cb.hmac_sha256(k_proof1, proof1_input(*args))


def validate_proof1(k_proof1: bytes, supplied: bytes, *args) -> None:
    if not cb.ct_equal(supplied, compute_proof1(k_proof1, *args)):
        raise ProofError("stage3", "client proof1 mismatch")


# ===========================================================================
# Stage 4 -- VM-derived digest (server recomputes the VM independently)
# ===========================================================================
def validate_vm(username_norm: bytes, license_struct: bytes,
                server_random: bytes, session_id: bytes,
                transcript_prefix: bytes, session_nonce: bytes,
                supplied: vm_reference.VMResult) -> None:
    expected = vm_reference.run_vm(username_norm, license_struct, server_random,
                                   session_id, transcript_prefix, session_nonce)
    if not (expected == supplied):
        raise ProofError("stage4", "vm result mismatch")


# ===========================================================================
# Stage 6 -- client proof #2 (bound to server challenge material)
# ===========================================================================
def proof2_input(server_challenge2: bytes, server_random: bytes,
                 server_pub: bytes, vm_digest: bytes,
                 transcript_prefix: bytes) -> bytes:
    return (b"RG6-PROOF2/v6" + server_challenge2 + server_random
            + server_pub + vm_digest + transcript_prefix)


def compute_proof2(k_proof2: bytes, *args) -> bytes:
    return cb.hmac_sha256(k_proof2, proof2_input(*args))


def validate_proof2(k_proof2: bytes, supplied: bytes, *args) -> None:
    if not cb.ct_equal(supplied, compute_proof2(k_proof2, *args)):
        raise ProofError("stage6", "client proof2 mismatch")
