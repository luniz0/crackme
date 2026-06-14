"""Configuration, domain constants, and server key material for RankGate Insane.

SECURITY / DISTRIBUTION NOTE
----------------------------
This is a *local-only educational* challenge. The "server secrets" below
(Ed25519 signing seed, license HMAC secret) are deterministic defaults so the
reference solver and the documentation are reproducible out of the box.

For a harder distribution, the author can override every secret via environment
variables (see below) and hand players only a pre-generated (username, license)
pair -- never the secrets. The challenge difficulty does NOT rest on these
secrets staying hidden; it rests on understanding the client, the binary
protocol, the VM, and how the proof is assembled.

What the CLIENT is allowed to know (public / discoverable):
  * SERVER_SIGN_PK            (Ed25519 public verify key, served at /public-key)
  * VM_BLOB_KEY               (obfuscation key for the bytecode blob at rest)
  * every domain-separation constant in this file

What stays SERVER-ONLY (never embedded in the client binary):
  * SERVER_SIGN_SK            (Ed25519 signing private key)
  * LICENSE_SECRET            (HMAC key that authenticates a license checksum)
"""

from __future__ import annotations

import os

from nacl import signing


# ---------------------------------------------------------------------------
# Wire / protocol constants
# ---------------------------------------------------------------------------
MAGIC = b"RG6\x00"          # 4 bytes
PROTO_VERSION = 6           # 1 byte
LISTEN_PORT = 31337

# message_type enumeration (1 byte on the wire)
MT_HELLO = 0x01
MT_SERVER_CHALLENGE = 0x02
MT_CLIENT_PROOF_1 = 0x03
MT_SERVER_PROOF_1 = 0x04
MT_CLIENT_PROOF_2 = 0x05
MT_FINALIZE = 0x06           # carried as CLIENT_PROOF_2's role at /finalize
MT_SEALED_FLAG = 0x07
MT_ERROR = 0xFF

# Fixed field sizes (bytes) -- see docs/protocol.md
SZ_MAGIC = 4
SZ_VERSION = 1
SZ_MSGTYPE = 1
SZ_SESSION_ID = 16
SZ_COUNTER = 8
SZ_NONCE = 24               # XChaCha20-Poly1305 IETF nonce
SZ_PAYLEN = 4
SZ_AUTHTAG = 16             # Poly1305 tag (split out of combined AEAD output)
SZ_TRANSCRIPT_MAC = 32      # HMAC-SHA256

HEADER_SIZE = (
    SZ_MAGIC + SZ_VERSION + SZ_MSGTYPE + SZ_SESSION_ID
    + SZ_COUNTER + SZ_NONCE + SZ_PAYLEN
)

# ---------------------------------------------------------------------------
# Transcript / KDF domain separation strings
# ---------------------------------------------------------------------------
TRANSCRIPT_SEED = b"RG6-TRANSCRIPT/v6"
BOOTSTRAP_MAC_LABEL = b"RG6-BOOTSTRAP-MAC/v6"   # MAC key for pre-ECDH frames

HKDF_C2S = b"RG6 c2s aead"
HKDF_S2C = b"RG6 s2c aead"
HKDF_MAC = b"RG6 transcript mac"
HKDF_PROOF1 = b"RG6 client proof1"
HKDF_SPROOF1 = b"RG6 server proof1"
HKDF_PROOF2 = b"RG6 client proof2"
HKDF_SEAL = b"RG6 final seal"

SIGN_CONTEXT = b"RG6-SERVER-CHALLENGE/v6"        # Ed25519 signed-data prefix

# ---------------------------------------------------------------------------
# License domain constants
# ---------------------------------------------------------------------------
LICENSE_PREFIX = "RG6"
LICENSE_VERSION = 6
LICENSE_FRAGMENT_DOMAIN = b"RG6-LICENSE-FRAGMENT/v6"
LICENSE_CHECKSUM_DOMAIN = b"RG6-LICENSE-CHECKSUM/v6"
LICENSE_STRUCT_SIZE = 25     # bytes, before base32 block encoding

# ---------------------------------------------------------------------------
# VM domain constants
# ---------------------------------------------------------------------------
VM_INPUT_DOMAIN = b"RG6-VM-INPUT/v6"
VM_BLOB_DOMAIN = b"RG6-VM-BLOB/v6"
VM_MEM_WORDS = 64            # 64 x u64 words of VM memory
VM_NUM_REGS = 16
VM_USERNAME_CAP = 64         # username bytes packed into VM memory (capped)

# ---------------------------------------------------------------------------
# Server key material (deterministic defaults, env-overridable)
# ---------------------------------------------------------------------------
def _seed32(env_name: str, default_text: str) -> bytes:
    """Return a 32-byte seed from hex env var, else from a fixed text default."""
    hexval = os.environ.get(env_name)
    if hexval:
        raw = bytes.fromhex(hexval)
        if len(raw) != 32:
            raise ValueError(f"{env_name} must be 32 bytes of hex (64 chars)")
        return raw
    # Deterministic default: BLAKE2b of a constant label -> 32 bytes.
    import hashlib
    return hashlib.blake2b(default_text.encode(), digest_size=32).digest()


# Ed25519 server signing key (SERVER-ONLY private; public is shippable).
SERVER_SIGN_SEED = _seed32("RG6_SIGN_SEED", "rankgate-insane-ed25519-signing-seed/v6")
_SIGNING_KEY = signing.SigningKey(SERVER_SIGN_SEED)
SERVER_SIGN_SK = _SIGNING_KEY                      # nacl SigningKey
SERVER_SIGN_PK = bytes(_SIGNING_KEY.verify_key)    # 32-byte public key (shippable)

# License HMAC secret (SERVER-ONLY).
LICENSE_SECRET = _seed32("RG6_LICENSE_SECRET", "rankgate-insane-license-hmac-secret/v6")

# VM bytecode-blob obfuscation key (NOT secret -- lives in client too, obfuscated).
VM_BLOB_KEY = _seed32("RG6_VM_BLOB_KEY", "rankgate-insane-vm-blob-obfuscation/v6")

# ---------------------------------------------------------------------------
# Runtime toggles
# ---------------------------------------------------------------------------
SERVER_DEBUG = os.environ.get("SERVER_DEBUG", "0") == "1"

# The flag. Sealed twice before it leaves the server; never sent in the clear.
FLAG = b"FLAG{rankgate_insane_protocol_vm_server_mastery}"
DECOY_FLAG = b"FLAG{decoy_this_is_not_the_real_flag}"
