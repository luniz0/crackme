// path: RankGateInsane/client/src/constants.hpp
//
// Wire / KDF / VM / license constants. This is the client-side mirror of
// server/app/config.py. Everything here is PUBLIC and discoverable by design;
// the challenge difficulty does not rest on these staying hidden. Server-only
// secrets (Ed25519 signing key, license HMAC secret) are NOT here.
#pragma once

#include <string>

#include "common.hpp"
#include "protection/encoded_strings.hpp"

namespace rg::cfg {

// -- wire ------------------------------------------------------------------
inline const Bytes MAGIC = {'R', 'G', '6', 0x00};
constexpr uint8_t PROTO_VERSION = 6;
constexpr int LISTEN_PORT = 31337;

// message_type enumeration
constexpr uint8_t MT_HELLO = 0x01;
constexpr uint8_t MT_SERVER_CHALLENGE = 0x02;
constexpr uint8_t MT_CLIENT_PROOF_1 = 0x03;
constexpr uint8_t MT_SERVER_PROOF_1 = 0x04;
constexpr uint8_t MT_CLIENT_PROOF_2 = 0x05;
constexpr uint8_t MT_FINALIZE = 0x06;
constexpr uint8_t MT_SEALED_FLAG = 0x07;
constexpr uint8_t MT_ERROR = 0xFF;

// fixed field sizes (bytes)
constexpr size_t SZ_MAGIC = 4;
constexpr size_t SZ_VERSION = 1;
constexpr size_t SZ_MSGTYPE = 1;
constexpr size_t SZ_SESSION_ID = 16;
constexpr size_t SZ_COUNTER = 8;
constexpr size_t SZ_NONCE = 24;
constexpr size_t SZ_PAYLEN = 4;
constexpr size_t SZ_AUTHTAG = 16;
constexpr size_t SZ_TRANSCRIPT_MAC = 32;
constexpr size_t HEADER_SIZE = SZ_MAGIC + SZ_VERSION + SZ_MSGTYPE + SZ_SESSION_ID +
                               SZ_COUNTER + SZ_NONCE + SZ_PAYLEN;

// -- domain-separation labels (compile-time encrypted; not present as plaintext
//    in the binary, and never sent on the wire -- they live inside HMAC/HKDF) -
inline const std::string TRANSCRIPT_SEED = RG_OBF("RG6-TRANSCRIPT/v6");
inline const std::string BOOTSTRAP_MAC_LABEL = RG_OBF("RG6-BOOTSTRAP-MAC/v6");

inline const std::string HKDF_C2S = RG_OBF("RG6 c2s aead");
inline const std::string HKDF_S2C = RG_OBF("RG6 s2c aead");
inline const std::string HKDF_MAC = RG_OBF("RG6 transcript mac");
inline const std::string HKDF_PROOF1 = RG_OBF("RG6 client proof1");
inline const std::string HKDF_SPROOF1 = RG_OBF("RG6 server proof1");
inline const std::string HKDF_PROOF2 = RG_OBF("RG6 client proof2");
inline const std::string HKDF_SEAL = RG_OBF("RG6 final seal");

inline const std::string SIGN_CONTEXT = RG_OBF("RG6-SERVER-CHALLENGE/v6");
inline const std::string PROOF1_LABEL = RG_OBF("RG6-PROOF1/v6");
inline const std::string PROOF2_LABEL = RG_OBF("RG6-PROOF2/v6");
inline const std::string SPROOF1_LABEL = RG_OBF("RG6-SPROOF1/v6");
inline const std::string SEAL_INFO = RG_OBF("RG6 seal");

// -- license ----------------------------------------------------------------
inline const std::string LICENSE_PREFIX = "RG6";  // visible in the license string
constexpr uint8_t LICENSE_VERSION = 6;
inline const std::string LICENSE_FRAGMENT_DOMAIN = RG_OBF("RG6-LICENSE-FRAGMENT/v6");
constexpr size_t LICENSE_STRUCT_SIZE = 25;

// -- VM ---------------------------------------------------------------------
inline const std::string VM_INPUT_DOMAIN = RG_OBF("RG6-VM-INPUT/v6");
inline const std::string VM_BLOB_DOMAIN = RG_OBF("RG6-VM-BLOB/v6");
constexpr size_t VM_MEM_WORDS = 64;
constexpr size_t VM_NUM_REGS = 16;
constexpr size_t VM_USERNAME_CAP = 64;
inline const std::string VM_PERM_LABEL = RG_OBF("RG6-VM-PERM/v6");
inline const std::string VM_PERM_KS_DOMAIN = RG_OBF("RG6-VM-PERM-KS/v6");

// VM bytecode-blob obfuscation key: deterministic default == BLAKE2b(label,32),
// matching config._seed32. Computed at runtime in vm.cpp (not a secret).
inline const std::string VM_BLOB_KEY_LABEL = RG_OBF("rankgate-insane-vm-blob-obfuscation/v6");

}  // namespace rg::cfg
