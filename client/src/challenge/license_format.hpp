// path: RankGateInsane/client/src/challenge/license_format.hpp
//
// Username canonicalization and license decoding, matching server/app/verifier.py.
//
// License string:  RG6-{B1}-{B2}-{B3}-{B4}-{B5}
// Each block is RFC4648 base32 (no padding) of 5 bytes -> 8 chars; the five
// blocks decode to the 25-byte license structure:
//   version(1) fragment(4) proof_seed(8) vm_seed(4) parity(1) timestamp(3) checksum(4)
#pragma once

#include <string>

#include "../common.hpp"

namespace rg::challenge {

// Stage-1 canonical form: NFC (ASCII-only here), trim ASCII whitespace,
// require printable ASCII, lowercase A-Z. Throws on invalid input.
Bytes normalize_username(const std::string& raw);

// Decode "RG6-...-..." into the 25-byte license struct. Throws on bad layout.
Bytes decode_license(const std::string& license_str);

}  // namespace rg::challenge
