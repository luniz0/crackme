// path: RankGateInsane/client/src/crypto/kdf.hpp
//
// HKDF-SHA256 (RFC 5869), implemented on top of HMAC-SHA256 so it is
// byte-identical to server/app/crypto_box.py (which also rolls its own).
#pragma once

#include "../common.hpp"

namespace rg::crypto {

Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm);
Bytes hkdf_expand(const Bytes& prk, const Bytes& info, size_t length);
Bytes hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info, size_t length = 32);

}  // namespace rg::crypto
