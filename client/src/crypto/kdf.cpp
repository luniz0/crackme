// path: RankGateInsane/client/src/crypto/kdf.cpp
#include "kdf.hpp"

#include "crypto.hpp"

namespace rg::crypto {

Bytes hkdf_extract(const Bytes& salt, const Bytes& ikm) {
    Bytes s = salt;
    if (s.empty()) s = Bytes(32, 0);
    return hmac_sha256(s, ikm);
}

Bytes hkdf_expand(const Bytes& prk, const Bytes& info, size_t length) {
    Bytes out;
    Bytes t;
    uint8_t counter = 1;
    while (out.size() < length) {
        Bytes in = t;
        append(in, info);
        in.push_back(counter);
        t = hmac_sha256(prk, in);
        append(out, t);
        counter++;
    }
    out.resize(length);
    return out;
}

Bytes hkdf(const Bytes& salt, const Bytes& ikm, const Bytes& info, size_t length) {
    return hkdf_expand(hkdf_extract(salt, ikm), info, length);
}

}  // namespace rg::crypto
