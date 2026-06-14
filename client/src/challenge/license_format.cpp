// path: RankGateInsane/client/src/challenge/license_format.cpp
#include "license_format.hpp"

#include <array>
#include <stdexcept>

#include "../constants.hpp"

namespace rg::challenge {

namespace {

// RFC 4648 base32 decode of an 8-char block -> 5 bytes (no padding needed).
std::array<int8_t, 256> make_b32_rev() {
    std::array<int8_t, 256> r{};
    r.fill(-1);
    const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (int i = 0; i < 32; ++i) r[static_cast<uint8_t>(a[i])] = static_cast<int8_t>(i);
    return r;
}
const std::array<int8_t, 256> kB32 = make_b32_rev();

Bytes b32decode_block(const std::string& blk) {
    if (blk.size() != 8) throw std::runtime_error("license: bad block length");
    uint64_t acc = 0;
    for (char c : blk) {
        int8_t v = kB32[static_cast<uint8_t>(c)];
        if (v < 0) throw std::runtime_error("license: bad base32 char");
        acc = (acc << 5) | static_cast<uint64_t>(v);
    }
    // 8 * 5 = 40 bits = 5 bytes
    Bytes out(5);
    for (int i = 0; i < 5; ++i) out[i] = static_cast<uint8_t>(acc >> (32 - 8 * i));
    return out;
}

bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

}  // namespace

Bytes normalize_username(const std::string& raw) {
    // NFC over ASCII is the identity; trim ASCII whitespace.
    size_t b = 0, e = raw.size();
    while (b < e && is_ws(raw[b])) ++b;
    while (e > b && is_ws(raw[e - 1])) --e;
    std::string s = raw.substr(b, e - b);
    if (s.empty() || s.size() > cfg::VM_USERNAME_CAP)
        throw std::runtime_error("username length out of range");
    Bytes out;
    out.reserve(s.size());
    for (unsigned char ch : s) {
        if (ch < 0x20 || ch > 0x7E) throw std::runtime_error("non-printable username char");
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<unsigned char>(ch + 0x20);
        out.push_back(ch);
    }
    return out;
}

Bytes decode_license(const std::string& license_str) {
    // split on '-'
    std::vector<std::string> parts;
    std::string cur;
    for (char c : license_str) {
        if (is_ws(c)) continue;  // tolerate surrounding whitespace
        if (c == '-') { parts.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    parts.push_back(cur);

    if (parts.size() != 6 || parts[0] != cfg::LICENSE_PREFIX)
        throw std::runtime_error("license: bad layout");
    Bytes st;
    for (size_t i = 1; i < 6; ++i) append(st, b32decode_block(parts[i]));
    if (st.size() != cfg::LICENSE_STRUCT_SIZE)
        throw std::runtime_error("license: bad decoded length");
    if (st[0] != cfg::LICENSE_VERSION)
        throw std::runtime_error("license: bad version");
    return st;
}

}  // namespace rg::challenge
