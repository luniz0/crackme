// path: RankGateInsane/client/src/common.hpp
//
// Shared byte-buffer type and big-endian serialization helpers used across the
// whole client. The protocol is binary and big-endian on the wire, matching
// server/app/protocol.py, so these helpers are the single source of truth for
// integer<->bytes conversions.
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace rg {

using Bytes = std::vector<uint8_t>;

// -- concatenation ----------------------------------------------------------
inline void append(Bytes& dst, const Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
inline void append(Bytes& dst, const uint8_t* p, size_t n) {
    dst.insert(dst.end(), p, p + n);
}
inline Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    out.reserve(total);
    for (const auto& p : parts) append(out, p);
    return out;
}

// -- literals ---------------------------------------------------------------
inline Bytes str_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}
inline Bytes str_bytes(const char* s) {
    return Bytes(s, s + std::char_traits<char>::length(s));
}

// -- big-endian put ---------------------------------------------------------
inline Bytes be16(uint16_t v) {
    return {static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}
inline Bytes be32(uint32_t v) {
    return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
}
inline Bytes be64(uint64_t v) {
    Bytes out(8);
    for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
    return out;
}

// -- big-endian get ---------------------------------------------------------
inline uint16_t rd_be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t rd_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
inline uint64_t rd_be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

// -- slicing ----------------------------------------------------------------
inline Bytes slice(const Bytes& b, size_t off, size_t len) {
    if (off + len > b.size()) throw std::runtime_error("slice out of range");
    return Bytes(b.begin() + off, b.begin() + off + len);
}

}  // namespace rg
