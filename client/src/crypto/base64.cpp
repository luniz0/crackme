// path: RankGateInsane/client/src/crypto/base64.cpp
#include "base64.hpp"

#include <array>

namespace rg::crypto {

namespace {
constexpr char kAlpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<int8_t, 256> make_rev() {
    std::array<int8_t, 256> r{};
    r.fill(-1);
    for (int i = 0; i < 64; ++i) r[static_cast<uint8_t>(kAlpha[i])] = static_cast<int8_t>(i);
    return r;
}
const std::array<int8_t, 256> kRev = make_rev();
}  // namespace

std::string b64encode(const Bytes& data) {
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += kAlpha[(n >> 18) & 63];
        out += kAlpha[(n >> 12) & 63];
        out += kAlpha[(n >> 6) & 63];
        out += kAlpha[n & 63];
    }
    size_t rem = data.size() - i;
    if (rem == 1) {
        uint32_t n = data[i] << 16;
        out += kAlpha[(n >> 18) & 63];
        out += kAlpha[(n >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += kAlpha[(n >> 18) & 63];
        out += kAlpha[(n >> 12) & 63];
        out += kAlpha[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

Bytes b64decode(const std::string& text) {
    Bytes out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' ) break;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int8_t v = kRev[static_cast<uint8_t>(c)];
        if (v < 0) throw std::runtime_error("base64: invalid character");
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

}  // namespace rg::crypto
