// path: RankGateInsane/client/src/net/binary_frame.cpp
#include "binary_frame.hpp"

#include <stdexcept>

#include "../constants.hpp"

namespace rg::net {

Bytes Frame::header() const {
    Bytes h;
    append(h, cfg::MAGIC);
    h.push_back(cfg::PROTO_VERSION);
    h.push_back(message_type);
    append(h, session_id);
    append(h, be64(counter));
    append(h, nonce);
    append(h, be32(static_cast<uint32_t>(encrypted_payload.size())));
    return h;
}

Bytes Frame::pre_mac() const {
    Bytes b = header();
    append(b, encrypted_payload);
    append(b, auth_tag);
    return b;
}

Bytes Frame::serialize() const {
    Bytes b = pre_mac();
    append(b, transcript_mac);
    return b;
}

Frame Frame::parse(const Bytes& buf) {
    const size_t min = cfg::HEADER_SIZE + cfg::SZ_AUTHTAG + cfg::SZ_TRANSCRIPT_MAC;
    if (buf.size() < min) throw std::runtime_error("frame: too short");
    size_t off = 0;
    auto take = [&](size_t n) -> Bytes {
        if (off + n > buf.size()) throw std::runtime_error("frame: truncated");
        Bytes c(buf.begin() + off, buf.begin() + off + n);
        off += n;
        return c;
    };

    if (take(cfg::SZ_MAGIC) != cfg::MAGIC) throw std::runtime_error("frame: bad magic");
    if (take(cfg::SZ_VERSION)[0] != cfg::PROTO_VERSION)
        throw std::runtime_error("frame: bad version");
    Frame f;
    f.message_type = take(cfg::SZ_MSGTYPE)[0];
    f.session_id = take(cfg::SZ_SESSION_ID);
    f.counter = rd_be64(take(cfg::SZ_COUNTER).data());
    f.nonce = take(cfg::SZ_NONCE);
    uint32_t paylen = rd_be32(take(cfg::SZ_PAYLEN).data());
    if (paylen > (1u << 20)) throw std::runtime_error("frame: payload too large");
    f.encrypted_payload = take(paylen);
    f.auth_tag = take(cfg::SZ_AUTHTAG);
    f.transcript_mac = take(cfg::SZ_TRANSCRIPT_MAC);
    if (off != buf.size()) throw std::runtime_error("frame: trailing bytes");
    return f;
}

}  // namespace rg::net
