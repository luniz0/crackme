// path: RankGateInsane/client/src/net/binary_frame.hpp
//
// The binary protocol frame. Byte-for-byte identical to server/app/protocol.py
// (Frame). All integers big-endian. This is NOT JSON; the HTTP body is just
// base64 of serialize().
//
//   magic(4) version(1) msgtype(1) session_id(16) counter(8) nonce(24)
//   paylen(4) | encrypted_payload(N) | auth_tag(16) | transcript_mac(32)
//
//   pre_mac = header(58) || encrypted_payload || auth_tag
//   AAD     = header(58)
//   full    = pre_mac || transcript_mac
#pragma once

#include "../common.hpp"

namespace rg::net {

struct Frame {
    uint8_t message_type = 0;
    Bytes session_id;        // 16
    uint64_t counter = 0;
    Bytes nonce;             // 24
    Bytes encrypted_payload;
    Bytes auth_tag;          // 16
    Bytes transcript_mac;    // 32

    Bytes header() const;
    Bytes pre_mac() const;
    Bytes serialize() const;

    static Frame parse(const Bytes& buf);
};

}  // namespace rg::net
