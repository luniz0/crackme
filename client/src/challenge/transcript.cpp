// path: RankGateInsane/client/src/challenge/transcript.cpp
#include "transcript.hpp"

#include <stdexcept>

#include "../constants.hpp"
#include "../crypto/crypto.hpp"

namespace rg::challenge {

Transcript::Transcript() {
    state_ = crypto::sha256(str_bytes(cfg::TRANSCRIPT_SEED));
}

Bytes Transcript::mac_for(const Bytes& mac_key, const Bytes& frame_pre_mac) const {
    Bytes in = state_;
    append(in, frame_pre_mac);
    return crypto::hmac_sha256(mac_key, in);
}

void Transcript::absorb(const Bytes& full_frame) {
    Bytes in = state_;
    append(in, full_frame);
    state_ = crypto::sha256(in);
}

net::Frame Transcript::seal_frame(const Bytes& mac_key, uint8_t mt, const Bytes& sid,
                                  uint64_t counter, const Bytes& nonce,
                                  const Bytes& encrypted_payload,
                                  const Bytes& auth_tag) {
    net::Frame f;
    f.message_type = mt;
    f.session_id = sid;
    f.counter = counter;
    f.nonce = nonce;
    f.encrypted_payload = encrypted_payload;
    f.auth_tag = auth_tag;
    f.transcript_mac = mac_for(mac_key, f.pre_mac());
    absorb(f.serialize());
    return f;
}

void Transcript::open_frame(const Bytes& mac_key, const net::Frame& frame) {
    Bytes expected = mac_for(mac_key, frame.pre_mac());
    if (!crypto::ct_equal(expected, frame.transcript_mac))
        throw std::runtime_error("transcript MAC mismatch");
    absorb(frame.serialize());
}

}  // namespace rg::challenge
