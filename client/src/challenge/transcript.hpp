// path: RankGateInsane/client/src/challenge/transcript.hpp
//
// Rolling SHA-256 transcript with an HMAC-SHA256 framing MAC. Identical to
// server/app/protocol.py Transcript: every frame's MAC commits to all prior
// frames, so a single tampered byte anywhere breaks the chain.
//
//   T0     = SHA256(TRANSCRIPT_SEED)
//   mac_i  = HMAC-SHA256(k_mac, T_{i-1} || pre_mac_i)
//   T_i    = SHA256(T_{i-1} || full_i)
#pragma once

#include "../common.hpp"
#include "../net/binary_frame.hpp"

namespace rg::challenge {

class Transcript {
public:
    Transcript();

    const Bytes& state() const { return state_; }

    Bytes mac_for(const Bytes& mac_key, const Bytes& frame_pre_mac) const;
    void absorb(const Bytes& full_frame);

    // Build an outgoing frame with a correct MAC, then absorb it.
    net::Frame seal_frame(const Bytes& mac_key, uint8_t mt, const Bytes& sid,
                          uint64_t counter, const Bytes& nonce,
                          const Bytes& encrypted_payload, const Bytes& auth_tag);

    // Verify an incoming frame's MAC (throws on mismatch), then absorb it.
    void open_frame(const Bytes& mac_key, const net::Frame& frame);

private:
    Bytes state_;
};

}  // namespace rg::challenge
