// path: RankGateInsane/client/src/net/protocol.hpp
//
// Full client protocol orchestration: HELLO -> SERVER_CHALLENGE ->
// CLIENT_PROOF_1 -> SERVER_PROOF_1 -> CLIENT_PROOF_2 -> SEALED_FLAG, with
// rolling transcript binding, X25519/Ed25519 handshake, HKDF session keys, the
// VM, both nonce-bound proofs, and the double-sealed flag unwrap. Mirrors
// tools/solve_full_challenge.py.
#pragma once

#include <string>

#include "../common.hpp"

namespace rg::net {

struct ProtocolOptions {
    std::string server_url = "http://127.0.0.1:31337";
    bool verbose = false;
};

// Runs the whole session and returns the decrypted flag bytes.
// Throws std::runtime_error on any protocol/validation failure.
Bytes run_session(const ProtocolOptions& opt, const Bytes& username_norm,
                  const Bytes& license_struct);

}  // namespace rg::net
