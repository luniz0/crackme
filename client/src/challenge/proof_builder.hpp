// path: RankGateInsane/client/src/challenge/proof_builder.hpp
//
// Nonce-bound client proofs. Byte-for-byte identical to server/app/verifier.py
// (proof1_input/proof2_input + HMAC-SHA256). The proofs bind the username,
// license, VM output, server challenge material, and transcript prefix together
// so the server can recompute and compare.
#pragma once

#include "../common.hpp"
#include "../vm/vm.hpp"

namespace rg::challenge {

Bytes compute_proof1(const Bytes& k_proof1, const Bytes& username_norm,
                     const Bytes& license_struct, const vm::VMResult& vm,
                     const Bytes& server_random, const Bytes& session_id,
                     const Bytes& transcript_prefix);

Bytes compute_proof2(const Bytes& k_proof2, const Bytes& server_challenge2,
                     const Bytes& server_random, const Bytes& server_pub,
                     const Bytes& vm_digest, const Bytes& transcript_prefix);

}  // namespace rg::challenge
