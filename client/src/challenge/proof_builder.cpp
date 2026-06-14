// path: RankGateInsane/client/src/challenge/proof_builder.cpp
#include "proof_builder.hpp"

#include "../constants.hpp"
#include "../crypto/crypto.hpp"

namespace rg::challenge {

Bytes compute_proof1(const Bytes& k_proof1, const Bytes& username_norm,
                     const Bytes& license_struct, const vm::VMResult& vm,
                     const Bytes& server_random, const Bytes& session_id,
                     const Bytes& transcript_prefix) {
    Bytes in;
    append(in, str_bytes(cfg::PROOF1_LABEL));
    append(in, be16(static_cast<uint16_t>(username_norm.size())));
    append(in, username_norm);
    append(in, license_struct);
    append(in, vm.vm_digest);
    append(in, vm.vm_state_hash);
    append(in, be32(vm.vm_path_id));
    append(in, be32(vm.vm_halt_code));
    append(in, server_random);
    append(in, session_id);
    append(in, transcript_prefix);
    return crypto::hmac_sha256(k_proof1, in);
}

Bytes compute_proof2(const Bytes& k_proof2, const Bytes& server_challenge2,
                     const Bytes& server_random, const Bytes& server_pub,
                     const Bytes& vm_digest, const Bytes& transcript_prefix) {
    Bytes in;
    append(in, str_bytes(cfg::PROOF2_LABEL));
    append(in, server_challenge2);
    append(in, server_random);
    append(in, server_pub);
    append(in, vm_digest);
    append(in, transcript_prefix);
    return crypto::hmac_sha256(k_proof2, in);
}

}  // namespace rg::challenge
