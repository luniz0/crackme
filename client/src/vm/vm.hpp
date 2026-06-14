// path: RankGateInsane/client/src/vm/vm.hpp
//
// The RankGate Insane virtual machine (client engine). A faithful port of
// server/app/vm_reference.py: 16 x u64 registers, a call stack, ZF/CF/SF
// flags, variable-length table-dispatched instructions, 64-word memory loaded
// from the session inputs, a per-session handler permutation derived from the
// session nonce, and a structured output the server recomputes independently.
#pragma once

#include "../common.hpp"

namespace rg::vm {

struct VMResult {
    Bytes vm_digest;       // 32  (R12..R15 big-endian)
    Bytes vm_state_hash;   // 32  (BLAKE2b of full final machine state)
    uint32_t vm_path_id;   // FNV-style fold of branch decisions
    uint32_t vm_halt_code; // HALT operand mixed with path id
};

// Decrypts the embedded bytecode, packs VM memory from the session inputs,
// runs to HALT, and returns the structured result. session_nonce drives the
// handler permutation (== server_random in the live protocol).
VMResult run_vm(const Bytes& username_norm, const Bytes& license_struct,
                const Bytes& server_random, const Bytes& session_id,
                const Bytes& transcript_prefix, const Bytes& session_nonce);

}  // namespace rg::vm
