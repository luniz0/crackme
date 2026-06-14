// path: RankGateInsane/client/tests/selftest_vm.cpp
//
// VM parity self-test: runs the client VM over fixed inputs and compares the
// structured output to the Python reference (tools/_gen_vm_vectors.py). The
// Python side used the server's bytecode blob; agreement proves the C++ engine
// AND the embedded blob match the server.
#include <cstdio>
#include <string>

#include "../src/crypto/crypto.hpp"
#include "../src/vm/vm.hpp"
#include "vm_vectors.h"

using namespace rg;

static std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t x : b) { s += d[x >> 4]; s += d[x & 15]; }
    return s;
}

int main() {
    crypto::init();
    using namespace rg::vmvec;

    vm::VMResult r = vm::run_vm(kUsername, kLicense, kServerRandom, kSessionId,
                                kTranscriptPrefix, kServerRandom);
    int fail = 0;
    auto eq = [&](const char* n, const Bytes& g, const Bytes& w) {
        if (g == w) { std::printf("  [ok] %s\n", n); }
        else { std::printf("  [FAIL] %s\n   got : %s\n   want: %s\n", n,
                           hex(g).c_str(), hex(w).c_str()); ++fail; }
    };
    auto eqi = [&](const char* n, uint32_t g, uint32_t w) {
        if (g == w) { std::printf("  [ok] %s = 0x%08x\n", n, g); }
        else { std::printf("  [FAIL] %s got 0x%08x want 0x%08x\n", n, g, w); ++fail; }
    };

    std::printf("RankGate VM parity self-test (vs Python reference VM)\n");
    eq("vm_digest", r.vm_digest, kVmDigest);
    eq("vm_state_hash", r.vm_state_hash, kVmStateHash);
    eqi("vm_path_id", r.vm_path_id, kVmPathId);
    eqi("vm_halt_code", r.vm_halt_code, kVmHaltCode);

    std::printf("%s (%d failures)\n", fail ? "VM SELFTEST FAILED" : "VM PARITY OK", fail);
    return fail ? 1 : 0;
}
