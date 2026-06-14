// path: RankGateInsane/client/src/protection/decoys.cpp
#include "decoys.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

#include "obfuscation.hpp"
#include "opaque.hpp"

namespace rg::protection {

namespace {

// -- Decoy #4: a fake "VM bytecode" blob that looks just like the real one in
//    src/vm/bytecode_blob.cpp, but is never decrypted or executed. ----------
const unsigned char kDecoyBytecode[] = {
    0x10, 0x00, 0x2a, 0x33, 0x01, 0x02, 0x60, 0x00, 0x18, 0x70, 0x0c, 0x0d,
    0x0e, 0x40, 0x03, 0x11, 0x50, 0x04, 0x05, 0x61, 0x00, 0x2c, 0x33, 0x06,
    0x06, 0x71, 0x0c, 0x0c, 0x31, 0x07, 0x07, 0x08, 0xf0, 0x99, 0x21, 0x09,
    0x0a, 0x20, 0x0b, 0x0c, 0x33, 0x0d, 0x0e, 0x0f, 0x64, 0x42, 0x01, 0x02,
    0x03, 0x70, 0x0a, 0x0b, 0x0c, 0x36, 0x05, 0x06, 0xf0, 0x7e, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
};

// -- Decoy #5: a decoy flag, hidden only by a single-byte XOR so a casual
//    analyst recovers it quickly and then chases a dead end. -----------------
std::string decoy_flag() {
    static const unsigned char enc[] = {
        // "FLAG{decoy_this_is_not_the_real_flag}" ^ 0x5A
        0x1c, 0x16, 0x1b, 0x1d, 0x21, 0x3e, 0x3f, 0x39, 0x35, 0x23, 0x05, 0x2e,
        0x32, 0x33, 0x39, 0x05, 0x33, 0x29, 0x05, 0x34, 0x35, 0x2e, 0x05, 0x2e,
        0x32, 0x3f, 0x05, 0x28, 0x3f, 0x3b, 0x36, 0x05, 0x1c, 0x16, 0x1b, 0x1d,
        0x27,
    };
    std::string s;
    s.reserve(sizeof(enc));
    for (unsigned char c : enc) s.push_back(static_cast<char>(c ^ 0x5A));
    return s;
}

// -- Decoy #1: a fake local serial checker. Computes a believable checksum over
//    the license and "binds" it to the username, but the verdict is discarded.
bool fake_serial_check(const std::string& username, const std::string& license) {
    uint32_t acc = 0x811C9DC5u;  // looks like the real FNV basis used in the VM
    for (char c : license) acc = obf::blinded32(acc, static_cast<uint8_t>(c), 0x9E3779B9u);
    uint32_t ubind = 0;
    for (char c : username) ubind = static_cast<uint32_t>(obf::mba_add(ubind, static_cast<uint8_t>(c)));
    return ((acc ^ ubind) & 0xFFFFu) == 0x1337u;  // arbitrary, meaningless gate
}

// -- Decoy #4 (cont.): a fake "disassemble + checksum" of the decoy blob. -----
uint32_t fake_vm_trace() {
    uint32_t cs = 0;
    for (unsigned char b : kDecoyBytecode) cs = static_cast<uint32_t>(obf::mba_add(cs, b));
    return cs;
}

}  // namespace

// Plain FNV-1a over the raw inputs -- looks like the real "license hash" gate.
uint32_t input_hash(const std::string& a, const std::string& b) {
    uint32_t h = 0x811C9DC5u;
    auto fold = [&](const std::string& s) {
        for (char c : s) { h ^= static_cast<uint8_t>(c); h = static_cast<uint32_t>(obf::mba_add(h * 0x01000193u, 0)); }
    };
    fold(a);
    h ^= 0x7Cu;  // separator
    fold(b);
    return h;
}

int decoy_preflight(const std::string& username, const std::string& license,
                    bool verbose) {
    // -- Decoy #3: a fake endpoint route, left discoverable on purpose. -------
    const char* kDecoyRoute = "/api/v1/redeem";  // not a real route

    bool serial_ok = fake_serial_check(username, license);
    uint32_t trace = fake_vm_trace();

    // -- Decoy #2: a fake hardcoded "unlock" branch gated on an input hash.
    //    The comparison is input-dependent (so the compiler keeps the branch
    //    and its strings), and effectively never matches for a real license --
    //    but it looks exactly like the kind of magic check a solver hunts for. -
    int code = static_cast<int>(trace ^ (serial_ok ? 0xA5u : 0x5Au));
    if (input_hash(username, license) == 0x5A1C9E37u) {
        std::string tok = decoy_flag();
        std::printf("[unlock] %s via %s\n", tok.c_str(), kDecoyRoute);  // dead in practice
        code ^= static_cast<int>(tok.size());
    }

    if (verbose) {
        std::printf("[*] preflight: local checks complete (code=%08x)\n", code);
    }
    return code;  // ignored by the caller; the real flow is in net/protocol.cpp
}

}  // namespace rg::protection
