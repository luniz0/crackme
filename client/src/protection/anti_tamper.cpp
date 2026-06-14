// path: RankGateInsane/client/src/protection/anti_tamper.cpp
#include "anti_tamper.hpp"

#include <windows.h>

#include <array>

namespace rg::protection {

namespace {

// A fixed constant table. Its checksum is baked below; if anyone patches these
// bytes (or the expected value) the two disagree. This is the one check here
// that is genuinely self-verifying (the .text checks are reported only).
constexpr std::array<uint32_t, 8> kConstTable = {
    0x9E3779B9u, 0x85EBCA77u, 0xC2B2AE3Du, 0x27D4EB2Fu,
    0x165667B1u, 0xD1B54A33u, 0x811C9DC5u, 0x01000193u,
};

constexpr uint32_t const_table_expected() {
    uint32_t s = 0x12345678u;
    for (uint32_t v : kConstTable) s = (s ^ v) * 0x01000193u + 0xABCDu;
    return s;
}

// Locate this module's .text section [base+VA, size).
bool find_text(const BYTE*& start, size_t& size) {
    auto base = reinterpret_cast<const BYTE*>(GetModuleHandleW(nullptr));
    if (!base) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& s = sec[i];
        if (std::memcmp(s.Name, ".text", 5) == 0) {
            start = base + s.VirtualAddress;
            size = s.Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

}  // namespace

TamperReport run_anti_tamper() {
    TamperReport r;

    uint32_t s = 0x12345678u;
    for (uint32_t v : kConstTable) s = (s ^ v) * 0x01000193u + 0xABCDu;
    r.const_table_ok = (s == const_table_expected());

    const BYTE* text = nullptr;
    size_t n = 0;
    if (find_text(text, n)) {
        uint32_t cs = 0x811C9DC5u;
        uint32_t int3 = 0;
        for (size_t i = 0; i < n; ++i) {
            cs = (cs ^ text[i]) * 0x01000193u;
            if (text[i] == 0xCC) ++int3;
        }
        r.text_checksum = cs;
        r.int3_count = int3;
    }
    return r;
}

}  // namespace rg::protection
