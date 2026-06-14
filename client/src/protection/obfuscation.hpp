// path: RankGateInsane/client/src/protection/obfuscation.hpp
//
// Lightweight, harmless obfuscation helpers: mixed boolean-arithmetic (MBA)
// rewrites of simple operations, and constant blinding / split-constant
// reconstruction. These compute ordinary results via non-obvious expressions to
// slow down static reading. They are NOT a security boundary.
#pragma once

#include <cstdint>

#include "opaque.hpp"

namespace rg::obf {

// MBA identity for addition:  a + b == (a ^ b) + 2*(a & b)
inline uint64_t mba_add(uint64_t a, uint64_t b) {
    return (a ^ b) + 2u * (a & b);
}

// MBA identity for xor:  a ^ b == (a | b) - (a & b)
inline uint64_t mba_xor(uint64_t a, uint64_t b) {
    return (a | b) - (a & b);
}

// Reconstruct a 32-bit constant from split halves combined with arithmetic, so
// the literal never appears whole in the instruction stream.
inline uint32_t blinded32(uint32_t hi_split, uint32_t lo_split, uint32_t blind) {
    return static_cast<uint32_t>(mba_add(hi_split ^ blind, lo_split) ^ blind);
}

}  // namespace rg::obf
