// path: RankGateInsane/client/src/protection/opaque.hpp
//
// Opaque predicates: expressions whose value is mathematically constant but not
// obvious to a decompiler, seeded from a volatile so the optimizer cannot fold
// them. Used to make decoy branches look statically reachable while never
// executing, and to thread harmless control-flow noise through validation.
#pragma once

namespace rg::obf {

// Volatile seed prevents constant propagation of the predicates below.
inline volatile int g_opaque_seed = 0x1337;

inline long long opaque_x() {
    return static_cast<long long>(g_opaque_seed) | 1ll;  // arbitrary runtime value
}

// x*(x+1) is always even  ->  always true.
inline bool opaque_true() {
    long long x = opaque_x();
    return ((x * (x + 1)) % 2) == 0;
}

// x*(x+1) is even, +1 makes it odd  ->  %2 never 0  ->  always false.
inline bool opaque_false() {
    long long x = opaque_x();
    return ((x * x + x + 1) % 2) == 0;
}

}  // namespace rg::obf
