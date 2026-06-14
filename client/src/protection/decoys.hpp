// path: RankGateInsane/client/src/protection/decoys.hpp
//
// Decoy paths. These are deliberately plausible-looking but irrelevant: a fake
// local serial checker, a fake hardcoded success branch, a fake endpoint route,
// a fake VM bytecode blob, and a decoy flag. They waste an analyst's time
// without making the challenge unfair, and NONE of them affect the real
// protocol in net/protocol.cpp.
//
// Design note: unlike the real domain labels (strongly encrypted via RG_OBF),
// the decoy artifacts are only lightly hidden -- they are MEANT to be found.
#pragma once

#include <string>

namespace rg::protection {

// Runs the decoy preflight. Result is intentionally meaningless and never gates
// the real flow. Returns a throwaway code so the calls are not optimized away.
int decoy_preflight(const std::string& username, const std::string& license,
                    bool verbose);

}  // namespace rg::protection
