// path: RankGateInsane/client/src/protection/anti_debug.hpp
//
// Challenge-only, harmless, local-only anti-analysis guards. They never alter
// system state, never touch other processes, and can be fully disabled with
// --no-protection. In this Part-1 build the guards are observational (they do
// not abort the run); later parts wire them into the validation flow.
#pragma once

namespace rg::protection {

// Runs the enabled guards. `verbose` prints what was checked.
void run_guards(bool verbose);

}  // namespace rg::protection
