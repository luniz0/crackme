// path: RankGateInsane/client/src/protection/anti_tamper.hpp
//
// Challenge-only, harmless, in-process self-integrity checks:
//   * a constant-table checksum (detects a patched constant table),
//   * a checksum over this module's own .text section (reported), and
//   * a software-breakpoint (0xCC) scan of .text.
// Nothing here modifies state or touches other processes; all are reported and
// (in this build) non-fatal, and all are skipped under --no-protection.
#pragma once

#include <cstdint>

namespace rg::protection {

struct TamperReport {
    bool const_table_ok = true;   // baked constant table unmodified
    uint32_t text_checksum = 0;   // checksum over own .text section
    uint32_t int3_count = 0;      // 0xCC bytes in .text (note: MSVC pads with 0xCC)
};

TamperReport run_anti_tamper();

}  // namespace rg::protection
