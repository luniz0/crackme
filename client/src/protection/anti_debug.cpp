// path: RankGateInsane/client/src/protection/anti_debug.cpp
#include "anti_debug.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdint>

#include "anti_tamper.hpp"

namespace rg::protection {

namespace {

bool remote_debugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != FALSE;
}

bool peb_being_debugged() {
#if defined(_M_X64)
    auto peb = reinterpret_cast<const BYTE*>(__readgsqword(0x60));
    return peb && peb[2] != 0;  // PEB.BeingDebugged
#else
    return false;
#endif
}

// Hardware breakpoints live in the debug registers Dr0..Dr3 (enabled via Dr7).
bool hardware_breakpoints() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0xFF);
}

// Coarse timing check: a trivial loop that should be fast; single-stepping or a
// heavy debugger inflates it. Pure measurement, no side effects.
bool timing_anomaly() {
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    volatile uint64_t acc = 0;
    for (int i = 0; i < 100000; ++i) acc += static_cast<uint64_t>(i) * 2654435761u;
    QueryPerformanceCounter(&b);
    double ms = 1000.0 * static_cast<double>(b.QuadPart - a.QuadPart) /
                static_cast<double>(f.QuadPart);
    (void)acc;
    return ms > 50.0;  // generous threshold; harmless if it trips
}

}  // namespace

void run_guards(bool verbose) {
    // All checks are harmless, in-process, and read-only. They are reported and
    // are non-fatal in this build; they never alter the protocol outcome.
    bool dbg = IsDebuggerPresent();
    bool remote = remote_debugger();
    bool peb = peb_being_debugged();
    bool hwbp = hardware_breakpoints();
    bool slow = timing_anomaly();
    TamperReport tr = run_anti_tamper();

    bool watched = dbg || remote || peb || hwbp || slow;

    if (verbose) {
        std::printf("[*] guards: IsDebuggerPresent=%d remote=%d peb=%d hwbp=%d "
                    "timing=%d\n", dbg, remote, peb, hwbp, slow);
        std::printf("[*] guards: const_table_ok=%d text_cs=%08x int3=%u\n",
                    tr.const_table_ok, tr.text_checksum, tr.int3_count);
    }
    if (watched && verbose) {
        std::printf("[*] guards: analysis environment detected (harmless, "
                    "continuing)\n");
    }
}

}  // namespace rg::protection
