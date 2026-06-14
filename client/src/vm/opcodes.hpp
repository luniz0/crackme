// path: RankGateInsane/client/src/vm/opcodes.hpp
//
// Canonical opcode values for the RankGate VM. Mirrors server/app/vm_reference.py.
#pragma once

#include <cstdint>

namespace rg::vm {

enum Op : uint8_t {
    NOP = 0x00,
    MOV_RI = 0x10,
    MOV_RR = 0x11,
    LOAD = 0x20,
    STORE = 0x21,
    ADD = 0x30,
    SUB = 0x31,
    MUL = 0x32,
    XOR = 0x33,
    AND = 0x34,
    OR = 0x35,
    NOT = 0x36,
    ROL = 0x40,
    ROR = 0x41,
    SHL = 0x42,
    SHR = 0x43,
    CMP = 0x50,
    CMOV = 0x51,
    JMP = 0x60,
    JZ = 0x61,
    JNZ = 0x62,
    CALL = 0x63,
    RET = 0x64,
    HASH_ROUND = 0x70,
    MIX = 0x71,
    HALT = 0xF0,
};

// CMOV condition codes
enum Cond : uint8_t { COND_ZF, COND_NZF, COND_CF, COND_NCF, COND_SF, COND_NSF };

// Flag bits
constexpr uint8_t FL_ZF = 1, FL_CF = 2, FL_SF = 4;

}  // namespace rg::vm
