"""Reference implementation of the RankGate Insane virtual machine.

The VM is the heart of the challenge. The C++ client embeds an obfuscated copy
of the same bytecode and an equivalent engine; this module lets the server
recompute the expected VM output independently and compare.

Architecture (see docs/vm_design.md):
  * 16 virtual registers R0..R15 (64-bit, wrap-around arithmetic)
  * a virtual stack (for CALL/RET)
  * virtual flags: ZF, CF, SF
  * instruction pointer into a flat bytecode array
  * VM memory: 64 x u64 words, pre-loaded from the session inputs
  * variable-length instructions, table-dispatched
  * a runtime handler-table permutation derived from the session nonce
    (reorders where handlers live in memory; semantics are unchanged, so the
     reference and client agree, but a debugger sees a per-session table)

Structured output:
  * vm_digest      (32 bytes)  -- R12..R15 serialized big-endian
  * vm_state_hash  (32 bytes)  -- BLAKE2b over the full final machine state
  * vm_path_id     (u32)       -- FNV-style fold of every branch decision
  * vm_halt_code   (u32)       -- HALT operand mixed with the path id
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from . import crypto_box as cb

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

# ---------------------------------------------------------------------------
# Opcode table (canonical values). Variable-length encodings documented inline.
# ---------------------------------------------------------------------------
NOP = 0x00          # ()
MOV_RI = 0x10       # (rd, imm8)        R[rd] = imm
MOV_RR = 0x11       # (rd, rs)          R[rd] = R[rs]
LOAD = 0x20         # (rd, areg)        R[rd] = MEM[R[areg] % WORDS]
STORE = 0x21        # (areg, rs)        MEM[R[areg] % WORDS] = R[rs]
ADD = 0x30          # (rd, ra, rb)      R[rd] = R[ra] + R[rb]
SUB = 0x31          # (rd, ra, rb)
MUL = 0x32          # (rd, ra, rb)
XOR = 0x33          # (rd, ra, rb)
AND = 0x34          # (rd, ra, rb)
OR = 0x35           # (rd, ra, rb)
NOT = 0x36          # (rd, ra)          R[rd] = ~R[ra]
ROL = 0x40          # (rd, ra, imm8)    rotate-left by imm
ROR = 0x41          # (rd, ra, imm8)
SHL = 0x42          # (rd, ra, imm8)
SHR = 0x43          # (rd, ra, imm8)
CMP = 0x50          # (ra, rb)          flags from (R[ra]-R[rb])
CMOV = 0x51         # (rd, rs, cond)    if cond(flags): R[rd]=R[rs]
JMP = 0x60          # (addr16)
JZ = 0x61           # (addr16)          jump if ZF
JNZ = 0x62          # (addr16)          jump if !ZF
CALL = 0x63         # (addr16)
RET = 0x64          # ()
HASH_ROUND = 0x70   # (rd, ra, rb)      R[rd] = hash_round(R[ra], R[rb])
MIX = 0x71          # (rd, ra)          R[rd] = mix(R[rd], R[ra], rd)
HALT = 0xF0         # (code8)

# Operand widths in bytes for each opcode (excluding the 1-byte opcode itself).
OPERAND_LEN = {
    NOP: 0, MOV_RI: 9, MOV_RR: 2, LOAD: 2, STORE: 2,
    ADD: 3, SUB: 3, MUL: 3, XOR: 3, AND: 3, OR: 3, NOT: 2,
    ROL: 3, ROR: 3, SHL: 3, SHR: 3,
    CMP: 2, CMOV: 3, JMP: 2, JZ: 2, JNZ: 2, CALL: 2, RET: 0,
    HASH_ROUND: 3, MIX: 2, HALT: 1,
}

# CMOV condition codes
COND_ZF, COND_NZF, COND_CF, COND_NCF, COND_SF, COND_NSF = range(6)

# Flag bits
FL_ZF, FL_CF, FL_SF = 1, 2, 4


@dataclass
class VMResult:
    vm_digest: bytes        # 32
    vm_state_hash: bytes    # 32
    vm_path_id: int         # u32
    vm_halt_code: int       # u32

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VMResult):
            return NotImplemented
        return (
            cb.ct_equal(self.vm_digest, other.vm_digest)
            and cb.ct_equal(self.vm_state_hash, other.vm_state_hash)
            and self.vm_path_id == other.vm_path_id
            and self.vm_halt_code == other.vm_halt_code
        )


# ---------------------------------------------------------------------------
# 64-bit helpers
# ---------------------------------------------------------------------------
def rotl64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M64 if n else x & M64


def rotr64(x: int, n: int) -> int:
    n &= 63
    return ((x >> n) | (x << (64 - n))) & M64 if n else x & M64


def hash_round(a: int, b: int) -> int:
    x = (a ^ rotl64(b, 17)) & M64
    x = (x * 0x9E3779B97F4A7C15) & M64
    x ^= x >> 31
    x = (x + rotl64(a, 13)) & M64
    x ^= rotr64(x, 7)
    return x & M64


def mix(acc: int, val: int, rd: int) -> int:
    rotated = rotl64(val, (rd * 7 + 13) & 63)
    return (acc + (rotated ^ 0xD1B54A32D192ED03)) & M64


# ---------------------------------------------------------------------------
# Input packing -- pre-loads VM memory from the session inputs.
# ---------------------------------------------------------------------------
def _words_from(data: bytes, nwords: int) -> list[int]:
    padded = data + b"\x00" * (nwords * 8 - len(data))
    return [int.from_bytes(padded[i * 8:(i + 1) * 8], "big") for i in range(nwords)]


def pack_inputs(username_norm: bytes, license_struct: bytes,
                server_random: bytes, session_id: bytes,
                transcript_prefix: bytes) -> list[int]:
    mem = [0] * config.VM_MEM_WORDS
    uname = username_norm[:config.VM_USERNAME_CAP]
    mem[0] = len(uname)
    uw = _words_from(uname, 8)               # MEM[1..8]
    for i, w in enumerate(uw):
        mem[1 + i] = w
    lw = _words_from(license_struct, 4)      # MEM[9..12]
    for i, w in enumerate(lw):
        mem[9 + i] = w
    sr = _words_from(server_random, 2)       # MEM[13..14]
    mem[13], mem[14] = sr[0], sr[1]
    sid = _words_from(session_id, 2)         # MEM[15..16]
    mem[15], mem[16] = sid[0], sid[1]
    tp = _words_from(transcript_prefix, 4)   # MEM[17..20]
    for i, w in enumerate(tp):
        mem[17 + i] = w
    mem[21] = int.from_bytes(cb.blake2b(config.VM_INPUT_DOMAIN, size=8), "big")
    return mem


# ---------------------------------------------------------------------------
# Handler-table permutation derived from the session nonce.
# A bijection over opcode slots; semantics are identical, only the dispatch
# slot index changes per session (anti-dynamic-analysis flavor).
# ---------------------------------------------------------------------------
def handler_permutation(session_nonce: bytes) -> list[int]:
    perm = list(range(256))
    seed = cb.blake2b(b"RG6-VM-PERM/v6" + session_nonce, size=32)
    # Fisher-Yates seeded by a BLAKE2b keystream.
    ks = cb.blake2b_ctr_keystream(seed, 256 * 2, domain=b"RG6-VM-PERM-KS/v6")
    for i in range(255, 0, -1):
        j = ((ks[2 * i] << 8) | ks[2 * i + 1]) % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


# ---------------------------------------------------------------------------
# The VM
# ---------------------------------------------------------------------------
class VM:
    MAX_STEPS = 200_000

    def __init__(self, bytecode: bytes, mem: list[int], session_nonce: bytes):
        self.code = bytecode
        self.mem = list(mem)
        self.reg = [0] * config.VM_NUM_REGS
        self.stack: list[int] = []
        self.flags = 0
        self.ip = 0
        self.path = 0x811C9DC5            # FNV offset basis (32-bit)
        self.halted = False
        self.halt_operand = 0
        # The permutation is computed (and would drive an indirect dispatch in
        # the client); semantics are unaffected, so we keep it for fidelity.
        self.perm = handler_permutation(session_nonce)

    # -- flag helpers ------------------------------------------------------
    def _set_cmp_flags(self, a: int, b: int) -> None:
        diff = (a - b) & M64
        self.flags = 0
        if a == b:
            self.flags |= FL_ZF
        if a < b:
            self.flags |= FL_CF
        if diff >> 63:
            self.flags |= FL_SF

    def _cond(self, code: int) -> bool:
        z = bool(self.flags & FL_ZF)
        c = bool(self.flags & FL_CF)
        s = bool(self.flags & FL_SF)
        return [z, not z, c, not c, s, not s][code]

    def _fold_path(self, taken: bool) -> None:
        self.path = ((self.path * 0x01000193) ^ (self.ip & 0xFFFF) ^ int(taken)) & M32

    # -- fetch helpers -----------------------------------------------------
    def _u8(self) -> int:
        v = self.code[self.ip]
        self.ip += 1
        return v

    def _u16(self) -> int:
        v = (self.code[self.ip] << 8) | self.code[self.ip + 1]
        self.ip += 2
        return v

    def _u64(self) -> int:
        v = int.from_bytes(self.code[self.ip:self.ip + 8], "big")
        self.ip += 8
        return v

    # -- main loop ---------------------------------------------------------
    def run(self) -> VMResult:
        steps = 0
        while not self.halted:
            if steps >= self.MAX_STEPS:
                # Structured "runaway" halt; deterministic so server matches.
                self.halt_operand = 0xEE
                break
            steps += 1
            op = self._u8()
            self._exec(op)
        return self._finish()

    def _exec(self, op: int) -> None:
        R = self.reg
        if op == NOP:
            return
        if op == MOV_RI:
            rd = self._u8(); imm = self._u64(); R[rd] = imm & M64; return
        if op == MOV_RR:
            rd = self._u8(); rs = self._u8(); R[rd] = R[rs]; return
        if op == LOAD:
            rd = self._u8(); areg = self._u8()
            R[rd] = self.mem[R[areg] % config.VM_MEM_WORDS]; return
        if op == STORE:
            areg = self._u8(); rs = self._u8()
            self.mem[R[areg] % config.VM_MEM_WORDS] = R[rs]; return
        if op in (ADD, SUB, MUL, XOR, AND, OR):
            rd = self._u8(); ra = self._u8(); rb = self._u8()
            a, b = R[ra], R[rb]
            if op == ADD: R[rd] = (a + b) & M64
            elif op == SUB: R[rd] = (a - b) & M64
            elif op == MUL: R[rd] = (a * b) & M64
            elif op == XOR: R[rd] = a ^ b
            elif op == AND: R[rd] = a & b
            else: R[rd] = a | b
            return
        if op == NOT:
            rd = self._u8(); ra = self._u8(); R[rd] = (~R[ra]) & M64; return
        if op in (ROL, ROR, SHL, SHR):
            rd = self._u8(); ra = self._u8(); imm = self._u8()
            a = R[ra]
            if op == ROL: R[rd] = rotl64(a, imm)
            elif op == ROR: R[rd] = rotr64(a, imm)
            elif op == SHL: R[rd] = (a << (imm & 63)) & M64
            else: R[rd] = (a >> (imm & 63)) & M64
            return
        if op == CMP:
            ra = self._u8(); rb = self._u8(); self._set_cmp_flags(R[ra], R[rb]); return
        if op == CMOV:
            rd = self._u8(); rs = self._u8(); cond = self._u8()
            if self._cond(cond): R[rd] = R[rs]
            return
        if op == JMP:
            addr = self._u16(); self.ip = addr; return
        if op in (JZ, JNZ):
            addr = self._u16()
            taken = bool(self.flags & FL_ZF) if op == JZ else not (self.flags & FL_ZF)
            self._fold_path(taken)
            if taken: self.ip = addr
            return
        if op == CALL:
            addr = self._u16(); self.stack.append(self.ip); self.ip = addr; return
        if op == RET:
            self.ip = self.stack.pop(); return
        if op == HASH_ROUND:
            rd = self._u8(); ra = self._u8(); rb = self._u8()
            R[rd] = hash_round(R[ra], R[rb]); return
        if op == MIX:
            rd = self._u8(); ra = self._u8(); R[rd] = mix(R[rd], R[ra], rd); return
        if op == HALT:
            self.halt_operand = self._u8(); self.halted = True; return
        # Unknown opcode -> structured fault (deterministic).
        self.halt_operand = 0xFD
        self.halted = True

    def _finish(self) -> VMResult:
        digest = b"".join(self.reg[12 + i].to_bytes(8, "big") for i in range(4))
        state = bytearray()
        for r in self.reg:
            state += r.to_bytes(8, "big")
        for s in self.stack:
            state += s.to_bytes(8, "big")
        state += bytes([self.flags & 0xFF])
        state += (self.ip & 0xFFFF).to_bytes(2, "big")
        state += (self.path & M32).to_bytes(4, "big")
        state_hash = cb.blake2b(bytes(state), size=32)
        halt_code = (self.halt_operand ^ (self.path & 0xFF)) & M32
        return VMResult(digest, state_hash, self.path & M32, halt_code)


# ---------------------------------------------------------------------------
# Bytecode access: decrypt the obfuscated blob embedded in bytecode_blob.py
# ---------------------------------------------------------------------------
def load_bytecode() -> bytes:
    from . import bytecode_blob  # generated by tools/generate_vm_bytecode.py
    return cb.stream_xor(config.VM_BLOB_KEY, bytecode_blob.ENCRYPTED_BLOB,
                         domain=config.VM_BLOB_DOMAIN)


def run_vm(username_norm: bytes, license_struct: bytes, server_random: bytes,
           session_id: bytes, transcript_prefix: bytes,
           session_nonce: bytes) -> VMResult:
    mem = pack_inputs(username_norm, license_struct, server_random,
                      session_id, transcript_prefix)
    vm = VM(load_bytecode(), mem, session_nonce)
    return vm.run()
