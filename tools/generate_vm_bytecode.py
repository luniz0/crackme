#!/usr/bin/env python3
"""Generate the canonical RankGate Insane VM bytecode.

Outputs two byte-identical-at-runtime artifacts:

  * server/app/bytecode_blob.py   -- ENCRYPTED_BLOB (XOR-obfuscated at rest)
  * client/src/vm/bytecode_blob.cpp -- the same blob as a C++ byte array

Both the server reference VM and the C++ client decrypt the blob with
config.VM_BLOB_KEY (BLAKE2b-CTR keystream) before executing it.

The program folds the session inputs (username, license, server nonce, session
id, transcript prefix) loaded into VM memory into the four output accumulators
R12..R15, taking a data-dependent branch each iteration (which drives vm_path_id)
and finishing in a CALLed avalanche subroutine. Every required opcode appears at
least once.

Run from anywhere:  python tools/generate_vm_bytecode.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import config, crypto_box as cb           # noqa: E402
from app import vm_reference as vm                  # noqa: E402


# ---------------------------------------------------------------------------
# A tiny two-pass assembler with labels.
# ---------------------------------------------------------------------------
class Assembler:
    def __init__(self) -> None:
        self.items: list[tuple] = []   # (op, operands) operands may contain ('lbl', name)
        self.labels: dict[str, int] = {}

    def label(self, name: str) -> None:
        self.items.append(("__label__", name))

    def emit(self, op: int, *operands) -> None:
        self.items.append((op, operands))

    def _instr_size(self, op: int) -> int:
        return 1 + vm.OPERAND_LEN[op]

    def assemble(self) -> bytes:
        # Pass 1: assign byte offsets, record labels.
        off = 0
        for op, operands in self.items:
            if op == "__label__":
                self.labels[operands] = off
            else:
                off += self._instr_size(op)
        # Pass 2: emit bytes with resolved label addresses.
        branch_ops = {vm.JMP, vm.JZ, vm.JNZ, vm.CALL}
        out = bytearray()
        for op, operands in self.items:
            if op == "__label__":
                continue
            out.append(op)
            need = vm.OPERAND_LEN[op]
            body = bytearray()
            if op == vm.MOV_RI:
                rd, imm = operands
                body.append(rd & 0xFF)
                body += (imm & vm.M64).to_bytes(8, "big")
            elif op in branch_ops:
                ref = operands[0]
                addr = self.labels[ref[1]] if isinstance(ref, tuple) else ref
                body += (addr & 0xFFFF).to_bytes(2, "big")
            else:
                for operand in operands:
                    body.append(operand & 0xFF)
            assert len(body) == need, (
                f"opcode {op:#x} expected {need} operand bytes, got {len(body)}")
            out += body
        return bytes(out)


def build_program() -> bytes:
    a = Assembler()
    O = vm  # opcode namespace

    # 64-bit init constants for the accumulators (fixed, reproducible).
    C12 = 0x0123456789ABCDEF
    C13 = 0xDEADBEEFCAFEBABE
    C14 = 0xA5A5A5A55A5A5A5A
    C15 = 0xF0E1D2C3B4A59687

    # --- prologue: init accumulators, index, constants -----------------
    a.emit(O.MOV_RI, 12, C12)
    a.emit(O.MOV_RI, 13, C13)
    a.emit(O.MOV_RI, 14, C14)
    a.emit(O.MOV_RI, 15, C15)
    a.emit(O.MOV_RI, 0, 0)        # R0 = i
    a.emit(O.MOV_RI, 1, 22)       # R1 = limit (MEM words consumed)
    a.emit(O.MOV_RI, 6, 1)        # R6 = 1
    a.emit(O.MOV_RI, 8, 0)        # R8 = 0

    # --- main fold loop ------------------------------------------------
    a.label("loop")
    a.emit(O.CMP, 0, 1)           # compare i, limit
    a.emit(O.JZ, ("lbl", "end"))  # i == limit -> end
    a.emit(O.MOV_RR, 7, 0)        # R7 = i (address reg)
    a.emit(O.LOAD, 2, 7)          # R2 = MEM[i]
    a.emit(O.HASH_ROUND, 12, 12, 2)
    a.emit(O.MIX, 13, 2)
    a.emit(O.AND, 3, 2, 6)        # R3 = R2 & 1
    a.emit(O.CMP, 3, 8)           # R3 == 0 ?
    a.emit(O.JZ, ("lbl", "even"))
    # odd branch
    a.emit(O.HASH_ROUND, 15, 15, 2)
    a.emit(O.ROL, 15, 15, 7)
    a.emit(O.JMP, ("lbl", "after"))
    a.label("even")
    a.emit(O.HASH_ROUND, 14, 14, 2)
    a.emit(O.ROR, 14, 14, 11)
    a.label("after")
    a.emit(O.XOR, 12, 12, 14)
    a.emit(O.ADD, 13, 13, 15)
    a.emit(O.ADD, 0, 0, 6)        # i++
    a.emit(O.JMP, ("lbl", "loop"))

    # --- end: avalanche + call finalize subroutine ---------------------
    a.label("end")
    a.emit(O.HASH_ROUND, 12, 12, 13)
    a.emit(O.HASH_ROUND, 13, 13, 14)
    a.emit(O.HASH_ROUND, 14, 14, 15)
    a.emit(O.HASH_ROUND, 15, 15, 12)
    a.emit(O.CALL, ("lbl", "finalize"))
    a.emit(O.HALT, 0x42)

    # --- finalize subroutine (exercises remaining opcodes) -------------
    a.label("finalize")
    a.emit(O.NOP)
    a.emit(O.NOT, 3, 12)          # R3 = ~R12
    a.emit(O.OR, 4, 13, 3)        # R4 = R13 | R3
    a.emit(O.SUB, 5, 14, 15)      # R5 = R14 - R15
    a.emit(O.MUL, 9, 5, 6)        # R9 = R5 * 1
    a.emit(O.SHL, 10, 4, 3)       # R10 = R4 << 3
    a.emit(O.SHR, 11, 4, 5)       # R11 = R4 >> 5
    a.emit(O.XOR, 4, 10, 11)
    a.emit(O.MOV_RI, 0, 3)        # inner counter
    a.label("inner")
    a.emit(O.HASH_ROUND, 9, 9, 4)
    a.emit(O.CMP, 9, 8)           # R9 == 0 ?
    a.emit(O.CMOV, 5, 9, O.COND_NZF)  # if R9 != 0: R5 = R9
    a.emit(O.SUB, 0, 0, 6)        # counter--
    a.emit(O.CMP, 0, 8)           # counter == 0 ?
    a.emit(O.JNZ, ("lbl", "inner"))
    a.emit(O.STORE, 7, 9)         # MEM[R7 % WORDS] = R9
    a.emit(O.XOR, 12, 12, 9)
    a.emit(O.ADD, 13, 13, 5)
    a.emit(O.XOR, 14, 14, 4)
    a.emit(O.MIX, 15, 3)
    a.emit(O.RET)

    return a.assemble()


PY_TEMPLATE = '''\
"""GENERATED by tools/generate_vm_bytecode.py -- do not edit by hand.

ENCRYPTED_BLOB is the canonical VM bytecode XOR-obfuscated with a BLAKE2b-CTR
keystream derived from config.VM_BLOB_KEY (domain config.VM_BLOB_DOMAIN). The
reference VM decrypts it in vm_reference.load_bytecode().
"""

ENCRYPTED_BLOB = bytes.fromhex(
{hexlines}
)
'''


CPP_TEMPLATE = '''\
// GENERATED by tools/generate_vm_bytecode.py -- do not edit by hand.
// path: RankGateInsane/client/src/vm/bytecode_blob.cpp
//
// Encrypted VM bytecode blob (XOR with BLAKE2b-CTR keystream of VM_BLOB_KEY).
// Decrypted at runtime in vm.cpp before execution.

#include "bytecode.hpp"

namespace rg::vm {{

const unsigned char kEncryptedBlob[] = {{
{cpparray}
}};
const unsigned long kEncryptedBlobLen = {blen};

}} // namespace rg::vm
'''


def _hexlines(blob: bytes) -> str:
    h = blob.hex()
    chunks = [h[i:i + 64] for i in range(0, len(h), 64)]
    return "\n".join(f'    "{c}"' for c in chunks)


def _cpparray(blob: bytes) -> str:
    rows = []
    for i in range(0, len(blob), 12):
        row = ", ".join(f"0x{b:02x}" for b in blob[i:i + 12])
        rows.append("    " + row + ",")
    return "\n".join(rows)


def main() -> None:
    plain = build_program()
    encrypted = cb.stream_xor(config.VM_BLOB_KEY, plain,
                              domain=config.VM_BLOB_DOMAIN)

    py_path = ROOT / "server" / "app" / "bytecode_blob.py"
    py_path.write_text(PY_TEMPLATE.format(hexlines=_hexlines(encrypted)),
                       encoding="utf-8")

    cpp_path = ROOT / "client" / "src" / "vm" / "bytecode_blob.cpp"
    cpp_path.parent.mkdir(parents=True, exist_ok=True)
    cpp_path.write_text(
        CPP_TEMPLATE.format(cpparray=_cpparray(encrypted), blen=len(encrypted)),
        encoding="utf-8")

    print(f"canonical bytecode: {len(plain)} bytes")
    print(f"encrypted blob:     {len(encrypted)} bytes")
    print(f"wrote {py_path.relative_to(ROOT)}")
    print(f"wrote {cpp_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
