#!/usr/bin/env python3
"""Disassembler for the RankGate Insane VM bytecode.

Decrypts the embedded blob (config.VM_BLOB_KEY) and prints a human-readable
listing, resolving branch targets to labels. Useful for documenting the
intended solution and for players reversing the VM.

Usage:
    python tools/disassemble_vm.py
    python tools/disassemble_vm.py --raw    # print raw decrypted hex too
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import vm_reference as vm  # noqa: E402

# Reverse opcode -> mnemonic map, built from the module's UPPERCASE constants.
NAMES = {v: k for k, v in vars(vm).items()
         if isinstance(v, int) and k.isupper() and k in vm.OPERAND_LEN}

# How to render the operands of each opcode.
REG3 = ("reg", "reg", "reg")
REG2 = ("reg", "reg")
LAYOUT = {
    vm.NOP: (), vm.RET: (),
    vm.MOV_RI: ("reg", "imm64"), vm.MOV_RR: REG2,
    vm.LOAD: REG2, vm.STORE: REG2,
    vm.ADD: REG3, vm.SUB: REG3, vm.MUL: REG3, vm.XOR: REG3,
    vm.AND: REG3, vm.OR: REG3, vm.NOT: REG2,
    vm.ROL: ("reg", "reg", "imm8"), vm.ROR: ("reg", "reg", "imm8"),
    vm.SHL: ("reg", "reg", "imm8"), vm.SHR: ("reg", "reg", "imm8"),
    vm.CMP: REG2, vm.CMOV: ("reg", "reg", "cond"),
    vm.JMP: ("addr",), vm.JZ: ("addr",), vm.JNZ: ("addr",), vm.CALL: ("addr",),
    vm.HASH_ROUND: REG3, vm.MIX: REG2, vm.HALT: ("imm8",),
}
CONDS = {vm.COND_ZF: "ZF", vm.COND_NZF: "!ZF", vm.COND_CF: "CF",
         vm.COND_NCF: "!CF", vm.COND_SF: "SF", vm.COND_NSF: "!SF"}


def decode(code: bytes):
    """Yield (offset, opcode, operands_bytes)."""
    ip = 0
    while ip < len(code):
        op = code[ip]
        n = vm.OPERAND_LEN.get(op)
        if n is None:
            yield ip, None, bytes([op])
            ip += 1
            continue
        yield ip, op, code[ip + 1:ip + 1 + n]
        ip += 1 + n


def find_labels(code: bytes) -> dict[int, str]:
    targets = set()
    for _, op, operands in decode(code):
        if op in (vm.JMP, vm.JZ, vm.JNZ, vm.CALL):
            targets.add(int.from_bytes(operands[:2], "big"))
    return {addr: f"L{addr:04x}" for addr in sorted(targets)}


def render(op: int, operands: bytes, labels: dict[int, str]) -> str:
    layout = LAYOUT.get(op, ())
    parts = []
    off = 0
    for kind in layout:
        if kind == "reg":
            parts.append(f"R{operands[off]}")
            off += 1
        elif kind == "imm8":
            parts.append(f"{operands[off]:#04x}")
            off += 1
        elif kind == "imm64":
            parts.append(f"{int.from_bytes(operands[off:off+8], 'big'):#018x}")
            off += 8
        elif kind == "cond":
            parts.append(CONDS.get(operands[off], str(operands[off])))
            off += 1
        elif kind == "addr":
            addr = int.from_bytes(operands[off:off + 2], "big")
            parts.append(labels.get(addr, f"{addr:#06x}"))
            off += 2
    return ", ".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description="RankGate Insane VM disassembler")
    ap.add_argument("--raw", action="store_true")
    args = ap.parse_args()

    code = vm.load_bytecode()
    if args.raw:
        print(f"; decrypted bytecode ({len(code)} bytes)")
        print("; " + code.hex())
        print()

    labels = find_labels(code)
    for off, op, operands in decode(code):
        if off in labels:
            print(f"{labels[off]}:")
        if op is None:
            print(f"  {off:04x}: .byte {operands[0]:#04x}  ; unknown opcode")
            continue
        mnem = NAMES.get(op, f"OP_{op:#04x}")
        text = render(op, operands, labels)
        raw = bytes([op]) + operands
        print(f"  {off:04x}: {mnem:<11}{text:<28} ; {raw.hex()}")


if __name__ == "__main__":
    main()
