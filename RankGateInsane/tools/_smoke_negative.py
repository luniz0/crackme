"""Negative tests: the protocol must REJECT bad inputs at the right stages."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

from app import verifier, vm_reference
from app.errors import ProofError


def expect_reject(label, fn):
    try:
        fn()
    except (ProofError, RuntimeError) as e:
        print(f"[+] rejected ({label}): {type(e).__name__}")
        return
    raise SystemExit(f"[!] FAILED: {label} was accepted but should be rejected")


un_a = verifier.normalize_username("player1")
un_b = verifier.normalize_username("attacker")
lic_a = verifier.build_license_struct(un_a)

# 1. license for player1 must not validate for attacker (username binding).
expect_reject("license bound to other user",
              lambda: verifier.validate_license(un_b, lic_a))

# 2. flipping a license byte must break the checksum.
bad = bytearray(lic_a); bad[5] ^= 1
expect_reject("tampered license checksum",
              lambda: verifier.validate_license(un_a, bytes(bad)))

# 3. a forged VM result must be caught by the server's independent recompute.
real = vm_reference.run_vm(un_a, lic_a, b"\x00" * 16, b"\x00" * 16,
                           b"\x00" * 32, b"\x00" * 16)
forged = vm_reference.VMResult(bytes(32), real.vm_state_hash,
                               real.vm_path_id, real.vm_halt_code)
expect_reject("forged vm digest",
              lambda: verifier.validate_vm(un_a, lic_a, b"\x00" * 16,
                                           b"\x00" * 16, b"\x00" * 32,
                                           b"\x00" * 16, forged))
print("all negative tests passed")
