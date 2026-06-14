import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from app import vm_reference as vm

u = b"alice"
lic = bytes(range(25))
sr = bytes(16)
sid = bytes(range(16))
tp = bytes(range(32))
nonce = bytes(24)

r1 = vm.run_vm(u, lic, sr, sid, tp, nonce)
r2 = vm.run_vm(u, lic, sr, sid, tp, nonce)
print("digest    ", r1.vm_digest.hex())
print("state_hash", r1.vm_state_hash.hex())
print("path_id   ", hex(r1.vm_path_id))
print("halt_code ", hex(r1.vm_halt_code))
print("deterministic:", r1 == r2)

r3 = vm.run_vm(b"bob", lic, sr, sid, tp, nonce)
print("differs for other username:", not (r1 == r3))

r4 = vm.run_vm(u, lic, sr, sid, tp, b"\x01" * 24)  # different session nonce
print("perm differs nonce, same result (semantics invariant):", r1 == r4)
