#!/usr/bin/env python3
"""Reference solver for RankGate Insane -- the intended full solve path.

It plays the role of the client: performs the X25519/Ed25519 handshake, derives
the HKDF session keys, runs the VM, assembles both nonce-bound proofs, walks the
binary protocol through all stages, and finally unwraps the double-sealed flag.

Transports:
    --inproc        call the server handlers in-process (default; no server
                    needed -- used for development/CI verification)
    --http URL      talk to a running server (default URL http://127.0.0.1:31337)

The license is generated here via the author-only build path (see
tools/generate_license.py); for a real distribution players are given a license
and never see LICENSE_SECRET.

Usage:
    python tools/solve_full_challenge.py --inproc --username player1
    python tools/solve_full_challenge.py --http http://127.0.0.1:31337 -u player1
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import challenge_logic as L      # noqa: E402
from app import config                    # noqa: E402
from app import crypto_box as cb          # noqa: E402
from app import verifier                  # noqa: E402
from app import vm_reference              # noqa: E402
from app.protocol import Frame, Transcript  # noqa: E402


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
class InProcTransport:
    def __init__(self) -> None:
        self.routes = {
            "hello": L.handle_hello,
            "exchange": L.handle_exchange,
            "finalize": L.handle_finalize,
        }

    def send(self, route: str, frame_bytes: bytes) -> bytes:
        return self.routes[route](frame_bytes)


class HttpTransport:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")

    def send(self, route: str, frame_bytes: bytes) -> bytes:
        body = base64.b64encode(frame_bytes)
        req = urllib.request.Request(
            f"{self.base}/api/v1/{route}", data=body,
            headers={"Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
        try:
            obj = json.loads(data)
            if isinstance(obj, dict) and obj.get("ok") is False:
                raise RuntimeError(f"server rejected: {obj}")
        except json.JSONDecodeError:
            pass
        return base64.b64decode(data)


# ---------------------------------------------------------------------------
# The solve
# ---------------------------------------------------------------------------
def solve(transport, username: str, license_str: str | None) -> bytes:
    bootstrap = L._bootstrap_mac_key()
    username_norm = verifier.normalize_username(username)

    # License: use the supplied one, else build it (author path).
    if license_str:
        license_struct = verifier.decode_license(license_str)
        verifier.validate_license(username_norm, license_struct)
    else:
        license_struct = verifier.build_license_struct(username_norm)
    print(f"[*] username        : {username_norm.decode()}")
    print(f"[*] license         : {verifier.encode_license(license_struct)}")

    session_id = os.urandom(config.SZ_SESSION_ID)
    client_priv, client_pub = cb.x25519_keypair()
    client_random = os.urandom(16)

    # ---- HELLO --------------------------------------------------------
    t = Transcript()
    hello_payload = (client_pub + client_random
                     + len(username_norm).to_bytes(2, "big") + username_norm)
    hello = L._plain_seal(t, bootstrap, config.MT_HELLO, session_id, 1,
                          hello_payload)
    t1 = t.state  # signed prefix the server will use

    resp = transport.send("hello", hello.serialize())
    chal = Frame.parse(resp)
    chal_payload = L._plain_open(t, bootstrap, chal)
    server_pub = chal_payload[0:32]
    server_random = chal_payload[32:48]
    signature = chal_payload[48:112]

    # Authenticate the server challenge (Ed25519).
    signed = config.SIGN_CONTEXT + t1 + server_pub + server_random
    if not cb.ed25519_verify(config.SERVER_SIGN_PK, signed, signature):
        raise RuntimeError("server challenge signature invalid")
    print("[+] server challenge signature verified")

    # ---- session keys -------------------------------------------------
    salt = t.state  # T2
    shared = cb.x25519_shared(client_priv, server_pub)
    prk = cb.hkdf_extract(salt, shared)
    keys = L._derive_keys(prk)

    # ---- run the VM ---------------------------------------------------
    vmres = vm_reference.run_vm(username_norm, license_struct, server_random,
                                session_id, salt, server_random)
    print(f"[+] vm_digest={vmres.vm_digest.hex()[:16]}... "
          f"path={vmres.vm_path_id:#010x} halt={vmres.vm_halt_code:#04x}")

    # ---- CLIENT_PROOF_1 ----------------------------------------------
    proof1 = verifier.compute_proof1(
        keys["proof1"], username_norm, license_struct, vmres.vm_digest,
        vmres.vm_state_hash, vmres.vm_path_id, vmres.vm_halt_code,
        server_random, session_id, salt)
    p1_payload = (license_struct + vmres.vm_digest + vmres.vm_state_hash
                  + vmres.vm_path_id.to_bytes(4, "big")
                  + vmres.vm_halt_code.to_bytes(4, "big") + proof1)
    p1 = L._aead_seal(t, keys["mac"], keys["c2s"], config.MT_CLIENT_PROOF_1,
                      session_id, 2, p1_payload)
    t3 = t.state

    resp = transport.send("exchange", p1.serialize())
    sp = Frame.parse(resp)
    sp_payload = L._aead_open(t, keys["mac"], keys["s2c"], sp)
    server_proof1 = sp_payload[0:32]
    server_challenge2 = sp_payload[32:48]
    expected_sp1 = cb.hmac_sha256(
        keys["sproof1"],
        b"RG6-SPROOF1/v6" + t3 + vmres.vm_digest + server_challenge2)
    if not cb.ct_equal(server_proof1, expected_sp1):
        raise RuntimeError("server proof1 invalid")
    print("[+] server proof1 verified, got server_challenge2")

    # ---- CLIENT_PROOF_2 / FINALIZE -----------------------------------
    proof2 = verifier.compute_proof2(
        keys["proof2"], server_challenge2, server_random, server_pub,
        vmres.vm_digest, salt)
    p2 = L._aead_seal(t, keys["mac"], keys["c2s"], config.MT_CLIENT_PROOF_2,
                      session_id, 3, proof2)
    t5 = t.state  # transcript that seals the flag

    resp = transport.send("finalize", p2.serialize())
    sealed = Frame.parse(resp)
    inner_blob = L._aead_open(t, keys["mac"], keys["s2c"], sealed)

    # ---- unwrap the inner seal ---------------------------------------
    seal_nonce = inner_blob[0:config.SZ_NONCE]
    inner_ct = inner_blob[config.SZ_NONCE:-16]
    inner_tag = inner_blob[-16:]
    k_seal = cb.hkdf(t5, keys["seal"], b"RG6 seal", 32)
    flag = cb.aead_decrypt(k_seal, seal_nonce, inner_ct, inner_tag, t5)
    return flag


def main() -> None:
    ap = argparse.ArgumentParser(description="RankGate Insane reference solver")
    ap.add_argument("-u", "--username", default="player1")
    ap.add_argument("-l", "--license", default=None,
                    help="license string; if omitted, generated via author path")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--inproc", action="store_true",
                   help="call server handlers in-process (default)")
    g.add_argument("--http", metavar="URL", nargs="?",
                   const="http://127.0.0.1:31337",
                   help="talk to a running server")
    args = ap.parse_args()

    transport = HttpTransport(args.http) if args.http else InProcTransport()
    flag = solve(transport, args.username, args.license)
    print()
    print("ACCESS GRANTED")
    print(flag.decode())


if __name__ == "__main__":
    main()
