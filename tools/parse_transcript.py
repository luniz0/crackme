#!/usr/bin/env python3
"""Protocol transcript parser for RankGate Insane.

Reads captured frames and prints their decoded binary structure. Each input
line is one frame as base64 (the HTTP body) or hex. Header fields are always
decoded; the encrypted payload is only decrypted when the relevant session key
is supplied (--c2s-key / --s2c-key as 64-hex-char keys), since the application
protocol is authenticated and encrypted.

Usage:
    python tools/parse_transcript.py frames.txt
    python tools/parse_transcript.py --s2c-key <hex64> frames.txt
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import config            # noqa: E402
from app import crypto_box as cb  # noqa: E402
from app.protocol import Frame    # noqa: E402

MT_NAMES = {
    config.MT_HELLO: "HELLO",
    config.MT_SERVER_CHALLENGE: "SERVER_CHALLENGE",
    config.MT_CLIENT_PROOF_1: "CLIENT_PROOF_1",
    config.MT_SERVER_PROOF_1: "SERVER_PROOF_1",
    config.MT_CLIENT_PROOF_2: "CLIENT_PROOF_2",
    config.MT_FINALIZE: "FINALIZE",
    config.MT_SEALED_FLAG: "SEALED_FLAG",
    config.MT_ERROR: "ERROR",
}

# message_type -> ("c2s"|"s2c"|None) direction for decryption
DIRECTION = {
    config.MT_CLIENT_PROOF_1: "c2s",
    config.MT_CLIENT_PROOF_2: "c2s",
    config.MT_FINALIZE: "c2s",
    config.MT_SERVER_PROOF_1: "s2c",
    config.MT_SEALED_FLAG: "s2c",
}


def decode_line(line: str) -> bytes:
    line = line.strip()
    if not line:
        return b""
    try:
        return bytes.fromhex(line)
    except ValueError:
        return base64.b64decode(line)


def dump(frame: Frame, keys: dict[str, bytes | None]) -> None:
    name = MT_NAMES.get(frame.message_type, f"0x{frame.message_type:02x}")
    print(f"== {name} ==")
    print(f"  session_id  : {frame.session_id.hex()}")
    print(f"  counter     : {frame.counter}")
    print(f"  nonce       : {frame.nonce.hex()}")
    print(f"  payload_len : {len(frame.encrypted_payload)}")
    print(f"  auth_tag    : {frame.auth_tag.hex()}")
    print(f"  transcript  : {frame.transcript_mac.hex()}")

    direction = DIRECTION.get(frame.message_type)
    if direction is None:
        # Pre-key plaintext frame (HELLO / SERVER_CHALLENGE).
        print(f"  payload     : {frame.encrypted_payload.hex()}")
        return
    key = keys.get(direction)
    if not key:
        print(f"  payload     : <encrypted; supply --{direction}-key to decrypt>")
        return
    try:
        pt = cb.aead_decrypt(key, frame.nonce, frame.encrypted_payload,
                             frame.auth_tag, frame.header())
        print(f"  decrypted   : {pt.hex()}")
    except Exception as exc:  # noqa: BLE001
        print(f"  decrypt     : FAILED ({exc})")


def main() -> None:
    ap = argparse.ArgumentParser(description="RankGate Insane transcript parser")
    ap.add_argument("file", help="file with one base64/hex frame per line")
    ap.add_argument("--c2s-key", help="client->server AEAD key (64 hex chars)")
    ap.add_argument("--s2c-key", help="server->client AEAD key (64 hex chars)")
    args = ap.parse_args()

    keys = {
        "c2s": bytes.fromhex(args.c2s_key) if args.c2s_key else None,
        "s2c": bytes.fromhex(args.s2c_key) if args.s2c_key else None,
    }
    for line in Path(args.file).read_text(encoding="utf-8").splitlines():
        raw = decode_line(line)
        if not raw:
            continue
        try:
            frame = Frame.parse(raw)
        except Exception as exc:  # noqa: BLE001
            print(f"!! unparseable frame: {exc}")
            continue
        dump(frame, keys)
        print()


if __name__ == "__main__":
    main()
