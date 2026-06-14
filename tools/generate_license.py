#!/usr/bin/env python3
"""Author-only license generator for RankGate Insane.

Generates a valid RG6 license for a given username using the SERVER-ONLY
LICENSE_SECRET (config). This file is NOT distributed to players -- see
docs/challenge_distribution.md.

Usage:
    python tools/generate_license.py player1
    python tools/generate_license.py --show-struct player1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from app import verifier  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="RankGate Insane license generator")
    ap.add_argument("username")
    ap.add_argument("--show-struct", action="store_true",
                    help="also print the decoded 25-byte license structure")
    args = ap.parse_args()

    username_norm = verifier.normalize_username(args.username)
    struct = verifier.build_license_struct(username_norm)
    license_str = verifier.encode_license(struct)

    print(license_str)
    if args.show_struct:
        lic = verifier.parse_license(struct)
        print(f"  username_norm : {username_norm.decode()}", file=sys.stderr)
        print(f"  version       : {lic.version}", file=sys.stderr)
        print(f"  fragment      : {lic.fragment.hex()}", file=sys.stderr)
        print(f"  proof_seed    : {lic.proof_seed.hex()}", file=sys.stderr)
        print(f"  vm_seed       : {lic.vm_seed.hex()}", file=sys.stderr)
        print(f"  parity        : {lic.parity:#04x}", file=sys.stderr)
        print(f"  timestamp     : {lic.timestamp.hex()}", file=sys.stderr)
        print(f"  checksum      : {lic.checksum.hex()}", file=sys.stderr)


if __name__ == "__main__":
    main()
