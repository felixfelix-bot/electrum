#!/usr/bin/env python3
"""Create the demo trust set + a matching NIP-51 kind-30000 event JSON.

Usage (venv with coincurve, e.g. ~/worktrees/electrum-trust-vendor/.venv-trust):

    .venv-trust/bin/python trust_vendor_tests/make_fixture_set.py [outdir]

Writes ``trust_set.json`` (what the plugin caches / loads) and
``trust_set_event.json`` (the raw kind-30000 event, ready to publish with nak).
The member private keys are DERIVED (sha256 of a label) and never written to
disk, so the fixture holds public keys only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "electrum", "plugins"))

from trust_vendor.curve import base_mul, point_to_bytes, scalar_from_bytes, scalar_to_bytes  # noqa: E402
from trust_vendor.trustset import TrustMember, TrustSet, pin_trust_set                       # noqa: E402

SET_ID = "burger-vendors-berlin"
N = 8


def derived_secret(label: str) -> bytes:
    return hashlib.sha256(b"trust-vendor-demo/" + label.encode()).digest()


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.electrum/trust_vendor")
    os.makedirs(outdir, exist_ok=True)

    members, tags = [], []
    for i in range(N):
        secret = derived_secret(f"vendor-{i}")
        pub = point_to_bytes(base_mul(scalar_from_bytes(secret)))
        members.append(TrustMember(public_key=pub, label=f"vendor-{i:02d}", basis="met-in-person"))
        # NIP-51 'p' tag: pubkey, relay hint, label, basis, tier, expiry
        tags.append(["p", pub[1:33].hex(), "", f"vendor-{i:02d}", "met-in-person", "silver", "2030-01-01T00:00:00Z"])

    ts = TrustSet(set_id=SET_ID, description="Berlin vendors vetted in person (hackathon demo)",
                  members=members, published_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    pin = pin_trust_set(ts)

    set_path = os.path.join(outdir, "trust_set.json")
    payload = ts.to_dict()
    payload["content_hash"] = pin.content_hash
    with open(set_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")

    event = {
        "kind": 30000,
        "created_at": int(datetime.now(timezone.utc).timestamp()),
        "content": "",
        "tags": [["d", SET_ID], ["title", ts.description], *tags],
    }
    event_path = os.path.join(outdir, "trust_set_event.json")
    with open(event_path, "w", encoding="utf-8") as fh:
        json.dump(event, fh, indent=2)
        fh.write("\n")

    print(f"wrote {set_path}")
    print(f"wrote {event_path}")
    print(f"set_id={SET_ID} members={N} content_hash={pin.content_hash}")
    print("derived secrets for the demo (label -> secret hex), never written to disk:")
    for i in range(N):
        print(f"  vendor-{i:02d} {scalar_to_bytes(scalar_from_bytes(derived_secret(f'vendor-{i}'))).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
