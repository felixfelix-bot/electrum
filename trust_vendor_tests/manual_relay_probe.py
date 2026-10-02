#!/usr/bin/env python3
"""Manual live probe: fetch the pinned trust set from real relays (not a test).

Not part of the unit suite — it needs the network. Run it from a checkout whose
venv has electrum_aionostr installed (e.g. ~/worktrees/electrum-runtime):

    ./.venv-run/bin/python trust_vendor_tests/manual_relay_probe.py [set_id]
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "electrum", "plugins"))

from trust_vendor.relay import make_relay_fetch                      # noqa: E402
from trust_vendor.trustset_relay import (                            # noqa: E402
    TrustSetEventError,
    parse_trust_set_event,
)


def main() -> int:
    set_id = sys.argv[1] if len(sys.argv) > 1 else "burger-vendors-berlin"
    fetch = make_relay_fetch(timeout=12)
    event = fetch(set_id)
    if event is None:
        print(f"relay fetch returned None for {set_id!r} "
              "(no relay answered, or nothing published under that d-tag)")
        return 1
    print("raw event:", {k: (f"{len(v)} tags" if k == "tags" else v)
                         for k, v in event.items() if k in ("id", "kind", "created_at", "tags")})
    try:
        ts = parse_trust_set_event(event)
    except TrustSetEventError as e:
        print("parse rejected the fetched event:", e)
        return 2
    print(f"parsed: set_id={ts.set_id} members={len(ts.members)} published_at={ts.published_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
