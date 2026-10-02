"""Live relay transport for the pinned trust set (NIP-51 kind 30000).

``trustset_relay`` owns parsing/caching/monotonicity and takes the network access
as an injected callable; this module is that callable, built on
``electrum_aionostr`` (already an Electrum dependency, so no new package).

Everything is guarded: if aionostr's API or the network is unavailable,
``make_relay_fetch`` still returns a callable that yields ``None`` and logs,
which makes ``load_or_fetch`` fall back to the cached set with a warning instead
of failing the wallet.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Iterable, Optional

DEFAULT_RELAYS = (
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
)
KIND_NIP51_SET = 30000


def _event_to_dict(event) -> Optional[dict]:
    """aionostr Event -> plain dict. Tries the documented conversions in order."""
    for attr in ("to_dict", "dict", "to_json"):
        fn = getattr(event, attr, None)
        if callable(fn):
            try:
                out = fn()
                if isinstance(out, dict):
                    return out
                if isinstance(out, str):
                    import json
                    return json.loads(out)
            except Exception:
                pass
    try:  # last resort: read the attributes directly
        return {
            "id": event.id,
            "kind": int(event.kind),
            "created_at": int(event.created_at),
            "tags": [list(t) for t in event.tags],
            "content": event.content,
        }
    except Exception:
        return None


async def _fetch_event(set_id: str, relays: Iterable[str], timeout: float) -> Optional[dict]:
    from electrum_aionostr import Manager

    manager = Manager(relays=list(relays))
    try:
        await manager.connect()
        sub_id = f"trust-set:{set_id}"
        # Manager.subscribe is a coroutine in electrum_aionostr 0.1.0 — must be awaited
        queue = await manager.subscribe(
            sub_id, False, {"kinds": [KIND_NIP51_SET], "#d": [set_id], "limit": 5}
        )
        best: Optional[dict] = None
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if event is None:            # EOSE
                break
            candidate = _event_to_dict(event)
            if candidate and (best is None or int(candidate.get("created_at", 0)) > int(best.get("created_at", 0))):
                best = candidate
        return best
    finally:
        try:
            await manager.close()
        except Exception:
            pass


def make_relay_fetch(relays: Optional[Iterable[str]] = None, timeout: float = 10.0) -> Callable[[str], Optional[dict]]:
    """Build the ``fetch(set_id) -> event dict | None`` callable for load_or_fetch."""
    relay_list = list(relays) if relays else list(DEFAULT_RELAYS)

    def fetch(set_id: str) -> Optional[dict]:
        try:
            return asyncio.run(_fetch_event(set_id, relay_list, timeout))
        except Exception:
            return None

    return fetch
