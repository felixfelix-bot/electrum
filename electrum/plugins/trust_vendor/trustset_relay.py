"""Relay-fetched pinned trust set (NIP-51 kind 30000) plus a local cache.

The verifier owns the set and pins it by ``(set_id, content_hash)``. This module
is the transport: it turns a kind-30000 replaceable event into a :class:`TrustSet`,
caches it on disk, and refuses to move the pinned version backwards or forwards
into the future.

Event shape (documented, minimal NIP-51 usage)::

    kind: 30000
    tags:
      ["d", "<set_id>"]                       # the set id; e.g. burger-vendors-berlin
      ["title", "<human description>"]
      ["p", "<pubkey-hex>", "", "<label>", "<basis>", "<tier>", "<expiry ISO>"]
      ...
    created_at: <unix seconds>                 # the set's version timestamp
    content: ""

``p`` rows are ``["p", pubkey, relay-hint, label, basis, tier, expiry]`` with
everything after the pubkey optional. The pubkey may be a 64-hex BIP340 x-only
key (lifted to the even-y compressed point, the BIP340 convention) or an
already-compressed 66-hex key.

The content hash is computed over the NORMALISED set (see ``trustset.py``), not
over the raw event bytes: signer and verifier must lift x-only keys identically
for the pin to agree, so normalising on both sides is the contract.

Nothing here imports ``electrum``: the relay client is injected as a callable, so
the whole module is unit-testable without aiohttp/aionostr/Qt.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

try:  # in-tree Electrum import path
    from .curve import is_valid_point, xonly_to_point
    from .trustset import (
        TrustMember,
        TrustSet,
        TrustSetPin,
        check_freshness,
        pin_trust_set,
    )
except ImportError:  # direct / unit-test import path
    from curve import is_valid_point, xonly_to_point  # type: ignore
    from trustset import (  # type: ignore
        TrustMember,
        TrustSet,
        TrustSetPin,
        check_freshness,
        pin_trust_set,
    )

KIND_NIP51_SET = 30000
MEMBER_TAG = "p"
D_TAG = "d"
TITLE_TAG = "title"

DEFAULT_CACHE_DIR = os.path.expanduser("~/.electrum/trust_vendor")
DEFAULT_CACHE_NAME = "trust_set.json"


class TrustSetEventError(ValueError):
    """The relay event is not a usable trust-set event."""


@dataclass
class LoadResult:
    trust_set: TrustSet
    pin: TrustSetPin
    source: str                      # "cache" | "relay"
    warning: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.trust_set is not None


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalise_pubkey(raw: str) -> bytes:
    """64-hex x-only -> even-y 33-byte compressed; 66-hex -> validated as-is."""
    try:
        blob = bytes.fromhex(raw)
    except ValueError as e:
        raise TrustSetEventError(f"member pubkey is not hex: {raw!r}") from e
    if len(blob) == 32:
        try:
            point = xonly_to_point(blob)      # raises ValueError if not on curve
        except ValueError as e:
            raise TrustSetEventError(f"member pubkey is not a valid point: {raw!r}") from e
        return bytes(point.format(compressed=True))
    if len(blob) == 33:
        if not is_valid_point(blob):
            raise TrustSetEventError(f"member pubkey is not a valid point: {raw!r}")
        return blob
    raise TrustSetEventError(f"member pubkey must be 32 or 33 bytes, got {len(blob)}")


def parse_trust_set_event(event: dict) -> TrustSet:
    """kind-30000 event -> TrustSet. Raises TrustSetEventError on anything odd."""
    if not isinstance(event, dict):
        raise TrustSetEventError("event must be a JSON object")
    kind = int(event.get("kind", -1))
    if kind != KIND_NIP51_SET:
        raise TrustSetEventError(f"expected kind {KIND_NIP51_SET}, got {kind}")

    set_id: Optional[str] = None
    title = ""
    members: list[TrustMember] = []

    for tag in event.get("tags") or []:
        if not isinstance(tag, list) or not tag:
            continue
        name = tag[0]
        if name == D_TAG:
            set_id = tag[1] if len(tag) > 1 else ""
        elif name == TITLE_TAG and len(tag) > 1:
            title = tag[1]
        elif name == MEMBER_TAG:
            if len(tag) < 2 or not tag[1]:
                raise TrustSetEventError("'p' tag without a pubkey")
            members.append(TrustMember(
                public_key=_normalise_pubkey(tag[1]),
                label=(tag[3] or None) if len(tag) > 3 else None,
                basis=(tag[4] or "seed") if len(tag) > 4 else "seed",
                tier=(tag[5] or None) if len(tag) > 5 else None,
                expires_at=(tag[6] or None) if len(tag) > 6 else None,
            ))

    if not set_id:
        raise TrustSetEventError("event has no 'd' tag: cannot identify the set")
    if not members:
        raise TrustSetEventError("event carries no 'p' member tags")

    created_at = event.get("created_at")
    if created_at is None:
        raise TrustSetEventError("event has no created_at")
    return TrustSet(
        set_id=set_id,
        description=title or set_id,
        members=members,
        published_at=_iso(int(created_at)),
    )


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

def cache_path(cache_dir: Optional[str] = None, set_id: Optional[str] = None) -> str:
    if cache_dir is None:
        cache_dir = DEFAULT_CACHE_DIR
    name = DEFAULT_CACHE_NAME if not set_id else f"trust_set-{set_id}.json"
    return os.path.join(cache_dir, name)


def save_cache(path: str, ts: TrustSet) -> None:
    """Atomic write: tmp file in the same directory + os.replace."""
    payload = ts.to_dict()
    payload["content_hash"] = pin_trust_set(ts).content_hash
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".trust-set-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_cache(path: str) -> Optional[TrustSet]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return TrustSet.from_dict(json.load(fh))
    except FileNotFoundError:
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# load_or_fetch
# ---------------------------------------------------------------------------

def load_or_fetch(
    *,
    fetch: Optional[Callable[[str], Optional[dict]]],
    set_id: str,
    cache_dir: Optional[str] = None,
    now: Optional[str] = None,
) -> LoadResult:
    """Return the newest acceptable set, caching what we accept.

    ``fetch(set_id)`` returns a raw kind-30000 event dict or None when no relay
    could answer. Rules, in order:

    * a fetched set that is future-dated, or older than the cache, is REJECTED and
      the cached set is returned with ``warning`` set — the pin never moves
      backwards;
    * a fetched set newer than the cache is accepted, cached, and returned;
    * no fetch result falls back to the cache (``warning`` recorded), and if
      there is no cache either, ``TrustSetEventError`` is raised.
    """
    path = cache_path(cache_dir, set_id)
    cached = load_cache(path)
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if fetch is not None:
        event = fetch(set_id)
        if event is None:
            warn = "relay unavailable: no event returned"
        else:
            fetched = parse_trust_set_event(event)      # raises on malformed input
            if fetched.set_id != set_id:
                raise TrustSetEventError(
                    f"event set id {fetched.set_id!r} does not match requested {set_id!r}"
                )
            ok, reason = check_freshness(fetched, now=now, cached_set=cached)
            if ok:
                save_cache(path, fetched)
                return LoadResult(fetched, pin_trust_set(fetched), "relay")
            warn = f"fetched set rejected: {reason}"
    else:
        warn = "no relay client available"

    if cached is not None:
        ok, reason = check_freshness(cached, now=now)
        if ok:
            return LoadResult(cached, pin_trust_set(cached), "cache", warning=warn)
        raise TrustSetEventError(f"cached trust set unusable: {reason}")

    raise TrustSetEventError(f"no cached trust set at {path} and no usable relay fetch")
