"""Pinned trust set: a curated list of vendors, pinned by id + content hash.

The verifier (the party at risk) owns the set. Membership is a claim by that
verifier about specific peers — never an authority handed down by a
"coordinator". Pinning is what stops a prover from substituting a set that
happens to contain their own key: the pin carries the set id *and* a content
hash, so a swapped or edited set is rejected.

Set provenance lives on the set itself: every member carries a ``basis``
(how it was admitted) so a verifier can price the claim instead of reading
"trusted" as a bare flag.

The content-hash encoding is a byte-for-byte port of the fleet's TypeScript
implementation (``trustset.ts``): sha256 over utf8(set_id) || utf8(published_at)
|| each member's compressed-pubkey hex, sorted. Hex sorting is what makes it
independent of member order.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional, Sequence

TRUST_BASES = ("seed", "met-in-person", "vouched", "bonded")


@dataclass
class TrustMember:
    public_key: bytes                 # 33-byte compressed secp256k1 key
    label: Optional[str] = None       # display only — never hashed
    basis: str = "seed"               # how the key earned its place
    tier: Optional[str] = None
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if len(self.public_key) != 33:
            raise ValueError("public_key must be 33-byte compressed secp256k1")

    def to_dict(self) -> dict:
        return {
            "public_key": self.public_key.hex(),
            "label": self.label,
            "basis": self.basis,
            "tier": self.tier,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "TrustMember":
        return cls(
            public_key=bytes.fromhex(raw["public_key"]),
            label=raw.get("label"),
            basis=raw.get("basis", "seed"),
            tier=raw.get("tier"),
            expires_at=raw.get("expires_at"),
        )


@dataclass
class TrustSet:
    set_id: str
    description: str
    members: Sequence[TrustMember] = field(default_factory=list)
    published_at: str = "2026-10-02T00:00:00Z"   # ISO-8601

    def to_dict(self) -> dict:
        return {
            "set_id": self.set_id,
            "description": self.description,
            "published_at": self.published_at,
            "members": [m.to_dict() for m in self.members],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "TrustSet":
        return cls(
            set_id=raw["set_id"],
            description=raw.get("description", ""),
            members=[TrustMember.from_dict(m) for m in raw.get("members", [])],
            published_at=raw.get("published_at", "1970-01-01T00:00:00Z"),
        )


@dataclass(frozen=True)
class TrustSetPin:
    """The verifier's authority: which set, which exact content."""

    set_id: str
    content_hash: str

    def to_dict(self) -> dict:
        return {"set_id": self.set_id, "content_hash": self.content_hash}


def trust_set_content_hash(ts: TrustSet) -> str:
    h = hashlib.sha256()
    h.update(ts.set_id.encode("utf-8"))
    h.update(ts.published_at.encode("utf-8"))
    for member in sorted(m.public_key.hex() for m in ts.members):
        h.update(member.encode("utf-8"))
    return h.hexdigest()


def pin_trust_set(ts: TrustSet) -> TrustSetPin:
    return TrustSetPin(set_id=ts.set_id, content_hash=trust_set_content_hash(ts))


def matches_pin(ts: TrustSet, pin: TrustSetPin) -> bool:
    return ts.set_id == pin.set_id and trust_set_content_hash(ts) == pin.content_hash


def check_freshness(ts: TrustSet, now: str, cached_set: Optional[TrustSet] = None) -> tuple[bool, str]:
    """Reject future-dated sets and sets older than the newest one we cached.

    Removal from a trust set is always soft: nothing can call back a signature
    already handed over. Monotonic version acceptance plus a declared expiry is
    the honest mitigation, and this is where the version half lives.
    """
    if ts.published_at > now:
        return False, (
            f"trust set is future-dated ({ts.published_at} > verifier's clock {now})"
        )
    if cached_set is not None and ts.published_at < cached_set.published_at:
        return False, (
            "trust set is older than the cached newer version "
            f"({ts.published_at} < {cached_set.published_at})"
        )
    return True, "fresh"
