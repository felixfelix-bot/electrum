"""The verification policy — the ordered check list, with stable reasons.

The verifier is the party at risk and owns the pinned set. Order matters:
cheap structural checks run before the expensive EC verification, and the
key-image one-use check runs LAST so a rejected proof never burns a key image.

  1. the supplied trust set matches the verifier's pin (set id + content hash)
  2. the proof's own pin matches the verifier's pin
  3. ring size is at least the minimum (1 only in declared-1:1 mode)
  4. the ring is a SUBSET of the pinned set — every ring key must be trusted
  5. no duplicate keys in the ring
  6. the order has not expired
  7. the LSAG signature verifies over the order-bound message
  8. the key image has not been used before for this (order, set)

Check 4 is the one that makes the scheme sound. A ring signature only proves
"one ring member signed", so a verifier whose rule is "the ring contains at
least one key I trust" is broken: an attacker builds
ring = {their own key, one scraped trusted key}, signs with their own key, and
passes. Presence of a trusted key in a ring is not authorship by a trusted key.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Sequence

try:  # in-tree Electrum import path
    from .curve import tagged_hash
    from .lsag import LSAGSignature, verify as lsag_verify
    from .trustset import TrustSet, TrustSetPin, matches_pin
except ImportError:  # direct / unit-test import path
    from curve import tagged_hash  # type: ignore
    from lsag import LSAGSignature, verify as lsag_verify  # type: ignore
    from trustset import TrustSet, TrustSetPin, matches_pin  # type: ignore

MIN_RING_SIZE = 4                 # ADR 0002: anonymous floor
DECLARED_1_TO_1 = "declared-1:1"  # a labelled 1:1 relationship, never silent
ANONYMOUS = "anonymous"

_ORDER_TAG = b"trust-vendor/order/v1"
_PROTOCOL_VERSION = b"trust-vendor/v1"


@dataclass
class OrderContext:
    """Everything the payment is bound to. Changing any field breaks the proof."""

    order_id: str
    amount_sats: int
    payee: str
    pin: TrustSetPin
    expires_at: str


@dataclass
class TrustProof:
    """What the vendor hands over: the ring they claim, and the signature."""

    order: OrderContext
    ring: Sequence[bytes]
    signature: LSAGSignature


@dataclass
class VerifyResult:
    ok: bool
    reason: Optional[str] = None
    anonymity_set_size: Optional[int] = None


@dataclass
class KeyImageSeenSet:
    """One-use register, scoped per (order_id, set_id).

    Scoping is deliberate: a global seen-set would make every proof by the same
    key linkable across orders.
    """

    _store: dict = field(default_factory=dict)

    def scope(self, order: OrderContext) -> tuple[str, str]:
        return (order.order_id, order.pin.set_id)

    def check_and_record(self, order: OrderContext, key_image: bytes) -> bool:
        scope = self.scope(order)
        bucket = self._store.setdefault(scope, set())
        if key_image in bucket:
            return False
        bucket.add(key_image)
        return True


def create_seen_set() -> KeyImageSeenSet:
    return KeyImageSeenSet()


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def order_message(order: OrderContext) -> bytes:
    """Bind the proof to exactly one order.

    Without this, a captured proof is a bearer instrument: anyone could replay
    it for any amount. Domain-separated and length-prefixed so no two field
    assignments can produce the same digest.
    """
    payload = b"".join([
        _PROTOCOL_VERSION,
        _lp(b"order"),
        _lp(order.order_id.encode("utf-8")),
        _lp(str(int(order.amount_sats)).encode("ascii")),
        _lp(order.payee.encode("utf-8")),
        _lp(order.pin.set_id.encode("utf-8")),
        _lp(order.pin.content_hash.encode("ascii")),
        _lp(order.expires_at.encode("ascii")),
    ])
    return tagged_hash(_ORDER_TAG, payload)


def order_mismatch_field(a: OrderContext, b: OrderContext) -> Optional[str]:
    """Return the first field that differs, or None if the orders are identical.

    The field name is part of the stable reason string, so a caller (and the
    GUI) can point at exactly what was tampered with.
    """
    for name in ("order_id", "amount_sats", "payee", "expires_at"):
        if getattr(a, name) != getattr(b, name):
            return name
    if a.pin.set_id != b.pin.set_id:
        return "pin.set_id"
    if a.pin.content_hash != b.pin.content_hash:
        return "pin.content_hash"
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_proof(
    proof: TrustProof,
    trust_set: TrustSet,
    pin: TrustSetPin,
    seen: KeyImageSeenSet,
    *,
    mode: str = ANONYMOUS,
    min_ring_size: int = MIN_RING_SIZE,
    now: Optional[str] = None,
    expected_order: Optional[OrderContext] = None,
) -> VerifyResult:
    """Run the full policy. Returns a result whose ``reason`` is stable text."""
    now = now or _now_iso()

    # 1. the supplied set must be the pinned set
    if not matches_pin(trust_set, pin):
        return VerifyResult(False, "trust set does not match pin (setId or contentHash mismatch)")

    # 2. the proof must claim the same pin we hold
    if proof.order.pin.set_id != pin.set_id or proof.order.pin.content_hash != pin.content_hash:
        return VerifyResult(False, "proof's pinned set does not match the verifier's pin")

    # 2b. the order the VERIFIER believes it is paying must be the order the
    #     proof binds. Passing no expected_order verifies whatever order the
    #     prover supplied, which is only appropriate for a display/inspection
    #     path — a money path must always pass one.
    if expected_order is not None:
        mismatch = order_mismatch_field(proof.order, expected_order)
        if mismatch is not None:
            return VerifyResult(
                False,
                f"proof's order does not match the verifier's order ({mismatch})",
            )

    # 3. ring size floor
    floor = 1 if mode == DECLARED_1_TO_1 else min_ring_size
    if len(proof.ring) < floor:
        return VerifyResult(False, f"ring size {len(proof.ring)} is below minimum {floor}")

    # 4. subset of the pinned set — every permitted ring member must be trusted
    trusted = {m.public_key.hex() for m in trust_set.members}
    for pk in proof.ring:
        if pk.hex() not in trusted:
            return VerifyResult(False, "ring contains a key outside the pinned trust set")

    # 5. duplicate keys would let a signer shrink the effective ring
    ring_hexes = [pk.hex() for pk in proof.ring]
    if len(set(ring_hexes)) != len(ring_hexes):
        return VerifyResult(False, "ring contains duplicate keys")

    # 6. expiry
    if now > proof.order.expires_at:
        return VerifyResult(False, f"order expired at {proof.order.expires_at}")

    # 7. the actual proof
    if not lsag_verify(order_message(expected_order or proof.order), list(proof.ring), proof.signature):
        return VerifyResult(False, "LSAG signature verification failed")

    # 8. one-use (last, so a rejected proof does not consume the key image)
    if not seen.check_and_record(proof.order, proof.signature.key_image):
        return VerifyResult(False, "key image already used for this order — duplicate proof rejected")

    return VerifyResult(True, None, anonymity_set_size=len(proof.ring))


def verify_order_with_freshness(
    proof: TrustProof,
    trust_set: TrustSet,
    pin: TrustSetPin,
    seen: KeyImageSeenSet,
    *,
    cached_set: Optional[TrustSet] = None,
    now: Optional[str] = None,
    **kwargs,
) -> VerifyResult:
    """verify_proof plus the monotonic-version check on the pinned set."""
    from .trustset import check_freshness  # local import keeps the core deps light
    ok, reason = check_freshness(trust_set, now=now or _now_iso(), cached_set=cached_set)
    if not ok:
        return VerifyResult(False, reason)
    return verify_proof(proof, trust_set, pin, seen, now=now, **kwargs)


def copied_order(order: OrderContext, **changes) -> OrderContext:
    """Test/demo helper: a tampered order that must invalidate the proof."""
    new = copy.copy(order)
    for key, value in changes.items():
        setattr(new, key, value)
    return new
