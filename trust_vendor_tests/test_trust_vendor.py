"""Tests for the trust_vendor ring-signature vendor-vetting plugin.

These tests are written BEFORE the implementation (TDD). The attack cases are
the point of the whole design: a ring signature only proves "one ring member
signed", so a verifier whose rule is "the ring contains a key I trust" is
unsound. Every rejection reason string is asserted, because the reason is part
of the interface the GUI and the money-path gate display.

Run:  .venv-trust/bin/python -m pytest tests/test_trust_vendor.py -v
"""

from __future__ import annotations

import copy

import pytest

from trust_vendor.lsag import (
    LSAGSignature,
    generate_key_pair,
    sign,
    verify,
)
from trust_vendor.trustset import (
    TrustMember,
    TrustSet,
    TrustSetPin,
    check_freshness,
    matches_pin,
    pin_trust_set,
    trust_set_content_hash,
)
from trust_vendor.verify import (
    MIN_RING_SIZE,
    OrderContext,
    TrustProof,
    create_seen_set,
    order_message,
    verify_proof,
)

# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

N_MEMBERS = 8
RING_SIZE = 4


def _make_set(n: int = N_MEMBERS, published_at: str = "2026-10-02T00:00:00Z") -> tuple[TrustSet, list[bytes]]:
    secrets = []
    members = []
    for i in range(n):
        sk, pk = generate_key_pair()
        secrets.append(sk)
        members.append(TrustMember(public_key=pk, label=f"vendor-{i}", basis="met-in-person"))
    ts = TrustSet(
        set_id="burger-vendors-berlin",
        description="Vendors vetted in person",
        members=members,
        published_at=published_at,
    )
    return ts, secrets


def _order(ts: TrustSet, *, order_id: str = "order-1", amount_sats: int = 27900,
           payee: str = "burgermeister@example.org", expires_at: str = "2030-01-01T00:00:00Z") -> OrderContext:
    return OrderContext(
        order_id=order_id,
        amount_sats=amount_sats,
        payee=payee,
        pin=pin_trust_set(ts),
        expires_at=expires_at,
    )


def _proof(ts: TrustSet, secrets: list[bytes], order: OrderContext,
           ring_indices=(0, 1, 2, 3), signer_index: int = 2) -> TrustProof:
    ring = [ts.members[i].public_key for i in ring_indices]
    sig = sign(order_message(order), ring, signer_index, secrets[ring_indices[signer_index]])
    return TrustProof(order=order, ring=ring, signature=sig)


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------

def test_happy_path_verifies_and_reports_anonymity_set():
    ts, secrets = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    res = verify_proof(proof, ts, order.pin, create_seen_set(), expected_order=order)
    assert res.ok is True, res.reason
    assert res.anonymity_set_size == RING_SIZE


def test_signature_verifies_whatever_the_signer_position():
    ts, secrets = _make_set()
    order = _order(ts)
    for idx in range(RING_SIZE):
        proof = _proof(ts, secrets, order, signer_index=idx)
        res = verify_proof(proof, ts, order.pin, create_seen_set())
        assert res.ok is True, (idx, res.reason)


def test_lsag_verify_directly_accepts_and_rejects_wrong_message():
    ts, secrets = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    assert verify(order_message(order), proof.ring, proof.signature) is True
    assert verify(b"some other message", proof.ring, proof.signature) is False


def test_wrong_secret_key_fails_lsag_verification():
    """sign() with a key that does not match ring[signer_index] must not verify."""
    ts, _secrets = _make_set()
    order = _order(ts)
    ring = [ts.members[i].public_key for i in range(RING_SIZE)]
    sig = sign(order_message(order), ring, 0, b"\x11" * 32)
    res = verify_proof(TrustProof(order=order, ring=ring, signature=sig), ts, order.pin,
                       create_seen_set(), expected_order=order)
    assert res.ok is False
    assert res.reason == "LSAG signature verification failed"


# --------------------------------------------------------------------------
# ATTACK 1 — the non-member attack (the regression test for the whole design)
# --------------------------------------------------------------------------

def test_non_member_attack_is_rejected():
    """ring = {attacker key, one scraped trusted key, ...} must NOT pass.

    A naive verifier ("is a trusted key in the ring?") accepts this.
    """
    ts, secrets = _make_set()
    order = _order(ts)
    attacker_sk, attacker_pk = generate_key_pair()
    ring = [attacker_pk, ts.members[0].public_key, ts.members[1].public_key, ts.members[2].public_key]
    sig = sign(order_message(order), ring, 0, attacker_sk)
    proof = TrustProof(order=order, ring=ring, signature=sig)
    res = verify_proof(proof, ts, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason == "ring contains a key outside the pinned trust set"


# --------------------------------------------------------------------------
# ATTACK 2 — replay / tampering
# --------------------------------------------------------------------------

def test_replay_to_a_different_order_is_rejected():
    """A captured proof re-labelled onto another order must not pass.

    The verifier must hold the authoritative order. If it verified whatever
    order the prover supplied, a replay would simply re-declare itself.
    """
    ts, secrets = _make_set()
    order_a = _order(ts, order_id="order-A", amount_sats=27900)
    order_b = _order(ts, order_id="order-B", amount_sats=27900)
    proof = _proof(ts, secrets, order_a)
    res = verify_proof(proof, ts, order_b.pin, create_seen_set(), expected_order=order_b)
    assert res.ok is False
    assert res.reason == "proof's order does not match the verifier's order (order_id)"


def test_tampered_amount_is_rejected():
    ts, secrets = _make_set()
    order = _order(ts, amount_sats=27900)
    proof = _proof(ts, secrets, order)
    tampered = copy.copy(proof.order)
    tampered.amount_sats = 1
    res = verify_proof(TrustProof(order=tampered, ring=proof.ring, signature=proof.signature),
                       ts, order.pin, create_seen_set(), expected_order=order)
    assert res.ok is False
    assert res.reason == "proof's order does not match the verifier's order (amount_sats)"


# --------------------------------------------------------------------------
# ATTACK 3 — key-image reuse (one proof, two payouts)
# --------------------------------------------------------------------------

def test_key_image_reuse_for_the_same_order_is_rejected():
    ts, secrets = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    seen = create_seen_set()
    first = verify_proof(proof, ts, order.pin, seen)
    assert first.ok is True, first.reason
    second = verify_proof(proof, ts, order.pin, seen)
    assert second.ok is False
    assert second.reason == "key image already used for this order — duplicate proof rejected"


def test_key_image_is_scoped_per_order_not_global():
    """Same proof accepted for a different order id => no cross-order linkability."""
    ts, secrets = _make_set()
    order_a = _order(ts, order_id="order-A")
    order_b = _order(ts, order_id="order-B")
    seen = create_seen_set()
    proof_a = _proof(ts, secrets, order_a)
    a = verify_proof(proof_a, ts, order_a.pin, seen)
    assert a.ok is True, a.reason
    proof_b = _proof(ts, secrets, order_b)
    b = verify_proof(proof_b, ts, order_b.pin, seen)
    assert b.ok is True, b.reason


# --------------------------------------------------------------------------
# policy checks
# --------------------------------------------------------------------------

def test_ring_below_minimum_is_rejected():
    ts, secrets = _make_set()
    order = _order(ts)
    ring = [ts.members[i].public_key for i in range(MIN_RING_SIZE - 1)]
    sig = sign(order_message(order), ring, 0, secrets[0])
    res = verify_proof(TrustProof(order=order, ring=ring, signature=sig), ts, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason == f"ring size {MIN_RING_SIZE - 1} is below minimum {MIN_RING_SIZE}"


def test_declared_1to1_mode_allows_a_single_member_ring():
    ts, secrets = _make_set()
    order = _order(ts)
    ring = [ts.members[3].public_key]
    sig = sign(order_message(order), ring, 0, secrets[3])
    proof = TrustProof(order=order, ring=ring, signature=sig)
    res = verify_proof(proof, ts, order.pin, create_seen_set(), mode="declared-1:1")
    assert res.ok is True, res.reason
    assert res.anonymity_set_size == 1


def test_duplicate_keys_in_ring_are_rejected():
    ts, secrets = _make_set()
    order = _order(ts)
    ring = [ts.members[0].public_key, ts.members[1].public_key, ts.members[0].public_key, ts.members[2].public_key]
    sig = sign(order_message(order), ring, 0, secrets[0])
    res = verify_proof(TrustProof(order=order, ring=ring, signature=sig), ts, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason == "ring contains duplicate keys"


def test_expired_order_is_rejected():
    ts, secrets = _make_set()
    order = _order(ts, expires_at="2020-01-01T00:00:00Z")
    proof = _proof(ts, secrets, order)
    res = verify_proof(proof, ts, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason.startswith("order expired at ")


def test_swapped_trust_set_does_not_match_pin():
    ts, secrets = _make_set()
    other, _ = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    res = verify_proof(proof, other, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason == "trust set does not match pin (setId or contentHash mismatch)"


def test_proof_carrying_a_foreign_pin_is_rejected():
    ts, secrets = _make_set()
    foreign, _ = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    proof.order = copy.copy(proof.order)  # do not mutate the verifier's own pin
    proof.order.pin = pin_trust_set(foreign)
    res = verify_proof(proof, ts, order.pin, create_seen_set())
    assert res.ok is False
    assert res.reason == "proof's pinned set does not match the verifier's pin"


# --------------------------------------------------------------------------
# trust-set pinning / freshness
# --------------------------------------------------------------------------

def test_content_hash_is_stable_and_sensitive():
    ts, _ = _make_set()
    assert trust_set_content_hash(ts) == trust_set_content_hash(copy.deepcopy(ts))
    reordered = TrustSet(set_id=ts.set_id, description=ts.description,
                         members=list(reversed(ts.members)), published_at=ts.published_at)
    assert trust_set_content_hash(reordered) == trust_set_content_hash(ts)
    smaller = TrustSet(set_id=ts.set_id, description=ts.description,
                       members=ts.members[:-1], published_at=ts.published_at)
    assert trust_set_content_hash(smaller) != trust_set_content_hash(ts)


def test_matches_pin_requires_both_id_and_hash():
    ts, _ = _make_set()
    pin = pin_trust_set(ts)
    assert matches_pin(ts, pin) is True
    assert matches_pin(ts, TrustSetPin(set_id="other", content_hash=pin.content_hash)) is False
    assert matches_pin(ts, TrustSetPin(set_id=pin.set_id, content_hash="00" * 32)) is False


def test_freshness_rejects_future_dated_and_stale_sets():
    ts, _ = _make_set(published_at="2030-01-01T00:00:00Z")
    ok, reason = check_freshness(ts, now="2026-10-02T00:00:00Z")
    assert ok is False and "future" in reason

    fresh = copy.deepcopy(ts)
    fresh.published_at = "2026-10-01T00:00:00Z"
    newer = copy.deepcopy(fresh)
    newer.published_at = "2026-10-02T00:00:00Z"
    ok2, reason2 = check_freshness(newer, now="2026-10-03T00:00:00Z", cached_set=fresh)
    assert ok2 is True, reason2

    ok3, reason3 = check_freshness(fresh, now="2026-10-03T00:00:00Z", cached_set=newer)
    assert ok3 is False and "newer" in reason3


# --------------------------------------------------------------------------
# signature object shape
# --------------------------------------------------------------------------

def test_signature_is_serialisable_round_trip():
    ts, secrets = _make_set()
    order = _order(ts)
    proof = _proof(ts, secrets, order)
    raw = proof.signature.to_dict()
    assert set(raw) == {"key_image", "c0", "responses"}
    restored = LSAGSignature.from_dict(raw)
    assert verify(order_message(order), proof.ring, restored) is True


def test_message_binding_covers_every_order_field():
    ts, _ = _make_set()
    base = _order(ts)
    variants = [
        _order(ts, order_id="other"),
        _order(ts, amount_sats=1),
        _order(ts, payee="evil@example.org"),
        _order(ts, expires_at="2031-01-01T00:00:00Z"),
    ]
    msgs = {order_message(v) for v in [base, *variants]}
    assert len(msgs) == len(variants) + 1
