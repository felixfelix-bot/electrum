"""Tests for the send-path gate (P5): abort_send + tc_sign_wrapper decisions.

No Qt, no transaction object: the hook decisions are pure functions, which is
exactly why they can be tested here. The rule that matters most is that ordinary
wallet use is never blocked — only a send that matches a pending vendor order is
gated.
"""

from __future__ import annotations

import copy

from trust_vendor.gate import TrustGate
from trust_vendor.hooks import (
    PendingVendorOrder,
    TrustGateError,
    make_tc_sign_wrapper,
    payee_amount_from_tx,
    send_matches_pending,
    should_abort_send,
)
from trust_vendor.lsag import generate_key_pair, sign
from trust_vendor.trustset import TrustMember, TrustSet, pin_trust_set
from trust_vendor.verify import OrderContext, order_message

PAYEE = "bc1qvendor000000000000000000000000000000000"
AMOUNT = 27900
NOW = "2026-10-02T12:00:00Z"


def build(n: int = 6):
    secrets, members = [], []
    for i in range(n):
        sk, pk = generate_key_pair()
        secrets.append(sk)
        members.append(TrustMember(public_key=pk, label=f"vendor-{i}", basis="met-in-person"))
    ts = TrustSet(set_id="burger-vendors-berlin", description="demo", members=members,
                  published_at="2026-10-01T00:00:00Z")
    pin = pin_trust_set(ts)
    gate = TrustGate(trust_set=ts, pin=pin)
    return ts, secrets, gate, pin


def pending_for(ts, secrets, *, payee=PAYEE, amount=AMOUNT, signer=1, ring_indices=(0, 1, 2, 3),
                expires_at="2030-01-01T00:00:00Z", secret=None):
    order = OrderContext(order_id="order-1", amount_sats=amount, payee=payee,
                         pin=pin_trust_set(ts), expires_at=expires_at)
    ring = [ts.members[i].public_key for i in ring_indices]
    key = secret if secret is not None else secrets[ring_indices[signer]]
    sig = sign(order_message(order), ring, signer, key)
    return PendingVendorOrder(order=order, ring=ring, signature=sig)


# ---------------------------------------------------------------------------
# no pending order -> ordinary wallet use, never touched
# ---------------------------------------------------------------------------

def test_without_a_pending_order_nothing_is_aborted():
    abort, why = should_abort_send(None, None, payee=PAYEE, amount_sats=AMOUNT, now=NOW)
    assert abort is False
    assert "ordinary send" in why


def test_tc_wrapper_is_not_installed_without_a_pending_order():
    _ts, _secrets, gate, _pin = build()
    assert make_tc_sign_wrapper(None, gate, lambda r: "ok", lambda e: "bad") is None


# ---------------------------------------------------------------------------
# matching order -> gated on the real proof
# ---------------------------------------------------------------------------

def test_valid_proof_allows_the_matching_send():
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets)
    assert send_matches_pending(pending, payee=PAYEE, amount_sats=AMOUNT) is True
    abort, why = should_abort_send(pending, gate, payee=PAYEE, amount_sats=AMOUNT, now=NOW)
    assert abort is False
    assert "accepted" in why


def test_missing_proof_aborts_with_the_policy_reason():
    ts, secrets, gate, _pin = build()
    attacker_sk, attacker_pk = generate_key_pair()
    pending = pending_for(ts, secrets, ring_indices=(0, 1, 2, 3))
    # replace the ring with one drawn from outside the pinned set, signed by the attacker
    pending.ring = [attacker_pk, ts.members[0].public_key, ts.members[1].public_key, ts.members[2].public_key]
    pending.signature = sign(order_message(pending.order), list(pending.ring), 0, attacker_sk)
    abort, why = should_abort_send(pending, gate, payee=PAYEE, amount_sats=AMOUNT, now=NOW)
    assert abort is True
    assert "ring contains a key outside the pinned trust set" in why


def test_replayed_proof_for_a_different_amount_aborts():
    """We are paying OUR order; the vendor's signature binds a CHEAPER one.

    The signature is valid — it just binds a different order than the one we
    believe we are paying. A naive verifier checks the order the prover supplied
    and passes this. Ours treats the pending order as authoritative, so the
    binding check rejects it before the signature is even reached.
    """
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets, amount=AMOUNT + 1)   # OUR order
    replayed = copy.copy(pending.order)
    replayed.amount_sats = AMOUNT                           # what the vendor signed for
    ring = list(pending.ring)
    pending.proof_order = replayed
    pending.signature = sign(order_message(replayed), ring, 1, secrets[1])
    abort, why = should_abort_send(pending, gate, payee=PAYEE, amount_sats=AMOUNT + 1, now=NOW)
    assert abort is True
    assert "does not match the verifier's order (amount_sats)" in why


def test_expired_order_aborts():
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets, expires_at="2020-01-01T00:00:00Z")
    abort, why = should_abort_send(pending, gate, payee=PAYEE, amount_sats=AMOUNT, now=NOW)
    assert abort is True
    assert "order expired at " in why


def test_a_different_payee_is_ordinary_use_not_a_vendor_send():
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets)
    abort, why = should_abort_send(pending, gate, payee="bc1qsomeoneelse", amount_sats=AMOUNT, now=NOW)
    assert abort is False
    assert "does not match the pending vendor order" in why


def test_amount_difference_is_ordinary_use():
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets)
    abort, _why = should_abort_send(pending, gate, payee=PAYEE, amount_sats=AMOUNT + 1000, now=NOW)
    assert abort is False


def test_missing_gate_blocks_rather_than_allowing():
    ts, secrets, _gate, _pin = build()
    pending = pending_for(ts, secrets)
    abort, why = should_abort_send(pending, None, payee=PAYEE, amount_sats=AMOUNT, now=NOW)
    assert abort is True
    assert "no pinned trust set loaded" in why


# ---------------------------------------------------------------------------
# tc_sign_wrapper wiring
# ---------------------------------------------------------------------------

def test_tc_wrapper_routes_success_to_on_success():
    ts, secrets, gate, _pin = build()
    calls = []
    wrapper = make_tc_sign_wrapper(pending_for(ts, secrets), gate,
                                   lambda r: calls.append(("ok", r)),
                                   lambda e: calls.append(("fail", e)), now=NOW)
    assert callable(wrapper)
    wrapper("signed-tx")
    assert calls == [("ok", "signed-tx")]


def test_tc_wrapper_routes_a_bad_proof_to_on_failure_with_typed_error():
    ts, secrets, gate, _pin = build()
    pending = pending_for(ts, secrets, amount=AMOUNT + 1)
    replayed = copy.copy(pending.order)
    replayed.amount_sats = AMOUNT
    pending.proof_order = replayed
    pending.signature = sign(order_message(replayed), list(pending.ring), 1, secrets[1])
    calls = []
    wrapper = make_tc_sign_wrapper(pending, gate,
                                   lambda r: calls.append(("ok", r)),
                                   lambda e: calls.append(("fail", e)), now=NOW)
    wrapper("signed-tx")
    assert len(calls) == 1 and calls[0][0] == "fail"
    exc_type, exc, _tb = calls[0][1]
    assert exc_type is TrustGateError
    assert "vendor proof rejected" in str(exc)


def test_payee_amount_from_tx_never_raises_on_junk():
    class NoOutputs:
        pass
    assert payee_amount_from_tx(NoOutputs()) == []


def test_matches_pending_is_exact_on_amount():
    ts, secrets, _gate, _pin = build()
    pending = pending_for(ts, secrets)
    assert send_matches_pending(pending, payee=PAYEE, amount_sats=AMOUNT) is True
    assert send_matches_pending(None, payee=PAYEE, amount_sats=AMOUNT) is False
