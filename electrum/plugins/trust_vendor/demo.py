#!/usr/bin/env python3
"""Headless demo: the trust-vendor policy, beat by beat.

Run it (no Electrum, no Qt, no network needed):

    python electrum/plugins/trust_vendor/demo.py

Every beat asserts the real return value of the real policy — nothing here is
narrated. If the policy regresses, this exits non-zero.
"""

from __future__ import annotations

import copy
import sys

try:
    from .gate import TrustGate
    from .lsag import generate_key_pair, sign, verify
    from .trustset import TrustMember, TrustSet, pin_trust_set
    from .verify import (
        MIN_RING_SIZE,
        OrderContext,
        TrustProof,
        create_seen_set,
        order_message,
        verify_proof,
    )
except ImportError:  # run as a plain script
    import os

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gate import TrustGate  # type: ignore
    from lsag import generate_key_pair, sign, verify  # type: ignore
    from trustset import TrustMember, TrustSet, pin_trust_set  # type: ignore
    from verify import (  # type: ignore
        MIN_RING_SIZE,
        OrderContext,
        TrustProof,
        create_seen_set,
        order_message,
        verify_proof,
    )

N_TRUSTED = 20
RING_SIZE = 4


def build_world():
    secrets, members = [], []
    for i in range(N_TRUSTED):
        sk, pk = generate_key_pair()
        secrets.append(sk)
        members.append(TrustMember(public_key=pk, label=f"vendor-{i:02d}", basis="met-in-person"))
    ts = TrustSet(
        set_id="burger-vendors-berlin",
        description="Berlin vendors vetted in person (demo fixture)",
        members=members,
        published_at="2026-10-02T00:00:00Z",
    )
    return ts, secrets


def order_for(ts, order_id="order-1", amount_sats=27900, payee="burgermeister@example.org"):
    return OrderContext(
        order_id=order_id,
        amount_sats=amount_sats,
        payee=payee,
        pin=pin_trust_set(ts),
        expires_at="2030-01-01T00:00:00Z",
    )


def proof_for(ts, secrets, order, ring_indices=(0, 1, 2, 3), signer=2, secret=None):
    ring = [ts.members[i].public_key for i in ring_indices]
    key = secret if secret is not None else secrets[ring_indices[signer]]
    return TrustProof(order=order, ring=ring, signature=sign(order_message(order), ring, signer, key))


def beat(n, title):
    print(f"\n[{n}] {title}")
    print("-" * 68)


def main() -> int:
    ts, secrets = build_world()
    pin = pin_trust_set(ts)
    print("trust-vendor demo — ring-signature vendor vetting, policy only")
    print(f"pinned set: {ts.set_id} | {len(ts.members)} members | hash {pin.content_hash[:16]}…")

    # 1 — happy path
    beat(1, "Vetted vendor pays: proof over the exact order")
    order = order_for(ts)
    p1 = proof_for(ts, secrets, order)
    r1 = verify_proof(p1, ts, pin, create_seen_set(), expected_order=order)
    print(f"ring = {RING_SIZE} vendors drawn from the pinned set (which one signed is not revealed)")
    print(f"verdict: ok={r1.ok} anonymity_set={r1.anonymity_set_size}")
    assert r1.ok is True, r1.reason

    # 2 — the non-member attack (the reason this design exists)
    beat(2, "ATTACK: attacker adds their own key to the ring")
    attacker_sk, attacker_pk = generate_key_pair()
    ring = [attacker_pk, *[ts.members[i].public_key for i in range(3)]]
    sig = sign(order_message(order), ring, 0, attacker_sk)
    p2 = TrustProof(order=order, ring=ring, signature=sig)
    naive = any(pk in {m.public_key for m in ts.members} for pk in ring)
    r2 = verify_proof(p2, ts, pin, create_seen_set(), expected_order=order)
    print(f"naive check 'is a trusted key in the ring?' -> {naive}   (this is the bug)")
    print(f"real verdict: ok={r2.ok} reason={r2.reason!r}")
    assert r2.ok is False and r2.reason == "ring contains a key outside the pinned trust set"

    # 3 — replay onto another order
    beat(3, "ATTACK: replay a captured proof onto another order")
    order_b = order_for(ts, order_id="order-2")
    r3 = verify_proof(proof_for(ts, secrets, order_for(ts, order_id="order-1")), ts, pin,
                      create_seen_set(), expected_order=order_b)
    print(f"verdict: ok={r3.ok} reason={r3.reason!r}")
    assert r3.ok is False and "does not match the verifier's order" in r3.reason

    # 4 — key-image reuse (one proof, two payouts)
    beat(4, "ATTACK: submit the same proof twice")
    seen = create_seen_set()
    first = verify_proof(p1, ts, pin, seen, expected_order=order)
    second = verify_proof(p1, ts, pin, seen, expected_order=order)
    print(f"first  attempt: ok={first.ok}")
    print(f"second attempt: ok={second.ok} reason={second.reason!r}")
    assert first.ok is True and second.ok is False

    # 5 — structural checks
    beat(5, "Structural checks: small ring, duplicated key, stale order")
    ts_small = copy.deepcopy(ts)
    small_ring = [ts.members[i].public_key for i in range(MIN_RING_SIZE - 1)]
    small = TrustProof(order=order, ring=small_ring,
                       signature=sign(order_message(order), small_ring, 0, secrets[0]))
    r5a = verify_proof(small, ts, pin, create_seen_set(), expected_order=order)
    print(f"ring of {MIN_RING_SIZE - 1} (below floor {MIN_RING_SIZE}): {r5a.reason!r}")
    assert r5a.ok is False and "below minimum" in r5a.reason

    dup_ring = [ts.members[0].public_key, ts.members[1].public_key,
                ts.members[0].public_key, ts.members[2].public_key]
    dup = TrustProof(order=order, ring=dup_ring,
                     signature=sign(order_message(order), dup_ring, 0, secrets[0]))
    r5b = verify_proof(dup, ts, pin, create_seen_set(), expected_order=order)
    print(f"duplicated key in ring: {r5b.reason!r}")
    assert r5b.ok is False and r5b.reason == "ring contains duplicate keys"

    expired = order_for(ts, order_id="order-old")
    expired.expires_at = "2020-01-01T00:00:00Z"
    r5c = verify_proof(proof_for(ts, secrets, expired), ts, pin, create_seen_set(), expected_order=expired)
    print(f"expired order: {r5c.reason!r}")
    assert r5c.ok is False and r5c.reason.startswith("order expired at ")

    print("\nnaive-verifier check uses 'any trusted key present' — the real policy requires")
    print("every ring member to be drawn FROM the pinned set, which is what makes it sound.")
    print("\nALL BEATS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
