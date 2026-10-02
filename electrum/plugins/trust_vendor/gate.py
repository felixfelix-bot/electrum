"""The money-path gate.

This is the piece that matters architecturally: verification is not a screen
that turns green, it is a gate on the payment. Inside Electrum this is driven
from the ``make_unsigned_transaction`` hook (``electrum/wallet.py``), so a
transaction to a vendor cannot be built unless the vendor's proof checks out
for that exact order.

Kept dependency-free so it is unit-testable and so ``qt.py`` only renders
verdicts — it never decides them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:  # in-tree Electrum import path
    from .trustset import TrustSet, TrustSetPin
    from .verify import (
        ANONYMOUS,
        KeyImageSeenSet,
        OrderContext,
        TrustProof,
        VerifyResult,
        verify_order_with_freshness,
    )
except ImportError:  # direct / unit-test import path
    from trustset import TrustSet, TrustSetPin  # type: ignore
    from verify import (  # type: ignore
        ANONYMOUS,
        KeyImageSeenSet,
        OrderContext,
        TrustProof,
        VerifyResult,
        verify_order_with_freshness,
    )


@dataclass
class TrustGate:
    """Stateful gate: one pinned set, one one-use register, one verdict policy."""

    trust_set: TrustSet
    pin: TrustSetPin
    cached_set: Optional[TrustSet] = None
    mode: str = ANONYMOUS
    seen: KeyImageSeenSet = field(default_factory=KeyImageSeenSet)

    def verify(self, proof: TrustProof, *, now: Optional[str] = None,
               order: Optional[OrderContext] = None) -> VerifyResult:
        """Verify a proof. Pass ``order`` — the order YOU believe you are paying.

        Omitting it verifies the order the prover supplied, which is fine for
        inspecting a proof and wrong for spending money.
        """
        return verify_order_with_freshness(
            proof,
            self.trust_set,
            self.pin,
            self.seen,
            cached_set=self.cached_set,
            now=now,
            mode=self.mode,
            expected_order=order,
        )

    def verify_order(
        self,
        *,
        order_id: str,
        amount_sats: int,
        payee: str,
        expires_at: str,
        ring,
        signature,
        now: Optional[str] = None,
    ) -> VerifyResult:
        """Convenience entry point for an Electrum send-tab / hook call site."""
        proof = TrustProof(
            order=OrderContext(
                order_id=order_id,
                amount_sats=amount_sats,
                payee=payee,
                pin=self.pin,
                expires_at=expires_at,
            ),
            ring=list(ring),
            signature=signature,
        )
        return self.verify(proof, now=now)
