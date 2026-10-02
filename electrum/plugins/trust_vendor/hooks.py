"""Send-path gate: the money-path enforcement for the trust_vendor plugin.

Electrum facts this file is built on (all read from the 4.8 tree, not guessed):

* ``run_hook`` (``electrum/plugin.py:827``) **swallows hook exceptions** — a
  plugin can never block anything by raising inside a hook. Either return the
  documented truthy value, or return a replacement callable.
* ``abort_send``: ``send_tab.py:250`` and ``:303`` do
  ``if run_hook('abort_send', self): return`` — a truthy return aborts the send
  before the transaction is even built. The hook itself is responsible for
  showing the user why.
* ``tc_sign_wrapper``: ``main_window.py:1466`` does
  ``on_success = run_hook('tc_sign_wrapper', wallet, tx, on_success, on_failure) or on_success``.
  The returned callable is handed to ``WaitingDialog`` as the success callback
  and is therefore invoked with the signing result. Returning ``None`` leaves
  Electrum's normal flow untouched (``trustedcoin.py:461`` is the reference
  implementation).

Policy, deliberately conservative so ordinary wallet use is never broken:

* Enforcement applies **only while a vendor order is pending** (the user started
  the send from the vendor flow).
* A pending order is enforced when the send's payee and amount match it. A send
  that does not match the pending order is ordinary wallet use and is allowed.

The decision logic is pure (no Qt, no tx object) so it is unit-testable; ``qt.py``
wires these functions to the hooks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Sequence

try:  # in-tree Electrum import path
    from .gate import TrustGate
    from .lsag import LSAGSignature
    from .verify import OrderContext, TrustProof, VerifyResult
except ImportError:  # direct / unit-test import path
    from gate import TrustGate  # type: ignore
    from lsag import LSAGSignature  # type: ignore
    from verify import OrderContext, TrustProof, VerifyResult  # type: ignore


class TrustGateError(Exception):
    """Raised/forwarded when a vendor proof fails on the send path."""


@dataclass
class PendingVendorOrder:
    """The vendor order the user is currently paying, plus the vendor's proof.

    ``order`` is OURS — the order we believe we are paying, which is what the
    gate treats as authoritative. ``proof_order`` is the order the vendor's
    signature actually binds (it defaults to ours, and a mismatch is exactly the
    replay case the gate must catch).
    """

    order: OrderContext
    ring: Sequence[bytes]
    signature: LSAGSignature
    proof_order: Optional[OrderContext] = None

    @property
    def payee(self) -> str:
        return self.order.payee

    @property
    def amount_sats(self) -> int:
        return self.order.amount_sats

    def as_proof(self) -> TrustProof:
        return TrustProof(order=self.proof_order or self.order, ring=list(self.ring),
                          signature=self.signature)


def send_matches_pending(pending: Optional[PendingVendorOrder], *, payee: str, amount_sats: int) -> bool:
    """True when this send is the pending vendor order (payee + exact amount)."""
    if pending is None:
        return False
    return pending.payee == payee and int(pending.amount_sats) == int(amount_sats)


def should_abort_send(
    pending: Optional[PendingVendorOrder],
    gate: Optional[TrustGate],
    *,
    payee: str,
    amount_sats: int,
    now: Optional[str] = None,
) -> tuple[bool, str]:
    """Decide an ``abort_send`` hook return. Returns (abort, human reason)."""
    if pending is None:
        return False, "no vendor order pending: ordinary send"
    if not send_matches_pending(pending, payee=payee, amount_sats=amount_sats):
        return False, "send does not match the pending vendor order: ordinary send"
    if gate is None:
        return True, "vendor proof rejected: no pinned trust set loaded"
    res: VerifyResult = gate.verify(pending.as_proof(), order=pending.order, now=now)
    if res.ok:
        return False, f"vendor proof accepted (anonymity set {res.anonymity_set_size})"
    return True, f"vendor proof rejected: {res.reason}"


def make_tc_sign_wrapper(
    pending: Optional[PendingVendorOrder],
    gate: Optional[TrustGate],
    on_success: Callable,
    on_failure: Callable,
    *,
    now: Optional[str] = None,
) -> Optional[Callable]:
    """Build the ``tc_sign_wrapper`` replacement, or None to leave the flow alone."""
    if pending is None:
        return None

    def wrapper(result):
        if gate is None:
            err = TrustGateError("vendor proof rejected: no pinned trust set loaded")
            return on_failure((TrustGateError, err, None))
        res = gate.verify(pending.as_proof(), order=pending.order, now=now)
        if res.ok:
            return on_success(result)
        err = TrustGateError(f"vendor proof rejected: {res.reason}")
        return on_failure((TrustGateError, err, None))

    return wrapper


def payee_amount_from_tx(tx) -> list[tuple[str, int]]:
    """Best-effort read of a PartialTransaction's on-chain outputs (for the hook)."""
    try:
        return [(o.address, int(o.value)) for o in tx.outputs()]
    except Exception:
        return []
