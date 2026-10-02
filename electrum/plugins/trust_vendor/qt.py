"""Qt GUI for the trust_vendor plugin (Electrum 4.8, PyQt6).

VERIFICATION STATUS — read before trusting this file:
  * ``curve``/``lsag``/``trustset``/``verify``/``gate``/``hooks``/``trustset_relay``
    are covered by 52 unit tests + a headless demo (see ../README.md).
  * THIS file is written against the Electrum 4.8 Qt API. It renders verdicts
    produced by ``gate.py``/``hooks.py`` and never decides anything itself.

The GUI is presentation only: the enforcement lives in ``hooks.py``, attached to
``abort_send`` (blocks before the tx is built) and ``tc_sign_wrapper`` (blocks
before signing completes). ``run_hook`` swallows exceptions, so those hooks
return the documented truthy/callable values rather than raising.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Optional

from PyQt6.QtWidgets import (
    QGridLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook
from electrum.gui.qt.util import Buttons, CloseButton, WindowModalDialog

from .gate import TrustGate
from .hooks import PendingVendorOrder, make_tc_sign_wrapper, should_abort_send
from .lsag import LSAGSignature
from .trustset import TrustSet, pin_trust_set
from .trustset_relay import DEFAULT_CACHE_DIR, cache_path, load_or_fetch
from .verify import OrderContext

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins

DEFAULT_SET_FILE = os.path.expanduser("~/.electrum/trust_vendor/trust_set.json")
DEFAULT_SET_ID = "burger-vendors-berlin"


def _maybe_webview(parent: QWidget, url: str) -> Optional[QWidget]:
    """Return a QtWebEngine view if it is installed, else None.

    PyQt6-WebEngine is not an Electrum dependency and shipping a browser engine
    inside a wallet is a real attack surface, so this is strictly best-effort:
    the caller falls back to opening the system browser.
    """
    try:
        from PyQt6.QtCore import QUrl
        from PyQt6.QtWebEngineWidgets import QWebEngineView  # type: ignore
    except Exception:
        return None
    view = QWebEngineView(parent)
    view.setUrl(QUrl(url))
    return view


class Plugin(BasePlugin):
    """Adds a 'Trusted Vendors' menu entry, a Send-tab shop button, and the
    send-path gate (``abort_send`` + ``tc_sign_wrapper``)."""

    def __init__(self, parent: 'Plugins', config: 'SimpleConfig', name: str):
        BasePlugin.__init__(self, parent, config, name)
        self._gate: Optional[TrustGate] = None
        self._pending: Optional[PendingVendorOrder] = None

    # ------------------------------------------------------------------ config

    def _cfg(self, key: str, default=None):
        return self.config.get(f"plugins.trust_vendor.{key}", default)

    def _set_id(self) -> str:
        return self._cfg("set_id", DEFAULT_SET_ID)

    def _cache_dir(self) -> str:
        return self._cfg("cache_dir", DEFAULT_CACHE_DIR)

    def _relay_fetch(self, set_id: str):
        """Adapter for trustset_relay.load_or_fetch: relay event dict or None."""
        from .relay import make_relay_fetch   # optional, import-light
        relays = self._cfg("relays")
        return make_relay_fetch(relays)(set_id)

    def _load_gate(self) -> Optional[TrustGate]:
        try:
            res = load_or_fetch(fetch=self._relay_fetch, set_id=self._set_id(),
                                cache_dir=self._cache_dir())
        except Exception as e:
            self.logger.info(f"trust_vendor: no usable trust set ({e!r})")
            return None
        if res.warning:
            self.logger.info(f"trust_vendor: {res.warning}")
        self.logger.info(
            f"trust_vendor: pinned {res.trust_set.set_id} "
            f"({len(res.trust_set.members)} members, source={res.source}, "
            f"hash={res.pin.content_hash[:16]}…)"
        )
        return TrustGate(trust_set=res.trust_set, pin=res.pin)

    # ------------------------------------------------------------ send-path gate

    @hook
    def load_wallet(self, wallet, window):
        self._gate = self._load_gate()
        # Screenshot/demo aid: with TRUST_VENDOR_AUTO_OPEN=1 the shop dialog opens
        # on its own once the wallet window exists. A headless Xvfb run can then
        # photograph the REAL dialog instead of a menu item that needs a click —
        # and it exercises the dialog code path, which no unit test can reach.
        if os.environ.get("TRUST_VENDOR_AUTO_OPEN") == "1":
            try:
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(1500, lambda: self._open_shop(window))
                self.logger.info("trust_vendor: TRUST_VENDOR_AUTO_OPEN=1 — opening the shop dialog")
            except Exception as e:
                self.logger.info(f"trust_vendor: auto-open skipped ({e!r})")

    @hook
    def abort_send(self, send_tab) -> bool:
        """Block a send that pays a pending vendor order without a valid proof."""
        try:
            payee, amount_sats = self._send_tab_target(send_tab)
            abort, why = should_abort_send(self._pending, self._gate,
                                           payee=payee, amount_sats=amount_sats)
            if abort:
                self.logger.warning(f"trust_vendor: send aborted — {why}")
                try:
                    send_tab.show_error(_("Vendor proof rejected") + f":\n{why}")
                except Exception:
                    pass
            return abort
        except Exception as e:                      # never break the wallet
            self.logger.exception(f"trust_vendor: abort_send error {e!r}")
            return False

    @hook
    def tc_sign_wrapper(self, wallet, tx, on_success, on_failure):
        """Re-verify the vendor proof at signing time (returns None => no change)."""
        try:
            return make_tc_sign_wrapper(self._pending, self._gate, on_success, on_failure)
        except Exception as e:
            self.logger.exception(f"trust_vendor: tc_sign_wrapper error {e!r}")
            return None

    @staticmethod
    def _send_tab_target(send_tab) -> tuple[Optional[str], int]:
        """Best-effort read of the send tab's payee + amount (defensive: Qt only)."""
        try:
            pi = send_tab.payto_e.paymentIdentifier
            amount = int(send_tab.amount_e.get_amount() or 0)
        except Exception:
            return None, 0
        payee = None
        try:
            if pi is not None:
                payee = getattr(pi, "address", None)
                if payee is None and getattr(pi, "bip21", None):
                    payee = pi.bip21.get("address")
        except Exception:
            payee = None
        return payee, amount

    # -------------------------------------------------------------- menu / shop

    @hook
    def init_menubar(self, window):
        menu = window.wallet_menu.addMenu(_("Trusted Vendors"))
        menu.addAction(_("Vet a vendor…"), lambda: self._show_panel(window))
        self.logger.info("trust_vendor: menu installed ('Trusted Vendors' in the wallet menu)")

    @hook
    def create_send_tab(self, grid: QGridLayout):
        button = QPushButton(_("Shop at a trusted vendor…"))
        button.setToolTip(_(
            "Pick a vendor from your pinned trust set. The payment is gated on the "
            "vendor's ring-signature proof for this exact order."
        ))
        button.clicked.connect(lambda: self._open_shop(button.window()))
        grid.addWidget(button, grid.rowCount(), 0, 1, 2)
        self.logger.info("trust_vendor: Send-tab shop button installed")

    def set_pending_order(self, order: OrderContext, ring, signature: LSAGSignature) -> None:
        """Called by the shop flow once the buyer has chosen an order."""
        self._pending = PendingVendorOrder(order=order, ring=list(ring), signature=signature)
        self.logger.info(f"trust_vendor: pending vendor order {order.order_id} "
                         f"({order.amount_sats} sat to {order.payee})")

    def clear_pending_order(self) -> None:
        self._pending = None

    # -------------------------------------------------------------- shop panel

    def _open_shop(self, window: QWidget) -> None:
        url = self._cfg("shop_url", "")
        dialog = WindowModalDialog(window, _("Trusted Vendors"))
        dialog.setMinimumSize(760, 540)
        vbox = QVBoxLayout(dialog)

        if url:
            view = _maybe_webview(dialog, url)
            if view is not None:
                vbox.addWidget(view, 1)
            else:
                from PyQt6.QtCore import QUrl
                from PyQt6.QtGui import QDesktopServices
                vbox.addWidget(QLabel(_(
                    "PyQt6-WebEngine is not installed, so the shop opens in your system "
                    "browser instead of inside Electrum."
                )))
                vbox.addWidget(QLabel(url))
                open_btn = QPushButton(_("Open vendor shop"))
                open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
                vbox.addWidget(open_btn)
        else:
            vbox.addWidget(QLabel(_(
                "No shop URL configured (plugins.trust_vendor.shop_url)."
            )))

        vbox.addWidget(self._verdict_view(dialog), 1)
        vbox.addLayout(Buttons(dialog, CloseButton))
        dialog.exec()

    def _show_panel(self, window: QWidget) -> None:
        dialog = WindowModalDialog(window, _("Vendor vetting"))
        dialog.setMinimumSize(700, 480)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(self._verdict_view(dialog), 1)
        vbox.addLayout(Buttons(dialog, CloseButton))
        dialog.exec()

    def _verdict_view(self, parent: QWidget) -> QTextBrowser:
        view = QTextBrowser(parent)
        view.setOpenExternalLinks(True)
        gate = self._gate
        if gate is None:
            view.setHtml(
                "<h3>No pinned trust set</h3><p>Set <code>plugins.trust_vendor.set_id</code> "
                "and either run with a reachable relay or place a cached set at "
                f"<code>{self._cache_dir()}</code>.</p>"
            )
            return view

        ts = gate.trust_set
        modes = {m.public_key.hex(): m for m in ts.members}
        pend = self._pending
        rows = [
            f"<h3>{ts.set_id}</h3>",
            f"<p>{ts.description}</p>",
            f"<p><b>Members:</b> {len(ts.members)} &nbsp; "
            f"<b>pinned hash:</b> <code>{gate.pin.content_hash[:24]}…</code></p>",
            "<p><b>Policy, in order:</b> pinned-set match → proof pin match → "
            "order binding → ring size floor → ring ⊆ pinned set → no duplicate keys → "
            "not expired → LSAG verify → key image unused.</p>",
        ]
        if pend is not None:
            basis = modes.get(pend.order.payee, None)
            rows.append(
                f"<h4>Pending vendor order</h4><ul>"
                f"<li>order <code>{pend.order.order_id}</code>, "
                f"{pend.order.amount_sats} sat to <code>{pend.order.payee}</code></li>"
                f"<li>ring of {len(pend.ring)} vendors from the pinned set "
                f"(which one signed is not revealed)</li>"
                f"<li>expires {pend.order.expires_at}</li></ul>"
            )
        view.setHtml("".join(rows))
        return view

    # ----------------------------------------------------------------- helpers

    def verify_proof_json(self, raw: str, order: OrderContext):
        """Inspect a pasted vendor proof (used by the shop flow / tests)."""
        if self._gate is None:
            raise RuntimeError("no pinned trust set loaded")
        payload = json.loads(raw)
        from .verify import TrustProof
        proof = TrustProof(
            order=order,
            ring=[bytes.fromhex(k) for k in payload["ring"]],
            signature=LSAGSignature.from_dict(payload["signature"]),
        )
        return self._gate.verify(proof, order=order)
