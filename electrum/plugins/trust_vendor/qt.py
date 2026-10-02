"""Qt GUI for the trust_vendor plugin (Electrum 4.8, PyQt6).

VERIFICATION STATUS — read before trusting this file:
  * ``curve``/``lsag``/``trustset``/``verify``/``gate`` are covered by 20 unit
    tests and a headless demo (see ../README.md).
  * THIS file is written against the Electrum 4.8 Qt API but was NOT executed
    in the environment that produced it (no PyQt6, and ``electrum_ecc`` does not
    import there). It is reviewed-but-unrun: run ``run_electrum`` from the fork
    with the plugin enabled to validate it before showing it to anyone.

The GUI never decides anything: it renders verdicts produced by ``gate.py``.
That separation is deliberate — a screen that "turns green" is not a control.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
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
from .lsag import LSAGSignature
from .trustset import TrustSet, pin_trust_set
from .verify import OrderContext, TrustProof

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.plugin import Plugins

DEFAULT_SET_FILE = os.path.expanduser("~/.electrum/trust_vendor/trust_set.json")


def _maybe_webview(parent: QWidget, url: str) -> Optional[QWidget]:
    """Return a QtWebEngine view if available, else None.

    PyQt6-WebEngine is NOT a dependency of Electrum (and shipping a browser
    engine inside a wallet is a real attack surface), so this is strictly
    best-effort: when it is missing the caller falls back to opening the
    system browser.
    """
    try:
        from PyQt6.QtWebEngineWidgets import QWebEngineView  # type: ignore
        from PyQt6.QtCore import QUrl
    except Exception:
        return None
    view = QWebEngineView(parent)
    view.setUrl(QUrl(url))
    return view


class Plugin(BasePlugin):
    """Adds a "Trusted Vendors" menu entry and a shop button on the Send tab."""

    def __init__(self, parent: 'Plugins', config: 'SimpleConfig', name: str):
        BasePlugin.__init__(self, parent, config, name)
        self._gate: Optional[TrustGate] = None

    # ------------------------------------------------------------------ wiring

    @hook
    def load_wallet(self, wallet, window):
        """Rebuild the gate whenever a wallet window appears."""
        self._gate = self._load_gate()

    def _load_gate(self) -> Optional[TrustGate]:
        """Load the pinned trust set from disk (P3 replaces this with a NIP-51
        relay fetch via ``electrum_aionostr`` + a local cache)."""
        path = self.config.get("plugins.trust_vendor.set_file", DEFAULT_SET_FILE)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                ts = TrustSet.from_dict(json.load(fh))
        except Exception as e:
            self.logger.info(f"trust_vendor: no usable trust set at {path}: {e!r}")
            return None
        pin = pin_trust_set(ts)
        self.logger.info(f"trust_vendor: pinned {ts.set_id} ({len(ts.members)} members)")
        return TrustGate(trust_set=ts, pin=pin)

    @hook
    def init_menubar(self, window):
        menu = window.wallet_menu.addMenu(_("Trusted Vendors"))
        menu.addAction(_("Vet a vendor…"), lambda: self._show_panel(window))

    @hook
    def create_send_tab(self, grid: QGridLayout):
        """A shop button next to the normal send controls."""
        button = QPushButton(_("Shop at a trusted vendor…"))
        button.setToolTip(_(
            "Pick a vendor from your pinned trust set. The payment is gated on "
            "the vendor's ring-signature proof for the exact order."
        ))
        button.clicked.connect(lambda: self._open_shop(button.window()))
        row = grid.rowCount()
        grid.addWidget(button, row, 0, 1, 2)

    # -------------------------------------------------------------- shop panel

    def _open_shop(self, window: QWidget) -> None:
        url = self.config.get("plugins.trust_vendor.shop_url", "")
        dialog = WindowModalDialog(window, _("Trusted Vendors"))
        dialog.setMinimumSize(720, 520)
        vbox = QVBoxLayout(dialog)

        if not url:
            vbox.addWidget(QLabel(_(
                "No shop URL configured. Set plugins.trust_vendor.shop_url, or "
                "use the menu entry to inspect a vendor proof."
            )))
        else:
            view = _maybe_webview(dialog, url)
            if view is not None:
                vbox.addWidget(view, 1)
            else:
                from PyQt6.QtCore import QUrl
                from PyQt6.QtGui import QDesktopServices
                vbox.addWidget(QLabel(_(
                    "PyQt6-WebEngine is not installed, so the shop opens in your "
                    "system browser instead of inside Electrum."
                )))
                vbox.addWidget(QLabel(url))
                open_btn = QPushButton(_("Open vendor shop"))
                open_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(url)))
                vbox.addWidget(open_btn)

        vbox.addWidget(self._verdict_view(dialog), 1)
        buttons = Buttons(dialog, CloseButton)
        vbox.addLayout(buttons)

        dialog.exec()

    # ------------------------------------------------------------ verify panel

    def _show_panel(self, window: QWidget) -> None:
        dialog = WindowModalDialog(window, _("Vendor vetting"))
        dialog.setMinimumSize(680, 460)
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
                "<h3>No pinned trust set</h3>"
                "<p>Create a trust set JSON and point "
                "<code>plugins.trust_vendor.set_file</code> at it.</p>"
            )
            return view

        ts = gate.trust_set
        lines = [
            f"<h3>{ts.set_id}</h3>",
            f"<p>{ts.description}</p>",
            f"<p><b>Members:</b> {len(ts.members)} &nbsp; "
            f"<b>set version hash:</b> <code>{gate.pin.content_hash[:24]}…</code></p>",
            "<p><b>Policy (in order)</b>: pinned-set match → proof pin match → "
            "ring size floor → ring ⊆ pinned set → no duplicate keys → not "
            "expired → LSAG verify → key image unused.</p>",
        ]
        reasons = self.config.get("plugins.trust_vendor.last_reasons", [])
        if reasons:
            lines.append("<h4>Recent verdicts</h4><ul>")
            lines.extend(f"<li><code>{r}</code></li>" for r in reasons[-8:])
            lines.append("</ul>")
        view.setHtml("".join(lines))
        return view

    # ----------------------------------------------------------------- helpers

    def verify_proof_json(self, raw: str, order: OrderContext):
        """Inspect a pasted vendor proof. Returns the gate's VerifyResult."""
        if self._gate is None:
            raise RuntimeError("no pinned trust set loaded")
        payload = json.loads(raw)
        proof = TrustProof(
            order=order,
            ring=[bytes.fromhex(k) for k in payload["ring"]],
            signature=LSAGSignature.from_dict(payload["signature"]),
        )
        return self._gate.verify(proof, order=order)
