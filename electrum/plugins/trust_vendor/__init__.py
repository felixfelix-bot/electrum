"""trust_vendor — ring-signature vendor vetting for Electrum.

The GUI entry point is ``qt.py`` (``class Plugin``), which Electrum loads as
``electrum.plugins.trust_vendor.qt``. This module is intentionally import-light:
the core (``curve``, ``lsag``, ``trustset``, ``verify``, ``gate``) must be
unit-testable without Electrum, PyQt6, or network access.

Design in one line: the verifier owns a PINNED set of trusted vendors; a vendor
proves "one of those keys signed this exact order" with an LSAG ring signature,
without revealing which member it is.
"""
