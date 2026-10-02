"""secp256k1 adapter for the trust_vendor plugin — byte-in / byte-out.

Backend: ``coincurve`` (libsecp256k1 bindings). Electrum already ships its own
libsecp256k1 wrapper (``electrum_ecc``), so swapping the two is a one-file
change and produces identical bytes; the plugin stays on coincurve for this
spike because the published ``electrum_ecc`` wheel does not import in a bare
venv here (``PyInit_libsecp256k1``) and because coincurve is declared in
``manifest.json`` → ``requires`` so Electrum can install it.

This module deliberately exposes no backend types: everything is bytes, so the
LSAG implementation is portable and unit-testable without Electrum or Qt.
"""

from __future__ import annotations

import hashlib
import os
from typing import Sequence

from coincurve import PublicKey

# secp256k1 group order n and field prime p.
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

_H2C_TAG = b"LSAG/H2C"
_HASH_TAG = b"LSAG/v1"


# ---------------------------------------------------------------------------
# scalars
# ---------------------------------------------------------------------------

def mod_n(x: int) -> int:
    return x % CURVE_ORDER


def scalar_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big") % CURVE_ORDER


def scalar_to_bytes(s: int) -> bytes:
    return mod_n(s).to_bytes(32, "big")


def random_scalar() -> int:
    return scalar_from_bytes(os.urandom(32))


# ---------------------------------------------------------------------------
# points (33-byte compressed form on the wire)
# ---------------------------------------------------------------------------

def point_from_bytes(b: bytes) -> PublicKey:
    """Parse + validate a 33-byte compressed point. Raises ValueError."""
    return PublicKey(bytes(b))


def is_valid_point(b: bytes) -> bool:
    try:
        point_from_bytes(b)
        return True
    except Exception:
        return False


def point_to_bytes(point: PublicKey) -> bytes:
    return point.format(compressed=True)


def base_mul(k: int) -> PublicKey:
    """k*G."""
    return PublicKey.from_valid_secret(scalar_to_bytes(k))


def point_mul(point: PublicKey, k: int) -> PublicKey:
    """k*P."""
    return point.multiply(scalar_to_bytes(k))


def point_add(p: PublicKey, q: PublicKey) -> PublicKey:
    """P + Q (with an explicit doubling path)."""
    if point_to_bytes(p) == point_to_bytes(q):
        return point_mul(p, 2)
    return p.combine([q])


def point_negate(point: PublicKey) -> PublicKey:
    """-P: flip the parity byte of the compressed encoding."""
    raw = bytearray(point_to_bytes(point))
    raw[0] = 0x03 if raw[0] == 0x02 else 0x02
    return point_from_bytes(bytes(raw))


def xonly_to_point(x32: bytes, even_y: bool = True) -> PublicKey:
    """BIP340 x-only pubkey -> full point (even-y per BIP340 by default)."""
    if len(x32) != 32:
        raise ValueError(f"x-only key must be 32 bytes, got {len(x32)}")
    return point_from_bytes((b"\x02" if even_y else b"\x03") + x32)


def point_x(point: PublicKey) -> bytes:
    return point_to_bytes(point)[1:33]


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

def tagged_hash(tag: bytes, *parts: bytes) -> bytes:
    """sha256(tag || parts...). Callers length-prefix when ambiguity matters."""
    h = hashlib.sha256()
    h.update(tag)
    for part in parts:
        h.update(part)
    return h.digest()


def _length_prefixed(item: bytes) -> bytes:
    return len(item).to_bytes(4, "big") + item


def hash_to_scalar(items: Sequence[bytes]) -> int:
    """H('LSAG/v1', item_0 ... item_k-1) mod n, each item 4-byte length-prefixed.

    Byte-for-byte port of ``hashToScalar`` in the TypeScript implementation
    (``mcp-cashu-exchange/packages/plugin-trust-ring/src/lsag.ts``).
    """
    h = hashlib.sha256()
    h.update(_HASH_TAG)
    for item in items:
        h.update(_length_prefixed(bytes(item)))
    return scalar_from_bytes(h.digest())


def hash_to_curve(data: bytes) -> bytes:
    """Deterministic hash-to-curve: try-and-increment, ~1/2 hit rate per step.

    Faithful port of ``hashToCurve`` in the TypeScript implementation: the
    candidate x-coordinate is ``digest[1:32] || 0x00`` and the parity byte is
    taken from ``digest[0] & 1`` — quirky but deterministic, and identical on
    both sides. Do not "fix" it without changing both implementations.
    """
    counter = 0
    while True:
        digest = hashlib.sha256(
            _H2C_TAG + data + counter.to_bytes(4, "big")
        ).digest()
        x = digest[1:32] + b"\x00"
        prefix = b"\x02" if (digest[0] & 0x01) == 0 else b"\x03"
        candidate = prefix + x
        if is_valid_point(candidate):
            return candidate
        counter += 1
