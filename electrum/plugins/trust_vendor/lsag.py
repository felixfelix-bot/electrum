"""LSAG (Linkable Spontaneous Anonymous Group) ring signatures on secp256k1.

Reference: Liu, Wei, Wong — "Linkable Spontaneous Anonymous Group Signature for
Ad Hoc Groups" (2004).

Notation
    G      base point of secp256k1
    P_i    public key of ring member i (P_i = x_i * G)
    H(.)   hash-to-curve
    I      key image of the signer: I = x_s * H(P_s)
    c_i    challenge at position i
    r_i    response at position i

Sign (signer index s, secret x_s, ring P_0..P_{n-1}, message m)
    1. I = x_s * H(P_s)
    2. pick random r_s;  c_{s+1} = H(m, r_s*G, r_s*H(P_s))
    3. for i = s+1 .. s-1 (mod n), i != s:
         pick random r_i;  c_{i+1} = H(m, r_i*G + c_i*P_i, r_i*H(P_i) + c_i*I)
    4. close: r_s = r_s_random - x_s * c_s  (mod n)

Verify
    for each i: c_{i+1} = H(m, r_i*G + c_i*P_i, r_i*H(P_i) + c_i*I)
    accept iff c_n == c_0 and I is a valid non-identity point.

CRITICAL: r_i multiplies the generators (G, H(P_i)); c_i multiplies the public
keys (P_i, I). Swapping those roles breaks ring closure. This file is a
byte-for-byte port of the fleet's tested TypeScript implementation
(``mcp-cashu-exchange/packages/plugin-trust-ring/src/lsag.ts``, 18 tests green).

What it proves:   a holder of one ring key endorsed exactly this message.
What it does NOT: which member; that the key is not stolen/hot; that the signer
is still listed now (only as of the pinned set version).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

try:  # in-tree Electrum import path
    from .curve import (
        base_mul,
        hash_to_curve,
        hash_to_scalar,
        is_valid_point,
        mod_n,
        point_add,
        point_from_bytes,
        point_mul,
        point_to_bytes,
        random_scalar,
        scalar_from_bytes,
        scalar_to_bytes,
    )
except ImportError:  # direct / unit-test import path
    from curve import (  # type: ignore
        base_mul,
        hash_to_curve,
        hash_to_scalar,
        is_valid_point,
        mod_n,
        point_add,
        point_from_bytes,
        point_mul,
        point_to_bytes,
        random_scalar,
        scalar_from_bytes,
        scalar_to_bytes,
    )


@dataclass
class LSAGSignature:
    """(I, c_0, r_0..r_{n-1}) — the wire form the vendor hands to the verifier."""

    key_image: bytes                      # 33 bytes compressed
    c0: bytes                             # 32 bytes
    responses: list[bytes] = field(default_factory=list)  # n * 32 bytes

    def to_dict(self) -> dict:
        return {
            "key_image": self.key_image.hex(),
            "c0": self.c0.hex(),
            "responses": [r.hex() for r in self.responses],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "LSAGSignature":
        return cls(
            key_image=bytes.fromhex(raw["key_image"]),
            c0=bytes.fromhex(raw["c0"]),
            responses=[bytes.fromhex(r) for r in raw["responses"]],
        )


def generate_key_pair() -> tuple[bytes, bytes]:
    """Return (secret_key 32 bytes, compressed public key 33 bytes)."""
    secret = scalar_to_bytes(random_scalar())
    return secret, point_to_bytes(base_mul(scalar_from_bytes(secret)))


def _link_challenge(message: bytes, c: int, r: int, p_i: bytes, h_i: bytes, key_image: bytes) -> int:
    z1 = point_add(base_mul(r), point_mul(point_from_bytes(p_i), c))
    z2 = point_add(point_mul(point_from_bytes(h_i), r), point_mul(point_from_bytes(key_image), c))
    return hash_to_scalar([message, point_to_bytes(z1), point_to_bytes(z2)])


def sign(message: bytes, ring: Sequence[bytes], signer_index: int, secret_key: bytes) -> LSAGSignature:
    """Sign ``message`` as the ring member at ``signer_index``.

    If ``secret_key`` does not match ``ring[signer_index]`` the signature simply
    fails verification (it does not raise) — callers need that to build
    "wrong key" and adversarial test cases without try/except.
    """
    if not ring:
        raise ValueError("ring must have at least one member")
    if not 0 <= signer_index < len(ring):
        raise ValueError("signer_index out of range")

    n = len(ring)
    s = signer_index
    x_s = scalar_from_bytes(secret_key)

    h = [hash_to_curve(pk) for pk in ring]
    key_image = point_to_bytes(point_mul(point_from_bytes(h[s]), x_s))

    responses = [random_scalar() for _ in range(n)]
    r_s_random = responses[s]

    challenges = [0] * n
    # c_{s+1} = H(m, r_s*G, r_s*H(P_s)) using the *random* r_s
    c = hash_to_scalar([
        message,
        point_to_bytes(base_mul(r_s_random)),
        point_to_bytes(point_mul(point_from_bytes(h[s]), r_s_random)),
    ])
    challenges[(s + 1) % n] = c

    for step in range(1, n):
        i = (s + step) % n
        c = _link_challenge(message, c, responses[i], ring[i], h[i], key_image)
        challenges[(i + 1) % n] = c

    # c is now c_s — the challenge arriving back at the signer index.
    responses[s] = mod_n(r_s_random - x_s * c)
    return LSAGSignature(
        key_image=key_image,
        c0=scalar_to_bytes(challenges[0]),
        responses=[scalar_to_bytes(r) for r in responses],
    )


def verify(message: bytes, ring: Sequence[bytes], sig: LSAGSignature) -> bool:
    """Re-walk the ring; accept iff the hash chain closes at c_0."""
    n = len(ring)
    if n == 0 or len(sig.responses) != n:
        return False
    if not is_valid_point(sig.key_image):
        return False

    h: list[bytes] = []
    for pk in ring:
        if not is_valid_point(pk):
            return False
        h.append(hash_to_curve(pk))

    c0 = scalar_from_bytes(sig.c0)
    c = c0
    for i in range(n):
        r = scalar_from_bytes(sig.responses[i])
        try:
            c = _link_challenge(message, c, r, ring[i], h[i], sig.key_image)
        except Exception:
            return False
    return c == c0
