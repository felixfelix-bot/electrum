# trust_vendor — ring-signature vendor vetting for Electrum

A vendor (or the facilitator paying on your behalf) proves *"one of the keys in
the trust set **you** pinned signed **this exact order**"* — without the proof
revealing **which** member it was. Electrum renders the verdict and gates the
payment on it.

Built for the Berlin hackathon spike (`ring-signatures-web-of-trust`), as an
**internal plugin in the fork** `c03rad0r/electrum`, branch
`pr/trust-vendor-plugin`.

## What is verified, and what is not

| Component | Status |
|---|---|
| `curve.py`, `lsag.py`, `trustset.py`, `verify.py`, `gate.py`, `hooks.py`, `trustset_relay.py` | **52 unit tests green** + headless demo (`demo.py`) asserting every attack beat |
| TS→Python port parity | `lsag.py` / `trustset.ts` ported byte-for-byte from the fleet's tested TypeScript (`mcp-cashu-exchange/packages/plugin-trust-ring/src/`, 18 tests) — same hash-to-curve quirk, same hash-to-scalar length-prefixing, same content-hash encoding |
| `qt.py` | **loads inside real Electrum 4.8** — `loaded plugin 'trust_vendor'` (Qt 6.11, Xvfb); the on-screen menu still needs a visual pass (the GUI sat on the wallet wizard). See `RUNTIME-EVIDENCE.md` |
| P3 relay fetch of the trust set | **implemented and demonstrated live** — a kind-30000 set published to `relay.damus.io` + `relay.primal.net`, fetched back and parsed (8 members) |
| P5 money-path gate | **implemented** on `abort_send` (blocks before the tx is built) and `tc_sign_wrapper`. NOT on `make_unsigned_transaction` — `run_hook` swallows exceptions there, so it is inspect-only |

Run the verified parts (no Electrum, no Qt, no network):

```bash
python3 -m venv .venv-trust && .venv-trust/bin/pip install coincurve pytest
.venv-trust/bin/python electrum/plugins/trust_vendor/demo.py          # narrative, asserts
.venv-trust/bin/python -m pytest trust_vendor_tests -q                # 20 tests
```

(The tests live at the repo root, **not** under `electrum/`: pytest derives a
package-qualified module name from any `__init__.py` on the path and would then
import the whole `electrum` package, which needs aiohttp/electrum_ecc/Qt.)

## The rule that makes it sound

A ring signature only proves **"one ring member signed"**. A verifier whose rule
is *"the ring contains at least one key I trust"* is **broken**: an attacker
builds `ring = {their own key, one scraped trusted key}`, signs with their own
key, and passes. `demo.py` beat 2 shows exactly that contrast (naive check:
`True`; real policy: rejected).

So the policy REQUIRES: pin the set by **id + content hash**, and require the
ring to be a **subset** of the pinned set, with no duplicates and a size floor.
`demo.py` beat 2 is the regression test for the whole design.

## Interface

- `TrustSet` (pinned by `TrustSetPin(set_id, content_hash)`) — yours. Each member
  declares a `basis` (`seed` / `met-in-person` / `vouched` / `bonded`), optional
  tier and expiry, so "trusted" is priced rather than asserted.
- `OrderContext(order_id, amount_sats, payee, pin, expires_at)` — what the proof
  binds. `order_message()` is domain-separated and length-prefixed: no captured
  proof is replayable onto another order.
- `verify_proof(proof, trust_set, pin, seen, expected_order=…)` → `VerifyResult`
  with a **stable reason string**; `gate.py`'s `TrustGate` wraps it with state.
- **Pass `expected_order` on any money path.** Without it the verifier checks the
  order the prover supplied, which a replay would simply re-declare.

## Modes

- `anonymous` (default): ring size floor = 4. This is the mode that buys
  something: the registry (and the customer) cannot tell which member signed, so
  order volume is not linkable to a member.
- `declared-1:1`: floor 1, for a relationship that is explicitly one-to-one.
  Legitimate, but it must be **labelled** — never a silent ring-of-one.

If the buyer already knows which vendor they are paying, a ring proof buys
almost nothing over a plain BIP340 signature by a pinned-set key over the order.
The ring earns its cost only when membership must stay unlinkable. Decide that
before building the next layer — it is the one design question here.

## Enabling it in Electrum 4.8

- **Internal (this spike):** the plugin lives at `electrum/plugins/trust_vendor/`,
  so run the fork from source (`./run_electrum`) and set
  `plugins.trust_vendor.enabled = true` in the config.
- **External plugins are zip-only and must be signed** against a root-owned
  `/etc/electrum/plugins_key` (`electrum/plugin.py:670`), so a directory drop-in
  in `~/.electrum/plugins/` can never be enabled. `contrib/make_plugin <dir>`
  builds the zip for the signed path.
- `manifest.json` declares `requires: [[coincurve, …]]`; Electrum import-checks
  deps. `electrum_ecc` (already an Electrum dependency) is the intended backend
  once the swap is done in `curve.py` — one file, same libsecp256k1.

## Security boundary — do not cross this

An Electrum plugin runs **in-process with full wallet access**: it can read the
keystore and build/broadcast transactions. Electrum encodes that reality
(external plugins must be signed zips against a root owned key).

Therefore: **never auto-generate a plugin from a scanned QR code or an LLM
prompt and install/run it.** The LLM may emit **data** — a catalog-adapter spec
and a trust-set config — reviewed by a human. The plugin itself stays a fixed,
reviewed, versioned artifact.

Second hazard: a "vetted vendor" list is a commercial target (pay-to-list,
extortion, fake registrars). The hard part of the product is the admission
policy, not the cryptography. Ring signatures prove membership in whatever set
you pin; they say nothing about why a key is in it.

## Next steps

1. **P3** — fetch the pinned set as a NIP-51 kind 30000 event via
   `electrum_aionostr` (already an Electrum dependency), cache it, and enforce
   monotonic versions (`trustset.check_freshness`).
2. **P4** — run `qt.py` for real under `run_electrum`; fix whatever the API
   turns out to be.
3. **P5** — gate `make_unsigned_transaction` (`electrum/wallet.py:2160`) so a
   payment to a vendor cannot be built without a valid proof for that amount.
4. Vendor side: a small signer (CLI or a shop page) that produces the proof; the
   catalog adapter for the real restaurant API stays outside the plugin.
