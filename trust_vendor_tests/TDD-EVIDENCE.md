# TDD evidence

## RED — before the implementation existed (2026-10-02)

Command (run in the worktree, from the repo root):

```
.venv-trust/bin/python -m pytest trust_vendor_tests -q -p no:cacheprovider
```

Output:

```
electrum/plugins/trust_vendor/tests/test_trust_vendor.py:18: in <module>
    from trust_vendor.lsag import (
E   ModuleNotFoundError: No module named 'trust_vendor.lsag'
=========================== short test summary info ============================
ERROR electrum/plugins/trust_vendor/tests/test_trust_vendor.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.17s
rc=2
```

## First GREEN run after writing the core, with two honest failures

```
2 failed, 17 passed in 0.11s
```

Both failures were **test-design bugs, and they found a real design gap**:

1. `test_replay_to_a_different_order_is_rejected` — the policy verified the
   message built from `proof.order`, i.e. the order the *prover* supplied. A
   replay therefore re-declared itself and passed. Fix: `verify_proof` takes
   `expected_order` (the verifier's authoritative order) and requires the proof's
   order to match field-by-field; the money path must always pass it. The API
   docstring now says so.
2. `test_proof_carrying_a_foreign_pin_is_rejected` — the test mutated
   `proof.order.pin`, which was the *same object* as the verifier's own order, so
   the mismatch it produced was the wrong one. Fix in the test (copy before
   mutating).

Also added while fixing: `test_wrong_secret_key_fails_lsag_verification`, which
keeps the LSAG-failure path covered now that replays are caught earlier by the
order-match check.

## GREEN

```
.venv-trust/bin/python -m pytest trust_vendor_tests -q -p no:cacheprovider
....................                                                     [100%]
20 passed in 0.09s
```

## Demo (asserts every attack beat, exits non-zero on regression)

```
.venv-trust/bin/python electrum/plugins/trust_vendor/demo.py
```

Key beats, verbatim:

```
[2] ATTACK: attacker adds their own key to the ring
naive check 'is a trusted key in the ring?' -> True   (this is the bug)
real verdict: ok=False reason='ring contains a key outside the pinned trust set'

[3] ATTACK: replay a captured proof onto another order
verdict: ok=False reason="proof's order does not match the verifier's order (order_id)"

[4] ATTACK: submit the same proof twice
first  attempt: ok=True
second attempt: ok=False reason='key image already used for this order — duplicate proof rejected'

[5] Structural checks: small ring, duplicated key, stale order
ring of 3 (below floor 4): 'ring size 3 is below minimum 4'
duplicated key in ring: 'ring contains duplicate keys'
expired order: 'order expired at 2020-01-01T00:00:00Z'

ALL BEATS PASSED
```
