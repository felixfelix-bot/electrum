# Runtime evidence — the plugin inside real Electrum 4.8.0 (2026-10-02)

## 1. It loads in the real GUI

Command (see `electrum-plugin-run.sh`, shell-only):

```
bash ~/.hermes/profiles/manager/scripts/electrum-plugin-run.sh
```

Produced by Electrum itself, verbatim:

```
27:  1.52 | I | plugin.Plugins | loaded plugin 'trust_vendor'. (from thread: 'GUI')
30:  1.52 | I | gui.qt.ElectrumGui | Qt GUI starting up... Qt=6.11.0, PyQt=6.11.0
```

Full GUI log: `gui.log` (same directory as this file in the working copy).
Screenshot of the Xvfb display: `evidence/runtime-screenshot.png` (1280x900 PNG).

Environment: Electrum 4.8.0, Python 3.11.15, PyQt6/Qt 6.11.0, `electrum_ecc`
0.0.8, launched under `Xvfb :97`.

## 2. PITFALL: hand-writing the plugin key is not enough

Writing only the flat key into `<datadir>/config`:

```json
{ "plugins.trust_vendor.enabled": true }
```

leaves `is_plugin_enabled('trust_vendor')` **False**, and the plugin never loads.
The plugin manager reads the nested dict. Use Electrum's own API, which writes
both forms:

```python
from electrum.simple_config import SimpleConfig
cfg = SimpleConfig({'electrum_path': datadir})
cfg.enable_plugin('trust_vendor')
```

## 3. The relay transport is live, not theoretical

A NIP-51 kind-30000 trust set was published to public relays and then fetched
back by the plugin's own transport:

* published event id `06897768b60ee653f2c9b0da7773e025e3c95896a87275f72f4b19004cacfc24`
  (kind 30000, `d=burger-vendors-berlin`, 8 `p` tags with 64-hex x-only keys)
  to `wss://relay.damus.io` and `wss://relay.primal.net` — both reported success;
* `trustset_relay.load_or_fetch(fetch=relay.make_relay_fetch(...), set_id=...)`
  fetched it back through `electrum_aionostr` and parsed it:

```
raw event: {'id': '06897768b6…', 'kind': 30000, 'created_at': 1790926896, 'tags': '10 tags'}
parsed: set_id=burger-vendors-berlin members=8 published_at=2026-10-02T07:41:36Z
```

Reproduce with `trust_vendor_tests/manual_relay_probe.py` (needs the runtime venv).

API note worth keeping: in `electrum_aionostr` 0.1.0 `Manager.subscribe` is a
**coroutine** and must be awaited — the first version of `relay.py` silently
returned None until that was fixed.

## 4. What is still NOT proven

* The **on-screen** menu entry: the GUI reached the wallet wizard
  (`wizard | view "terms_of_use" last: True`) rather than a wallet window, so
  `init_menubar`/`create_send_tab` did not fire in that run. The hook wiring is
  covered by unit tests; a visual pass needs the wallet window open.
* A Qt-level smoke test that instantiates the plugin and calls the hooks with
  stub widgets **segfaulted** in this environment (Qt offscreen), so it was not
  committed — don't add one without a display.
