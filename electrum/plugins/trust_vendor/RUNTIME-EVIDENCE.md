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

Timing caveat (2026-10-02): the fetch returns the event but only when the window
elapses — `EOSE` is not surfaced through `electrum_aionostr`'s queue, so the loop
runs until the deadline. A 12 s window returned `None` on relays that answer;
20–25 s returns the event. `wss://nos.lol` never answered (left in the list as a
best-effort extra). The probe's default is now 25 s.

API note worth keeping: in `electrum_aionostr` 0.1.0 `Manager.subscribe` is a
**coroutine** and must be awaited — the first version of `relay.py` silently
returned None until that was fixed.

## 4. The on-screen UI, verified (2026-10-02, later run)

The earlier "not proven" ended. With a wallet in the datadir and the Terms-of-Use
accepted, the real GUI loads the wallet and the plugin's UI hooks fire — the log
is self-proving (verbatim):

```
enabled: True | terms_of_use_accepted: 1 | shop_url: http://127.0.0.1:8899/order.html
plugins.trust_vendor.qt.Plugin | trust_vendor: Send-tab shop button installed
plugins.trust_vendor.qt.Plugin | trust_vendor: menu installed ('Trusted Vendors' in the wallet menu)
plugins.trust_vendor.qt.Plugin | trust_vendor: pinned burger-vendors-berlin (8 members, source=relay, hash=493fd518f4db9756…)
plugins.trust_vendor.qt.Plugin | trust_vendor: dialog title='Trusted Vendors' shop_url='http://127.0.0.1:8899/order.html' first_widget=QWebEngineView
```

Zero exceptions in that run. Two flags make it reproducible:

* `TRUST_VENDOR_AUTO_OPEN=1` — opens the shop dialog once the wallet window
  exists (a menu item needs a human click; a screenshot must not).
* `TRUST_VENDOR_DUMP_UI=1` — the dialog logs its own title, shop URL, the widget
  class in the first slot, and the verdict panel's plain text. A screenshot is
  not evidence a text-first agent can read.

`source=relay` is the important bit: the trust set is pinned **over the network**
during the real GUI run, not from the cache.

## 5. Three ways this was broken and one that only looked broken

1. **The dialog could never open.** `Buttons(dialog, CloseButton)` passes a class
   and the dialog; `Buttons` takes widget INSTANCES. Electrum's crash reporter
   caught it the first time the dialog was actually opened:
   `TypeError: addWidget(...) unexpected type 'PyQt6.sip.wrappertype'`. Correct:
   `Buttons(CloseButton(dialog))` — as everywhere else in Electrum. **The whole
   Qt layer had never been executed before this run.**
2. **No wallet window, therefore no hooks.** The GUI stopped on the Terms-of-Use
   wizard (`wizard | view "terms_of_use" last: True`) and never created a window,
   so `init_menubar`/`create_send_tab` never fired — which is why the plugin
   *looked* like it had no UI. Accept it headlessly:
   `config.set_key('terms_of_use_accepted', TERMS_OF_USE_LATEST_VERSION)`.
3. **"Chrome inside Electrum" silently degraded to a browser tab.** Qt refuses to
   import `QtWebEngineWidgets` once a `QCoreApplication` exists, and by dialog
   time Electrum's app is long created — the ImportError was swallowed by the
   fallback and the dialog rendered a QLabel with no explanation. The import now
   happens at **plugin-module load**, opt-in via `TRUST_VENDOR_EMBED_SHOP=1`
   (a wallet should not pull a browser engine unasked); the fallback now names
   its reason. With it, `first_widget=QWebEngineView` — real embedded Chromium.
   Under Xvfb it also needs
   `QTWEBENGINE_CHROMIUM_FLAGS='--no-sandbox --disable-gpu --disable-dev-shm-usage'`.
4. **The runner only worked from one directory.** The enable-plugin snippet
   imports `electrum.*`, so it must run from the runtime checkout; called from
   elsewhere it died with `ModuleNotFoundError: No module named
   'electrum.simple_config'` **into the log, silently**, and the plugin kept the
   shop URL of the last successful run. `electrum-plugin-run.sh` now `cd`s first.

The runner (`~/.hermes/profiles/manager/scripts/electrum-plugin-run.sh`) does the
whole loop — enable, accept ToU, launch under Xvfb, auto-open, dump the UI, kill,
grep the evidence — in about 60 seconds.

## 6. Still NOT proven

* A Qt-level smoke test that instantiates the plugin and calls the hooks with
  stub widgets **segfaulted** in this environment (Qt offscreen) and was deleted
  rather than committed — don't add one without a display. The auto-open run
  covers the same ground honestly (real window, real dialog, real webview).
* No installable external plugin zip yet (`contrib/make_plugin` unrun).
