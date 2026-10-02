#!/usr/bin/env bash
# Run the trust_vendor plugin inside REAL Electrum 4.8 under Xvfb and capture
# proof that it loads and its UI is present.
#
# Shell-only (no LLM). Requires the runtime venv built by
# electrum-runtime-bringup.sh.
#
# PITFALL (measured 2026-10-02): writing only the flat key
# "plugins.trust_vendor.enabled" into the config file is NOT enough for Electrum
# 4.8 — the plugin manager reads the nested "plugins" dict. Use Electrum's own
# SimpleConfig.enable_plugin(), which writes both. Also: run run_electrum with
# the VENV python ($PY run_electrum); the file's shebang picks the system python.
set -uo pipefail
RUNTIME="$HOME/worktrees/electrum-runtime"
PY="$RUNTIME/.venv-run/bin/python"
DIR="$HOME/electrum-tv-demo"
OUT="$HOME/worktrees/electrum-plugin-run"
LOG="$OUT/run.log"
SHOT="$OUT/screenshot.png"
SET_ID="${SET_ID:-burger-vendors-berlin}"
SHOP_URL="${SHOP_URL:-http://127.0.0.1:8899/order.html}"   # the real pizza shop; start it with:
#   python3 -m http.server 8899 --bind 127.0.0.1 --directory ~/worktrees/mcp-cashu-exchange/apps/worker/public
mkdir -p "$DIR" "$OUT"
# The enable-plugin snippet imports electrum.*, so it must run from the runtime
# checkout. Without this cd the script only worked when the caller happened to
# be in $RUNTIME (measured 2026-10-02: silent ModuleNotFoundError, and the
# plugin then kept whatever shop_url the last successful run had written).
cd "$RUNTIME"
: >"$LOG"
exec >>"$LOG" 2>&1

echo "=== $(date -Is) trust_vendor in Electrum $(grep -m1 "ELECTRUM_VERSION" "$RUNTIME/electrum/version.py" | cut -d"'" -f2) ==="

echo "--- enable the plugin through Electrum's own config API"
"$PY" - "$DIR" "$SET_ID" "$SHOP_URL" <<'PY'
import sys
from electrum.simple_config import SimpleConfig
d, set_id, shop_url = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = SimpleConfig({'electrum_path': d})
cfg.enable_plugin('trust_vendor')            # writes BOTH the nested dict and the flat key
cfg.set_key('plugins.trust_vendor.set_id', set_id, save=True)
cfg.set_key('plugins.trust_vendor.shop_url', shop_url, save=True)
# PITFALL (measured 2026-10-02): without this the GUI stops on the Terms-of-Use
# wizard and NO wallet window is ever created, so init_menubar/create_send_tab
# never fire and the run looks like "the plugin UI is broken". The check is
# `TERMS_OF_USE_ACCEPTED >= TERMS_OF_USE_LATEST_VERSION` (electrum/gui/messages.py).
try:
    from electrum.gui.messages import TERMS_OF_USE_LATEST_VERSION as TOU
except Exception:
    TOU = 99
cfg.set_key('terms_of_use_accepted', TOU, save=True)
print("enabled:", cfg.is_plugin_enabled('trust_vendor'), "| terms_of_use_accepted:", TOU,
      "| shop_url:", shop_url)
PY

echo "--- wallet"
WALLET="$DIR/wallets/demo"
if [ ! -f "$WALLET" ]; then
  mkdir -p "$DIR/wallets"
  printf '\n\n' | timeout 120 xvfb-run -a "$PY" "$RUNTIME/run_electrum" --offline --dir "$DIR" -w demo create >/dev/null 2>&1
  STRAY="$RUNTIME/demo"
  if [ -f "$STRAY" ]; then cp "$STRAY" "$WALLET"; fi
  [ -f "$WALLET" ] || cp "$DIR/demo" "$WALLET" 2>/dev/null
fi
ls -la "$DIR/wallets" || true

echo "--- launch under Xvfb"
export DISPLAY=:97
# Screenshot aid: opens the shop dialog by itself once the wallet window exists,
# so the captured PNG shows the real UI (see qt.py load_wallet).
export TRUST_VENDOR_AUTO_OPEN="${TRUST_VENDOR_AUTO_OPEN:-1}"
export TRUST_VENDOR_DUMP_UI="${TRUST_VENDOR_DUMP_UI:-1}"
# Opt-in embedded shop view ('chrome inside Electrum'). Must be set in the env
# BEFORE the plugin module loads — QtWebEngineWidgets cannot be imported once a
# QCoreApplication exists (see qt.py _EMBED_SHOP).
export TRUST_VENDOR_EMBED_SHOP="${TRUST_VENDOR_EMBED_SHOP:-1}"
# Chromium inside Xvfb needs these or QWebEngineView dies at construction and the
# plugin falls back to "open in the system browser" (measured 2026-10-02).
export QTWEBENGINE_CHROMIUM_FLAGS="${QTWEBENGINE_CHROMIUM_FLAGS:---no-sandbox --disable-gpu --disable-dev-shm-usage}"
rm -f /tmp/.X97-lock
Xvfb :97 -screen 0 1280x900x24 >"$OUT/xvfb.log" 2>&1 &
XPID=$!
sleep 3
"$PY" "$RUNTIME/run_electrum" --offline --dir "$DIR" -w demo -v >"$OUT/gui.log" 2>&1 &
APP=$!
sleep 40
if command -v import >/dev/null; then import -window root "$SHOT" && echo "screenshot: $SHOT"; fi
ls -la "$SHOT" || true

echo "--- proof: plugin load + plugin log lines"
grep -n "loaded plugin 'trust_vendor'" "$OUT/gui.log" || echo "!! plugin load line NOT found"
grep -n "trust_vendor:" "$OUT/gui.log" | head -8 || true
grep -n "Qt GUI starting up\|ElectrumWindow" "$OUT/gui.log" | head -3 || true

kill "$APP" 2>/dev/null; sleep 2; kill -9 "$APP" 2>/dev/null
kill "$XPID" 2>/dev/null
echo "=== done $(date -Is) ==="
tail -30 "$LOG"
