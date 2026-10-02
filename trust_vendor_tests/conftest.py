"""Make the plugin package importable without importing the whole Electrum tree.

The plugin core (curve/lsag/trustset/verify/gate) is deliberately
dependency-light: it is byte-in/byte-out secp256k1 work with no aiohttp, no
electrum_ecc and no Qt. That is what lets this suite run in a plain venv, and
what makes the crypto testable independently of Electrum's GUI.

Run from the repository root:

    .venv-trust/bin/python -m pytest trust_vendor_tests -q -p no:cacheprovider

(The directory must NOT contain an ``__init__.py``: pytest would then derive a
package-qualified module name and import the whole ``electrum`` package first.)
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PLUGINS_DIR = os.path.join(_REPO_ROOT, "electrum", "plugins")
if _PLUGINS_DIR not in sys.path:
    sys.path.insert(0, _PLUGINS_DIR)
