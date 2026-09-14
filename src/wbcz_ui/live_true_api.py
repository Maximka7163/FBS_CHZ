"""Public v0.4 LIVE READ-ONLY True API boundary.

The implementation lives in ``_live_true_api_base``. There is intentionally a
single fail-closed GOST-session proof shared by both the public API and backing
module; configuration/offered GOST cipher names are never accepted as proof of
an actually negotiated production TLS session.
"""

from ._live_true_api_base import *  # noqa: F401,F403
from ._live_true_api_base import _find_cryptopro_binary  # agent signing reuse
