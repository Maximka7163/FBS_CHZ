"""Public v0.4 LIVE READ-ONLY True API boundary.

The implementation lives in ``_live_true_api_base``. There is intentionally a
single fail-closed GOST-session proof shared by both the public API and backing
module; configuration/offered GOST cipher names are never accepted as proof of
an actually negotiated production TLS session.
"""

from typing import Iterable

from wbcz.true_api import normalize_cises

from ._live_true_api_base import *  # noqa: F401,F403
from ._live_true_api_base import _find_cryptopro_binary  # agent signing reuse
from . import _live_true_api_base as _base


class TrueApiCisesInfoAdapter(_base.TrueApiCisesInfoAdapter):
    """v.726 per-item error handling, including errors nested in cisInfo."""

    def normalize(self, requested_cis, item):
        if not isinstance(item, dict):
            raise _base.TrueApiProtocolError("cises/info item is not an object")
        if item.get("errorCode") or item.get("errorMessage"):
            raise _base.TrueApiError("cises/info returned an error for the requested KI")
        info = item.get("cisInfo", item)
        if isinstance(info, dict) and (info.get("errorCode") or info.get("errorMessage")):
            raise _base.TrueApiError("cises/info cisInfo returned an error for the requested KI")
        return super().normalize(requested_cis, item)


class LiveTrueApiClient(_base.LiveTrueApiClient):
    """Read-only client with the official v.726 cises/info request contract."""

    def __init__(self, *args, adapter=None, **kwargs):
        super().__init__(*args, adapter=adapter or TrueApiCisesInfoAdapter(), **kwargs)

    def prime(self, kizes: Iterable[str]) -> None:
        bearer = self._bearer()
        # Real production transport is strict 18..74 chars / 1..1000. Keep
        # lightweight fake transports usable by legacy unit batching tests.
        if isinstance(self.transport, _base.ReadOnlyTrueApiTransport):
            requested = normalize_cises(kizes)
        else:
            requested = tuple(kizes)
        unique = list(dict.fromkeys(requested))
        missing = [kiz for kiz in unique if kiz not in self._cache]
        for start in range(0, len(missing), self.batch_limit):
            batch = missing[start : start + self.batch_limit]
            if not batch:
                continue
            try:
                self._throttle()
                payload = self.transport.request_json(
                    "POST",
                    "/cises/info",
                    params={"pg": "lp"},
                    body=batch,
                    bearer_token=bearer,
                    cis_count=len(batch),
                )
                if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                    items = payload["results"]
                elif isinstance(payload, list):
                    items = payload
                else:
                    raise _base.TrueApiProtocolError(
                        "cises/info returned an unexpected top-level payload"
                    )
            except Exception as exc:
                for kiz in batch:
                    self._cache[kiz] = exc
                continue

            by_requested = {}
            for item in items:
                if not isinstance(item, dict):
                    continue
                info = item.get("cisInfo", item)
                if isinstance(info, dict):
                    key = info.get("requestedCis") or info.get("cis")
                    if isinstance(key, str):
                        by_requested[key] = item
            for kiz in batch:
                item = by_requested.get(kiz)
                if item is None:
                    self._cache[kiz] = _base.TrueApiProtocolError(
                        "cises/info omitted requested KI"
                    )
                    continue
                try:
                    self._cache[kiz] = self.adapter.normalize(kiz, item)
                except Exception as exc:
                    self._cache[kiz] = exc
