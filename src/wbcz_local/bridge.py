from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import platform
import shutil
from typing import Iterable


@dataclass(frozen=True, slots=True)
class CryptoProFoundationStatus:
    windows: bool
    cryptopro_csp_detected: bool
    cryptcp_path: str | None
    stunnel_path: str | None
    real_read_enabled: bool = False
    business_write_enabled: bool = False

    def safe_dict(self) -> dict:
        return asdict(self)


def _candidate_paths(explicit: str | None, names: Iterable[str]) -> list[Path]:
    result: list[Path] = []
    if explicit:
        result.append(Path(explicit).expanduser())
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            result.append(Path(resolved))
    roots = [
        os.getenv("ProgramFiles", ""),
        os.getenv("ProgramFiles(x86)", ""),
    ]
    for root in filter(None, roots):
        base = Path(root) / "Crypto Pro" / "CSP"
        for name in names:
            result.append(base / name)
    return result


def _first_existing(candidates: Iterable[Path]) -> Path | None:
    for path in candidates:
        try:
            if path.is_file():
                return path.resolve()
        except OSError:
            continue
    return None


def inspect_local_cryptopro_foundation() -> CryptoProFoundationStatus:
    windows = platform.system().lower() == "windows"
    cryptcp = _first_existing(
        _candidate_paths(os.getenv("WBCZ_CRYPTOPRO_CRYPTCP"), ("cryptcp.exe", "cryptcp"))
    )
    stunnel = _first_existing(
        _candidate_paths(os.getenv("WBCZ_CRYPTOPRO_STUNNEL"), ("stunnel.exe", "stunnel"))
    )
    csp_candidates = _candidate_paths(None, ("csptest.exe", "csptest"))
    csp = _first_existing(csp_candidates)
    return CryptoProFoundationStatus(
        windows=windows,
        cryptopro_csp_detected=bool(windows and (csp or cryptcp)),
        cryptcp_path=str(cryptcp) if cryptcp else None,
        stunnel_path=str(stunnel) if stunnel else None,
        real_read_enabled=False,
        business_write_enabled=False,
    )


class LocalTrueApiBridgeFoundation:
    """Diagnostics-only bridge boundary for phase 058.

    It intentionally exposes no arbitrary signing or business-document method.
    The accepted local read transport will be wired in a later task.
    """

    def diagnostics(self) -> dict:
        return inspect_local_cryptopro_foundation().safe_dict()
