from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import json
import math
import os
import re
from typing import Any, Mapping, Protocol, Sequence

from wbcz.printing import (
    MAX_MODULE_SIZE_MM,
    MIN_MODULE_SIZE_MM,
    PrintingContractError,
    PrintingRuntimeUnavailable,
    SYNTHETIC_PREVIEW_FULL_KM,
    render_gs1_datamatrix,
    validate_layout,
)


PRINT_PROTOCOL_VERSION = "printing-agent-v2"
DISCOVERY_CAPABILITY = "PRINT_DISCOVER_PRINTERS"
SYNTHETIC_FIXTURE_VERSION = "SELLARI_SYNTHETIC_LABEL_V1"
PHYSICAL_EXECUTION_BLOCKED = "PHYSICAL_EXECUTION_BLOCKED_PHASE_C"
DISCOVERY_OPERATIONS = frozenset({"LIST", "CAPABILITIES"})
PROFILE_STATES = frozenset({"ACTIVE", "STALE", "MISSING", "INCOMPATIBLE", "DISABLED"})
OBSERVATION_STATES = frozenset({"AVAILABLE", "UNAVAILABLE", "ERROR"})
ORIENTATIONS = frozenset({"PORTRAIT", "LANDSCAPE"})
COMPATIBLE = "COMPATIBLE"

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_SAFE_NAME = 160
MAX_PRINTERS_DEFAULT = 64
MAX_PRINTERS_HARD = 256
MIN_DPI = 150
MAX_DPI = 1200
MEDIA_TOLERANCE_MM = 0.5


class PrinterProfileContractError(ValueError):
    pass


class PrinterProfileSecurityError(PrinterProfileContractError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _finite_number(value: Any, label: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrinterProfileContractError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise PrinterProfileContractError(f"{label} is invalid")
    return result


def sanitize_display_name(value: str, *, fallback: str = "Printer") -> str:
    if not isinstance(value, str):
        raise PrinterProfileContractError("printer display value must be a string")
    # Exact Windows queue/server/port paths remain local. For a connection-style
    # queue name only the leaf label is allowed to cross the Agent boundary.
    text = value.strip()
    if text.startswith("\\\\"):
        text = text.rstrip("\\").rsplit("\\", 1)[-1]
    elif text.startswith("//"):
        text = text.rstrip("/").rsplit("/", 1)[-1]
    text = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text)
    text = " ".join(text.split())
    if not text:
        text = fallback
    if (
        text.startswith("/")
        or re.match(r"^[A-Za-z]:[\\/]", text)
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text)
    ):
        raise PrinterProfileSecurityError("printer path must not cross the Agent boundary")
    return text[:MAX_SAFE_NAME]


def _canonical_capability_payload(value: Mapping[str, Any]) -> bytes:
    keys = (
        "driver_name_sanitized",
        "dpi_x",
        "dpi_y",
        "media_width_mm",
        "media_height_mm",
        "orientation",
        "physical_width_px",
        "physical_height_px",
        "printable_width_px",
        "printable_height_px",
        "offset_x_px",
        "offset_y_px",
        "availability_state",
    )
    data = {key: value[key] for key in keys}
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def capability_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(b"sellari-printer-capability-v1\0" + _canonical_capability_payload(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class PrinterObservation:
    agent_printer_id: str
    local_printer_fingerprint: str
    display_name_sanitized: str
    driver_name_sanitized: str | None
    dpi_x: int
    dpi_y: int
    media_width_mm: float
    media_height_mm: float
    orientation: str
    physical_width_px: int
    physical_height_px: int
    printable_width_px: int
    printable_height_px: int
    offset_x_px: int
    offset_y_px: int
    capability_hash: str
    observed_at: str
    availability_state: str = "AVAILABLE"
    safe_error_code: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PrinterObservation":
        allowed = {
            "agent_printer_id", "local_printer_fingerprint", "display_name_sanitized",
            "driver_name_sanitized", "dpi_x", "dpi_y", "media_width_mm",
            "media_height_mm", "orientation", "physical_width_px",
            "physical_height_px", "printable_width_px", "printable_height_px",
            "offset_x_px", "offset_y_px", "capability_hash", "observed_at",
            "availability_state", "safe_error_code",
        }
        forbidden = {
            "queue", "queue_name", "printer_name", "printer_path", "server_name",
            "share_name", "port", "port_name", "devmode", "raw_devmode",
            "command", "printer_command", "zpl", "epl", "cpcl", "url", "path",
        }
        keys = {str(key).casefold() for key in raw}
        if keys & forbidden:
            raise PrinterProfileSecurityError("raw printer path/command fields are forbidden")
        unknown = set(raw) - allowed
        if unknown:
            raise PrinterProfileContractError(f"unsupported printer observation fields: {sorted(unknown)}")
        display = sanitize_display_name(str(raw.get("display_name_sanitized") or ""))
        driver_raw = raw.get("driver_name_sanitized")
        driver = sanitize_display_name(str(driver_raw), fallback="Unknown driver") if driver_raw is not None else None
        value = cls(
            agent_printer_id=str(raw.get("agent_printer_id") or ""),
            local_printer_fingerprint=str(raw.get("local_printer_fingerprint") or ""),
            display_name_sanitized=display,
            driver_name_sanitized=driver,
            dpi_x=int(raw.get("dpi_x") or 0),
            dpi_y=int(raw.get("dpi_y") or 0),
            media_width_mm=_finite_number(raw.get("media_width_mm", 0), "media_width_mm"),
            media_height_mm=_finite_number(raw.get("media_height_mm", 0), "media_height_mm"),
            orientation=str(raw.get("orientation") or ""),
            physical_width_px=int(raw.get("physical_width_px") or 0),
            physical_height_px=int(raw.get("physical_height_px") or 0),
            printable_width_px=int(raw.get("printable_width_px") or 0),
            printable_height_px=int(raw.get("printable_height_px") or 0),
            offset_x_px=int(raw.get("offset_x_px") or 0),
            offset_y_px=int(raw.get("offset_y_px") or 0),
            capability_hash=str(raw.get("capability_hash") or ""),
            observed_at=str(raw.get("observed_at") or ""),
            availability_state=str(raw.get("availability_state") or ""),
            safe_error_code=(str(raw["safe_error_code"])[:80] if raw.get("safe_error_code") else None),
        )
        value.validate()
        return value

    def validate(self) -> None:
        if not _ID.fullmatch(self.agent_printer_id):
            raise PrinterProfileContractError("invalid opaque agent_printer_id")
        if not _SHA.fullmatch(self.local_printer_fingerprint):
            raise PrinterProfileContractError("invalid local printer fingerprint")
        if self.availability_state not in OBSERVATION_STATES:
            raise PrinterProfileContractError("invalid printer availability state")
        if self.orientation not in ORIENTATIONS:
            raise PrinterProfileContractError("invalid printer orientation")
        for name, value in (
            ("dpi_x", self.dpi_x), ("dpi_y", self.dpi_y),
            ("physical_width_px", self.physical_width_px),
            ("physical_height_px", self.physical_height_px),
            ("printable_width_px", self.printable_width_px),
            ("printable_height_px", self.printable_height_px),
        ):
            if type(value) is not int or value < 0:
                raise PrinterProfileContractError(f"{name} is invalid")
        if self.offset_x_px < 0 or self.offset_y_px < 0:
            raise PrinterProfileContractError("printer physical offsets must be non-negative")
        if self.availability_state == "AVAILABLE":
            if self.dpi_x <= 0 or self.dpi_y <= 0:
                raise PrinterProfileContractError("available printer must report positive DPI")
            if self.media_width_mm <= 0 or self.media_height_mm <= 0:
                raise PrinterProfileContractError("available printer must report media dimensions")
            if self.printable_width_px <= 0 or self.printable_height_px <= 0:
                raise PrinterProfileContractError("available printer must report printable area")
            if self.offset_x_px + self.printable_width_px > self.physical_width_px:
                raise PrinterProfileContractError("printable width exceeds physical media")
            if self.offset_y_px + self.printable_height_px > self.physical_height_px:
                raise PrinterProfileContractError("printable height exceeds physical media")
        try:
            parsed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PrinterProfileContractError("invalid observed_at") from exc
        if parsed.tzinfo is None:
            raise PrinterProfileContractError("observed_at must be timezone-aware")
        if capability_hash(asdict(self)) != self.capability_hash:
            raise PrinterProfileContractError("capability hash mismatch")

    def safe_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PrinterDiscoveryJob:
    contract_version: str
    operation: str
    discovery_request_id: str
    agent_printer_id: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PrinterDiscoveryJob":
        allowed = {"contract_version", "operation", "discovery_request_id", "agent_printer_id"}
        unknown = set(raw) - allowed
        if unknown:
            raise PrinterProfileSecurityError(f"unsupported discovery job fields: {sorted(unknown)}")
        value = cls(
            contract_version=str(raw.get("contract_version") or ""),
            operation=str(raw.get("operation") or ""),
            discovery_request_id=str(raw.get("discovery_request_id") or ""),
            agent_printer_id=str(raw["agent_printer_id"]) if raw.get("agent_printer_id") is not None else None,
        )
        value.validate()
        return value

    def validate(self) -> None:
        if self.contract_version != PRINT_PROTOCOL_VERSION:
            raise PrinterProfileContractError("unsupported printer discovery contract version")
        if self.operation not in DISCOVERY_OPERATIONS:
            raise PrinterProfileContractError("unknown printer discovery operation")
        if not _ID.fullmatch(self.discovery_request_id):
            raise PrinterProfileContractError("invalid discovery request id")
        if self.operation == "LIST" and self.agent_printer_id is not None:
            raise PrinterProfileSecurityError("LIST does not accept a printer target")
        if self.operation == "CAPABILITIES" and (
            self.agent_printer_id is None or not _ID.fullmatch(self.agent_printer_id)
        ):
            raise PrinterProfileContractError("CAPABILITIES requires opaque agent_printer_id only")

    def safe_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "operation": self.operation,
            "discovery_request_id": self.discovery_request_id,
            "agent_printer_id": self.agent_printer_id,
        }


@dataclass(frozen=True, slots=True)
class LocalPrinterDescriptor:
    queue_name: str
    server_name: str | None = None


@dataclass(frozen=True, slots=True)
class LocalPrinterCapabilities:
    queue_name: str
    server_name: str | None
    port_name: str | None
    driver_name: str | None
    dpi_x: int
    dpi_y: int
    media_width_mm: float
    media_height_mm: float
    orientation: str
    physical_width_px: int
    physical_height_px: int
    printable_width_px: int
    printable_height_px: int
    offset_x_px: int
    offset_y_px: int


class PrinterDiscoveryBackend(Protocol):
    def enumerate_printers(self) -> Sequence[LocalPrinterDescriptor]: ...
    def inspect_printer(self, descriptor: LocalPrinterDescriptor) -> LocalPrinterCapabilities: ...


def _local_identity_id(queue_name: str, server_name: str | None) -> str:
    raw = json.dumps(
        {"queue_name": queue_name, "server_name": server_name or ""},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return "prn_" + hashlib.sha256(b"sellari-agent-printer-id-v1\0" + raw).hexdigest()[:40]


def observation_from_local(value: LocalPrinterCapabilities) -> PrinterObservation:
    display = sanitize_display_name(value.queue_name)
    driver = sanitize_display_name(value.driver_name, fallback="Unknown driver") if value.driver_name else None
    typed = {
        "driver_name_sanitized": driver,
        "dpi_x": int(value.dpi_x),
        "dpi_y": int(value.dpi_y),
        "media_width_mm": round(float(value.media_width_mm), 4),
        "media_height_mm": round(float(value.media_height_mm), 4),
        "orientation": value.orientation,
        "physical_width_px": int(value.physical_width_px),
        "physical_height_px": int(value.physical_height_px),
        "printable_width_px": int(value.printable_width_px),
        "printable_height_px": int(value.printable_height_px),
        "offset_x_px": int(value.offset_x_px),
        "offset_y_px": int(value.offset_y_px),
        "availability_state": "AVAILABLE",
    }
    exact_local = json.dumps(
        {
            "queue_name": value.queue_name,
            "server_name": value.server_name or "",
            "port_name": value.port_name or "",
            "driver_name": value.driver_name or "",
            **typed,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    local_fp = hashlib.sha256(b"sellari-local-printer-v1\0" + exact_local).hexdigest()
    base = {
        "agent_printer_id": _local_identity_id(value.queue_name, value.server_name),
        "local_printer_fingerprint": local_fp,
        "display_name_sanitized": display,
        **typed,
        "observed_at": utcnow().isoformat().replace("+00:00", "Z"),
        "safe_error_code": None,
    }
    base["capability_hash"] = capability_hash(base)
    return PrinterObservation.from_mapping(base)


class BoundedPrinterDiscovery:
    """Runs potentially blocking Win32 calls outside the Agent polling thread."""

    def __init__(
        self,
        backend: PrinterDiscoveryBackend,
        *,
        max_printers: int = MAX_PRINTERS_DEFAULT,
        enumerate_timeout_seconds: float = 5.0,
        per_printer_timeout_seconds: float = 3.0,
    ) -> None:
        if not 1 <= max_printers <= MAX_PRINTERS_HARD:
            raise ValueError("max_printers out of range")
        if not 0.01 <= enumerate_timeout_seconds <= 30:
            raise ValueError("enumerate timeout out of range")
        if not 0.01 <= per_printer_timeout_seconds <= 30:
            raise ValueError("printer timeout out of range")
        self.backend = backend
        self.max_printers = max_printers
        self.enumerate_timeout_seconds = enumerate_timeout_seconds
        self.per_printer_timeout_seconds = per_printer_timeout_seconds

    def discover(self) -> list[PrinterObservation]:
        enum_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sellari-printer-enum")
        future = enum_pool.submit(self.backend.enumerate_printers)
        try:
            descriptors = list(future.result(timeout=self.enumerate_timeout_seconds))
        finally:
            enum_pool.shutdown(wait=False, cancel_futures=True)
        descriptors = descriptors[: self.max_printers]
        if not descriptors:
            return []

        pool = ThreadPoolExecutor(
            max_workers=min(8, len(descriptors)),
            thread_name_prefix="sellari-printer-cap",
        )
        futures = {pool.submit(self.backend.inspect_printer, item): item for item in descriptors}
        done, pending = wait(futures, timeout=self.per_printer_timeout_seconds)
        result: list[PrinterObservation] = []
        for completed in done:
            descriptor = futures[completed]
            try:
                result.append(observation_from_local(completed.result()))
            except Exception:
                # One bad queue cannot poison the full discovery result.
                safe_name = sanitize_display_name(descriptor.queue_name)
                base = {
                    "agent_printer_id": _local_identity_id(descriptor.queue_name, descriptor.server_name),
                    "local_printer_fingerprint": hashlib.sha256(
                        ("unavailable\0" + descriptor.queue_name).encode("utf-8")
                    ).hexdigest(),
                    "display_name_sanitized": safe_name,
                    "driver_name_sanitized": None,
                    "dpi_x": 0,
                    "dpi_y": 0,
                    "media_width_mm": 0.0,
                    "media_height_mm": 0.0,
                    "orientation": "PORTRAIT",
                    "physical_width_px": 0,
                    "physical_height_px": 0,
                    "printable_width_px": 0,
                    "printable_height_px": 0,
                    "offset_x_px": 0,
                    "offset_y_px": 0,
                    "availability_state": "ERROR",
                    "observed_at": utcnow().isoformat().replace("+00:00", "Z"),
                    "safe_error_code": "PRINTER_CAPABILITY_QUERY_FAILED",
                }
                base["capability_hash"] = capability_hash(base)
                result.append(PrinterObservation.from_mapping(base))
        for incomplete in pending:
            descriptor = futures[incomplete]
            incomplete.cancel()
            safe_name = sanitize_display_name(descriptor.queue_name)
            base = {
                "agent_printer_id": _local_identity_id(descriptor.queue_name, descriptor.server_name),
                "local_printer_fingerprint": hashlib.sha256(
                    ("timeout\0" + descriptor.queue_name).encode("utf-8")
                ).hexdigest(),
                "display_name_sanitized": safe_name,
                "driver_name_sanitized": None,
                "dpi_x": 0,
                "dpi_y": 0,
                "media_width_mm": 0.0,
                "media_height_mm": 0.0,
                "orientation": "PORTRAIT",
                "physical_width_px": 0,
                "physical_height_px": 0,
                "printable_width_px": 0,
                "printable_height_px": 0,
                "offset_x_px": 0,
                "offset_y_px": 0,
                "availability_state": "UNAVAILABLE",
                "observed_at": utcnow().isoformat().replace("+00:00", "Z"),
                "safe_error_code": "PRINTER_CAPABILITY_QUERY_TIMEOUT",
            }
            base["capability_hash"] = capability_hash(base)
            result.append(PrinterObservation.from_mapping(base))
        pool.shutdown(wait=False, cancel_futures=True)
        return sorted(result, key=lambda item: (item.display_name_sanitized.casefold(), item.agent_printer_id))


class PrinterDiscoveryAgent:
    """Executes only typed, read-only discovery operations."""

    def __init__(self, discovery: BoundedPrinterDiscovery) -> None:
        self.discovery = discovery

    @staticmethod
    def capabilities() -> dict[str, Any]:
        return {
            "print_protocol_version": PRINT_PROTOCOL_VERSION,
            "capabilities": [DISCOVERY_CAPABILITY],
            "physical_printing": PHYSICAL_EXECUTION_BLOCKED,
        }

    def execute(self, raw_job: Mapping[str, Any]) -> dict[str, Any]:
        job = PrinterDiscoveryJob.from_mapping(raw_job)
        observations = self.discovery.discover()
        if job.operation == "CAPABILITIES":
            observations = [
                item for item in observations
                if item.agent_printer_id == job.agent_printer_id
            ]
        return {
            "contract_version": PRINT_PROTOCOL_VERSION,
            "discovery_request_id": job.discovery_request_id,
            "status": "COMPLETED",
            "observations": [item.safe_dict() for item in observations],
        }


class WindowsPrinterBackend:
    """Read-only Win32 printer discovery. No StartDoc/WritePrinter/spool submission."""

    PRINTER_ENUM_LOCAL = 0x00000002
    PRINTER_ENUM_CONNECTIONS = 0x00000004
    LOGPIXELSX = 88
    LOGPIXELSY = 90
    HORZRES = 8
    VERTRES = 10
    PHYSICALWIDTH = 110
    PHYSICALHEIGHT = 111
    PHYSICALOFFSETX = 112
    PHYSICALOFFSETY = 113
    HORZSIZE = 4
    VERTSIZE = 6

    class PRINTER_INFO_4W(ctypes.Structure):
        _fields_ = [
            ("pPrinterName", wintypes.LPWSTR),
            ("pServerName", wintypes.LPWSTR),
            ("Attributes", wintypes.DWORD),
        ]

    class PRINTER_INFO_2W(ctypes.Structure):
        _fields_ = [
            ("pServerName", wintypes.LPWSTR), ("pPrinterName", wintypes.LPWSTR),
            ("pShareName", wintypes.LPWSTR), ("pPortName", wintypes.LPWSTR),
            ("pDriverName", wintypes.LPWSTR), ("pComment", wintypes.LPWSTR),
            ("pLocation", wintypes.LPWSTR), ("pDevMode", ctypes.c_void_p),
            ("pSepFile", wintypes.LPWSTR), ("pPrintProcessor", wintypes.LPWSTR),
            ("pDatatype", wintypes.LPWSTR), ("pParameters", wintypes.LPWSTR),
            ("pSecurityDescriptor", ctypes.c_void_p), ("Attributes", wintypes.DWORD),
            ("Priority", wintypes.DWORD), ("DefaultPriority", wintypes.DWORD),
            ("StartTime", wintypes.DWORD), ("UntilTime", wintypes.DWORD),
            ("Status", wintypes.DWORD), ("cJobs", wintypes.DWORD),
            ("AveragePPM", wintypes.DWORD),
        ]

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows printer discovery is unavailable on this platform")
        self.winspool = ctypes.WinDLL("winspool.drv", use_last_error=True)
        self.gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        self.winspool.EnumPrintersW.argtypes = [
            wintypes.DWORD, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        self.winspool.EnumPrintersW.restype = wintypes.BOOL
        self.winspool.OpenPrinterW.argtypes = [
            wintypes.LPWSTR, ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
        ]
        self.winspool.OpenPrinterW.restype = wintypes.BOOL
        self.winspool.GetPrinterW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.winspool.GetPrinterW.restype = wintypes.BOOL
        self.winspool.ClosePrinter.argtypes = [wintypes.HANDLE]
        self.winspool.ClosePrinter.restype = wintypes.BOOL
        self.gdi32.CreateDCW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
        ]
        self.gdi32.CreateDCW.restype = ctypes.c_void_p
        self.gdi32.GetDeviceCaps.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.gdi32.GetDeviceCaps.restype = ctypes.c_int
        self.gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
        self.gdi32.DeleteDC.restype = wintypes.BOOL

    def enumerate_printers(self) -> Sequence[LocalPrinterDescriptor]:
        needed = wintypes.DWORD()
        returned = wintypes.DWORD()
        flags = self.PRINTER_ENUM_LOCAL | self.PRINTER_ENUM_CONNECTIONS
        self.winspool.EnumPrintersW(flags, None, 4, None, 0, ctypes.byref(needed), ctypes.byref(returned))
        if needed.value == 0:
            return []
        buffer = (ctypes.c_ubyte * needed.value)()
        ok = self.winspool.EnumPrintersW(
            flags, None, 4, ctypes.byref(buffer), needed.value,
            ctypes.byref(needed), ctypes.byref(returned),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        array_type = self.PRINTER_INFO_4W * returned.value
        rows = ctypes.cast(ctypes.byref(buffer), ctypes.POINTER(array_type)).contents
        result = []
        for row in rows:
            if row.pPrinterName:
                result.append(LocalPrinterDescriptor(str(row.pPrinterName), str(row.pServerName) if row.pServerName else None))
        return result

    def inspect_printer(self, descriptor: LocalPrinterDescriptor) -> LocalPrinterCapabilities:
        handle = wintypes.HANDLE()
        if not self.winspool.OpenPrinterW(descriptor.queue_name, ctypes.byref(handle), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            needed = wintypes.DWORD()
            self.winspool.GetPrinterW(handle, 2, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = (ctypes.c_ubyte * needed.value)()
            if not self.winspool.GetPrinterW(handle, 2, ctypes.byref(buffer), needed.value, ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            info = ctypes.cast(ctypes.byref(buffer), ctypes.POINTER(self.PRINTER_INFO_2W)).contents
            driver = str(info.pDriverName) if info.pDriverName else None
            port = str(info.pPortName) if info.pPortName else None

            dc = self.gdi32.CreateDCW("WINSPOOL", descriptor.queue_name, None, info.pDevMode)
            if not dc:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                cap = lambda index: int(self.gdi32.GetDeviceCaps(dc, index))
                dpi_x, dpi_y = cap(self.LOGPIXELSX), cap(self.LOGPIXELSY)
                physical_width, physical_height = cap(self.PHYSICALWIDTH), cap(self.PHYSICALHEIGHT)
                printable_width, printable_height = cap(self.HORZRES), cap(self.VERTRES)
                offset_x, offset_y = cap(self.PHYSICALOFFSETX), cap(self.PHYSICALOFFSETY)
                media_width_mm = (
                    physical_width * 25.4 / dpi_x if dpi_x > 0
                    else float(cap(self.HORZSIZE))
                )
                media_height_mm = (
                    physical_height * 25.4 / dpi_y if dpi_y > 0
                    else float(cap(self.VERTSIZE))
                )
                orientation = "LANDSCAPE" if media_width_mm > media_height_mm else "PORTRAIT"
            finally:
                self.gdi32.DeleteDC(dc)
        finally:
            self.winspool.ClosePrinter(handle)
        return LocalPrinterCapabilities(
            queue_name=descriptor.queue_name,
            server_name=descriptor.server_name,
            port_name=port,
            driver_name=driver,
            dpi_x=dpi_x,
            dpi_y=dpi_y,
            media_width_mm=media_width_mm,
            media_height_mm=media_height_mm,
            orientation=orientation,
            physical_width_px=physical_width,
            physical_height_px=physical_height,
            printable_width_px=printable_width,
            printable_height_px=printable_height,
            offset_x_px=offset_x,
            offset_y_px=offset_y,
        )


def evaluate_template_compatibility(
    *,
    profile_state: str,
    dpi_x: int,
    dpi_y: int,
    media_width_mm: float,
    media_height_mm: float,
    physical_width_px: int,
    physical_height_px: int,
    printable_width_px: int,
    printable_height_px: int,
    offset_x_px: int,
    offset_y_px: int,
    template_layout: Mapping[str, Any],
    label_width_mm: float,
    label_height_mm: float,
) -> dict[str, Any]:
    if profile_state == "STALE":
        return {"result": "PRINTER_PROFILE_STALE"}
    if profile_state == "MISSING":
        return {"result": "PRINTER_PROFILE_MISSING"}
    if profile_state == "DISABLED":
        return {"result": "PRINTER_PROFILE_DISABLED"}
    if profile_state == "INCOMPATIBLE":
        return {"result": "PRINTER_PROFILE_INCOMPATIBLE"}
    if profile_state != "ACTIVE":
        return {"result": "PRINTER_PROFILE_NOT_ACTIVE"}
    if dpi_x != dpi_y or not MIN_DPI <= dpi_x <= MAX_DPI:
        return {"result": "PRINTER_DPI_UNSUPPORTED", "safe_reason_code": "INCOMPATIBLE_DPI_FOR_PRINTING_V1"}
    dpi = dpi_x
    if abs(float(media_width_mm) - float(label_width_mm)) > MEDIA_TOLERANCE_MM or abs(
        float(media_height_mm) - float(label_height_mm)
    ) > MEDIA_TOLERANCE_MM:
        return {"result": "PRINTER_MEDIA_TEMPLATE_MISMATCH"}

    normalized = validate_layout(
        template_layout,
        label_width_mm=float(label_width_mm),
        label_height_mm=float(label_height_mm),
    )
    label_width_px = round(float(label_width_mm) * dpi / 25.4)
    label_height_px = round(float(label_height_mm) * dpi / 25.4)
    if label_width_px > physical_width_px or label_height_px > physical_height_px:
        return {"result": "PRINTER_MEDIA_TEMPLATE_MISMATCH"}

    right = offset_x_px + printable_width_px
    bottom = offset_y_px + printable_height_px
    for item in normalized["elements"]:
        left_px = round(item["x"] * dpi / 25.4)
        top_px = round(item["y"] * dpi / 25.4)
        item_right = round((item["x"] + item["width"]) * dpi / 25.4)
        item_bottom = round((item["y"] + item["height"]) * dpi / 25.4)
        if left_px < offset_x_px or top_px < offset_y_px or item_right > right or item_bottom > bottom:
            return {"result": "PRINT_LAYOUT_OUTSIDE_PRINTABLE_AREA"}

    dm = next(item for item in normalized["elements"] if item["type"] == "DATA_MATRIX_KM")
    module_pixels = round(dm["module_size_mm"] * dpi / 25.4)
    if module_pixels < 1:
        return {"result": "DATAMATRIX_MODULE_SIZE_UNSUPPORTED"}
    effective_module_mm = module_pixels * 25.4 / dpi
    if not MIN_MODULE_SIZE_MM <= effective_module_mm <= MAX_MODULE_SIZE_MM:
        return {
            "result": "DATAMATRIX_MODULE_SIZE_UNSUPPORTED",
            "module_pixels": module_pixels,
            "effective_module_mm": effective_module_mm,
        }
    try:
        rendered = render_gs1_datamatrix(
            SYNTHETIC_PREVIEW_FULL_KM,
            module_size_mm=dm["module_size_mm"],
            quiet_zone_modules=dm["quiet_zone_modules"],
            dpi=dpi,
        )
    except PrintingRuntimeUnavailable:
        return {
            "result": "PRINT_RENDERER_RUNTIME_UNAVAILABLE",
            "safe_reason_code": "LIBDMTX_RUNTIME_UNAVAILABLE",
        }
    except PrintingContractError:
        return {"result": "DATAMATRIX_MODULE_SIZE_UNSUPPORTED"}
    dm_width_px = round(dm["width"] * dpi / 25.4)
    dm_height_px = round(dm["height"] * dpi / 25.4)
    if rendered.image.width > dm_width_px or rendered.image.height > dm_height_px:
        return {"result": "DATAMATRIX_MODULE_SIZE_UNSUPPORTED"}
    return {
        "result": COMPATIBLE,
        "dpi": dpi,
        "label_width_px": label_width_px,
        "label_height_px": label_height_px,
        "module_pixels": module_pixels,
        "effective_module_mm": effective_module_mm,
        "synthetic_fixture_version": SYNTHETIC_FIXTURE_VERSION,
    }


@dataclass(frozen=True, slots=True)
class SyntheticTestPrintContract:
    contract_version: str
    operation: str
    printer_profile_id: str
    synthetic_fixture_version: str

    def validate(self) -> None:
        if self.contract_version != PRINT_PROTOCOL_VERSION:
            raise PrinterProfileContractError("unsupported synthetic test contract version")
        if self.operation != "TEST_PRINT_SYNTHETIC":
            raise PrinterProfileContractError("unknown synthetic test operation")
        if not _ID.fullmatch(self.printer_profile_id):
            raise PrinterProfileContractError("invalid printer profile id")
        if self.synthetic_fixture_version != SYNTHETIC_FIXTURE_VERSION:
            raise PrinterProfileSecurityError("arbitrary synthetic payload is forbidden")

    def blocked_result(self) -> dict[str, Any]:
        self.validate()
        return {
            "operation": self.operation,
            "printer_profile_id": self.printer_profile_id,
            "synthetic_fixture_version": self.synthetic_fixture_version,
            "state": PHYSICAL_EXECUTION_BLOCKED,
            "physical_printer_called": False,
        }
