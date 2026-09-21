from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import json
from importlib.metadata import PackageNotFoundError, version as package_version
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable, Mapping, Protocol

from wbcz.printing import (
    PRINTING_CONTRACT_VERSION,
    PRINT_LAYOUT_SCHEMA_VERSION,
    RENDERER_VERSION,
    PhysicalLabelRaster,
    PrintingContractError,
    PrintingSecurityError,
    libdmtx_version,
    render_decode_verify_physical_label,
)
from wbcz.printer_profiles import (
    LocalPrinterCapabilities,
    LocalPrinterDescriptor,
    PrinterDiscoveryBackend,
    PrinterProfileContractError,
    _local_identity_id,
    observation_from_local,
)


PHYSICAL_CAPABILITY = "PRINTING_PHYSICAL_V1"
PHYSICAL_OPERATION = "PRINT_RENDER_AND_SPOOL"
STATUS_OPERATION = "PRINT_STATUS"
SYNTHETIC_OPERATION = "TEST_PRINT_SYNTHETIC"
SYNTHETIC_FIXTURE_VERSION = "SELLARI_SYNTHETIC_LABEL_V1"
PRINT_PROTOCOL_VERSION = "printing-agent-v2"

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
SAFE_WINDOWS_STATUS = frozenset({
    "QUEUED", "PRINTING", "PAUSED", "ERROR", "OFFLINE", "PAPER_OUT",
    "USER_INTERVENTION", "DELETING", "DELETED", "SPOOLER_REPORTED_COMPLETE", "UNKNOWN",
})


class PhysicalPrintError(RuntimeError):
    pass


class PhysicalPrintSecurityError(PhysicalPrintError):
    pass


class PhysicalReplayBlocked(PhysicalPrintError):
    pass


class DefinitePreSpoolFailure(PhysicalPrintError):
    def __init__(self, code: str) -> None:
        self.code = code[:96]
        super().__init__(self.code)


class AmbiguousAfterSpool(PhysicalPrintError):
    def __init__(self, code: str, *, windows_spool_job_id: int | None = None) -> None:
        self.code = code[:96]
        self.windows_spool_job_id = windows_spool_job_id
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class PhysicalExecutionControl:
    contract_version: str
    operation: str
    execution_id: str
    print_job_item_id: str
    delivery_reservation_id: str
    payload_sha256: str
    layout_sha256: str
    template_version_id: str
    printer_profile_id: str
    printer_profile_fingerprint: str
    agent_printer_id: str
    organisation_id: str
    participant_id: str
    agent_binding_id: str
    printing_contract_version: str
    layout_schema_version: str
    renderer_version: str
    copies: int = 1

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PhysicalExecutionControl":
        allowed = {
            "contract_version", "operation", "execution_id", "print_job_item_id",
            "delivery_reservation_id", "payload_sha256", "layout_sha256",
            "template_version_id", "printer_profile_id", "printer_profile_fingerprint",
            "agent_printer_id", "organisation_id", "participant_id", "agent_binding_id",
            "printing_contract_version", "layout_schema_version", "renderer_version", "copies",
        }
        unknown = set(raw) - allowed
        forbidden = {
            "full_km", "payload", "queue", "queue_name", "path", "url", "devmode",
            "zpl", "epl", "cpcl", "command", "writeprinter", "raw",
        }
        if unknown:
            raise PhysicalPrintSecurityError(f"unsupported physical print fields: {sorted(unknown)}")
        if {str(key).casefold() for key in raw} & forbidden:
            raise PhysicalPrintSecurityError("raw printer/payload field is forbidden")
        value = cls(
            contract_version=str(raw.get("contract_version") or ""),
            operation=str(raw.get("operation") or ""),
            execution_id=str(raw.get("execution_id") or ""),
            print_job_item_id=str(raw.get("print_job_item_id") or ""),
            delivery_reservation_id=str(raw.get("delivery_reservation_id") or ""),
            payload_sha256=str(raw.get("payload_sha256") or ""),
            layout_sha256=str(raw.get("layout_sha256") or ""),
            template_version_id=str(raw.get("template_version_id") or ""),
            printer_profile_id=str(raw.get("printer_profile_id") or ""),
            printer_profile_fingerprint=str(raw.get("printer_profile_fingerprint") or ""),
            agent_printer_id=str(raw.get("agent_printer_id") or ""),
            organisation_id=str(raw.get("organisation_id") or ""),
            participant_id=str(raw.get("participant_id") or ""),
            agent_binding_id=str(raw.get("agent_binding_id") or ""),
            printing_contract_version=str(raw.get("printing_contract_version") or ""),
            layout_schema_version=str(raw.get("layout_schema_version") or ""),
            renderer_version=str(raw.get("renderer_version") or ""),
            copies=int(raw.get("copies", 1)),
        )
        value.validate()
        return value

    def validate(self) -> None:
        if self.contract_version != PRINT_PROTOCOL_VERSION or self.operation != PHYSICAL_OPERATION:
            raise PhysicalPrintError("unsupported physical print operation")
        for value in (
            self.execution_id, self.print_job_item_id, self.delivery_reservation_id,
            self.template_version_id, self.printer_profile_id, self.agent_printer_id,
            self.organisation_id, self.participant_id, self.agent_binding_id,
        ):
            if not _ID.fullmatch(value):
                raise PhysicalPrintError("invalid physical print identifier")
        if not _SHA.fullmatch(self.payload_sha256) or not _SHA.fullmatch(self.layout_sha256):
            raise PhysicalPrintError("invalid physical print hash")
        if not _SHA.fullmatch(self.printer_profile_fingerprint):
            raise PhysicalPrintError("invalid printer profile fingerprint")
        if self.printing_contract_version != PRINTING_CONTRACT_VERSION:
            raise PhysicalPrintError("incompatible printing contract version")
        if self.layout_schema_version != PRINT_LAYOUT_SCHEMA_VERSION:
            raise PhysicalPrintError("incompatible layout schema version")
        if self.renderer_version != RENDERER_VERSION:
            raise PhysicalPrintError("incompatible renderer version")
        if self.copies != 1:
            raise PhysicalPrintSecurityError("physical printing copies must equal 1")


@dataclass(frozen=True, slots=True)
class PhysicalRenderContract:
    execution_id: str
    layout: Mapping[str, Any]
    label_width_mm: float
    label_height_mm: float
    dpi_x: int
    dpi_y: int
    media_width_mm: float
    media_height_mm: float
    physical_width_px: int
    physical_height_px: int
    printable_width_px: int
    printable_height_px: int
    offset_x_px: int
    offset_y_px: int
    printer_profile_state: str
    printer_profile_fingerprint: str
    agent_printer_id: str
    field_values: Mapping[str, str]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PhysicalRenderContract":
        allowed = {
            "execution_id", "layout", "label_width_mm", "label_height_mm", "dpi_x", "dpi_y",
            "media_width_mm", "media_height_mm", "physical_width_px", "physical_height_px",
            "printable_width_px", "printable_height_px", "offset_x_px", "offset_y_px",
            "printer_profile_state", "printer_profile_fingerprint", "agent_printer_id",
            "field_values",
        }
        if set(raw) - allowed:
            raise PhysicalPrintSecurityError("physical render contract has unsupported fields")
        layout = raw.get("layout")
        field_values = raw.get("field_values", {})
        if not isinstance(layout, Mapping) or not isinstance(field_values, Mapping):
            raise PhysicalPrintError("invalid physical render contract")
        return cls(
            execution_id=str(raw.get("execution_id") or ""),
            layout=layout,
            label_width_mm=float(raw.get("label_width_mm") or 0),
            label_height_mm=float(raw.get("label_height_mm") or 0),
            dpi_x=int(raw.get("dpi_x") or 0),
            dpi_y=int(raw.get("dpi_y") or 0),
            media_width_mm=float(raw.get("media_width_mm") or 0),
            media_height_mm=float(raw.get("media_height_mm") or 0),
            physical_width_px=int(raw.get("physical_width_px") or 0),
            physical_height_px=int(raw.get("physical_height_px") or 0),
            printable_width_px=int(raw.get("printable_width_px") or 0),
            printable_height_px=int(raw.get("printable_height_px") or 0),
            offset_x_px=int(raw.get("offset_x_px") or 0),
            offset_y_px=int(raw.get("offset_y_px") or 0),
            printer_profile_state=str(raw.get("printer_profile_state") or ""),
            printer_profile_fingerprint=str(raw.get("printer_profile_fingerprint") or ""),
            agent_printer_id=str(raw.get("agent_printer_id") or ""),
            field_values={str(k): str(v) for k, v in field_values.items()},
        )


@dataclass(frozen=True, slots=True)
class LocalResolvedPrinter:
    descriptor: LocalPrinterDescriptor
    capabilities: LocalPrinterCapabilities
    fingerprint: str


class LocalPrinterResolver:
    def __init__(self, backend: PrinterDiscoveryBackend) -> None:
        self.backend = backend

    def resolve(self, *, agent_printer_id: str, expected_fingerprint: str) -> LocalResolvedPrinter:
        candidates = [
            descriptor
            for descriptor in self.backend.enumerate_printers()
            if _local_identity_id(descriptor.queue_name, descriptor.server_name) == agent_printer_id
        ]
        if len(candidates) != 1:
            raise DefinitePreSpoolFailure("PRINTER_LOCAL_ID_NOT_RESOLVED")
        descriptor = candidates[0]
        capabilities = self.backend.inspect_printer(descriptor)
        observation = observation_from_local(capabilities)
        if observation.local_printer_fingerprint != expected_fingerprint:
            raise DefinitePreSpoolFailure("PRINTER_PROFILE_FINGERPRINT_CHANGED")
        return LocalResolvedPrinter(descriptor, capabilities, observation.local_printer_fingerprint)


class AgentPhysicalReplayStore:
    """Durable local evidence. Never stores FULL KM, raster, queue path or DEVMODE."""

    _IRREVERSIBLE = {
        "SPOOL_SUBMITTING", "SPOOL_JOB_CREATED", "SPOOLER_ACCEPTED",
        "UNKNOWN_AFTER_SPOOL", "FAILED_PRE_SPOOL",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS print_physical_replay (
                  execution_id TEXT PRIMARY KEY,
                  print_job_item_id TEXT NOT NULL,
                  delivery_reservation_id TEXT NOT NULL,
                  payload_sha256 TEXT NOT NULL,
                  layout_sha256 TEXT NOT NULL,
                  printer_profile_id TEXT NOT NULL,
                  printer_profile_fingerprint TEXT NOT NULL,
                  state TEXT NOT NULL,
                  windows_spool_job_id INTEGER,
                  windows_status TEXT,
                  first_seen_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  safe_error_code TEXT
                )
                """
            )
            db.commit()
        self._fsync_db()

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _fsync_open_flags() -> int:
        # Windows CRT _commit(), used by os.fsync(), requires a descriptor
        # opened with write access. O_BINARY avoids text-mode translation on
        # Windows and is zero/absent on POSIX.
        return os.O_RDWR | getattr(os, "O_BINARY", 0)

    def _fsync_db(self) -> None:
        if not self.path.exists():
            return
        fd = os.open(self.path, self._fsync_open_flags())
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _identity(
        *,
        print_job_item_id: str,
        delivery_reservation_id: str,
        payload_sha256: str,
        layout_sha256: str,
        printer_profile_id: str,
        printer_profile_fingerprint: str,
    ) -> tuple[str, ...]:
        return (
            print_job_item_id, delivery_reservation_id, payload_sha256, layout_sha256,
            printer_profile_id, printer_profile_fingerprint,
        )

    def get(self, execution_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT print_job_item_id,delivery_reservation_id,payload_sha256,layout_sha256,
                       printer_profile_id,printer_profile_fingerprint,state,
                       windows_spool_job_id,windows_status,first_seen_at,updated_at,safe_error_code
                FROM print_physical_replay WHERE execution_id=?
                """,
                (execution_id,),
            ).fetchone()
        if row is None:
            return None
        keys = (
            "print_job_item_id","delivery_reservation_id","payload_sha256","layout_sha256",
            "printer_profile_id","printer_profile_fingerprint","state","windows_spool_job_id",
            "windows_status","first_seen_at","updated_at","safe_error_code",
        )
        return dict(zip(keys, row))

    def record(
        self,
        *,
        execution_id: str,
        print_job_item_id: str,
        delivery_reservation_id: str,
        payload_sha256: str,
        layout_sha256: str,
        printer_profile_id: str,
        printer_profile_fingerprint: str,
        state: str,
        windows_spool_job_id: int | None = None,
        windows_status: str | None = None,
        safe_error_code: str | None = None,
        durable: bool = False,
    ) -> None:
        allowed = {
            "RENDERED_VERIFIED", "SPOOL_SUBMITTING", "SPOOL_JOB_CREATED",
            "SPOOLER_ACCEPTED", "FAILED_PRE_SPOOL", "BLOCKED", "UNKNOWN_AFTER_SPOOL",
        }
        if state not in allowed:
            raise ValueError("invalid physical replay state")
        now = datetime.now(timezone.utc).isoformat()
        identity = self._identity(
            print_job_item_id=print_job_item_id,
            delivery_reservation_id=delivery_reservation_id,
            payload_sha256=payload_sha256,
            layout_sha256=layout_sha256,
            printer_profile_id=printer_profile_id,
            printer_profile_fingerprint=printer_profile_fingerprint,
        )
        with self._connect() as db:
            existing = db.execute(
                """
                SELECT print_job_item_id,delivery_reservation_id,payload_sha256,layout_sha256,
                       printer_profile_id,printer_profile_fingerprint,state
                FROM print_physical_replay WHERE execution_id=?
                """,
                (execution_id,),
            ).fetchone()
            if existing is not None:
                if tuple(existing[:6]) != identity:
                    raise PhysicalReplayBlocked("physical replay identity conflict")
                old_state = str(existing[6])
                if old_state in self._IRREVERSIBLE and state == "RENDERED_VERIFIED":
                    raise PhysicalReplayBlocked("physical execution already crossed spool boundary")
                if old_state == "SPOOLER_ACCEPTED" and state != "SPOOLER_ACCEPTED":
                    raise PhysicalReplayBlocked("accepted physical execution cannot regress")
                first_seen = db.execute(
                    "SELECT first_seen_at FROM print_physical_replay WHERE execution_id=?",
                    (execution_id,),
                ).fetchone()[0]
            else:
                first_seen = now
            db.execute(
                """
                INSERT INTO print_physical_replay (
                  execution_id,print_job_item_id,delivery_reservation_id,payload_sha256,layout_sha256,
                  printer_profile_id,printer_profile_fingerprint,state,windows_spool_job_id,
                  windows_status,first_seen_at,updated_at,safe_error_code
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(execution_id) DO UPDATE SET
                  state=excluded.state,
                  windows_spool_job_id=COALESCE(excluded.windows_spool_job_id,print_physical_replay.windows_spool_job_id),
                  windows_status=COALESCE(excluded.windows_status,print_physical_replay.windows_status),
                  updated_at=excluded.updated_at,
                  safe_error_code=excluded.safe_error_code
                """,
                (
                    execution_id, *identity, state, windows_spool_job_id, windows_status,
                    first_seen, now, safe_error_code,
                ),
            )
            db.commit()
        if durable:
            self._fsync_db()

    def cross_spool_boundary(self, control: PhysicalExecutionControl) -> None:
        existing = self.get(control.execution_id)
        if existing is None or existing["state"] != "RENDERED_VERIFIED":
            if existing and existing["state"] in self._IRREVERSIBLE:
                raise PhysicalReplayBlocked("physical execution already crossed spool boundary")
            raise PhysicalReplayBlocked("render verification must be durably recorded first")
        self.record(
            execution_id=control.execution_id,
            print_job_item_id=control.print_job_item_id,
            delivery_reservation_id=control.delivery_reservation_id,
            payload_sha256=control.payload_sha256,
            layout_sha256=control.layout_sha256,
            printer_profile_id=control.printer_profile_id,
            printer_profile_fingerprint=control.printer_profile_fingerprint,
            state="SPOOL_SUBMITTING",
            durable=True,
        )


@dataclass(frozen=True, slots=True)
class GdiSpoolOutcome:
    windows_spool_job_id: int
    windows_status: str = "QUEUED"


class RasterSpoolAdapter(Protocol):
    def submit(
        self,
        *,
        queue_name: str,
        raster: PhysicalLabelRaster,
        on_job_created: Callable[[int], None],
    ) -> GdiSpoolOutcome: ...


class _DOCINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_int),
        ("lpszDocName", wintypes.LPCWSTR),
        ("lpszOutput", wintypes.LPCWSTR),
        ("lpszDatatype", wintypes.LPCWSTR),
        ("fwType", wintypes.DWORD),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", _BITMAPINFOHEADER), ("bmiColors", wintypes.DWORD * 3)]


class _DEVMODE_PRINTER_PREFIX(ctypes.Structure):
    """Stable DEVMODEW prefix through dmPrintQuality.

    DocumentProperties owns the complete driver buffer, including dmDriverExtra.
    We only mutate standard printer fields in this fixed Win32 prefix.
    """
    _fields_ = [
        ("dmDeviceName", wintypes.WCHAR * 32),
        ("dmSpecVersion", wintypes.WORD),
        ("dmDriverVersion", wintypes.WORD),
        ("dmSize", wintypes.WORD),
        ("dmDriverExtra", wintypes.WORD),
        ("dmFields", wintypes.DWORD),
        ("dmOrientation", ctypes.c_short),
        ("dmPaperSize", ctypes.c_short),
        ("dmPaperLength", ctypes.c_short),
        ("dmPaperWidth", ctypes.c_short),
        ("dmScale", ctypes.c_short),
        ("dmCopies", ctypes.c_short),
        ("dmDefaultSource", ctypes.c_short),
        ("dmPrintQuality", ctypes.c_short),
        ("dmColor", ctypes.c_short),
        ("dmDuplex", ctypes.c_short),
        ("dmYResolution", ctypes.c_short),
        ("dmTTOption", ctypes.c_short),
        ("dmCollate", ctypes.c_short),
        ("dmFormName", wintypes.WCHAR * 32),
        ("dmLogPixels", wintypes.WORD),
        ("dmBitsPerPel", wintypes.DWORD),
        ("dmPelsWidth", wintypes.DWORD),
        ("dmPelsHeight", wintypes.DWORD),
        ("dmNup", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class ValidatedPrinterDevMode:
    buffer: Any
    size_bytes: int
    copies: int
    scale_percent: int | None


@dataclass(frozen=True, slots=True)
class PrinterDcGeometry:
    dpi_x: int
    dpi_y: int
    physical_width_px: int
    physical_height_px: int
    printable_width_px: int
    printable_height_px: int
    offset_x_px: int
    offset_y_px: int


class WindowsGdiRasterSpooler:
    """Closed raster-only GDI adapter. Never accepts PDL/raw command data."""

    DIB_RGB_COLORS = 0
    BI_RGB = 0

    DM_OUT_BUFFER = 0x00000002
    DM_IN_BUFFER = 0x00000008
    DM_SCALE = 0x00000010
    DM_NUP = 0x00000040
    DM_COPIES = 0x00000100
    DMNUP_ONEUP = 2
    IDOK = 1

    LOGPIXELSX = 88
    LOGPIXELSY = 90
    HORZRES = 8
    VERTRES = 10
    PHYSICALWIDTH = 110
    PHYSICALHEIGHT = 111
    PHYSICALOFFSETX = 112
    PHYSICALOFFSETY = 113

    def __init__(self, *, _winspool=None, _gdi32=None) -> None:
        injected = _winspool is not None or _gdi32 is not None
        if injected and (_winspool is None or _gdi32 is None):
            raise ValueError("both Win32 test boundaries must be supplied together")
        if not injected and os.name != "nt":
            raise OSError("Windows GDI printing is unavailable on this platform")
        self.winspool = _winspool or ctypes.WinDLL("winspool.drv", use_last_error=True)
        self.gdi32 = _gdi32 or ctypes.WinDLL("gdi32", use_last_error=True)
        if injected:
            return

        self.winspool.OpenPrinterW.argtypes = [
            wintypes.LPWSTR, ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
        ]
        self.winspool.OpenPrinterW.restype = wintypes.BOOL
        self.winspool.DocumentPropertiesW.argtypes = [
            ctypes.c_void_p, wintypes.HANDLE, wintypes.LPWSTR,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
        ]
        self.winspool.DocumentPropertiesW.restype = ctypes.c_long
        self.winspool.ClosePrinter.argtypes = [wintypes.HANDLE]
        self.winspool.ClosePrinter.restype = wintypes.BOOL
        self.gdi32.CreateDCW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
        ]
        self.gdi32.CreateDCW.restype = ctypes.c_void_p
        self.gdi32.GetDeviceCaps.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.gdi32.GetDeviceCaps.restype = ctypes.c_int
        self.gdi32.StartDocW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DOCINFOW)]
        self.gdi32.StartDocW.restype = ctypes.c_int
        self.gdi32.StartPage.argtypes = [ctypes.c_void_p]
        self.gdi32.StartPage.restype = ctypes.c_int
        self.gdi32.SetDIBitsToDevice.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int, ctypes.c_int, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, wintypes.UINT, wintypes.UINT,
            ctypes.c_void_p, ctypes.POINTER(_BITMAPINFO), wintypes.UINT,
        ]
        self.gdi32.SetDIBitsToDevice.restype = ctypes.c_int
        self.gdi32.EndPage.argtypes = [ctypes.c_void_p]
        self.gdi32.EndPage.restype = ctypes.c_int
        self.gdi32.EndDoc.argtypes = [ctypes.c_void_p]
        self.gdi32.EndDoc.restype = ctypes.c_int
        self.gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
        self.gdi32.DeleteDC.restype = wintypes.BOOL

    @staticmethod
    def _devmode_prefix(buffer: Any) -> _DEVMODE_PRINTER_PREFIX:
        return ctypes.cast(buffer, ctypes.POINTER(_DEVMODE_PRINTER_PREFIX)).contents

    def _load_validated_devmode(self, queue_name: str) -> ValidatedPrinterDevMode:
        handle = wintypes.HANDLE()
        if not self.winspool.OpenPrinterW(queue_name, ctypes.byref(handle), None):
            raise DefinitePreSpoolFailure("PRINTER_DEVMODE_OPEN_FAILED")
        try:
            size = int(self.winspool.DocumentPropertiesW(
                None, handle, queue_name, None, None, 0
            ))
            if size < ctypes.sizeof(_DEVMODE_PRINTER_PREFIX):
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_UNAVAILABLE")

            source = (ctypes.c_ubyte * size)()
            result = int(self.winspool.DocumentPropertiesW(
                None, handle, queue_name, ctypes.cast(source, ctypes.c_void_p),
                None, self.DM_OUT_BUFFER,
            ))
            if result != self.IDOK:
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_UNAVAILABLE")
            source_dm = self._devmode_prefix(source)
            if (
                int(source_dm.dmSize) < ctypes.sizeof(_DEVMODE_PRINTER_PREFIX)
                or int(source_dm.dmSize) + int(source_dm.dmDriverExtra) > size
            ):
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_INVALID")

            source_fields = int(source_dm.dmFields)
            source_dm.dmFields = source_fields | self.DM_COPIES
            source_dm.dmCopies = 1
            scale_supported = bool(source_fields & self.DM_SCALE)
            if scale_supported:
                source_dm.dmFields = int(source_dm.dmFields) | self.DM_SCALE
                source_dm.dmScale = 100
            nup_supported = bool(source_fields & self.DM_NUP)
            if nup_supported:
                source_dm.dmFields = int(source_dm.dmFields) | self.DM_NUP
                source_dm.dmNup = self.DMNUP_ONEUP

            canonical = (ctypes.c_ubyte * size)()
            result = int(self.winspool.DocumentPropertiesW(
                None, handle, queue_name, ctypes.cast(canonical, ctypes.c_void_p),
                ctypes.cast(source, ctypes.c_void_p),
                self.DM_IN_BUFFER | self.DM_OUT_BUFFER,
            ))
            if result != self.IDOK:
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_CANONICALIZATION_FAILED")
            effective = self._devmode_prefix(canonical)
            if (
                int(effective.dmSize) < ctypes.sizeof(_DEVMODE_PRINTER_PREFIX)
                or int(effective.dmSize) + int(effective.dmDriverExtra) > size
            ):
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_INVALID")

            effective_fields = int(effective.dmFields)
            if not (effective_fields & self.DM_COPIES) or int(effective.dmCopies) != 1:
                raise DefinitePreSpoolFailure("PRINTER_DEVMODE_COPIES_UNSAFE")
            scale_value: int | None = None
            if scale_supported or (effective_fields & self.DM_SCALE):
                if not (effective_fields & self.DM_SCALE) or int(effective.dmScale) != 100:
                    raise DefinitePreSpoolFailure("PRINTER_DEVMODE_SCALING_UNSAFE")
                scale_value = int(effective.dmScale)
            if nup_supported or (effective_fields & self.DM_NUP):
                if not (effective_fields & self.DM_NUP) or int(effective.dmNup) != self.DMNUP_ONEUP:
                    raise DefinitePreSpoolFailure("PRINTER_DEVMODE_SCALING_UNSAFE")

            return ValidatedPrinterDevMode(
                buffer=canonical,
                size_bytes=size,
                copies=int(effective.dmCopies),
                scale_percent=scale_value,
            )
        finally:
            self.winspool.ClosePrinter(handle)

    def _read_dc_geometry(self, hdc: Any) -> PrinterDcGeometry:
        cap = lambda index: int(self.gdi32.GetDeviceCaps(hdc, index))
        return PrinterDcGeometry(
            dpi_x=cap(self.LOGPIXELSX),
            dpi_y=cap(self.LOGPIXELSY),
            physical_width_px=cap(self.PHYSICALWIDTH),
            physical_height_px=cap(self.PHYSICALHEIGHT),
            printable_width_px=cap(self.HORZRES),
            printable_height_px=cap(self.VERTRES),
            offset_x_px=cap(self.PHYSICALOFFSETX),
            offset_y_px=cap(self.PHYSICALOFFSETY),
        )

    @staticmethod
    def _validate_final_dc_geometry(
        actual: PrinterDcGeometry,
        raster: PhysicalLabelRaster,
    ) -> None:
        if actual.dpi_x != raster.dpi or actual.dpi_y != raster.dpi:
            raise DefinitePreSpoolFailure("PRINTER_PROFILE_DPI_CHANGED")
        if (
            actual.physical_width_px != raster.image.width
            or actual.physical_height_px != raster.image.height
        ):
            raise DefinitePreSpoolFailure("PRINTER_PHYSICAL_GEOMETRY_CHANGED")
        if (
            actual.printable_width_px != raster.printable_width_px
            or actual.printable_height_px != raster.printable_height_px
        ):
            raise DefinitePreSpoolFailure("PRINTER_PRINTABLE_AREA_CHANGED")
        if (
            actual.offset_x_px != raster.physical_offset_x_px
            or actual.offset_y_px != raster.physical_offset_y_px
        ):
            raise DefinitePreSpoolFailure("PRINTER_PHYSICAL_OFFSET_CHANGED")

    def safe_preflight(self, queue_name: str) -> dict[str, Any]:
        """Local-only, no-StartDoc Windows smoke helper."""
        devmode = self._load_validated_devmode(queue_name)
        hdc = self.gdi32.CreateDCW(
            "WINSPOOL", queue_name, None, ctypes.cast(devmode.buffer, ctypes.c_void_p)
        )
        if not hdc:
            raise DefinitePreSpoolFailure("GDI_CREATE_DC_FAILED")
        try:
            geometry = self._read_dc_geometry(hdc)
            return {
                "copies": devmode.copies,
                "scale_percent": devmode.scale_percent,
                "dpi_x": geometry.dpi_x,
                "dpi_y": geometry.dpi_y,
                "physical_width_px": geometry.physical_width_px,
                "physical_height_px": geometry.physical_height_px,
                "printable_width_px": geometry.printable_width_px,
                "printable_height_px": geometry.printable_height_px,
                "offset_x_px": geometry.offset_x_px,
                "offset_y_px": geometry.offset_y_px,
            }
        finally:
            self.gdi32.DeleteDC(hdc)

    @staticmethod
    def _bgr_bottom_up(raster: PhysicalLabelRaster) -> tuple[bytes, int]:
        image = raster.image
        if image.bpp != 24 or len(image.pixels) != image.width * image.height * 3:
            raise DefinitePreSpoolFailure("FINAL_RASTER_INVALID")
        row_bytes = image.width * 3
        stride = (row_bytes + 3) & ~3
        padding = b"\x00" * (stride - row_bytes)
        rows = []
        for y in range(image.height - 1, -1, -1):
            row = image.pixels[y * row_bytes:(y + 1) * row_bytes]
            bgr = bytearray(row_bytes)
            for x in range(0, row_bytes, 3):
                bgr[x] = row[x + 2]
                bgr[x + 1] = row[x + 1]
                bgr[x + 2] = row[x]
            rows.append(bytes(bgr) + padding)
        return b"".join(rows), stride

    def submit(
        self,
        *,
        queue_name: str,
        raster: PhysicalLabelRaster,
        on_job_created: Callable[[int], None],
    ) -> GdiSpoolOutcome:
        if not isinstance(queue_name, str) or not queue_name:
            raise DefinitePreSpoolFailure("LOCAL_PRINTER_QUEUE_UNAVAILABLE")
        devmode = self._load_validated_devmode(queue_name)
        if devmode.copies != 1:
            raise DefinitePreSpoolFailure("PRINTER_DEVMODE_COPIES_UNSAFE")
        if devmode.scale_percent not in {None, 100}:
            raise DefinitePreSpoolFailure("PRINTER_DEVMODE_SCALING_UNSAFE")
        hdc = self.gdi32.CreateDCW(
            "WINSPOOL", queue_name, None, ctypes.cast(devmode.buffer, ctypes.c_void_p)
        )
        if not hdc:
            raise DefinitePreSpoolFailure("GDI_CREATE_DC_FAILED")
        job_id: int | None = None
        try:
            # Same validated DEVMODE/DC is used for geometry proof and StartDoc.
            # No printer configuration change is accepted after this point.
            self._validate_final_dc_geometry(self._read_dc_geometry(hdc), raster)
            doc = _DOCINFOW(
                ctypes.sizeof(_DOCINFOW),
                "Sellari label",
                None,
                None,
                0,
            )
            job_id = int(self.gdi32.StartDocW(hdc, ctypes.byref(doc)))
            if job_id <= 0:
                raise DefinitePreSpoolFailure("GDI_START_DOC_FAILED")
            on_job_created(job_id)
            if self.gdi32.StartPage(hdc) <= 0:
                raise AmbiguousAfterSpool("GDI_START_PAGE_FAILED", windows_spool_job_id=job_id)

            raw, stride = self._bgr_bottom_up(raster)
            header = _BITMAPINFOHEADER(
                ctypes.sizeof(_BITMAPINFOHEADER),
                raster.image.width,
                raster.image.height,
                1,
                24,
                self.BI_RGB,
                stride * raster.image.height,
                0, 0, 0, 0,
            )
            info = _BITMAPINFO()
            info.bmiHeader = header
            buffer = ctypes.create_string_buffer(raw)
            scanlines = self.gdi32.SetDIBitsToDevice(
                hdc,
                -raster.physical_offset_x_px, -raster.physical_offset_y_px,
                raster.image.width, raster.image.height,
                0, 0,
                0, raster.image.height,
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.byref(info),
                self.DIB_RGB_COLORS,
            )
            if scanlines != raster.image.height:
                raise AmbiguousAfterSpool("GDI_RASTER_OUTPUT_FAILED", windows_spool_job_id=job_id)
            if self.gdi32.EndPage(hdc) <= 0:
                raise AmbiguousAfterSpool("GDI_END_PAGE_FAILED", windows_spool_job_id=job_id)
            if self.gdi32.EndDoc(hdc) <= 0:
                raise AmbiguousAfterSpool("GDI_END_DOC_FAILED", windows_spool_job_id=job_id)
            return GdiSpoolOutcome(job_id, "QUEUED")
        except DefinitePreSpoolFailure:
            raise
        except AmbiguousAfterSpool:
            raise
        except Exception as exc:
            if job_id and job_id > 0:
                raise AmbiguousAfterSpool(
                    "GDI_EXCEPTION_AFTER_START_DOC",
                    windows_spool_job_id=job_id,
                ) from exc
            raise DefinitePreSpoolFailure("GDI_EXCEPTION_BEFORE_JOB") from exc
        finally:
            self.gdi32.DeleteDC(hdc)


class FakeGdiRasterSpooler:
    """Hardware-independent outcome matrix for tests."""

    def __init__(self, *, fail_at: str | None = None, job_id: int = 123) -> None:
        self.fail_at = fail_at
        self.job_id = job_id
        self.calls: list[str] = []

    def submit(
        self,
        *,
        queue_name: str,
        raster: PhysicalLabelRaster,
        on_job_created: Callable[[int], None],
    ) -> GdiSpoolOutcome:
        self.calls.append("CreateDC")
        if self.fail_at == "CreateDC":
            raise DefinitePreSpoolFailure("GDI_CREATE_DC_FAILED")
        self.calls.append("StartDoc")
        if self.fail_at == "StartDoc":
            raise DefinitePreSpoolFailure("GDI_START_DOC_FAILED")
        on_job_created(self.job_id)
        self.calls.append("StartPage")
        if self.fail_at == "StartPage":
            raise AmbiguousAfterSpool("GDI_START_PAGE_FAILED", windows_spool_job_id=self.job_id)
        self.calls.append("Raster")
        if self.fail_at == "Raster":
            raise AmbiguousAfterSpool("GDI_RASTER_OUTPUT_FAILED", windows_spool_job_id=self.job_id)
        self.calls.append("EndPage")
        if self.fail_at == "EndPage":
            raise AmbiguousAfterSpool("GDI_END_PAGE_FAILED", windows_spool_job_id=self.job_id)
        self.calls.append("EndDoc")
        if self.fail_at == "EndDoc":
            raise AmbiguousAfterSpool("GDI_END_DOC_FAILED", windows_spool_job_id=self.job_id)
        return GdiSpoolOutcome(self.job_id, "QUEUED")


def derive_gs1_display_values(full_km: bytes) -> dict[str, str]:
    """Derive only display values already present in the exact in-memory FULL KM."""
    values: dict[str, str] = {}
    if full_km.startswith(b"01") and len(full_km) >= 18:
        gtin = full_km[2:16]
        if len(gtin) == 14 and gtin.isdigit() and full_km[16:18] == b"21":
            serial_start = 18
            separators = [pos for pos in (
                full_km.find(b"\x1d", serial_start),
                full_km.find(b"91", serial_start),
            ) if pos >= serial_start]
            serial_end = min(separators) if separators else len(full_km)
            serial = full_km[serial_start:serial_end]
            try:
                values["GTIN"] = gtin.decode("ascii")
                values["HUMAN_READABLE_KI"] = full_km[:serial_end].decode("ascii")
            except UnicodeDecodeError:
                pass
    return values


class PhysicalPrintRuntime:
    def __init__(
        self,
        *,
        resolver: LocalPrinterResolver,
        spooler: RasterSpoolAdapter,
        replay: AgentPhysicalReplayStore,
        mark_rendered: Callable[[dict[str, Any]], Mapping[str, Any]],
        begin_spool: Callable[[dict[str, Any]], Mapping[str, Any]],
        report_result: Callable[[dict[str, Any]], Mapping[str, Any]],
    ) -> None:
        self.resolver = resolver
        self.spooler = spooler
        self.replay = replay
        self.mark_rendered = mark_rendered
        self.begin_spool = begin_spool
        self.report_result = report_result

    @staticmethod
    def capability_report() -> dict[str, Any]:
        try:
            __import__("zxingcpp")
            decoder_version = package_version("zxing-cpp")
        except (ImportError, PackageNotFoundError):
            decoder_version = "unavailable"
        return {
            "print_protocol_version": PRINT_PROTOCOL_VERSION,
            "capabilities": [PHYSICAL_CAPABILITY],
            "printing_contract_version": PRINTING_CONTRACT_VERSION,
            "layout_schema_version": PRINT_LAYOUT_SCHEMA_VERSION,
            "renderer_version": RENDERER_VERSION,
            "libdmtx_version": libdmtx_version(),
            "decoder_version": decoder_version,
            "copies": 1,
        }

    def execute(
        self,
        control_raw: Mapping[str, Any],
        render_contract_raw: Mapping[str, Any],
        *,
        full_km: bytes,
    ) -> dict[str, Any]:
        control = PhysicalExecutionControl.from_mapping(control_raw)
        try:
            return self._execute_inner(
                control_raw,
                render_contract_raw,
                full_km=full_km,
            )
        except PhysicalReplayBlocked:
            raise
        except (
            DefinitePreSpoolFailure,
            PhysicalPrintSecurityError,
            PhysicalPrintError,
            PrintingContractError,
            PrintingSecurityError,
            PrinterProfileContractError,
        ) as exc:
            existing = self.replay.get(control.execution_id)
            if existing is not None and existing["state"] in AgentPhysicalReplayStore._IRREVERSIBLE:
                raise
            if isinstance(exc, DefinitePreSpoolFailure):
                state = "FAILED_PRE_SPOOL"
                code = exc.code
            elif isinstance(exc, (PhysicalPrintSecurityError, PrintingSecurityError)):
                state = "BLOCKED"
                code = "PHYSICAL_SECURITY_VALIDATION_FAILED"
            elif isinstance(exc, PrintingContractError):
                state = "BLOCKED"
                code = "PHYSICAL_RENDER_VALIDATION_FAILED"
            else:
                state = "BLOCKED"
                code = "PHYSICAL_PRE_SPOOL_VALIDATION_FAILED"
            self.replay.record(
                execution_id=control.execution_id,
                print_job_item_id=control.print_job_item_id,
                delivery_reservation_id=control.delivery_reservation_id,
                payload_sha256=control.payload_sha256,
                layout_sha256=control.layout_sha256,
                printer_profile_id=control.printer_profile_id,
                printer_profile_fingerprint=control.printer_profile_fingerprint,
                state=state,
                safe_error_code=code,
                durable=True,
            )
            self.report_result({
                "execution_id": control.execution_id,
                "state": state,
                "safe_error_code": code,
            })
            return {"state": state, "safe_error_code": code}

    def _execute_inner(
        self,
        control_raw: Mapping[str, Any],
        render_contract_raw: Mapping[str, Any],
        *,
        full_km: bytes,
    ) -> dict[str, Any]:
        control = PhysicalExecutionControl.from_mapping(control_raw)
        render_contract = PhysicalRenderContract.from_mapping(render_contract_raw)
        if render_contract.execution_id != control.execution_id:
            raise PhysicalPrintSecurityError("render contract execution mismatch")
        if hashlib.sha256(full_km).hexdigest() != control.payload_sha256:
            raise PhysicalPrintSecurityError("physical payload SHA-256 mismatch")
        if render_contract.printer_profile_state != "ACTIVE":
            raise PhysicalPrintError("printer profile is not ACTIVE")
        if render_contract.printer_profile_fingerprint != control.printer_profile_fingerprint:
            raise PhysicalPrintSecurityError("printer profile fingerprint mismatch")
        if render_contract.agent_printer_id != control.agent_printer_id:
            raise PhysicalPrintSecurityError("agent printer ID mismatch")
        if render_contract.dpi_x != render_contract.dpi_y:
            raise PhysicalPrintError("PRINTER_DPI_UNSUPPORTED")

        resolved = self.resolver.resolve(
            agent_printer_id=control.agent_printer_id,
            expected_fingerprint=control.printer_profile_fingerprint,
        )
        if resolved.capabilities.dpi_x != render_contract.dpi_x or resolved.capabilities.dpi_y != render_contract.dpi_y:
            raise PhysicalPrintError("PRINTER_PROFILE_DPI_CHANGED")

        raster, decoder_version = render_decode_verify_physical_label(
            full_km,
            layout=render_contract.layout,
            label_width_mm=render_contract.label_width_mm,
            label_height_mm=render_contract.label_height_mm,
            dpi=render_contract.dpi_x,
            field_values={**derive_gs1_display_values(full_km), **dict(render_contract.field_values)},
        )
        if raster.layout_sha256 != control.layout_sha256:
            raise PhysicalPrintSecurityError("physical layout SHA-256 mismatch")
        if (
            raster.image.width != render_contract.physical_width_px
            or raster.image.height != render_contract.physical_height_px
        ):
            raise PrintingContractError("final raster does not exactly match approved physical media pixels")
        raster = replace(
            raster,
            physical_offset_x_px=render_contract.offset_x_px,
            physical_offset_y_px=render_contract.offset_y_px,
            printable_width_px=render_contract.printable_width_px,
            printable_height_px=render_contract.printable_height_px,
        )

        self.replay.record(
            execution_id=control.execution_id,
            print_job_item_id=control.print_job_item_id,
            delivery_reservation_id=control.delivery_reservation_id,
            payload_sha256=control.payload_sha256,
            layout_sha256=control.layout_sha256,
            printer_profile_id=control.printer_profile_id,
            printer_profile_fingerprint=control.printer_profile_fingerprint,
            state="RENDERED_VERIFIED",
            durable=True,
        )
        self.mark_rendered({
            "execution_id": control.execution_id,
            "payload_sha256": control.payload_sha256,
            "layout_sha256": control.layout_sha256,
            "printer_profile_id": control.printer_profile_id,
            "printer_profile_fingerprint": control.printer_profile_fingerprint,
            "renderer_version": RENDERER_VERSION,
            "decoder_version": decoder_version,
        })

        # Irreversible duplicate-prevention boundary: local fsync first, then
        # backend durable acknowledgement, then and only then any GDI side effect.
        self.replay.cross_spool_boundary(control)
        self.begin_spool({
            "execution_id": control.execution_id,
            "payload_sha256": control.payload_sha256,
            "layout_sha256": control.layout_sha256,
            "printer_profile_id": control.printer_profile_id,
            "printer_profile_fingerprint": control.printer_profile_fingerprint,
        })

        try:
            # Re-resolve immediately before the first Windows side effect. This
            # closes the render-to-StartDoc race if queue/driver/port/capability
            # evidence changed after the earlier compatibility check.
            resolved = self.resolver.resolve(
                agent_printer_id=control.agent_printer_id,
                expected_fingerprint=control.printer_profile_fingerprint,
            )
            if (
                resolved.capabilities.dpi_x != render_contract.dpi_x
                or resolved.capabilities.dpi_y != render_contract.dpi_y
            ):
                raise DefinitePreSpoolFailure("PRINTER_PROFILE_DPI_CHANGED")

            def on_job_created(job_id: int) -> None:
                self.replay.record(
                    execution_id=control.execution_id,
                    print_job_item_id=control.print_job_item_id,
                    delivery_reservation_id=control.delivery_reservation_id,
                    payload_sha256=control.payload_sha256,
                    layout_sha256=control.layout_sha256,
                    printer_profile_id=control.printer_profile_id,
                    printer_profile_fingerprint=control.printer_profile_fingerprint,
                    state="SPOOL_JOB_CREATED",
                    windows_spool_job_id=job_id,
                    windows_status="QUEUED",
                    durable=True,
                )
                self.report_result({
                    "execution_id": control.execution_id,
                    "state": "SPOOL_JOB_CREATED",
                    "windows_spool_job_id": job_id,
                    "last_windows_status": "QUEUED",
                })

            outcome = self.spooler.submit(
                queue_name=resolved.descriptor.queue_name,
                raster=raster,
                on_job_created=on_job_created,
            )
        except DefinitePreSpoolFailure as exc:
            self.replay.record(
                execution_id=control.execution_id,
                print_job_item_id=control.print_job_item_id,
                delivery_reservation_id=control.delivery_reservation_id,
                payload_sha256=control.payload_sha256,
                layout_sha256=control.layout_sha256,
                printer_profile_id=control.printer_profile_id,
                printer_profile_fingerprint=control.printer_profile_fingerprint,
                state="FAILED_PRE_SPOOL",
                safe_error_code=exc.code,
                durable=True,
            )
            self.report_result({
                "execution_id": control.execution_id,
                "state": "FAILED_PRE_SPOOL",
                "safe_error_code": exc.code,
            })
            return {"state": "FAILED_PRE_SPOOL", "safe_error_code": exc.code}
        except AmbiguousAfterSpool as exc:
            if exc.windows_spool_job_id is not None:
                self.replay.record(
                    execution_id=control.execution_id,
                    print_job_item_id=control.print_job_item_id,
                    delivery_reservation_id=control.delivery_reservation_id,
                    payload_sha256=control.payload_sha256,
                    layout_sha256=control.layout_sha256,
                    printer_profile_id=control.printer_profile_id,
                    printer_profile_fingerprint=control.printer_profile_fingerprint,
                    state="SPOOL_JOB_CREATED",
                    windows_spool_job_id=exc.windows_spool_job_id,
                    windows_status="UNKNOWN",
                    durable=True,
                )
            self.replay.record(
                execution_id=control.execution_id,
                print_job_item_id=control.print_job_item_id,
                delivery_reservation_id=control.delivery_reservation_id,
                payload_sha256=control.payload_sha256,
                layout_sha256=control.layout_sha256,
                printer_profile_id=control.printer_profile_id,
                printer_profile_fingerprint=control.printer_profile_fingerprint,
                state="UNKNOWN_AFTER_SPOOL",
                windows_spool_job_id=exc.windows_spool_job_id,
                windows_status="UNKNOWN",
                safe_error_code=exc.code,
                durable=True,
            )
            self.report_result({
                "execution_id": control.execution_id,
                "state": "UNKNOWN_AFTER_SPOOL",
                "windows_spool_job_id": exc.windows_spool_job_id,
                "last_windows_status": "UNKNOWN",
                "safe_error_code": exc.code,
            })
            return {
                "state": "UNKNOWN_AFTER_SPOOL",
                "windows_spool_job_id": exc.windows_spool_job_id,
                "safe_error_code": exc.code,
            }

        self.replay.record(
            execution_id=control.execution_id,
            print_job_item_id=control.print_job_item_id,
            delivery_reservation_id=control.delivery_reservation_id,
            payload_sha256=control.payload_sha256,
            layout_sha256=control.layout_sha256,
            printer_profile_id=control.printer_profile_id,
            printer_profile_fingerprint=control.printer_profile_fingerprint,
            state="SPOOL_JOB_CREATED",
            windows_spool_job_id=outcome.windows_spool_job_id,
            windows_status=outcome.windows_status,
            durable=True,
        )
        self.replay.record(
            execution_id=control.execution_id,
            print_job_item_id=control.print_job_item_id,
            delivery_reservation_id=control.delivery_reservation_id,
            payload_sha256=control.payload_sha256,
            layout_sha256=control.layout_sha256,
            printer_profile_id=control.printer_profile_id,
            printer_profile_fingerprint=control.printer_profile_fingerprint,
            state="SPOOLER_ACCEPTED",
            windows_spool_job_id=outcome.windows_spool_job_id,
            windows_status=outcome.windows_status,
            durable=True,
        )
        self.report_result({
            "execution_id": control.execution_id,
            "state": "SPOOLER_ACCEPTED",
            "windows_spool_job_id": outcome.windows_spool_job_id,
            "last_windows_status": outcome.windows_status,
        })
        return {
            "state": "SPOOLER_ACCEPTED",
            "windows_spool_job_id": outcome.windows_spool_job_id,
            "display_status": "Отправлено на принтер",
        }


@dataclass(frozen=True, slots=True)
class PrintStatusRequest:
    contract_version: str
    operation: str
    execution_id: str
    printer_profile_id: str
    printer_profile_fingerprint: str
    agent_printer_id: str
    windows_spool_job_id: int

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PrintStatusRequest":
        allowed = {
            "contract_version", "operation", "execution_id", "printer_profile_id",
            "printer_profile_fingerprint", "agent_printer_id", "windows_spool_job_id",
        }
        if set(raw) != allowed:
            raise PhysicalPrintSecurityError("print status contract fields mismatch")
        value = cls(
            contract_version=str(raw["contract_version"]),
            operation=str(raw["operation"]),
            execution_id=str(raw["execution_id"]),
            printer_profile_id=str(raw["printer_profile_id"]),
            printer_profile_fingerprint=str(raw["printer_profile_fingerprint"]),
            agent_printer_id=str(raw["agent_printer_id"]),
            windows_spool_job_id=int(raw["windows_spool_job_id"]),
        )
        value.validate()
        return value

    def validate(self) -> None:
        if self.contract_version != PRINT_PROTOCOL_VERSION or self.operation != STATUS_OPERATION:
            raise PhysicalPrintError("unsupported print status operation")
        for value in (self.execution_id, self.printer_profile_id, self.agent_printer_id):
            if not _ID.fullmatch(value):
                raise PhysicalPrintError("invalid print status identifier")
        if not _SHA.fullmatch(self.printer_profile_fingerprint):
            raise PhysicalPrintError("invalid print status printer fingerprint")
        if type(self.windows_spool_job_id) is not int or self.windows_spool_job_id <= 0:
            raise PhysicalPrintError("invalid Windows spool job id")


class PhysicalPrintStatusRuntime:
    def __init__(
        self,
        *,
        resolver: LocalPrinterResolver,
        status_adapter: "WindowsSpoolStatusAdapter",
    ) -> None:
        self.resolver = resolver
        self.status_adapter = status_adapter

    def query(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        request = PrintStatusRequest.from_mapping(raw)
        resolved = self.resolver.resolve(
            agent_printer_id=request.agent_printer_id,
            expected_fingerprint=request.printer_profile_fingerprint,
        )
        result = self.status_adapter.query(
            queue_name=resolved.descriptor.queue_name,
            windows_spool_job_id=request.windows_spool_job_id,
        )
        return {
            "execution_id": request.execution_id,
            "printer_profile_id": request.printer_profile_id,
            "windows_spool_job_id": request.windows_spool_job_id,
            "normalized_state": result["normalized_state"],
            "observed_at": result["observed_at"],
            "safe_error_code": result.get("safe_error_code"),
            "physical_output_proven": False,
        }



class _SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD), ("wMonth", wintypes.WORD), ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD), ("wHour", wintypes.WORD), ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD), ("wMilliseconds", wintypes.WORD),
    ]


class _JOB_INFO_1W(ctypes.Structure):
    _fields_ = [
        ("JobId", wintypes.DWORD),
        ("pPrinterName", wintypes.LPWSTR),
        ("pMachineName", wintypes.LPWSTR),
        ("pUserName", wintypes.LPWSTR),
        ("pDocument", wintypes.LPWSTR),
        ("pDatatype", wintypes.LPWSTR),
        ("pStatus", wintypes.LPWSTR),
        ("Status", wintypes.DWORD),
        ("Priority", wintypes.DWORD),
        ("Position", wintypes.DWORD),
        ("TotalPages", wintypes.DWORD),
        ("PagesPrinted", wintypes.DWORD),
        ("Submitted", _SYSTEMTIME),
    ]


class WindowsSpoolStatusAdapter:
    """Read-only safe status normalizer for one already-known local queue/job id."""

    JOB_STATUS_PAUSED = 0x00000001
    JOB_STATUS_ERROR = 0x00000002
    JOB_STATUS_DELETING = 0x00000004
    JOB_STATUS_SPOOLING = 0x00000008
    JOB_STATUS_PRINTING = 0x00000010
    JOB_STATUS_OFFLINE = 0x00000020
    JOB_STATUS_PAPEROUT = 0x00000040
    JOB_STATUS_PRINTED = 0x00000080
    JOB_STATUS_DELETED = 0x00000100
    JOB_STATUS_USER_INTERVENTION = 0x00000400
    JOB_STATUS_COMPLETE = 0x00001000

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows spool status is unavailable on this platform")
        self.winspool = ctypes.WinDLL("winspool.drv", use_last_error=True)
        self.winspool.OpenPrinterW.argtypes = [
            wintypes.LPWSTR, ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p,
        ]
        self.winspool.OpenPrinterW.restype = wintypes.BOOL
        self.winspool.GetJobW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        self.winspool.GetJobW.restype = wintypes.BOOL
        self.winspool.ClosePrinter.argtypes = [wintypes.HANDLE]
        self.winspool.ClosePrinter.restype = wintypes.BOOL

    @classmethod
    def normalize(cls, flags: int) -> str:
        if flags & cls.JOB_STATUS_OFFLINE:
            return "OFFLINE"
        if flags & cls.JOB_STATUS_PAPEROUT:
            return "PAPER_OUT"
        if flags & cls.JOB_STATUS_USER_INTERVENTION:
            return "USER_INTERVENTION"
        if flags & cls.JOB_STATUS_ERROR:
            return "ERROR"
        if flags & cls.JOB_STATUS_PAUSED:
            return "PAUSED"
        if flags & cls.JOB_STATUS_DELETING:
            return "DELETING"
        if flags & cls.JOB_STATUS_DELETED:
            return "DELETED"
        if flags & cls.JOB_STATUS_PRINTING:
            return "PRINTING"
        if flags & (cls.JOB_STATUS_PRINTED | cls.JOB_STATUS_COMPLETE):
            # Windows reporting this state is not proof that a physical,
            # readable label emerged from the device.
            return "SPOOLER_REPORTED_COMPLETE"
        return "QUEUED"

    def query(self, *, queue_name: str, windows_spool_job_id: int) -> dict[str, Any]:
        if not queue_name or windows_spool_job_id <= 0:
            raise ValueError("invalid local spool status target")
        handle = wintypes.HANDLE()
        if not self.winspool.OpenPrinterW(queue_name, ctypes.byref(handle), None):
            return {
                "normalized_state": "UNKNOWN",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "safe_error_code": "WINDOWS_OPEN_PRINTER_STATUS_FAILED",
            }
        try:
            needed = wintypes.DWORD()
            self.winspool.GetJobW(handle, windows_spool_job_id, 1, None, 0, ctypes.byref(needed))
            if needed.value == 0:
                return {
                    "normalized_state": "UNKNOWN",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "safe_error_code": "WINDOWS_SPOOL_JOB_NOT_OBSERVED",
                }
            buffer = (ctypes.c_ubyte * needed.value)()
            ok = self.winspool.GetJobW(
                handle, windows_spool_job_id, 1, ctypes.byref(buffer), needed.value, ctypes.byref(needed)
            )
            if not ok:
                return {
                    "normalized_state": "UNKNOWN",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "safe_error_code": "WINDOWS_GET_JOB_FAILED",
                }
            info = ctypes.cast(ctypes.byref(buffer), ctypes.POINTER(_JOB_INFO_1W)).contents
            return {
                "normalized_state": self.normalize(int(info.Status)),
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "safe_error_code": None,
            }
        finally:
            self.winspool.ClosePrinter(handle)


class SyntheticPhysicalTestRuntime:
    """Physical test uses only the built-in synthetic fixture, never M8/FULL KM input."""

    def __init__(
        self,
        *,
        resolver: LocalPrinterResolver,
        spooler: RasterSpoolAdapter,
    ) -> None:
        self.resolver = resolver
        self.spooler = spooler

    def execute(
        self,
        *,
        synthetic_fixture_version: str,
        agent_printer_id: str,
        printer_profile_fingerprint: str,
        layout: Mapping[str, Any],
        label_width_mm: float,
        label_height_mm: float,
        dpi: int,
    ) -> dict[str, Any]:
        if synthetic_fixture_version != SYNTHETIC_FIXTURE_VERSION:
            raise PhysicalPrintSecurityError("arbitrary synthetic payload is forbidden")
        from wbcz.printing import SYNTHETIC_PREVIEW_FULL_KM
        resolved = self.resolver.resolve(
            agent_printer_id=agent_printer_id,
            expected_fingerprint=printer_profile_fingerprint,
        )
        raster, _ = render_decode_verify_physical_label(
            SYNTHETIC_PREVIEW_FULL_KM,
            layout=layout,
            label_width_mm=label_width_mm,
            label_height_mm=label_height_mm,
            dpi=dpi,
            field_values=derive_gs1_display_values(SYNTHETIC_PREVIEW_FULL_KM),
        )
        created: list[int] = []
        try:
            outcome = self.spooler.submit(
                queue_name=resolved.descriptor.queue_name,
                raster=raster,
                on_job_created=lambda job_id: created.append(job_id),
            )
        except DefinitePreSpoolFailure as exc:
            return {"state": "FAILED_PRE_SPOOL", "safe_error_code": exc.code}
        except AmbiguousAfterSpool as exc:
            return {
                "state": "UNKNOWN_AFTER_SPOOL",
                "windows_spool_job_id": exc.windows_spool_job_id,
                "safe_error_code": exc.code,
            }
        return {
            "state": "SPOOLER_ACCEPTED",
            "windows_spool_job_id": outcome.windows_spool_job_id,
            "display_status": "Отправлено на принтер",
            "physical_output_proven": False,
            "synthetic_fixture_version": SYNTHETIC_FIXTURE_VERSION,
        }
