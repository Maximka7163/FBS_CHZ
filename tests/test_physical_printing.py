from __future__ import annotations

from dataclasses import replace
import ctypes
import hashlib
import json
import os
import sqlite3

import pytest

from wbcz.physical_printing import (
    AgentPhysicalReplayStore,
    AmbiguousAfterSpool,
    DefinitePreSpoolFailure,
    FakeGdiRasterSpooler,
    LocalPrinterResolver,
    PhysicalExecutionControl,
    PhysicalPrintError,
    PhysicalPrintRuntime,
    PhysicalPrintStatusRuntime,
    PhysicalReplayBlocked,
    SyntheticPhysicalTestRuntime,
    WindowsGdiRasterSpooler,
    WindowsSpoolStatusAdapter,
    _DEVMODE_PRINTER_PREFIX,
)
from wbcz.printing import (
    PRINTING_CONTRACT_VERSION,
    PRINT_LAYOUT_SCHEMA_VERSION,
    RENDERER_VERSION,
    SYNTHETIC_PREVIEW_FULL_KM,
    PrintingSecurityError,
    render_decode_verify_physical_label,
)
from wbcz.printer_profiles import (
    LocalPrinterCapabilities,
    LocalPrinterDescriptor,
    WindowsPrinterBackend,
    observation_from_local,
)


def layout(module_size_mm=0.34):
    return {
        "schema_version": "printing-layout-v1",
        "elements": [{
            "type": "DATA_MATRIX_KM",
            "x": 2.0,
            "y": 2.0,
            "width": 30.0,
            "height": 30.0,
            "rotation": 0,
            "module_size_mm": module_size_mm,
            "quiet_zone_modules": 1,
            "payload_source": "SYSTEM_FULL_KM",
        }],
    }


class FakeDiscovery:
    def __init__(self, caps):
        self.caps = caps

    def enumerate_printers(self):
        return [LocalPrinterDescriptor(self.caps.queue_name, self.caps.server_name)]

    def inspect_printer(self, descriptor):
        return replace(
            self.caps,
            queue_name=descriptor.queue_name,
            server_name=descriptor.server_name,
        )


def caps(dpi=300):
    width = round(50.0 * dpi / 25.4)
    height = round(35.0 * dpi / 25.4)
    return LocalPrinterCapabilities(
        queue_name="Synthetic Local Queue",
        server_name=None,
        port_name="LOCALPORT",
        driver_name="Synthetic Driver",
        dpi_x=dpi,
        dpi_y=dpi,
        media_width_mm=50.0,
        media_height_mm=35.0,
        orientation="LANDSCAPE",
        physical_width_px=width,
        physical_height_px=height,
        printable_width_px=width,
        printable_height_px=height,
        offset_x_px=0,
        offset_y_px=0,
    )


def contracts(full_km=SYNTHETIC_PREVIEW_FULL_KM, dpi=300):
    local = caps(dpi)
    observation = observation_from_local(local)
    _, layout_hash = __import__("wbcz.printing", fromlist=["canonical_layout_sha256"]).canonical_layout_sha256(
        layout(), label_width_mm=50, label_height_mm=35
    )
    control = {
        "contract_version": "printing-agent-v2",
        "operation": "PRINT_RENDER_AND_SPOOL",
        "execution_id": "exec-1",
        "print_job_item_id": "item-1",
        "delivery_reservation_id": "reservation-1",
        "payload_sha256": hashlib.sha256(full_km).hexdigest(),
        "layout_sha256": layout_hash,
        "template_version_id": "template-v1",
        "printer_profile_id": "profile-1",
        "printer_profile_fingerprint": observation.local_printer_fingerprint,
        "agent_printer_id": observation.agent_printer_id,
        "organisation_id": "org-1",
        "participant_id": "participant-1",
        "agent_binding_id": "binding-1",
        "printing_contract_version": PRINTING_CONTRACT_VERSION,
        "layout_schema_version": PRINT_LAYOUT_SCHEMA_VERSION,
        "renderer_version": RENDERER_VERSION,
        "copies": 1,
    }
    render_contract = {
        "execution_id": "exec-1",
        "layout": layout(),
        "label_width_mm": 50,
        "label_height_mm": 35,
        "dpi_x": dpi,
        "dpi_y": dpi,
        "media_width_mm": 50,
        "media_height_mm": 35,
        "physical_width_px": local.physical_width_px,
        "physical_height_px": local.physical_height_px,
        "printable_width_px": local.printable_width_px,
        "printable_height_px": local.printable_height_px,
        "offset_x_px": 0,
        "offset_y_px": 0,
        "printer_profile_state": "ACTIVE",
        "printer_profile_fingerprint": observation.local_printer_fingerprint,
        "agent_printer_id": observation.agent_printer_id,
        "field_values": {},
    }
    return local, control, render_contract


def runtime(tmp_path, *, spooler=None, callbacks=None):
    local, control, render_contract = contracts()
    replay = AgentPhysicalReplayStore(tmp_path / "physical.sqlite")
    events = callbacks if callbacks is not None else []
    physical = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=spooler or FakeGdiRasterSpooler(job_id=417),
        replay=replay,
        mark_rendered=lambda payload: events.append(("rendered", payload)) or {"state": "RENDERED_VERIFIED"},
        begin_spool=lambda payload: events.append(("boundary", payload)) or {"state": "SPOOL_SUBMITTING"},
        report_result=lambda payload: events.append(("result", payload)) or payload,
    )
    return physical, replay, events, control, render_contract


def test_exact_final_raster_independently_decodes_ascii29_bytes():
    full_km = b"010460000000001221SERIAL-C\x1d91ABCD\x1d92SIGNATURE"
    raster, decoder = render_decode_verify_physical_label(
        full_km,
        layout=layout(),
        label_width_mm=50,
        label_height_mm=35,
        dpi=300,
    )
    assert raster.payload_sha256 == hashlib.sha256(full_km).hexdigest()
    assert raster.layout_sha256
    assert raster.module_pixels >= 1
    assert decoder


def test_physical_control_is_closed_versions_exact_and_copies_one():
    _, control, _ = contracts()
    parsed = PhysicalExecutionControl.from_mapping(control)
    assert parsed.copies == 1
    for forbidden in ("queue_name", "path", "url", "zpl", "epl", "cpcl", "full_km"):
        with pytest.raises(Exception):
            PhysicalExecutionControl.from_mapping({**control, forbidden: "x"})
    with pytest.raises(PhysicalPrintError):
        PhysicalExecutionControl.from_mapping({**control, "renderer_version": "different"})
    with pytest.raises(Exception):
        PhysicalExecutionControl.from_mapping({**control, "copies": 2})


@pytest.mark.parametrize(
    "fail_at,expected",
    [
        ("StartDoc", "FAILED_PRE_SPOOL"),
        ("StartPage", "UNKNOWN_AFTER_SPOOL"),
        ("Raster", "UNKNOWN_AFTER_SPOOL"),
        ("EndPage", "UNKNOWN_AFTER_SPOOL"),
        ("EndDoc", "UNKNOWN_AFTER_SPOOL"),
        (None, "SPOOLER_ACCEPTED"),
    ],
)
def test_fake_gdi_outcome_matrix_never_blind_retries(tmp_path, fail_at, expected):
    physical, replay, events, control, render_contract = runtime(
        tmp_path, spooler=FakeGdiRasterSpooler(fail_at=fail_at, job_id=712)
    )
    result = physical.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    assert result["state"] == expected
    stored = replay.get("exec-1")
    assert stored["state"] == expected
    assert events[0][0] == "rendered"
    assert events[1][0] == "boundary"
    if fail_at != "StartDoc":
        assert stored["windows_spool_job_id"] == 712
    # Every post-boundary outcome, including a provable StartDoc failure,
    # is terminal for automatic retry of this execution identity.
    with pytest.raises(PhysicalReplayBlocked):
        physical.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)


def test_local_replay_is_durable_before_startdoc_and_contains_no_sensitive_payload(tmp_path):
    local, control, render_contract = contracts()
    replay = AgentPhysicalReplayStore(tmp_path / "physical.sqlite")
    order = []

    class AssertingSpooler:
        def submit(self, *, queue_name, raster, on_job_created):
            order.append("StartDoc")
            assert replay.get("exec-1")["state"] == "SPOOL_SUBMITTING"
            assert "backend-boundary-ack" in order
            on_job_created(991)
            return __import__("wbcz.physical_printing", fromlist=["GdiSpoolOutcome"]).GdiSpoolOutcome(991)

    physical = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=AssertingSpooler(),
        replay=replay,
        mark_rendered=lambda payload: order.append("backend-rendered-ack") or payload,
        begin_spool=lambda payload: order.append("backend-boundary-ack") or payload,
        report_result=lambda payload: order.append("backend-result") or payload,
    )
    result = physical.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    assert result["state"] == "SPOOLER_ACCEPTED"
    assert order.index("backend-boundary-ack") < order.index("StartDoc")

    raw = (tmp_path / "physical.sqlite").read_bytes()
    assert SYNTHETIC_PREVIEW_FULL_KM not in raw
    assert b"DataMatrix" not in raw


def test_crash_before_boundary_is_pre_spool_but_crash_after_local_boundary_blocks_retry(tmp_path):
    local, control, render_contract = contracts()

    # Failure before local SPOOL_SUBMITTING: no physical side effect occurred.
    replay_a = AgentPhysicalReplayStore(tmp_path / "before.sqlite")
    def fail_mark(_):
        raise RuntimeError("backend unavailable before boundary")
    before = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=FakeGdiRasterSpooler(),
        replay=replay_a,
        mark_rendered=fail_mark,
        begin_spool=lambda payload: payload,
        report_result=lambda payload: payload,
    )
    with pytest.raises(RuntimeError):
        before.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    assert replay_a.get("exec-1")["state"] == "RENDERED_VERIFIED"

    # Failure after durable local SPOOL_SUBMITTING but before backend ack:
    # conservative replay protection prevents an automatic second attempt.
    replay_b = AgentPhysicalReplayStore(tmp_path / "after.sqlite")
    after = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=FakeGdiRasterSpooler(),
        replay=replay_b,
        mark_rendered=lambda payload: payload,
        begin_spool=lambda payload: (_ for _ in ()).throw(RuntimeError("crash")),
        report_result=lambda payload: payload,
    )
    with pytest.raises(RuntimeError):
        after.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    assert replay_b.get("exec-1")["state"] == "SPOOL_SUBMITTING"
    with pytest.raises(PhysicalReplayBlocked):
        after.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)


def test_payload_hash_layout_hash_and_local_profile_fingerprint_fail_before_spool(tmp_path):
    local, control, render_contract = contracts()

    physical, replay, _, _, _ = runtime(tmp_path / "hash")
    result = physical.execute(
        {**control, "payload_sha256": "0" * 64},
        render_contract,
        full_km=SYNTHETIC_PREVIEW_FULL_KM,
    )
    assert result["state"] == "BLOCKED"
    assert replay.get("exec-1")["state"] == "BLOCKED"

    physical2, replay2, _, _, _ = runtime(tmp_path / "layout")
    result = physical2.execute(
        {**control, "layout_sha256": "0" * 64},
        render_contract,
        full_km=SYNTHETIC_PREVIEW_FULL_KM,
    )
    assert result["state"] == "BLOCKED"
    assert replay2.get("exec-1")["state"] == "BLOCKED"

    changed = replace(local, driver_name="Changed Driver")
    replay3 = AgentPhysicalReplayStore(tmp_path / "profile" / "physical.sqlite")
    bad = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(changed)),
        spooler=FakeGdiRasterSpooler(),
        replay=replay3,
        mark_rendered=lambda payload: payload,
        begin_spool=lambda payload: payload,
        report_result=lambda payload: payload,
    )
    result = bad.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    assert result["state"] == "FAILED_PRE_SPOOL"
    assert result["safe_error_code"] == "PRINTER_PROFILE_FINGERPRINT_CHANGED"
    assert replay3.get("exec-1")["state"] == "FAILED_PRE_SPOOL"


def test_windows_status_normalization_never_claims_physical_proof():
    assert WindowsSpoolStatusAdapter.normalize(WindowsSpoolStatusAdapter.JOB_STATUS_OFFLINE) == "OFFLINE"
    assert WindowsSpoolStatusAdapter.normalize(WindowsSpoolStatusAdapter.JOB_STATUS_PAPEROUT) == "PAPER_OUT"
    assert WindowsSpoolStatusAdapter.normalize(WindowsSpoolStatusAdapter.JOB_STATUS_PRINTED) == "SPOOLER_REPORTED_COMPLETE"
    assert WindowsSpoolStatusAdapter.normalize(WindowsSpoolStatusAdapter.JOB_STATUS_COMPLETE) == "SPOOLER_REPORTED_COMPLETE"


def test_synthetic_physical_test_uses_only_builtin_fixture(tmp_path):
    local, _, render_contract = contracts()
    obs = observation_from_local(local)
    runtime = SyntheticPhysicalTestRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=FakeGdiRasterSpooler(job_id=881),
    )
    result = runtime.execute(
        synthetic_fixture_version="SELLARI_SYNTHETIC_LABEL_V1",
        agent_printer_id=obs.agent_printer_id,
        printer_profile_fingerprint=obs.local_printer_fingerprint,
        layout=render_contract["layout"],
        label_width_mm=50,
        label_height_mm=35,
        dpi=300,
    )
    assert result["state"] == "SPOOLER_ACCEPTED"
    assert result["physical_output_proven"] is False
    with pytest.raises(Exception, match="arbitrary synthetic payload"):
        runtime.execute(
            synthetic_fixture_version="CALLER_PAYLOAD",
            agent_printer_id=obs.agent_printer_id,
            printer_profile_fingerprint=obs.local_printer_fingerprint,
            layout=render_contract["layout"],
            label_width_mm=50,
            label_height_mm=35,
            dpi=300,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows GDI load smoke only")
def test_windows_gdi_and_status_adapters_load_without_printing():
    # No StartDoc is called. If hosted Windows exposes any printer queue, safely
    # exercise local OpenPrinter/DocumentProperties/CreateDC/GetDeviceCaps only.
    spooler = WindowsGdiRasterSpooler()
    WindowsSpoolStatusAdapter()
    backend = WindowsPrinterBackend()
    descriptors = list(backend.enumerate_printers())
    if descriptors:
        try:
            result = spooler.safe_preflight(descriptors[0].queue_name)
        except DefinitePreSpoolFailure as exc:
            assert exc.code.startswith(("PRINTER_DEVMODE_", "GDI_CREATE_DC_"))
        else:
            assert result["copies"] == 1
            assert result["scale_percent"] in {None, 100}
            assert result["dpi_x"] > 0
            assert result["dpi_y"] > 0



def test_crash_after_spool_acceptance_before_backend_report_is_not_replayed(tmp_path):
    local, control, render_contract = contracts()
    replay = AgentPhysicalReplayStore(tmp_path / "accepted-crash.sqlite")
    reports = []

    def report(payload):
        reports.append(dict(payload))
        if payload["state"] == "SPOOLER_ACCEPTED":
            raise RuntimeError("synthetic network crash after EndDoc")
        return payload

    physical = PhysicalPrintRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        spooler=FakeGdiRasterSpooler(job_id=733),
        replay=replay,
        mark_rendered=lambda payload: payload,
        begin_spool=lambda payload: payload,
        report_result=report,
    )
    with pytest.raises(RuntimeError, match="synthetic network crash"):
        physical.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)
    stored = replay.get("exec-1")
    assert stored["state"] == "SPOOLER_ACCEPTED"
    assert stored["windows_spool_job_id"] == 733
    with pytest.raises(PhysicalReplayBlocked):
        physical.execute(control, render_contract, full_km=SYNTHETIC_PREVIEW_FULL_KM)


class FakeStatusAdapter:
    def query(self, *, queue_name, windows_spool_job_id):
        assert queue_name == "Synthetic Local Queue"
        assert windows_spool_job_id == 412
        return {
            "normalized_state": "OFFLINE",
            "observed_at": "2026-09-21T01:02:03+00:00",
            "safe_error_code": "PRINTER_OFFLINE",
        }


def test_typed_print_status_resolves_only_opaque_approved_printer():
    local, control, _ = contracts()
    runtime = PhysicalPrintStatusRuntime(
        resolver=LocalPrinterResolver(FakeDiscovery(local)),
        status_adapter=FakeStatusAdapter(),
    )
    result = runtime.query({
        "contract_version": "printing-agent-v2",
        "operation": "PRINT_STATUS",
        "execution_id": control["execution_id"],
        "printer_profile_id": control["printer_profile_id"],
        "printer_profile_fingerprint": control["printer_profile_fingerprint"],
        "agent_printer_id": control["agent_printer_id"],
        "windows_spool_job_id": 412,
    })
    assert result["normalized_state"] == "OFFLINE"
    assert result["physical_output_proven"] is False
    assert "queue_name" not in result

    with pytest.raises(Exception):
        runtime.query({
            "contract_version": "printing-agent-v2",
            "operation": "PRINT_STATUS",
            "execution_id": control["execution_id"],
            "printer_profile_id": control["printer_profile_id"],
            "printer_profile_fingerprint": control["printer_profile_fingerprint"],
            "agent_printer_id": control["agent_printer_id"],
            "windows_spool_job_id": 412,
            "queue_name": "caller-controlled",
        })



class _FakeWinspool:
    def __init__(
        self,
        *,
        source_copies=4,
        source_scale=75,
        copies_supported=True,
        scale_supported=True,
        canonical_copies=None,
        canonical_scale=None,
        canonical_copies_supported=True,
        canonical_scale_supported=True,
    ):
        self.source_copies = source_copies
        self.source_scale = source_scale
        self.copies_supported = copies_supported
        self.scale_supported = scale_supported
        self.canonical_copies = canonical_copies
        self.canonical_scale = canonical_scale
        self.canonical_copies_supported = canonical_copies_supported
        self.canonical_scale_supported = canonical_scale_supported
        self.size = ctypes.sizeof(_DEVMODE_PRINTER_PREFIX) + 32
        self.closed = 0

    @staticmethod
    def _write(ptr, value):
        ctypes.memmove(ptr, ctypes.byref(value), ctypes.sizeof(value))

    def OpenPrinterW(self, queue_name, handle_ptr, defaults):
        del queue_name, defaults
        ctypes.cast(handle_ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value = 1
        return 1

    def ClosePrinter(self, handle):
        del handle
        self.closed += 1
        return 1

    def DocumentPropertiesW(self, hwnd, handle, device_name, output, input_, mode):
        del hwnd, handle, device_name
        if mode == 0:
            return self.size
        if mode == WindowsGdiRasterSpooler.DM_OUT_BUFFER and not input_:
            dm = _DEVMODE_PRINTER_PREFIX()
            dm.dmSize = ctypes.sizeof(_DEVMODE_PRINTER_PREFIX)
            dm.dmDriverExtra = 0
            dm.dmFields = 0
            if self.copies_supported:
                dm.dmFields |= WindowsGdiRasterSpooler.DM_COPIES
            if self.scale_supported:
                dm.dmFields |= WindowsGdiRasterSpooler.DM_SCALE
            dm.dmCopies = self.source_copies
            dm.dmScale = self.source_scale
            self._write(output, dm)
            return WindowsGdiRasterSpooler.IDOK
        if mode == (
            WindowsGdiRasterSpooler.DM_IN_BUFFER
            | WindowsGdiRasterSpooler.DM_OUT_BUFFER
        ):
            incoming = ctypes.cast(
                input_, ctypes.POINTER(_DEVMODE_PRINTER_PREFIX)
            ).contents
            dm = _DEVMODE_PRINTER_PREFIX()
            ctypes.memmove(ctypes.byref(dm), input_, ctypes.sizeof(dm))
            if not self.canonical_copies_supported:
                dm.dmFields &= ~WindowsGdiRasterSpooler.DM_COPIES
            if not self.canonical_scale_supported:
                dm.dmFields &= ~WindowsGdiRasterSpooler.DM_SCALE
            if self.canonical_copies is not None:
                dm.dmCopies = self.canonical_copies
            else:
                dm.dmCopies = incoming.dmCopies
            if self.canonical_scale is not None:
                dm.dmScale = self.canonical_scale
            else:
                dm.dmScale = incoming.dmScale
            self._write(output, dm)
            return WindowsGdiRasterSpooler.IDOK
        return -1


class _FakeGdi:
    def __init__(self, geometry):
        self.geometry = dict(geometry)
        self.start_doc_calls = 0
        self.create_dc_calls = 0
        self.effective_copies = None
        self.effective_scale = None

    def CreateDCW(self, driver, queue_name, output, devmode):
        del driver, queue_name, output
        self.create_dc_calls += 1
        dm = ctypes.cast(devmode, ctypes.POINTER(_DEVMODE_PRINTER_PREFIX)).contents
        self.effective_copies = int(dm.dmCopies)
        self.effective_scale = (
            int(dm.dmScale)
            if int(dm.dmFields) & WindowsGdiRasterSpooler.DM_SCALE
            else None
        )
        return 101

    def GetDeviceCaps(self, hdc, index):
        del hdc
        return self.geometry[index]

    def StartDocW(self, hdc, doc):
        del hdc, doc
        self.start_doc_calls += 1
        return 733

    def StartPage(self, hdc):
        del hdc
        return 1

    def SetDIBitsToDevice(self, *args):
        return self.geometry[WindowsGdiRasterSpooler.PHYSICALHEIGHT]

    def EndPage(self, hdc):
        del hdc
        return 1

    def EndDoc(self, hdc):
        del hdc
        return 1

    def DeleteDC(self, hdc):
        del hdc
        return 1


def _approved_gdi_raster():
    local = caps()
    raster, _ = render_decode_verify_physical_label(
        SYNTHETIC_PREVIEW_FULL_KM,
        layout=layout(),
        label_width_mm=50,
        label_height_mm=35,
        dpi=local.dpi_x,
    )
    return replace(
        raster,
        physical_offset_x_px=local.offset_x_px,
        physical_offset_y_px=local.offset_y_px,
        printable_width_px=local.printable_width_px,
        printable_height_px=local.printable_height_px,
    )


def _gdi_geometry(raster):
    return {
        WindowsGdiRasterSpooler.LOGPIXELSX: raster.dpi,
        WindowsGdiRasterSpooler.LOGPIXELSY: raster.dpi,
        WindowsGdiRasterSpooler.PHYSICALWIDTH: raster.image.width,
        WindowsGdiRasterSpooler.PHYSICALHEIGHT: raster.image.height,
        WindowsGdiRasterSpooler.HORZRES: raster.printable_width_px,
        WindowsGdiRasterSpooler.VERTRES: raster.printable_height_px,
        WindowsGdiRasterSpooler.PHYSICALOFFSETX: raster.physical_offset_x_px,
        WindowsGdiRasterSpooler.PHYSICALOFFSETY: raster.physical_offset_y_px,
    }


def test_gdi_devmode_normalizes_driver_copies_and_scaling_before_create_dc():
    raster = _approved_gdi_raster()
    winspool = _FakeWinspool(source_copies=5, source_scale=75)
    gdi = _FakeGdi(_gdi_geometry(raster))
    spooler = WindowsGdiRasterSpooler(_winspool=winspool, _gdi32=gdi)
    created = []
    result = spooler.submit(
        queue_name="local-only-queue",
        raster=raster,
        on_job_created=created.append,
    )
    assert result.windows_spool_job_id == 733
    assert created == [733]
    assert gdi.effective_copies == 1
    assert gdi.effective_scale == 100
    assert gdi.start_doc_calls == 1


@pytest.mark.parametrize(
    "winspool,code",
    [
        (
            _FakeWinspool(canonical_copies=2),
            "PRINTER_DEVMODE_COPIES_UNSAFE",
        ),
        (
            _FakeWinspool(canonical_copies_supported=False),
            "PRINTER_DEVMODE_COPIES_UNSAFE",
        ),
        (
            _FakeWinspool(canonical_scale=90),
            "PRINTER_DEVMODE_SCALING_UNSAFE",
        ),
        (
            _FakeWinspool(canonical_scale_supported=False),
            "PRINTER_DEVMODE_SCALING_UNSAFE",
        ),
    ],
)
def test_gdi_devmode_canonicalization_fails_closed_before_startdoc(winspool, code):
    raster = _approved_gdi_raster()
    gdi = _FakeGdi(_gdi_geometry(raster))
    spooler = WindowsGdiRasterSpooler(_winspool=winspool, _gdi32=gdi)
    with pytest.raises(DefinitePreSpoolFailure, match=code):
        spooler.submit(
            queue_name="local-only-queue",
            raster=raster,
            on_job_created=lambda _: None,
        )
    assert gdi.start_doc_calls == 0


def test_gdi_devmode_without_standard_scale_support_remains_safe_if_copies_proven_one():
    raster = _approved_gdi_raster()
    winspool = _FakeWinspool(
        source_copies=3,
        scale_supported=False,
        canonical_scale_supported=False,
    )
    gdi = _FakeGdi(_gdi_geometry(raster))
    spooler = WindowsGdiRasterSpooler(_winspool=winspool, _gdi32=gdi)
    spooler.submit(
        queue_name="local-only-queue",
        raster=raster,
        on_job_created=lambda _: None,
    )
    assert gdi.effective_copies == 1
    assert gdi.effective_scale is None


@pytest.mark.parametrize(
    "cap_index,delta,code",
    [
        (WindowsGdiRasterSpooler.LOGPIXELSX, 1, "PRINTER_PROFILE_DPI_CHANGED"),
        (WindowsGdiRasterSpooler.LOGPIXELSY, 1, "PRINTER_PROFILE_DPI_CHANGED"),
        (WindowsGdiRasterSpooler.PHYSICALWIDTH, 1, "PRINTER_PHYSICAL_GEOMETRY_CHANGED"),
        (WindowsGdiRasterSpooler.PHYSICALHEIGHT, 1, "PRINTER_PHYSICAL_GEOMETRY_CHANGED"),
        (WindowsGdiRasterSpooler.HORZRES, -1, "PRINTER_PRINTABLE_AREA_CHANGED"),
        (WindowsGdiRasterSpooler.VERTRES, -1, "PRINTER_PRINTABLE_AREA_CHANGED"),
        (WindowsGdiRasterSpooler.PHYSICALOFFSETX, 1, "PRINTER_PHYSICAL_OFFSET_CHANGED"),
        (WindowsGdiRasterSpooler.PHYSICALOFFSETY, 1, "PRINTER_PHYSICAL_OFFSET_CHANGED"),
    ],
)
def test_final_dc_geometry_mismatch_blocks_before_startdoc(cap_index, delta, code):
    raster = _approved_gdi_raster()
    geometry = _gdi_geometry(raster)
    geometry[cap_index] += delta
    gdi = _FakeGdi(geometry)
    spooler = WindowsGdiRasterSpooler(
        _winspool=_FakeWinspool(),
        _gdi32=gdi,
    )
    with pytest.raises(DefinitePreSpoolFailure, match=code):
        spooler.submit(
            queue_name="local-only-queue",
            raster=raster,
            on_job_created=lambda _: None,
        )
    assert gdi.start_doc_calls == 0


def test_final_dc_exact_geometry_allows_exactly_one_startdoc_and_one_spool_job():
    raster = _approved_gdi_raster()
    gdi = _FakeGdi(_gdi_geometry(raster))
    spooler = WindowsGdiRasterSpooler(
        _winspool=_FakeWinspool(source_copies=9, source_scale=10),
        _gdi32=gdi,
    )
    created = []
    outcome = spooler.submit(
        queue_name="local-only-queue",
        raster=raster,
        on_job_created=created.append,
    )
    assert outcome.windows_spool_job_id == 733
    assert created == [733]
    assert gdi.start_doc_calls == 1
    assert gdi.effective_copies == 1
    assert gdi.effective_scale == 100
