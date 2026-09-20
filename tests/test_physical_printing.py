from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
import sqlite3

import pytest

from wbcz.physical_printing import (
    AgentPhysicalReplayStore,
    AmbiguousAfterSpool,
    FakeGdiRasterSpooler,
    LocalPrinterResolver,
    PhysicalExecutionControl,
    PhysicalPrintError,
    PhysicalPrintRuntime,
    PhysicalReplayBlocked,
    SyntheticPhysicalTestRuntime,
    WindowsGdiRasterSpooler,
    WindowsSpoolStatusAdapter,
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
    # Construction validates ctypes surface only. No printer is selected and no
    # StartDoc/spool side effect is invoked by this smoke test.
    WindowsGdiRasterSpooler()
    WindowsSpoolStatusAdapter()
