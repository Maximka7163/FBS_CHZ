from __future__ import annotations

import os
import time
from dataclasses import replace

import pytest

from wbcz.printing import PrintingRuntimeUnavailable

from wbcz.printer_profiles import (
    BoundedPrinterDiscovery,
    LocalPrinterCapabilities,
    LocalPrinterDescriptor,
    PrinterDiscoveryJob,
    PrinterObservation,
    PrinterProfileContractError,
    PrinterProfileSecurityError,
    SyntheticTestPrintContract,
    WindowsPrinterBackend,
    capability_hash,
    evaluate_template_compatibility,
    sanitize_display_name,
)


def _layout(module_size_mm: float = 0.4):
    return {
        "schema_version": "printing-layout-v1",
        "elements": [
            {
                "type": "DATA_MATRIX_KM",
                "x": 5.0,
                "y": 5.0,
                "width": 25.0,
                "height": 25.0,
                "rotation": 0,
                "module_size_mm": module_size_mm,
                "quiet_zone_modules": 1,
                "payload_source": "SYSTEM_FULL_KM",
            }
        ],
    }


def _profile_kwargs(dpi: int = 300, *, state: str = "ACTIVE", offset_x: int = 0, offset_y: int = 0):
    physical_width = round(50.0 * dpi / 25.4)
    physical_height = round(35.0 * dpi / 25.4)
    return {
        "profile_state": state,
        "dpi_x": dpi,
        "dpi_y": dpi,
        "media_width_mm": 50.0,
        "media_height_mm": 35.0,
        "physical_width_px": physical_width,
        "physical_height_px": physical_height,
        "printable_width_px": physical_width - offset_x,
        "printable_height_px": physical_height - offset_y,
        "offset_x_px": offset_x,
        "offset_y_px": offset_y,
        "template_layout": _layout(),
        "label_width_mm": 50.0,
        "label_height_mm": 35.0,
    }


class FakeBackend:
    def __init__(self, descriptors, values, *, delay=None):
        self.descriptors = list(descriptors)
        self.values = dict(values)
        self.delay = dict(delay or {})

    def enumerate_printers(self):
        return list(self.descriptors)

    def inspect_printer(self, descriptor):
        time.sleep(self.delay.get(descriptor.queue_name, 0))
        value = self.values[descriptor.queue_name]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, LocalPrinterCapabilities):
            return replace(value, server_name=descriptor.server_name)
        return value


def _caps(name: str, *, driver: str = "Synthetic Driver", port: str = "PORT1", dpi: int = 300):
    width = round(50.0 * dpi / 25.4)
    height = round(35.0 * dpi / 25.4)
    return LocalPrinterCapabilities(
        queue_name=name,
        server_name=None,
        port_name=port,
        driver_name=driver,
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


def test_discovery_contract_is_closed_and_never_accepts_queue_paths_or_commands():
    value = PrinterDiscoveryJob.from_mapping({
        "contract_version": "printing-agent-v2",
        "operation": "LIST",
        "discovery_request_id": "run-1",
        "agent_printer_id": None,
    })
    assert value.operation == "LIST"
    with pytest.raises(PrinterProfileSecurityError):
        PrinterDiscoveryJob.from_mapping({
            "contract_version": "printing-agent-v2",
            "operation": "LIST",
            "discovery_request_id": "run-1",
            "queue_name": "\\\\server\\label",
        })
    with pytest.raises(PrinterProfileContractError):
        PrinterDiscoveryJob.from_mapping({
            "contract_version": "printing-agent-v2",
            "operation": "WRITE_RAW",
            "discovery_request_id": "run-1",
        })


def test_observation_rejects_raw_device_fields_and_sanitizes_control_characters():
    base = {
        "agent_printer_id": "prn_123",
        "local_printer_fingerprint": "a" * 64,
        "display_name_sanitized": "Label\nPrinter\x00One",
        "driver_name_sanitized": "Driver\tName",
        "dpi_x": 300,
        "dpi_y": 300,
        "media_width_mm": 50.0,
        "media_height_mm": 35.0,
        "orientation": "LANDSCAPE",
        "physical_width_px": 591,
        "physical_height_px": 413,
        "printable_width_px": 591,
        "printable_height_px": 413,
        "offset_x_px": 0,
        "offset_y_px": 0,
        "availability_state": "AVAILABLE",
        "observed_at": "2026-09-21T00:00:00Z",
        "safe_error_code": None,
    }
    hashed = dict(base)
    hashed["display_name_sanitized"] = sanitize_display_name(base["display_name_sanitized"])
    hashed["driver_name_sanitized"] = sanitize_display_name(base["driver_name_sanitized"])
    base["capability_hash"] = capability_hash(hashed)
    value = PrinterObservation.from_mapping(base)
    assert "\n" not in value.display_name_sanitized
    assert "\x00" not in value.display_name_sanitized
    assert value.display_name_sanitized == "Label Printer One"
    assert value.driver_name_sanitized == "Driver Name"

    with pytest.raises(PrinterProfileSecurityError):
        PrinterObservation.from_mapping({**base, "queue_name": "raw-local-queue"})


def test_connection_style_name_is_reduced_to_leaf_and_paths_never_cross_boundary():
    assert sanitize_display_name("\\\\print-server\\Warehouse Label") == "Warehouse Label"
    with pytest.raises(PrinterProfileSecurityError):
        sanitize_display_name("C:\\spool\\queue")


def test_bounded_discovery_isolates_failure_and_slow_printer():
    fast = LocalPrinterDescriptor("Fast")
    broken = LocalPrinterDescriptor("Broken")
    slow = LocalPrinterDescriptor("Slow")
    backend = FakeBackend(
        [fast, broken, slow],
        {
            "Fast": _caps("Fast"),
            "Broken": RuntimeError("offline"),
            "Slow": _caps("Slow"),
        },
        delay={"Slow": 0.25},
    )
    started = time.monotonic()
    result = BoundedPrinterDiscovery(
        backend,
        per_printer_timeout_seconds=0.05,
        enumerate_timeout_seconds=1.0,
    ).discover()
    elapsed = time.monotonic() - started
    states = {item.display_name_sanitized: item.availability_state for item in result}
    assert states["Fast"] == "AVAILABLE"
    assert states["Broken"] == "ERROR"
    assert states["Slow"] == "UNAVAILABLE"
    assert elapsed < 0.2


def test_duplicate_display_names_keep_distinct_opaque_ids_and_max_count_is_bounded():
    descriptors = [LocalPrinterDescriptor("Same", server_name=f"server-{i}") for i in range(3)]
    backend = FakeBackend(
        descriptors,
        {"Same": _caps("Same")},
    )
    result = BoundedPrinterDiscovery(backend, max_printers=2).discover()
    assert len(result) == 2
    assert result[0].display_name_sanitized == result[1].display_name_sanitized == "Same"
    assert result[0].agent_printer_id != result[1].agent_printer_id


@pytest.mark.parametrize("dpi", [203, 300, 600])
def test_representative_printer_dpi_is_compatible(dpi):
    result = evaluate_template_compatibility(**_profile_kwargs(dpi))
    assert result["result"] == "COMPATIBLE"
    assert result["module_pixels"] >= 1


def test_missing_renderer_runtime_is_not_misclassified_as_module_size(monkeypatch):
    def unavailable(*args, **kwargs):
        raise PrintingRuntimeUnavailable("libdmtx unavailable")

    monkeypatch.setattr("wbcz.printer_profiles.render_gs1_datamatrix", unavailable)
    result = evaluate_template_compatibility(**_profile_kwargs(300))
    assert result == {
        "result": "PRINT_RENDERER_RUNTIME_UNAVAILABLE",
        "safe_reason_code": "LIBDMTX_RUNTIME_UNAVAILABLE",
    }


def test_anisotropic_dpi_media_mismatch_clipping_and_module_rounding_fail_closed():
    anisotropic = _profile_kwargs(300)
    anisotropic["dpi_y"] = 600
    assert evaluate_template_compatibility(**anisotropic)["result"] == "PRINTER_DPI_UNSUPPORTED"

    media = _profile_kwargs(300)
    media["media_width_mm"] = 60.0
    assert evaluate_template_compatibility(**media)["result"] == "PRINTER_MEDIA_TEMPLATE_MISMATCH"

    clipped = _profile_kwargs(300, offset_x=80, offset_y=80)
    assert evaluate_template_compatibility(**clipped)["result"] == "PRINT_LAYOUT_OUTSIDE_PRINTABLE_AREA"

    too_small = _profile_kwargs(203)
    too_small["template_layout"] = _layout(0.255)
    assert evaluate_template_compatibility(**too_small)["result"] == "DATAMATRIX_MODULE_SIZE_UNSUPPORTED"

    too_large = _profile_kwargs(203)
    too_large["template_layout"] = _layout(0.615)
    assert evaluate_template_compatibility(**too_large)["result"] == "DATAMATRIX_MODULE_SIZE_UNSUPPORTED"


@pytest.mark.parametrize(
    "state,expected",
    [
        ("STALE", "PRINTER_PROFILE_STALE"),
        ("MISSING", "PRINTER_PROFILE_MISSING"),
        ("INCOMPATIBLE", "PRINTER_PROFILE_INCOMPATIBLE"),
        ("DISABLED", "PRINTER_PROFILE_DISABLED"),
    ],
)
def test_non_active_profile_states_are_never_compatible(state, expected):
    assert evaluate_template_compatibility(**_profile_kwargs(300, state=state))["result"] == expected


def test_synthetic_test_print_contract_is_typed_but_physically_blocked():
    contract = SyntheticTestPrintContract(
        contract_version="printing-agent-v2",
        operation="TEST_PRINT_SYNTHETIC",
        printer_profile_id="profile-1",
        synthetic_fixture_version="SELLARI_SYNTHETIC_LABEL_V1",
    )
    result = contract.blocked_result()
    assert result["state"] == "PHYSICAL_EXECUTION_BLOCKED_PHASE_C"
    assert result["physical_printer_called"] is False


@pytest.mark.skipif(os.name != "nt", reason="real Windows printer enumeration only runs on Windows")
def test_real_windows_enumprinters_adapter_smoke_is_safe_with_zero_or_more_printers():
    backend = WindowsPrinterBackend()
    rows = list(backend.enumerate_printers())
    assert all(isinstance(row, LocalPrinterDescriptor) and row.queue_name for row in rows)
