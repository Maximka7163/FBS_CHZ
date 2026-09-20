from __future__ import annotations

from dataclasses import replace

import pytest
import numpy as np
import zxingcpp

from wbcz.printing import (
    PRINT_LAYOUT_SCHEMA_VERSION,
    PrintingContractError,
    PrintingSecurityError,
    render_gs1_datamatrix,
    render_synthetic_preview,
    validate_layout,
)
from wbcz.printing_agent import FakePrintExecutor, PrintAgentContractError
from wbcz_web.config import WebConfig
from wbcz_web.services.authorization import Permission, ROLE_PERMISSIONS, Role


SYNTHETIC_FULL_KM = b"010460000000001221SYNTHETIC01\x1d91TEST\x1d92SYNTHETIC-SIGNATURE"


def layout(*, module_size_mm: float = 0.34) -> dict:
    return {
        "schema_version": PRINT_LAYOUT_SCHEMA_VERSION,
        "elements": [
            {
                "type": "DATA_MATRIX_KM",
                "x": 2,
                "y": 2,
                "width": 24,
                "height": 24,
                "rotation": 0,
                "module_size_mm": module_size_mm,
                "quiet_zone_modules": 1,
                "payload_source": "SYSTEM_FULL_KM",
            },
            {
                "type": "HUMAN_READABLE_KI",
                "x": 2,
                "y": 28,
                "width": 45,
                "height": 5,
                "font_family": "Arial",
                "font_size_pt": 8,
                "alignment": "LEFT",
                "rotation": 0,
            },
            {
                "type": "STATIC_TEXT",
                "x": 2,
                "y": 34,
                "width": 45,
                "height": 5,
                "font_family": "Inter",
                "font_size_pt": 8,
                "alignment": "LEFT",
                "rotation": 0,
                "text": "Synthetic fixture",
            },
        ],
    }


def test_gs1_datamatrix_round_trip_with_independent_libdmtx_decoder_preserves_exact_bytes():
    rendered = render_gs1_datamatrix(
        SYNTHETIC_FULL_KM,
        module_size_mm=0.34,
        quiet_zone_modules=1,
        dpi=300,
    )
    # libdmtx is the encoder. zxing-cpp is an independent decoder.
    image = np.frombuffer(rendered.image.pixels, dtype=np.uint8).reshape(
        rendered.image.height, rendered.image.width, 3
    )
    decoded = zxingcpp.read_barcode(
        image,
        formats=zxingcpp.BarcodeFormat.DataMatrix,
        is_pure=True,
        text_mode=zxingcpp.TextMode.Plain,
    )
    assert decoded is not None
    assert decoded.content_type == zxingcpp.ContentType.GS1
    assert decoded.symbology_identifier == "]d2"
    assert decoded.bytes == SYNTHETIC_FULL_KM
    assert b"\x1d91TEST\x1d92" in decoded.bytes
    assert b"<GS>" not in decoded.bytes
    assert rendered.payload_sha256
    assert rendered.quiet_zone_modules == 1


def test_preview_is_synthetic_only_and_never_accepts_or_returns_caller_full_km():
    preview = render_synthetic_preview(layout(), label_width_mm=50, label_height_mm=40)
    assert preview["synthetic"] is True
    assert "datamatrix_svg" in preview
    rendered = repr(preview)
    assert SYNTHETIC_FULL_KM.decode("latin1") not in rendered
    assert "FULL_KM" not in rendered


@pytest.mark.parametrize(
    "mutator,error",
    [
        (lambda x: x["elements"][0].update(payload_source="CALLER_PAYLOAD"), PrintingSecurityError),
        (lambda x: x["elements"][0].update(module_size_mm=0.1), PrintingContractError),
        (lambda x: x["elements"][0].update(quiet_zone_modules=2), PrintingContractError),
        (lambda x: x["elements"][0].update(script="alert(1)"), PrintingSecurityError),
        (lambda x: x["elements"][1].update(font_family="../../etc/passwd"), PrintingSecurityError),
        (lambda x: x["elements"].append(dict(x["elements"][0])), PrintingContractError),
    ],
)
def test_closed_template_schema_rejects_payload_override_executable_content_and_invalid_geometry(mutator, error):
    value = layout()
    mutator(value)
    with pytest.raises(error):
        validate_layout(value, label_width_mm=50, label_height_mm=40)


def test_renderer_rejects_visible_gs_marker_and_never_recomputes_91_92():
    with pytest.raises(PrintingSecurityError):
        render_gs1_datamatrix(
            b"010460000000001221SYNTHETIC<GS>91A<GS>92B",
            module_size_mm=0.34,
        )
    rendered = render_gs1_datamatrix(SYNTHETIC_FULL_KM, module_size_mm=0.34)
    image = np.frombuffer(rendered.image.pixels, dtype=np.uint8).reshape(
        rendered.image.height, rendered.image.width, 3
    )
    decoded = zxingcpp.read_barcode(image, formats=zxingcpp.BarcodeFormat.DataMatrix, is_pure=True)
    assert decoded is not None
    assert decoded.bytes.endswith(b"91TEST\x1d92SYNTHETIC-SIGNATURE")


def test_print_agent_contract_contains_ids_hashes_only_and_fake_executor_never_prints():
    value = {
        "contract_version": "printing-agent-v1",
        "job_id": "job-1",
        "organisation_id": "org-1",
        "participant_id": "part-1",
        "template_version_id": "tpl-v1",
        "mode": "INITIAL_PRINT",
        "printer_profile_id": "logical-printer-1",
        "printer_profile_fingerprint": "a" * 64,
        "items": [{
            "print_job_item_id": "item-1",
            "stored_full_km_item_id": "stored-1",
            "ordinal": 0,
            "payload_sha256": "b" * 64,
        }],
        "sensitive_payload_delivery": "BLOCKED_NOT_IMPLEMENTED",
    }
    result = FakePrintExecutor().execute(value)
    assert result.outcome == "BLOCKED"
    assert result.physical_printer_called is False
    assert result.sensitive_payload_received is False
    assert result.safe_error_code == "SENSITIVE_PAYLOAD_DELIVERY_NOT_IMPLEMENTED"

    for forbidden in ("full_km", "zpl", "command_bytes", "url", "path"):
        bad = dict(value)
        bad[forbidden] = "SYNTHETIC-SECRET-CANARY"
        with pytest.raises(PrintAgentContractError):
            FakePrintExecutor().execute(bad)


def test_print_rbac_mapping_matches_product_contract():
    assert Permission.PRINT_READ in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.PRINT_EXECUTE not in ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.PRINT_TEMPLATES_MANAGE not in ROLE_PERMISSIONS[Role.VIEWER]

    assert Permission.PRINT_READ in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.PRINT_EXECUTE in ROLE_PERMISSIONS[Role.OPERATOR]
    assert Permission.PRINT_TEMPLATES_MANAGE not in ROLE_PERMISSIONS[Role.OPERATOR]

    assert Permission.PRINT_TEMPLATES_MANAGE in ROLE_PERMISSIONS[Role.ADMIN]
    assert set((Permission.PRINT_READ, Permission.PRINT_EXECUTE, Permission.PRINT_TEMPLATES_MANAGE)).issubset(
        ROLE_PERMISSIONS[Role.OWNER]
    )


def test_printing_feature_gates_are_fail_closed_and_production_physical_execution_cannot_be_enabled():
    base = WebConfig.from_env()
    assert base.printing_enabled is False
    assert base.print_execution_enabled is False
    assert base.suz_full_km_remote_acquisition_enabled is False

    with pytest.raises(ValueError, match="FULL KM SUZ acquisition remains blocked"):
        replace(base, suz_full_km_remote_acquisition_enabled=True).validate_for_startup()

    production_execution = replace(
        base,
        environment="production",
        printing_enabled=True,
        print_execution_enabled=True,
        agent_enabled=True,
    )
    with pytest.raises(ValueError, match="Physical print execution remains blocked"):
        production_execution.validate_for_startup()


def test_printing_api_surface_has_no_export_copy_or_generic_printer_proxy():
    from wbcz_web.main import create_app

    app = create_app(WebConfig.from_env().validate_for_startup())
    paths = {route.path for route in app.routes if hasattr(route, "path")}
    required = {
        "/api/printing/printability/resolve",
        "/api/printing/templates",
        "/api/printing/templates/{template_id}",
        "/api/printing/templates/{template_id}/versions",
        "/api/printing/templates/{template_id}/archive",
        "/api/printing/template-versions/{version_id}/preview",
        "/api/printing/jobs",
        "/api/printing/jobs/{job_id}",
        "/api/printing/jobs/reprint",
        "/api/printing/jobs/{job_id}/agent-contract",
    }
    assert required.issubset(paths)
    forbidden_fragments = ("/export", "/copy", "/clipboard", "/printer-proxy", "/zpl", "/raw-command")
    assert not any(
        path.startswith("/api/printing") and any(fragment in path for fragment in forbidden_fragments)
        for path in paths
    )
