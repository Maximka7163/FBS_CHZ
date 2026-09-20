from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Mapping, Sequence

import zxingcpp


PRINT_LAYOUT_SCHEMA_VERSION = "printing-layout-v1"
ALLOWED_ELEMENT_TYPES = frozenset({
    "DATA_MATRIX_KM",
    "HUMAN_READABLE_KI",
    "GTIN",
    "ARTICLE",
    "SKU",
    "PRODUCT_NAME",
    "STATIC_TEXT",
    "LINE",
    "RECTANGLE",
})
ALLOWED_FONTS = frozenset({"Arial", "DejaVu Sans", "Inter"})
ALLOWED_ALIGNMENTS = frozenset({"LEFT", "CENTER", "RIGHT"})
ALLOWED_ROTATIONS = frozenset({0, 90, 180, 270})
MIN_LABEL_MM = 10.0
MAX_LABEL_MM = 300.0
MAX_ELEMENTS = 64
MAX_TEXT_LENGTH = 500
MIN_FONT_PT = 5.0
MAX_FONT_PT = 72.0

# Accepted printing research range. The renderer converts this to an integer
# device module scale at the selected DPI and rejects an effective X-dimension
# that would leave this range.
MIN_MODULE_SIZE_MM = 0.255
MAX_MODULE_SIZE_MM = 0.615
MIN_QUIET_ZONE_MODULES = 1
MAX_QUIET_ZONE_MODULES = 1

SYNTHETIC_PREVIEW_FULL_KM = b"010460000000001221SYNTHETIC01\x1d91TEST\x1d92SYNTHETIC-SIGNATURE"


class PrintingContractError(ValueError):
    pass


class PrintingSecurityError(PrintingContractError):
    pass


@dataclass(frozen=True, slots=True)
class RenderedDataMatrix:
    image: Any
    svg: str
    payload_sha256: str
    module_size_mm_requested: float
    module_size_mm_effective: float
    scale_pixels: int
    quiet_zone_modules: int

    def __repr__(self) -> str:
        return (
            "RenderedDataMatrix(image=<MATRIX>, svg=<SVG>, "
            f"payload_sha256={self.payload_sha256!r}, "
            f"module_size_mm_effective={self.module_size_mm_effective!r})"
        )


def _num(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PrintingContractError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise PrintingContractError(f"{label} must be finite")
    return result


def _bounded_text(value: Any, label: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise PrintingContractError(f"{label} must be a string")
    if required and not value:
        raise PrintingContractError(f"{label} must not be empty")
    if len(value) > MAX_TEXT_LENGTH:
        raise PrintingContractError(f"{label} is too long")
    if any(ord(ch) < 0x20 and ch not in "\t" for ch in value):
        raise PrintingSecurityError(f"{label} contains forbidden control characters")
    return value


def _rect(element: Mapping[str, Any], *, width_mm: float, height_mm: float, label: str) -> dict[str, float]:
    x = _num(element.get("x"), f"{label}.x")
    y = _num(element.get("y"), f"{label}.y")
    width = _num(element.get("width"), f"{label}.width")
    height = _num(element.get("height"), f"{label}.height")
    if x < 0 or y < 0 or width <= 0 or height <= 0:
        raise PrintingContractError(f"{label} rectangle must be positive and inside label")
    if x + width > width_mm + 1e-9 or y + height > height_mm + 1e-9:
        raise PrintingContractError(f"{label} rectangle exceeds label bounds")
    return {"x": x, "y": y, "width": width, "height": height}


def _style(element: Mapping[str, Any], label: str, *, text_capable: bool) -> dict[str, Any]:
    allowed = {"rotation"}
    if text_capable:
        allowed |= {"font_family", "font_size_pt", "alignment"}
    result: dict[str, Any] = {}
    rotation = element.get("rotation", 0)
    if type(rotation) is not int or rotation not in ALLOWED_ROTATIONS:
        raise PrintingContractError(f"{label}.rotation is unsupported")
    result["rotation"] = rotation
    if text_capable:
        family = element.get("font_family", "Arial")
        if family not in ALLOWED_FONTS:
            raise PrintingSecurityError(f"{label}.font_family is not allowlisted")
        size = _num(element.get("font_size_pt", 9), f"{label}.font_size_pt")
        if not MIN_FONT_PT <= size <= MAX_FONT_PT:
            raise PrintingContractError(f"{label}.font_size_pt is out of range")
        alignment = element.get("alignment", "LEFT")
        if alignment not in ALLOWED_ALIGNMENTS:
            raise PrintingContractError(f"{label}.alignment is unsupported")
        result.update(font_family=family, font_size_pt=size, alignment=alignment)
    return result


def validate_layout(layout: Mapping[str, Any], *, label_width_mm: float, label_height_mm: float) -> dict[str, Any]:
    width_mm = _num(label_width_mm, "label_width_mm")
    height_mm = _num(label_height_mm, "label_height_mm")
    if not MIN_LABEL_MM <= width_mm <= MAX_LABEL_MM or not MIN_LABEL_MM <= height_mm <= MAX_LABEL_MM:
        raise PrintingContractError("label dimensions are out of range")
    if not isinstance(layout, Mapping):
        raise PrintingContractError("layout must be an object")
    unknown_root = set(layout) - {"schema_version", "elements"}
    if unknown_root:
        raise PrintingSecurityError(f"layout has forbidden fields: {sorted(unknown_root)}")
    if layout.get("schema_version") != PRINT_LAYOUT_SCHEMA_VERSION:
        raise PrintingContractError("unsupported print layout schema_version")
    elements = layout.get("elements")
    if not isinstance(elements, list) or not 1 <= len(elements) <= MAX_ELEMENTS:
        raise PrintingContractError(f"layout.elements must contain 1..{MAX_ELEMENTS} elements")

    normalized: list[dict[str, Any]] = []
    dm_count = 0
    for index, raw in enumerate(elements):
        label = f"elements[{index}]"
        if not isinstance(raw, Mapping):
            raise PrintingContractError(f"{label} must be an object")
        kind = raw.get("type")
        if kind not in ALLOWED_ELEMENT_TYPES:
            raise PrintingSecurityError(f"{label}.type is not allowed")
        base_allowed = {"type", "x", "y", "width", "height", "rotation"}
        item: dict[str, Any] = {"type": kind, **_rect(raw, width_mm=width_mm, height_mm=height_mm, label=label)}

        if kind == "DATA_MATRIX_KM":
            dm_count += 1
            allowed = base_allowed | {"module_size_mm", "quiet_zone_modules", "payload_source"}
            unknown = set(raw) - allowed
            if unknown:
                raise PrintingSecurityError(f"{label} has forbidden fields: {sorted(unknown)}")
            if raw.get("payload_source") != "SYSTEM_FULL_KM":
                raise PrintingSecurityError("DATA_MATRIX_KM payload source is system-owned and non-editable")
            module_size = _num(raw.get("module_size_mm"), f"{label}.module_size_mm")
            if not MIN_MODULE_SIZE_MM <= module_size <= MAX_MODULE_SIZE_MM:
                raise PrintingContractError("DataMatrix module size is outside accepted research range")
            quiet = raw.get("quiet_zone_modules", MIN_QUIET_ZONE_MODULES)
            if type(quiet) is not int or not MIN_QUIET_ZONE_MODULES <= quiet <= MAX_QUIET_ZONE_MODULES:
                raise PrintingContractError("DataMatrix quiet zone is outside standards-compatible bound")
            item.update(_style(raw, label, text_capable=False))
            item.update(
                module_size_mm=module_size,
                quiet_zone_modules=quiet,
                payload_source="SYSTEM_FULL_KM",
            )
        elif kind in {"HUMAN_READABLE_KI", "GTIN", "ARTICLE", "SKU", "PRODUCT_NAME"}:
            allowed = base_allowed | {"font_family", "font_size_pt", "alignment"}
            unknown = set(raw) - allowed
            if unknown:
                raise PrintingSecurityError(f"{label} has forbidden fields: {sorted(unknown)}")
            item.update(_style(raw, label, text_capable=True))
        elif kind == "STATIC_TEXT":
            allowed = base_allowed | {"font_family", "font_size_pt", "alignment", "text"}
            unknown = set(raw) - allowed
            if unknown:
                raise PrintingSecurityError(f"{label} has forbidden fields: {sorted(unknown)}")
            item.update(_style(raw, label, text_capable=True))
            item["text"] = _bounded_text(raw.get("text"), f"{label}.text")
        else:
            allowed = base_allowed | {"stroke_width_mm"}
            unknown = set(raw) - allowed
            if unknown:
                raise PrintingSecurityError(f"{label} has forbidden fields: {sorted(unknown)}")
            item.update(_style(raw, label, text_capable=False))
            stroke = _num(raw.get("stroke_width_mm", 0.2), f"{label}.stroke_width_mm")
            if not 0.05 <= stroke <= 2.0:
                raise PrintingContractError(f"{label}.stroke_width_mm is out of range")
            item["stroke_width_mm"] = stroke
        normalized.append(item)

    if dm_count != 1:
        raise PrintingContractError("layout must contain exactly one DATA_MATRIX_KM element")
    return {"schema_version": PRINT_LAYOUT_SCHEMA_VERSION, "elements": normalized}


def canonical_layout_sha256(layout: Mapping[str, Any], *, label_width_mm: float, label_height_mm: float) -> tuple[dict[str, Any], str]:
    normalized = validate_layout(layout, label_width_mm=label_width_mm, label_height_mm=label_height_mm)
    canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return normalized, hashlib.sha256(canonical).hexdigest()


def _scale_for_module(module_size_mm: float, dpi: int) -> tuple[int, float]:
    if type(dpi) is not int or not 150 <= dpi <= 1200:
        raise PrintingContractError("dpi must be 150..1200")
    if not MIN_MODULE_SIZE_MM <= module_size_mm <= MAX_MODULE_SIZE_MM:
        raise PrintingContractError("DataMatrix module size is outside accepted research range")
    pixels = max(1, round(module_size_mm * dpi / 25.4))
    effective = pixels * 25.4 / dpi
    if not MIN_MODULE_SIZE_MM <= effective <= MAX_MODULE_SIZE_MM:
        raise PrintingContractError("device DPI cannot represent an accepted module size")
    return pixels, effective


def render_gs1_datamatrix(
    full_km: bytes,
    *,
    module_size_mm: float,
    quiet_zone_modules: int = MIN_QUIET_ZONE_MODULES,
    dpi: int = 300,
) -> RenderedDataMatrix:
    if not isinstance(full_km, bytes) or not full_km:
        raise PrintingContractError("FULL KM must be non-empty bytes")
    if b"<GS>" in full_km:
        raise PrintingSecurityError("visible <GS> marker is not an accepted substitute for ASCII 29")
    if b"\x00" in full_km:
        raise PrintingSecurityError("NUL is not accepted in printable FULL KM")
    if type(quiet_zone_modules) is not int or not MIN_QUIET_ZONE_MODULES <= quiet_zone_modules <= MAX_QUIET_ZONE_MODULES:
        raise PrintingContractError("quiet zone is outside standards-compatible bound")
    scale, effective = _scale_for_module(float(module_size_mm), dpi)
    # zxing-cpp 3.x accepts bytes and GS1 creator mode. bytes avoids any
    # Unicode normalization/transcoding of the logical FULL KM.
    barcode = zxingcpp.create_barcode(
        full_km,
        zxingcpp.BarcodeFormat.DataMatrix,
        gs1=True,
        force_square=True,
    )
    image = barcode.to_image(scale=scale, add_quiet_zones=True)
    svg = barcode.to_svg(scale=scale, add_quiet_zones=True)
    return RenderedDataMatrix(
        image=image,
        svg=svg,
        payload_sha256=hashlib.sha256(full_km).hexdigest(),
        module_size_mm_requested=float(module_size_mm),
        module_size_mm_effective=effective,
        scale_pixels=scale,
        quiet_zone_modules=quiet_zone_modules,
    )


def render_synthetic_preview(layout: Mapping[str, Any], *, label_width_mm: float, label_height_mm: float, dpi: int = 300) -> dict[str, Any]:
    normalized = validate_layout(layout, label_width_mm=label_width_mm, label_height_mm=label_height_mm)
    dm = next(item for item in normalized["elements"] if item["type"] == "DATA_MATRIX_KM")
    rendered = render_gs1_datamatrix(
        SYNTHETIC_PREVIEW_FULL_KM,
        module_size_mm=dm["module_size_mm"],
        quiet_zone_modules=dm["quiet_zone_modules"],
        dpi=dpi,
    )
    return {
        "synthetic": True,
        "schema_version": PRINT_LAYOUT_SCHEMA_VERSION,
        "payload_sha256": rendered.payload_sha256,
        "datamatrix_svg": rendered.svg,
        "module_size_mm_effective": rendered.module_size_mm_effective,
        "quiet_zone_modules": rendered.quiet_zone_modules,
    }
