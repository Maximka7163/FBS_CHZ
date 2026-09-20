from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import POINTER, byref, c_int, c_ubyte, c_void_p
from ctypes.util import find_library
import hashlib
import json
import math
from typing import Any, Mapping


PRINT_LAYOUT_SCHEMA_VERSION = "printing-layout-v1"
PRINTING_CONTRACT_VERSION = "sellari-printing-contract-v1"
RENDERER_VERSION = "sellari-libdmtx-raster-v1"
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
class RasterImage:
    width: int
    height: int
    bpp: int
    pixels: bytes


@dataclass(frozen=True, slots=True)
class RenderedDataMatrix:
    image: RasterImage
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


class _DmtxImage(ctypes.Structure):
    _fields_ = [
        ("width", c_int),
        ("height", c_int),
        ("pixelPacking", c_int),
        ("bitsPerPixel", c_int),
        ("bytesPerPixel", c_int),
        ("rowPadBytes", c_int),
        ("rowSizeBytes", c_int),
        ("imageFlip", c_int),
        ("channelCount", c_int),
        ("channelStart", c_int * 4),
        ("bitsPerChannel", c_int * 4),
        ("pxl", POINTER(c_ubyte)),
    ]


class _DmtxEncode(ctypes.Structure):
    # libdmtx >=0.7.5 prefix only; fields after image are not accessed.
    _fields_ = [
        ("method", c_int),
        ("scheme", c_int),
        ("sizeIdxRequest", c_int),
        ("marginSize", c_int),
        ("moduleSize", c_int),
        ("pixelPacking", c_int),
        ("imageFlip", c_int),
        ("rowPadBytes", c_int),
        ("fnc1", c_int),
        ("message", c_void_p),
        ("image", POINTER(_DmtxImage)),
    ]


def _load_libdmtx() -> Any:
    candidates = [find_library("dmtx"), "libdmtx.so.0", "libdmtx.so", "libdmtx.dll", "libdmtx.dylib"]
    library = None
    for candidate in candidates:
        if not candidate:
            continue
        try:
            library = ctypes.CDLL(candidate)
            break
        except OSError:
            continue
    if library is None:
        raise PrintingContractError("libdmtx runtime is unavailable")

    library.dmtxVersion.restype = ctypes.c_char_p
    version = (library.dmtxVersion() or b"").decode("ascii", errors="strict")
    parts = tuple(int(piece) for piece in version.split(".")[:3] if piece.isdigit())
    if not parts or parts < (0, 7, 5):
        raise PrintingContractError("libdmtx >=0.7.5 is required")

    library.dmtxEncodeCreate.argtypes = []
    library.dmtxEncodeCreate.restype = POINTER(_DmtxEncode)
    library.dmtxEncodeDestroy.argtypes = [POINTER(POINTER(_DmtxEncode))]
    library.dmtxEncodeDestroy.restype = ctypes.c_uint
    library.dmtxEncodeSetProp.argtypes = [POINTER(_DmtxEncode), c_int, c_int]
    library.dmtxEncodeSetProp.restype = ctypes.c_uint
    library.dmtxEncodeDataMatrix.argtypes = [POINTER(_DmtxEncode), c_int, POINTER(c_ubyte)]
    library.dmtxEncodeDataMatrix.restype = ctypes.c_uint
    return library


def _svg_from_rgb(raster: RasterImage) -> str:
    if raster.bpp != 24:
        raise PrintingContractError("unexpected libdmtx raster format")
    if len(raster.pixels) != raster.width * raster.height * 3:
        raise PrintingContractError("invalid libdmtx raster size")
    rects: list[str] = []
    pixels = raster.pixels
    for y in range(raster.height):
        row = y * raster.width * 3
        x = 0
        while x < raster.width:
            idx = row + x * 3
            is_dark = pixels[idx] < 128 and pixels[idx + 1] < 128 and pixels[idx + 2] < 128
            if not is_dark:
                x += 1
                continue
            start = x
            while x < raster.width:
                idx = row + x * 3
                if not (pixels[idx] < 128 and pixels[idx + 1] < 128 and pixels[idx + 2] < 128):
                    break
                x += 1
            rects.append(f'<rect x="{start}" y="{y}" width="{x-start}" height="1"/>')
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {raster.width} {raster.height}" '
        f'width="{raster.width}" height="{raster.height}" shape-rendering="crispEdges">'
        '<rect width="100%" height="100%" fill="white"/>'
        '<g fill="black">' + "".join(rects) + "</g></svg>"
    )


def _encode_gs1_raw_libdmtx(full_km: bytes, *, module_pixels: int, quiet_zone_modules: int) -> RasterImage:
    library = _load_libdmtx()
    encoder = library.dmtxEncodeCreate()
    if not encoder:
        raise PrintingContractError("libdmtx encoder creation failed")
    try:
        # libdmtx DmtxPropFnc1 makes the configured input byte encode as FNC1.
        # A leading ASCII 29 represents the GS1 symbology FNC1 and is not part
        # of the recovered logical payload. ASCII 29 already present inside the
        # exact FULL KM becomes separator FNC1 and decodes back to ASCII 29.
        encoded_input = b"\x1d" + full_km
        source = (c_ubyte * len(encoded_input)).from_buffer_copy(encoded_input)
        properties = (
            (100, 0),  # DmtxPropScheme = ASCII
            (101, -2),  # DmtxPropSizeRequest = square auto
            (102, module_pixels * quiet_zone_modules),  # margin
            (103, module_pixels),  # module size
            (104, 29),  # DmtxPropFnc1 = ASCII GS
        )
        for prop, value in properties:
            if library.dmtxEncodeSetProp(encoder, prop, value) == 0:
                raise PrintingContractError("libdmtx rejected renderer property")
        if library.dmtxEncodeDataMatrix(encoder, len(encoded_input), source) == 0:
            raise PrintingContractError("libdmtx failed to encode GS1 DataMatrix")
        image = encoder.contents.image
        if not image:
            raise PrintingContractError("libdmtx returned no raster")
        raw = image.contents
        if raw.bitsPerPixel != 24 or raw.width <= 0 or raw.height <= 0:
            raise PrintingContractError("libdmtx returned unsupported raster format")
        byte_count = raw.width * raw.height * raw.bitsPerPixel // 8
        pixels = ctypes.string_at(raw.pxl, byte_count)
        return RasterImage(raw.width, raw.height, raw.bitsPerPixel, pixels)
    finally:
        library.dmtxEncodeDestroy(byref(encoder))


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
    if any(byte > 0x7F for byte in full_km):
        raise PrintingSecurityError("FULL KM renderer accepts exact ASCII/control bytes only")
    if type(quiet_zone_modules) is not int or not MIN_QUIET_ZONE_MODULES <= quiet_zone_modules <= MAX_QUIET_ZONE_MODULES:
        raise PrintingContractError("quiet zone is outside standards-compatible bound")
    scale, effective = _scale_for_module(float(module_size_mm), dpi)
    raster = _encode_gs1_raw_libdmtx(
        full_km,
        module_pixels=scale,
        quiet_zone_modules=quiet_zone_modules,
    )
    return RenderedDataMatrix(
        image=raster,
        svg=_svg_from_rgb(raster),
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



@dataclass(frozen=True, slots=True)
class PhysicalLabelRaster:
    image: RasterImage
    payload_sha256: str
    layout_sha256: str
    dpi: int
    renderer_version: str
    datamatrix_bounds_px: tuple[int, int, int, int]
    module_pixels: int
    effective_module_mm: float


def libdmtx_version() -> str:
    library = _load_libdmtx()
    raw = library.dmtxVersion()
    if not raw:
        raise PrintingContractError("libdmtx version unavailable")
    return raw.decode("ascii", errors="strict")


def _font_for_physical_raster(family: str, size_px: int):
    try:
        from PIL import ImageFont
    except Exception as exc:
        raise PrintingContractError("Pillow runtime is unavailable") from exc
    candidates = {
        "Arial": ("arial.ttf", "Arial.ttf"),
        "DejaVu Sans": ("DejaVuSans.ttf",),
        "Inter": ("Inter.ttf", "Inter-Regular.ttf"),
    }.get(family, ())
    for name in candidates:
        try:
            return ImageFont.truetype(name, size_px)
        except OSError:
            continue
    raise PrintingContractError("approved template font is unavailable on this runtime")


def _element_text(item: Mapping[str, Any], field_values: Mapping[str, str]) -> str:
    kind = item["type"]
    if kind == "STATIC_TEXT":
        return str(item["text"])
    if kind in {"HUMAN_READABLE_KI", "GTIN", "ARTICLE", "SKU", "PRODUCT_NAME"}:
        value = field_values.get(kind)
        if value is None:
            raise PrintingContractError(f"physical render field unavailable: {kind}")
        return str(value)
    raise PrintingContractError("element is not text-capable")


def render_physical_label_raster(
    full_km: bytes,
    *,
    layout: Mapping[str, Any],
    label_width_mm: float,
    label_height_mm: float,
    dpi: int,
    field_values: Mapping[str, str] | None = None,
) -> PhysicalLabelRaster:
    """Build the final device-size RGB raster.

    The DataMatrix is generated by the accepted libdmtx renderer at integer
    device module pixels and pasted 1:1. It is never rescaled after creation.
    Other immutable template elements are rasterized around that exact symbol.
    """

    try:
        from PIL import Image, ImageDraw
    except Exception as exc:
        raise PrintingContractError("Pillow runtime is unavailable") from exc

    normalized, layout_sha = canonical_layout_sha256(
        layout,
        label_width_mm=label_width_mm,
        label_height_mm=label_height_mm,
    )
    if type(dpi) is not int or not 150 <= dpi <= 1200:
        raise PrintingContractError("dpi must be 150..1200")
    if not isinstance(full_km, bytes) or not full_km:
        raise PrintingContractError("FULL KM must be non-empty bytes")

    width_px = round(float(label_width_mm) * dpi / 25.4)
    height_px = round(float(label_height_mm) * dpi / 25.4)
    if width_px <= 0 or height_px <= 0:
        raise PrintingContractError("physical label raster dimensions are invalid")

    canvas = Image.new("RGB", (width_px, height_px), "white")
    draw = ImageDraw.Draw(canvas)
    values = dict(field_values or {})
    dm_bounds: tuple[int, int, int, int] | None = None
    dm_scale = 0
    dm_effective = 0.0

    def px(mm: float) -> int:
        return round(float(mm) * dpi / 25.4)

    for item in normalized["elements"]:
        kind = item["type"]
        x, y = px(item["x"]), px(item["y"])
        w, h = px(item["width"]), px(item["height"])
        if w <= 0 or h <= 0 or x < 0 or y < 0 or x + w > width_px or y + h > height_px:
            raise PrintingContractError("physical layout element exceeds final raster")

        if kind == "DATA_MATRIX_KM":
            rendered = render_gs1_datamatrix(
                full_km,
                module_size_mm=item["module_size_mm"],
                quiet_zone_modules=item["quiet_zone_modules"],
                dpi=dpi,
            )
            if rendered.image.width > w or rendered.image.height > h:
                raise PrintingContractError("DataMatrix plus quiet zone does not fit immutable element")
            symbol = Image.frombytes(
                "RGB",
                (rendered.image.width, rendered.image.height),
                rendered.image.pixels,
            )
            # No resize. Exact device pixels from libdmtx go directly to final raster.
            canvas.paste(symbol, (x, y))
            dm_bounds = (x, y, x + rendered.image.width, y + rendered.image.height)
            dm_scale = rendered.scale_pixels
            dm_effective = rendered.module_size_mm_effective
            continue

        if kind in {"HUMAN_READABLE_KI", "GTIN", "ARTICLE", "SKU", "PRODUCT_NAME", "STATIC_TEXT"}:
            value = _element_text(item, values)
            if any(ord(ch) < 0x20 and ch not in "\t" for ch in value):
                raise PrintingSecurityError("physical text value contains forbidden control characters")
            font_px = max(1, round(float(item["font_size_pt"]) * dpi / 72.0))
            font = _font_for_physical_raster(str(item["font_family"]), font_px)
            bbox = font.getbbox(value)
            text_w = max(0, bbox[2] - bbox[0])
            text_h = max(0, bbox[3] - bbox[1])
            layer = Image.new("L", (max(1, text_w + 4), max(1, text_h + 4)), 255)
            layer_draw = ImageDraw.Draw(layer)
            layer_draw.text((2 - bbox[0], 2 - bbox[1]), value, font=font, fill=0)
            rotation = int(item.get("rotation", 0))
            if rotation:
                layer = layer.rotate(-rotation, expand=True, resample=Image.Resampling.NEAREST, fillcolor=255)
            if layer.width > w or layer.height > h:
                raise PrintingContractError("physical text does not fit immutable element")
            alignment = item.get("alignment", "LEFT")
            if alignment == "CENTER":
                tx = x + (w - layer.width) // 2
            elif alignment == "RIGHT":
                tx = x + w - layer.width
            else:
                tx = x
            ty = y
            canvas.paste(Image.merge("RGB", (layer, layer, layer)), (tx, ty))
            continue

        stroke = max(1, px(float(item.get("stroke_width_mm", 0.2))))
        if kind == "LINE":
            draw.line((x, y, x + w - 1, y + h - 1), fill="black", width=stroke)
        elif kind == "RECTANGLE":
            draw.rectangle((x, y, x + w - 1, y + h - 1), outline="black", width=stroke)
        else:
            raise PrintingContractError("unsupported physical layout element")

    if dm_bounds is None:
        raise PrintingContractError("physical label requires exactly one DataMatrix")
    raw = canvas.tobytes()
    return PhysicalLabelRaster(
        image=RasterImage(width_px, height_px, 24, raw),
        payload_sha256=hashlib.sha256(full_km).hexdigest(),
        layout_sha256=layout_sha,
        dpi=dpi,
        renderer_version=RENDERER_VERSION,
        datamatrix_bounds_px=dm_bounds,
        module_pixels=dm_scale,
        effective_module_mm=dm_effective,
    )


def independently_decode_gs1_datamatrix(raster: RasterImage) -> tuple[bytes, str]:
    """Decode using zxing-cpp, independent from the libdmtx renderer."""
    if raster.bpp != 24 or len(raster.pixels) != raster.width * raster.height * 3:
        raise PrintingContractError("invalid physical raster")
    try:
        import numpy as np
        import zxingcpp
    except Exception as exc:
        raise PrintingContractError("independent DataMatrix decoder runtime is unavailable") from exc
    image = np.frombuffer(raster.pixels, dtype=np.uint8).reshape((raster.height, raster.width, 3))
    result = zxingcpp.read_barcode(
        image,
        formats=zxingcpp.BarcodeFormat.DataMatrix,
        try_rotate=False,
        try_downscale=False,
        try_invert=False,
        text_mode=zxingcpp.TextMode.Plain,
    )
    if result is None or not result.valid:
        raise PrintingContractError("independent DataMatrix decode failed")
    symbology = str(result.symbology_identifier or "")
    if symbology != "]d2":
        raise PrintingSecurityError("decoded DataMatrix is not GS1 DataMatrix")
    return bytes(result.bytes), getattr(zxingcpp, "__version__", "zxing-cpp-unknown")


def render_decode_verify_physical_label(
    full_km: bytes,
    *,
    layout: Mapping[str, Any],
    label_width_mm: float,
    label_height_mm: float,
    dpi: int,
    field_values: Mapping[str, str] | None = None,
) -> tuple[PhysicalLabelRaster, str]:
    raster = render_physical_label_raster(
        full_km,
        layout=layout,
        label_width_mm=label_width_mm,
        label_height_mm=label_height_mm,
        dpi=dpi,
        field_values=field_values,
    )
    decoded, decoder_version = independently_decode_gs1_datamatrix(raster.image)
    if decoded != full_km:
        raise PrintingSecurityError("independent DataMatrix decode does not equal exact FULL KM bytes")
    return raster, decoder_version
