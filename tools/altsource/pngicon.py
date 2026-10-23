"""PNG helpers for app icons: header probing and conversion of Apple CgBI PNGs to standard PNGs.

CgBI ("iPhone-optimized") PNGs put a ``CgBI`` chunk before ``IHDR``, store IDAT as raw deflate (no
zlib header or Adler-32) and keep 8-bit RGB/RGBA pixels as BGR(A) with premultiplied alpha.
:func:`to_png` turns either flavour into a clean standard PNG: pixels are restored to RGB(A) with
straight alpha, the image is re-encoded with filter 0 and no interlacing, and only colour and
geometry chunks survive (text, EXIF, time stamps and Apple's ``iDOT`` are dropped).

All decoding is bounded: dimensions are capped and every inflate is limited to the exact number of
bytes the header implies.
"""

from __future__ import annotations

import dataclasses
import struct
import zlib
from typing import Iterator, List, Tuple

PNG_SIG = b"\x89PNG\r\n\x1a\n"
MAX_PIXELS = 2048 * 2048  # app icons are at most 1024 px; CgBI conversion runs per pixel
# colour/geometry information that stays valid after conversion
_KEEP = (b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"pHYs")
_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
# _UNPRE[a][c] = round(c * 255 / a) clamped to 255; alpha 0 maps every channel to 0
_UNPRE = [bytes(256)] + [bytes(min(255, (c * 255 + a // 2) // a) for c in range(256)) for a in range(1, 256)]


class PNGError(ValueError):
    """The data is not a usable PNG."""


@dataclasses.dataclass(frozen=True)
class PngHeader:
    width: int
    height: int
    bit_depth: int
    color_type: int
    interlace: int
    cgbi: bool


def is_png(data: bytes) -> bool:
    return data[:8] == PNG_SIG


def is_cgbi(data: bytes) -> bool:
    """A PNG whose first chunk is ``CgBI``."""
    return data[:8] == PNG_SIG and data[12:16] == b"CgBI"


def iter_chunks(data: bytes) -> Iterator[Tuple[bytes, bytes]]:
    """Yield ``(type, body)`` up to and including IEND (CRCs are not checked)."""
    if data[:8] != PNG_SIG:
        raise PNGError("not a PNG")
    off, n = 8, len(data)
    while True:
        if off + 12 > n:
            raise PNGError("truncated PNG (no IEND)")
        length, ctype = struct.unpack_from(">I4s", data, off)
        end = off + 12 + length
        if length > 0x7FFFFFFF or end > n:
            raise PNGError("truncated chunk")
        yield ctype, data[off + 8:off + 8 + length]
        off = end
        if ctype == b"IEND":
            return


def read_header(data: bytes) -> PngHeader:
    """IHDR facts from the first bytes of a file (the second chunk for CgBI, else the first)."""
    if data[:8] != PNG_SIG:
        raise PNGError("not a PNG")
    off = 8
    cgbi = False
    for _ in range(2):
        if off + 8 > len(data):
            raise PNGError("truncated header")
        length, ctype = struct.unpack_from(">I4s", data, off)
        if ctype == b"CgBI" and not cgbi and off == 8:
            cgbi = True
            off += 12 + length
            continue
        if ctype != b"IHDR" or length != 13 or off + 8 + 13 > len(data):
            raise PNGError("IHDR is not the first chunk")
        return _header(data[off + 8:off + 21], cgbi)
    raise PNGError("IHDR missing")


def _header(ihdr: bytes, cgbi: bool) -> PngHeader:
    w, h, bd, ct, cm, fm, il = struct.unpack(">IIBBBBB", ihdr)
    if ct not in _DEPTHS or bd not in _DEPTHS[ct] or cm != 0 or fm != 0 or il not in (0, 1):
        raise PNGError("unsupported IHDR")
    if not 0 < w <= 0x7FFFFFFF or not 0 < h <= 0x7FFFFFFF:
        raise PNGError("bad dimensions")
    return PngHeader(w, h, bd, ct, il, cgbi)


def _chunk(ctype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)


def _row_bytes(width: int, hdr: PngHeader) -> int:
    return (width * _CHANNELS[hdr.color_type] * hdr.bit_depth + 7) // 8


def _passes(w: int, h: int) -> Iterator[Tuple[int, int, int, int, int, int]]:
    for x0, y0, dx, dy in _ADAM7:
        pw, ph = (w - x0 + dx - 1) // dx, (h - y0 + dy - 1) // dy
        if pw > 0 and ph > 0:
            yield x0, y0, dx, dy, pw, ph


def _expected_size(hdr: PngHeader) -> int:
    if hdr.interlace == 0:
        return hdr.height * (1 + _row_bytes(hdr.width, hdr))
    return sum(ph * (1 + _row_bytes(pw, hdr)) for _, _, _, _, pw, ph in _passes(hdr.width, hdr.height))


def _check_filters(raw: bytes, hdr: PngHeader) -> None:
    """Every scanline must start with a filter type 0-4."""
    if hdr.interlace == 0:
        blocks = [(hdr.width, hdr.height)]
    else:
        blocks = [(pw, ph) for _, _, _, _, pw, ph in _passes(hdr.width, hdr.height)]
    pos = 0
    for width, rows in blocks:
        step = 1 + _row_bytes(width, hdr)
        for _ in range(rows):
            if raw[pos] > 4:
                raise PNGError("bad filter type")
            pos += step


def _inflate(comp: bytes, expected: int, raw: bool) -> bytes:
    d = zlib.decompressobj(-15 if raw else 15)
    out = d.decompress(comp, expected + 1)  # max_length bounds memory
    if len(out) > expected:
        raise PNGError("image data inflates past the expected size")
    if len(out) != expected:
        raise PNGError("image data has the wrong size")
    return out


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _unfilter(buf: bytes, stride: int, rows: int, bpp: int) -> bytearray:
    """Undo per-row filters; returns ``rows * stride`` bytes without filter bytes."""
    out = bytearray(rows * stride)
    prev = bytearray(stride)
    pos = 0
    for y in range(rows):
        ft = buf[pos]
        row = bytearray(buf[pos + 1:pos + 1 + stride])
        pos += 1 + stride
        if len(row) != stride:
            raise PNGError("short image data")
        if ft == 1:
            for i in range(bpp, stride):
                row[i] = (row[i] + row[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                row[i] = (row[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                left = row[i - bpp] if i >= bpp else 0
                row[i] = (row[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                if i >= bpp:
                    row[i] = (row[i] + _paeth(row[i - bpp], prev[i], prev[i - bpp])) & 0xFF
                else:
                    row[i] = (row[i] + prev[i]) & 0xFF
        elif ft != 0:
            raise PNGError("bad filter type")
        out[y * stride:(y + 1) * stride] = row
        prev = row
    return out


def _collect(data: bytes) -> Tuple[PngHeader, bytes, List[Tuple[bytes, bytes]]]:
    """(header, concatenated IDAT, kept ancillary chunks in order) with chunk-order checks."""
    cgbi = is_cgbi(data)
    hdr = None
    idat: List[bytes] = []
    keep: List[Tuple[bytes, bytes]] = []
    first = True
    idat_done = False
    for ctype, body in iter_chunks(data):
        if first and cgbi:
            first = False
            continue
        if hdr is None:
            if ctype != b"IHDR" or len(body) != 13:
                raise PNGError("IHDR is not the first chunk")
            hdr = _header(body, cgbi)
            continue
        if ctype == b"IHDR":
            raise PNGError("duplicate IHDR")
        if ctype == b"IDAT":
            if idat_done:
                raise PNGError("IDAT chunks are not consecutive")
            idat.append(body)
        else:
            if idat:
                idat_done = True
            if ctype in _KEEP or ctype in (b"PLTE", b"tRNS"):
                keep.append((ctype, body))
    if hdr is None or not idat:
        raise PNGError("missing IHDR or IDAT")
    if hdr.width * hdr.height > MAX_PIXELS:
        raise PNGError("image too large")
    if hdr.color_type == 3 and not any(t == b"PLTE" for t, _ in keep):
        raise PNGError("palette image without PLTE")
    return hdr, b"".join(idat), keep


def _encode(hdr: PngHeader, raw: bytes, keep: List[Tuple[bytes, bytes]]) -> bytes:
    ihdr = struct.pack(">IIBBBBB", hdr.width, hdr.height, hdr.bit_depth, hdr.color_type, 0, 0, hdr.interlace)
    return (PNG_SIG + _chunk(b"IHDR", ihdr) + b"".join(_chunk(t, b) for t, b in keep)
            + _chunk(b"IDAT", zlib.compress(raw, 9)) + _chunk(b"IEND", b""))


def to_png(data: bytes) -> bytes:
    """A standard PNG for ``data`` (CgBI converted, other PNGs re-encoded without metadata chunks)."""
    if is_cgbi(data):
        return cgbi_to_png(data)
    hdr, comp, keep = _collect(data)
    try:
        raw = _inflate(comp, _expected_size(hdr), raw=False)
    except zlib.error:
        raise PNGError("corrupt image data") from None
    _check_filters(raw, hdr)
    # the filtered scanlines are kept as they are; only the container is rebuilt
    return _encode(hdr, raw, keep)


def cgbi_to_png(data: bytes) -> bytes:
    """Convert a CgBI PNG to a standard PNG (un-premultiplied RGB(A), filter 0, not interlaced)."""
    if not is_cgbi(data):
        raise PNGError("not a CgBI PNG")
    hdr, comp, keep = _collect(data)
    expected = _expected_size(hdr)
    raw = None
    for raw_mode in (True, False):  # Apple writes raw deflate; tolerate a zlib wrapper
        try:
            raw = _inflate(comp, expected, raw_mode)
            break
        except (zlib.error, PNGError):
            continue
    if raw is None:
        raise PNGError("cannot inflate image data")
    if hdr.bit_depth != 8 or hdr.color_type not in (2, 6):
        # only 8-bit RGB/RGBA is pixel-swapped; everything else just needs a zlib stream
        _check_filters(raw, hdr)
        return _encode(hdr, raw, keep)
    w, h = hdr.width, hdr.height
    bpp = 4 if hdr.color_type == 6 else 3
    if hdr.interlace == 0:
        px = _unfilter(raw, w * bpp, h, bpp)
    else:
        px = bytearray(w * h * bpp)
        pos = 0
        for x0, y0, dx, dy, pw, ph in _passes(w, h):
            n = ph * (1 + pw * bpp)
            sub = _unfilter(raw[pos:pos + n], pw * bpp, ph, bpp)
            pos += n
            for sy in range(ph):
                for sx in range(pw):
                    s = (sy * pw + sx) * bpp
                    d = ((y0 + sy * dy) * w + x0 + sx * dx) * bpp
                    px[d:d + bpp] = sub[s:s + bpp]
    px[0::bpp], px[2::bpp] = px[2::bpp], px[0::bpp]  # BGR(A) -> RGB(A)
    if bpp == 4:
        for i in range(3, len(px), 4):
            a = px[i]
            if a != 255:
                t = _UNPRE[a]
                px[i - 3] = t[px[i - 3]]
                px[i - 2] = t[px[i - 2]]
                px[i - 1] = t[px[i - 1]]
    stride = w * bpp
    out_raw = b"".join(b"\x00" + px[y * stride:(y + 1) * stride] for y in range(h))
    # a tRNS colour key would be in BGR order and PLTE is meaningless for RGB: keep colour info only
    out_hdr = PngHeader(w, h, 8, hdr.color_type, 0, False)
    return _encode(out_hdr, out_raw, [(t, b) for t, b in keep if t in _KEEP])
