"""Synthetic fixture builders shared by the test suite (no binary blobs are committed).

Builders cover Info.plist (XML or binary), fake Mach-O images (thin 32/64-bit in either byte order,
FAT and FAT64) with or without an embedded signature SuperBlob (CodeDirectory with ad-hoc flag and
optional team id, XML entitlements in slot 5, DER entitlements in slot 7, CMS wrapper in slot
0x10000), standard and CgBI PNGs, app extensions, lproj folders and whole IPAs. ``write_raw_zip``
writes archives byte by byte so tests can plant malformed or hostile entries that ``zipfile``
refuses to produce.
"""

from __future__ import annotations

import atexit
import dataclasses
import os
import plistlib
import shutil
import struct
import tempfile
import zipfile
import zlib
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# -- constants ------------------------------------------------------------------------------------

CPU_ARM = 12
CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007
SUB_ARM64_ALL = 0
SUB_ARM64E = 2
SUB_ARMV7 = 9

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_DSYM = 0xA
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSSLOT_CODEDIRECTORY = 0
CSSLOT_REQUIREMENTS = 2
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_SIGNATURESLOT = 0x10000
CS_ADHOC = 0x2
CS_LINKER_SIGNED = 0x20000

PNG_SIG = b"\x89PNG\r\n\x1a\n"
APP = "Payload/Demo.app"
BUNDLE_ID = "io.example.demo"

# -- property lists -------------------------------------------------------------------------------


def info_plist(bundle_id: str = BUNDLE_ID, *, executable: str = "Demo", name: Optional[str] = "Demo",
               display_name: Optional[str] = None, version: Optional[str] = "1.2.3", build: Optional[str] = "7",
               min_os: Optional[str] = "15.0", package_type: str = "APPL", extra: Optional[Dict[str, Any]] = None,
               omit: Iterable[str] = (), binary: bool = False) -> bytes:
    """An Info.plist (XML unless ``binary``). ``None`` values and keys in ``omit`` are left out."""
    info: Dict[str, Any] = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleExecutable": executable,
        "CFBundleName": name,
        "CFBundleDisplayName": display_name,
        "CFBundleShortVersionString": version,
        "CFBundleVersion": build,
        "MinimumOSVersion": min_os,
        "CFBundlePackageType": package_type,
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
    }
    info.update(extra or {})
    info = {k: v for k, v in info.items() if v is not None and k not in set(omit)}
    return plistlib.dumps(info, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)


def xml_entitlements(ents: Dict[str, Any]) -> bytes:
    return plistlib.dumps(ents, fmt=plistlib.FMT_XML)


# -- DER entitlements (CoreEntitlements encoding) -------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def der_value(value: Any, *, dict_tag: int = 0xB0) -> bytes:
    if isinstance(value, bool):
        return der_tlv(0x01, b"\xff" if value else b"\x00")
    if isinstance(value, int):
        length = max(1, (value + (value < 0)).bit_length() // 8 + 1)
        return der_tlv(0x02, value.to_bytes(length, "big", signed=True))
    if isinstance(value, str):
        return der_tlv(0x0C, value.encode("utf-8"))
    if isinstance(value, bytes):
        return der_tlv(0x04, value)
    if isinstance(value, (list, tuple)):
        return der_tlv(0x30, b"".join(der_value(v, dict_tag=dict_tag) for v in value))
    if isinstance(value, dict):
        entries = [der_tlv(0x30, der_value(k, dict_tag=dict_tag) + der_value(v, dict_tag=dict_tag))
                   for k, v in sorted(value.items())]
        return der_tlv(dict_tag, b"".join(entries))
    raise TypeError(type(value))


def der_entitlements(ents: Dict[str, Any], *, ldid: bool = False) -> bytes:
    """Apple's ``[APPLICATION 16] {INTEGER 1, dict}`` form, or ldid's bare SET form."""
    if ldid:
        return der_value(ents, dict_tag=0x31)
    return der_tlv(0x70, der_tlv(0x02, b"\x01") + der_value(ents))


# -- code signature -------------------------------------------------------------------------------

def blob(magic: int, payload: bytes) -> bytes:
    return struct.pack(">II", magic, 8 + len(payload)) + payload


def code_directory(identifier: str = BUNDLE_ID, *, team_id: Optional[str] = None, adhoc: bool = True,
                   linker_signed: bool = False, version: int = 0x20400, flags: Optional[int] = None) -> bytes:
    """A CS_CodeDirectory without hash slots (the reader only needs flags, identifier and team id)."""
    if flags is None:
        flags = (CS_ADHOC if adhoc else 0) | (CS_LINKER_SIGNED if linker_signed else 0)
    header_size = (44 + (4 if version >= 0x20100 else 0) + (4 if version >= 0x20200 else 0)
                   + (12 if version >= 0x20300 else 0) + (24 if version >= 0x20400 else 0))
    ident = identifier.encode("utf-8") + b"\x00"
    team = (team_id.encode("utf-8") + b"\x00") if team_id is not None else b""
    ident_off = header_size
    team_off = header_size + len(ident) if team_id is not None else 0
    total = header_size + len(ident) + len(team)
    head = struct.pack(">IIIIIIIIIBBBBI", CSMAGIC_CODEDIRECTORY, total, version, flags, total, ident_off,
                       0, 0, 0, 32, 2, 0, 12, 0)  # hashOffset, ident, nSpecial, nCode, codeLimit, hash info
    if version >= 0x20100:
        head += struct.pack(">I", 0)  # scatterOffset
    if version >= 0x20200:
        head += struct.pack(">I", team_off)
    if version >= 0x20300:
        head += struct.pack(">IQ", 0, 0)
    if version >= 0x20400:
        head += struct.pack(">QQQ", 0, 0, 0)
    assert len(head) == header_size, (len(head), header_size)
    return head + ident + team


def super_blob(slots: Sequence[Tuple[int, bytes]]) -> bytes:
    """An embedded-signature SuperBlob holding ``(slot type, blob bytes)`` entries in order."""
    index = b""
    body = b""
    offset = 12 + 8 * len(slots)
    for stype, data in slots:
        index += struct.pack(">II", stype, offset + len(body))
        body += data
    return struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, 12 + len(index) + len(body), len(slots)) + index + body


def code_signature(*, entitlements: Union[None, Dict[str, Any], bytes] = None,
                   der: Union[None, Dict[str, Any], bytes] = None, cms: Optional[bytes] = b"",
                   team_id: Optional[str] = None, adhoc: bool = True, linker_signed: bool = False,
                   identifier: str = BUNDLE_ID, cd_version: int = 0x20400, alternate_cd: bool = False,
                   requirements: bool = True) -> bytes:
    """A SuperBlob like codesign writes: CodeDirectory, requirements, entitlements, CMS wrapper.

    ``entitlements``/``der`` take a dict (encoded here) or raw payload bytes. ``cms=None`` omits the
    CMS slot; ``b""`` is the empty wrapper of an ad-hoc signature; other bytes make it "signed".
    """
    slots: List[Tuple[int, bytes]] = [(CSSLOT_CODEDIRECTORY, code_directory(
        identifier, team_id=team_id, adhoc=adhoc, linker_signed=linker_signed, version=cd_version))]
    if requirements:
        slots.append((CSSLOT_REQUIREMENTS, struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)))
    if entitlements is not None:
        payload = entitlements if isinstance(entitlements, bytes) else xml_entitlements(entitlements)
        slots.append((CSSLOT_ENTITLEMENTS, blob(CSMAGIC_EMBEDDED_ENTITLEMENTS, payload)))
    if der is not None:
        payload = der if isinstance(der, bytes) else der_entitlements(der)
        slots.append((CSSLOT_DER_ENTITLEMENTS, blob(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, payload)))
    if alternate_cd:
        slots.append((CSSLOT_ALTERNATE_CODEDIRECTORIES, code_directory(
            identifier, team_id=team_id, adhoc=adhoc, linker_signed=linker_signed, version=cd_version)))
    if cms is not None:
        slots.append((CSSLOT_SIGNATURESLOT, blob(CSMAGIC_BLOBWRAPPER, cms)))
    return super_blob(slots)


# -- Mach-O ---------------------------------------------------------------------------------------

def macho(*, cputype: int = CPU_ARM64, cpusubtype: int = SUB_ARM64_ALL, bits: int = 64, big_endian: bool = False,
          filetype: int = MH_EXECUTE, signature: Optional[bytes] = None, cryptid: Optional[int] = None,
          body: bytes = b"\x00" * 64, uuid: bool = True, signature_pad: int = 16) -> bytes:
    """A thin Mach-O image: header, a few load commands, ``body``, then the signature (if any)."""
    e = ">" if big_endian else "<"
    magic = MH_MAGIC_64 if bits == 64 else MH_MAGIC
    header_size = 32 if bits == 64 else 28
    cmds: List[Tuple[int, bytes]] = []
    if uuid:
        cmds.append((LC_UUID, b"\x11" * 16))
    if cryptid is not None:
        if bits == 64:
            cmds.append((LC_ENCRYPTION_INFO_64, struct.pack(e + "IIII", 0x4000, 0x1000, cryptid, 0)))
        else:
            cmds.append((LC_ENCRYPTION_INFO, struct.pack(e + "III", 0x4000, 0x1000, cryptid)))
    if signature is not None:
        cmds.append((LC_CODE_SIGNATURE, b"\x00" * 8))  # patched below
    sizeofcmds = sum(8 + len(payload) for _, payload in cmds)
    data_start = header_size + sizeofcmds + len(body)
    data_start += -data_start % 16
    out = bytearray()
    if bits == 64:
        out += struct.pack(e + "IiiIIIII", magic, cputype, cpusubtype, filetype, len(cmds), sizeofcmds, 0, 0)
    else:
        out += struct.pack(e + "IiiIIII", magic, cputype, cpusubtype, filetype, len(cmds), sizeofcmds, 0)
    for cmd, payload in cmds:
        if cmd == LC_CODE_SIGNATURE:
            assert signature is not None
            padded = len(signature) + (-len(signature) % signature_pad)
            payload = struct.pack(e + "II", data_start, padded)
        out += struct.pack(e + "II", cmd, 8 + len(payload)) + payload
    out += body
    out += b"\x00" * (data_start - len(out))
    if signature is not None:
        out += signature + b"\x00" * (-len(signature) % signature_pad)
    return bytes(out)


def _slice_arch(image: bytes) -> Tuple[int, int]:
    le = struct.unpack_from("<I", image, 0)[0]
    e = "<" if le in (MH_MAGIC, MH_MAGIC_64) else ">"
    return struct.unpack_from(e + "ii", image, 4)


def fat(slices: Sequence[bytes], *, fat64: bool = False, align: int = 12) -> bytes:
    """A FAT (or FAT64) container; slice offsets are aligned to ``2**align``."""
    count = len(slices)
    step = 32 if fat64 else 20
    offset = 8 + count * step
    table = b""
    placed: List[Tuple[int, bytes]] = []
    for image in slices:
        offset += -offset % (1 << align)
        cputype, cpusub = _slice_arch(image)
        if fat64:
            table += struct.pack(">iiQQII", cputype, cpusub, offset, len(image), align, 0)
        else:
            table += struct.pack(">iiIII", cputype, cpusub, offset, len(image), align)
        placed.append((offset, image))
        offset += len(image)
    out = bytearray(struct.pack(">II", FAT_MAGIC_64 if fat64 else FAT_MAGIC, count) + table)
    for off, image in placed:
        out += b"\x00" * (off - len(out))
        out += image
    return bytes(out)


# -- PNG ------------------------------------------------------------------------------------------

def png_chunk(ctype: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def filter_rows(pixels: bytes, width: int, height: int, bpp: int, filters: Sequence[int] = (0,)) -> bytes:
    """PNG-filter rows of ``pixels`` (filter type per row cycles through ``filters``)."""
    stride = width * bpp
    out = bytearray()
    prev = bytes(stride)
    for y in range(height):
        row = pixels[y * stride:(y + 1) * stride]
        ft = filters[y % len(filters)]
        enc = bytearray(stride)
        for i in range(stride):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            upleft = prev[i - bpp] if i >= bpp else 0
            if ft == 0:
                pred = 0
            elif ft == 1:
                pred = left
            elif ft == 2:
                pred = up
            elif ft == 3:
                pred = (left + up) >> 1
            else:
                pred = _paeth(left, up, upleft)
            enc[i] = (row[i] - pred) & 0xFF
        out.append(ft)
        out += enc
        prev = row
    return bytes(out)


_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


def interlace_rows(pixels: bytes, width: int, height: int, bpp: int, filters: Sequence[int] = (0,)) -> bytes:
    out = b""
    for x0, y0, dx, dy in _ADAM7:
        pw, ph = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
        if pw <= 0 or ph <= 0:
            continue
        sub = bytearray()
        for sy in range(ph):
            for sx in range(pw):
                i = ((y0 + sy * dy) * width + x0 + sx * dx) * bpp
                sub += pixels[i:i + bpp]
        out += filter_rows(bytes(sub), pw, ph, bpp, filters)
    return out


def gradient(width: int, height: int, channels: int = 4, *, alphas: Sequence[int] = (255,)) -> bytes:
    """Deterministic test pixels (straight alpha) with varied colours; alpha cycles through ``alphas``."""
    out = bytearray()
    for y in range(height):
        for x in range(width):
            px = [(x * 37 + y * 11) % 256, (x * 7 + y * 53 + 90) % 256, (x * y * 3 + 200) % 256]
            if channels == 4:
                px.append(alphas[(x + y * width) % len(alphas)])
            out += bytes(px[:channels])
    return bytes(out)


def png(width: int, height: int, pixels: Optional[bytes] = None, *, color_type: int = 6, bit_depth: int = 8,
        filters: Sequence[int] = (0,), interlace: bool = False, ancillary: Sequence[Tuple[bytes, bytes]] = (),
        trailing: Sequence[Tuple[bytes, bytes]] = (), raw_rows: Optional[bytes] = None,
        idat_parts: int = 1) -> bytes:
    """A standard PNG. ``raw_rows`` (already filtered scanlines) overrides ``pixels``."""
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    if raw_rows is None:
        bpp = channels * bit_depth // 8
        if pixels is None:
            pixels = gradient(width, height, channels) if bit_depth == 8 else bytes(width * height * bpp)
        rows = (interlace_rows if interlace else filter_rows)(pixels, width, height, max(bpp, 1), filters)
    else:
        rows = raw_rows
    data = zlib.compress(rows, 9)
    ihdr = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 1 if interlace else 0)
    step = -(-len(data) // idat_parts)
    idats = b"".join(png_chunk(b"IDAT", data[i:i + step]) for i in range(0, len(data), step))
    return (PNG_SIG + png_chunk(b"IHDR", ihdr) + b"".join(png_chunk(t, b) for t, b in ancillary)
            + idats + b"".join(png_chunk(t, b) for t, b in trailing) + png_chunk(b"IEND", b""))


def premultiply(pixels: bytes) -> bytes:
    """Straight RGBA -> premultiplied RGBA with Apple's rounding, round(c * a / 255)."""
    out = bytearray(pixels)
    for i in range(0, len(out), 4):
        a = out[i + 3]
        for j in range(3):
            out[i + j] = (out[i + j] * a * 2 + 255) // 510
    return bytes(out)


def swap_rb(pixels: bytes, bpp: int) -> bytes:
    out = bytearray(pixels)
    out[0::bpp], out[2::bpp] = out[2::bpp], out[0::bpp]
    return bytes(out)


def cgbi_png(width: int, height: int, pixels: Optional[bytes] = None, *, color_type: int = 6,
             filters: Sequence[int] = (0,), interlace: bool = False, flags: bytes = b"\x50\x00\x20\x02",
             zlib_wrapped: bool = False, idot: bool = True, ancillary: Sequence[Tuple[bytes, bytes]] = ()) -> bytes:
    """An Apple CgBI PNG from straight-alpha RGB(A) ``pixels`` (premultiplied, BGR(A), raw deflate)."""
    bpp = 4 if color_type == 6 else 3
    if pixels is None:
        pixels = gradient(width, height, bpp)
    stored = premultiply(pixels) if bpp == 4 else pixels
    stored = swap_rb(stored, bpp)
    rows = (interlace_rows if interlace else filter_rows)(stored, width, height, bpp, filters)
    if zlib_wrapped:
        data = zlib.compress(rows, 9)
    else:
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        data = comp.compress(rows) + comp.flush()
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 1 if interlace else 0)
    out = PNG_SIG + png_chunk(b"CgBI", flags) + png_chunk(b"IHDR", ihdr)
    out += b"".join(png_chunk(t, b) for t, b in ancillary)
    if idot:
        out += png_chunk(b"iDOT", b"\x00" * 28)
    return out + png_chunk(b"IDAT", data) + png_chunk(b"IEND", b"")


def decode_png(data: bytes) -> Tuple[int, int, int, bytes]:
    """Independent decoder for 8-bit non-interlaced RGB/RGBA PNGs: (width, height, channels, pixels)."""
    assert data[:8] == PNG_SIG
    off = 8
    ihdr = None
    idat = b""
    while off < len(data):
        length, ctype = struct.unpack_from(">I4s", data, off)
        body = data[off + 8:off + 8 + length]
        crc = struct.unpack_from(">I", data, off + 8 + length)[0]
        assert crc == zlib.crc32(ctype + body) & 0xFFFFFFFF, "bad CRC"
        if ctype == b"IHDR":
            ihdr = body
        elif ctype == b"IDAT":
            idat += body
        off += 12 + length
    assert ihdr is not None
    w, h, bd, ct, _, _, il = struct.unpack(">IIBBBBB", ihdr)
    assert bd == 8 and ct in (2, 6) and il == 0, (bd, ct, il)
    bpp = 4 if ct == 6 else 3
    raw = zlib.decompress(idat)
    stride = w * bpp
    out = bytearray()
    prev = bytearray(stride)
    for y in range(h):
        ft = raw[y * (stride + 1)]
        row = bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            upleft = prev[i - bpp] if i >= bpp else 0
            pred = (0, left, up, (left + up) >> 1, _paeth(left, up, upleft))[ft]
            row[i] = (row[i] + pred) & 0xFF
        out += row
        prev = row
    return w, h, bpp, bytes(out)


def chunk_types(data: bytes) -> List[bytes]:
    off = 8
    out = []
    while off < len(data):
        length, ctype = struct.unpack_from(">I4s", data, off)
        out.append(ctype)
        off += 12 + length
    return out


# -- bundles --------------------------------------------------------------------------------------

Entry = Union[bytes, str, Tuple[str, str]]


def app_entries(*, app: str = APP, bundle_id: str = BUNDLE_ID, executable: str = "Demo",
                exe: Optional[bytes] = None, plist: Optional[bytes] = None, **plist_kw: Any) -> Dict[str, Entry]:
    """Entries of a minimal unsigned app: Info.plist plus an arm64 executable without a signature."""
    return {
        app + "/Info.plist": plist if plist is not None else info_plist(bundle_id, executable=executable, **plist_kw),
        app + "/" + executable: exe if exe is not None else macho(),
    }


def add_appex(entries: Dict[str, Entry], name: str, *, kind: str = "PlugIns", app: str = APP,
              bundle_id: Optional[str] = None, exe: Optional[bytes] = None, extra: Optional[Dict[str, Any]] = None,
              plist: Optional[bytes] = None) -> str:
    """Add ``<app>/<kind>/<name>.appex`` with its own Info.plist and executable; returns the bundle path."""
    bundle = "%s/%s/%s.appex" % (app, kind, name)
    entries[bundle + "/Info.plist"] = plist if plist is not None else info_plist(
        bundle_id or "%s.%s" % (BUNDLE_ID, name.lower()), executable=name, name=name,
        package_type="XPC!", extra=extra)
    entries[bundle + "/" + name] = exe if exe is not None else macho()
    return bundle


def add_lproj(entries: Dict[str, Entry], *langs: str, app: str = APP) -> None:
    for lang in langs:
        entries["%s/%s.lproj/InfoPlist.strings" % (app, lang)] = plistlib.dumps({"CFBundleName": "Demo"})


_TMP: List[str] = []


def _scratch_dir() -> str:
    if not _TMP:
        _TMP.append(tempfile.mkdtemp(prefix="alt-fixtures-"))
        atexit.register(shutil.rmtree, _TMP[0], True)
    return _TMP[0]


def build_ipa(entries: Dict[str, Entry], path: Optional[str] = None, *, compression: int = zipfile.ZIP_DEFLATED,
              dirs: bool = False, exec_mode: Iterable[str] = ()) -> str:
    """Write an IPA from ``{path: bytes | str | ("symlink", target)}``; returns the archive path.

    Names ending in ``/`` become directory entries. ``dirs`` adds explicit entries for every parent
    directory. Mach-O members (and names in ``exec_mode``) get mode 0755.
    """
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".ipa", dir=_scratch_dir())
        os.close(fd)
    names = list(entries)
    if dirs:
        parents = set()
        for name in names:
            parts = name.rstrip("/").split("/")
            for i in range(1, len(parts)):
                parents.add("/".join(parts[:i]) + "/")
        names = sorted(parents - set(names)) + names
    executable = set(exec_mode)
    with zipfile.ZipFile(path, "w", compression) as zf:
        for name in names:
            value = entries.get(name, b"")
            zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.compress_type = compression
            if name.endswith("/"):
                zi.external_attr = (0o40755 << 16) | 0x10
                zi.compress_type = zipfile.ZIP_STORED
                zf.writestr(zi, b"")
                continue
            if isinstance(value, tuple):
                kind, target = value
                assert kind == "symlink", kind
                zi.external_attr = 0o120777 << 16
                zi.compress_type = zipfile.ZIP_STORED
                zf.writestr(zi, target.encode("utf-8"))
                continue
            data = value.encode("utf-8") if isinstance(value, str) else value
            is_exec = name in executable or data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
            zi.external_attr = (0o100755 if is_exec else 0o100644) << 16
            zf.writestr(zi, data)
    return path


def minimal_ipa(path: Optional[str] = None, **kw: Any) -> str:
    """A minimal unsigned IPA (see :func:`app_entries` for the keyword arguments)."""
    return build_ipa(app_entries(**kw), path)


# -- raw zip writer -------------------------------------------------------------------------------

@dataclasses.dataclass
class RawEntry:
    """One member for :func:`write_raw_zip`; every header field can be forced."""

    name: Union[str, bytes]
    data: bytes = b""
    method: int = 0  # 0 stored, 8 deflated, anything else is written as-is (stored bytes)
    flags: int = 0
    create_system: int = 3
    external_attr: int = 0o100644 << 16
    extra: bytes = b""
    file_size: Optional[int] = None  # declared sizes (default: real)
    compress_size: Optional[int] = None
    crc: Optional[int] = None
    local: bool = True  # False: no local header; the central record points at ``offset_of``
    offset_of: Optional[int] = None  # index of an earlier entry whose local header is reused


def write_raw_zip(path: str, entries: Sequence[RawEntry], *, comment: bytes = b"") -> str:
    """A zip written byte by byte (no zip64): lets tests plant entries that zipfile will not write."""
    out = bytearray()
    central = bytearray()
    offsets: List[int] = []
    for entry in entries:
        name = entry.name.encode("utf-8") if isinstance(entry.name, str) else entry.name
        if entry.method == 8:
            comp = zlib.compressobj(9, zlib.DEFLATED, -15)
            stored = comp.compress(entry.data) + comp.flush()
        else:
            stored = entry.data
        crc = entry.crc if entry.crc is not None else zlib.crc32(entry.data) & 0xFFFFFFFF
        usize = entry.file_size if entry.file_size is not None else len(entry.data)
        csize = entry.compress_size if entry.compress_size is not None else len(stored)
        if entry.local:
            offset = len(out)
            out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, entry.flags, entry.method, 0, 0x21, crc,
                               csize, usize, len(name), len(entry.extra)) + name + entry.extra + stored
        else:
            assert entry.offset_of is not None
            offset = offsets[entry.offset_of]
        offsets.append(offset)
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (entry.create_system << 8) | 20, 20, entry.flags,
                               entry.method, 0, 0x21, crc, csize, usize, len(name), len(entry.extra), 0, 0, 0,
                               entry.external_attr, offset) + name + entry.extra
    start = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), start,
                       len(comment)) + comment
    with open(path, "wb") as fh:
        fh.write(out)
    return path


def unicode_path_extra(name: str, header_name: bytes) -> bytes:
    """An Info-ZIP unicode path extra field (0x7075) claiming ``name``."""
    body = b"\x01" + struct.pack("<I", zlib.crc32(header_name) & 0xFFFFFFFF) + name.encode("utf-8")
    return struct.pack("<HH", 0x7075, len(body)) + body


# -- archives that zipfile reads with exceptions other than BadZipFile ----------------------------

def set_extract_version(path: str, version: int = 64, index: int = 0) -> str:
    """Set "version needed to extract" of central directory record ``index`` (zipfile reads up to 63)."""
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    pos = -1
    for _ in range(index + 1):
        pos = data.index(b"PK\x01\x02", pos + 1)
    struct.pack_into("<H", data, pos + 6, version)
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return path


def break_local_name(path: str, name: str) -> str:
    """Make the local header name of member ``name`` invalid UTF-8; the central directory keeps the
    valid name with the UTF-8 flag, so ``zipfile`` only fails when the member is opened."""
    raw = name.encode("utf-8")
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    pos = 0
    while True:
        pos = data.index(b"PK\x03\x04", pos)
        flags, = struct.unpack_from("<H", data, pos + 6)
        size, = struct.unpack_from("<H", data, pos + 26)
        if data[pos + 30:pos + 30 + size] == raw:
            assert flags & 0x800, "the member must carry the UTF-8 flag"
            first = next(i for i, b in enumerate(raw) if b >= 0x80)
            data[pos + 30 + first] = 0xFF
            break
        pos += 4
    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return path
