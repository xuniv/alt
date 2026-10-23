"""Mach-O reader for code-signing facts: slices, LC_CODE_SIGNATURE, entitlements, team ids.

Handles thin 32/64-bit images in either byte order and FAT/FAT64 containers. Only the parts needed
by the gate are decoded: the load command list, the encryption command and the embedded signature
SuperBlob (CodeDirectory flags and team id, the XML and DER entitlement blobs, the CMS blob size).

Byte orders: FAT headers and every code-signing structure are big-endian; the Mach-O header and
load commands use the slice's own order. ``buf`` arguments may be ``bytes``, ``bytearray``,
``memoryview`` or ``mmap`` objects; nothing larger than a single blob payload is copied.

Errors raise :class:`MachOError` whose ``rule`` is one of ``macho-invalid``,
``macho-signature-invalid`` or ``macho-entitlements-invalid``.
"""

from __future__ import annotations

import dataclasses
import mmap
import plistlib
import struct
from typing import Any, Dict, Iterator, List, Optional, Tuple

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MAX_FAT_ARCHS = 32  # 0xCAFEBABE is also the Java class magic; there the next field is >= 45

LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8
MH_DSYM = 0xA

CPU_ARCH_ABI64 = 0x01000000
CPU_SUBTYPE_MASK = 0xFF000000

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
CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5
CSSLOT_SIGNATURESLOT = 0x10000

CS_ADHOC = 0x00000002
CS_LINKER_SIGNED = 0x00020000
CS_SUPPORTSTEAMID = 0x20200
_CD_TEAM_OFFSET = 48  # offset of teamOffset inside CS_CodeDirectory (version >= 0x20200)
_CD_MIN_SIZE = 44  # up to and including spare2

MAX_LOAD_COMMANDS = 1 << 16  # real images carry a few hundred at most
MAX_BLOB_SLOTS = 256  # codesign writes fewer than a dozen
MAX_ENTITLEMENTS_SIZE = 8 << 20
MAX_TEAM_ID_LEN = 64

SIGNATURE_ORDER = ("none", "adhoc", "signed")

CPU_NAMES = {
    (12, 9): "armv7",
    (12, 11): "armv7s",
    (0x0100000C, 0): "arm64",
    (0x0100000C, 1): "arm64",
    (0x0100000C, 2): "arm64e",
    (0x0200000C, 1): "arm64_32",
    (7, 3): "i386",
    (0x01000007, 3): "x86_64",
    (0x01000007, 8): "x86_64h",
}


class MachOError(Exception):
    """A Mach-O image (or its signature) is malformed. ``rule`` is a stable id."""

    def __init__(self, rule: str, detail: str = ""):
        self.rule = rule
        self.detail = detail
        super().__init__("%s: %s" % (rule, detail) if detail else rule)


@dataclasses.dataclass
class CodeSignature:
    """Facts from one embedded signature SuperBlob."""

    code_directories: int = 0
    flags: int = 0
    identifier: Optional[str] = None
    team_id: Optional[str] = None
    cms_size: int = 0  # payload bytes of the CMS blob wrapper (0 = absent or empty)
    entitlements_xml: Optional[bytes] = None  # raw payload of slot 5
    entitlements: Optional[Dict[str, Any]] = None  # parsed slot 5 (None when absent or empty)
    der_entitlements: Optional[Dict[str, Any]] = None  # parsed slot 7 (informational)
    der_error: Optional[str] = None

    @property
    def adhoc(self) -> bool:
        return bool(self.flags & CS_ADHOC)

    @property
    def linker_signed(self) -> bool:
        return bool(self.flags & CS_LINKER_SIGNED)

    @property
    def state(self) -> str:
        """``signed`` when a CMS signature or a team id is present, else ``adhoc``."""
        return "signed" if self.cms_size > 0 or self.team_id else "adhoc"


@dataclasses.dataclass
class Slice:
    offset: int
    size: int
    cputype: int
    cpusubtype: int
    bits: int
    big_endian: bool
    filetype: int
    encrypted: bool = False
    code_signature: Optional[CodeSignature] = None

    @property
    def arch(self) -> str:
        key = (self.cputype, self.cpusubtype & ~CPU_SUBTYPE_MASK)
        return CPU_NAMES.get(key, "%x/%x" % (self.cputype & 0xFFFFFFFF, key[1]))

    @property
    def signature(self) -> str:
        return "none" if self.code_signature is None else self.code_signature.state


@dataclasses.dataclass
class MachO:
    slices: List[Slice]
    fat: bool = False
    fat64: bool = False

    @property
    def signature(self) -> str:
        """Worst state over all slices: ``none`` < ``adhoc`` < ``signed``."""
        return worst_signature(s.signature for s in self.slices)

    @property
    def team_ids(self) -> List[str]:
        return sorted({s.code_signature.team_id for s in self.slices
                       if s.code_signature is not None and s.code_signature.team_id})

    @property
    def entitlements(self) -> Optional[Dict[str, Any]]:
        """XML entitlements of the first slice whose slot-5 blob is non-empty (what ldid/AltSign read)."""
        for s in self.slices:
            cs = s.code_signature
            if cs is not None and cs.entitlements_xml:
                return cs.entitlements
        return None

    @property
    def all_entitlements(self) -> List[Dict[str, Any]]:
        """Parsed XML entitlements of every slice that has them."""
        return [s.code_signature.entitlements for s in self.slices
                if s.code_signature is not None and s.code_signature.entitlements is not None]

    @property
    def encrypted(self) -> bool:
        return any(s.encrypted for s in self.slices)

    @property
    def filetypes(self) -> List[int]:
        return sorted({s.filetype for s in self.slices})


def worst_signature(states: Any) -> str:
    worst = 0
    for state in states:
        worst = max(worst, SIGNATURE_ORDER.index(state))
    return SIGNATURE_ORDER[worst]


# -- detection ------------------------------------------------------------------------------------

def is_macho(head: bytes) -> bool:
    """Whether ``head`` (at least the first 8 bytes of a file) starts like a Mach-O or FAT image."""
    if len(head) < 8:
        return False
    be = struct.unpack_from(">I", head, 0)[0]
    le = struct.unpack_from("<I", head, 0)[0]
    if be in (MH_MAGIC, MH_MAGIC_64) or le in (MH_MAGIC, MH_MAGIC_64):
        return True
    if be in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", head, 4)[0]
        return 0 < nfat <= MAX_FAT_ARCHS
    return False


# -- parsing --------------------------------------------------------------------------------------

def _u32(buf: Any, off: int, endian: str = ">") -> int:
    return struct.unpack_from(endian + "I", buf, off)[0]


def iter_slices(buf: Any) -> Iterator[Tuple[int, int]]:
    """Yield ``(offset, size)`` of every slice (a thin image is one slice covering the buffer)."""
    n = len(buf)
    if n < 8:
        raise MachOError("macho-invalid", "file too small")
    magic, nfat = struct.unpack_from(">II", buf, 0)
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        yield 0, n
        return
    if not 0 < nfat <= MAX_FAT_ARCHS:
        raise MachOError("macho-invalid", "implausible FAT arch count")
    fmt, step = (">iiQQII", 32) if magic == FAT_MAGIC_64 else (">iiIII", 20)
    table_end = 8 + nfat * step
    if table_end > n:
        raise MachOError("macho-invalid", "FAT arch table truncated")
    spans = []
    for i in range(nfat):
        _cputype, _cpusub, off, size = struct.unpack_from(fmt, buf, 8 + i * step)[:4]
        if off < table_end or size == 0 or off + size > n:
            raise MachOError("macho-invalid", "FAT slice out of bounds")
        spans.append((off, size))
    ordered = sorted(spans)
    for (a_off, a_size), (b_off, _) in zip(ordered, ordered[1:]):
        if a_off + a_size > b_off:
            raise MachOError("macho-invalid", "FAT slices overlap")
    for span in spans:
        yield span


def parse_macho(buf: Any) -> MachO:
    """Parse a thin or FAT Mach-O held in ``buf``."""
    try:
        fat_magic = _u32(buf, 0) if len(buf) >= 4 else 0
        slices = [parse_slice(buf, off, size) for off, size in iter_slices(buf)]
    except struct.error:
        raise MachOError("macho-invalid", "truncated structure") from None
    return MachO(slices=slices, fat=fat_magic in (FAT_MAGIC, FAT_MAGIC_64), fat64=fat_magic == FAT_MAGIC_64)


def parse_file(path: str) -> MachO:
    """Parse the Mach-O file at ``path`` through a read-only memory map."""
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        if fh.tell() == 0:
            raise MachOError("macho-invalid", "empty file")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            return parse_macho(mm)


def parse_slice(buf: Any, base: int, size: int) -> Slice:
    if size < 28 or base + size > len(buf):
        raise MachOError("macho-invalid", "slice too small")
    if _u32(buf, base, "<") in (MH_MAGIC, MH_MAGIC_64):
        e = "<"
    elif _u32(buf, base, ">") in (MH_MAGIC, MH_MAGIC_64):
        e = ">"
    else:
        raise MachOError("macho-invalid", "bad slice magic")
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(e + "IiiIIII", buf, base)
    is64 = magic == MH_MAGIC_64
    hdr = 32 if is64 else 28
    if hdr + sizeofcmds > size:
        raise MachOError("macho-invalid", "load commands exceed the slice")
    if ncmds * 8 > sizeofcmds or ncmds > MAX_LOAD_COMMANDS:
        raise MachOError("macho-invalid", "implausible load command count")
    res = Slice(offset=base, size=size, cputype=cputype, cpusubtype=cpusub & 0xFFFFFFFF, bits=64 if is64 else 32,
                big_endian=e == ">", filetype=filetype)
    off, end = base + hdr, base + hdr + sizeofcmds
    seen_signature = False
    for _ in range(ncmds):
        if off + 8 > end:
            raise MachOError("macho-invalid", "truncated load command")
        cmd, cmdsize = struct.unpack_from(e + "II", buf, off)
        if cmdsize < 8 or cmdsize % 4 or off + cmdsize > end:
            raise MachOError("macho-invalid", "bad cmdsize")
        cmd &= 0x7FFFFFFF  # LC_REQ_DYLD bit
        if cmd == LC_CODE_SIGNATURE:
            if seen_signature:
                raise MachOError("macho-signature-invalid", "more than one LC_CODE_SIGNATURE")
            if cmdsize < 16:
                raise MachOError("macho-signature-invalid", "short LC_CODE_SIGNATURE")
            seen_signature = True
            dataoff, datasize = struct.unpack_from(e + "II", buf, off + 8)
            if datasize < 12 or dataoff + datasize > size:
                raise MachOError("macho-signature-invalid", "code signature out of the slice")
            res.code_signature = parse_superblob(buf, base + dataoff, datasize)
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if cmdsize < 20:
                raise MachOError("macho-invalid", "short encryption command")
            cryptid = struct.unpack_from(e + "III", buf, off + 8)[2]
            res.encrypted = res.encrypted or cryptid != 0
        off += cmdsize
    return res


def parse_superblob(buf: Any, start: int, avail: int) -> CodeSignature:
    """Decode the embedded signature at ``buf[start:start+avail]`` (rules follow xnu cs_validate_csblob)."""
    bad = "macho-signature-invalid"
    if avail < 12:
        raise MachOError(bad, "SuperBlob too small")
    magic, length, count = struct.unpack_from(">III", buf, start)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise MachOError(bad, "bad SuperBlob magic")
    if length < 12 or length > avail or (length - 12) // 8 < count or count > MAX_BLOB_SLOTS:
        raise MachOError(bad, "bad SuperBlob length or count")
    out = CodeSignature()
    seen = set()
    for i in range(count):
        stype, boff = struct.unpack_from(">II", buf, start + 12 + i * 8)
        if stype in seen:
            raise MachOError(bad, "duplicate blob slot")
        seen.add(stype)
        if boff < 12 + count * 8 or boff + 8 > length:
            raise MachOError(bad, "blob offset out of the SuperBlob")
        bmagic, blen = struct.unpack_from(">II", buf, start + boff)
        if blen < 8 or boff + blen > length:
            raise MachOError(bad, "blob length out of the SuperBlob")
        pstart, plen = start + boff + 8, blen - 8
        if stype == CSSLOT_CODEDIRECTORY or (
                CSSLOT_ALTERNATE_CODEDIRECTORIES <= stype
                < CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX):
            if bmagic != CSMAGIC_CODEDIRECTORY:
                raise MachOError(bad, "bad CodeDirectory magic")
            _parse_code_directory(buf, start + boff, blen, out)
        elif stype == CSSLOT_SIGNATURESLOT:
            # any payload here is a CMS signature (an ad-hoc signature carries an empty wrapper)
            out.cms_size = plen
        elif stype == CSSLOT_ENTITLEMENTS:
            if bmagic != CSMAGIC_EMBEDDED_ENTITLEMENTS:
                raise MachOError(bad, "bad entitlements blob magic")
            payload = bytes(buf[pstart:pstart + plen]) if plen <= MAX_ENTITLEMENTS_SIZE else None
            if payload is None:
                raise MachOError("macho-entitlements-invalid", "entitlements blob too large")
            out.entitlements_xml = payload
            out.entitlements = parse_xml_entitlements(payload) if payload else None
        elif stype == CSSLOT_DER_ENTITLEMENTS:
            if bmagic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
                raise MachOError(bad, "bad DER entitlements blob magic")
            if plen > MAX_ENTITLEMENTS_SIZE:
                out.der_error = "too large"
                continue
            try:
                out.der_entitlements = der_entitlements_to_dict(bytes(buf[pstart:pstart + plen]))
            except (MachOError, UnicodeDecodeError, IndexError, ValueError) as exc:
                out.der_error = getattr(exc, "detail", None) or type(exc).__name__
    return out


def _parse_code_directory(buf: Any, start: int, length: int, out: CodeSignature) -> None:
    bad = "macho-signature-invalid"
    if length < _CD_MIN_SIZE:
        raise MachOError(bad, "CodeDirectory too small")
    _magic, cd_len, version, flags, _hash_off, ident_off = struct.unpack_from(">IIIIII", buf, start)
    if cd_len < _CD_MIN_SIZE or cd_len > length:
        raise MachOError(bad, "CodeDirectory length out of its blob")
    first = out.code_directories == 0
    out.code_directories += 1
    if first:
        out.flags = flags
        if ident_off:
            out.identifier = _cstring(buf, start, cd_len, ident_off)
    if version >= CS_SUPPORTSTEAMID and cd_len >= _CD_TEAM_OFFSET + 4:
        team_off = struct.unpack_from(">I", buf, start + _CD_TEAM_OFFSET)[0]
        if team_off:
            team = _cstring(buf, start, cd_len, team_off)
            if team and not out.team_id:
                out.team_id = team[:MAX_TEAM_ID_LEN]


def _cstring(buf: Any, start: int, length: int, off: int) -> str:
    if off >= length:
        raise MachOError("macho-signature-invalid", "CodeDirectory string out of bounds")
    end = start + length
    pos = start + off
    chunk = bytes(buf[pos:min(end, pos + 1024)])
    nul = chunk.find(b"\x00")
    if nul < 0:
        raise MachOError("macho-signature-invalid", "unterminated CodeDirectory string")
    return chunk[:nul].decode("utf-8", "replace")


def parse_xml_entitlements(payload: bytes) -> Dict[str, Any]:
    """Parse a slot-5 payload (XML plist; plistlib rejects entity declarations)."""
    data = payload.rstrip(b"\x00")
    try:
        try:
            value = plistlib.loads(data)
        except Exception:
            value = plistlib.loads(data.lstrip(), fmt=plistlib.FMT_XML)
    except Exception:
        raise MachOError("macho-entitlements-invalid", "entitlements are not a plist") from None
    if not isinstance(value, dict):
        raise MachOError("macho-entitlements-invalid", "entitlements are not a dictionary")
    return value


# -- DER entitlements (CoreEntitlements form and ldid's SET form) ---------------------------------

def _tlv(b: bytes, i: int) -> Tuple[Any, bytes, int]:
    if i + 2 > len(b):
        raise MachOError("macho-entitlements-invalid", "DER truncated")
    tag: Any = b[i]
    i += 1
    if tag & 0x1F == 0x1F:  # high-tag-number form
        num = 0
        while True:
            if i >= len(b):
                raise MachOError("macho-entitlements-invalid", "DER truncated")
            t = b[i]
            i += 1
            num = (num << 7) | (t & 0x7F)
            if not t & 0x80:
                break
        tag = (tag & 0xE0, num)
    if i >= len(b):
        raise MachOError("macho-entitlements-invalid", "DER truncated")
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4:  # 0x80 is the indefinite form, not DER
            raise MachOError("macho-entitlements-invalid", "unsupported DER length")
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise MachOError("macho-entitlements-invalid", "DER value overruns its buffer")
    return tag, b[i:i + n], i + n


def _children(b: bytes) -> List[Tuple[Any, bytes]]:
    i, out = 0, []
    while i < len(b):
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def _der_value(tag: Any, val: bytes, depth: int = 0) -> Any:
    if depth > 32:
        raise MachOError("macho-entitlements-invalid", "DER nesting too deep")
    if tag == 0x01:
        return val != b"\x00"
    if tag == 0x02:
        return int.from_bytes(val, "big", signed=True)
    if tag == 0x0C:
        return val.decode("utf-8")
    if tag == 0x04:
        return bytes(val)
    if tag == 0x30:
        return [_der_value(t, v, depth + 1) for t, v in _children(val)]
    if tag in (0xB0, 0x31):  # Apple [CONTEXT 16] dictionary, ldid SET dictionary
        d = {}
        for t, v in _children(val):
            kv = _children(v)
            if t != 0x30 or len(kv) != 2 or kv[0][0] != 0x0C:
                raise MachOError("macho-entitlements-invalid", "bad DER dictionary entry")
            d[kv[0][1].decode("utf-8")] = _der_value(kv[1][0], kv[1][1], depth + 1)
        return d
    raise MachOError("macho-entitlements-invalid", "unsupported DER tag")


def der_entitlements_to_dict(payload: bytes) -> Dict[str, Any]:
    tag, val, _ = _tlv(payload, 0)
    if tag == 0x70:  # [APPLICATION 16] { INTEGER version, dictionary }
        kids = _children(val)
        if len(kids) != 2 or kids[0][0] != 0x02:
            raise MachOError("macho-entitlements-invalid", "bad CoreEntitlements wrapper")
        value = _der_value(*kids[1])
    else:
        value = _der_value(tag, val)
    if not isinstance(value, dict):
        raise MachOError("macho-entitlements-invalid", "DER root is not a dictionary")
    return value
