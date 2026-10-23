"""Deterministic, idempotent re-pack of an IPA.

``normalize_ipa`` rewrites an archive so that its bytes depend only on the names, contents and
executable bits of the bundle:

- junk is dropped: ``__MACOSX/``, ``.DS_Store``, ``._*`` (AppleDouble), ``Thumbs.db`` and the
  ``iTunesMetadata.plist`` at the archive root (App Store exports keep the purchaser's account in it);
- entries are sorted by their UTF-8 name and every directory gets an explicit entry;
- every entry carries the timestamp 1980-01-01 00:00:00, ``create_system`` 3 (Unix), no extra
  fields and no comments; the archive has no comment;
- modes are fixed: directories 0o040755, files 0o100644, or 0o100755 when the source entry had an
  execute bit or the file is Mach-O, symlinks 0o120777 (kept only when they resolve inside their
  ``.app`` bundle);
- files are deflated at level 9, directories and symlinks are stored;
- ``BuildMachineOSBuild`` is removed from every ``Info.plist``, which is re-serialized in its
  original format (a binary plist stays binary).

Signing material (``*.mobileprovision``, ``_CodeSignature/``, ``*.xcent`` entitlement files,
CMS-signed binaries) is neither stripped nor hidden: it is copied like any other entry and listed in
``NormalizeReport.refused`` so that the leak gate rejects the result. The archive writer is
self-contained, so the output does not depend on the Python version's ``zipfile`` writer.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import os
import plistlib
import posixpath
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

CHUNK = 1 << 20
PLIST_MAX_BYTES = 8 << 20
SYMLINK_MAX_BYTES = 1024
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_DOS_TIME = 0
_DOS_DATE = (1 << 5) | 1  # 1980-01-01
_VERSION = 20  # 2.0: deflate, directories
_MADE_BY = (3 << 8) | _VERSION  # Unix
_UTF8_FLAG = 0x800
_U32 = 0xFFFFFFFF

DIR_MODE = 0o040755
FILE_MODE = 0o100644
EXEC_MODE = 0o100755
LINK_MODE = 0o120777

STRIP_PLIST_KEYS = ("BuildMachineOSBuild",)
JUNK_NAMES = frozenset((".ds_store", "thumbs.db"))  # compared case-insensitively
ROOT_JUNK_NAMES = frozenset(("itunesmetadata.plist",))  # only at the archive root, case-insensitively
MACHO_MAGICS = frozenset((
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # 64-bit
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # FAT
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",  # FAT64
))
_APP_RE = re.compile(r"^(Payload/[^/]+\.app)/", re.IGNORECASE)
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclasses.dataclass(frozen=True)
class ZipLimits:
    """Archive bounds shared by normalization and the leak gate (same values as inspection)."""

    max_entries: int = 50_000
    max_total: int = 4 << 30
    max_entry: int = 2 << 30
    max_ratio: int = 200
    ratio_min_size: int = 1 << 20


DEFAULT_LIMITS = ZipLimits()


class ArchiveError(zipfile.BadZipFile):
    """The archive is unsafe or unreadable. ``rule`` is a stable id; messages carry no names."""

    def __init__(self, rule: str, message: str = ""):
        super().__init__(message or rule)
        self.rule = rule


class NormalizeError(ArchiveError):
    """The IPA cannot be normalized."""


@dataclasses.dataclass
class NormalizeReport:
    removed: List[str]
    plist_keys_removed: int
    input_sha256: str
    output_sha256: str
    output_size: int
    changed: bool
    refused: List[str] = dataclasses.field(default_factory=list)
    entries: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# -- archive reading helpers (also used by the leak gate) ------------------------------------------

def unix_mode(zi: zipfile.ZipInfo) -> int:
    return (zi.external_attr >> 16) & 0xFFFF if zi.create_system == 3 else 0


def is_symlink(zi: zipfile.ZipInfo) -> bool:
    return stat.S_ISLNK(unix_mode(zi))


def is_dir_entry(zi: zipfile.ZipInfo, name: str) -> bool:
    return name.endswith("/") or (stat.S_ISDIR(unix_mode(zi)) and zi.file_size == 0)


def entry_name(zi: zipfile.ZipInfo, error: type = ArchiveError) -> str:
    """The entry name as UTF-8 text.

    ``zipfile`` decodes names without the UTF-8 flag as cp437, but many tools (and the AltStore
    unzipper, which always decodes UTF-8) store UTF-8 bytes without setting it.
    """
    name = zi.orig_filename  # the header name; ``filename`` may come from a Unicode path extra field
    if "\x00" in name:
        raise error("zip-path", "entry name contains NUL")
    if not zi.flag_bits & _UTF8_FLAG and not name.isascii():
        try:
            name = name.encode("cp437").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise error("zip-name-encoding", "entry name is not UTF-8") from None
    return name


@contextlib.contextmanager
def zip_library_errors(error: type = ArchiveError) -> Iterator[None]:
    """Turn what ``zipfile`` raises besides ``BadZipFile`` into ``error``.

    A name flagged as UTF-8 that is not (in the central directory or a local header) raises
    ``UnicodeDecodeError``; a feature ``zipfile`` lacks, such as a "version needed to extract" above
    6.3, raises ``NotImplementedError``.
    """
    try:
        yield
    except UnicodeDecodeError:
        raise error("zip-name-encoding", "entry name is not UTF-8") from None
    except NotImplementedError:
        raise error("zip-unsupported", "zip feature not supported") from None


def check_path(name: str, error: type = ArchiveError) -> None:
    """Reject names that are absolute, use backslashes or drive letters, or step outside the root."""
    if not name or "\\" in name or name.startswith("/") or _DRIVE_RE.match(name):
        raise error("zip-path", "unsafe entry name")
    parts = name[:-1].split("/") if name.endswith("/") else name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise error("zip-path", "unsafe entry name")


def check_limits(infos: List[zipfile.ZipInfo], limits: ZipLimits = DEFAULT_LIMITS,
                 error: type = ArchiveError) -> None:
    """Entry count, sizes, compression ratio, encryption and compression method."""
    if len(infos) > limits.max_entries:
        raise error("zip-entries", "too many entries")
    total = 0
    for zi in infos:
        if zi.flag_bits & 0x1:
            raise error("zip-encrypted", "encrypted entry")
        if zi.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise error("zip-compression", "unsupported compression method")
        if zi.file_size > limits.max_entry:
            raise error("zip-entry-size", "entry too large")
        if zi.file_size > limits.ratio_min_size and zi.file_size > limits.max_ratio * max(zi.compress_size, 1):
            raise error("zip-ratio", "compression ratio too high")
        total += zi.file_size
        if total > limits.max_total:
            raise error("zip-total-size", "archive too large")


def name_key(name: str) -> bytes:
    return name.encode("utf-8")


def is_macho(head: bytes) -> bool:
    return head[:4] in MACHO_MAGICS


def is_junk(name: str) -> bool:
    parts = name.rstrip("/").split("/")
    if parts[0] == "__MACOSX":
        return True
    if len(parts) == 1 and not name.endswith("/") and parts[0].lower() in ROOT_JUNK_NAMES:
        return True
    return any(p.lower() in JUNK_NAMES or p.startswith("._") for p in parts)


def is_refused(name: str) -> bool:
    """Signing material the gate rejects; normalization keeps it so the gate sees it."""
    parts = name.rstrip("/").split("/")
    last = parts[-1].lower()
    return "_CodeSignature" in parts or last.endswith(".mobileprovision") or (
        last.endswith(".xcent") and not name.endswith("/"))


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


# -- Info.plist ------------------------------------------------------------------------------------

def strip_plist_keys(data: bytes, keys: Iterable[str] = STRIP_PLIST_KEYS) -> Tuple[bytes, bool]:
    """Remove top-level ``keys`` from a plist, keeping its format. Unparseable data is returned as is."""
    binary = data.startswith(b"bplist00")
    try:
        obj = plistlib.loads(data)
    except Exception:
        if binary:
            return data, False
        try:
            obj = plistlib.loads(data.lstrip())
        except Exception:
            return data, False
    if not isinstance(obj, dict) or not any(k in obj for k in keys):
        return data, False
    for key in keys:
        obj.pop(key, None)
    try:
        out = plistlib.dumps(obj, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML, sort_keys=True)
    except Exception:
        return data, False
    return out, True


# -- archive writer --------------------------------------------------------------------------------

class _Writer:
    """Minimal deterministic zip writer: no extra fields, no data descriptors, no zip64."""

    def __init__(self, fh, error: type):
        self.fh = fh
        self.error = error
        self.central: List[bytes] = []

    def _offset(self) -> int:
        offset = self.fh.tell()
        if offset >= _U32:
            raise self.error("zip-total-size", "normalized archive too large")
        return offset

    def _local_header(self, name: bytes, flags: int, method: int, crc: int, csize: int, usize: int) -> bytes:
        return struct.pack("<IHHHHHIIIHH", 0x04034B50, _VERSION, flags, method, _DOS_TIME, _DOS_DATE,
                           crc, csize, usize, len(name), 0) + name

    def add(self, name: str, mode: Any, chunks: Iterable[bytes], deflate: bool) -> None:
        """Append an entry; ``mode`` may be a callable evaluated once the data has been read."""
        raw = name.encode("utf-8")
        flags = 0 if raw.isascii() else _UTF8_FLAG
        method = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
        offset = self._offset()
        self.fh.write(self._local_header(raw, flags, method, 0, 0, 0))
        crc = 0
        usize = 0
        csize = 0
        comp = zlib.compressobj(9, zlib.DEFLATED, -15) if deflate else None
        for chunk in chunks:
            if not chunk:
                continue
            crc = zlib.crc32(chunk, crc)
            usize += len(chunk)
            out = comp.compress(chunk) if comp is not None else chunk
            csize += len(out)
            self.fh.write(out)
        if comp is not None:
            out = comp.flush()
            csize += len(out)
            self.fh.write(out)
        if csize >= _U32 or usize >= _U32:
            raise self.error("zip-entry-size", "entry too large")
        end = self.fh.tell()
        self.fh.seek(offset + 14)
        self.fh.write(struct.pack("<III", crc & _U32, csize, usize))
        self.fh.seek(end)
        mode = mode() if callable(mode) else mode
        attr = (mode << 16) | (0x10 if stat.S_ISDIR(mode) else 0)
        self.central.append(struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, _MADE_BY, _VERSION, flags, method, _DOS_TIME, _DOS_DATE,
            crc & _U32, csize, usize, len(raw), 0, 0, 0, 0, attr, offset) + raw)

    def close(self) -> None:
        start = self._offset()
        for record in self.central:
            self.fh.write(record)
        size = self.fh.tell() - start
        if len(self.central) > 0xFFFF or self.fh.tell() >= _U32:
            raise self.error("zip-total-size", "normalized archive too large")
        self.fh.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(self.central), len(self.central),
                                  size, start, 0))


# -- normalization ---------------------------------------------------------------------------------

@dataclasses.dataclass
class _Entry:
    name: str
    kind: str  # "dir" | "file" | "link"
    info: Optional[zipfile.ZipInfo] = None
    target: bytes = b""


def _app_root(name: str) -> Optional[str]:
    match = _APP_RE.match(name)
    return match.group(1) if match else None


MAX_LINK_HOPS = 32


def _link_text(target: bytes) -> str:
    try:
        text = target.decode("utf-8")
    except UnicodeDecodeError:
        raise NormalizeError("zip-symlink", "symlink target is not UTF-8") from None
    if not text or "\x00" in text or "\\" in text or text.startswith("/"):
        raise NormalizeError("zip-symlink", "symlink target is empty or absolute")
    return text


def check_links(links: Dict[str, str]) -> None:
    """Every symlink (name -> target) must resolve inside the ``.app`` bundle that contains it.

    Targets are resolved component by component, following other symlinks of the archive the way
    a file system would, and no step may leave the bundle (a lexical check alone can be escaped
    through a chain such as ``a -> .``, ``b -> a/..``).
    """
    for name in links:
        root = _app_root(name)
        if root is None:
            raise NormalizeError("zip-symlink", "symlink outside an app bundle")
        root_parts = root.split("/")
        stack = name.split("/")[:-1]
        todo = links[name].split("/")
        hops = 0
        while todo:
            part = todo.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                stack.pop()
                if len(stack) < len(root_parts):
                    raise NormalizeError("zip-symlink", "symlink points outside its bundle")
                continue
            stack.append(part)
            current = "/".join(stack)
            if current in links:
                hops += 1
                if hops > MAX_LINK_HOPS:
                    raise NormalizeError("zip-symlink", "symlink chain too long")
                stack.pop()
                todo = links[current].split("/") + todo


def _collect(zf: zipfile.ZipFile, limits: ZipLimits) -> Tuple[Dict[str, _Entry], List[str]]:
    infos = zf.infolist()
    check_limits(infos, limits, NormalizeError)
    entries: Dict[str, _Entry] = {}
    removed: List[str] = []
    seen = set()
    links: Dict[str, str] = {}
    for zi in infos:
        name = entry_name(zi, NormalizeError)
        check_path(name, NormalizeError)
        if name in seen:
            raise NormalizeError("zip-duplicate", "duplicate entry")
        seen.add(name)
        if is_junk(name):
            removed.append(name)
            continue
        if is_dir_entry(zi, name):
            key = name if name.endswith("/") else name + "/"
            entries[key] = _Entry(key, "dir")
        elif is_symlink(zi):
            if zi.file_size > SYMLINK_MAX_BYTES:
                raise NormalizeError("zip-symlink", "symlink target too long")
            target = zf.read(zi)
            links[name] = _link_text(target)
            entries[name] = _Entry(name, "link", zi, target)
        else:
            entries[name] = _Entry(name, "file", zi)
    check_links(links)
    # explicit entries for every directory
    for name in list(entries):
        parts = name.rstrip("/").split("/")
        for i in range(1, len(parts)):
            key = "/".join(parts[:i]) + "/"
            if key not in entries:
                entries[key] = _Entry(key, "dir")
    # a path cannot be both a directory and a file/link; case-folded names must stay unique
    folded: Dict[str, str] = {}
    for name in entries:
        bare = name.rstrip("/")
        if name.endswith("/") and bare in entries:
            raise NormalizeError("zip-duplicate", "path is both a file and a directory")
        key = unicodedata.normalize("NFC", bare).casefold()
        if key in folded:
            raise NormalizeError("zip-case-collision", "entry names collide when case-folded")
        folded[key] = name
    return entries, sorted(removed, key=name_key)


def _file_chunks(zf: zipfile.ZipFile, zi: zipfile.ZipInfo, head: List[bytes]):
    """Stream an entry's data; the first bytes are kept in ``head`` for Mach-O detection."""
    with zf.open(zi) as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            if not head:
                head.append(chunk[:4])
            yield chunk


def _output_mode(dst: str) -> int:
    """Permissions for ``dst``: those of the file it replaces, else what a new file gets (umask)."""
    try:
        return stat.S_IMODE(os.stat(dst).st_mode)
    except OSError:
        mask = os.umask(0)
        os.umask(mask)
        return 0o666 & ~mask


def normalize_ipa(src: str, dst: str, *, strip_build_machine: bool = True,
                  limits: Optional[ZipLimits] = None) -> NormalizeReport:
    """Write the normalized form of ``src`` to ``dst`` (atomically). ``src`` may equal ``dst``."""
    limits = limits or DEFAULT_LIMITS
    input_sha = sha256_file(src)
    out_dir = os.path.dirname(os.path.abspath(dst))
    fd, tmp = tempfile.mkstemp(prefix=".normalize-", suffix=".tmp", dir=out_dir)
    plists = 0
    try:
        with os.fdopen(fd, "w+b") as out, zip_library_errors(NormalizeError), zipfile.ZipFile(src) as zf:
            entries, removed = _collect(zf, limits)
            writer = _Writer(out, NormalizeError)
            for name in sorted(entries, key=name_key):
                entry = entries[name]
                if entry.kind == "dir":
                    writer.add(name, DIR_MODE, (), deflate=False)
                    continue
                if entry.kind == "link":
                    writer.add(name, LINK_MODE, (entry.target,), deflate=False)
                    continue
                zi = entry.info
                assert zi is not None
                plist = (strip_build_machine and posixpath.basename(name) == "Info.plist"
                         and zi.file_size <= PLIST_MAX_BYTES)
                head: List[bytes] = []
                if plist:
                    data, stripped = strip_plist_keys(zf.read(zi))
                    plists += 1 if stripped else 0
                    head.append(data[:4])
                    chunks: Iterable[bytes] = (data,)
                else:
                    chunks = _file_chunks(zf, zi, head)

                def mode(zi: zipfile.ZipInfo = zi, head: List[bytes] = head) -> int:
                    executable = bool(unix_mode(zi) & 0o111) or is_macho(b"".join(head))
                    return EXEC_MODE if executable else FILE_MODE

                writer.add(name, mode, chunks, deflate=True)
            writer.close()
        refused = sorted((n for n in entries if is_refused(n)), key=name_key)
        os.chmod(tmp, _output_mode(dst))
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    output_sha = sha256_file(dst)
    return NormalizeReport(
        removed=removed,
        plist_keys_removed=plists,
        input_sha256=input_sha,
        output_sha256=output_sha,
        output_size=os.path.getsize(dst),
        changed=input_sha != output_sha,
        refused=refused,
        entries=len(entries),
    )
