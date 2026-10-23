"""IPA inspection: zip safety audit, bundle facts, signatures, entitlements, privacy keys and icons.

:func:`inspect_ipa` never extracts anything: members are read in place through :mod:`zipfile`, whose
reads stop at the declared size and verify the CRC. Every archive is audited first; any problem is
raised as :class:`IpaError` with a stable rule id (no archive-derived text in the message):

==========================  ========================================================================
rule                        meaning
==========================  ========================================================================
zip-invalid                 not a zip archive (unreadable central directory)
zip-corrupt                 member data cannot be read (CRC, truncated stream, header mismatch)
zip-unsupported             a zip feature the reader does not implement (for example a "version
                            needed to extract" above 6.3)
zip-too-many-entries        more than ``Limits.max_entries`` entries
zip-total-size              declared uncompressed total above ``Limits.max_total_size``
zip-entry-size              one entry above ``Limits.max_entry_size``
zip-bomb-ratio              entry above ``Limits.ratio_min_size`` with ratio above ``Limits.max_ratio``
zip-overlap                 entries share or overlap their data (overlap bombs)
zip-compression             compression other than stored or deflated
zip-encrypted               encrypted entry
zip-path-absolute           name starts with ``/``
zip-path-drive              name starts with a drive letter
zip-path-traversal          ``..`` component
zip-path-backslash          backslash in a name
zip-path-nul                NUL in a name
zip-path-invalid            empty or ``.`` component, control character, directory with data,
                            Info-ZIP unicode path field that disagrees with the name
zip-path-encoding           name is not valid UTF-8 (unflagged, or flagged as UTF-8 in the central
                            directory or a local header)
zip-path-too-long           name longer than ``Limits.max_name_bytes``
zip-duplicate               same path twice, or one path used as both file and directory
zip-case-collision          paths equal after Unicode NFC normalization and case folding
zip-special-file            device, FIFO or socket entry
zip-symlink-escape          symlink that resolves outside the app bundle (or lives outside it)
zip-symlink-invalid         symlink with an empty, oversized, non-UTF-8 or looping target
ipa-no-app                  no ``Payload/<X>.app/`` directory
ipa-multiple-apps           more than one ``Payload/<X>.app/`` directory
plist-missing               a bundle has no ``Info.plist``
plist-too-large             ``Info.plist`` above ``Limits.max_plist_size``
plist-invalid               ``Info.plist`` cannot be parsed or is not a dictionary
ipa-executable-missing      ``CFBundleExecutable`` absent, unsafe, or naming a missing member
ipa-executable-invalid      the bundle executable is not a Mach-O image
macho-invalid               a member with Mach-O magic cannot be parsed
macho-signature-invalid     malformed ``LC_CODE_SIGNATURE`` data
macho-entitlements-invalid  entitlement blob (XML plist or DER) that cannot be decoded as a
                            dictionary
==========================  ========================================================================

Paths in :class:`IpaInfo` are archive-relative; directories carry no trailing slash.
"""

from __future__ import annotations

import contextlib
import dataclasses
import mmap
import plistlib
import re
import shutil
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from . import macho as machomod
from . import pngicon

# AltStore Regex+Permissions: Optionally("NS") Capture(OneOrMore(.any)) "UsageDescription" Optionally(...)
PRIVACY_RE = re.compile(r"(?:NS)?(.+)UsageDescription(.+)?", re.DOTALL)
IGNORED_ENTITLEMENTS = frozenset(("application-identifier", "com.apple.developer.team-identifier"))
TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
_ICON_RE = re.compile(r"(?:app)?icon[^/]*\.png", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ICON_SUFFIXES = ("", "@2x", "@3x")
_ICON_IDIOMS = ("", "~iphone", "~ipad")
_ARTWORK = ("iTunesArtwork@2x", "iTunesArtwork")
_UNICODE_PATH_EXTRA = 0x7075
_IN_MEMORY = 32 << 20  # larger members are spooled to a temporary file and memory-mapped
_ZIP_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError)


@dataclasses.dataclass(frozen=True)
class Limits:
    max_entries: int = 50_000
    max_total_size: int = 4 << 30
    max_entry_size: int = 2 << 30
    max_ratio: int = 200
    ratio_min_size: int = 1 << 20
    max_plist_size: int = 8 << 20
    max_name_bytes: int = 1024
    max_symlink_size: int = 1024
    max_symlink_hops: int = 32
    max_icon_size: int = 16 << 20


class IpaError(Exception):
    """The IPA is unsafe or malformed. ``rule`` is a stable id; ``path`` the in-IPA member, if any."""

    def __init__(self, rule: str, detail: str = "", path: Optional[str] = None):
        self.rule = rule
        self.detail = detail
        self.path = path
        super().__init__("%s: %s" % (rule, detail) if detail else rule)


@dataclasses.dataclass
class IconInfo:
    path: str
    width: int
    height: int
    is_cgbi: bool


@dataclasses.dataclass
class IpaInfo:
    bundle_id: str = ""
    short_version: str = ""
    build_version: str = ""
    name: str = ""
    executable: str = ""
    min_os: Optional[str] = None
    platforms: List[str] = dataclasses.field(default_factory=list)
    app_dir: str = ""
    extensions: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    privacy: Dict[str, str] = dataclasses.field(default_factory=dict)
    entitlements: List[str] = dataclasses.field(default_factory=list)
    signature: str = "none"
    team_ids: List[str] = dataclasses.field(default_factory=list)
    provisioning_profiles: List[str] = dataclasses.field(default_factory=list)
    code_signature_dirs: List[str] = dataclasses.field(default_factory=list)
    localizations: List[str] = dataclasses.field(default_factory=list)
    dsym_like: List[str] = dataclasses.field(default_factory=list)
    icon: Optional[IconInfo] = None
    macho_files: List[str] = dataclasses.field(default_factory=list)
    macho_signatures: Dict[str, str] = dataclasses.field(default_factory=dict)
    encrypted_macho_files: List[str] = dataclasses.field(default_factory=list)  # FairPlay cryptid != 0

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# -- archive access -------------------------------------------------------------------------------

def _entry_name(zi: zipfile.ZipInfo) -> str:
    """The member name as AltSign sees it (UTF-8 even without the UTF-8 flag)."""
    name = zi.orig_filename
    if not zi.flag_bits & 0x800 and not name.isascii():
        try:
            name = name.encode("cp437").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise IpaError("zip-path-encoding") from None
    upath = _unicode_path_field(zi.extra)
    if upath is not None and upath != name:
        raise IpaError("zip-path-invalid", "unicode path field differs from the name")
    return name


def _unicode_path_field(extra: bytes) -> Optional[str]:
    i = 0
    while i + 4 <= len(extra):
        hid, size = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + size]
        if hid == _UNICODE_PATH_EXTRA:
            if len(body) < 5:
                return "\x00"
            try:
                return body[5:].decode("utf-8")
            except UnicodeDecodeError:
                return "\x00"
        i += 4 + size
    return None


def _check_name(name: str, limits: Limits) -> None:
    if not name:
        raise IpaError("zip-path-invalid", "empty name")
    if "\x00" in name:
        raise IpaError("zip-path-nul")
    if "\\" in name:
        raise IpaError("zip-path-backslash")
    if name.startswith("/"):
        raise IpaError("zip-path-absolute")
    if _DRIVE_RE.match(name):
        raise IpaError("zip-path-drive")
    if _CONTROL_RE.search(name):
        raise IpaError("zip-path-invalid", "control character")
    if len(name.encode("utf-8")) > limits.max_name_bytes:
        raise IpaError("zip-path-too-long")
    parts = (name[:-1] if name.endswith("/") else name).split("/")
    if ".." in parts:
        raise IpaError("zip-path-traversal")
    if any(p in ("", ".") for p in parts):
        raise IpaError("zip-path-invalid", "empty or dot component")


def _fold(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def _resolve(path: str, links: Dict[str, str], max_hops: int) -> Tuple[Optional[str], str]:
    """Resolve ``path`` through the archive's own symlinks.

    Returns ``(resolved, "")`` or ``(None, reason)`` with reason ``escape`` (climbs above the archive
    root or uses an absolute target) or ``loop`` (more than ``max_hops`` links).
    """
    pending = path.split("/")
    pending.reverse()
    stack: List[str] = []
    hops = 0
    while pending:
        comp = pending.pop()
        if comp in ("", "."):
            continue
        if comp == "..":
            if not stack:
                return None, "escape"
            stack.pop()
            continue
        stack.append(comp)
        target = links.get("/".join(stack))
        if target is not None:
            hops += 1
            if hops > max_hops:
                return None, "loop"
            if target.startswith("/"):
                return None, "escape"
            stack.pop()
            pending.extend(reversed(target.split("/")))
    return "/".join(stack), ""


class _Archive:
    """An audited zip: path tables plus bounded readers."""

    def __init__(self, zf: zipfile.ZipFile, limits: Limits):
        self.zf = zf
        self.limits = limits
        self.files: Dict[str, zipfile.ZipInfo] = {}  # regular files
        self.links: Dict[str, str] = {}  # symlink path -> target
        self.dirs: Set[str] = set()  # explicit and implicit directories
        self.children: Dict[str, Set[str]] = {}  # directory -> child directories
        self.app_dir = ""
        self._audit()

    # every check that needs no member data comes first, then symlink targets are read
    def _audit(self) -> None:
        lim = self.limits
        infos = self.zf.infolist()
        if len(infos) > lim.max_entries:
            raise IpaError("zip-too-many-entries")
        total = 0
        kinds: Dict[str, str] = {}
        link_infos: Dict[str, zipfile.ZipInfo] = {}
        for zi in infos:
            name = _entry_name(zi)
            _check_name(name, lim)  # an unsafe name is never attached to the error
            if zi.flag_bits & 0x2041:  # traditional, strong or central-directory encryption
                raise IpaError("zip-encrypted", path=name)
            if zi.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise IpaError("zip-compression", path=name)
            if zi.file_size > lim.max_entry_size:
                raise IpaError("zip-entry-size", path=name)
            if zi.file_size > lim.ratio_min_size and zi.file_size > lim.max_ratio * max(zi.compress_size, 1):
                raise IpaError("zip-bomb-ratio", path=name)
            total += zi.file_size
            if total > lim.max_total_size:
                raise IpaError("zip-total-size")
            is_dir = name.endswith("/")
            path = name[:-1] if is_dir else name
            mode = (zi.external_attr >> 16) & 0xFFFF if zi.create_system in (3, 19) else 0  # Unix, OS X
            fmt = stat.S_IFMT(mode)
            if is_dir:
                if zi.file_size:
                    raise IpaError("zip-path-invalid", "directory entry with data", path=path)
                kind = "dir"
            elif fmt == stat.S_IFLNK:
                kind = "link"
            elif fmt in (0, stat.S_IFREG):
                kind = "file"
            else:
                raise IpaError("zip-special-file", path=path)
            if path in kinds:
                raise IpaError("zip-duplicate", path=path)
            kinds[path] = kind
            if kind == "dir":
                self.dirs.add(path)
            elif kind == "link":
                link_infos[path] = zi
            else:
                self.files[path] = zi

        for path in list(kinds):
            parts = path.split("/")
            for i in range(1, len(parts)):
                parent = "/".join(parts[:i])
                if kinds.get(parent, "dir") != "dir":
                    raise IpaError("zip-duplicate", "path used as file and directory", path=parent)
                self.dirs.add(parent)
        folded: Dict[str, str] = {}
        for path in list(kinds) + sorted(self.dirs):
            key = _fold(path)
            other = folded.setdefault(key, path)
            if other != path:
                raise IpaError("zip-case-collision", path=path)
        for path in self.dirs:
            if "/" in path:
                parent, _ = path.rsplit("/", 1)
                self.children.setdefault(parent, set()).add(path)
        self._check_overlap(infos)

        apps = sorted(d for d in self.children.get("Payload", ()) if d.lower().endswith(".app"))
        if not apps:
            raise IpaError("ipa-no-app")
        if len(apps) > 1:
            raise IpaError("ipa-multiple-apps")
        self.app_dir = apps[0]

        for path, zi in sorted(link_infos.items()):
            if zi.file_size > lim.max_symlink_size:
                raise IpaError("zip-symlink-invalid", path=path)
            with self.zf.open(zi) as fh:
                raw = fh.read(lim.max_symlink_size + 1)
            try:
                target = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise IpaError("zip-symlink-invalid", path=path) from None
            if not target or "\x00" in target:
                raise IpaError("zip-symlink-invalid", path=path)
            if target.startswith("/") or not path.startswith(self.app_dir + "/"):
                raise IpaError("zip-symlink-escape", path=path)
            self.links[path] = target
        inside = self.app_dir + "/"
        for path in sorted(self.links):
            resolved, reason = _resolve(path, self.links, lim.max_symlink_hops)
            if reason == "loop":
                raise IpaError("zip-symlink-invalid", "symlink loop", path=path)
            if resolved is None or not resolved.startswith(inside):
                raise IpaError("zip-symlink-escape", path=path)

    def _check_overlap(self, infos: List[zipfile.ZipInfo]) -> None:
        ordered = sorted(infos, key=lambda zi: zi.header_offset)
        start_dir = getattr(self.zf, "start_dir", None)
        for i, zi in enumerate(ordered):
            try:
                name_len = len(zi.orig_filename.encode("utf-8" if zi.flag_bits & 0x800 else "cp437"))
            except UnicodeEncodeError:
                name_len = 0
            end = zi.header_offset + 30 + name_len + zi.compress_size
            limit = ordered[i + 1].header_offset if i + 1 < len(ordered) else start_dir
            if limit is not None and end > limit:
                raise IpaError("zip-overlap")

    # -- readers ----------------------------------------------------------------------------------

    def read(self, path: str, limit: int, rule: str) -> bytes:
        zi = self.files[path]
        if zi.file_size > limit:
            raise IpaError(rule, path=path)
        with self.zf.open(zi) as fh:
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise IpaError(rule, path=path)
        return data

    def head(self, path: str, size: int) -> bytes:
        with self.zf.open(self.files[path]) as fh:
            return fh.read(size)

    @contextlib.contextmanager
    def buffer(self, path: str) -> Iterator[Any]:
        """The whole member as ``bytes`` or, when large, as a read-only memory map of a spooled copy."""
        zi = self.files[path]
        if zi.file_size <= _IN_MEMORY:
            yield self.read(path, self.limits.max_entry_size, "zip-entry-size")
            return
        with tempfile.TemporaryFile() as tmp:
            with self.zf.open(zi) as src:
                shutil.copyfileobj(src, tmp, 1 << 20)
            tmp.flush()
            with mmap.mmap(tmp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                yield mm

    def plist(self, path: str) -> Dict[str, Any]:
        if path not in self.files:
            raise IpaError("plist-missing", path=path)
        return parse_plist(self.read(path, self.limits.max_plist_size, "plist-too-large"), path)

    def all_paths(self) -> List[str]:
        return sorted(set(self.files) | set(self.links) | self.dirs)


@contextlib.contextmanager
def _open_archive(path: str, limits: Limits) -> Iterator[_Archive]:
    # besides BadZipFile, zipfile raises UnicodeDecodeError for a name flagged as UTF-8 that is not
    # (central directory or local header) and NotImplementedError for features it lacks, such as a
    # "version needed to extract" above 6.3
    try:
        zf = zipfile.ZipFile(path)
    except UnicodeDecodeError:
        raise IpaError("zip-path-encoding") from None
    except NotImplementedError:
        raise IpaError("zip-unsupported") from None
    except _ZIP_ERRORS:
        raise IpaError("zip-invalid") from None
    try:
        with zf:
            yield _Archive(zf, limits)
    except UnicodeDecodeError:
        raise IpaError("zip-path-encoding") from None
    except NotImplementedError:
        raise IpaError("zip-unsupported") from None
    except _ZIP_ERRORS:
        raise IpaError("zip-corrupt") from None


def parse_plist(data: bytes, path: Optional[str] = None) -> Dict[str, Any]:
    """Parse an XML or binary property list that must be a dictionary (leading whitespace tolerated)."""
    try:
        value = plistlib.loads(data)
    except Exception:
        try:
            value = plistlib.loads(data.lstrip(), fmt=plistlib.FMT_XML)
        except Exception:
            raise IpaError("plist-invalid", path=path) from None
    if not isinstance(value, dict):
        raise IpaError("plist-invalid", "not a dictionary", path=path)
    return value


# -- facts ----------------------------------------------------------------------------------------

def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _opt_text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _display_name(info: Dict[str, Any]) -> str:
    for key in ("CFBundleDisplayName", "CFBundleName"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _executable(ar: _Archive, bundle: str, info: Dict[str, Any], machos: Dict[str, Any]) -> str:
    exe = info.get("CFBundleExecutable")
    if not isinstance(exe, str) or not exe or "/" in exe or exe in (".", "..") or "\x00" in exe:
        raise IpaError("ipa-executable-missing", path=bundle)
    path = bundle + "/" + exe
    if path in machos:
        return path
    if path in ar.files or path in ar.links:
        raise IpaError("ipa-executable-invalid", path=path)
    raise IpaError("ipa-executable-missing", path=path)


def _privacy(infos: List[Dict[str, Any]], fallback: str) -> Dict[str, str]:
    """Usage-description keys of the given Info.plists; missing or non-string text is synthesized."""
    out: Dict[str, str] = {}
    synthesized: Set[str] = set()
    for info in infos:
        for key, value in info.items():
            if not isinstance(key, str) or not PRIVACY_RE.fullmatch(key):
                continue
            real = isinstance(value, str) and bool(value.strip())
            if key in out and not (key in synthesized and real):
                continue
            out[key] = value if real else fallback
            if real:
                synthesized.discard(key)
            else:
                synthesized.add(key)
    return dict(sorted(out.items()))


def _team_ids(machos: Dict[str, Any]) -> List[str]:
    """Team ids from the CodeDirectories and from the XML and DER entitlements of every slice."""
    teams: Set[str] = set()
    for m in machos.values():
        teams.update(m.team_ids)
        for ents in m.all_entitlements:
            team = ents.get("com.apple.developer.team-identifier")
            if isinstance(team, str) and team.strip():
                teams.add(team.strip())
            app_id = ents.get("application-identifier")
            if isinstance(app_id, str) and "." in app_id:
                prefix = app_id.split(".", 1)[0]
                if TEAM_ID_RE.match(prefix):
                    teams.add(prefix)
    return sorted(teams)


def _component_dirs(paths: List[str], match: Any) -> List[str]:
    out: Set[str] = set()
    for path in paths:
        parts = path.split("/")
        for i, comp in enumerate(parts):
            if match(comp):
                out.add("/".join(parts[:i + 1]))
                break
    return sorted(out)


def _dsym_like(ar: _Archive, paths: List[str], machos: Dict[str, Any]) -> List[str]:
    out = set(_component_dirs(paths, lambda c: c.lower().endswith(".dsym")))
    for path in paths:
        if path in ar.dirs:
            continue
        if path.lower().endswith(".dsym.zip") or "/Contents/Resources/DWARF/" in "/" + path:
            out.add(path)
    for path, m in machos.items():
        if machomod.MH_DSYM in m.filetypes:
            out.add(path)
    return sorted(out)


def icon_basenames(info: Dict[str, Any]) -> List[str]:
    """Icon names from Info.plist in precedence order (CFBundleIcons, ~ipad, CFBundleIconFiles, CFBundleIconFile)."""
    out: List[str] = []
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        icons = info.get(key)
        if not isinstance(icons, dict):
            continue
        primary = icons.get("CFBundlePrimaryIcon")
        if isinstance(primary, str):  # tvOS form
            out.append(primary)
        elif isinstance(primary, dict):
            files = primary.get("CFBundleIconFiles")
            if isinstance(files, list):
                out.extend(f for f in files if isinstance(f, str))
            if isinstance(primary.get("CFBundleIconName"), str):
                out.append(primary["CFBundleIconName"])
    files = info.get("CFBundleIconFiles")
    if isinstance(files, list):
        out.extend(f for f in files if isinstance(f, str))
    if isinstance(info.get("CFBundleIconFile"), str):
        out.append(info["CFBundleIconFile"])
    return list(dict.fromkeys(n for n in out if n and "/" not in n))


def _probe_icon(ar: _Archive, path: str) -> Optional[IconInfo]:
    zi = ar.files[path]
    if zi.file_size > ar.limits.max_icon_size:
        return None
    try:
        hdr = pngicon.read_header(ar.head(path, 256))
    except pngicon.PNGError:
        return None
    if hdr.width != hdr.height or hdr.width * hdr.height > pngicon.MAX_PIXELS:
        return None
    return IconInfo(path=path, width=hdr.width, height=hdr.height, is_cgbi=hdr.cgbi)


def icon_candidates(ar: _Archive, info: Dict[str, Any]) -> List[IconInfo]:
    """Square PNG icons at the bundle root, best first (largest; ties keep Info.plist precedence)."""
    prefix = ar.app_dir + "/"
    root = {}
    for path in sorted(ar.files):
        rest = path[len(prefix):] if path.startswith(prefix) else None
        if rest and "/" not in rest:
            root.setdefault(rest.lower(), path)
    names: List[str] = []
    for base in icon_basenames(info):
        stem = base[:-4] if base.lower().endswith(".png") else base
        for suffix in _ICON_SUFFIXES:
            for idiom in _ICON_IDIOMS:
                names.append(stem + suffix + idiom + ".png")
        names.append(base)
    names.extend(r for r in sorted(root) if _ICON_RE.fullmatch(r))
    order = list(dict.fromkeys(root[n.lower()] for n in names if n.lower() in root))
    found = [(i, c) for i, c in enumerate(_probe_icon(ar, p) for p in order) if c is not None]
    if not found:  # App Store artwork at the archive root
        artwork = [p for p in _ARTWORK if p in ar.files]
        found = [(i, c) for i, c in enumerate(_probe_icon(ar, p) for p in artwork) if c is not None]
    found.sort(key=lambda item: (-item[1].width, item[0]))
    return [c for _, c in found]


def _inspect(ar: _Archive) -> IpaInfo:
    app = ar.app_dir
    main = ar.plist(app + "/Info.plist")

    plugins: List[Tuple[str, Dict[str, Any]]] = []
    others: List[Tuple[str, Dict[str, Any]]] = []
    extensions: List[Dict[str, Any]] = []
    for kind, sub in (("plugin", "PlugIns"), ("extensionkit", "Extensions")):
        for bundle in sorted(ar.children.get(app + "/" + sub, ())):
            if not bundle.lower().endswith(".appex"):
                continue
            info = ar.plist(bundle + "/Info.plist")
            extensions.append({"path": bundle, "bundle_id": _opt_text(info.get("CFBundleIdentifier")), "kind": kind})
            (plugins if kind == "plugin" else others).append((bundle, info))

    machos: Dict[str, Any] = {}
    for path in sorted(ar.files):
        if ar.files[path].file_size < 8 or not machomod.is_macho(ar.head(path, 8)):
            continue
        with ar.buffer(path) as buf:
            try:
                machos[path] = machomod.parse_macho(buf)
            except machomod.MachOError as exc:
                raise IpaError(exc.rule, exc.detail, path=path) from None
        if machos[path].entitlement_errors:  # facts that cannot be read cannot be shown to be clean
            raise IpaError("macho-entitlements-invalid", "undecodable DER entitlements", path=path)

    main_exe = _executable(ar, app, main, machos)
    plugin_exes = [_executable(ar, bundle, info, machos) for bundle, info in plugins]
    for bundle, info in others:
        _executable(ar, bundle, info, machos)

    # the union of the XML and DER keys of every slice: a key in either form is a key of the app
    main_ents = machos[main_exe].all_entitlements
    entitlements = {k for ents in main_ents for k in ents if isinstance(k, str)}
    for path in plugin_exes:
        entitlements.update(k for ents in machos[path].all_entitlements for k in ents if isinstance(k, str))
    entitlements -= IGNORED_ENTITLEMENTS
    task_allow = [ents["get-task-allow"] for ents in main_ents if "get-task-allow" in ents]
    if task_allow and all(value is False for value in task_allow):
        entitlements.discard("get-task-allow")

    name = _display_name(main)
    bundle_id = _text(main.get("CFBundleIdentifier"))
    executable = _text(main.get("CFBundleExecutable"))
    fallback = "Used by %s." % (name or executable or bundle_id or "the app")
    platforms = main.get("CFBundleSupportedPlatforms")
    paths = ar.all_paths()
    icons = icon_candidates(ar, main)
    return IpaInfo(
        bundle_id=bundle_id,
        short_version=_text(main.get("CFBundleShortVersionString")),
        build_version=_text(main.get("CFBundleVersion")),
        name=name,
        executable=executable,
        min_os=_opt_text(main.get("MinimumOSVersion")),
        platforms=[p for p in platforms if isinstance(p, str)] if isinstance(platforms, list) else [],
        app_dir=app,
        extensions=extensions,
        privacy=_privacy([main] + [info for _, info in plugins], fallback),
        entitlements=sorted(entitlements),
        signature=machomod.worst_signature(m.signature for m in machos.values()),
        team_ids=_team_ids(machos),
        provisioning_profiles=sorted(
            p for p in paths if p not in ar.dirs and p.lower().endswith((".mobileprovision", ".provisionprofile"))),
        code_signature_dirs=_component_dirs(paths, lambda c: c == "_CodeSignature"),
        localizations=sorted(d.rsplit("/", 1)[1] for d in ar.children.get(app, ()) if d.lower().endswith(".lproj")),
        dsym_like=_dsym_like(ar, paths, machos),
        icon=icons[0] if icons else None,
        macho_files=sorted(machos),
        macho_signatures={p: machos[p].signature for p in sorted(machos)},
        encrypted_macho_files=sorted(p for p, m in machos.items() if m.encrypted),
    )


# -- public API -----------------------------------------------------------------------------------

def inspect_ipa(path: str, *, limits: Optional[Limits] = None) -> IpaInfo:
    """Audit the archive at ``path`` and describe the app in it. Raises :class:`IpaError`."""
    with _open_archive(path, limits or Limits()) as ar:
        return _inspect(ar)


def audit_ipa(path: str, *, limits: Optional[Limits] = None) -> str:
    """Run only the archive audit; returns the app directory (``Payload/<X>.app``)."""
    with _open_archive(path, limits or Limits()) as ar:
        return ar.app_dir


def extract_icon(path: str, *, limits: Optional[Limits] = None) -> Optional[bytes]:
    """The best app icon as a standard PNG (CgBI converted and un-premultiplied), or None."""
    limits = limits or Limits()
    with _open_archive(path, limits) as ar:
        info = ar.plist(ar.app_dir + "/Info.plist")
        for icon in icon_candidates(ar, info):
            data = ar.read(icon.path, limits.max_icon_size, "zip-entry-size")
            try:
                return pngicon.to_png(data)
            except pngicon.PNGError:
                continue
    return None
