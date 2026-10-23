"""Leak gate: decide whether an IPA may become public.

``scan_ipa`` streams every entry of the archive (bounded memory, with an overlap window so matches
spanning read boundaries are found) and searches the raw bytes, decoding nothing, for

- ``denylist``: each denylist literal, case-insensitively, as ASCII/UTF-8, UTF-16LE and UTF-16BE
  (NFC and NFD forms);
- ``home-path``: user home directories in the same three encodings. ``/Users/<x>/`` blocks;
  ``/home/<x>/`` and ``C:\\Users\\<x>\\`` only warn (they mostly come from third-party help text, and
  the hosted Linux runners build under ``/home/runner``). Well-known CI accounts and generic
  placeholder names (``user``, ``yourname``, ...) are not counted;
- ``ci-workspace-path`` (warn): the workspace of a hosted runner, ``/Users/runner/work/`` and
  ``/home/runner/work/``. A build of a checked-out repository records paths below
  ``<workspace>/<repository>/<repository>/``, so these hits can name a private repository; builds
  are expected to run from a generic directory or to map their source prefix away. The runner's
  own directories (``_temp``, ``_actions``, ``_tool``) name no repository and are not counted.

Entry names, entry comments, extra fields and the archive comment are searched as well. Structural
rules come from the entry names and from the inspection result (``ipa.inspect_ipa``): signatures,
provisioning profiles, ``_CodeSignature`` directories, entitlement files (``*.xcent``, which carry the
team identifier), ``iTunesMetadata.plist`` (the purchaser's account), debug symbols, VCS and Xcode
user data, Swift module sources and non-English localizations.

Results carry rule ids, severities, counts and up to five in-IPA paths per rule. Matched bytes are
never stored, returned or printed.
"""

from __future__ import annotations

import dataclasses
import importlib
import os
import re
import struct
import unicodedata
import zipfile
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .normalize import (
    DEFAULT_LIMITS,
    ArchiveError,
    ZipLimits,
    check_limits,
    entry_name,
    is_dir_entry,
    name_key,
    zip_library_errors,
)

CHUNK = 1 << 20
MAX_PATHS = 5
MAX_HOME_NAME = 64
BLOCK = "block"
WARN = "warn"
CI_ACCOUNTS = ("runner", "Shared", "builder", "runneradmin")
# generic names from documentation and help text. Forms such as ``<user>``, ``$USER``, ``${USER}`` and
# ``%USER%`` contain characters outside the name class and never match in the first place.
PLACEHOLDER_ACCOUNTS = ("user", "username", "me", "you", "yourname", "your_name", "name", "john", "jdoe",
                        "johndoe", "foo", "bar", "example", "test", "admin", "guest", "someone", "xxx")
ALLOWED_HOME_NAMES = CI_ACCOUNTS + PLACEHOLDER_ACCOUNTS  # matched case-insensitively, as a whole name
BLOCK_HOME_PREFIXES = ("/Users/",)
WARN_HOME_PREFIXES = ("/home/", ":\\Users\\")  # the drive letter is checked separately
CI_WORKSPACE_PREFIXES = ("/Users/runner/work/", "/home/runner/work/")
RUNNER_DIRS = ("_temp", "_actions", "_tool")  # below the workspace, but not a repository checkout
ENGLISH_LPROJ = re.compile(r"^(?:en(?:[-_][A-Za-z0-9]+)*|English|Base)$")
ZIP_COMMENT_PATH = "<zip-comment>"
ZIP_LAYOUT_PATH = "<zip-layout>"  # bytes outside the entries of the archive
DENYLIST_ENV = "ALT_DENYLIST"

# rule ids
DENYLIST = "denylist"
HOME_PATH = "home-path"
CI_WORKSPACE_PATH = "ci-workspace-path"
SIGNED = "signed"
SIGNATURE_UNKNOWN = "signature-unknown"
PROVISIONING_PROFILE = "provisioning-profile"
CODE_SIGNATURE_DIR = "code-signature-dir"
DSYM = "dsym"
VCS_DIR = "vcs-dir"
XCUSERDATA = "xcuserdata"
SWIFTSOURCEINFO = "swiftsourceinfo"
ITUNES_METADATA = "itunes-metadata"
XCENT = "xcent"
LOCALIZATION_NON_EN = "localization-non-en"
# counter key of the home paths that only warn; reported as rule ``home-path`` with severity warn
HOME_PATH_WARN = "home-path:warn"

SIGNATURE_STATES = ("none", "adhoc", "signed")
VCS_NAMES = frozenset((".git", ".svn", ".hg"))
_ASCII_LETTERS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_APP_RE = re.compile(r"^(Payload/[^/]+\.app)/", re.IGNORECASE)

# The text form of the home-path rule (release notes, metadata). Text written for a release is held
# to the stricter standard: every prefix counts.
HOME_PATH_RE = re.compile(
    r"(/Users/|/home/|[A-Za-z]:\\Users\\)(?!(?i:%s)[/\\])[A-Za-z0-9._-]{1,64}[/\\]"
    % "|".join(re.escape(name) for name in ALLOWED_HOME_NAMES))
CI_WORKSPACE_RE = re.compile("(?:%s)(?!(?:%s)/)" % ("|".join(re.escape(p) for p in CI_WORKSPACE_PREFIXES),
                                                    "|".join(re.escape(d) for d in RUNNER_DIRS)))


class GateError(Exception):
    """The gate cannot run (for example: the denylist is missing). Callers must fail closed."""

    def __init__(self, rule: str, message: str = ""):
        super().__init__(message or rule)
        self.rule = rule


class ScanError(ArchiveError):
    """The archive cannot be scanned (unsafe or damaged); treated as a gate rejection."""


@dataclasses.dataclass(frozen=True)
class GatePolicy:
    allow_home_paths: bool = False  # home paths become warnings (third-party ingest opt-in only)
    allow_empty_denylist: bool = False  # tests only


@dataclasses.dataclass
class GateResult:
    ok: bool
    findings: List[Dict[str, Any]]

    @property
    def blocking(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f["severity"] == BLOCK]

    @property
    def warnings(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f["severity"] == WARN]

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "findings": [dict(f, paths=list(f["paths"])) for f in self.findings]}


# -- denylist --------------------------------------------------------------------------------------

def clean_denylist(words: Optional[Iterable[str]]) -> List[str]:
    """Strip entries; drop blanks and ``#`` comments; keep order, drop duplicates."""
    out: List[str] = []
    for word in words or ():
        word = str(word).strip()
        if word and not word.startswith("#") and word not in out:
            out.append(word)
    return out


def load_denylist(path: Optional[str] = None, *, environ: Optional[Mapping[str, str]] = None) -> List[str]:
    """Denylist from the file ``path`` or env ``ALT_DENYLIST`` (newline separated); fail closed."""
    env = os.environ if environ is None else environ
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                text: Optional[str] = fh.read()
        except (OSError, UnicodeDecodeError):
            raise GateError("denylist-missing", "denylist file cannot be read") from None
    else:
        text = env.get(DENYLIST_ENV)
    words = clean_denylist((text or "").splitlines())
    if not words:
        raise GateError("denylist-missing", "denylist is missing or empty")
    return words


def _word_forms(word: str) -> List[str]:
    forms: List[str] = []
    for norm in ("NFC", "NFD"):
        base = unicodedata.normalize(norm, word)
        for form in (base, base.lower(), base.upper()):
            if form not in forms:
                forms.append(form)
    return forms


def denylist_literals(words: Sequence[str]) -> List[bytes]:
    """Byte literals (ASCII-lowercased) for every form and encoding of the denylist words.

    When every UTF-16 code unit of a form has a zero high byte (Latin-1 text), the UTF-16BE bytes
    without their first byte equal the UTF-16LE bytes without their last byte; that one literal
    finds both encodings and keeps the frequent NUL byte out of the pattern's first position.
    """
    lits = set()
    for word in clean_denylist(words):
        for form in _word_forms(word):
            try:
                lits.add(form.encode("utf-8").lower())
                le = form.encode("utf-16-le").lower()
                be = form.encode("utf-16-be").lower()
            except UnicodeEncodeError:  # lone surrogates
                continue
            if le[:-1] == be[1:]:
                lits.add(le[:-1])
            else:
                lits.update((le, be))
    return sorted(lits)


def _trie_regex(literals: Sequence[bytes]) -> Optional["re.Pattern[bytes]"]:
    """One regex matching any of ``literals`` (shared prefixes are factored out)."""
    if not literals:
        return None
    trie: Dict[Any, Any] = {}
    for lit in literals:
        node = trie
        for byte in lit:
            node = node.setdefault(byte, {})
        node[None] = {}

    def emit(node: Dict[Any, Any]) -> bytes:
        out = b""
        while True:
            # a literal ends here: longer literals sharing this prefix add nothing to a hit
            if None in node:
                return out
            children = sorted((k, v) for k, v in node.items() if k is not None)
            if len(children) != 1:
                break
            byte, node = children[0]  # single-child chains are emitted without recursion
            out += re.escape(bytes([byte]))
        alts = [re.escape(bytes([b])) + emit(child) for b, child in children]
        return out + b"(?:" + b"|".join(alts) + b")"

    return re.compile(emit(trie))


# -- byte matchers ---------------------------------------------------------------------------------

def _home_patterns() -> List[Tuple[str, "re.Pattern[bytes]", Optional[Callable[[bytes, int], bool]], int]]:
    """(counter key, pattern, accept, max length) for the home-path and ci-workspace-path rules.

    Each pattern starts with a literal so the regex engine can use its fast prefix search; the drive
    letter before ``:\\Users\\`` is checked by ``accept`` instead of in the pattern.
    """
    out = []
    for enc in ("8", "le", "be"):
        def unit(atom: bytes, enc: str = enc) -> bytes:
            if enc == "8":
                return atom
            return atom + rb"\x00" if enc == "le" else rb"\x00" + atom

        def lit(text: str, unit: Callable[[bytes], bytes] = unit, fold: bool = False) -> bytes:
            out = b""
            for c in text.encode("ascii"):
                ch = bytes([c])
                if fold and ch.isalpha():
                    out += unit(b"[" + ch.upper() + ch.lower() + b"]")
                else:
                    out += unit(re.escape(ch))
            return out

        width = 1 if enc == "8" else 2
        name = unit(rb"[A-Za-z0-9._-]")
        sep = unit(rb"[/\\]")
        allowed = b"(?!(?:" + b"|".join(lit(w, fold=True) for w in ALLOWED_HOME_NAMES) + b")" + sep + b")"
        rest = allowed + b"(?:" + name + b"){1,%d}" % MAX_HOME_NAME + sep
        for prefix in BLOCK_HOME_PREFIXES + WARN_HOME_PREFIXES:
            key = HOME_PATH if prefix in BLOCK_HOME_PREFIXES else HOME_PATH_WARN
            accept = _drive_letter(enc) if prefix.startswith(":") else None
            size = (len(prefix) + MAX_HOME_NAME + 1) * width
            out.append((key, re.compile(lit(prefix) + rest), accept, size))
        # runner accounts are allowed above; their workspace directory is counted on its own
        own = b"(?!(?:" + b"|".join(lit(d + "/") for d in RUNNER_DIRS) + b"))"
        longest = max(len(d) + 1 for d in RUNNER_DIRS)
        for prefix in CI_WORKSPACE_PREFIXES:
            out.append((CI_WORKSPACE_PATH, re.compile(lit(prefix) + own), None, (len(prefix) + longest) * width))
    return out


def _drive_letter(enc: str) -> Callable[[bytes, int], bool]:
    def accept(buf: bytes, start: int) -> bool:
        if enc == "8":
            return start >= 1 and buf[start - 1] in _ASCII_LETTERS
        if start < 2:
            return False
        if enc == "le":
            return buf[start - 2] in _ASCII_LETTERS and buf[start - 1] == 0
        return buf[start - 2] == 0 and buf[start - 1] in _ASCII_LETTERS
    return accept


_HOME = _home_patterns()
_CONTEXT = 2  # bytes kept before the scan window for the drive letter check


class Matcher:
    """Counts denylist, home-path and ci-workspace-path hits in byte streams; never keeps matched bytes.

    Counts are keyed by rule id, except that home paths which only warn are counted under
    ``HOME_PATH_WARN``.
    """

    def __init__(self, denylist: Sequence[str]):
        literals = denylist_literals(denylist)
        self.deny = _trie_regex(literals)
        longest = max([len(x) for x in literals] + [size for _, _, _, size in _HOME])
        self.overlap = longest + 8
        # (rule, pattern, accept, lowercase the data first)
        self.patterns: List[Tuple[str, "re.Pattern[bytes]", Optional[Callable[[bytes, int], bool]], bool]] = [
            (key, rx, accept, False) for key, rx, accept, _ in _HOME]
        if self.deny is not None:
            self.patterns.append((DENYLIST, self.deny, None, True))

    def scan_bytes(self, data: bytes) -> Dict[str, int]:
        return self.scan_chunks((data,))

    def scan_stream(self, fh: Any, chunk_size: int = CHUNK) -> Dict[str, int]:
        return self.scan_chunks(iter(lambda: fh.read(chunk_size), b""))

    def scan_chunks(self, chunks: Iterable[bytes]) -> Dict[str, int]:
        """Hit counts per rule over the concatenation of ``chunks``.

        Same result as one non-overlapping search per pattern over the whole data: a window of
        ``overlap`` bytes is carried to the next round, a match counts only when it starts before
        the window, and a pattern's search resumes after its previous match. Overlapping matches
        of one rule count once (UTF-16 text also matches the other byte order's pattern shifted
        by one byte).
        """
        counts: Dict[str, int] = {}
        resume = [0] * len(self.patterns)  # absolute offset where each pattern's search resumes
        covered: Dict[str, int] = {}  # absolute end of each rule's last counted match (cluster)
        carry = b""
        skip = 0  # leading bytes of ``buf`` that are context only
        base = 0  # absolute offset of buf[0]
        it = iter(chunks)
        eof = False
        while not eof:
            chunk = next(it, None)
            eof = chunk is None
            buf = carry + (chunk or b"")
            limit = len(buf) if eof else max(skip, len(buf) - self.overlap)
            if limit > skip:
                low = None
                spans: Dict[str, List[Tuple[int, int]]] = {}
                for i, (rule, rx, accept, lower) in enumerate(self.patterns):
                    if lower:
                        low = buf.lower() if low is None else low
                    data = low if lower else buf
                    pos = max(skip, resume[i] - base)
                    for m in rx.finditer(data, pos):
                        start = m.start()
                        if start >= limit:
                            break
                        if accept is not None and not accept(buf, start):
                            continue
                        end = base + max(m.end(), start + 1)
                        resume[i] = end
                        spans.setdefault(rule, []).append((base + start, end))
                for rule, found in spans.items():
                    for start, end in sorted(found):
                        if start < covered.get(rule, -1):
                            covered[rule] = max(covered[rule], end)
                            continue
                        counts[rule] = counts.get(rule, 0) + 1
                        covered[rule] = end
            keep = max(0, limit - _CONTEXT)
            carry = buf[keep:]
            skip = limit - keep
            base += keep
        return counts


# -- results ---------------------------------------------------------------------------------------

class _Findings:
    def __init__(self) -> None:
        self.counts: Dict[str, int] = {}
        self.paths: Dict[str, List[str]] = {}

    def add(self, rule: str, count: int = 1, path: Optional[str] = None) -> None:
        if count <= 0:
            return
        self.counts[rule] = self.counts.get(rule, 0) + count
        paths = self.paths.setdefault(rule, [])
        if path is not None and path not in paths and len(paths) < MAX_PATHS:
            paths.append(path)

    def merge(self, counts: Mapping[str, int], path: Optional[str]) -> None:
        for rule, count in counts.items():
            self.add(rule, count, path)

    def result(self, policy: Any) -> GateResult:
        allow_home = getattr(policy, "allow_home_paths", False)
        merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for key in sorted(self.counts):
            rule = HOME_PATH if key == HOME_PATH_WARN else key
            severity = BLOCK
            if rule in (LOCALIZATION_NON_EN, CI_WORKSPACE_PATH) or key == HOME_PATH_WARN or (
                    rule == HOME_PATH and allow_home):
                severity = WARN
            finding = merged.setdefault((rule, severity), {"rule": rule, "severity": severity, "count": 0,
                                                           "paths": []})
            finding["count"] += self.counts[key]
            for path in self.paths.get(key, []):
                if path not in finding["paths"] and len(finding["paths"]) < MAX_PATHS:
                    finding["paths"].append(path)
        findings = [merged[k] for k in sorted(merged, key=lambda k: (k[0], k[1] != BLOCK))]
        return GateResult(ok=not any(f["severity"] == BLOCK for f in findings), findings=findings)


# -- structural rules ------------------------------------------------------------------------------

def _get(info: Any, name: str, default: Any = None) -> Any:
    if isinstance(info, Mapping):
        return info.get(name, default)
    return getattr(info, name, default)


def _str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value if isinstance(value, str) else value.decode("utf-8", "replace")]
    out = []
    for item in value:
        if isinstance(item, Mapping):
            item = item.get("path", "")
        if item:
            out.append(str(item))
    return out


def _name_rules(name: str, is_dir: bool) -> List[str]:
    parts = name.rstrip("/").split("/")
    lowered = [p.lower() for p in parts]
    rules = []
    if lowered[-1].endswith((".mobileprovision", ".provisionprofile")) and not is_dir:
        rules.append(PROVISIONING_PROFILE)
    if "_CodeSignature" in parts:
        rules.append(CODE_SIGNATURE_DIR)
    if any(p.endswith(".dsym") for p in lowered) or (
            "dwarf" in lowered[:-1] and "resources" in lowered[:-1]):
        rules.append(DSYM)
    if any(p in VCS_NAMES for p in parts):
        rules.append(VCS_DIR)
    if "xcuserdata" in lowered or lowered[-1].endswith(".xcuserstate"):
        rules.append(XCUSERDATA)
    if lowered[-1].endswith(".swiftsourceinfo") or any(p.endswith(".swiftmodule") for p in lowered):
        rules.append(SWIFTSOURCEINFO)
    if lowered[-1] == "itunesmetadata.plist" and not is_dir:
        rules.append(ITUNES_METADATA)
    if lowered[-1].endswith(".xcent") and not is_dir:
        rules.append(XCENT)
    return rules


def _lproj_dirs(names: Iterable[str]) -> List[str]:
    """``Payload/X.app/<lang>.lproj/`` directories at an app root."""
    found = []
    for name in names:
        match = _APP_RE.match(name)
        if not match:
            continue
        rest = name[len(match.group(0)):].split("/")
        if rest[0].lower().endswith(".lproj") and len(rest) > 1:
            path = match.group(0) + rest[0] + "/"
            if path not in found:
                found.append(path)
    return found


def _lang(lproj: str) -> str:
    base = lproj.rstrip("/").rsplit("/", 1)[-1]
    return base[:-6] if base.lower().endswith(".lproj") else base


def _signed_paths(info: Any) -> List[str]:
    """In-IPA paths of signed Mach-O files when the inspection result lists them per file."""
    for key in ("signatures", "macho_signatures"):
        mapping = _get(info, key)
        if isinstance(mapping, Mapping):
            return sorted((str(p) for p, state in mapping.items() if state == "signed"), key=name_key)
    return []


def _structural(findings: _Findings, names: Sequence[Tuple[str, bool]], info: Any) -> None:
    for name, is_dir in names:
        for rule in _name_rules(name, is_dir):
            findings.add(rule, 1, name)
    for rule, key in ((PROVISIONING_PROFILE, "provisioning_profiles"),
                      (CODE_SIGNATURE_DIR, "code_signature_dirs"),
                      (DSYM, "dsym_like")):
        for path in _str_list(_get(info, key)):
            if path not in findings.paths.get(rule, []):
                findings.add(rule, 1, path)

    signature = _get(info, "signature")
    team_ids = _str_list(_get(info, "team_ids"))
    if signature == "signed" or team_ids:
        signed = _signed_paths(info)
        findings.add(SIGNED, max(1, len(signed)))
        findings.paths[SIGNED] = signed[:MAX_PATHS]
    elif signature not in SIGNATURE_STATES:
        findings.add(SIGNATURE_UNKNOWN, 1)

    lproj = _lproj_dirs(name for name, _ in names)
    app_dir = str(_get(info, "app_dir") or "").rstrip("/")
    langs = {_lang(p) for p in lproj}
    for loc in _str_list(_get(info, "localizations")):
        if _lang(loc) not in langs:
            langs.add(_lang(loc))
            lproj.append("%s/%s.lproj/" % (app_dir, _lang(loc)) if app_dir else loc)
    for path in lproj:
        if not ENGLISH_LPROJ.match(_lang(path)):
            findings.add(LOCALIZATION_NON_EN, 1, path)


def _inspect(path: str) -> Any:
    try:
        ipa = importlib.import_module((__package__ or "altsource") + ".ipa")
    except ImportError:
        raise GateError("gate-unavailable", "IPA inspection is not available") from None
    return ipa.inspect_ipa(path)


# -- public API ------------------------------------------------------------------------------------

def scan_ipa(path: str, *, denylist: Sequence[str], policy: Any = None, info: Any = None,
             limits: Optional[ZipLimits] = None) -> GateResult:
    """Run every gate rule on the IPA at ``path``.

    ``info`` is the inspection result (``IpaInfo`` or its dict) used by the structural rules; when
    omitted the IPA is inspected here. Raises ``GateError`` when the denylist is empty (unless the
    policy allows it), ``ScanError``/``zipfile.BadZipFile`` when the archive cannot be read, and the
    inspection's ``IpaError`` when inspection rejects the IPA.
    """
    policy = policy if policy is not None else GatePolicy()
    words = clean_denylist(denylist)
    if not words and not getattr(policy, "allow_empty_denylist", False):
        raise GateError("denylist-missing", "denylist is missing or empty")
    if info is None:
        info = _inspect(path)
    matcher = Matcher(words)
    findings = _Findings()
    names: List[Tuple[str, bool]] = []
    with zip_library_errors(ScanError), zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        check_limits(infos, limits or DEFAULT_LIMITS, ScanError)
        decoded = [(entry_name(zi, ScanError), zi) for zi in infos]
        decoded.sort(key=lambda item: name_key(item[0]))
        if zf.comment:
            findings.merge(matcher.scan_bytes(zf.comment), ZIP_COMMENT_PATH)
        for name, zi in decoded:
            is_dir = is_dir_entry(zi, name)
            names.append((name, is_dir))
            findings.merge(matcher.scan_bytes(name.encode("utf-8")), name)
            if zi.filename != name:  # a Unicode path extra field names the entry differently
                findings.merge(matcher.scan_bytes(zi.filename.encode("utf-8", "replace")), name)
            for meta in (zi.comment, zi.extra):
                if meta:
                    findings.merge(matcher.scan_bytes(meta), name)
            with zf.open(zi) as fh:  # directories too: AltStore ignores their data, a download does not
                findings.merge(matcher.scan_stream(fh), name)
        labels = {id(zi): name for name, zi in decoded}
        with open(path, "rb") as raw:
            for start, end, zi in _raw_regions(raw, infos, zf.start_dir):
                label = labels[id(zi)] if zi is not None else ZIP_LAYOUT_PATH
                findings.merge(matcher.scan_stream(_Region(raw, start, end)), label)
    _structural(findings, names, info)
    return findings.result(policy)


class _Region:
    """File-like view of ``fh[start:end]``."""

    def __init__(self, fh: Any, start: int, end: int):
        self.fh = fh
        self.pos = start
        self.end = end

    def read(self, n: int) -> bytes:
        n = min(n, self.end - self.pos)
        if n <= 0:
            return b""
        self.fh.seek(self.pos)
        data = self.fh.read(n)
        self.pos += len(data)
        return data


def _raw_regions(fh: Any, infos: Sequence[zipfile.ZipInfo], start_dir: int) -> List[Tuple[int, int, Any]]:
    """Byte ranges of the archive that no entry accounts for, plus local header extra fields.

    Entry data is scanned decompressed and central directory fields are scanned one by one; what
    remains is prepended data, gaps between entries, data descriptors, local extra fields, anything
    between the central directory and the end record, and bytes after the archive comment.
    Returns (start, end, ZipInfo or None).
    """
    size = fh.seek(0, os.SEEK_END)
    regions: List[Tuple[int, int, Any]] = []
    pos = 0
    for zi in sorted(infos, key=lambda z: z.header_offset):
        offset = zi.header_offset
        if offset > pos:
            regions.append((pos, offset, None))
        fh.seek(offset)
        head = fh.read(30)
        if len(head) < 30 or head[:4] != b"PK\x03\x04":
            raise ScanError("zip-layout", "local header missing")
        name_len, extra_len = struct.unpack("<HH", head[26:30])
        if extra_len:
            regions.append((offset + 30 + name_len, offset + 30 + name_len + extra_len, zi))
        pos = max(pos, offset + 30 + name_len + extra_len + zi.compress_size)
    if start_dir > pos:
        regions.append((pos, start_dir, None))
    cd_end = start_dir
    for zi in infos:
        encoding = "utf-8" if zi.flag_bits & 0x800 else "cp437"
        cd_end += 46 + len(zi.orig_filename.encode(encoding, "replace")) + len(zi.extra) + len(zi.comment)
    tail_start = max(0, size - (1 << 16) - 22)
    fh.seek(tail_start)
    tail = fh.read()
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or len(tail) - eocd < 22:
        raise ScanError("zip-layout", "end record missing")
    eocd += tail_start
    if eocd > cd_end:
        regions.append((cd_end, eocd, None))
    comment_len = struct.unpack("<H", tail[eocd - tail_start + 20:eocd - tail_start + 22])[0]
    after = eocd + 22 + comment_len
    if size > after:
        regions.append((after, size, None))
    return regions


def scan_bytes(data: bytes, denylist: Sequence[str]) -> List[str]:
    """Rule ids (``denylist``, ``home-path``, ``ci-workspace-path``) that hit in ``data``, whatever
    their severity."""
    return sorted({HOME_PATH if key == HOME_PATH_WARN else key for key in Matcher(denylist).scan_bytes(data)})


def scan_text(text: str, denylist: Sequence[str]) -> List[str]:
    """Rule ids (``denylist``, ``home-path``, ``ci-workspace-path``) that hit in a metadata string
    such as release notes.

    The denylist match is case-insensitive and Unicode-normalized. An empty denylist only checks
    the path rules; callers that need the fail-closed check use ``scan_ipa`` or ``load_denylist``.
    """
    text = text or ""
    rules = []
    folded = unicodedata.normalize("NFC", text).casefold()
    for word in clean_denylist(denylist):
        if unicodedata.normalize("NFC", word).casefold() in folded:
            rules.append(DENYLIST)
            break
    nfc = unicodedata.normalize("NFC", text)
    if HOME_PATH_RE.search(text) or HOME_PATH_RE.search(nfc):
        rules.append(HOME_PATH)
    if CI_WORKSPACE_RE.search(text) or CI_WORKSPACE_RE.search(nfc):
        rules.append(CI_WORKSPACE_PATH)
    return sorted(rules)
