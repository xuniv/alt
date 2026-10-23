"""Generate and validate the AltStore source (``source.json``).

Inputs, all inside the repository:

- ``source.base.json``: source metadata plus ``defaults`` (developerName, category, tintColor) that
  the generator consumes but never emits;
- ``apps/<bid>/app.json``: curated app metadata and listing options;
- ``apps/<bid>/icon.png``: the app icon, published with the Pages site;
- ``apps/<bid>/versions/<semver>.json``: one record per published release, written by sync;
- ``site/icon.png``: the icon of last resort, so every app and the source always have an iconURL.

``apps/<bid>/retracted.json`` (tombstones of withdrawn versions, written by sync) is not an input:
the published releases, through their records, decide what is listed.

The output is strict JSON accepted by AltStore Classic, SideStore, Feather and LiveContainer. One
malformed app breaks the whole source in those clients, so :func:`validate_source` re-checks the
generated object against their decoding rules before anything is committed.
"""

from __future__ import annotations

import dataclasses
import datetime
import glob
import json
import math
import os
import re
import sys
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .tags import SemVer, TagError, is_valid_bid, make_tag

PAGES_BASE = "https://xuniv.github.io/alt"
SOURCE_URL = PAGES_BASE + "/source.json"
SITE_ICON = "icon.png"  # site/icon.png, deployed at the root of the Pages site
CATEGORIES = ("developer", "entertainment", "games", "lifestyle", "other", "photo-video", "social",
              "utilities")
DEFAULT_CATEGORY = "other"
DEFAULT_MAX_VERSIONS = 10
MAX_VERSIONS_LIMIT = 100
NOTES_LIMIT = 4000
SIZE_LIMIT = 2 ** 31 - 1  # the legacy app-level size is decoded as Int32

_HEX6 = re.compile(r"#?[0-9A-Fa-f]{6}")
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}")
_OS_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}")
_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})", re.ASCII)
_DATETIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})", re.ASCII)
_PRINTABLE_ASCII = re.compile(r"[\x21-\x7e]+")

Log = Callable[[str], None]


class SourceError(Exception):
    """An input file of the generator is unreadable or malformed."""

    rule = "source-input"


# -- shared format checks ----------------------------------------------------------------------------

def is_url(value: Any) -> bool:
    """Absolute ``http(s)`` URL made of printable ASCII, with a host and no user info."""
    if not isinstance(value, str) or not _PRINTABLE_ASCII.fullmatch(value) or "\\" in value:
        return False
    if not value.startswith(("https://", "http://")):
        return False
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # raises ValueError for a malformed port
    except ValueError:
        return False
    return bool(parts.hostname) and "@" not in parts.netloc


def is_hex_color(value: Any) -> bool:
    """Six hex digits with an optional leading ``#`` (3 and 8 digit forms differ between clients)."""
    return isinstance(value, str) and _HEX6.fullmatch(value) is not None


def is_date(value: Any) -> bool:
    """``YYYY-MM-DD`` or ``YYYY-MM-DDTHH:MM:SS`` plus ``Z``/``±HH:MM``; no fractional seconds."""
    if not isinstance(value, str):
        return False
    match = _DATETIME.fullmatch(value) or _DATE.fullmatch(value)
    if match is None:
        return False
    nums = [int(g) for g in match.groups()[:6]]
    try:
        datetime.datetime(*nums) if len(nums) == 6 else datetime.date(*nums)
    except ValueError:
        return False
    zone = match.groups()[6] if len(match.groups()) == 7 else "Z"
    return zone == "Z" or (int(zone[1:3]) <= 23 and int(zone[4:6]) <= 59)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _size_ok(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= SIZE_LIMIT


def dumps_source(obj: Any) -> bytes:
    """Canonical serialization (identical to the one sync uses for every generated file)."""
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# -- inputs -------------------------------------------------------------------------------------------

def _reject_constant(name: str) -> Any:
    raise ValueError("%s is not valid JSON" % name)


def _read_json(path: str, what: str) -> Any:
    """Parsed JSON at ``path``; None if the file does not exist; SourceError if it is malformed."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError:
        raise SourceError("%s cannot be read" % what) from None
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        raise SourceError("%s is not valid JSON" % what) from None


def _stderr_log(message: str) -> None:
    sys.stderr.write("warning: " + message + "\n")


@dataclasses.dataclass
class _Version:
    semver: SemVer
    tag: str
    version: str
    build: Optional[str]
    date: str
    notes: str
    url: str
    size: int
    sha256: str
    min_os: Optional[str]
    prerelease: bool
    name: str
    privacy: Dict[str, Any]
    entitlements: List[str]

    def entry(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"version": self.version}
        if self.build:
            out["buildVersion"] = self.build
        out["marketingVersion"] = str(self.semver)
        out["date"] = self.date
        out["localizedDescription"] = self.notes
        out["downloadURL"] = self.url
        out["size"] = self.size
        out["sha256"] = self.sha256
        if self.min_os:
            out["minOSVersion"] = self.min_os
        return out


def _record_version(record: Any, bid: str) -> Tuple[Optional[_Version], str]:
    """A record as a listable version, or (None, reason)."""
    if not isinstance(record, dict):
        return None, "not an object"
    if record.get("bundleIdentifier") != bid:
        return None, "bundleIdentifier does not match the directory"
    try:
        semver = SemVer(record.get("semver"))
        tag = make_tag(bid, semver)
    except TagError:
        return None, "semver does not fit the tag grammar"
    if record.get("tag") != tag:
        return None, "tag does not match bundleIdentifier and semver"
    version = record.get("version")
    if not _nonempty_str(version):
        return None, "version is missing"
    build = record.get("buildVersion")
    if build is not None and not isinstance(build, str):
        return None, "buildVersion is not a string"
    if not is_date(record.get("date")):
        return None, "date is missing or malformed"
    if not is_url(record.get("downloadURL")):
        return None, "downloadURL is not an absolute http(s) URL"
    if not _size_ok(record.get("size")):
        return None, "size is not a positive 32-bit integer"
    sha = record.get("sha256")
    if not isinstance(sha, str) or not _SHA256.fullmatch(sha):
        return None, "sha256 is not 64 hex digits"
    min_os = record.get("minOSVersion")
    if min_os is not None and not (isinstance(min_os, str) and _OS_VERSION.fullmatch(min_os)):
        return None, "minOSVersion is malformed"
    notes = record.get("localizedDescription")
    notes = notes.strip()[:NOTES_LIMIT].rstrip() if isinstance(notes, str) else ""
    privacy = record.get("privacy")
    entitlements = record.get("entitlements")
    name = record.get("name")
    return _Version(
        semver=semver,
        tag=tag,
        version=version,
        build=build or None,
        date=record["date"],
        notes=notes or "Version %s" % semver,
        url=record["downloadURL"],
        size=record["size"],
        sha256=sha.lower(),
        min_os=min_os or None,
        prerelease=bool(record.get("prerelease")) or semver.is_prerelease,
        name=name.strip() if _nonempty_str(name) else "",
        privacy=privacy if isinstance(privacy, dict) else {},
        entitlements=[e for e in entitlements if _nonempty_str(e)] if isinstance(entitlements, list) else [],
    ), ""


def _max_versions(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_VERSIONS_LIMIT:
        return value
    return DEFAULT_MAX_VERSIONS


def _listed_versions(bid: str, versions: List[_Version], app: Dict[str, Any], log: Log) -> List[_Version]:
    """Newest first by SemVer, prereleases dropped unless opted in, duplicates removed, capped."""
    include_pre = app.get("includePrereleases") is True
    if "maxVersions" in app and _max_versions(app["maxVersions"]) != app["maxVersions"]:
        log("apps/%s/app.json: maxVersions is invalid; using %d" % (bid, DEFAULT_MAX_VERSIONS))
    ordered = sorted((v for v in versions if include_pre or not v.prerelease),
                     key=lambda v: (v.semver, v.tag), reverse=True)
    seen: Dict[Tuple[str, Optional[str]], str] = {}
    unique: List[_Version] = []
    for v in ordered:
        pair = (v.version, v.build)
        if pair in seen:
            # clients identify a version by (version, buildVersion); a duplicate fails the source
            log("%s: %s repeats version %s build %s of %s; not listed" % (
                bid, v.tag, v.version, v.build or "-", seen[pair]))
            continue
        seen[pair] = v.tag
        unique.append(v)
    return unique[:_max_versions(app.get("maxVersions"))]


def _permissions(listed: Sequence[_Version], app_name: str) -> Dict[str, Any]:
    """Union over every listed version: clients check any installed IPA against the app-level set."""
    entitlements = sorted({e for v in listed for e in v.entitlements})
    privacy: Dict[str, str] = {}
    for v in listed:  # newest first: the newest usable description wins
        for key, text in v.privacy.items():
            if isinstance(key, str) and key and key not in privacy and _nonempty_str(text):
                privacy[key] = text
    for v in listed:
        for key in v.privacy:
            if isinstance(key, str) and key and key not in privacy:
                privacy[key] = "Used by %s." % app_name  # a missing description fails the source
    return {"entitlements": entitlements, "privacy": {k: privacy[k] for k in sorted(privacy)}}


def _pick(log: Log, where: str, key: str, candidates: Sequence[Any], check: Callable[[Any], bool]) -> Any:
    """First candidate that passes ``check``; an invalid curated value (the first) is reported."""
    for index, value in enumerate(candidates):
        if value is None:
            continue
        if check(value):
            return value
        if index == 0:
            log("%s: %s is invalid; using the default" % (where, key))
    return None


def _strip_str(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


def _build_app(bid: str, app: Dict[str, Any], listed: List[_Version], has_icon: bool, base: Dict[str, Any],
               defaults: Dict[str, Any], pages_base: str, log: Log) -> Dict[str, Any]:
    where = "apps/%s/app.json" % bid
    newest = listed[0]
    name = _pick(log, where, "name", [_strip_str(app.get("name")), newest.name, bid], _nonempty_str)
    developer = _pick(log, where, "developerName",
                      [_strip_str(app.get("developerName")), _strip_str(defaults.get("developerName")),
                       _strip_str(base.get("name"))], _nonempty_str) or name
    subtitle = _pick(log, where, "subtitle", [_strip_str(app.get("subtitle"))], _nonempty_str)
    description = _pick(log, where, "localizedDescription", [app.get("localizedDescription")],
                        _nonempty_str) or subtitle or name
    tint = _pick(log, where, "tintColor", [app.get("tintColor"), defaults.get("tintColor"),
                                           base.get("tintColor")], is_hex_color)
    category = _pick(log, where, "category", [app.get("category"), defaults.get("category")],
                     lambda c: isinstance(c, str) and c in CATEGORIES) or DEFAULT_CATEGORY
    icon = _pick(log, where, "iconURL", [app.get("iconURL")], is_url)
    if icon is None and has_icon:
        icon = "%s/apps/%s/icon.png" % (pages_base, bid)

    entry: Dict[str, Any] = {"name": name, "bundleIdentifier": bid, "developerName": developer}
    if subtitle:
        entry["subtitle"] = subtitle
    entry["localizedDescription"] = description
    entry["iconURL"] = icon  # None is replaced by the source or site icon by the caller
    if tint:
        entry["tintColor"] = tint.lstrip("#")
    entry["category"] = category
    shots = app.get("screenshots")
    if shots is not None:
        good = [s for s in shots if is_url(s)] if isinstance(shots, list) else []
        if not isinstance(shots, list) or len(good) != len(shots):
            log("%s: screenshots must be absolute http(s) URLs; invalid entries dropped" % where)
        if good:
            entry["screenshots"] = good
    entry["versions"] = [v.entry() for v in listed]
    entry["appPermissions"] = _permissions(listed, name)
    # legacy app-level fields mirror versions[0] for clients that predate ``versions``
    first = entry["versions"][0]
    entry["version"] = first["version"]
    entry["versionDate"] = first["date"]
    entry["versionDescription"] = first["localizedDescription"]
    entry["downloadURL"] = first["downloadURL"]
    entry["size"] = first["size"]
    return entry


def _app_dirs(root: str, log: Log) -> List[str]:
    apps = os.path.join(root, "apps")
    if not os.path.isdir(apps):
        return []
    out = []
    for name in sorted(os.listdir(apps)):
        if not os.path.isdir(os.path.join(apps, name)):
            continue
        if not is_valid_bid(name):
            log("apps/%s: not a bundle identifier; ignored" % name)
            continue
        out.append(name)
    return out


def _load_versions(root: str, bid: str, log: Log) -> List[_Version]:
    versions = []
    pattern = os.path.join(root, "apps", bid, "versions", "*.json")
    for path in sorted(glob.glob(pattern)):
        rel = "apps/%s/versions/%s" % (bid, os.path.basename(path))
        try:
            record = _read_json(path, rel)
        except SourceError as exc:
            log("%s: %s; skipped" % (rel, exc))
            continue
        version, reason = _record_version(record, bid)
        if version is None:
            log("%s: %s; skipped" % (rel, reason))
            continue
        versions.append(version)
    return versions


def generate_source(repo_root: str, *, pages_base: str = PAGES_BASE, log: Optional[Log] = None) -> Dict[str, Any]:
    """Build the source object from ``source.base.json`` and ``apps/`` under ``repo_root``.

    Records that cannot be listed are skipped and reported through ``log`` (default: stderr). An
    unreadable ``source.base.json`` or ``app.json`` raises :class:`SourceError` rather than being
    ignored, because ignoring it could list an app that is meant to be hidden.
    """
    log = log or _stderr_log
    root = os.path.abspath(repo_root)
    pages_base = pages_base.rstrip("/")
    base = _read_json(os.path.join(root, "source.base.json"), "source.base.json")
    if not isinstance(base, dict):
        raise SourceError("source.base.json is missing or not a JSON object")
    defaults = base.get("defaults") if isinstance(base.get("defaults"), dict) else {}

    apps: List[Dict[str, Any]] = []
    for bid in _app_dirs(root, log):
        app = _read_json(os.path.join(root, "apps", bid, "app.json"), "apps/%s/app.json" % bid)
        if app is None:
            app = {}
        if not isinstance(app, dict):
            raise SourceError("apps/%s/app.json must be a JSON object" % bid)
        if app.get("hidden", False) is not False:
            continue
        listed = _listed_versions(bid, _load_versions(root, bid, log), app, log)
        if not listed:
            continue
        has_icon = os.path.isfile(os.path.join(root, "apps", bid, "icon.png"))
        apps.append(_build_app(bid, app, listed, has_icon, base, defaults, pages_base, log))

    # Clients require an icon for the source and for every app, so one is always emitted. The source
    # icon is source.base.json's iconURL, else the first app with its own icon, else the site icon
    # (site/icon.png, deployed at the root of the Pages site); apps without an icon use the source
    # icon. An invalid curated iconURL is reported and replaced, like an invalid app.json value.
    base_icon = _pick(log, "source.base.json", "iconURL", [base.get("iconURL")], is_url)
    source_icon = (base_icon or next((a["iconURL"] for a in apps if a["iconURL"]), None)
                   or "%s/%s" % (pages_base, SITE_ICON))
    for app in apps:
        if app["iconURL"] is None:
            app["iconURL"] = source_icon

    out: Dict[str, Any] = {}
    for key in ("name", "identifier", "subtitle", "description"):
        if key in base:
            out[key] = base[key]
    out["iconURL"] = source_icon
    for key in ("headerURL", "website", "tintColor"):
        if key in base:
            out[key] = base[key]
    listed_ids = [a["bundleIdentifier"] for a in apps]
    featured = base.get("featuredApps")
    if isinstance(featured, list):
        keep = [b for b in dict.fromkeys(f for f in featured if isinstance(f, str)) if b in listed_ids]
        if keep:  # absent means "all apps"; an empty list would feature none
            out["featuredApps"] = keep
    elif featured is not None:
        log("source.base.json: featuredApps must be a list of bundle identifiers; ignored")
    out["apps"] = apps
    news = base.get("news")
    if isinstance(news, list):
        if news:
            out["news"] = news
    elif news is not None:
        out["news"] = news  # validate_source reports it
    return out


def write_source(repo_root: str, *, pages_base: str = PAGES_BASE, path: Optional[str] = None,
                 log: Optional[Log] = None) -> bool:
    """Write ``source.json`` (or ``path``) deterministically. Returns whether the bytes changed."""
    data = dumps_source(generate_source(repo_root, pages_base=pages_base, log=log))
    target = path or os.path.join(repo_root, "source.json")
    try:
        with open(target, "rb") as fh:
            if fh.read() == data:
                return False
    except FileNotFoundError:
        pass
    tmp = target + ".tmp-source"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, target)
    return True


# -- validation ---------------------------------------------------------------------------------------

class _Checker:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def error(self, where: str, message: str) -> None:
        self.errors.append("%s: %s" % (where, message) if where else message)

    def warn(self, where: str, message: str) -> None:
        self.warnings.append("warning: %s: %s" % (where, message) if where else "warning: " + message)

    # field helpers: ``required`` reports a missing key, otherwise only present keys are checked
    def string(self, obj: Dict[str, Any], key: str, where: str, *, required: bool = False,
               nonempty: bool = False) -> None:
        if key not in obj:
            if required:
                self.error(where, "%s is required" % key)
            return
        value = obj[key]
        if not isinstance(value, str):
            self.error(where, "%s must be a string" % key)
        elif nonempty and not value.strip():
            self.error(where, "%s must not be empty" % key)

    def url(self, obj: Dict[str, Any], key: str, where: str, *, required: bool = False) -> None:
        if key not in obj:
            if required:
                self.error(where, "%s is required" % key)
        elif not is_url(obj[key]):
            self.error(where, "%s must be an absolute http(s) URL" % key)

    def color(self, obj: Dict[str, Any], key: str, where: str) -> None:
        if key in obj and not is_hex_color(obj[key]):
            self.error(where, "%s must be 6 hex digits" % key)

    def date(self, obj: Dict[str, Any], key: str, where: str, *, required: bool = False) -> None:
        if key not in obj:
            if required:
                self.error(where, "%s is required" % key)
        elif not is_date(obj[key]):
            self.error(where, "%s must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ (no fractional seconds)" % key)

    def size(self, obj: Dict[str, Any], key: str, where: str, *, required: bool = False) -> None:
        if key not in obj:
            if required:
                self.error(where, "%s is required" % key)
        elif not _size_ok(obj[key]):
            self.error(where, "%s must be an integer between 1 and %d" % (key, SIZE_LIMIT))

    def boolean(self, obj: Dict[str, Any], key: str, where: str) -> None:
        if key in obj and not isinstance(obj[key], bool):
            self.error(where, "%s must be a boolean" % key)


def _json_types(value: Any, where: str, check: _Checker, depth: int = 0) -> None:
    """Only types a strict JSON decoder accepts: no NaN/Infinity, string keys, encodable strings."""
    if depth > 64:
        check.error(where, "nested too deeply")
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            check.error(where, "string is not valid Unicode")
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            check.error(where, "number must be finite")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_types(item, "%s[%d]" % (where, index), check, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                check.error(where, "object keys must be strings")
                continue
            _json_types(item, "%s.%s" % (where, key), check, depth + 1)
        return
    check.error(where, "%s is not a JSON type" % type(value).__name__)


def _check_screenshots(shots: Any, where: str, check: _Checker) -> None:
    def item(value: Any, label: str, need_size: bool) -> None:
        if isinstance(value, str):
            if not is_url(value):
                check.error(where, "%s must be an absolute http(s) URL" % label)
            elif need_size:
                check.error(where, "%s needs imageURL, width and height" % label)
            return
        if not isinstance(value, dict):
            check.error(where, "%s must be a URL or an object" % label)
            return
        if not is_url(value.get("imageURL")):
            check.error(where, "%s.imageURL must be an absolute http(s) URL" % label)
        for dim in ("width", "height"):
            if dim in value or need_size:
                n = value.get(dim)
                if not (isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 32767):
                    check.error(where, "%s.%s must be an integer between 1 and 32767" % (label, dim))

    if isinstance(shots, list):
        for index, value in enumerate(shots):
            item(value, "screenshots[%d]" % index, False)
    elif isinstance(shots, dict):
        for key in shots:
            if key not in ("iphone", "ipad"):
                check.error(where, "screenshots.%s is not iphone or ipad" % key)
        for device in ("iphone", "ipad"):
            if device not in shots:
                continue
            if not isinstance(shots[device], list):
                check.error(where, "screenshots.%s must be a list" % device)
                continue
            for index, value in enumerate(shots[device]):
                item(value, "screenshots.%s[%d]" % (device, index), device == "ipad")
    else:
        check.error(where, "screenshots must be a list or an object with iphone/ipad lists")


def _check_permissions(perms: Any, where: str, check: _Checker) -> None:
    if not isinstance(perms, dict):
        check.error(where, "appPermissions must be an object")
        return
    ents = perms.get("entitlements")
    if ents is not None:
        if isinstance(ents, list):
            for index, value in enumerate(ents):
                ok = _nonempty_str(value) or (isinstance(value, dict) and _nonempty_str(value.get("name")))
                if not ok:
                    check.error(where, "appPermissions.entitlements[%d] must be a non-empty string" % index)
        elif not isinstance(ents, dict):
            check.error(where, "appPermissions.entitlements must be a list of strings")
    privacy = perms.get("privacy")
    if privacy is None:
        return
    if isinstance(privacy, dict):
        for key, value in privacy.items():
            if not _nonempty_str(value):
                check.error(where, "appPermissions.privacy.%s must be a non-empty string" % key)
    elif isinstance(privacy, list):
        for index, value in enumerate(privacy):
            if not (isinstance(value, dict) and _nonempty_str(value.get("name"))
                    and _nonempty_str(value.get("usageDescription"))):
                check.error(where, "appPermissions.privacy[%d] needs name and a non-empty usageDescription"
                            % index)
    else:
        check.error(where, "appPermissions.privacy must be an object of strings")


def _check_version(v: Any, where: str, check: _Checker) -> None:
    if not isinstance(v, dict):
        check.error(where, "must be an object")
        return
    check.string(v, "version", where, required=True, nonempty=True)
    check.string(v, "buildVersion", where, nonempty=True)
    check.string(v, "marketingVersion", where, nonempty=True)
    check.date(v, "date", where, required=True)
    check.string(v, "localizedDescription", where)
    check.url(v, "downloadURL", where, required=True)
    check.size(v, "size", where, required=True)
    if "sha256" in v and not (isinstance(v["sha256"], str) and _SHA256.fullmatch(v["sha256"])):
        check.error(where, "sha256 must be 64 hex digits")
    for key in ("minOSVersion", "maxOSVersion"):
        if key in v and not (isinstance(v[key], str) and _OS_VERSION.fullmatch(v[key])):
            check.error(where, "%s must look like 15.0" % key)


def _check_versions(versions: Any, where: str, check: _Checker) -> None:
    if not isinstance(versions, list) or not versions:
        check.error(where, "versions must be a non-empty list")
        return
    pairs = set()
    semvers: List[Optional[SemVer]] = []
    for index, v in enumerate(versions):
        label = "%s: versions[%d]" % (where, index)
        _check_version(v, label, check)
        if not isinstance(v, dict):
            semvers.append(None)
            continue
        pair = (v.get("version"), v.get("buildVersion"))
        if all(isinstance(p, str) or p is None for p in pair):
            if pair in pairs:
                check.error(label, "repeats version %s build %s" % (pair[0], pair[1] or "-"))
            pairs.add(pair)
        try:
            semvers.append(SemVer(v.get("marketingVersion")))
        except TagError:
            semvers.append(None)
    if None not in semvers and any(not a > b for a, b in zip(semvers, semvers[1:])):
        check.error(where, "versions must be ordered newest first")


def _check_app(app: Any, where: str, check: _Checker) -> None:
    if not isinstance(app, dict):
        check.error(where, "must be an object")
        return
    for key in ("name", "bundleIdentifier", "developerName", "localizedDescription"):
        check.string(app, key, where, required=True, nonempty=True)
    check.url(app, "iconURL", where, required=True)
    check.string(app, "subtitle", where)
    check.color(app, "tintColor", where)
    if "category" in app and app["category"] not in CATEGORIES:
        check.error(where, "category must be one of %s" % ", ".join(CATEGORIES))
    if "marketplaceID" in app:
        check.error(where, "marketplaceID is not allowed (AltStore Classic and Feather reject the source)")
    if "permissions" in app:
        check.error(where, "the legacy permissions key is not allowed; use appPermissions")
    if "screenshots" in app:
        _check_screenshots(app["screenshots"], where, check)
    if "screenshotURLs" in app:
        urls = app["screenshotURLs"]
        if not isinstance(urls, list) or not all(is_url(u) for u in urls):
            check.error(where, "screenshotURLs must be a list of absolute http(s) URLs")
    check.boolean(app, "beta", where)
    _check_versions(app.get("versions"), where, check)
    if "appPermissions" in app:
        _check_permissions(app["appPermissions"], where, check)
    check.string(app, "version", where, nonempty=True)
    check.date(app, "versionDate", where)
    check.string(app, "versionDescription", where)
    check.url(app, "downloadURL", where)
    check.size(app, "size", where)


def _check_news(news: Any, check: _Checker, bids: Sequence[str]) -> None:
    if not isinstance(news, list):
        check.error("news", "must be a list")
        return
    seen = set()
    for index, item in enumerate(news):
        where = "news[%d]" % index
        if not isinstance(item, dict):
            check.error(where, "must be an object")
            continue
        for key in ("identifier", "title", "caption"):
            check.string(item, key, where, required=True, nonempty=True)
        ident = item.get("identifier")
        if isinstance(ident, str):
            if ident in seen:
                check.error(where, "identifier %s is not unique" % ident)
            seen.add(ident)
        check.date(item, "date", where, required=True)
        check.color(item, "tintColor", where)
        check.url(item, "imageURL", where)
        check.url(item, "url", where)
        check.string(item, "appID", where)
        check.boolean(item, "notify", where)
        if isinstance(item.get("appID"), str) and item["appID"] not in bids:
            check.warn(where, "appID %s is not listed" % item["appID"])


def validate_source(obj: Any) -> List[str]:
    """Problems that would make AltStore, SideStore or Feather reject the source.

    Returns error strings; entries starting with ``warning`` are advisory only.
    """
    check = _Checker()
    if not isinstance(obj, dict):
        return ["source must be a JSON object"]
    _json_types(obj, "source", check)
    check.string(obj, "name", "source", required=True, nonempty=True)
    check.string(obj, "identifier", "source", required=True, nonempty=True)
    check.string(obj, "subtitle", "source")
    check.string(obj, "description", "source")
    for key in ("iconURL", "headerURL", "website", "patreonURL"):
        check.url(obj, key, "source")
    check.color(obj, "tintColor", "source")
    if "marketplaceID" in obj:
        check.error("source", "marketplaceID is not allowed")
    if "version" in obj and (not isinstance(obj["version"], int) or isinstance(obj["version"], bool)):
        check.error("source", "version must be an integer")
    if "userInfo" in obj:
        info = obj["userInfo"]
        if not isinstance(info, dict) or not all(isinstance(v, str) for v in info.values()):
            check.error("source", "userInfo must be an object of strings")

    apps = obj.get("apps")
    bids: List[str] = []
    if not isinstance(apps, list):
        check.error("source", "apps must be a list")
        apps = []
    elif not apps:
        check.warn("", "source has no apps (Feather rejects an empty source)")
    for index, app in enumerate(apps):
        bid = app.get("bundleIdentifier") if isinstance(app, dict) else None
        where = "app %s" % bid if isinstance(bid, str) and bid else "apps[%d]" % index
        _check_app(app, where, check)
        if isinstance(bid, str):
            if bid in bids:
                check.error(where, "bundleIdentifier is not unique")
            bids.append(bid)

    featured = obj.get("featuredApps")
    if featured is not None:
        if not isinstance(featured, list) or not all(isinstance(f, str) for f in featured):
            check.error("source", "featuredApps must be a list of bundle identifiers")
        else:
            for bid in featured:
                if bid not in bids:
                    check.warn("source", "featured app %s is not listed" % bid)
    if "news" in obj:
        _check_news(obj["news"], check, bids)
    return check.errors + check.warnings
