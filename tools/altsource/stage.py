"""Pre-publication gate shared by every route: inspect, normalize, scan, then draft and publish.

Nothing is sent to GitHub before the gate has passed. Besides the IPA bytes, the gate checks every
text that becomes public in decoded form: the release tag, title, target, notes and asset file name,
the app.json keys and values, and the facts the catalog lists from the inspection (app name, bundle
identifier, versions, privacy keys and descriptions, entitlement keys). Escapes in JSON or XML
entities in a property list therefore cannot hide a denylist term. Labels of reused assets are
cleared, because GitHub shows a label in place of the file name.

The inspection, normalization, scanning and tag helpers are resolved lazily through
:class:`Toolkit`, so callers and tests can inject their own.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import os
import re
import tempfile
import time
import unicodedata
import zipfile
import zlib
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

APP_JSON_MAX_BYTES = 64 * 1024
# title prefix of drafts the gate has blocked; ``stage-draft --all`` leaves them alone
BLOCKED_MARK = "[blocked] "
# title prefix of drafts withdrawn with ``bin/alt retract --unpublish``; ``stage-draft --all`` leaves
# them alone as well, whether or not sync has listed the version in retracted.json yet
WITHDRAWN_MARK = "[withdrawn] "
# a damaged archive surfaces as one of these from any reader (inspection, normalization, scanning).
# The readers map zipfile's UnicodeDecodeError (a bad UTF-8 name) and NotImplementedError (an
# unsupported zip feature) to their own errors; both are listed here as well, so that an injected or
# future reader that lets them through still gets the release rejected rather than the run aborted.
ARCHIVE_ERRORS: Tuple[type, ...] = (zipfile.BadZipFile, zlib.error, EOFError, UnicodeDecodeError,
                                    NotImplementedError)
NOTES_PATH = "<release-notes>"
TAG_PATH = "<release-tag>"
TITLE_PATH = "<release-title>"
TARGET_PATH = "<release-target>"
ASSET_NAME_PATH = "<asset-name>"
ASSET_VERIFY_ATTEMPTS = 5
# path rules that the home-path opt-in (app.json ``allowHomePaths``) turns into warnings for text
# taken from the IPA; text written for a release (tag, title, notes, asset name) always blocks
PATH_RULES = frozenset({"home-path", "ci-workspace-path"})

# name -> (module inside the package, attribute)
_BINDINGS: Dict[str, Tuple[str, str]] = {
    "inspect_ipa": ("ipa", "inspect_ipa"),
    "extract_icon": ("ipa", "extract_icon"),
    "IpaError": ("ipa", "IpaError"),
    "normalize_ipa": ("normalize", "normalize_ipa"),
    "NormalizeError": ("normalize", "NormalizeError"),
    "scan_ipa": ("leaks", "scan_ipa"),
    "scan_text": ("leaks", "scan_text"),
    "GatePolicy": ("leaks", "GatePolicy"),
    "GateError": ("leaks", "GateError"),
    "parse_tag": ("tags", "parse_tag"),
    "make_tag": ("tags", "make_tag"),
    "SemVer": ("tags", "SemVer"),
    "core_matches": ("tags", "core_matches"),
    "alias_for": ("tags", "alias_for"),
    "TagError": ("tags", "TagError"),
    "generate_source": ("source", "generate_source"),
    "validate_source": ("source", "validate_source"),
    "fetch": ("fetch", "fetch"),
    "FetchError": ("fetch", "FetchError"),
}


class Toolkit:
    """Late-bound access to the sibling modules; keyword overrides replace single functions."""

    def __init__(self, **overrides: Any):
        self.__dict__.update(overrides)

    def __getattr__(self, name: str) -> Any:
        try:
            module, attr = _BINDINGS[name]
        except KeyError:
            raise AttributeError(name) from None
        mod = importlib.import_module("." + module, __package__)
        value = getattr(mod, attr)
        self.__dict__[name] = value
        return value


def errors_of(deps: Any, *names: str) -> Tuple[type, ...]:
    """Exception classes among ``names`` that ``deps`` provides (missing ones are skipped)."""
    found = []
    for name in names:
        try:
            cls = getattr(deps, name)
        except (AttributeError, ImportError):
            continue
        if isinstance(cls, type) and issubclass(cls, BaseException):
            found.append(cls)
    return tuple(found)


class StageError(Exception):
    """Staging failed for a reason other than the gate (bad input, GitHub failure)."""


class GateRejected(StageError):
    """The gate blocked the IPA or its metadata. ``findings`` lists rule ids, counts and paths."""

    def __init__(self, message: str, findings: Sequence[Dict[str, Any]] = ()):
        super().__init__(message)
        self.findings = [dict(f) for f in findings]


class Conflict(StageError):
    """A published release with the same tag carries a different asset."""


@dataclasses.dataclass
class StageResult:
    tag: str
    release_id: Optional[int]
    asset: Optional[str]
    sha256: str
    size: int
    published: bool
    noop: bool
    asset_id: Optional[int] = None
    download_url: Optional[str] = None
    bundle_id: str = ""
    semver: str = ""
    normalized_changed: bool = False
    warnings: List[Dict[str, Any]] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# -- small helpers --------------------------------------------------------------------------------

def field(obj: Any, name: str, default: Any = None) -> Any:
    """Read ``name`` from a mapping or an object."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str, fallback: str = "App") -> str:
    """ASCII-fold ``name`` to ``[A-Za-z0-9._-]`` for asset file names."""
    folded = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode("ascii")
    folded = re.sub(r"[^A-Za-z0-9._-]+", "-", folded).strip("-._")
    return folded or fallback


def app_name(info: Any, bid: str) -> str:
    """The app name used in release titles and asset names: display name, else executable, else ``bid``."""
    return str(field(info, "name", "") or field(info, "executable", "") or bid)


def ipa_asset_name(name: str, bid: str, semver: str) -> str:
    """``<SafeName>-<semver>.ipa``: the file name of every IPA the gate publishes."""
    return "%s-%s.ipa" % (safe_name(name, safe_name(bid)), semver)


def normalize_short_version(short_version: str) -> str:
    """CFBundleShortVersionString "1.2" -> "1.2.0". Raises ValueError for non-numeric versions."""
    parts = (short_version or "").strip().split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() and p.isascii() for p in parts):
        raise ValueError("short version is not numeric X[.Y[.Z]]")
    nums = [str(int(p)) for p in parts] + ["0"] * (3 - len(parts))
    return ".".join(nums)


def parse_semver(deps: Any, text: str) -> Any:
    cls = deps.SemVer
    parse = getattr(cls, "parse", None)
    return parse(text) if callable(parse) else cls(text)


def is_semver(text: Any) -> bool:
    """Whether ``text`` is a version that a tag may carry (``MAJOR.MINOR.PATCH[-PRERELEASE]``)."""
    from .tags import SemVer  # no Toolkit: app.json validation has no dependencies to replace

    if not isinstance(text, str):
        return False
    try:
        SemVer(text)
    except (TypeError, ValueError):
        return False
    return True


def semver_prerelease(deps: Any, text: str) -> bool:
    return bool(field(parse_semver(deps, text), "prerelease"))


def core_matches(deps: Any, semver: str, short_version: str) -> bool:
    try:
        return bool(deps.core_matches(semver, short_version))
    except (AttributeError, TypeError):
        return bool(deps.core_matches(parse_semver(deps, semver), short_version))


def finding_dicts(findings: Any) -> List[Dict[str, Any]]:
    out = []
    for f in findings or []:
        paths = field(f, "paths", None) or []
        out.append({
            "rule": str(field(f, "rule", "unknown")),
            "severity": str(field(f, "severity", "block")),
            "count": int(field(f, "count", 1) or 1),
            "paths": [str(p) for p in list(paths)[:5]],
        })
    return out


def blocking(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in findings if f.get("severity") != "warn"]


def rule_of(exc: BaseException, default: str) -> str:
    for attr in ("rule", "rule_id"):
        value = getattr(exc, attr, None)
        if isinstance(value, str) and re.match(r"^[a-z0-9][a-z0-9_.-]*$", value):
            return value
    return default


def single_finding(rule: str, path: Optional[str] = None) -> Dict[str, Any]:
    return {"rule": rule, "severity": "block", "count": 1, "paths": [path] if path else []}


def text_findings(deps: Any, text: str, denylist: Sequence[str], where: str) -> List[Dict[str, Any]]:
    if not text:
        return []
    rules = deps.scan_text(text, list(denylist)) or []
    counts: Dict[str, int] = {}
    for rule in rules:
        rule = str(field(rule, "rule", rule))
        counts[rule] = counts.get(rule, 0) + 1
    return [{"rule": r, "severity": "block", "count": n, "paths": [where]} for r, n in sorted(counts.items())]


def value_strings(value: Any) -> List[str]:
    """Every string in a JSON-like value: dictionary keys and string leaves, in document order."""
    out: List[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                stack.append(child)
                stack.append(key)
        elif isinstance(item, (list, tuple)):
            stack.extend(reversed(item))
    return out


def value_findings(deps: Any, value: Any, denylist: Sequence[str], where: str, *,
                   relaxed: bool = False) -> List[Dict[str, Any]]:
    """Findings (one per rule, counts only) for every decoded string in ``value``.

    ``relaxed`` (the home-path opt-in) makes the path rules warnings.
    """
    counts: Dict[str, int] = {}
    for text in value_strings(value):
        for f in text_findings(deps, text, denylist, where):
            counts[f["rule"]] = counts.get(f["rule"], 0) + f["count"]
    return [{"rule": r, "severity": "warn" if relaxed and r in PATH_RULES else "block", "count": n,
             "paths": [where]} for r, n in sorted(counts.items())]


def info_texts(info: Any, bid: str) -> List[Tuple[str, Any]]:
    """(label, value) of every inspection fact that the catalog makes public."""
    privacy = field(info, "privacy", None)
    return [
        ("<app-name>", app_name(info, bid)),
        ("<bundle-id>", str(field(info, "bundle_id", "") or "")),
        ("<version>", [str(field(info, key, "") or "") for key in ("short_version", "build_version", "min_os")]),
        ("<privacy>", dict(privacy) if isinstance(privacy, dict) else {}),
        ("<entitlements>", [str(e) for e in field(info, "entitlements", None) or []]),
    ]


def info_findings(deps: Any, info: Any, bid: str, denylist: Sequence[str], *,
                  relaxed: bool = False) -> List[Dict[str, Any]]:
    """Findings for the decoded inspection facts that become public (see :func:`info_texts`)."""
    out: List[Dict[str, Any]] = []
    for where, value in info_texts(info, bid):
        out += value_findings(deps, value, denylist, where, relaxed=relaxed)
    return out


def tag_findings(deps: Any, tag: str, denylist: Sequence[str]) -> List[Dict[str, Any]]:
    return text_findings(deps, tag, denylist, TAG_PATH)


def is_ipa_asset(asset: Dict[str, Any]) -> bool:
    return str(asset.get("name", "")).lower().endswith(".ipa")


# -- app.json validation (shared with sync and the CLI) -------------------------------------------

CATEGORIES = ("developer", "entertainment", "games", "lifestyle", "other", "photo-video", "social",
              "utilities")
_HEX6 = re.compile(r"^[0-9A-Fa-f]{6}$")
_URL = re.compile(r"^https?://[^\s/?#]+[^\s]*$")
_STR_KEYS = ("name", "developerName", "subtitle", "localizedDescription")
_BOOL_KEYS = ("includePrereleases", "hidden", "allowHomePaths")
APP_JSON_KEYS = frozenset(_STR_KEYS + _BOOL_KEYS + ("category", "tintColor", "iconURL", "screenshots",
                                                    "maxVersions", "privateBuild", "allowHomeUsers"))
SEED_KEYS = ("name", "developerName", "subtitle", "localizedDescription", "category", "tintColor",
             "iconURL", "screenshots", "allowHomePaths")


def validate_app_json(obj: Any) -> List[str]:
    """Errors for an ``apps/<bid>/app.json`` object (strict: unknown keys are errors)."""
    if not isinstance(obj, dict):
        return ["app.json must be a JSON object"]
    errors = []
    for key in sorted(obj):
        if key not in APP_JSON_KEYS:
            errors.append("unknown key %s" % key)
    for key in _STR_KEYS:
        if key in obj and (not isinstance(obj[key], str) or not obj[key].strip()):
            errors.append("%s must be a non-empty string" % key)
    for key in _BOOL_KEYS:
        if key in obj and not isinstance(obj[key], bool):
            errors.append("%s must be a boolean" % key)
    if "category" in obj and obj["category"] not in CATEGORIES:
        errors.append("category must be one of %s" % ", ".join(CATEGORIES))
    if "tintColor" in obj and not (isinstance(obj["tintColor"], str) and _HEX6.match(obj["tintColor"])):
        errors.append("tintColor must be 6 hex digits without #")
    if "iconURL" in obj and not (isinstance(obj["iconURL"], str) and _URL.match(obj["iconURL"])):
        errors.append("iconURL must be an absolute http(s) URL")
    if "screenshots" in obj:
        shots = obj["screenshots"]
        if not isinstance(shots, list) or not all(isinstance(s, str) and _URL.match(s) for s in shots):
            errors.append("screenshots must be a list of absolute http(s) URLs")
    if "maxVersions" in obj:
        value = obj["maxVersions"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
            errors.append("maxVersions must be an integer between 1 and 100")
    if "privateBuild" in obj:
        errors.extend(_validate_private_build(obj["privateBuild"]))
    if "allowHomeUsers" in obj:
        from .leaks import check_home_users  # no Toolkit: app.json validation has no dependencies to replace

        try:
            check_home_users(obj["allowHomeUsers"])
        except ValueError:
            errors.append("allowHomeUsers must be a list of at most 16 account names (letters, digits, . _ -)")
    return errors


def _validate_private_build(pb: Any) -> List[str]:
    if not isinstance(pb, dict):
        return ["privateBuild must be an object"]
    errors = []
    for key in sorted(pb):
        if key not in ("enabled", "tagPattern", "minVersion", "windowed"):
            errors.append("unknown key privateBuild.%s" % key)
    for key in ("enabled", "windowed"):
        if key in pb and not isinstance(pb[key], bool):
            errors.append("privateBuild.%s must be a boolean" % key)
    if "minVersion" in pb and not is_semver(pb["minVersion"]):
        errors.append("privateBuild.minVersion must be a semver such as 1.2.3")
    if "tagPattern" in pb:
        pattern = pb["tagPattern"]
        try:
            compiled = re.compile(pattern) if isinstance(pattern, str) else None
        except re.error:
            compiled = None
        if compiled is None or "version" not in compiled.groupindex:
            errors.append("privateBuild.tagPattern must be a regex with a named group 'version'")
    return errors


def check_app_json_text(deps: Any, raw: bytes, denylist: Sequence[str]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse + validate + leak-scan an app.json payload. Returns (object or None, findings)."""
    if len(raw) > APP_JSON_MAX_BYTES:
        return None, [single_finding("app-json-size", "app.json")]
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        return None, [single_finding("app-json-invalid", "app.json")]
    if validate_app_json(obj):
        return None, [single_finding("app-json-invalid", "app.json")]
    findings = text_findings(deps, text, denylist, "app.json")
    # the decoded keys and values are what the catalog shows; JSON escapes do not hide a term
    raw_rules = {f["rule"] for f in findings}
    findings += [f for f in value_findings(deps, obj, denylist, "app.json") if f["rule"] not in raw_rules]
    return (None if findings else obj), findings


# -- the gate -------------------------------------------------------------------------------------

@dataclasses.dataclass
class _Gated:
    tag: str
    bid: str
    semver: str
    prerelease: bool
    name: str
    title: str
    path: str
    sha256: str
    size: int
    changed: bool
    asset_name: str
    warnings: List[Dict[str, Any]]
    extra_assets: List[Tuple[str, str, str]]


def _gate(ipa_path: str, tmp: str, *, expected_bid: Optional[str], semver: Optional[str], notes: str,
          denylist: Sequence[str], policy: Any, deps: Any, app_json: Optional[str], target: str = "") -> _Gated:
    ipa_errors = errors_of(deps, "IpaError") + ARCHIVE_ERRORS
    tag_errors = errors_of(deps, "TagError") + (ValueError,)
    gate_errors = errors_of(deps, "GateError")

    try:
        info = deps.inspect_ipa(ipa_path)
    except ipa_errors as exc:
        raise GateRejected("IPA rejected", [single_finding(rule_of(exc, "ipa-invalid"))]) from None
    bid = str(field(info, "bundle_id", "") or "")
    short = str(field(info, "short_version", "") or "")
    if not bid:
        raise GateRejected("IPA has no bundle identifier", [single_finding("bundle-id-missing")])
    if expected_bid and expected_bid != bid:
        raise GateRejected("bundle identifier does not match", [single_finding("bundle-id-mismatch")])

    if semver:
        try:
            parse_semver(deps, semver)
        except tag_errors:
            raise StageError("invalid semver") from None
    else:
        try:
            semver = normalize_short_version(short)
        except ValueError:
            raise GateRejected("version cannot be derived from the IPA",
                               [single_finding("version-mismatch")]) from None
    if not core_matches(deps, semver, short):
        raise GateRejected("semver does not match CFBundleShortVersionString",
                           [single_finding("version-mismatch")])
    try:
        tag = deps.make_tag(bid, semver)
    except tag_errors:
        raise GateRejected("bundle identifier or version does not fit the tag grammar",
                           [single_finding("tag-grammar")]) from None

    normalized = os.path.join(tmp, "normalized.ipa")
    norm_errors = ipa_errors + errors_of(deps, "NormalizeError")
    try:
        deps.normalize_ipa(ipa_path, normalized)
    except norm_errors as exc:
        raise GateRejected("IPA cannot be normalized", [single_finding(rule_of(exc, "normalize"))]) from None
    try:
        info2 = deps.inspect_ipa(normalized)
    except ipa_errors as exc:
        raise GateRejected("normalized IPA rejected", [single_finding(rule_of(exc, "ipa-invalid"))]) from None
    if str(field(info2, "bundle_id", "")) != bid or str(field(info2, "short_version", "")) != short:
        raise GateRejected("normalization changed the app identity", [single_finding("normalize-mismatch")])

    name = app_name(info2, bid)
    asset_name = ipa_asset_name(name, bid, semver)
    title = "%s %s" % (name, semver)
    relaxed = bool(getattr(policy, "allow_home_paths", False))
    try:
        result = deps.scan_ipa(normalized, denylist=list(denylist), policy=policy, info=info2)
        findings = finding_dicts(field(result, "findings", []))
        ok = bool(field(result, "ok", not blocking(findings)))
        # every text that GitHub or the catalog shows, as it will be shown
        findings += tag_findings(deps, tag, denylist)
        findings += text_findings(deps, title, denylist, TITLE_PATH)
        findings += text_findings(deps, asset_name, denylist, ASSET_NAME_PATH)
        findings += text_findings(deps, target, denylist, TARGET_PATH)
        findings += text_findings(deps, notes, denylist, NOTES_PATH)
        findings += info_findings(deps, info2, bid, denylist, relaxed=relaxed)
    except gate_errors as exc:
        raise StageError("gate unavailable (%s)" % rule_of(exc, "gate-error")) from None
    except ipa_errors as exc:  # the scanner reads every entry; inspection does not
        raise GateRejected("IPA cannot be scanned", [single_finding(rule_of(exc, "ipa-invalid"))]) from None

    seed: Optional[Dict[str, Any]] = None
    seed_raw: Optional[bytes] = None
    if app_json is not None:
        with open(app_json, "rb") as fh:
            raw = fh.read(APP_JSON_MAX_BYTES + 1)
        seed, app_findings = check_app_json_text(deps, raw, denylist)
        findings += app_findings
        seed_raw = raw if seed is not None else None

    blocks = blocking(findings)
    if blocks or not ok:
        raise GateRejected("gate rejected the IPA", findings)

    allowed_home = getattr(policy, "allow_home_paths", False)
    if allowed_home and any(f["rule"] == "home-path" for f in findings) \
            and (seed or {}).get("allowHomePaths") is not True:
        # sync scans published releases again; the opt-in has to travel with the release. Without the
        # opt-in, home-path findings that passed are warnings by rule and need no app.json.
        seed = dict(seed or {})
        seed["allowHomePaths"] = True
        seed_raw = (json.dumps(seed, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    extra: List[Tuple[str, str, str]] = []
    if seed_raw is not None:
        seed_path = os.path.join(tmp, "app.json")
        with open(seed_path, "wb") as fh:
            fh.write(seed_raw)
        extra.append((seed_path, "app.json", "application/json"))

    digest = sha256_file(normalized)
    return _Gated(
        tag=tag,
        bid=bid,
        semver=semver,
        prerelease=semver_prerelease(deps, semver),
        name=name,
        title=title,
        path=normalized,
        sha256=digest,
        size=os.path.getsize(normalized),
        changed=sha256_file(ipa_path) != digest,
        asset_name=asset_name,
        warnings=[f for f in findings if f.get("severity") == "warn"],
        extra_assets=extra,
    )


def _default_gh() -> Any:
    from . import gh as ghmod

    return ghmod.client()


def _result(gated: _Gated, *, release_id=None, asset=None, published=False, noop=False) -> StageResult:
    return StageResult(
        tag=gated.tag,
        release_id=release_id,
        asset=field(asset, "name") if asset else gated.asset_name,
        sha256=gated.sha256,
        size=gated.size,
        published=published,
        noop=noop,
        asset_id=field(asset, "id") if asset else None,
        download_url=field(asset, "browser_download_url") if asset else None,
        bundle_id=gated.bid,
        semver=gated.semver,
        normalized_changed=gated.changed,
        warnings=gated.warnings,
    )


def _verify_upload(gh: Any, release_id: int, want: str, sleep: Callable[[float], None], *,
                   asset_id: Optional[int] = None, name: Optional[str] = None) -> Tuple[Dict[str, Any], List[Any]]:
    """Poll the asset list until the IPA (by id, else by name) is ``uploaded`` with digest ``want``.

    A just-uploaded asset can briefly be listed as ``starter`` or without a digest. Returns the asset
    and the listing it was found in.
    """
    for attempt in range(ASSET_VERIFY_ATTEMPTS):
        assets = gh.list_assets(release_id)
        if asset_id is not None:
            found = [a for a in assets if a.get("id") == asset_id]
        else:
            found = [a for a in assets if _same_name(a.get("name"), name)]
        if len(found) == 1 and found[0].get("state") == "uploaded":
            digest = found[0].get("digest")
            if digest == want:
                return found[0], assets
            if digest:
                break
        if attempt + 1 < ASSET_VERIFY_ATTEMPTS:
            sleep(2.0)
    raise StageError("uploaded asset could not be verified")


def _same_name(a: Any, b: Any) -> bool:
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


def _set_aside_name(asset: Dict[str, Any]) -> str:
    """Temporary name for an asset that is replaced; it no longer ends in ``.ipa``."""
    return "%s.stale-%d" % (asset.get("name") or "asset", int(asset["id"]))


def _undo(gh: Any, release_id: int, *, created: bool, before: Sequence[int],
          renamed: Sequence[Tuple[int, str]]) -> None:
    """Best-effort rollback of a failed upload: never lose what the release carried before."""
    try:
        if created:
            gh.delete_release(release_id)
            return
        for asset in gh.list_assets(release_id):
            if asset.get("id") not in before:
                gh.delete_asset(asset["id"])
        for asset_id, original in renamed:
            gh.update_asset(asset_id, name=original)
    except Exception:  # the original error is the one worth reporting
        pass


def _release(gated: _Gated, *, gh: Any, existing: Optional[Dict[str, Any]], notes: str, publish: bool,
             target: str, sleep: Callable[[float], None]) -> StageResult:
    rel = existing if existing is not None else gh.get_release_by_tag(gated.tag)
    want = "sha256:" + gated.sha256
    title = gated.title

    if rel is not None and not rel.get("draft"):
        for asset in rel.get("assets") or []:
            if is_ipa_asset(asset) and asset.get("state") == "uploaded" and asset.get("digest") == want:
                return _result(gated, release_id=rel["id"], asset=asset, published=True, noop=True)
        raise Conflict("%s is already published with a different asset" % gated.tag)

    created = rel is None
    if created:
        rel = gh.create_draft(gated.tag, target, title, notes, gated.prerelease)
        current: List[Dict[str, Any]] = []
    else:
        current = list(gh.list_assets(int(rel["id"])))
    release_id = int(rel["id"])

    # what the release must carry: the normalized IPA plus extra assets such as app.json
    wanted = [(gated.path, gated.asset_name, "application/octet-stream", want)]
    wanted += [(p, n, ct, "sha256:" + sha256_file(p)) for p, n, ct in gated.extra_assets]
    keep: Dict[str, Dict[str, Any]] = {}
    stale: List[Dict[str, Any]] = []
    for asset in current:
        uploaded = asset.get("state") == "uploaded"
        if uploaded and is_ipa_asset(asset) and asset.get("digest") == want and gated.asset_name not in keep:
            keep[gated.asset_name] = asset
            continue
        match = [n for _, n, _, d in wanted[1:] if _same_name(asset.get("name"), n) and asset.get("digest") == d]
        if uploaded and match and match[0] not in keep:
            keep[match[0]] = asset
            continue
        stale.append(asset)
    uploads = [(p, n, ct) for p, n, ct, _ in wanted if n not in keep]

    # upload and verify first; stale assets (possibly the only copy of an upload) go last
    before = [a.get("id") for a in current]
    renamed: List[Tuple[int, str]] = []
    try:
        for asset in [a for a in stale if a.get("state") != "uploaded"]:
            gh.delete_asset(asset["id"])  # an unfinished upload holds no content, only its name
            stale.remove(asset)
        taken = [n for _, n, _ in uploads]
        ipa = keep.get(gated.asset_name)
        if ipa is not None and not _same_name(ipa.get("name"), gated.asset_name):
            taken.append(gated.asset_name)
        for asset in stale:
            if any(_same_name(asset.get("name"), n) for n in taken):
                gh.update_asset(asset["id"], name=_set_aside_name(asset))
                renamed.append((int(asset["id"]), str(asset.get("name"))))
        for kept in keep.values():
            changes: Dict[str, Any] = {}
            if kept is ipa and not _same_name(kept.get("name"), gated.asset_name):
                changes["name"] = gated.asset_name  # the permanent download URL uses it
            if kept.get("label"):
                changes["label"] = ""  # shown in place of the file name, and never checked
            if changes:
                gh.update_asset(kept["id"], **changes)
        ipa_id = ipa.get("id") if ipa is not None else None
        for path, name, content_type in uploads:
            response = gh.upload_asset(release_id, path, name, content_type)
            if name == gated.asset_name:
                ipa_id = field(response, "id", None) if response else None
        asset, listing = _verify_upload(gh, release_id, want, sleep, asset_id=ipa_id, name=gated.asset_name)
    except Exception:
        _undo(gh, release_id, created=created, before=before, renamed=renamed)
        raise

    for old in stale:
        gh.delete_asset(old["id"])
    gone = {a.get("id") for a in stale}
    remaining = [a for a in listing if a.get("id") not in gone]
    allowed = {n.lower() for _, n, _ in gated.extra_assets}
    if len([a for a in remaining if is_ipa_asset(a)]) != 1 or any(
            not is_ipa_asset(a) and str(a.get("name", "")).lower() not in allowed for a in remaining):
        raise StageError("%s carries unexpected assets; not published" % gated.tag)
    if any(a.get("label") for a in remaining):
        raise StageError("%s carries asset labels; not published" % gated.tag)
    if not created:
        gh.update_release(release_id, name=title, body=notes, prerelease=gated.prerelease,
                          target_commitish=target, tag_name=gated.tag)
    if publish:
        published = gh.publish(release_id, prerelease=gated.prerelease, make_latest="false")
        got = published.get("tag_name") if isinstance(published, dict) else None
        if got is not None and got != gated.tag:
            fixed = gh.update_release(release_id, tag_name=gated.tag)
            got = fixed.get("tag_name") if isinstance(fixed, dict) else None
            if got is not None and got != gated.tag:
                raise StageError("%s was published under a different tag" % gated.tag)
    return _result(gated, release_id=release_id, asset=asset, published=publish)


def stage(
    ipa_path: str,
    *,
    expected_bid: Optional[str] = None,
    semver: Optional[str] = None,
    notes: str = "",
    denylist: Sequence[str],
    policy: Any = None,
    publish: bool = True,
    dry_run: bool = False,
    target: str = "main",
    app_json: Optional[str] = None,
    gh: Any = None,
    deps: Any = None,
    sleep: Callable[[float], None] = time.sleep,
    _existing: Optional[Dict[str, Any]] = None,
) -> StageResult:
    """Gate ``ipa_path`` and, unless ``dry_run``, publish it as release ``<bid>-v<semver>``."""
    deps = deps if deps is not None else Toolkit()
    if policy is None:
        policy = deps.GatePolicy()
    notes = (notes or "").strip()
    with tempfile.TemporaryDirectory(prefix="alt-stage-") as tmp:
        gated = _gate(ipa_path, tmp, expected_bid=expected_bid, semver=semver, notes=notes,
                      denylist=denylist, policy=policy, deps=deps, app_json=app_json, target=target)
        if dry_run:
            return _result(gated)
        gh = gh if gh is not None else _default_gh()
        return _release(gated, gh=gh, existing=_existing, notes=notes, publish=publish, target=target,
                        sleep=sleep)


def stage_existing_draft(
    tag: str,
    *,
    notes: Optional[str] = None,
    denylist: Sequence[str],
    policy: Any = None,
    publish: bool = True,
    dry_run: bool = False,
    target: str = "main",
    gh: Any = None,
    deps: Any = None,
    sleep: Callable[[float], None] = time.sleep,
) -> StageResult:
    """Download the single .ipa of the release ``tag`` (normally a draft) and run :func:`stage` on it."""
    deps = deps if deps is not None else Toolkit()
    gh = gh if gh is not None else _default_gh()
    try:
        bid, semver = deps.parse_tag(tag)
    except errors_of(deps, "TagError") + (ValueError,):
        raise StageError("tag does not match the grammar") from None
    leaky_tag = blocking(tag_findings(deps, tag, denylist))
    rel = gh.get_release_by_tag(tag)
    if leaky_tag:  # neither a message nor a title may repeat the tag
        if rel is not None and rel.get("draft") and not dry_run:
            mark_blocked(gh, rel, "release %d" % int(rel["id"]))
        raise GateRejected("release tag rejected", leaky_tag)
    if rel is None:
        raise StageError("no release uses tag %s" % tag)
    assets = gh.list_assets(int(rel["id"]))
    ipas = [a for a in assets if is_ipa_asset(a)]
    if len(ipas) != 1 or ipas[0].get("state") != "uploaded":
        raise StageError("%s must carry exactly one uploaded .ipa asset" % tag)
    seeds = [a for a in assets if a.get("name") == "app.json" and a.get("state") == "uploaded"]
    body = notes if notes is not None else (rel.get("body") or "")
    with tempfile.TemporaryDirectory(prefix="alt-draft-") as tmp:
        source = os.path.join(tmp, "input.ipa")
        gh.download_asset(int(ipas[0]["id"]), source)
        digest = ipas[0].get("digest")
        if digest and digest != "sha256:" + sha256_file(source):
            raise StageError("downloaded asset does not match its digest")
        app_json = None
        if len(seeds) == 1 and int(seeds[0].get("size") or 0) <= APP_JSON_MAX_BYTES:
            app_json = os.path.join(tmp, "app.json")
            gh.download_asset(int(seeds[0]["id"]), app_json)
        try:
            return stage(source, expected_bid=bid, semver=str(semver), notes=body, denylist=denylist,
                         policy=policy, publish=publish, dry_run=dry_run, target=target, app_json=app_json,
                         gh=gh, deps=deps, sleep=sleep, _existing=rel)
        except GateRejected:
            if rel.get("draft") and not dry_run:
                mark_blocked(gh, rel, tag)
            raise


def mark_blocked(gh: Any, rel: Dict[str, Any], tag: str) -> None:
    """Retitle a blocked draft so scheduled runs skip it; staging it by tag clears the mark.

    ``tag`` is the text after the mark: the tag, or a neutral label when the tag itself is rejected.
    """
    if str(rel.get("name") or "").startswith(BLOCKED_MARK):
        return
    try:
        gh.update_release(int(rel["id"]), name=BLOCKED_MARK + tag)
    except Exception:  # the rejection itself is what gets reported
        pass


def draft_tags(gh: Any, deps: Any = None) -> Tuple[List[str], List[str]]:
    """(pending, blocked) tags of draft releases that follow the tag grammar, oldest first.

    Drafts marked withdrawn are in neither list.
    """
    deps = deps if deps is not None else Toolkit()
    tag_errors = errors_of(deps, "TagError") + (ValueError,)
    pending: List[str] = []
    blocked: List[str] = []
    for rel in sorted(gh.list_releases(), key=lambda r: int(r.get("id", 0))):
        if not rel.get("draft"):
            continue
        tag = str(rel.get("tag_name") or "")
        try:
            deps.parse_tag(tag)
        except tag_errors:
            continue
        name = str(rel.get("name") or "")
        if name.startswith(WITHDRAWN_MARK):
            continue
        bucket = blocked if name.startswith(BLOCKED_MARK) else pending
        if tag not in pending and tag not in blocked:
            bucket.append(tag)
    return pending, blocked


def pending_drafts(gh: Any, deps: Any = None) -> List[str]:
    """Tags of draft releases that follow the tag grammar and are marked neither blocked nor withdrawn,
    oldest first."""
    return draft_tags(gh, deps)[0]
