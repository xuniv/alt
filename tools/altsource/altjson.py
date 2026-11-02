"""The private repository's ``.alt.json``.

Format 1 (no ``version`` key) is a bare build section: ``runner``, ``xcode``, ``setup``, ``command``,
``ipa_glob``, ``env``. The registered configuration (secret ``ALT_APP``) overrides its keys.

Format 2 (``"version": 2``) is the repository's own, complete configuration; alt keeps only the
registration (which repository, and the branch that holds the policy) and its global invariants:

- ``build``: the format 1 keys; ``xcode`` is ``major.minor`` (the newest release of that minor on the
  runner, else its release candidate). Read from the tag that is built.
- ``gate``: ``homeUsers``, the build accounts of prebuilt third-party code inside the IPA. Their
  ``/Users/<name>/`` paths only warn. Read from the tag; the exception travels with the release.
- ``scope``: which tags ``poll.yml`` builds by itself: ``tagPattern``, ``minVersion``,
  ``prereleases`` (``skip`` or ``build``) and ``auto``. Read from the policy branch (``policyRef`` of
  the registration, default the repository's default branch), so that it can change without a tag.

Nothing here can relax the denylist, the structural gate rules or a withdrawal. Error messages name
keys of the private file only when ``reveal`` is set.
"""

from __future__ import annotations

import dataclasses
import json
import re
from typing import Any, Dict, Optional, Tuple

from .leaks import check_home_users
from .tags import SemVer

FORMAT_2 = 2
TOP_KEYS = ("version", "build", "gate", "scope")
BUILD_KEYS = ("runner", "xcode", "setup", "command", "ipa_glob", "env")
GATE_KEYS = ("homeUsers",)
SCOPE_KEYS = ("tagPattern", "minVersion", "prereleases", "auto")
PRERELEASE_MODES = ("skip", "build")
XCODE_MINOR_RE = re.compile(r"^\d{1,3}\.\d{1,3}$")
MAX_PATTERN = 512
MAX_BYTES = 64 * 1024
POLICY_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


class AltJsonError(ValueError):
    """The file cannot be used; the message never quotes its values."""


@dataclasses.dataclass(frozen=True)
class Scope:
    tag_pattern: Optional[str] = None
    min_version: Optional[str] = None
    prereleases: str = "skip"
    auto: bool = True


@dataclasses.dataclass(frozen=True)
class AltJson:
    format: int
    build: Dict[str, Any]
    home_users: Tuple[str, ...] = ()
    scope: Optional[Scope] = None


def _names(keys: Any, reveal: bool) -> str:
    return (": " + ", ".join(sorted(str(k) for k in keys))) if reveal else ""


def _object(obj: Any, what: str, allowed: Tuple[str, ...], reveal: bool) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise AltJsonError("%s must be a JSON object" % what)
    unknown = [k for k in obj if k not in allowed]
    if unknown:
        raise AltJsonError("%s has %d unknown key(s)%s" % (what, len(unknown), _names(unknown, reveal)))
    return obj


def check_tag_pattern(pattern: Any, what: str = "scope.tagPattern") -> str:
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_PATTERN:
        raise AltJsonError("%s must be a regular expression of at most %d characters" % (what, MAX_PATTERN))
    try:
        compiled = re.compile(pattern)
    except re.error:
        raise AltJsonError("%s is not a valid regular expression" % what) from None
    if "version" not in compiled.groupindex:
        raise AltJsonError("%s needs a named group 'version'" % what)
    return pattern


def check_policy_ref(ref: Any) -> str:
    if not isinstance(ref, str) or not POLICY_REF_RE.match(ref) or ".." in ref or "//" in ref \
            or ref.endswith(("/", ".", ".lock")) or "@{" in ref:
        raise AltJsonError("policyRef must be a branch name")
    return ref


def parse_scope(obj: Any, reveal: bool = False) -> Scope:
    obj = _object(obj, "scope", SCOPE_KEYS, reveal)
    pattern = check_tag_pattern(obj["tagPattern"]) if "tagPattern" in obj else None
    floor = obj.get("minVersion")
    if floor is not None:
        try:
            SemVer(floor)
        except (TypeError, ValueError):
            raise AltJsonError("scope.minVersion must be a semver such as 1.2.3") from None
    mode = obj.get("prereleases", "skip")
    if mode not in PRERELEASE_MODES:
        raise AltJsonError("scope.prereleases must be one of %s" % ", ".join(PRERELEASE_MODES))
    auto = obj.get("auto", True)
    if not isinstance(auto, bool):
        raise AltJsonError("scope.auto must be true or false")
    return Scope(tag_pattern=pattern, min_version=floor, prereleases=mode, auto=auto)


def parse(obj: Any, reveal: bool = False) -> AltJson:
    """Validate a decoded ``.alt.json`` of either format."""
    if not isinstance(obj, dict):
        raise AltJsonError(".alt.json must be a JSON object")
    if "version" not in obj:
        unknown = [k for k in obj if k not in BUILD_KEYS]
        if unknown:
            raise AltJsonError(".alt.json has %d unknown key(s)%s" % (len(unknown), _names(unknown, reveal)))
        return AltJson(format=1, build=dict(obj))
    if obj["version"] != FORMAT_2 or isinstance(obj["version"], bool):
        raise AltJsonError(".alt.json version must be 2")
    _object(obj, ".alt.json", TOP_KEYS, reveal)
    build = dict(_object(obj.get("build"), "build", BUILD_KEYS, reveal)) if "build" in obj else {}
    if "xcode" in build and not (isinstance(build["xcode"], str) and XCODE_MINOR_RE.match(build["xcode"])):
        raise AltJsonError("build.xcode must be major.minor, such as 27.2")
    users: Tuple[str, ...] = ()
    if "gate" in obj:
        gate = _object(obj["gate"], "gate", GATE_KEYS, reveal)
        if "homeUsers" in gate:
            try:
                users = check_home_users(gate["homeUsers"])
            except ValueError:
                raise AltJsonError("gate.homeUsers must be a list of at most 16 account names "
                                   "(letters, digits, . _ -)") from None
    scope = parse_scope(obj["scope"], reveal) if "scope" in obj else None
    return AltJson(format=FORMAT_2, build=build, home_users=users, scope=scope)


def loads(raw: bytes, reveal: bool = False) -> AltJson:
    if len(raw) > MAX_BYTES:
        raise AltJsonError(".alt.json is too large")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AltJsonError(".alt.json is not valid JSON") from None
    return parse(obj, reveal)


def load(path: str, reveal: bool = False) -> AltJson:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError:
        raise AltJsonError(".alt.json cannot be read") from None
    return loads(raw, reveal)
