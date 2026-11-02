"""Pick the Xcode for a ``major.minor`` request (``.alt.json`` format 2).

The newest release of that minor wins; without one, the newest release candidate. Betas are never
picked. An app is a release candidate or a beta when its real (symlink-resolved) bundle name says so,
as the runner images name them (``Xcode_27.2_Release_Candidate.app``, ``Xcode_27.1_beta_2.app``).
"""

from __future__ import annotations

import dataclasses
import os
import plistlib
import re
from typing import Iterable, List, Optional, Tuple

RELEASE = "release"
RELEASE_CANDIDATE = "release candidate"
BETA = "beta"
_RC_RE = re.compile(r"(?i)(release[ _-]?candidate|(^|[ _.-])rc\d*($|[ _.-]))")
_BETA_RE = re.compile(r"(?i)beta")
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")
_BUILD_RE = re.compile(r"^(\d+)([A-Z])(\d+)([a-z]?)$")


class XcodeError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Xcode:
    path: str  # the real path of the app bundle
    version: str  # CFBundleShortVersionString
    build: str  # ProductBuildVersion
    kind: str

    def describe(self) -> str:
        return "Xcode %s (%s%s)" % (self.version, self.build, "" if self.kind == RELEASE else ", " + self.kind)


def kind_of(name: str) -> str:
    stem = name[:-4] if name.lower().endswith(".app") else name
    if _BETA_RE.search(stem):
        return BETA
    if _RC_RE.search(stem):
        return RELEASE_CANDIDATE
    return RELEASE


def _version_key(version: str) -> Tuple[int, int, int]:
    match = _VERSION_RE.match(version)
    if not match:
        return (-1, -1, -1)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def _build_key(build: str) -> Tuple[int, str, int, str]:
    match = _BUILD_RE.match(build)
    if not match:
        return (-1, "", -1, "")
    return (int(match.group(1)), match.group(2), int(match.group(3)), match.group(4))


def choose(apps: Iterable[Xcode], want: str) -> Xcode:
    """The Xcode for ``want`` (``major.minor``) among ``apps``; raises XcodeError."""
    match = re.match(r"^(\d+)\.(\d+)$", want or "")
    if not match:
        raise XcodeError("the requested Xcode must be major.minor, such as 27.2")
    major, minor = int(match.group(1)), int(match.group(2))
    candidates = [a for a in apps if _version_key(a.version)[:2] == (major, minor) and a.kind != BETA]
    for kind in (RELEASE, RELEASE_CANDIDATE):
        found = [a for a in candidates if a.kind == kind]
        if found:
            return max(found, key=lambda a: (_version_key(a.version), _build_key(a.build), a.path))
    raise XcodeError("no release or release candidate of Xcode %s is installed" % want)


def read_app(path: str) -> Optional[Xcode]:
    """The facts of the Xcode bundle at ``path`` (symlinks resolved), or None."""
    real = os.path.realpath(path)
    try:
        with open(os.path.join(real, "Contents", "version.plist"), "rb") as fh:
            info = plistlib.load(fh)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    version = info.get("CFBundleShortVersionString")
    build = info.get("ProductBuildVersion")
    if not isinstance(version, str) or not isinstance(build, str):
        return None
    return Xcode(path=real, version=version, build=build, kind=kind_of(os.path.basename(real)))


def installed(applications: str = "/Applications") -> List[Xcode]:
    """Every Xcode bundle under ``applications`` once (symlinks lead to their target)."""
    seen = {}
    try:
        names = sorted(os.listdir(applications))
    except OSError:
        return []
    for name in names:
        if not (name.startswith("Xcode") and name.endswith(".app")):
            continue
        app = read_app(os.path.join(applications, name))
        if app is not None:
            seen.setdefault(app.path, app)
    return list(seen.values())
