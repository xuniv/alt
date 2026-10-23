"""Release tag grammar ``<bundle id>-v<semver>`` and SemVer 2.0 precedence.

A tag splits at the last ``-v`` that is followed by a valid version: the bundle id part is matched
greedily. Bundle ids that contain ``-v<digit>`` are refused, which makes every accepted tag
unambiguous; :func:`make_tag` additionally checks that its result parses back to its inputs.
Build metadata (``+build``) is not allowed in tags.
"""

from __future__ import annotations

import functools
import re
from typing import Any, Optional, Tuple, Union

SEMVER_PATTERN = (r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                  r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
BID_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"

TAG_RE = re.compile(r"^(?P<bid>" + BID_PATTERN + r")-v(?P<ver>" + SEMVER_PATTERN + r")$", re.ASCII)
SEMVER_RE = re.compile(r"(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
                       r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", re.ASCII)
BID_RE = re.compile(BID_PATTERN, re.ASCII)
_AMBIGUOUS = re.compile(r"-v[0-9]")


class TagError(ValueError):
    """A tag, bundle id or version does not follow the grammar."""

    rule = "tag-grammar"


@functools.total_ordering
class SemVer:
    """A ``MAJOR.MINOR.PATCH[-PRERELEASE]`` version ordered by SemVer 2.0 precedence.

    Numeric prerelease identifiers with leading zeros are refused (SemVer 2.0 section 9), so two
    distinct versions never have equal precedence. Build metadata is refused as in tags.
    """

    __slots__ = ("major", "minor", "patch", "prerelease", "_key")

    def __init__(self, text: str):
        match = SEMVER_RE.fullmatch(text) if isinstance(text, str) else None
        if match is None:
            raise TagError("not a semantic version")
        pre: Optional[str] = match.group("pre")
        ids: Tuple[Tuple[int, int, str], ...] = ()
        if pre is not None:
            parts = pre.split(".")
            for part in parts:
                if part.isdigit() and len(part) > 1 and part[0] == "0":
                    raise TagError("numeric prerelease identifiers must not have leading zeros")
            # numeric identifiers sort numerically and before alphanumeric ones (ASCII order)
            ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts)
        self.major = int(match.group("major"))
        self.minor = int(match.group("minor"))
        self.patch = int(match.group("patch"))
        self.prerelease = pre
        # a release sorts after all of its prereleases; a longer identifier list wins a tie
        self._key = (self.major, self.minor, self.patch, 0 if pre is not None else 1, ids)

    @classmethod
    def parse(cls, text: str) -> "SemVer":
        return cls(text)

    @property
    def core(self) -> str:
        return "%d.%d.%d" % (self.major, self.minor, self.patch)

    @property
    def is_prerelease(self) -> bool:
        return self.prerelease is not None

    def __str__(self) -> str:
        return self.core + ("-" + self.prerelease if self.prerelease is not None else "")

    def __repr__(self) -> str:
        return "SemVer(%r)" % str(self)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key == other._key

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._key < other._key

    def __hash__(self) -> int:
        return hash(self._key)


def _as_semver(semver: Union[str, SemVer]) -> SemVer:
    return semver if isinstance(semver, SemVer) else SemVer(semver)


def is_valid_bid(bid: Any) -> bool:
    """Whether ``bid`` can appear in a tag (grammar, and no ``-v<digit>``)."""
    return isinstance(bid, str) and BID_RE.fullmatch(bid) is not None and not _AMBIGUOUS.search(bid)


def parse_tag(tag: str) -> Tuple[str, str]:
    """``"io.example.app-v1.2.3-rc.1"`` -> ``("io.example.app", "1.2.3-rc.1")``. Raises :class:`TagError`."""
    match = TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise TagError("tag does not match <bundle id>-v<semver>")
    bid, ver = match.group("bid"), match.group("ver")
    if _AMBIGUOUS.search(bid):
        raise TagError("bundle id contains -v<digit>; the tag is ambiguous")
    SemVer(ver)  # leading zeros in numeric prerelease identifiers
    return bid, ver


def make_tag(bid: str, semver: Union[str, SemVer]) -> str:
    """The release tag for ``bid`` at ``semver``. Raises :class:`TagError`."""
    if not is_valid_bid(bid):
        raise TagError("bundle id does not fit the tag grammar")
    version = str(_as_semver(semver))
    tag = "%s-v%s" % (bid, version)
    if parse_tag(tag) != (bid, version):
        raise TagError("bundle id and version do not form an unambiguous tag")
    return tag


def _numeric_parts(text: str) -> Optional[Tuple[int, int, int]]:
    parts = text.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    if not all(p and p.isdigit() and p.isascii() for p in parts):
        return None
    nums = [int(p) for p in parts] + [0] * (3 - len(parts))
    return nums[0], nums[1], nums[2]


def core_matches(semver: Union[str, SemVer], short_version: Any) -> bool:
    """Whether ``X.Y.Z`` of ``semver`` equals CFBundleShortVersionString padded to three numbers.

    ``"1.2"`` matches ``1.2.0``; a short version with non-numeric or more than three parts never
    matches. An invalid ``semver`` raises :class:`TagError`.
    """
    version = _as_semver(semver)
    if not isinstance(short_version, str):
        return False
    nums = _numeric_parts(short_version.strip())
    return nums is not None and nums == (version.major, version.minor, version.patch)


def alias_for(bid: str) -> str:
    """Secret-name safe alias: uppercase, every other character ``_`` (``io.a-b`` -> ``IO_A_B``)."""
    return "".join(c.upper() if c.isascii() and c.isalnum() else "_" for c in str(bid))
