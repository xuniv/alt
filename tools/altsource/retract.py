"""Tombstones of withdrawn versions: ``apps/<bid>/retracted.json``.

A version is withdrawn when its release is deleted or turned back into a draft by hand. Sync then
drops the version's record (published releases are the truth for ``source.json``) and remembers the
version here, so that builders do not bring it back by themselves::

    {
      "schemaVersion": 1,
      "versions": {
        "1.2.3": {"date": "2026-10-23T08:00:00Z", "reason": "deleted"}
      }
    }

``reason`` is ``deleted`` (no release uses the tag any more) or ``unpublished`` (the release is a
draft again). The file is derived: only sync writes it, with sorted keys, and sync removes an entry
(and the file once it is empty) when a release for that version is published again. Tombstones
never change ``source.json``; they are a signal for builders, which refuse a withdrawn version
unless forced.

:func:`load` and :func:`is_retracted` read the file strictly: a missing file means "nothing
withdrawn", a malformed one raises :class:`RetractError` so callers fail instead of building a
version that may have been withdrawn.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Mapping, Set, Tuple

from .tags import SemVer, TagError, is_valid_bid

SCHEMA_VERSION = 1
FILE_NAME = "retracted.json"
DELETED = "deleted"
UNPUBLISHED = "unpublished"
REASONS = (DELETED, UNPUBLISHED)
MAX_BYTES = 1 << 20
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", re.ASCII)
_TOP_KEYS = frozenset(("schemaVersion", "versions"))
_ENTRY_KEYS = frozenset(("date", "reason"))

Entries = Dict[str, Dict[str, str]]


class RetractError(ValueError):
    """A tombstone file (or the bundle identifier naming it) is not valid. Messages carry no file text."""

    rule = "retracted-invalid"


def rel_path(bid: str) -> str:
    """Repository-relative path of the tombstone file of ``bid``."""
    if not is_valid_bid(bid):
        raise RetractError("invalid bundle identifier")
    return "apps/%s/%s" % (bid, FILE_NAME)


def is_semver(text: Any) -> bool:
    try:
        SemVer(text)
    except TagError:
        return False
    return True


def entry(date: str, reason: str) -> Dict[str, str]:
    """One tombstone; ``date`` is ``YYYY-MM-DDTHH:MM:SSZ``."""
    if not isinstance(date, str) or not _DATE.fullmatch(date):
        raise RetractError("date must be YYYY-MM-DDTHH:MM:SSZ")
    if reason not in REASONS:
        raise RetractError("reason must be one of %s" % ", ".join(REASONS))
    return {"date": date, "reason": reason}


def _valid_entry(version: Any, value: Any) -> bool:
    return (is_semver(version) and isinstance(value, dict) and set(value) == _ENTRY_KEYS
            and isinstance(value.get("date"), str) and _DATE.fullmatch(value["date"]) is not None
            and value.get("reason") in REASONS)


def _is_schema(value: Any) -> bool:
    return type(value) is int and value == SCHEMA_VERSION


def _decode(data: bytes) -> Any:
    if len(data) > MAX_BYTES:
        raise RetractError("file is too large")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise RetractError("not valid JSON") from None


def parse(data: bytes) -> Entries:
    """Entries of a tombstone file; anything unexpected raises :class:`RetractError`."""
    obj = _decode(data)
    if not isinstance(obj, dict) or set(obj) != _TOP_KEYS:
        raise RetractError("must be an object with schemaVersion and versions")
    if not _is_schema(obj["schemaVersion"]):
        raise RetractError("unsupported schemaVersion")
    versions = obj["versions"]
    if not isinstance(versions, dict):
        raise RetractError("versions must be an object")
    for version, value in versions.items():
        if not _valid_entry(version, value):
            raise RetractError("versions has an invalid entry")
    return {v: dict(e) for v, e in versions.items()}


def parse_lenient(data: bytes) -> Tuple[Entries, int]:
    """(valid entries, number of problems) of a tombstone file that may be damaged.

    Sync uses this to rewrite a damaged file without losing the entries that are still readable.
    """
    try:
        obj = _decode(data)
    except RetractError:
        return {}, 1
    if not isinstance(obj, dict):
        return {}, 1
    problems = len(set(obj) - _TOP_KEYS)
    if not _is_schema(obj.get("schemaVersion")):
        problems += 1
    versions = obj.get("versions")
    if not isinstance(versions, dict):
        return {}, problems + 1
    out: Entries = {}
    for version, value in versions.items():
        if _valid_entry(version, value):
            out[version] = {"date": value["date"], "reason": value["reason"]}
        else:
            problems += 1
    return out, problems


def dumps(entries: Mapping[str, Mapping[str, str]]) -> bytes:
    """Canonical file contents: sorted keys, two-space indent, trailing newline."""
    versions = {}
    for version, value in entries.items():
        if not _valid_entry(version, dict(value)):
            raise RetractError("invalid entry")
        versions[version] = {"date": value["date"], "reason": value["reason"]}
    obj = {"schemaVersion": SCHEMA_VERSION, "versions": versions}
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def read(repo_root: str, bid: str) -> Entries:
    """Entries for ``bid`` under ``repo_root``; ``{}`` when the file does not exist."""
    path = os.path.join(repo_root, *rel_path(bid).split("/"))
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return {}
    except OSError:
        raise RetractError("file cannot be read") from None
    return parse(data)


def load(repo_root: str, bid: str) -> Set[str]:
    """The withdrawn versions (semver strings) of ``bid``."""
    return set(read(repo_root, bid))


def is_retracted(repo_root: str, bid: str, version: str) -> bool:
    """Whether ``version`` of ``bid`` is withdrawn. An invalid version raises :class:`RetractError`."""
    if not is_semver(version):
        raise RetractError("not a semantic version")
    return version in load(repo_root, bid)
