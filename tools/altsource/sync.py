"""Idempotent catalog regeneration: the only writer of derived files.

The full list of published releases is the source of truth. Records under ``apps/<bid>/versions/``,
missing ``app.json``/``icon.png`` files and ``source.json`` are derived from it and committed in one
``createCommitOnBranch`` call. An incomplete release listing aborts before anything is changed.

A record whose release, IPA asset and app.json asset are unchanged is reused without downloading or
scanning the IPA again. After the denylist or the gate rules change, run with ``rescan=True``
(``sync --rescan``) once so every published IPA is checked against them.

The tag, the name of a published IPA asset and the facts listed from the IPA (app name, versions,
privacy keys and descriptions, entitlement keys, all in decoded form) are public text like the
release notes: a release whose tag, asset name or listed facts contain a denylist term or a path
rule hit is taken down. Leaky release notes and titles are cleared or reset, and leaky asset labels
(GitHub shows a label in place of the file name) are cleared, also for records reused from an
earlier run. As a final guard every string of every record and of the generated ``source.json`` is
checked before anything is committed: a record that fails takes its release down, and a failure in
text from curated files (``app.json``, ``source.base.json``) aborts the sync. Reports name rules and
counts, never the matched text.

A published IPA that passes the gate but is not in normalized form (it was uploaded directly rather
than through ``stage``) is replaced by its normalized form: the normalized file is inspected and
scanned like ``stage`` does, then the release goes back to draft, the normalized IPA is uploaded and
its digest verified, the old asset is deleted, the new one is named ``<SafeName>-<semver>.ipa`` like
``stage`` names it, and the release is published again with the same prerelease flag. When a step
fails while the old asset is still listed, the upload is removed and the release is published again
unchanged; the error is reported and ``sync --rescan`` tries again. When the old asset is gone, the
verified upload completes the replacement; when that cannot be confirmed, the release is left as a
draft. Immutable releases are recorded as they are, with a warning. Without gate scanning
(``scan_published=False``) nothing is normalized.

Sync also keeps the tombstones of withdrawn versions (``apps/<bid>/retracted.json``, see
:mod:`altsource.retract`). A record that a run drops because no release uses its tag any more is
remembered as ``deleted``; one whose release is a draft again (and not marked blocked by the gate)
as ``unpublished``. Records that sync drops itself (a gate block, an ungated asset, a takedown, a
replacement left as a draft) get no tombstone, and an aborted run writes none. Once a release for a
withdrawn version is published again, its entry is removed, and the file with its last entry.
Tombstones never change ``source.json``; builders read them.
"""

from __future__ import annotations

import dataclasses
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import retract as retractmod
from .stage import (
    APP_JSON_MAX_BYTES,
    ARCHIVE_ERRORS,
    BLOCKED_MARK,
    PATH_RULES,
    SEED_KEYS,
    Toolkit,
    blocking,
    check_app_json_text,
    core_matches,
    errors_of,
    field,
    finding_dicts,
    info_findings,
    is_ipa_asset,
    parse_semver,
    rule_of,
    semver_prerelease,
    tag_findings,
    value_findings,
    _verify_upload,
    app_name,
    ipa_asset_name,
    sha256_file,
)

SCHEMA_VERSION = 1
NOTES_LIMIT = 4000
SEED_ASSET = "app.json"
OPT_IN_RULES = PATH_RULES  # findings that app.json ``allowHomePaths`` turns into warnings
NOTES_PATH = "<release-notes>"
TITLE_PATH = "<release-title>"
ASSET_NAME_PATH = "<asset-name>"
LABEL_PATH = "<asset-label>"
RECORD_PATH = "<catalog-record>"
TOMBSTONE_PATH = "<tombstone>"
LIST_ATTEMPTS = 2  # listings that decide whether a failed replacement can be undone
RECORD_RE = re.compile(r"^apps/[^/]+/versions/[^/]+\.json$")
_WARNING_PREFIX = re.compile(r"^warning:\s*", re.IGNORECASE)
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})$")
_PLAIN_KEY = re.compile(r"^[A-Za-z]{1,40}$")


class SyncError(Exception):
    """Sync failed."""


class SyncAborted(SyncError):
    """Sync stopped before changing anything (incomplete listing, invalid output, missing denylist)."""

    def __init__(self, message: str, details: Sequence[str] = ()):
        super().__init__(message)
        self.details = list(details)


class _Skipped(Exception):
    """Local trouble with one release: keep its previous record and try again on the next run."""


@dataclasses.dataclass
class SyncResult:
    changed: bool = False
    commit: Optional[str] = None
    apps: int = 0
    versions: int = 0
    attempts: int = 0
    files: List[str] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)
    warnings: List[str] = dataclasses.field(default_factory=list)
    blocked: List[str] = dataclasses.field(default_factory=list)
    normalized: List[str] = dataclasses.field(default_factory=list)  # tags whose IPA was replaced
    retracted: List[str] = dataclasses.field(default_factory=list)  # tags that got a tombstone
    restored: List[str] = dataclasses.field(default_factory=list)  # tags whose tombstone was removed
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def dumps_json(obj: Any) -> bytes:
    """Canonical serialization for every generated JSON file."""
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


# -- git access -----------------------------------------------------------------------------------

class GitRepo:
    """The local checkout: HEAD oid, HEAD tree blob ids, and refresh after the branch moved."""

    def __init__(self, root: str, *, environ: Optional[Mapping[str, str]] = None):
        self.root = root
        self.environ = os.environ if environ is None else environ
        self._format: Optional[str] = None

    def _git(self, *args: str) -> bytes:
        proc = subprocess.run(["git", "-C", self.root] + list(args), stdin=subprocess.DEVNULL,
                              capture_output=True)
        if proc.returncode != 0:
            raise SyncError("git %s failed" % args[0])
        return proc.stdout

    def head(self) -> str:
        return self._git("rev-parse", "HEAD").decode("ascii").strip()

    def tree_blobs(self) -> Dict[str, str]:
        out = self._git("ls-tree", "-r", "-z", "--full-tree", "HEAD")
        blobs = {}
        for entry in out.split(b"\0"):
            if not entry:
                continue
            meta, _, path = entry.partition(b"\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == b"blob":
                blobs[path.decode("utf-8", "surrogateescape")] = parts[2].decode("ascii")
        return blobs

    def blob_id(self, data: bytes) -> str:
        if self._format is None:
            try:
                self._format = self._git("rev-parse", "--show-object-format").decode().strip() or "sha1"
            except SyncError:
                self._format = "sha1"
        algo = hashlib.sha256 if self._format == "sha256" else hashlib.sha1
        return algo(b"blob %d\0" % len(data) + data).hexdigest()

    def refresh(self, branch: str) -> None:
        if self.environ.get("GITHUB_ACTIONS") != "true":
            raise SyncError("the branch moved; update the local checkout and run sync again")
        self._git("fetch", "--no-tags", "--depth=1", "origin", branch)
        self._git("reset", "--hard", "FETCH_HEAD")


# -- helpers --------------------------------------------------------------------------------------

def normalize_date(value: Any) -> Optional[str]:
    """GitHub timestamp -> ``YYYY-MM-DDTHH:MM:SSZ`` (UTC, no fractional seconds)."""
    match = _DATE_RE.match(str(value or ""))
    if not match:
        return None
    year, month, day, hour, minute, second, zone = match.groups()
    stamp = datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        offset = datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        stamp -= sign * offset
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def release_notes(body: Any, semver: str) -> str:
    text = str(body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > NOTES_LIMIT:
        text = text[:NOTES_LIMIT].rstrip()
    return text or "Version %s" % semver


def _read_json(path: str) -> Any:
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def load_records(root: str) -> Dict[str, Tuple[str, Dict[str, Any]]]:
    """Existing records by tag -> (repo-relative path, record)."""
    records: Dict[str, Tuple[str, Dict[str, Any]]] = {}
    for path in sorted(glob.glob(os.path.join(root, "apps", "*", "versions", "*.json"))):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        record = _read_json(path)
        if isinstance(record, dict) and isinstance(record.get("tag"), str):
            records.setdefault(record["tag"], (rel, record))
    return records


def disk_record_paths(root: str) -> List[str]:
    return sorted(os.path.relpath(p, root).replace(os.sep, "/")
                  for p in glob.glob(os.path.join(root, "apps", "*", "versions", "*.json")))


def _write_tree(root: str, files: Mapping[str, bytes], deletions: Sequence[str]) -> None:
    for rel, data in sorted(files.items()):
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp-sync"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    for rel in deletions:
        path = os.path.join(root, *rel.split("/"))
        if os.path.exists(path):
            os.unlink(path)
        parent = os.path.dirname(path)
        while parent != root and os.path.isdir(parent) and not os.listdir(parent):
            os.rmdir(parent)
            parent = os.path.dirname(parent)


# -- one sync attempt -----------------------------------------------------------------------------

class _Run:
    def __init__(self, root, *, gh, deps, denylist, scan_published, policy, dry_run, log, tmp, cache,
                 rescan=False, sleep=time.sleep, taken_down=None):
        self.root = root
        self.rescan = rescan
        self.sleep = sleep
        self.gh = gh
        self.deps = deps
        self.denylist = list(denylist)
        self.scan_published = scan_published
        self.policy = policy
        self.dry_run = dry_run
        self.log = log
        self.tmp = tmp
        self.cache: Dict[int, str] = cache
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.blocked: List[str] = []
        # errors describing actions already taken on GitHub (unpublish, delete, scrub); they must
        # survive a restart after HeadMoved because the next attempt no longer sees the cause
        self.remediations: List[str] = []
        self.normalized: List[str] = []
        # ids of releases this sync unpublished or deleted itself, shared by every attempt: dropping
        # their records is not a withdrawal
        self.taken_down: Set[int] = taken_down if taken_down is not None else set()
        self.retracted: List[str] = []
        self.restored: List[str] = []
        self.tombstone_removals: List[str] = []
        self.desired: Dict[str, bytes] = {}
        self.records: Dict[str, Dict[str, Any]] = {}
        self.ipa_errors = errors_of(deps, "IpaError") + ARCHIVE_ERRORS
        self.tag_errors = errors_of(deps, "TagError") + (ValueError,)
        self.gate_errors = errors_of(deps, "GateError")
        self.norm_errors = self.ipa_errors + errors_of(deps, "NormalizeError")

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.log("warning: " + message)

    def error(self, message: str) -> None:
        self.errors.append(message)
        self.log("error: " + message)

    def block(self, tag: str, message: str) -> None:
        if tag not in self.blocked:
            self.blocked.append(tag)
        self.remediations.append(message)
        self.error(message)

    def lasting_error(self, message: str) -> None:
        """An error about a change on GitHub that the next attempt cannot see (survives HeadMoved)."""
        self.remediations.append(message)
        self.error(message)

    # downloads are cached per asset id for the whole sync run (across retries)
    def download(self, asset_id: int, digest: Optional[str]) -> str:
        path = self.cache.get(asset_id)
        if path is None:
            path = os.path.join(self.tmp, "asset-%d" % asset_id)
            self.gh.download_asset(asset_id, path)
            self.cache[asset_id] = path
        if digest and "sha256:" + sha256_file(path) != digest:
            self.cache.pop(asset_id, None)
            os.unlink(path)
            raise SyncError("downloaded bytes do not match the asset digest")
        return path

    def policy_for(self, bid: str, seed: Optional[Dict[str, Any]] = None) -> Any:
        """Gate policy for ``bid``: the committed app.json decides; a new app uses the release's app.json."""
        path = os.path.join(self.root, "apps", bid, "app.json")
        planned = self.desired.get("apps/%s/app.json" % bid)  # written for a new app by this run
        if planned is not None:
            app = json.loads(planned.decode("utf-8"))
        elif os.path.exists(path):
            app = _read_json(path)
        else:
            app = seed  # validated by read_seed; stage attaches the opt-in it was given
        if isinstance(app, dict) and app.get("allowHomePaths") is True:
            try:
                return dataclasses.replace(self.policy, allow_home_paths=True)
            except TypeError:
                return self.deps.GatePolicy(allow_home_paths=True)
        return self.policy

    def remediate(self, rel: Dict[str, Any], tag: str, rules: Sequence[str], subject: str = "") -> None:
        """Take a published release that fails the gate out of public view.

        ``subject`` names what failed when it is not the IPA (for example ``"asset name "``).
        """
        summary = ", ".join(sorted(set(rules))) or "gate"
        what = "%s: %sblocked (%s)" % (tag, subject, summary)
        if rel.get("immutable") and rules and set(rules) <= OPT_IN_RULES:
            # deleting would burn the tag forever for a finding that app.json can allow
            self.block(tag, "%s; immutable release left in place: allow it in app.json or delete the "
                            "release" % what)
            return
        self.taken_down.add(int(rel["id"]))  # also when the request fails: it may have taken effect
        if self.dry_run:
            self.block(tag, "%s; would be unpublished" % what)
            return
        try:
            if rel.get("immutable"):
                self.gh.delete_release(int(rel["id"]))
                action = "deleted (immutable)"
            else:
                self.gh.unpublish(int(rel["id"]), name=BLOCKED_MARK + tag)
                action = "unpublished"
        except Exception as exc:  # the release may still be public: make the run fail loudly
            self.block(tag, "%s; remediation failed (%s)" % (what, type(exc).__name__))
            return
        self.block(tag, "%s; %s" % (what, action))

    @staticmethod
    def relaxed(policy: Any) -> bool:
        """Whether path-rule hits in text taken from the IPA are warnings (the home-path opt-in)."""
        return bool(getattr(policy, "allow_home_paths", False))

    def scrub_labels(self, rel: Dict[str, Any], tag: str) -> bool:
        """Clear leaky asset labels; GitHub shows a label in place of the file name.

        Returns False when a label could not be cleared and the release was taken down instead.
        """
        for asset in rel.get("assets") or []:
            label = asset.get("label") if isinstance(asset, dict) else None
            if not isinstance(label, str) or not label:
                continue
            rules = _rules(_text_hits(self.deps, label, self.denylist, LABEL_PATH))
            if not rules:
                continue
            if self.dry_run:
                self.block(tag, "%s: asset label blocked (%s); would be cleared" % (tag, ", ".join(rules)))
                continue
            try:
                self.gh.update_asset(int(asset["id"]), label="")
            except Exception as exc:
                self.error("%s: clearing an asset label failed (%s)" % (tag, type(exc).__name__))
                self.remediate(rel, tag, rules, subject="asset label ")
                return False
            asset["label"] = ""
            self.block(tag, "%s: asset label blocked (%s); cleared" % (tag, ", ".join(rules)))
        return True

    def admit(self, path: str, record: Dict[str, Any], rel: Dict[str, Any], tag: str, policy: Any) -> bool:
        """List ``record`` unless one of its strings (or its path) fails the leak check.

        Records reused from earlier runs were made under earlier rules; a failing record takes its
        release down like a failing IPA.
        """
        findings = value_findings(self.deps, [path, record], self.denylist, RECORD_PATH,
                                  relaxed=self.relaxed(policy))
        rules = _rules(findings)
        if rules:
            self.records.pop(path, None)
            self.remediate(rel, tag, rules, subject="catalog record ")
            return False
        self.records[path] = record
        return True

    def scrub_text(self, rel: Dict[str, Any], tag: str, bid: str, semver: str) -> str:
        """Clear leaky release notes and reset a leaky release title. Returns the notes to publish."""
        body = str(rel.get("body") or "")
        title = str(rel.get("name") or "")
        changes: Dict[str, Any] = {}
        parts = []
        rules = _rules(_text_hits(self.deps, body, self.denylist, NOTES_PATH))
        if rules:
            changes["body"] = ""
            parts.append(("release notes", rules, "cleared", "clearing"))
        rules = _rules(_text_hits(self.deps, title, self.denylist, TITLE_PATH))
        if rules:
            changes["name"] = "%s %s" % (bid, semver)
            parts.append(("release title", rules, "reset", "reset"))
        if not changes:
            return body
        failure = None
        if not self.dry_run:
            try:
                self.gh.update_release(int(rel["id"]), **changes)
            except Exception as exc:
                failure = type(exc).__name__
        for label, rules, done, doing in parts:
            if self.dry_run:
                outcome = "would be " + done
            elif failure:
                outcome = "%s failed (%s)" % (doing, failure)
            else:
                outcome = done
            self.block(tag, "%s: %s blocked (%s); %s" % (tag, label, ", ".join(rules), outcome))
        return "" if "body" in changes else body

    def build_record(self, rel, asset, tag, bid, semver, info, notes) -> Dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "tag": tag,
            "bundleIdentifier": bid,
            "semver": semver,
            "version": str(field(info, "short_version", "")),
            "buildVersion": str(field(info, "build_version", "") or ""),
            "prerelease": bool(rel.get("prerelease")) or semver_prerelease(self.deps, semver),
            "date": self.release_date(rel),
            "localizedDescription": notes,
            "downloadURL": asset.get("browser_download_url"),
            "size": int(asset.get("size") or 0),
            "sha256": str(asset.get("digest", ""))[len("sha256:"):],
            "minOSVersion": field(info, "min_os", None),
            "releaseId": int(rel["id"]),
            "assetId": int(asset["id"]),
            "assetDigest": asset.get("digest"),
            "name": str(field(info, "name", "") or bid),
            "privacy": dict(field(info, "privacy", None) or {}),
            "entitlements": sorted(field(info, "entitlements", None) or []),
        }

    @staticmethod
    def release_date(rel: Dict[str, Any]) -> Optional[str]:
        return normalize_date(rel.get("published_at")) or normalize_date(rel.get("created_at"))

    def refresh_record(self, record, rel, asset, semver, notes) -> Dict[str, Any]:
        updated = dict(record)
        updated["date"] = self.release_date(rel) or record.get("date")
        updated["localizedDescription"] = notes
        updated["prerelease"] = bool(rel.get("prerelease")) or semver_prerelease(self.deps, semver)
        updated["downloadURL"] = asset.get("browser_download_url") or record.get("downloadURL")
        return updated

    def keep(self, path: str, prev: Optional[Tuple[str, Dict[str, Any]]], rel: Dict[str, Any], tag: str,
             policy: Any, asset_id: Optional[int] = None) -> None:
        if prev is None:
            return
        record = prev[1]
        if record.get("releaseId") != int(rel["id"]):
            return
        if asset_id is not None and record.get("assetId") != asset_id:
            return
        self.admit(path, record, rel, tag, policy)

    def process(self, rel, tag, bid, semver, existing) -> None:
        path = "apps/%s/versions/%s.json" % (bid, semver)
        prev = existing.get(tag)
        rel_id = int(rel["id"])
        rules = _rules(tag_findings(self.deps, tag, self.denylist))
        if rules:  # the tag names the release everywhere; messages and the draft title use its id
            self.remediate(rel, "release %d" % rel_id, rules, subject="tag ")
            return
        policy = self.policy_for(bid)
        # release notes and title are public even when the assets are unusable
        notes = release_notes(self.scrub_text(rel, tag, bid, semver), semver)
        if not self.scrub_labels(rel, tag):
            return

        uploaded = [a for a in rel.get("assets") or [] if a.get("state") == "uploaded"]
        ipas = [a for a in uploaded if is_ipa_asset(a)]
        seeds = [a for a in uploaded if a.get("name") == SEED_ASSET]
        if len(ipas) > 1 or len(uploaded) > len(ipas) + len(seeds):
            # a second IPA or any other file (logs, archives) was never gated: take it down
            self.remediate(rel, tag, ["unexpected-asset"])
            return
        if not ipas:
            self.warn("%s: no uploaded .ipa asset; skipped" % tag)
            self.keep(path, prev, rel, tag, policy)
            return
        asset = ipas[0]
        # the file name is part of the download URL in the release, the records and source.json
        rules = _rules(_text_hits(self.deps, str(asset.get("name") or ""), self.denylist, ASSET_NAME_PATH))
        if rules:
            self.remediate(rel, tag, rules, subject="asset name ")
            return
        digest = asset.get("digest")
        if not isinstance(digest, str) or not re.match(r"^sha256:[0-9a-f]{64}$", digest):
            self.error("%s: asset has no sha256 digest; skipped" % tag)
            return
        seed_id = int(seeds[0]["id"]) if seeds else None
        seed: Optional[Dict[str, Any]] = None

        if prev is not None and not self.rescan:
            record = prev[1]
            if (record.get("releaseId") == rel_id and record.get("assetId") == asset.get("id")
                    and record.get("assetDigest") == digest and record.get("appJsonAssetId") == seed_id):
                self.admit(path, self.refresh_record(record, rel, asset, semver, notes), rel, tag, policy)
                return

        if seeds:
            try:
                seed, rules = self.read_seed(seeds[0])
            except Exception as exc:
                self.error("%s: app.json download failed (%s); skipped" % (tag, type(exc).__name__))
                self.keep(path, prev, rel, tag, policy, int(asset["id"]))
                return
            if seed is None:
                self.remediate(rel, tag, rules)
                return
            policy = self.policy_for(bid, seed)
        try:
            ipa = self.download(int(asset["id"]), digest)
        except Exception as exc:
            self.error("%s: download failed (%s); skipped" % (tag, type(exc).__name__))
            self.keep(path, prev, rel, tag, policy, int(asset["id"]))
            return
        try:
            info = self.deps.inspect_ipa(ipa)
        except self.ipa_errors as exc:
            self.remediate(rel, tag, [rule_of(exc, "ipa-invalid")])
            return
        except OSError as exc:  # local trouble (disk, permissions), not a verdict on the release
            self.error("%s: IPA could not be read (%s); skipped" % (tag, type(exc).__name__))
            self.keep(path, prev, rel, tag, policy, int(asset["id"]))
            return
        problems = []
        if str(field(info, "bundle_id", "")) != bid:
            problems.append("bundle-id-mismatch")
        if not core_matches(self.deps, semver, str(field(info, "short_version", "") or "")):
            problems.append("version-mismatch")
        if problems:
            self.remediate(rel, tag, problems)
            return
        # the listed facts are decoded text (property list entities, for example): check them as shown
        rules = _rules(info_findings(self.deps, info, bid, self.denylist, relaxed=self.relaxed(policy)))
        if rules:
            self.remediate(rel, tag, rules, subject="listed metadata ")
            return
        if self.scan_published:
            try:
                result = self.deps.scan_ipa(ipa, denylist=self.denylist, policy=policy, info=info)
            except self.gate_errors as exc:
                raise SyncAborted("gate unavailable (%s)" % rule_of(exc, "gate-error")) from None
            except self.ipa_errors as exc:  # the scanner reads entries that inspection skipped
                self.remediate(rel, tag, [rule_of(exc, "ipa-invalid")])
                return
            except OSError as exc:
                self.error("%s: IPA could not be scanned (%s); skipped" % (tag, type(exc).__name__))
                self.keep(path, prev, rel, tag, policy, int(asset["id"]))
                return
            findings = finding_dicts(field(result, "findings", []))
            blocks = blocking(findings)
            if blocks or not field(result, "ok", True):
                self.remediate(rel, tag, [f["rule"] for f in blocks])
                return
            try:
                outcome = self.normalize_published(rel, asset, tag, bid, semver, ipa, info, policy)
            except _Skipped:
                self.keep(path, prev, rel, tag, policy, int(asset["id"]))
                return
            if outcome is None:
                return
            rel, asset, info = outcome
        record = self.build_record(rel, asset, tag, bid, semver, info, notes)
        if seed_id is not None:
            record["appJsonAssetId"] = seed_id
        self.admit(path, record, rel, tag, policy)

    # -- normalization of directly published IPAs ----------------------------------------------

    def normalize_published(self, rel, asset, tag, bid, semver, ipa, info, policy):
        """(release, asset, inspection result) to record once the gate-clean IPA ``ipa`` is normalized.

        Returns None when nothing may be recorded: the normalized form failed the gate (the release
        is taken down like any other blocked release) or the release was left as a draft. Raises
        ``_Skipped`` on local trouble (disk, permissions).
        """
        immutable = bool(rel.get("immutable"))
        out = os.path.join(self.tmp, "normalized-%d" % int(asset["id"]))
        try:
            self.deps.normalize_ipa(ipa, out)
            want = "sha256:" + sha256_file(out)
        except self.norm_errors as exc:  # stage rejects such an IPA, so the gate does here as well
            rule = rule_of(exc, "normalize")
            if immutable:
                self.warn("%s: immutable release cannot be normalized (%s); recorded as published" % (tag, rule))
                return rel, asset, info
            self.remediate(rel, tag, [rule])
            return None
        except OSError as exc:
            self.error("%s: IPA could not be normalized (%s); skipped" % (tag, type(exc).__name__))
            raise _Skipped() from None
        if want == asset.get("digest"):
            os.unlink(out)
            return rel, asset, info
        if immutable:
            os.unlink(out)
            self.warn("%s: IPA is not in normalized form, but the release is immutable; recorded as published"
                      % tag)
            return rel, asset, info

        # the normalized bytes are what becomes public: check them like stage does
        try:
            normalized = self.deps.inspect_ipa(out)
            result = self.deps.scan_ipa(out, denylist=self.denylist, policy=policy, info=normalized)
        except self.gate_errors as exc:
            raise SyncAborted("gate unavailable (%s)" % rule_of(exc, "gate-error")) from None
        except self.ipa_errors as exc:
            self.remediate(rel, tag, [rule_of(exc, "ipa-invalid")])
            return None
        except OSError as exc:
            self.error("%s: normalized IPA could not be checked (%s); skipped" % (tag, type(exc).__name__))
            raise _Skipped() from None
        rules = []
        if (str(field(normalized, "bundle_id", "")) != bid
                or str(field(normalized, "short_version", "")) != str(field(info, "short_version", ""))):
            rules.append("normalize-mismatch")
        rules += [f["rule"] for f in blocking(finding_dicts(field(result, "findings", [])))]
        rules += _rules(info_findings(self.deps, normalized, bid, self.denylist, relaxed=self.relaxed(policy)))
        if rules or not field(result, "ok", True):
            self.remediate(rel, tag, rules)
            return None
        name = ipa_asset_name(app_name(normalized, bid), bid, semver)  # the name stage would give it
        rules = _rules(_text_hits(self.deps, name, self.denylist, ASSET_NAME_PATH)
                       + _text_hits(self.deps, _upload_name(name, int(asset["id"])), self.denylist, ASSET_NAME_PATH))
        if rules:  # checked before the release is touched: both names become public
            self.remediate(rel, tag, rules, subject="asset name ")
            return None
        if self.dry_run:
            self.warn("%s: IPA is not in normalized form; would be replaced and published again" % tag)
            return rel, asset, info

        replaced = self.replace_ipa(rel, asset, tag, out, want, name)
        if replaced is None:
            return None
        rel, new = replaced
        if new is asset:  # published again unchanged
            return rel, asset, info
        self.cache[int(new["id"])] = out  # the icon and a retry after HeadMoved read it from here
        return rel, new, normalized

    def replace_ipa(self, rel, asset, tag, path, want, name):
        """Swap the release's IPA for the normalized file ``path`` (digest ``want``), named ``name``.

        Returns (release, asset) to record (the new asset, or the old one when the release was
        published again unchanged), or None when the release is left as a draft.
        """
        rel_id = int(rel["id"])
        old_id = int(asset["id"])
        old_name = str(asset.get("name") or "")
        upload_name = _upload_name(name, old_id)
        prerelease = bool(rel.get("prerelease"))
        self.taken_down.add(rel_id)  # a draft left behind by a failed replacement is not a withdrawal
        try:
            self.gh.unpublish(rel_id)
        except Exception as exc:  # the release is still published with the old IPA
            self.error("%s: not normalized: unpublishing failed (%s); recorded as published"
                       % (tag, type(exc).__name__))
            return rel, asset
        step = "upload"
        new: Optional[Dict[str, Any]] = None
        new_id: Optional[int] = None
        try:
            response = self.gh.upload_asset(rel_id, path, upload_name, "application/octet-stream")
            new_id = field(response, "id", None)
            step = "verification"
            new, _ = _verify_upload(self.gh, rel_id, want, self.sleep, asset_id=new_id, name=upload_name)
            new_id = new.get("id")
            step = "deleting the old IPA"
            self.gh.delete_asset(old_id)
        except Exception as exc:
            failure = "%s failed (%s)" % (step, type(exc).__name__)
            listing = self.listing(rel_id)
            if listing is None:  # neither undoing nor finishing is safe without knowing what is there
                self.lasting_error("%s: not normalized: %s; the release's assets could not be listed; "
                                   "left as a draft" % (tag, failure))
                return None
            if any(a.get("id") == old_id for a in listing):
                return self.restore(rel, asset, tag, upload_name, prerelease, failure, listing)
            # the old IPA is gone even though a request failed: the upload is the only copy left
            new = _verified(listing, want, new_id, upload_name)
            if new is None:
                self.lasting_error("%s: not normalized: %s; the old IPA is gone and the upload could not "
                                   "be verified; left as a draft" % (tag, failure))
                return None
        final_name = str(new.get("name") or upload_name)
        if final_name.lower() != name.lower():
            try:
                self.gh.update_asset(int(new["id"]), name=name)
                final_name = name
            except Exception as exc:
                self.warn("%s: the normalized IPA keeps its upload name (%s)" % (tag, type(exc).__name__))
        try:
            published = self.gh.publish(rel_id, prerelease=prerelease, make_latest="false")
        except Exception as exc:
            self.lasting_error("%s: normalized IPA uploaded, but publishing again failed (%s); left as a "
                               "draft for stage-draft" % (tag, type(exc).__name__))
            return None
        rel = _republished(rel, published)
        final = dict(new, name=final_name, browser_download_url=_download_url(
            asset.get("browser_download_url"), old_name, final_name))
        for listed in rel.get("assets") or []:
            if isinstance(listed, dict) and listed.get("id") == new.get("id"):
                final.update({k: v for k, v in listed.items() if v is not None})
        self.normalized.append(tag)
        self.log("%s: IPA replaced by its normalized form; release published again" % tag)
        return rel, final

    def listing(self, rel_id: int) -> Optional[List[Dict[str, Any]]]:
        """The release's assets, or None when every attempt to list them failed."""
        for attempt in range(LIST_ATTEMPTS):
            try:
                return [a for a in self.gh.list_assets(rel_id) if isinstance(a, dict)]
            except Exception:
                if attempt + 1 < LIST_ATTEMPTS:
                    self.sleep(2.0)
        return None

    def restore(self, rel, asset, tag, upload_name, prerelease, failure, listing):
        """Undo a failed replacement while the old IPA is still listed: drop the (partial) upload and
        publish the release again."""
        rel_id = int(rel["id"])
        try:
            for extra in listing:
                ours = str(extra.get("name", "")).lower() == upload_name.lower()
                if ours and extra.get("id") != asset.get("id"):
                    self.gh.delete_asset(int(extra["id"]))
            published = self.gh.publish(rel_id, prerelease=prerelease, make_latest="false")
        except Exception as exc:
            self.lasting_error("%s: not normalized: %s; restoring failed (%s); left as a draft"
                               % (tag, failure, type(exc).__name__))
            return None
        self.error("%s: not normalized: %s; published again unchanged" % (tag, failure))
        return _republished(rel, published), asset

    def read_seed(self, asset: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """A release's ``app.json`` asset: (validated object, []) or (None, rule ids). Download errors raise."""
        if int(asset.get("size") or 0) > APP_JSON_MAX_BYTES:
            return None, ["app-json-size"]
        path = self.download(int(asset["id"]), asset.get("digest"))
        with open(path, "rb") as fh:
            raw = fh.read(APP_JSON_MAX_BYTES + 1)
        obj, findings = check_app_json_text(self.deps, raw, self.denylist)
        if obj is None:
            return None, sorted({f["rule"] for f in findings}) or ["app-json-invalid"]
        return obj, []

    def app_files(self, published: List[Tuple[Dict[str, Any], str, str, str]], base: Dict[str, Any]) -> None:
        """Create ``icon.png`` and ``app.json`` for apps that have records but lack them."""
        by_bid: Dict[str, List[Dict[str, Any]]] = {}
        for record in self.records.values():
            by_bid.setdefault(record["bundleIdentifier"], []).append(record)
        defaults = base.get("defaults") if isinstance(base.get("defaults"), dict) else {}
        for bid in sorted(by_bid):
            records = sorted(by_bid[bid], key=lambda r: parse_semver(self.deps, r["semver"]))
            newest = records[-1]
            app_dir = os.path.join(self.root, "apps", bid)
            if not os.path.exists(os.path.join(app_dir, "icon.png")):
                self.app_icon(bid, records, _read_json(os.path.join(app_dir, "app.json")))
            if not os.path.exists(os.path.join(app_dir, "app.json")):
                seed = self.seed_for(bid, published)
                app: Dict[str, Any] = {"name": newest.get("name") or bid}
                for key in SEED_KEYS:
                    if key in seed:
                        app[key] = seed[key]
                for key in ("developerName", "category", "tintColor"):
                    if key not in app and defaults.get(key):
                        app[key] = defaults[key]
                app["includePrereleases"] = False
                app["maxVersions"] = 10
                self.desired["apps/%s/app.json" % bid] = dumps_json(app)

    def app_icon(self, bid: str, records: List[Dict[str, Any]], app: Any) -> None:
        """Extract ``apps/<bid>/icon.png`` from the newest record whose IPA has a usable icon.

        Versions the catalog lists come first (prereleases only with ``includePrereleases``), newest
        first, then the others. An IPA without a usable icon is remembered in its record
        (``iconUnavailable``), so later runs do not download it again but still try other versions.
        A download failure stops the search until the next run.
        """
        include_pre = isinstance(app, dict) and app.get("includePrereleases") is True
        listed: List[Dict[str, Any]] = []
        others: List[Dict[str, Any]] = []
        for record in reversed(records):
            prerelease = bool(record.get("prerelease")) or semver_prerelease(self.deps, record["semver"])
            (listed if include_pre or not prerelease else others).append(record)
        for record in listed + others:
            if record.get("iconUnavailable"):
                continue
            icon, final = self.icon_for(record)
            if icon:
                self.desired["apps/%s/icon.png" % bid] = icon
                return
            if not final:
                return
            record["iconUnavailable"] = True

    def icon_for(self, record: Dict[str, Any]) -> Tuple[Optional[bytes], bool]:
        """(PNG bytes or None, whether a missing icon is final for this asset)."""
        try:
            ipa = self.download(int(record["assetId"]), record.get("assetDigest"))
        except Exception as exc:  # transient: try again next run
            self.warn("%s: icon download failed (%s)" % (record.get("tag"), type(exc).__name__))
            return None, False
        try:
            data = self.deps.extract_icon(ipa)
        except Exception as exc:
            self.warn("%s: icon extraction failed (%s)" % (record.get("tag"), type(exc).__name__))
            return None, True
        if not data:
            self.warn("%s: the IPA has no usable icon" % record.get("tag"))
        return (data or None), True

    def seed_for(self, bid: str, published) -> Dict[str, Any]:
        """Descriptive keys from the newest valid app.json asset; allowHomePaths if any release opted in.

        Only releases that are listed (have a record) count; remediated or skipped ones do not.
        """
        listed = {r.get("tag") for r in self.records.values()}
        candidates = sorted((p for p in published if p[2] == bid and p[1] in listed),
                            key=lambda p: parse_semver(self.deps, p[3]), reverse=True)
        found: Optional[Dict[str, Any]] = None
        opted_in = False
        for rel, tag, _, _ in candidates:
            seeds = [a for a in rel.get("assets") or []
                     if a.get("name") == SEED_ASSET and a.get("state") == "uploaded"]
            if len(seeds) != 1:
                continue
            try:
                obj, rules = self.read_seed(seeds[0])
            except Exception as exc:
                self.warn("%s: app.json asset download failed (%s)" % (tag, type(exc).__name__))
                continue
            if obj is None:
                self.warn("%s: app.json asset rejected (%s)" % (tag, ", ".join(rules)))
                continue
            if found is None:
                found = {k: obj[k] for k in SEED_KEYS if k in obj}
            opted_in = opted_in or obj.get("allowHomePaths") is True
        seed = found or {}
        if opted_in:
            seed["allowHomePaths"] = True
        return seed

    # -- tombstones of withdrawn versions ------------------------------------------------------

    def withdrawal(self, record: Dict[str, Any], drafts: Sequence[Dict[str, Any]]) -> Optional[str]:
        """Why a dropped record's release is gone (a tombstone reason), or None when it is not a withdrawal.

        Only called for records whose tag no published release uses. Releases this sync took down
        itself and drafts that carry the gate's mark (an earlier run's takedown) do not count.
        """
        if _int(record.get("releaseId")) in self.taken_down:
            return None
        if any(_int(r.get("id")) in self.taken_down for r in drafts):
            return None
        if any(str(r.get("name") or "").startswith(BLOCKED_MARK) for r in drafts):
            return None
        return retractmod.UNPUBLISHED if drafts else retractmod.DELETED

    def tombstone_rules(self, path: str, values: Sequence[Any]) -> List[str]:
        """Blocking rules for the strings of one tombstone (its file path included)."""
        return _rules(value_findings(self.deps, [path] + list(values), self.denylist, TOMBSTONE_PATH))

    def plan_tombstones(self, existing: Mapping[str, Tuple[str, Dict[str, Any]]],
                        releases: Sequence[Dict[str, Any]],
                        published: Sequence[Tuple[Dict[str, Any], str, str, str]], stamp: str) -> None:
        """Plan every ``apps/<bid>/retracted.json`` once the records of this attempt are known.

        Requires the complete release listing (an incomplete one aborted earlier). A record that is
        dropped because no published release uses its tag gets an entry dated ``stamp``, unless
        :meth:`withdrawal` says otherwise. Entries whose version is published again are removed; a
        file left without entries is deleted. Files are rewritten in canonical form, damaged parts
        are dropped, and every string is checked like a record: an entry that fails is dropped and
        reported by rule, without naming it.
        """
        published_tags = {tag for _, tag, _, _ in published}
        live: Dict[Tuple[str, str], str] = {}
        for rel, tag, bid, semver in published:
            listed = "apps/%s/versions/%s.json" % (bid, semver) in self.desired
            if listed or _int(rel.get("id")) not in self.taken_down:
                live[(bid, semver)] = tag
        drafts: Dict[str, List[Dict[str, Any]]] = {}
        for rel in releases:
            if isinstance(rel, dict) and rel.get("draft"):
                drafts.setdefault(str(rel.get("tag_name") or ""), []).append(rel)

        added: Dict[str, Dict[str, Tuple[str, Dict[str, str]]]] = {}  # bid -> semver -> (tag, entry)
        for tag, (path, record) in sorted(existing.items()):
            if path in self.desired or tag in published_tags:
                continue  # listed, or still published (kept, skipped or taken down by this run)
            reason = self.withdrawal(record, drafts.get(tag, []))
            if reason is None:
                continue
            try:
                bid, semver = (str(x) for x in self.deps.parse_tag(tag))
                target = retractmod.rel_path(bid)
            except self.tag_errors:  # RetractError is a ValueError as well
                continue
            entry = retractmod.entry(stamp, reason)
            rules = self.tombstone_rules(target, [tag, semver, entry])
            if rules:
                rid = _int(record.get("releaseId"))
                self.error("%s: tombstone blocked (%s); not written" % (
                    "release %d" % rid if rid is not None else "a withdrawn version", ", ".join(rules)))
                continue
            added.setdefault(bid, {})[semver] = (tag, entry)

        on_disk: Dict[str, str] = {}
        for full in sorted(glob.glob(os.path.join(self.root, "apps", "*", retractmod.FILE_NAME))):
            bid = os.path.basename(os.path.dirname(full))
            try:
                retractmod.rel_path(bid)
            except retractmod.RetractError:
                continue  # not an app directory; left alone
            on_disk[bid] = full
        for bid in sorted(set(on_disk) | set(added)):
            target = retractmod.rel_path(bid)
            shown = target if not self.tombstone_rules(target, []) else "a tombstone file"
            entries: Dict[str, Dict[str, str]] = {}
            if bid in on_disk:
                try:
                    with open(on_disk[bid], "rb") as fh:
                        data = fh.read(retractmod.MAX_BYTES + 1)
                except OSError as exc:  # local trouble; going on could lose this run's tombstones
                    raise SyncAborted("%s could not be read (%s); nothing changed"
                                      % (shown, type(exc).__name__)) from None
                entries, problems = retractmod.parse_lenient(data)
                if problems:
                    self.error("%s: %d invalid part(s) dropped" % (shown, problems))
                for semver in sorted(entries):
                    rules = self.tombstone_rules(target, [semver, entries[semver]])
                    if rules:
                        del entries[semver]
                        self.error("%s: an entry is blocked (%s); dropped" % (shown, ", ".join(rules)))
                    elif (bid, semver) in live:
                        del entries[semver]
                        self.restored.append(live[(bid, semver)])
                        self.log("%s: published again; tombstone removed" % live[(bid, semver)])
            for semver, (tag, entry) in sorted(added.get(bid, {}).items()):
                entries[semver] = entry
                self.retracted.append(tag)
                self.log("%s: withdrawn (%s); tombstone added" % (tag, entry["reason"]))
            if entries:
                self.desired[target] = retractmod.dumps(entries)
            elif bid in on_disk:
                self.tombstone_removals.append(target)


def _verified(listing: Sequence[Dict[str, Any]], want: str, asset_id: Optional[int],
              name: str) -> Optional[Dict[str, Any]]:
    """The uploaded asset (by id, else by name) when it is listed as ``uploaded`` with digest ``want``."""
    if asset_id is not None:
        found = [a for a in listing if a.get("id") == asset_id]
    else:
        found = [a for a in listing if str(a.get("name", "")).lower() == name.lower()]
    if len(found) == 1 and found[0].get("state") == "uploaded" and found[0].get("digest") == want:
        return found[0]
    return None


def _upload_name(name: str, asset_id: int) -> str:
    """Temporary name of the normalized upload while the old IPA may still hold ``name``; it ends in
    ``.ipa`` too."""
    stem = name[:-4] if name.lower().endswith(".ipa") else name
    return "%s.normalized-%d.ipa" % (stem or "asset", asset_id)


def _download_url(url: Any, old_name: str, new_name: str) -> Any:
    """``url`` of an asset named ``old_name`` in the same release, for the asset named ``new_name``."""
    if not isinstance(url, str) or new_name == old_name:
        return url
    base, sep, _ = url.rpartition("/")
    return base + sep + urllib.parse.quote(new_name, safe="") if sep else url


def _republished(rel: Dict[str, Any], response: Any) -> Dict[str, Any]:
    out = dict(rel)
    if isinstance(response, dict):
        out.update(response)
    out["draft"] = False
    return out


def _int(value: Any) -> Optional[int]:
    """``value`` as a release id (None unless it is an integer)."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _utc_stamp(now: Optional[Callable[[], datetime.datetime]]) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` of ``now()`` (default: the current time)."""
    moment = now() if now is not None else datetime.datetime.now(datetime.timezone.utc)
    if moment.tzinfo is not None:
        moment = moment.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _text_hits(deps: Any, text: str, denylist: Sequence[str], where: str) -> List[Dict[str, Any]]:
    from .stage import text_findings

    return text_findings(deps, text, denylist, where) if text else []


def _rules(findings: Sequence[Dict[str, Any]]) -> List[str]:
    return sorted({f["rule"] for f in blocking(findings)})


def source_leaks(run: "_Run", source: Any) -> List[str]:
    """Counts-only problems for strings of the generated source that fail the leak check.

    Each app is checked with its own policy (the home-path opt-in), everything else strictly. A
    location names the app by position and the key only when the key is plain and clean itself.
    """
    if not isinstance(source, dict):
        return []
    apps = source.get("apps") if isinstance(source.get("apps"), list) else []
    groups: List[Tuple[str, Any, bool]] = [("source", {k: v for k, v in source.items() if k != "apps"}, False)]
    for index, app in enumerate(apps):
        bid = app.get("bundleIdentifier") if isinstance(app, dict) else None
        relaxed = isinstance(bid, str) and "/" not in bid and run.relaxed(run.policy_for(bid))
        groups.append(("apps[%d]" % index, app, relaxed))
    problems = []
    for where, obj, relaxed in groups:
        for key, value in (obj.items() if isinstance(obj, dict) else [("", obj)]):
            found = blocking(value_findings(run.deps, [key, value], run.denylist, where, relaxed=relaxed))
            if not found:
                continue
            plain = (isinstance(key, str) and _PLAIN_KEY.match(key) is not None
                     and not _text_hits(run.deps, key, run.denylist, where))
            problems.append("source.json %s%s: %s" % (where, "." + key if plain else "", ", ".join(
                "%s (%d)" % (f["rule"], f["count"]) for f in found)))
    return problems


def _generate(root: str, desired: Mapping[str, bytes], deps: Any, pages_base: Optional[str]) -> Any:
    """Run the generator on a staging copy that already contains the planned files."""
    with tempfile.TemporaryDirectory(prefix="alt-gen-") as staging:
        base = os.path.join(root, "source.base.json")
        if os.path.exists(base):
            shutil.copy2(base, os.path.join(staging, "source.base.json"))
        apps = os.path.join(root, "apps")
        if os.path.isdir(apps):
            shutil.copytree(apps, os.path.join(staging, "apps"),
                            ignore=lambda d, names: [n for n in names if n == "versions"])
        _write_tree(staging, {p: d for p, d in desired.items() if p != "source.json"}, [])
        kwargs = {"pages_base": pages_base} if pages_base else {}
        return deps.generate_source(staging, **kwargs)


def _counts(source: Any) -> Tuple[int, int]:
    apps = source.get("apps") if isinstance(source, dict) else None
    apps = apps if isinstance(apps, list) else []
    versions = sum(len(a.get("versions") or []) for a in apps if isinstance(a, dict))
    return len(apps), versions


def _merged(first: Sequence[str], second: Sequence[str]) -> List[str]:
    """Ordered union without duplicates."""
    return list(dict.fromkeys(list(first) + list(second)))


def _stderr_log(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def sync(
    repo_root: str,
    *,
    commit: bool = True,
    dry_run: bool = False,
    denylist: Sequence[str],
    scan_published: bool = True,
    rescan: bool = False,
    policy: Any = None,
    gh: Any = None,
    git: Any = None,
    deps: Any = None,
    branch: str = "main",
    max_attempts: int = 5,
    pages_base: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    output_path: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Optional[Callable[[], datetime.datetime]] = None,
) -> SyncResult:
    """Regenerate every derived file from the published releases and commit the difference.

    ``now`` returns the time that new tombstones carry (default: the current time); it is read
    once, so every attempt of the run plans the same files.
    """
    root = os.path.abspath(repo_root)
    deps = deps if deps is not None else Toolkit()
    log = log or _stderr_log
    env = os.environ if environ is None else environ
    if gh is None:
        from . import gh as ghmod

        gh = ghmod.client()
    git = git if git is not None else GitRepo(root, environ=env)
    if policy is None:
        policy = deps.GatePolicy()
    if scan_published and not denylist and not getattr(policy, "allow_empty_denylist", False):
        raise SyncAborted("denylist is empty or missing")
    from .gh import HeadMoved, write_outputs

    result = SyncResult(dry_run=dry_run)
    stamp = _utc_stamp(now)
    taken_down: Set[int] = set()
    cache: Dict[int, str] = {}
    carried_blocked: List[str] = []  # remediations of earlier attempts that ended in HeadMoved
    carried_errors: List[str] = []
    carried_normalized: List[str] = []
    with tempfile.TemporaryDirectory(prefix="alt-sync-") as tmp:
        for attempt in range(1, max_attempts + 1):
            result.attempts = attempt
            head = git.head()
            run = _Run(root, gh=gh, deps=deps, denylist=denylist, scan_published=scan_published,
                       policy=policy, dry_run=dry_run, log=log, tmp=tmp, cache=cache, rescan=rescan,
                       sleep=sleep, taken_down=taken_down)
            try:
                releases = gh.list_releases()
            except Exception as exc:
                raise SyncAborted("release listing failed (%s); nothing changed" % type(exc).__name__) from None
            if not isinstance(releases, list):
                raise SyncAborted("release listing is incomplete; nothing changed")

            existing = load_records(root)
            published: List[Tuple[Dict[str, Any], str, str, str]] = []
            seen_tags = set()
            for rel in releases:
                if rel.get("draft"):
                    continue
                tag = str(rel.get("tag_name") or "")
                try:
                    bid, semver = run.deps.parse_tag(tag)
                except run.tag_errors:
                    continue
                if tag in seen_tags:
                    shown = "release %d" % int(rel["id"]) if _rules(tag_findings(deps, tag, denylist)) else tag
                    run.warn("%s: more than one published release; extra ignored" % shown)
                    continue
                seen_tags.add(tag)
                published.append((rel, tag, str(bid), str(semver)))

            for rel, tag, bid, semver in published:
                run.process(rel, tag, bid, semver, existing)

            base = _read_json(os.path.join(root, "source.base.json"))
            base = base if isinstance(base, dict) else {}
            run.app_files(published, base)
            for path, record in run.records.items():
                run.desired[path] = dumps_json(record)
            run.plan_tombstones(existing, releases, published, stamp)

            source = _generate(root, run.desired, deps, pages_base)
            problems = [str(e) for e in (deps.validate_source(source) or [])]
            fatal = [e for e in problems if not e.lower().startswith("warning")]
            for message in problems:
                if message not in fatal:
                    run.warn(_WARNING_PREFIX.sub("", message, count=1))  # warn() adds the prefix
            if fatal:
                raise SyncAborted("generated source.json failed validation; nothing changed", fatal)
            # records passed already, so what remains comes from curated files: nothing is committed
            leaked = source_leaks(run, source)
            if leaked:
                raise SyncAborted("generated source.json failed the leak check; nothing changed", leaked)
            run.desired["source.json"] = dumps_json(source)

            tree = git.tree_blobs()
            additions = {p: d for p, d in run.desired.items() if tree.get(p) != git.blob_id(d)}
            removals = set(run.tombstone_removals)
            deletions = sorted(p for p in tree if (RECORD_RE.match(p) and p not in run.desired) or p in removals)
            local_deletions = sorted(set(deletions) | removals | {p for p in disk_record_paths(root)
                                                                  if p not in run.desired})

            result.apps, result.versions = _counts(source)
            result.errors = _merged(carried_errors, run.errors)
            result.warnings = list(run.warnings)
            result.blocked = _merged(carried_blocked, run.blocked)
            result.normalized = _merged(carried_normalized, run.normalized)
            result.retracted = list(run.retracted)
            result.restored = list(run.restored)
            result.files = sorted(set(additions) | set(deletions))
            result.changed = bool(additions or deletions)

            if not result.changed:
                log("catalog unchanged (%d app(s), %d version(s))" % (result.apps, result.versions))
                break
            if dry_run:
                for path in result.files:
                    log("would %s %s" % ("delete" if path in deletions else "write", path))
                break
            if commit:
                message = "catalog: sync %d app(s), %d version(s)" % (result.apps, result.versions)
                try:
                    result.commit = gh.commit_files(branch, head, additions, deletions, message)
                except HeadMoved:
                    if attempt >= max_attempts:
                        raise SyncError("the branch kept moving; gave up after %d attempts" % attempt) from None
                    log("branch moved; refreshing and retrying (attempt %d)" % (attempt + 1))
                    carried_blocked = list(result.blocked)
                    carried_errors = _merged(carried_errors, run.remediations)
                    carried_normalized = list(result.normalized)
                    git.refresh(branch)
                    continue
            _write_tree(root, run.desired, local_deletions)
            log("catalog %s: %d file(s) (%d app(s), %d version(s))" % (
                "committed" if commit else "written", len(result.files), result.apps, result.versions))
            break

    # written even when releases were blocked: a deploy step keyed on ``commit`` must still run
    write_outputs({"changed": result.changed, "commit": result.commit or "", "blocked": len(result.blocked),
                   "errors": len(result.errors), "retracted": len(result.retracted)}, output_path, env)
    return result
