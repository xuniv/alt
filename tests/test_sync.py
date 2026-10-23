"""Tests for the gh layer and catalog sync, plus in-memory fakes shared with other test modules.

Nothing here touches the network or a real repository: GitHub, git and the IPA tooling are fakes.
"""

from __future__ import annotations

import copy
import dataclasses
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import types
import unittest

from altsource import gh as ghmod
from altsource import sync as syncmod

# -- fake IPA tooling ---------------------------------------------------------------------------------

SEMVER = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
TAG_RE = re.compile(r"^(?P<bid>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)-v(?P<ver>" + SEMVER + r")$")
HOME_RE = re.compile(r"/users/(?!runner/|shared/)[a-z0-9._-]+/")

IPA_DEFAULTS = {
    "bundle_id": "io.example.demo",
    "short_version": "1.2.3",
    "build_version": "7",
    "name": "Demo App",
    "min_os": "15.0",
    "privacy": {"NSCameraUsageDescription": "Scans codes."},
    "entitlements": [],
    "payload": "binary",
}


class FakeIpaError(Exception):
    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


class FakeGateError(Exception):
    rule = "denylist-missing"


class FakeTagError(ValueError):
    pass


@dataclasses.dataclass
class FakePolicy:
    allow_home_paths: bool = False
    allow_empty_denylist: bool = False


class FakeSemVer:
    def __init__(self, text):
        if not re.fullmatch(SEMVER, text or ""):
            raise FakeTagError("bad semver")
        self.text = text
        core, _, pre = text.partition("-")
        self.core_parts = tuple(int(p) for p in core.split("."))
        self.core = core
        self.prerelease = pre or None

    @classmethod
    def parse(cls, text):
        return cls(text)

    def _key(self):
        if self.prerelease is None:
            return (self.core_parts, 1, ())
        ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.prerelease.split("."))
        return (self.core_parts, 0, ids)

    def __lt__(self, other):
        return self._key() < other._key()

    def __eq__(self, other):
        return isinstance(other, FakeSemVer) and self._key() == other._key()

    def __str__(self):
        return self.text


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def write_ipa(path, **fields):
    data = dict(IPA_DEFAULTS)
    data.update(fields)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def ipa_bytes(**fields):
    data = dict(IPA_DEFAULTS)
    data.update(fields)
    return json.dumps(data, sort_keys=True).encode("utf-8")


class FakeToolkit:
    IpaError = FakeIpaError
    GateError = FakeGateError
    TagError = FakeTagError
    GatePolicy = FakePolicy
    SemVer = FakeSemVer

    def __init__(self):
        self.validation_errors = []
        self.inspected = []
        self.scanned = []

    def inspect_ipa(self, path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.inspected.append(path)
        if data.get("broken"):
            raise FakeIpaError(data["broken"])
        info = dict(data)
        return types.SimpleNamespace(to_dict=lambda: dict(info), **info)

    def normalize_ipa(self, src, dst, strip_build_machine=True):
        with open(src, encoding="utf-8") as fh:
            data = json.load(fh)
        data.pop("junk", None)
        out = json.dumps(data, sort_keys=True).encode("utf-8")
        with open(dst, "wb") as fh:
            fh.write(out)
        return {"output_sha256": hashlib.sha256(out).hexdigest(), "output_size": len(out), "changed": True,
                "removed": [], "plist_keys_removed": 0}

    def _hits(self, data, denylist):
        low = data.lower()
        return {w: low.count(w.lower()) for w in denylist if w.lower() in low}

    def scan_ipa(self, path, *, denylist, policy=None, info=None):
        policy = policy or FakePolicy()
        if not denylist and not policy.allow_empty_denylist:
            raise FakeGateError("empty denylist")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if json.loads(text).get("broken"):
            raise FakeIpaError(json.loads(text)["broken"])
        self.scanned.append(path)
        findings = []
        hits = self._hits(text, denylist)
        if hits:
            findings.append({"rule": "denylist", "severity": "block", "count": sum(hits.values()),
                             "paths": ["Payload/Demo.app/Demo"]})
        homes = HOME_RE.findall(text.lower())
        if homes:
            findings.append({"rule": "home-path", "severity": "warn" if policy.allow_home_paths else "block",
                             "count": len(homes), "paths": ["Payload/Demo.app/Demo"]})
        ok = not any(f["severity"] == "block" for f in findings)
        return types.SimpleNamespace(ok=ok, findings=findings)

    def scan_text(self, text, denylist):
        rules = []
        if self._hits(text or "", denylist):
            rules.append("denylist")
        if HOME_RE.search((text or "").lower()):
            rules.append("home-path")
        return rules

    def extract_icon(self, path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return b"\x89PNG\r\n\x1a\n" + data["bundle_id"].encode()

    def parse_tag(self, tag):
        m = TAG_RE.match(tag or "")
        if not m or re.search(r"-v\d", m.group("bid")):
            raise FakeTagError("bad tag")
        return m.group("bid"), m.group("ver")

    def make_tag(self, bid, semver):
        tag = "%s-v%s" % (bid, semver)
        self.parse_tag(tag)
        return tag

    def core_matches(self, semver, short):
        parts = short.split(".")
        if not 1 <= len(parts) <= 3 or not all(p.isdigit() for p in parts):
            return False
        nums = tuple(int(p) for p in parts) + (0,) * (3 - len(parts))
        return nums == FakeSemVer(str(semver)).core_parts

    def alias_for(self, bid):
        return re.sub(r"[^A-Z0-9]", "_", bid.upper())

    def generate_source(self, root, pages_base="https://example.invalid/alt"):
        with open(os.path.join(root, "source.base.json"), encoding="utf-8") as fh:
            base = json.load(fh)
        apps = []
        for app_dir in sorted(glob.glob(os.path.join(root, "apps", "*"))):
            bid = os.path.basename(app_dir)
            app_path = os.path.join(app_dir, "app.json")
            app = load_json(app_path) if os.path.exists(app_path) else {}
            recs = [load_json(p) for p in glob.glob(os.path.join(app_dir, "versions", "*.json"))]
            if not app.get("includePrereleases"):
                recs = [r for r in recs if not r["prerelease"]]
            if not recs or app.get("hidden"):
                continue
            recs.sort(key=lambda r: FakeSemVer(r["semver"]), reverse=True)
            entry = {"name": app.get("name") or recs[0]["name"], "bundleIdentifier": bid,
                     "versions": [{"version": r["version"], "buildVersion": r["buildVersion"],
                                   "marketingVersion": r["semver"], "date": r["date"],
                                   "localizedDescription": r["localizedDescription"],
                                   "downloadURL": r["downloadURL"], "size": r["size"],
                                   "sha256": r["sha256"]} for r in recs]}
            if os.path.exists(os.path.join(app_dir, "icon.png")):
                entry["iconURL"] = "%s/apps/%s/icon.png" % (pages_base, bid)
            apps.append(entry)
        return {"name": base["name"], "identifier": base["identifier"], "apps": apps}

    def validate_source(self, obj):
        return list(self.validation_errors)


# -- fake GitHub ---------------------------------------------------------------------------------------

MUTATIONS = {"create_draft", "update_release", "upload_asset", "update_asset", "delete_asset", "publish",
             "unpublish", "delete_release", "commit_files", "dispatch_workflow", "delete_artifact"}


class FakeGitHub:
    repo = "example/alt"

    def __init__(self, git=None):
        self.releases = {}
        self.blobs = {}
        self.calls = []
        self.next_id = 1000
        self.list_error = None
        self.download_error = None
        self.git = git
        self.commits = []
        self.corrupt_uploads = False
        self.upload_failures = 0

    # helpers ---------------------------------------------------------------------------------
    def _id(self):
        self.next_id += 1
        return self.next_id

    def add_release(self, tag, *, draft=False, prerelease=False, body="", immutable=False,
                    published_at="2026-10-20T01:17:00Z"):
        rid = self._id()
        rel = {"id": rid, "tag_name": tag, "name": tag, "draft": draft, "prerelease": prerelease,
               "body": body, "immutable": immutable, "published_at": None if draft else published_at,
               "created_at": "2026-10-19T01:17:00Z", "assets": []}
        self.releases[rid] = rel
        return rel

    def add_asset(self, rel, name, data, *, state="uploaded", digest=True):
        aid = self._id()
        asset = {"id": aid, "name": name, "size": len(data), "state": state,
                 "digest": ("sha256:" + hashlib.sha256(data).hexdigest()) if digest else None,
                 "browser_download_url": self._url(rel, name)}
        self.blobs[aid] = data
        rel["assets"].append(asset)
        return asset

    def _url(self, rel, name):
        return "https://github.com/%s/releases/download/%s/%s" % (self.repo, rel["tag_name"], name)

    def mutations(self):
        return [c for c in self.calls if c[0] in MUTATIONS]

    def _rel(self, rid):
        return self.releases[int(rid)]

    # API -------------------------------------------------------------------------------------
    def list_releases(self):
        self.calls.append(("list_releases",))
        if self.list_error is not None:
            raise self.list_error
        return [copy.deepcopy(r) for _, r in sorted(self.releases.items(), reverse=True)]

    def get_release_by_tag(self, tag):
        self.calls.append(("get_release_by_tag", tag))
        matches = [r for r in self.releases.values() if r["tag_name"] == tag]
        published = [r for r in matches if not r["draft"]]
        pick = published or matches
        return copy.deepcopy(pick[0]) if pick else None

    def list_assets(self, release_id):
        self.calls.append(("list_assets", release_id))
        return copy.deepcopy(self._rel(release_id)["assets"])

    def create_draft(self, tag, target, name, body, prerelease):
        self.calls.append(("create_draft", tag, target, name, body, prerelease))
        rel = self.add_release(tag, draft=True, prerelease=prerelease, body=body)
        rel["name"] = name
        rel["target_commitish"] = target
        return copy.deepcopy(rel)

    def update_release(self, release_id, **fields):
        self.calls.append(("update_release", release_id, fields))
        self._rel(release_id).update(fields)
        return copy.deepcopy(self._rel(release_id))

    def _name_taken(self, release_id, name, except_id=None):
        return any(a["name"].lower() == name.lower() and a["id"] != except_id
                   for a in self._rel(release_id)["assets"])

    def upload_asset(self, release_id, path, name, content_type="application/octet-stream"):
        self.calls.append(("upload_asset", release_id, name, content_type))
        if self._name_taken(release_id, name):
            raise ghmod.GhError("POST release asset upload failed (HTTP 422): already_exists", status=422)
        if self.upload_failures:
            self.upload_failures -= 1
            self.add_asset(self._rel(release_id), name, b"", state="starter", digest=False)
            raise ghmod.GhError("POST release asset upload failed (HTTP 502)", status=502)
        with open(path, "rb") as fh:
            data = fh.read()
        asset = self.add_asset(self._rel(release_id), name, data)
        if self.corrupt_uploads:
            asset["digest"] = "sha256:" + "0" * 64
        return copy.deepcopy(asset)

    def update_asset(self, asset_id, **fields):
        self.calls.append(("update_asset", asset_id, fields))
        for rel in self.releases.values():
            for asset in rel["assets"]:
                if asset["id"] == asset_id:
                    if "name" in fields and self._name_taken(rel["id"], fields["name"], asset_id):
                        raise ghmod.GhError("PATCH asset failed (HTTP 422)", status=422)
                    asset.update(fields)
                    if "name" in fields:  # GitHub derives the download URL from the name
                        asset["browser_download_url"] = self._url(rel, asset["name"])
                    return copy.deepcopy(asset)
        raise ghmod.NotFound("PATCH asset failed (HTTP 404)", status=404)

    def delete_asset(self, asset_id):
        self.calls.append(("delete_asset", asset_id))
        for rel in self.releases.values():
            rel["assets"] = [a for a in rel["assets"] if a["id"] != asset_id]

    def publish(self, release_id, prerelease, make_latest="false"):
        self.calls.append(("publish", release_id, prerelease, make_latest))
        rel = self._rel(release_id)
        rel.update(draft=False, prerelease=prerelease, published_at="2026-10-21T07:13:00Z")
        return copy.deepcopy(rel)

    def unpublish(self, release_id, name=None):
        self.calls.append(("unpublish", release_id))
        self._rel(release_id)["draft"] = True
        if name is not None:
            self._rel(release_id)["name"] = name
        return copy.deepcopy(self._rel(release_id))

    def delete_release(self, release_id):
        self.calls.append(("delete_release", release_id))
        self.releases.pop(int(release_id), None)

    def download_asset(self, asset_id, dest):
        self.calls.append(("download_asset", asset_id))
        if self.download_error is not None:
            raise self.download_error
        with open(dest, "wb") as fh:
            fh.write(self.blobs[asset_id])
        return dest

    def commit_files(self, branch, expected_head, additions, deletions, message):
        self.calls.append(("commit_files", branch, expected_head, sorted(additions), sorted(deletions), message))
        git = self.git
        if expected_head != git.remote_oid:
            raise ghmod.HeadMoved("branch head moved")
        tree = dict(git.remote_tree)
        tree.update(additions)
        for path in deletions:
            tree.pop(path, None)
        git.remote_counter += 1
        git.remote_oid = "%040x" % git.remote_counter
        git.remote_tree = tree
        self.commits.append((message, dict(additions), list(deletions)))
        return git.remote_oid


class FakeGit:
    """HEAD of the local checkout plus a 'remote' branch that the fake GitHub commits to."""

    def __init__(self, root):
        self.root = root
        self.oid = "%040x" % 1
        self.tree = {}
        self.remote_counter = 1
        self.remote_oid = self.oid
        self.remote_tree = {}
        self.refreshes = 0

    def seed(self, files):
        """Commit ``files`` locally and remotely (as if the checkout was up to date)."""
        for path, data in files.items():
            full = os.path.join(self.root, *path.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as fh:
                fh.write(data)
        self.tree.update(files)
        self.remote_tree = dict(self.tree)

    def push_elsewhere(self, files=None):
        """Someone else moved the remote branch."""
        self.remote_counter += 1
        self.remote_oid = "%040x" % self.remote_counter
        self.remote_tree.update(files or {})

    def head(self):
        return self.oid

    def tree_blobs(self):
        return {p: self.blob_id(d) for p, d in self.tree.items()}

    @staticmethod
    def blob_id(data):
        return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()

    def refresh(self, branch):
        self.refreshes += 1
        self.oid = self.remote_oid
        self.tree = dict(self.remote_tree)


BASE = {"name": "alt", "identifier": "io.github.example.alt", "subtitle": "s", "description": "d",
        "website": "https://example.invalid", "tintColor": "5B6CFF",
        "defaults": {"developerName": "example", "category": "utilities", "tintColor": "5B6CFF"}}
DENY = ["leaky-host-0", "leakyuser0"]


class SyncCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.git = FakeGit(self.root)
        self.git.seed({"source.base.json": syncmod.dumps_json(BASE)})
        self.gh = FakeGitHub(self.git)
        self.deps = FakeToolkit()
        self.log = []
        self.output = os.path.join(self.root, "gh-output")

    def tearDown(self):
        self._tmp.cleanup()

    def run_sync(self, **kw):
        kw.setdefault("denylist", DENY)
        return syncmod.sync(self.root, gh=self.gh, git=self.git, deps=self.deps, log=self.log.append,
                            output_path=self.output, environ={}, **kw)

    def publish(self, tag, data, **kw):
        rel = self.gh.add_release(tag, **kw)
        asset = self.gh.add_asset(rel, "Demo-%s.ipa" % tag.split("-v")[-1], data)
        return rel, asset

    def read(self, rel):
        with open(os.path.join(self.root, *rel.split("/")), "rb") as fh:
            return fh.read()

    def outputs(self):
        with open(self.output, encoding="utf-8") as fh:
            return fh.read()


class SyncTests(SyncCase):
    def test_new_release_creates_record_app_icon_and_source(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="First release.\r\n")
        result = self.run_sync()
        self.assertTrue(result.changed)
        self.assertEqual((result.apps, result.versions), (1, 1))
        self.assertEqual(result.errors, [])
        message, additions, deletions = self.gh.commits[0]
        self.assertEqual(message, "catalog: sync 1 app(s), 1 version(s)")
        self.assertEqual(deletions, [])
        self.assertEqual(sorted(additions), [
            "apps/io.example.demo/app.json",
            "apps/io.example.demo/icon.png",
            "apps/io.example.demo/versions/1.2.3.json",
            "source.json",
        ])
        commit_call = [c for c in self.gh.calls if c[0] == "commit_files"][0]
        self.assertEqual(commit_call[1:3], ("main", "%040x" % 1))
        record = json.loads(additions["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["tag"], "io.example.demo-v1.2.3")
        self.assertEqual(record["schemaVersion"], 1)
        self.assertEqual(record["releaseId"], rel["id"])
        self.assertEqual(record["assetId"], asset["id"])
        self.assertEqual(record["assetDigest"], asset["digest"])
        self.assertEqual(record["sha256"], asset["digest"][7:])
        self.assertEqual(record["downloadURL"], asset["browser_download_url"])
        self.assertEqual(record["localizedDescription"], "First release.")
        self.assertEqual(record["date"], "2026-10-20T01:17:00Z")
        self.assertEqual(record["version"], "1.2.3")
        self.assertEqual(record["buildVersion"], "7")
        self.assertFalse(record["prerelease"])
        self.assertEqual(record["privacy"], {"NSCameraUsageDescription": "Scans codes."})
        app = json.loads(additions["apps/io.example.demo/app.json"])
        self.assertEqual(app, {"name": "Demo App", "developerName": "example", "category": "utilities",
                               "tintColor": "5B6CFF", "includePrereleases": False, "maxVersions": 10})
        self.assertTrue(additions["apps/io.example.demo/icon.png"].startswith(b"\x89PNG"))
        # the working tree mirrors the commit
        self.assertEqual(self.read("source.json"), additions["source.json"])
        self.assertTrue(additions["source.json"].endswith(b"}\n"))
        self.assertIn("changed=true\n", self.outputs())
        self.assertIn("commit=%s\n" % result.commit, self.outputs())
        self.assertIn("blocked=0\nerrors=0\n", self.outputs())
        # downloaded once: the icon reuses the cached IPA
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "download_asset"]), 1)

    def test_second_run_is_a_cache_hit_and_unchanged(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")  # local checkout catches up with the commit
        self.gh.calls.clear()
        os.unlink(self.output)
        result = self.run_sync()
        self.assertFalse(result.changed)
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])
        self.assertEqual(self.gh.mutations(), [])
        self.assertIn("changed=false\n", self.outputs())

    def test_cache_hit_updates_mutable_fields_without_download(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="old notes")
        self.run_sync()
        self.git.refresh("main")
        self.gh.releases[rel["id"]].update(body="new notes", published_at="2026-10-22T13:17:05.123Z")
        self.gh.calls.clear()
        result = self.run_sync()
        self.assertTrue(result.changed)
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])
        additions = self.gh.commits[-1][1]
        record = json.loads(additions["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["localizedDescription"], "new notes")
        self.assertEqual(record["date"], "2026-10-22T13:17:05Z")
        self.assertNotIn("apps/io.example.demo/app.json", additions)  # curated files are never rewritten

    def test_rescan_applies_a_new_denylist_to_cached_records(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="mentions newly-listed-word"))
        self.run_sync()
        self.git.refresh("main")
        deny = DENY + ["newly-listed-word"]
        self.gh.calls.clear()
        self.assertFalse(self.run_sync(denylist=deny).changed)  # the cache hides the new term
        self.assertEqual(self.gh.mutations(), [])
        result = self.run_sync(denylist=deny, rescan=True)
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertEqual(self.gh.commits[-1][2], ["apps/io.example.demo/versions/1.2.3.json"])

    def test_rescan_of_clean_releases_changes_nothing(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        self.gh.calls.clear()
        result = self.run_sync(rescan=True)
        self.assertFalse(result.changed)
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "download_asset"]), 1)

    def test_record_of_removed_release_is_deleted(self):
        rel_a, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3"))
        self.run_sync()
        self.git.refresh("main")
        self.assertTrue(os.path.exists(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json")))
        del self.gh.releases[rel_a["id"]]
        result = self.run_sync()
        self.assertTrue(result.changed)
        message, additions, deletions = self.gh.commits[-1]
        self.assertEqual(deletions, ["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(message, "catalog: sync 1 app(s), 1 version(s)")
        self.assertFalse(os.path.exists(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json")))

    def test_incomplete_listing_aborts_without_changes(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        before = sorted(glob.glob(os.path.join(self.root, "apps", "*", "versions", "*.json")))
        self.gh.list_error = ghmod.GhError("GET releases failed (HTTP 502)", status=502)
        self.gh.calls.clear()
        with self.assertRaises(syncmod.SyncAborted):
            self.run_sync()
        self.assertEqual(self.gh.mutations(), [])
        self.assertEqual(sorted(glob.glob(os.path.join(self.root, "apps", "*", "versions", "*.json"))), before)

    def test_head_moved_is_retried_after_refresh(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync()
        self.assertEqual(result.attempts, 2)
        self.assertEqual(self.git.refreshes, 1)
        commits = [c for c in self.gh.calls if c[0] == "commit_files"]
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[1][2], "%040x" % 2)
        self.assertEqual(result.commit, self.git.remote_oid)
        # restart re-lists releases; the download is reused from the first attempt
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "list_releases"]), 2)
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "download_asset"]), 1)

    def test_remediation_survives_head_moved_retry(self):
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="built on leaky-host-0"))
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync()
        self.assertEqual(result.attempts, 2)
        self.assertTrue(self.gh.releases[bad["id"]]["draft"])
        # the second attempt no longer sees the release, but the run must still report it
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("blocked (denylist); unpublished" in e for e in result.errors))
        self.assertEqual(result.versions, 1)
        self.assertEqual(len(self.gh.commits), 1)

    def test_scrubbed_notes_survive_head_moved_retry(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="built on leaky-host-0")
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync()
        self.assertEqual(result.attempts, 2)
        self.assertEqual(self.gh.releases[rel["id"]]["body"], "")
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertEqual(len([e for e in result.errors if "release notes blocked" in e]), 1)

    def test_failed_remediation_is_reported_once_per_tag(self):
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="built on leaky-host-0"))

        def broken(release_id, **kw):
            raise ghmod.GhError("PATCH failed (HTTP 500)", status=500)

        self.gh.unpublish = broken
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync()
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertEqual(len([e for e in result.errors if "remediation failed" in e]), 1)

    def test_head_moved_gives_up_after_max_attempts(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())

        class Restless(FakeGit):
            def refresh(inner, branch):
                inner.refreshes += 1
                inner.oid = inner.remote_oid
                inner.push_elsewhere()

        self.git.__class__ = Restless
        self.git.push_elsewhere()
        with self.assertRaises(syncmod.SyncError):
            self.run_sync(max_attempts=3)
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "commit_files"]), 3)

    def test_gate_blocked_published_release_is_unpublished(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="built on leaky-host-0"))
        result = self.run_sync()
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.versions, 0)
        self.assertFalse(any(p.endswith("1.2.3.json") for p in result.files))
        joined = "\n".join(self.log)
        self.assertIn("denylist", joined)
        self.assertNotIn("leaky-host-0", joined)

    def test_unpublished_release_is_marked_blocked(self):
        from altsource import stage as stagemod

        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="built on leaky-host-0"))
        self.run_sync()
        self.assertEqual(self.gh.releases[rel["id"]]["name"], "[blocked] io.example.demo-v1.2.3")
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps), ([], ["io.example.demo-v1.2.3"]))

    def test_gate_blocked_immutable_release_is_deleted(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser0/src"),
                              immutable=True)
        result = self.run_sync()
        self.assertIn(("delete_release", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_bundle_id_mismatch_is_unpublished(self):
        rel, _ = self.publish("io.example.other-v1.2.3", ipa_bytes())
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertTrue(any("bundle-id-mismatch" in e for e in result.errors))

    def test_version_mismatch_and_invalid_ipa_are_unpublished(self):
        rel_v, _ = self.publish("io.example.demo-v2.0.0", ipa_bytes())
        rel_b, _ = self.publish("io.example.demo-v1.0.0", ipa_bytes(broken="zip-traversal"))
        result = self.run_sync()
        self.assertIn(("unpublish", rel_v["id"]), self.gh.calls)
        self.assertIn(("unpublish", rel_b["id"]), self.gh.calls)
        self.assertTrue(any("zip-traversal" in e for e in result.errors))
        self.assertTrue(any("version-mismatch" in e for e in result.errors))

    def test_previously_published_record_is_dropped_when_rescan_blocks(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        # the asset is replaced on a mutable release by something that fails the gate
        self.gh.delete_asset(asset["id"])
        self.gh.add_asset(self.gh.releases[rel["id"]], "Demo-1.2.3.ipa", ipa_bytes(payload="leaky-host-0"))
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(self.gh.commits[-1][2], ["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(result.versions, 0)

    def test_dry_run_changes_nothing(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="leaky-host-0"))
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        result = self.run_sync(dry_run=True)
        self.assertTrue(result.changed)
        self.assertEqual(self.gh.mutations(), [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "source.json")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "apps")))
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_no_commit_writes_working_tree_only(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        result = self.run_sync(commit=False)
        self.assertTrue(result.changed)
        self.assertIsNone(result.commit)
        self.assertEqual([c for c in self.gh.calls if c[0] == "commit_files"], [])
        self.assertTrue(os.path.exists(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json")))
        self.assertTrue(os.path.exists(os.path.join(self.root, "source.json")))

    def test_validation_errors_abort_without_commit(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.deps.validation_errors = ["apps[0].tintColor: not 6 hex digits"]
        with self.assertRaises(syncmod.SyncAborted) as ctx:
            self.run_sync()
        self.assertEqual(ctx.exception.details, ["apps[0].tintColor: not 6 hex digits"])
        self.assertEqual([c for c in self.gh.calls if c[0] == "commit_files"], [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "source.json")))

    def test_validation_warnings_do_not_abort(self):
        self.deps.validation_errors = ["warning: source has no apps"]
        result = self.run_sync()
        self.assertTrue(result.changed)
        self.assertEqual(sorted(self.gh.commits[0][1]), ["source.json"])
        self.assertIn("source has no apps", result.warnings)
        self.assertIn("warning: source has no apps", self.log)  # the prefix appears once

    def test_validation_warning_prefix_is_not_repeated(self):
        self.deps.validation_errors = ["Warning: source: featured app io.example.gone is not listed"]
        result = self.run_sync()
        self.assertEqual(result.warnings, ["source: featured app io.example.gone is not listed"])
        self.assertFalse(any("warning: warning" in line.lower() for line in self.log))

    def test_second_ipa_on_recorded_release_is_unpublished(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        self.gh.add_asset(self.gh.releases[rel["id"]], "Other.ipa", ipa_bytes(payload="never scanned"))
        self.gh.calls.clear()
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("blocked (unexpected-asset)" in e for e in result.errors))
        self.assertEqual(self.gh.commits[-1][2], ["apps/io.example.demo/versions/1.2.3.json"])

    def test_extra_non_ipa_asset_is_unpublished(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.add_asset(rel, "build.log", b"anything at all")
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertEqual(result.versions, 0)
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])

    def test_extra_asset_on_immutable_release_deletes_it(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), immutable=True)
        self.gh.add_asset(rel, "Demo.app.dSYM.zip", b"zip")
        result = self.run_sync()
        self.assertIn(("delete_release", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_leaky_asset_name_takes_the_release_down(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo-leaky-host-0.ipa", ipa_bytes())
        result = self.run_sync()
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertIn("io.example.demo-v1.2.3: asset name blocked (denylist); unpublished", result.errors)
        self.assertEqual(self.gh.releases[rel["id"]]["name"], "[blocked] io.example.demo-v1.2.3")
        self.assertNotIn("download_asset", [c[0] for c in self.gh.calls])
        self.assertEqual(result.versions, 0)
        self.assertNotIn("leaky-host-0", "\n".join(self.log + result.errors + result.warnings))

    def test_renamed_asset_of_a_cached_record_is_checked_again(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        self.gh.update_asset(asset["id"], name="Demo-leakyuser0.ipa")  # same asset id and digest
        result = self.run_sync()
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertEqual(result.versions, 0)
        self.assertNotIn(b"leakyuser0", self.gh.commits[-1][1]["source.json"])

    def test_unfinished_assets_are_not_unexpected(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.add_asset(rel, "partial.zip", b"", state="starter")
        result = self.run_sync()
        self.assertEqual(result.blocked, [])
        self.assertEqual(result.versions, 1)

    def test_only_unfinished_ipa_keeps_previous_record(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        self.git.refresh("main")
        self.gh.releases[rel["id"]]["assets"][0]["state"] = "open"
        result = self.run_sync()
        self.assertFalse(result.changed)
        self.assertEqual(result.errors, [])
        self.assertTrue(any("no uploaded .ipa asset" in w for w in result.warnings))

    def test_missing_asset_without_previous_record_is_skipped(self):
        self.gh.add_release("io.example.demo-v1.2.3")
        result = self.run_sync()
        self.assertEqual(result.versions, 0)
        self.assertEqual(self.gh.mutations()[0][0], "commit_files")
        self.assertEqual(sorted(self.gh.commits[0][1]), ["source.json"])

    def test_digest_mismatch_is_an_error_without_remediation(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.blobs[asset["id"]] = ipa_bytes(payload="tampered")
        result = self.run_sync()
        self.assertTrue(any("download failed" in e for e in result.errors))
        self.assertNotIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.versions, 0)

    def test_missing_digest_is_an_error(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(), digest=False)
        result = self.run_sync()
        self.assertTrue(any("no sha256 digest" in e for e in result.errors))
        self.assertEqual(result.versions, 0)

    def test_drafts_and_foreign_tags_are_ignored(self):
        draft = self.gh.add_release("io.example.demo-v1.2.3", draft=True)
        self.gh.add_asset(draft, "Demo.ipa", ipa_bytes())
        other = self.gh.add_release("v1.0.0")
        self.gh.add_asset(other, "Demo.ipa", ipa_bytes())
        result = self.run_sync()
        self.assertEqual(result.versions, 0)
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])

    def test_prerelease_records(self):
        self.publish("io.example.demo-v1.3.0-beta.1", ipa_bytes(short_version="1.3.0"))
        self.publish("io.example.demo-v1.2.3", ipa_bytes(), prerelease=True)
        result = self.run_sync()
        additions = self.gh.commits[0][1]
        beta = json.loads(additions["apps/io.example.demo/versions/1.3.0-beta.1.json"])
        flagged = json.loads(additions["apps/io.example.demo/versions/1.2.3.json"])
        self.assertTrue(beta["prerelease"])
        self.assertTrue(flagged["prerelease"])
        self.assertEqual(result.versions, 0)  # the fake generator drops prereleases by default
        # the icon comes from the newest record by SemVer
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "download_asset"]), 2)

    def test_app_json_seed_from_release_asset(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        seed = {"name": "Seeded", "subtitle": "From the release", "category": "games",
                "privateBuild": {"enabled": True}}
        self.gh.add_asset(rel, "app.json", json.dumps(seed).encode())
        self.run_sync()
        app = json.loads(self.gh.commits[0][1]["apps/io.example.demo/app.json"])
        self.assertEqual(app["name"], "Seeded")
        self.assertEqual(app["subtitle"], "From the release")
        self.assertEqual(app["category"], "games")
        self.assertEqual(app["developerName"], "example")
        self.assertNotIn("privateBuild", app)  # seeds can only set descriptive fields

    def test_leaky_app_json_asset_unpublishes_release(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.add_asset(rel, "app.json", json.dumps({"subtitle": "made on leaky-host-0"}).encode())
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("blocked (denylist)" in e for e in result.errors))
        self.assertNotIn("apps/io.example.demo/app.json", self.gh.commits[0][1])
        self.assertNotIn("leaky-host-0", "\n".join(self.log))

    def test_invalid_app_json_asset_unpublishes_release(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.add_asset(rel, "app.json", b'{"tintColor": "#123456"}')
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertTrue(any("blocked (app-json-invalid)" in e for e in result.errors))

    def test_app_json_asset_is_part_of_the_cache_key(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.gh.add_asset(rel, "app.json", json.dumps({"subtitle": "Fine"}).encode())
        self.run_sync()
        self.git.refresh("main")
        record = load_json(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json"))
        seed = [a for a in self.gh.releases[rel["id"]]["assets"] if a["name"] == "app.json"][0]
        self.assertEqual(record["appJsonAssetId"], seed["id"])
        self.gh.calls.clear()
        self.assertFalse(self.run_sync().changed)
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])
        # a replaced app.json is a new asset: the release is checked again
        self.gh.delete_asset(seed["id"])
        self.gh.add_asset(self.gh.releases[rel["id"]], "app.json", b'{"subtitle": "on leaky-host-0"}')
        result = self.run_sync()
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_leaky_release_title_is_reset(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="Fine notes.")
        self.gh.releases[rel["id"]]["name"] = "Nightly from leaky-host-0"
        result = self.run_sync()
        self.assertIn(("update_release", rel["id"], {"name": "io.example.demo 1.2.3"}), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("release title blocked (denylist); reset" in e for e in result.errors))
        record = json.loads(self.gh.commits[0][1]["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["localizedDescription"], "Fine notes.")

    def test_leaky_title_and_notes_share_one_update(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="see /Users/leakyuser0/x")
        self.gh.releases[rel["id"]]["name"] = "leakyuser0 build"
        result = self.run_sync(dry_run=True)
        self.assertEqual(self.gh.mutations(), [])
        self.assertTrue(any("release title blocked (denylist); would be reset" in e for e in result.errors))
        self.assertTrue(any("release notes blocked (denylist, home-path); would be cleared" in e
                            for e in result.errors))
        result = self.run_sync()
        updates = [c for c in self.gh.calls if c[0] == "update_release"]
        self.assertEqual(updates, [("update_release", rel["id"], {"body": "", "name": "io.example.demo 1.2.3"})])

    def test_notes_are_scrubbed_even_without_usable_assets(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3", body="built on leaky-host-0")
        result = self.run_sync()
        self.assertIn(("update_release", rel["id"], {"body": ""}), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_missing_icon_is_not_retried_for_the_same_asset(self):
        self.deps.extract_icon = lambda path: None
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        result = self.run_sync()
        self.assertTrue(any("no usable icon" in w for w in result.warnings))
        record = json.loads(self.gh.commits[0][1]["apps/io.example.demo/versions/1.2.3.json"])
        self.assertIs(record["iconUnavailable"], True)
        for _ in range(2):
            self.git.refresh("main")
            self.gh.calls.clear()
            result = self.run_sync()
            self.assertFalse(result.changed)
            self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])
        # a newer version is tried again
        self.deps.extract_icon = FakeToolkit().extract_icon
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        self.run_sync()
        self.assertIn("apps/io.example.demo/icon.png", self.gh.commits[-1][1])

    def icons_only_for(self, *versions):
        """extract_icon finds an icon only in the IPAs of ``versions``; returns the versions asked."""
        asked = []

        def extract_icon(path):
            short = load_json(path)["short_version"]
            asked.append(short)
            return b"\x89PNG\r\n\x1a\n" + short.encode() if short in versions else None

        self.deps.extract_icon = extract_icon
        return asked

    def test_icon_comes_from_the_newest_listed_version(self):
        asked = self.icons_only_for("1.2.3", "1.1.0")
        self.publish("io.example.demo-v1.1.0", ipa_bytes(short_version="1.1.0"))
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.publish("io.example.demo-v1.3.0-beta.1", ipa_bytes(short_version="1.3.0"), prerelease=True)
        result = self.run_sync()
        self.assertEqual(asked, ["1.2.3"])  # the prerelease is not listed, so it is not asked first
        self.assertEqual(self.gh.commits[0][1]["apps/io.example.demo/icon.png"], b"\x89PNG\r\n\x1a\n1.2.3")
        self.assertFalse(any("no usable icon" in w for w in result.warnings))

    def test_icon_falls_back_to_an_older_version(self):
        asked = self.icons_only_for("1.1.0")
        self.publish("io.example.demo-v1.1.0", ipa_bytes(short_version="1.1.0"))
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.publish("io.example.demo-v1.3.0-beta.1", ipa_bytes(short_version="1.3.0"), prerelease=True)
        self.run_sync()
        self.assertEqual(asked, ["1.2.3", "1.1.0"])
        added = self.gh.commits[0][1]
        self.assertEqual(added["apps/io.example.demo/icon.png"], b"\x89PNG\r\n\x1a\n1.1.0")
        self.assertIs(json.loads(added["apps/io.example.demo/versions/1.2.3.json"])["iconUnavailable"], True)
        self.assertNotIn("iconUnavailable", json.loads(added["apps/io.example.demo/versions/1.1.0.json"]))

    def test_unlisted_versions_are_tried_last(self):
        asked = self.icons_only_for("1.3.0")
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.publish("io.example.demo-v1.3.0-beta.1", ipa_bytes(short_version="1.3.0"), prerelease=True)
        self.run_sync()
        self.assertEqual(asked, ["1.2.3", "1.3.0"])
        self.assertEqual(self.gh.commits[0][1]["apps/io.example.demo/icon.png"], b"\x89PNG\r\n\x1a\n1.3.0")

    def test_listed_prereleases_are_tried_first(self):
        self.git.seed({"apps/io.example.demo/app.json": b'{"includePrereleases": true}\n'})
        asked = self.icons_only_for("1.2.3", "1.3.0")
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.publish("io.example.demo-v1.3.0-beta.1", ipa_bytes(short_version="1.3.0"), prerelease=True)
        self.run_sync()
        self.assertEqual(asked, ["1.3.0"])

    def test_icon_download_failure_is_retried(self):
        rel, asset = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync(commit=False)  # records exist locally, the IPA was downloaded once
        self.git.seed({p: self.read(p) for p in ("apps/io.example.demo/versions/1.2.3.json",
                                                   "apps/io.example.demo/app.json", "source.json")})
        os.unlink(os.path.join(self.root, "apps/io.example.demo/icon.png"))
        self.gh.download_error = ghmod.GhError("GET failed (HTTP 502)", status=502)
        result = self.run_sync()
        self.assertTrue(any("icon download failed" in w for w in result.warnings))
        # the record is not marked: the next run tries again
        self.assertNotIn("apps/io.example.demo/versions/1.2.3.json", result.files)
        self.assertNotIn("iconUnavailable", load_json(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json")))

    def test_seed_comes_from_listed_releases_only(self):
        listed, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="see leaky-host-0")
        self.gh.add_asset(listed, "app.json", b'{"subtitle": "Listed"}')
        blocked, _ = self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0", payload="leaky-host-0"))
        self.gh.add_asset(blocked, "app.json", b'{"subtitle": "Blocked"}')
        result = self.run_sync()
        self.assertEqual(sorted(result.blocked), ["io.example.demo-v1.2.3", "io.example.demo-v1.3.0"])
        app = json.loads(self.gh.commits[0][1]["apps/io.example.demo/app.json"])
        self.assertEqual(app["subtitle"], "Listed")  # scrubbed notes do not disqualify a listed release

    def test_existing_curated_files_are_kept(self):
        self.git.seed({"apps/io.example.demo/app.json": b'{"name": "Curated"}\n',
                       "apps/io.example.demo/icon.png": b"curated"})
        self.publish("io.example.demo-v1.2.3", ipa_bytes())
        self.run_sync()
        additions = self.gh.commits[0][1]
        self.assertNotIn("apps/io.example.demo/app.json", additions)
        self.assertNotIn("apps/io.example.demo/icon.png", additions)
        self.assertEqual(json.loads(additions["source.json"])["apps"][0]["name"], "Curated")

    def test_allow_home_paths_opt_in_from_app_json(self):
        self.git.seed({"apps/io.example.demo/app.json": b'{"allowHomePaths": true}\n'})
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser3/build"))
        result = self.run_sync()
        self.assertEqual(result.blocked, [])
        self.assertEqual(result.versions, 1)

    def test_allow_home_paths_opt_in_from_release_app_json(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser3/build"))
        self.gh.add_asset(rel, "app.json", b'{"name": "Third", "allowHomePaths": true}')
        result = self.run_sync()
        self.assertEqual(result.blocked, [])
        self.assertEqual(result.versions, 1)
        app = json.loads(self.gh.commits[0][1]["apps/io.example.demo/app.json"])
        self.assertIs(app["allowHomePaths"], True)  # later runs read the opt-in from the repository
        self.assertEqual(app["name"], "Third")

    def test_committed_app_json_overrides_release_opt_in(self):
        self.git.seed({"apps/io.example.demo/app.json": b'{"name": "Curated"}\n'})
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser3/build"))
        self.gh.add_asset(rel, "app.json", b'{"allowHomePaths": true}')
        result = self.run_sync()
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertIn(("unpublish", rel["id"]), self.gh.calls)

    def test_opt_in_of_an_older_release_is_kept_in_the_seed(self):
        old, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser3/build"))
        self.gh.add_asset(old, "app.json", b'{"allowHomePaths": true}')
        new, _ = self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        self.gh.add_asset(new, "app.json", b'{"subtitle": "Newer"}')
        result = self.run_sync()
        self.assertEqual(result.versions, 2)
        app = json.loads(self.gh.commits[0][1]["apps/io.example.demo/app.json"])
        self.assertEqual((app["subtitle"], app["allowHomePaths"]), ("Newer", True))

    def test_immutable_release_blocked_only_by_home_path_is_not_deleted(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser3/build"),
                              immutable=True)
        result = self.run_sync()
        self.assertNotIn(("delete_release", rel["id"]), self.gh.calls)
        self.assertIn(rel["id"], self.gh.releases)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("immutable release left in place" in e for e in result.errors))
        self.assertEqual(result.versions, 0)

    def test_immutable_release_with_denylist_hit_is_still_deleted(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="/Users/leakyuser0/build"),
                              immutable=True)
        self.run_sync()
        self.assertIn(("delete_release", rel["id"]), self.gh.calls)

    def test_release_notes_with_leak_are_cleared(self):
        rel, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(), body="built on leaky-host-0")
        result = self.run_sync()
        self.assertIn(("update_release", rel["id"], {"body": ""}), self.gh.calls)
        record = json.loads(self.gh.commits[0][1]["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["localizedDescription"], "Version 1.2.3")
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_empty_denylist_aborts_before_listing(self):
        with self.assertRaises(syncmod.SyncAborted):
            self.run_sync(denylist=[])
        self.assertEqual(self.gh.calls, [])

    def test_gate_error_aborts_whole_sync(self):
        self.publish("io.example.demo-v1.2.3", ipa_bytes())

        def failing(*a, **k):
            raise FakeGateError("scanner unavailable")

        self.deps.scan_ipa = failing
        with self.assertRaises(syncmod.SyncAborted):
            self.run_sync()
        self.assertEqual(self.gh.mutations(), [])


class ScannerErrorTests(SyncCase):
    def scanner_raising(self, exc, bad_payload="unreadable"):
        real = self.deps.scan_ipa

        def scan(path, **kw):
            with open(path, encoding="utf-8") as fh:
                if bad_payload in fh.read():
                    raise exc
            return real(path, **kw)

        self.deps.scan_ipa = scan

    def test_ipa_error_from_scanner_blocks_only_that_release(self):
        self.scanner_raising(FakeIpaError("zip-bomb-ratio"))
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="unreadable"))
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        result = self.run_sync()
        self.assertIn(("unpublish", bad["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])
        self.assertTrue(any("blocked (zip-bomb-ratio)" in e for e in result.errors))
        self.assertEqual(result.versions, 1)
        self.assertEqual(len(self.gh.commits), 1)

    def test_corrupt_archive_from_scanner_is_remediated(self):
        import zipfile

        self.scanner_raising(zipfile.BadZipFile("Bad CRC-32 for file 'x'"))
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="unreadable"))
        result = self.run_sync()
        self.assertIn(("unpublish", bad["id"]), self.gh.calls)
        self.assertTrue(any("blocked (ipa-invalid)" in e for e in result.errors))

    def test_corrupt_archive_from_inspection_is_remediated(self):
        import zlib

        def inspect(path):
            raise zlib.error("invalid stored block lengths")

        self.deps.inspect_ipa = inspect
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes())
        result = self.run_sync()
        self.assertIn(("unpublish", bad["id"]), self.gh.calls)
        self.assertEqual(result.blocked, ["io.example.demo-v1.2.3"])

    def test_local_os_error_skips_without_remediation(self):
        self.scanner_raising(OSError(28, "No space left on device"))
        bad, _ = self.publish("io.example.demo-v1.2.3", ipa_bytes(payload="unreadable"))
        result = self.run_sync()
        self.assertNotIn(("unpublish", bad["id"]), self.gh.calls)
        self.assertEqual(result.blocked, [])
        self.assertTrue(any("could not be scanned (OSError)" in e for e in result.errors))
        self.assertEqual(result.versions, 0)


class FakeNormalizeError(ValueError):
    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


class NormalizePublishedTests(SyncCase):
    """A gate-clean IPA published without stage is replaced by its normalized form."""

    TAG = "io.example.demo-v1.2.3"
    FINAL = "Demo-App-1.2.3.ipa"  # <SafeName>-<semver>.ipa from the IPA's name "Demo App", as stage names it

    def setUp(self):
        super().setUp()
        self.deps.NormalizeError = FakeNormalizeError

    def publish_raw(self, **kw):
        """A release whose IPA is not in normalized form (the fake normalizer drops ``junk``)."""
        return self.publish(self.TAG, ipa_bytes(junk=True), **kw)

    def record(self):
        return load_json(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json"))

    def ipa_assets(self, rel):
        return [a for a in self.gh.releases[rel["id"]]["assets"] if a["name"].endswith(".ipa")]

    def test_ipa_is_replaced_and_the_release_published_again(self):
        rel, old = self.publish_raw(body="Notes.")
        result = self.run_sync()
        self.assertEqual((result.errors, result.blocked, result.normalized), ([], [], [self.TAG]))
        [new] = self.ipa_assets(rel)
        upload = "Demo-App-1.2.3.normalized-%d.ipa" % old["id"]
        self.assertEqual([c for c in self.gh.mutations() if c[0] != "commit_files"], [
            ("unpublish", rel["id"]),
            ("upload_asset", rel["id"], upload, "application/octet-stream"),
            ("delete_asset", old["id"]),
            ("update_asset", new["id"], {"name": self.FINAL}),
            ("publish", rel["id"], False, "false"),
        ])
        released = self.gh.releases[rel["id"]]
        self.assertFalse(released["draft"])
        self.assertEqual(released["body"], "Notes.")
        self.assertEqual(self.gh.blobs[new["id"]], ipa_bytes())
        self.assertEqual(new["name"], self.FINAL)
        record = self.record()
        self.assertEqual(record["assetId"], new["id"])
        self.assertEqual(record["assetDigest"], "sha256:" + hashlib.sha256(ipa_bytes()).hexdigest())
        self.assertEqual(record["sha256"], hashlib.sha256(ipa_bytes()).hexdigest())
        self.assertEqual(record["size"], len(ipa_bytes()))
        self.assertEqual(record["downloadURL"], self.gh._url(rel, self.FINAL))
        self.assertEqual(record["downloadURL"], new["browser_download_url"])
        self.assertEqual(record["date"], "2026-10-21T07:13:00Z")  # published again
        self.assertEqual(record["localizedDescription"], "Notes.")
        self.assertIn("%s: IPA replaced by its normalized form; release published again" % self.TAG, self.log)
        # the original and the normalized file were checked; the icon reused the normalized file
        self.assertEqual(len(self.deps.scanned), 2)
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "download_asset"]), 1)
        # the next run finds the normalized asset recorded
        self.git.refresh("main")
        self.gh.calls.clear()
        again = self.run_sync()
        self.assertFalse(again.changed)
        self.assertEqual((self.gh.mutations(), again.normalized), ([], []))
        self.assertEqual([c for c in self.gh.calls if c[0] == "download_asset"], [])

    def test_prerelease_flag_of_the_release_is_kept(self):
        rel, _ = self.publish_raw(prerelease=True)
        self.run_sync()
        self.assertIn(("publish", rel["id"], True, "false"), self.gh.calls)
        self.assertTrue(self.gh.releases[rel["id"]]["prerelease"])
        self.assertTrue(self.record()["prerelease"])

    def test_app_json_asset_is_kept(self):
        rel, _ = self.publish_raw()
        seed = self.gh.add_asset(rel, "app.json", b'{"subtitle": "Kept"}')
        result = self.run_sync()
        self.assertEqual(result.normalized, [self.TAG])
        names = sorted(a["name"] for a in self.gh.releases[rel["id"]]["assets"])
        self.assertEqual(names, [self.FINAL, "app.json"])
        self.assertEqual(self.record()["appJsonAssetId"], seed["id"])
        self.git.refresh("main")
        self.assertFalse(self.run_sync().changed)

    def test_normalized_ipa_is_left_alone(self):
        rel, asset = self.publish(self.TAG, ipa_bytes())
        result = self.run_sync()
        self.assertEqual(result.normalized, [])
        self.assertEqual([c[0] for c in self.gh.mutations()], ["commit_files"])
        self.assertEqual(self.record()["assetId"], asset["id"])
        self.assertEqual(len(self.deps.scanned), 1)

    def test_immutable_release_is_recorded_as_it_is(self):
        rel, asset = self.publish_raw(immutable=True)
        result = self.run_sync()
        self.assertEqual([c[0] for c in self.gh.mutations()], ["commit_files"])
        self.assertEqual((result.errors, result.blocked, result.normalized), ([], [], []))
        self.assertTrue(any("not in normalized form, but the release is immutable; recorded as published" in w
                            for w in result.warnings))
        self.assertEqual(self.record()["assetId"], asset["id"])

    def test_immutable_release_that_cannot_be_normalized_is_recorded(self):
        def refuse(src, dst, **kw):
            raise FakeNormalizeError("zip-symlink")

        self.deps.normalize_ipa = refuse
        rel, asset = self.publish_raw(immutable=True)
        result = self.run_sync()
        self.assertEqual(result.blocked, [])
        self.assertTrue(any("cannot be normalized (zip-symlink); recorded as published" in w
                            for w in result.warnings))
        self.assertEqual(self.record()["assetId"], asset["id"])

    def test_dry_run_only_reports(self):
        self.publish_raw()
        result = self.run_sync(dry_run=True)
        self.assertEqual(self.gh.mutations(), [])
        self.assertEqual(result.normalized, [])
        self.assertTrue(any("would be replaced and published again" in w for w in result.warnings))

    def test_nothing_is_normalized_without_the_gate(self):
        rel, asset = self.publish_raw()
        result = self.run_sync(scan_published=False)
        self.assertEqual([c[0] for c in self.gh.mutations()], ["commit_files"])
        self.assertEqual(self.record()["assetId"], asset["id"])
        self.assertEqual(result.normalized, [])

    def test_ipa_that_cannot_be_normalized_is_taken_down(self):
        def refuse(src, dst, **kw):
            raise FakeNormalizeError("zip-case-collision")

        self.deps.normalize_ipa = refuse
        rel, _ = self.publish_raw()
        result = self.run_sync()
        self.assertEqual(result.blocked, [self.TAG])
        self.assertTrue(any("blocked (zip-case-collision); unpublished" in e for e in result.errors))
        self.assertEqual(self.gh.releases[rel["id"]]["name"], "[blocked] " + self.TAG)
        self.assertNotIn("upload_asset", [c[0] for c in self.gh.calls])
        self.assertEqual(result.versions, 0)

    def assert_normalized_form_is_taken_down(self, planted, rule):
        real = self.deps.normalize_ipa

        def tamper(src, dst, **kw):
            report = real(src, dst, **kw)
            data = dict(load_json(dst), **planted)
            with open(dst, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            return report

        self.deps.normalize_ipa = tamper
        rel, _ = self.publish_raw()
        result = self.run_sync()
        self.assertEqual(result.blocked, [self.TAG])
        self.assertTrue(any("blocked (%s); unpublished" % rule in e for e in result.errors), result.errors)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertNotIn("upload_asset", [c[0] for c in self.gh.calls])
        self.assertEqual(result.versions, 0)
        self.assertNotIn("leaky-host-0", "\n".join(self.log + result.errors + result.warnings))

    def test_normalized_form_with_a_leak_is_taken_down(self):
        self.assert_normalized_form_is_taken_down({"payload": "built on leaky-host-0"}, "denylist")

    def test_normalized_form_with_another_identity_is_taken_down(self):
        self.assert_normalized_form_is_taken_down({"bundle_id": "io.example.other"}, "normalize-mismatch")

    def test_unreadable_normalized_form_is_taken_down(self):
        self.assert_normalized_form_is_taken_down({"broken": "zip-traversal"}, "zip-traversal")

    def test_failed_unpublish_records_the_release_as_it_is(self):
        def broken(release_id, name=None):
            raise ghmod.GhError("PATCH failed (HTTP 500)", status=500)

        self.gh.unpublish = broken
        rel, asset = self.publish_raw()
        result = self.run_sync()
        self.assertTrue(any("not normalized: unpublishing failed (GhError); recorded as published" in e
                            for e in result.errors))
        self.assertEqual(self.record()["assetId"], asset["id"])
        self.assertEqual([c[0] for c in self.gh.mutations()], ["commit_files"])

    def assert_restored(self, rel, old, result, failure):
        released = self.gh.releases[rel["id"]]
        self.assertFalse(released["draft"])
        self.assertEqual([a["id"] for a in released["assets"]], [old["id"]])
        self.assertEqual(self.gh.blobs[old["id"]], ipa_bytes(junk=True))
        self.assertEqual(self.record()["assetId"], old["id"])
        self.assertEqual(self.record()["date"], "2026-10-21T07:13:00Z")
        self.assertTrue(any("not normalized: %s; published again unchanged" % failure in e
                            for e in result.errors), result.errors)
        self.assertEqual((result.blocked, result.normalized), ([], []))

    def test_failed_upload_restores_the_release(self):
        self.gh.upload_failures = 1  # leaves an unfinished asset behind, like GitHub does
        rel, old = self.publish_raw()
        result = self.run_sync()
        self.assert_restored(rel, old, result, "upload failed (GhError)")

    def test_restoring_keeps_the_app_json_asset(self):
        self.gh.upload_failures = 1
        rel, old = self.publish_raw()
        seed = self.gh.add_asset(rel, "app.json", b'{"subtitle": "Kept"}')
        result = self.run_sync()
        self.assertEqual(sorted(a["id"] for a in self.gh.releases[rel["id"]]["assets"]), [old["id"], seed["id"]])
        self.assertEqual(self.record()["appJsonAssetId"], seed["id"])
        self.assertEqual(result.blocked, [])

    def test_publish_response_without_assets(self):
        rel, old = self.publish_raw()
        real = self.gh.publish

        def publish(release_id, prerelease, make_latest="false"):
            response = real(release_id, prerelease, make_latest)
            response.pop("assets")
            return response

        self.gh.publish = publish
        result = self.run_sync()
        self.assertEqual(result.normalized, [self.TAG])
        [new] = self.ipa_assets(rel)
        record = self.record()
        self.assertEqual((record["assetId"], record["assetDigest"]), (new["id"], new["digest"]))
        self.assertEqual(record["downloadURL"], self.gh._url(rel, self.FINAL))

    def test_digest_mismatch_after_upload_restores_the_release(self):
        self.gh.corrupt_uploads = True
        rel, old = self.publish_raw()
        result = self.run_sync(sleep=lambda s: None)
        self.assert_restored(rel, old, result, "verification failed (StageError)")

    def test_failed_delete_of_the_old_ipa_restores_the_release(self):
        rel, old = self.publish_raw()
        delete = self.gh.delete_asset

        def delete_asset(asset_id):
            if asset_id == old["id"]:
                self.gh.calls.append(("delete_asset", asset_id))
                raise ghmod.GhError("DELETE failed (HTTP 502)", status=502)
            delete(asset_id)

        self.gh.delete_asset = delete_asset
        result = self.run_sync()
        self.assert_restored(rel, old, result, "deleting the old IPA failed (GhError)")

    def test_delete_that_failed_but_took_effect_finishes_the_replacement(self):
        rel, old = self.publish_raw()
        delete = self.gh.delete_asset

        def delete_asset(asset_id):
            delete(asset_id)
            if asset_id == old["id"]:
                raise ghmod.GhError("DELETE failed (HTTP 502)", status=502)

        self.gh.delete_asset = delete_asset
        result = self.run_sync()
        self.assertEqual((result.errors, result.normalized), ([], [self.TAG]))
        [new] = self.ipa_assets(rel)
        self.assertEqual((new["name"], self.record()["assetId"]), (self.FINAL, new["id"]))

    def fail_delete_after_it_took_effect(self, old, list_failures):
        """``delete_asset(old)`` takes effect but reports an error; then ``list_failures`` listings fail."""
        delete, list_assets = self.gh.delete_asset, self.gh.list_assets
        state = {"failures": 0}

        def failing_delete(asset_id):
            delete(asset_id)
            if asset_id == old["id"]:
                state["failures"] = list_failures
                raise ghmod.GhError("DELETE failed (HTTP 502)", status=502)

        def failing_list(release_id):
            if state["failures"]:
                state["failures"] -= 1
                self.gh.calls.append(("list_assets", release_id))
                raise ghmod.GhError("GET failed (HTTP 502)", status=502)
            return list_assets(release_id)

        self.gh.delete_asset, self.gh.list_assets = failing_delete, failing_list

    def test_delete_that_took_effect_and_a_failed_listing_still_finish_the_replacement(self):
        rel, old = self.publish_raw()
        self.fail_delete_after_it_took_effect(old, list_failures=1)
        result = self.run_sync(sleep=lambda s: None)
        self.assertEqual((result.errors, result.normalized), ([], [self.TAG]))
        [new] = self.ipa_assets(rel)
        self.assertEqual((new["name"], self.record()["assetId"]), (self.FINAL, new["id"]))
        self.assertFalse(self.gh.releases[rel["id"]]["draft"])

    def test_assets_that_cannot_be_listed_leave_the_upload_in_a_draft(self):
        rel, old = self.publish_raw()
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        self.fail_delete_after_it_took_effect(old, list_failures=2)
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync(sleep=lambda s: None)
        self.assertEqual(result.attempts, 2)
        message = "%s: not normalized: deleting the old IPA failed (GhError); the release's assets could not " \
                  "be listed; left as a draft" % self.TAG
        self.assertEqual([e for e in result.errors if e.startswith(self.TAG)], [message])
        released = self.gh.releases[rel["id"]]
        self.assertTrue(released["draft"])
        [upload] = self.ipa_assets(rel)  # the only copy of the IPA is kept
        self.assertEqual(self.gh.blobs[upload["id"]], ipa_bytes())
        self.assertEqual(result.versions, 1)
        self.assertFalse(os.path.exists(os.path.join(self.root, "apps/io.example.demo/versions/1.2.3.json")))

    def test_old_ipa_gone_and_upload_unverified_leave_a_draft(self):
        rel, old = self.publish_raw()
        self.gh.corrupt_uploads = True
        upload = self.gh.upload_asset

        def upload_and_lose_the_old_ipa(release_id, path, name, content_type="application/octet-stream"):
            response = upload(release_id, path, name, content_type)
            self.gh.delete_asset(old["id"])  # removed elsewhere meanwhile
            return response

        self.gh.upload_asset = upload_and_lose_the_old_ipa
        result = self.run_sync(sleep=lambda s: None)
        self.assertTrue(any("verification failed (StageError); the old IPA is gone and the upload could not be "
                            "verified; left as a draft" in e for e in result.errors), result.errors)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertEqual(len(self.ipa_assets(rel)), 1)  # nothing deleted, nothing published
        self.assertNotIn("publish", [c[0] for c in self.gh.calls])
        self.assertEqual(result.versions, 0)

    def test_failed_restore_leaves_a_draft_and_is_reported_after_head_moved(self):
        from altsource import stage as stagemod

        self.gh.corrupt_uploads = True
        rel, old = self.publish_raw()
        self.publish("io.example.demo-v1.3.0", ipa_bytes(short_version="1.3.0"))
        real_publish = self.gh.publish

        def publish(release_id, prerelease, make_latest="false"):
            if release_id == rel["id"]:
                raise ghmod.GhError("PATCH failed (HTTP 500)", status=500)
            return real_publish(release_id, prerelease, make_latest)

        self.gh.publish = publish
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync(sleep=lambda s: None)
        self.assertEqual(result.attempts, 2)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertEqual(len([e for e in result.errors if "restoring failed (GhError); left as a draft" in e]), 1)
        self.assertEqual(result.versions, 1)
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps), ([self.TAG], []))

    def test_failed_publish_after_the_replacement_leaves_a_draft_for_stage_draft(self):
        from altsource import stage as stagemod

        def broken(release_id, prerelease, make_latest="false"):
            raise ghmod.GhError("PATCH failed (HTTP 500)", status=500)

        self.gh.publish = broken
        rel, old = self.publish_raw()
        result = self.run_sync()
        self.assertTrue(any("publishing again failed (GhError); left as a draft for stage-draft" in e
                            for e in result.errors))
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertEqual([a["name"] for a in self.ipa_assets(rel)], [self.FINAL])
        self.assertEqual(result.versions, 0)
        self.assertEqual(result.normalized, [])
        # the draft carries one gated, normalized IPA: the scheduled stage-draft run can publish it
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps), ([self.TAG], []))

    def test_failed_rename_keeps_the_upload_name(self):
        def broken(asset_id, **fields):
            raise ghmod.GhError("PATCH asset failed (HTTP 500)", status=500)

        self.gh.update_asset = broken
        rel, old = self.publish_raw()
        result = self.run_sync()
        self.assertEqual((result.errors, result.normalized), ([], [self.TAG]))
        self.assertTrue(any("keeps its upload name (GhError)" in w for w in result.warnings))
        [new] = self.ipa_assets(rel)
        upload = "Demo-App-1.2.3.normalized-%d.ipa" % old["id"]
        self.assertEqual(new["name"], upload)
        self.assertEqual(self.record()["downloadURL"], new["browser_download_url"])
        self.assertTrue(self.record()["downloadURL"].endswith("/" + upload))

    def test_replacement_survives_head_moved_retry(self):
        rel, old = self.publish_raw()
        self.git.push_elsewhere({"README.md": b"x\n"})
        result = self.run_sync()
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.normalized, [self.TAG])
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "upload_asset"]), 1)
        self.assertEqual(len([c for c in self.gh.calls if c[0] == "unpublish"]), 1)
        # the second attempt reads the normalized file from the cache instead of downloading it
        self.assertEqual([c[1] for c in self.gh.calls if c[0] == "download_asset"], [old["id"]])
        [new] = self.ipa_assets(rel)
        record = json.loads(self.gh.commits[-1][1]["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["assetId"], new["id"])

    def test_local_trouble_while_normalizing_keeps_the_previous_record(self):
        rel, asset = self.publish(self.TAG, ipa_bytes())
        self.run_sync()
        self.git.refresh("main")

        def full(src, dst, **kw):
            raise OSError(28, "No space left on device")

        self.deps.normalize_ipa = full
        result = self.run_sync(rescan=True)
        self.assertTrue(any("IPA could not be normalized (OSError); skipped" in e for e in result.errors))
        self.assertFalse(result.changed)
        self.assertEqual(self.record()["assetId"], asset["id"])
        self.assertEqual(result.blocked, [])


class RealNormalizeTests(unittest.TestCase):
    """sync with the real inspection, normalization, gate and validator on directly published IPAs."""

    TAG = "io.example.demo-v1.2.3"

    def setUp(self):
        from altsource import stage as stagemod

        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.git = FakeGit(self.root)
        self.git.seed({"source.base.json": syncmod.dumps_json(BASE)})
        self.gh = FakeGitHub(self.git)
        self.deps = stagemod.Toolkit()

    def tearDown(self):
        self._tmp.cleanup()

    def publish(self, files=None, name="Demo.ipa"):
        """A release carrying an IPA built without normalization (junk entry, BuildMachineOSBuild)."""
        from tests import helpers

        entries = helpers.app_entries(extra={"BuildMachineOSBuild": "23A344"}, binary=True)
        entries["__MACOSX/Payload/Demo.app/._Demo"] = b"\x00\x05\x16\x07"
        entries.update(files or {})
        path = helpers.build_ipa(entries, os.path.join(self.root, "raw.ipa"))
        rel = self.gh.add_release(self.TAG)
        return rel, self.gh.add_asset(rel, name, read_bytes(path)), path

    def run_sync(self):
        return syncmod.sync(self.root, gh=self.gh, git=self.git, deps=self.deps, denylist=DENY,
                            log=lambda m: None, environ={}, sleep=lambda s: None)

    def test_directly_published_ipa_is_normalized_once(self):
        from altsource import normalize as normmod

        rel, old, raw = self.publish()
        expected = os.path.join(self.root, "expected.ipa")
        normmod.normalize_ipa(raw, expected)
        result = self.run_sync()
        self.assertEqual((result.errors, result.blocked, result.normalized), ([], [], [self.TAG]))
        [new] = self.gh.releases[rel["id"]]["assets"]
        self.assertEqual((new["name"], self.gh.blobs[new["id"]]), ("Demo-1.2.3.ipa", read_bytes(expected)))
        self.assertNotEqual(new["id"], old["id"])
        record = json.loads(self.gh.commits[0][1]["apps/io.example.demo/versions/1.2.3.json"])
        self.assertEqual(record["assetDigest"], new["digest"])
        self.git.refresh("main")
        self.assertFalse(self.run_sync().changed)  # normalizing the normalized IPA changes nothing

    def test_linux_home_paths_only_warn(self):
        rel, _, _ = self.publish({"Payload/Demo.app/help.txt": "keys live in /home/leakyuser1/.ssh\n"})
        result = self.run_sync()
        self.assertEqual((result.blocked, result.normalized, result.versions), ([], [self.TAG], 1))
        self.assertFalse(self.gh.releases[rel["id"]]["draft"])

    def test_validator_warning_is_logged_with_one_prefix(self):
        log = []
        result = syncmod.sync(self.root, gh=self.gh, git=self.git, deps=self.deps, denylist=DENY,
                              log=log.append, environ={}, sleep=lambda s: None)
        self.assertEqual(result.versions, 0)
        self.assertIn("source has no apps (Feather rejects an empty source)", result.warnings)
        self.assertIn("warning: source has no apps (Feather rejects an empty source)", log)
        self.assertFalse(any("warning: warning" in line.lower() for line in log))

    def test_published_itunes_metadata_takes_the_release_down(self):
        rel, old, _ = self.publish({"iTunesMetadata.plist": "<plist><dict/></plist>\n"})
        result = self.run_sync()
        self.assertEqual((result.blocked, result.normalized, result.versions), ([self.TAG], [], 0))
        self.assertTrue(any("blocked (itunes-metadata); unpublished" in e for e in result.errors), result.errors)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])

    def test_leaky_asset_name_is_never_published_by_the_catalog(self):
        rel, _, _ = self.publish(name="Demo-leaky-host-0.ipa")
        result = self.run_sync()
        self.assertEqual((result.blocked, result.normalized, result.versions), ([self.TAG], [], 0))
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        for _, additions, _ in self.gh.commits:
            self.assertFalse(any(b"leaky-host-0" in data for data in additions.values()))

    def test_macos_home_path_takes_the_release_down(self):
        rel, old, _ = self.publish({"Payload/Demo.app/help.txt": "built in /Users/leakyuser1/src\n"})
        result = self.run_sync()
        self.assertEqual((result.blocked, result.normalized, result.versions), ([self.TAG], [], 0))
        self.assertTrue(any("blocked (home-path); unpublished" in e for e in result.errors))
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertEqual([a["id"] for a in self.gh.releases[rel["id"]]["assets"]], [old["id"]])


class SyncHelperTests(unittest.TestCase):
    def test_upload_name_and_download_url(self):
        self.assertEqual(syncmod._upload_name("Demo-1.2.3.IPA", 7), "Demo-1.2.3.normalized-7.ipa")
        self.assertEqual(syncmod._upload_name(".ipa", 7), "asset.normalized-7.ipa")
        url = "https://github.com/example/alt/releases/download/x-v1.0.0/Demo.ipa"
        self.assertEqual(syncmod._download_url(url, "Demo.ipa", "Demo.ipa"), url)
        self.assertEqual(syncmod._download_url(url, "Demo.ipa", "Demo.normalized-7.ipa"),
                         "https://github.com/example/alt/releases/download/x-v1.0.0/Demo.normalized-7.ipa")
        self.assertIsNone(syncmod._download_url(None, "a.ipa", "b.ipa"))

    def test_normalize_date(self):
        self.assertEqual(syncmod.normalize_date("2026-10-23T07:28:00Z"), "2026-10-23T07:28:00Z")
        self.assertEqual(syncmod.normalize_date("2026-10-23T07:28:00.512Z"), "2026-10-23T07:28:00Z")
        self.assertEqual(syncmod.normalize_date("2026-10-23T09:28:00+02:00"), "2026-10-23T07:28:00Z")
        self.assertIsNone(syncmod.normalize_date(None))
        self.assertIsNone(syncmod.normalize_date("yesterday"))

    def test_release_notes(self):
        self.assertEqual(syncmod.release_notes("  \r\n", "1.0.0"), "Version 1.0.0")
        self.assertEqual(syncmod.release_notes("a\r\nb", "1.0.0"), "a\nb")
        self.assertEqual(len(syncmod.release_notes("x" * 5000, "1.0.0")), 4000)

    def test_dumps_json_is_stable(self):
        self.assertEqual(syncmod.dumps_json({"b": "é", "a": [1]}), '{\n  "b": "é",\n  "a": [\n    1\n  ]\n}\n'.encode())

    @unittest.skipUnless(shutil.which("git"), "git missing")
    def test_git_repo_blob_ids_match_git(self):
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            run = lambda *a: subprocess.run(["git", "-C", root] + list(a), check=True, capture_output=True, env=env)
            try:
                run("init", "-q")
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("git unavailable")
            os.makedirs(os.path.join(root, "apps", "x", "versions"))
            data = b'{"tag": "x-v1.0.0"}\n'
            with open(os.path.join(root, "apps", "x", "versions", "1.0.0.json"), "wb") as fh:
                fh.write(data)
            run("add", "-A")
            run("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--no-verify",
                "-m", "seed")
            repo = syncmod.GitRepo(root, environ={})
            blobs = repo.tree_blobs()
            self.assertEqual(blobs["apps/x/versions/1.0.0.json"], repo.blob_id(data))
            self.assertEqual(len(repo.head()), 40)
            with self.assertRaises(syncmod.SyncError):
                repo.refresh("main")  # outside CI the checkout is never reset


@unittest.skipUnless(shutil.which("git"), "git missing")
class GitRefreshTests(unittest.TestCase):
    """GitRepo.refresh in CI mode: fetch the branch and reset a stale (even detached) checkout to it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args, cwd=None):
        proc = subprocess.run(["git"] + list(args), cwd=cwd, env=self.env, capture_output=True)
        if proc.returncode != 0:
            self.skipTest("git unavailable: %s" % args[0])
        return proc.stdout.decode().strip()

    def commit(self, work, name, data):
        with open(os.path.join(work, name), "w", encoding="utf-8") as fh:
            fh.write(data)
        self.git("add", name, cwd=work)
        self.git("commit", "-q", "--no-verify", "-m", "change " + name, cwd=work)
        self.git("push", "-q", "origin", "HEAD:main", cwd=work)
        return self.git("rev-parse", "HEAD", cwd=work)

    def test_refresh_resets_a_stale_detached_checkout(self):
        origin = os.path.join(self.dir, "origin.git")
        work = os.path.join(self.dir, "work")
        ci = os.path.join(self.dir, "ci")
        self.git("init", "-q", "--bare", origin)
        self.git("symbolic-ref", "HEAD", "refs/heads/main", cwd=origin)
        self.git("clone", "-q", origin, work)
        self.git("checkout", "-q", "-b", "main", cwd=work)
        self.commit(work, "source.json", "{}\n")
        self.git("clone", "-q", "--depth=1", "file://" + origin, ci)
        self.git("checkout", "-q", "--detach", cwd=ci)  # like a checkout of a tag or an older sha
        latest = self.commit(work, "apps.txt", "moved\n")

        repo = syncmod.GitRepo(ci, environ={"GITHUB_ACTIONS": "true"})
        self.assertNotEqual(repo.head(), latest)
        repo.refresh("main")
        self.assertEqual(repo.head(), latest)
        self.assertIn("apps.txt", repo.tree_blobs())
        with open(os.path.join(ci, "apps.txt"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "moved\n")

    def test_refresh_failure_is_a_sync_error(self):
        work = os.path.join(self.dir, "lonely")
        self.git("init", "-q", work)
        self.git("commit", "-q", "--no-verify", "--allow-empty", "-m", "seed", cwd=work)
        repo = syncmod.GitRepo(work, environ={"GITHUB_ACTIONS": "true"})
        with self.assertRaises(syncmod.SyncError):
            repo.refresh("main")  # no origin remote


# -- gh layer -----------------------------------------------------------------------------------------

class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, args, *, input=None, stdout_path=None):
        self.calls.append({"args": list(args), "input": input, "stdout_path": stdout_path})
        rc, out, err = self.responses.pop(0)
        if callable(out):
            out = out(args, input, stdout_path)
        if stdout_path is not None and rc == 0:
            with open(stdout_path, "wb") as fh:
                fh.write(out)
            out = b""
        elif stdout_path is not None:
            with open(stdout_path, "wb") as fh:
                fh.write(b"partial")
        return subprocess.CompletedProcess(args, rc, out, err)


def ok(obj):
    return (0, json.dumps(obj).encode(), b"")


def http_error(status, message="Error"):
    return (1, json.dumps({"message": message}).encode(), ("gh: %s (HTTP %d)\n" % (message, status)).encode())


class GhClientTests(unittest.TestCase):
    def client(self, *responses):
        runner = FakeRunner(responses)
        return ghmod.GitHub("example/alt", runner=runner, sleep=lambda s: None), runner

    def test_get_with_fields_uses_query_string(self):
        client, runner = self.client(ok({"x": 1}))
        self.assertEqual(client.api("GET", "repos/example/alt/releases", fields={"per_page": 5}), {"x": 1})
        args = runner.calls[0]["args"]
        self.assertEqual(args[:3], ["api", "--method", "GET"])
        self.assertEqual(args[-1], "repos/example/alt/releases?per_page=5")
        self.assertNotIn("--input", args)
        self.assertIn("X-GitHub-Api-Version: 2022-11-28", args)

    def test_post_sends_json_body_on_stdin(self):
        client, runner = self.client(ok({"id": 7}))
        client.create_draft("io.example.demo-v1.0.0", "main", "Demo 1.0.0", "notes", False)
        call = runner.calls[0]
        self.assertIn("--input", call["args"])
        self.assertEqual(call["args"][call["args"].index("--input") + 1], "-")
        body = json.loads(call["input"])
        self.assertEqual(body, {"tag_name": "io.example.demo-v1.0.0", "target_commitish": "main",
                                "name": "Demo 1.0.0", "body": "notes", "draft": True, "prerelease": False})

    def test_list_releases_paginates_and_dedupes(self):
        page1 = [{"id": i, "tag_name": "t%d" % i, "draft": False} for i in range(100)]
        page2 = [{"id": 99, "tag_name": "t99", "draft": False}, {"id": 100, "tag_name": "t100", "draft": True}]
        client, runner = self.client(ok(page1), ok(page2))
        releases = client.list_releases()
        self.assertEqual(len(releases), 101)
        self.assertTrue(runner.calls[0]["args"][-1].endswith("per_page=100&page=1"))
        self.assertTrue(runner.calls[1]["args"][-1].endswith("per_page=100&page=2"))

    def test_list_releases_raises_on_page_error(self):
        page1 = [{"id": i, "tag_name": "t%d" % i, "draft": False} for i in range(100)]
        client, _ = self.client(ok(page1), http_error(404, "Not Found"))
        with self.assertRaises(ghmod.GhError):
            client.list_releases()

    def test_get_retries_transient_errors_but_mutations_do_not(self):
        client, runner = self.client(http_error(502, "Bad Gateway"), ok([]))
        self.assertEqual(client.api("GET", "repos/example/alt/releases"), [])
        self.assertEqual(len(runner.calls), 2)
        client, runner = self.client(http_error(502, "Bad Gateway"))
        with self.assertRaises(ghmod.GhError) as ctx:
            client.delete_release(5)
        self.assertEqual(ctx.exception.status, 502)
        self.assertEqual(len(runner.calls), 1)

    def test_get_release_by_tag_falls_back_to_drafts(self):
        drafts = [{"id": 3, "tag_name": "io.example.demo-v1.0.0", "draft": True},
                  {"id": 2, "tag_name": "other-v1.0.0", "draft": True}]
        client, runner = self.client(http_error(404, "Not Found"), ok(drafts))
        rel = client.get_release_by_tag("io.example.demo-v1.0.0")
        self.assertEqual(rel["id"], 3)
        self.assertEqual(runner.calls[0]["args"][-1], "repos/example/alt/releases/tags/io.example.demo-v1.0.0")
        client, _ = self.client(http_error(404, "Not Found"), ok([]))
        self.assertIsNone(client.get_release_by_tag("io.example.demo-v1.0.0"))

    def test_upload_asset_targets_uploads_host(self):
        client, runner = self.client(ok({"id": 9, "name": "Demo-1.0.0.ipa"}))
        client.upload_asset(5, "x.ipa", "Demo 1.0.0.ipa")
        args = runner.calls[0]["args"]
        self.assertEqual(args[-1], "https://uploads.github.com/repos/example/alt/releases/5/assets?name=Demo%201.0.0.ipa")
        self.assertEqual(args[args.index("--input") + 1], os.path.abspath("x.ipa"))
        self.assertIn("Content-Type: application/octet-stream", args)

    def test_download_asset_streams_to_file_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "a.ipa")
            client, runner = self.client((0, b"IPA", b""))
            client.download_asset(12, dest)
            self.assertEqual(read_bytes(dest), b"IPA")
            self.assertIn("Accept: application/octet-stream", runner.calls[0]["args"])
            self.assertEqual(runner.calls[0]["stdout_path"], dest)
            client, _ = self.client(http_error(404, "Not Found"))
            with self.assertRaises(ghmod.NotFound):
                client.download_asset(12, dest)
            self.assertFalse(os.path.exists(dest))

    def test_update_asset_patches_the_asset(self):
        client, runner = self.client(ok({"id": 9, "name": "Demo-1.0.0.ipa"}))
        client.update_asset(9, name="Demo-1.0.0.ipa")
        call = runner.calls[0]
        self.assertEqual(call["args"][2], "PATCH")
        self.assertEqual(call["args"][-1], "repos/example/alt/releases/assets/9")
        self.assertEqual(json.loads(call["input"]), {"name": "Demo-1.0.0.ipa"})

    def test_publish_and_unpublish_payloads(self):
        client, runner = self.client(ok({}), ok({}), ok({}))
        client.publish(5, prerelease=True)
        client.unpublish(5)
        client.unpublish(5, name="[blocked] x-v1.0.0")
        self.assertEqual(json.loads(runner.calls[0]["input"]), {"draft": False, "prerelease": True, "make_latest": "false"})
        self.assertEqual(json.loads(runner.calls[1]["input"]), {"draft": True})
        self.assertEqual(json.loads(runner.calls[2]["input"]), {"draft": True, "name": "[blocked] x-v1.0.0"})
        self.assertEqual(runner.calls[0]["args"][2], "PATCH")

    def test_commit_files_builds_create_commit_on_branch(self):
        client, runner = self.client(ok({"data": {"createCommitOnBranch": {"commit": {"oid": "abc"}}}}))
        oid = client.commit_files("main", "f" * 40, {"source.json": b"{}\n"}, ["apps/x/versions/1.0.0.json"],
                                  "catalog: sync 1 app(s), 1 version(s)")
        self.assertEqual(oid, "abc")
        call = runner.calls[0]
        self.assertEqual(call["args"][:2], ["api", "graphql"])
        body = json.loads(call["input"])
        inp = body["variables"]["input"]
        self.assertEqual(inp["branch"], {"repositoryNameWithOwner": "example/alt", "branchName": "main"})
        self.assertEqual(inp["expectedHeadOid"], "f" * 40)
        self.assertEqual(inp["message"], {"headline": "catalog: sync 1 app(s), 1 version(s)"})
        self.assertEqual(inp["fileChanges"]["additions"], [{"path": "source.json", "contents": "e30K"}])
        self.assertEqual(inp["fileChanges"]["deletions"], [{"path": "apps/x/versions/1.0.0.json"}])
        self.assertIn("createCommitOnBranch", body["query"])

    def test_commit_files_stale_head_raises_head_moved(self):
        stale = {"data": None, "errors": [{"type": "STALE_DATA", "message":
                 "Expected branch to point to \"%s\" but it did not. Pull and try again." % ("f" * 40)}]}
        client, _ = self.client((1, json.dumps(stale).encode(), b"GraphQL: Expected branch to point to"))
        with self.assertRaises(ghmod.HeadMoved):
            client.commit_files("main", "f" * 40, {"a": b"b"}, [], "m")
        other = {"errors": [{"type": "FORBIDDEN", "message": "Resource not accessible by integration"}]}
        client, _ = self.client((1, json.dumps(other).encode(), b""))
        with self.assertRaises(ghmod.GraphQLError):
            client.commit_files("main", "f" * 40, {"a": b"b"}, [], "m")
        with self.assertRaises(ValueError):
            client.commit_files("main", "f" * 40, {}, [], "m")

    def test_dispatch_and_artifact_paths(self):
        client, runner = self.client((0, b"", b""), (0, b"", b""))
        self.assertIsNone(client.dispatch_workflow("stage.yml", "main", {"tag": "x-v1.0.0"}))
        client.delete_artifact(44)
        self.assertEqual(runner.calls[0]["args"][-1], "repos/example/alt/actions/workflows/stage.yml/dispatches")
        self.assertEqual(json.loads(runner.calls[0]["input"]), {"ref": "main", "inputs": {"tag": "x-v1.0.0"}})
        self.assertEqual(runner.calls[1]["args"][-1], "repos/example/alt/actions/artifacts/44")

    def test_error_message_has_no_stderr_text(self):
        client, _ = self.client((1, b"", b"gh: something about leaky-host-0 (HTTP 403)"))
        with self.assertRaises(ghmod.GhError) as ctx:
            client.delete_asset(1)
        self.assertEqual(ctx.exception.status, 403)
        self.assertNotIn("leaky-host-0", str(ctx.exception))

    def test_repo_is_validated(self):
        with self.assertRaises(ghmod.GhError):
            ghmod.GitHub("not a repo", runner=FakeRunner([]))

    def test_module_level_functions_use_replaceable_client(self):
        fake = FakeGitHub()
        previous = ghmod.set_client(fake)
        try:
            self.assertEqual(ghmod.list_releases(), [])
        finally:
            ghmod.set_client(previous)
        self.assertEqual(fake.calls, [("list_releases",)])

    def test_write_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out")
            self.assertFalse(ghmod.write_outputs({"a": 1}, environ={}))
            self.assertTrue(ghmod.write_outputs({"changed": True, "cmd": "line1\nline2"}, environ={"GITHUB_OUTPUT": path}))
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertTrue(text.startswith("changed=true\ncmd<<ALT_EOF_"))
            self.assertIn("\nline1\nline2\nALT_EOF_", text)
            with self.assertRaises(ValueError):
                ghmod.format_output("bad key", "x")


if __name__ == "__main__":
    unittest.main()
