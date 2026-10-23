"""Source generation and validation, the landing page, and the pipeline running on the real modules."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

from altsource import cli, retract, source, tags
from altsource import stage as stagemod
from altsource import sync as syncmod
from tests.test_sync import BASE, DENY, FakeGit, FakeGitHub, FakeToolkit, ipa_bytes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BID = "io.example.demo"
PAGES = "https://example.invalid/alt"


def record(semver="1.2.3", bid=BID, **fields):
    """A version record as sync writes it."""
    core = semver.split("-")[0]
    seed = int(hashlib.sha256(("%s %s" % (bid, semver)).encode()).hexdigest()[:6], 16)
    sha = hashlib.sha256(("%s %s" % (bid, semver)).encode()).hexdigest()
    rec = {
        "schemaVersion": 1,
        "tag": "%s-v%s" % (bid, semver),
        "bundleIdentifier": bid,
        "semver": semver,
        "version": core,
        "buildVersion": str(seed % 1000 + 1),
        "prerelease": "-" in semver,
        "date": "2026-10-20T01:17:00Z",
        "localizedDescription": "Notes for %s." % semver,
        "downloadURL": "https://github.com/example/alt/releases/download/%s-v%s/Demo-%s.ipa" % (bid, semver, semver),
        "size": 1000 + seed % 5000,
        "sha256": sha,
        "minOSVersion": "15.0",
        "releaseId": seed,
        "assetId": seed + 1,
        "assetDigest": "sha256:" + sha,
        "name": "Demo",
        "privacy": {},
        "entitlements": [],
    }
    rec.update(fields)
    return rec


class Repo:
    def __init__(self, root, base=None):
        self.root = root
        self.write("source.base.json", BASE if base is None else base)

    def write(self, rel, obj):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(obj if isinstance(obj, bytes) else source.dumps_source(obj))
        return path

    def app(self, bid=BID, app_json=None, icon=False):
        os.makedirs(os.path.join(self.root, "apps", bid), exist_ok=True)
        if app_json is not None:
            self.write("apps/%s/app.json" % bid, app_json)
        if icon:
            self.write("apps/%s/icon.png" % bid, b"\x89PNG\r\n\x1a\n")

    def add(self, *records):
        for rec in records:
            self.write("apps/%s/versions/%s.json" % (rec["bundleIdentifier"], rec["semver"]), rec)

    def generate(self, **kw):
        logs = []
        kw.setdefault("pages_base", PAGES)
        obj = source.generate_source(self.root, log=logs.append, **kw)
        return obj, logs


class SourceCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def only_app(self, obj):
        self.assertEqual(len(obj["apps"]), 1)
        return obj["apps"][0]

    def assertValid(self, obj):
        errors = [e for e in source.validate_source(obj) if not e.startswith("warning")]
        self.assertEqual(errors, [])


class GenerateTests(SourceCase):
    def test_minimal_app_and_key_order(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.2.3"))
        obj, logs = self.repo.generate()
        self.assertEqual(logs, [])
        self.assertEqual(list(obj), ["name", "identifier", "subtitle", "description", "iconURL", "website",
                                     "tintColor", "apps"])
        app = self.only_app(obj)
        self.assertEqual(list(app), [
            "name", "bundleIdentifier", "developerName", "localizedDescription", "iconURL", "tintColor",
            "category", "versions", "appPermissions", "version", "versionDate", "versionDescription",
            "downloadURL", "size"])
        rec = record("1.2.3")
        self.assertEqual(app["versions"], [{
            "version": "1.2.3", "buildVersion": rec["buildVersion"], "marketingVersion": "1.2.3",
            "date": "2026-10-20T01:17:00Z", "localizedDescription": "Notes for 1.2.3.",
            "downloadURL": rec["downloadURL"], "size": rec["size"], "sha256": rec["sha256"],
            "minOSVersion": "15.0"}])
        self.assertEqual(app["name"], "Demo")  # newest record's name when app.json has none
        self.assertEqual(app["developerName"], "example")  # source.base.json defaults
        self.assertEqual(app["category"], "utilities")
        self.assertEqual(app["tintColor"], "5B6CFF")
        self.assertEqual(app["localizedDescription"], "Demo")
        self.assertEqual(app["iconURL"], PAGES + "/apps/io.example.demo/icon.png")
        self.assertEqual(obj["iconURL"], app["iconURL"])  # source icon falls back to the first app icon
        self.assertValid(obj)

    def test_never_emits_forbidden_or_internal_keys(self):
        base = dict(BASE, marketplaceID="1", version=2, permissions=[], userInfo={"a": "b"},
                    patreonURL="https://example.invalid/p")
        repo = Repo(os.path.join(self._tmp.name, "other"), base)
        repo.app(app_json={"name": "Demo", "privateBuild": {"enabled": True}, "allowHomePaths": True,
                           "includePrereleases": False, "maxVersions": 5, "hidden": False}, icon=True)
        repo.add(record("1.0.0"))
        obj, _ = repo.generate()
        text = source.dumps_source(obj).decode()
        for key in ("marketplaceID", '"permissions"', "defaults", "privateBuild", "allowHomePaths",
                    "includePrereleases", "maxVersions", "hidden", "userInfo", "patreonURL", "schemaVersion",
                    "releaseId", "assetId", "assetDigest", '"tag"', '"semver"', '"prerelease"'):
            self.assertNotIn(key, text)
        self.assertNotIn("version", obj)

    def test_versions_newest_first_by_semver(self):
        self.repo.app(icon=True)
        dates = {"1.2.0": "2026-10-22T00:00:00Z", "1.10.0": "2026-10-01T00:00:00Z", "1.9.0": "2026-10-10T00:00:00Z"}
        for ver, date in dates.items():
            self.repo.add(record(ver, date=date))
        obj, _ = self.repo.generate()
        app = self.only_app(obj)
        self.assertEqual([v["marketingVersion"] for v in app["versions"]], ["1.10.0", "1.9.0", "1.2.0"])
        self.assertValid(obj)

    def test_prereleases_need_opt_in(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0"), record("1.1.0-rc.1"), record("1.1.0"),
                      record("1.2.0", prerelease=True))  # marked prerelease on GitHub only
        obj, _ = self.repo.generate()
        self.assertEqual([v["marketingVersion"] for v in self.only_app(obj)["versions"]], ["1.1.0", "1.0.0"])
        self.repo.app(app_json={"includePrereleases": True})
        obj, _ = self.repo.generate()
        self.assertEqual([v["marketingVersion"] for v in self.only_app(obj)["versions"]],
                         ["1.2.0", "1.1.0", "1.1.0-rc.1", "1.0.0"])
        self.assertValid(obj)

    def test_only_prereleases_means_not_listed(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0-beta.1"))
        obj, _ = self.repo.generate()
        self.assertEqual(obj["apps"], [])
        self.assertEqual(obj["iconURL"], PAGES + "/icon.png")  # the site icon when no app has one

    def test_duplicate_version_and_build_keeps_higher_semver(self):
        self.repo.app(app_json={"includePrereleases": True}, icon=True)
        self.repo.add(record("1.0.0-rc.1", version="1.0.0", buildVersion="42"),
                      record("1.0.0", version="1.0.0", buildVersion="42"),
                      record("0.9.0"))
        obj, logs = self.repo.generate()
        self.assertEqual([v["marketingVersion"] for v in self.only_app(obj)["versions"]], ["1.0.0", "0.9.0"])
        self.assertEqual(len(logs), 1)
        self.assertIn("io.example.demo-v1.0.0-rc.1 repeats version 1.0.0 build 42", logs[0])
        self.assertValid(obj)

    def test_max_versions_cap_and_permission_union_over_listed_versions(self):
        self.repo.app(app_json={"maxVersions": 2}, icon=True)
        self.repo.add(
            record("1.2.0", privacy={"NSCameraUsageDescription": "Newest camera text."},
                   entitlements=["keychain-access-groups"]),
            record("1.1.0", privacy={"NSCameraUsageDescription": "Older camera text.",
                                     "NSMicrophoneUsageDescription": "Record audio."},
                   entitlements=["com.apple.security.application-groups", "keychain-access-groups"]),
            record("1.0.0", privacy={"NSLocationWhenInUseUsageDescription": "Not listed any more."},
                   entitlements=["aps-environment"]),
        )
        obj, _ = self.repo.generate()
        app = self.only_app(obj)
        self.assertEqual([v["marketingVersion"] for v in app["versions"]], ["1.2.0", "1.1.0"])
        self.assertEqual(app["appPermissions"], {
            "entitlements": ["com.apple.security.application-groups", "keychain-access-groups"],
            "privacy": {"NSCameraUsageDescription": "Newest camera text.",
                        "NSMicrophoneUsageDescription": "Record audio."},
        })
        self.assertValid(obj)

    def test_privacy_descriptions_are_never_empty(self):
        self.repo.app(app_json={"name": "Curated"}, icon=True)
        self.repo.add(record("1.1.0", privacy={"NSCameraUsageDescription": "", "NFCReaderUsageDescription": None}),
                      record("1.0.0", privacy={"NSCameraUsageDescription": "Older text."}))
        obj, _ = self.repo.generate()
        self.assertEqual(self.only_app(obj)["appPermissions"]["privacy"], {
            "NFCReaderUsageDescription": "Used by Curated.", "NSCameraUsageDescription": "Older text."})
        self.assertValid(obj)

    def test_legacy_fields_mirror_the_newest_version(self):
        self.repo.app(icon=True)
        self.repo.add(record("2.0.0", localizedDescription="  New things.\n"), record("1.0.0"))
        app = self.only_app(self.repo.generate()[0])
        first = app["versions"][0]
        self.assertEqual(first["localizedDescription"], "New things.")
        self.assertEqual((app["version"], app["versionDate"], app["versionDescription"], app["downloadURL"],
                          app["size"]),
                         (first["version"], first["date"], first["localizedDescription"], first["downloadURL"],
                          first["size"]))

    def test_optional_version_fields(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0", buildVersion="", minOSVersion=None, localizedDescription=""))
        version = self.only_app(self.repo.generate()[0])["versions"][0]
        self.assertNotIn("buildVersion", version)  # absent, not "" (which never equals CFBundleVersion)
        self.assertNotIn("minOSVersion", version)
        self.assertEqual(version["localizedDescription"], "Version 1.0.0")

    def test_long_notes_are_trimmed(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0", localizedDescription="x" * 5000))
        notes = self.only_app(self.repo.generate()[0])["versions"][0]["localizedDescription"]
        self.assertEqual(len(notes), source.NOTES_LIMIT)

    def test_curated_app_json_wins(self):
        self.repo.app(app_json={
            "name": "Curated", "developerName": "Someone", "subtitle": "Short pitch.",
            "localizedDescription": "Long text.", "category": "games", "tintColor": "112233",
            "iconURL": "https://cdn.example.invalid/icon.png",
            "screenshots": ["https://cdn.example.invalid/1.png", "https://cdn.example.invalid/2.png"],
        }, icon=True)
        self.repo.add(record("1.0.0"))
        app = self.only_app(self.repo.generate()[0])
        self.assertEqual({k: app[k] for k in ("name", "developerName", "subtitle", "localizedDescription",
                                              "category", "tintColor", "iconURL", "screenshots")}, {
            "name": "Curated", "developerName": "Someone", "subtitle": "Short pitch.",
            "localizedDescription": "Long text.", "category": "games", "tintColor": "112233",
            "iconURL": "https://cdn.example.invalid/icon.png",
            "screenshots": ["https://cdn.example.invalid/1.png", "https://cdn.example.invalid/2.png"]})
        self.assertEqual(list(app)[:9], ["name", "bundleIdentifier", "developerName", "subtitle",
                                         "localizedDescription", "iconURL", "tintColor", "category", "screenshots"])

    def test_invalid_curated_values_fall_back(self):
        self.repo.app(app_json={"category": "tools", "tintColor": "red", "iconURL": "ftp://x/icon.png",
                                "screenshots": ["https://cdn.example.invalid/1.png", "relative.png"],
                                "maxVersions": 0, "subtitle": "   "}, icon=False)
        self.repo.add(record("1.0.0"))
        obj, logs = self.repo.generate()
        app = self.only_app(obj)
        self.assertEqual(app["category"], "utilities")
        self.assertEqual(app["tintColor"], "5B6CFF")
        self.assertEqual(app["screenshots"], ["https://cdn.example.invalid/1.png"])
        self.assertNotIn("subtitle", app)
        self.assertEqual(app["iconURL"], PAGES + "/icon.png")  # no icon anywhere: the site icon
        self.assertEqual(obj["iconURL"], app["iconURL"])
        self.assertNotIn("app io.example.demo: iconURL is required", source.validate_source(obj))
        joined = "\n".join(logs)
        for key in ("category", "tintColor", "iconURL", "screenshots", "maxVersions", "subtitle"):
            self.assertIn(key, joined)

    def test_category_falls_back_to_other(self):
        base = copy.deepcopy(BASE)
        del base["defaults"]
        repo = Repo(os.path.join(self._tmp.name, "nodefaults"), base)
        repo.app(icon=True)
        repo.add(record("1.0.0"))
        app = self.only_app(repo.generate()[0])
        self.assertEqual(app["category"], "other")
        self.assertEqual(app["developerName"], "alt")  # source name as the last resort
        self.assertEqual(app["tintColor"], "5B6CFF")  # source tint

    def test_icon_rules(self):
        base = dict(BASE, iconURL="https://cdn.example.invalid/source.png")
        repo = Repo(os.path.join(self._tmp.name, "icons"), base)
        repo.app("io.example.a", icon=True)
        repo.app("io.example.b", app_json={"iconURL": "https://cdn.example.invalid/b.png"})
        repo.app("io.example.c")
        for bid in ("io.example.a", "io.example.b", "io.example.c"):
            repo.add(record("1.0.0", bid=bid))
        obj, _ = repo.generate()
        icons = {a["bundleIdentifier"]: a["iconURL"] for a in obj["apps"]}
        self.assertEqual(icons, {
            "io.example.a": PAGES + "/apps/io.example.a/icon.png",
            "io.example.b": "https://cdn.example.invalid/b.png",
            "io.example.c": "https://cdn.example.invalid/source.png",
        })
        self.assertEqual(obj["iconURL"], "https://cdn.example.invalid/source.png")
        self.assertValid(obj)
        # without a source icon: the first app with its own icon (in listed order) is used
        self.repo.app("io.example.a")
        self.repo.app("io.example.b", icon=True)
        self.repo.app("io.example.c", app_json={"iconURL": "https://cdn.example.invalid/c.png"})
        for bid in ("io.example.a", "io.example.b", "io.example.c"):
            self.repo.add(record("1.0.0", bid=bid))
        obj, _ = self.repo.generate(pages_base=PAGES + "/")
        self.assertEqual(obj["iconURL"], PAGES + "/apps/io.example.b/icon.png")
        self.assertEqual(obj["apps"][0]["iconURL"], obj["iconURL"])
        self.assertValid(obj)

    def test_invalid_source_icon_is_reported_and_replaced(self):
        bads = ("icon.png", "ftp://cdn.example.invalid/x.png", "", 5, ["https://cdn.example.invalid/x.png"])
        for index, bad in enumerate(bads):
            repo = Repo(os.path.join(self._tmp.name, "badicon-%d" % index), dict(BASE, iconURL=bad))
            repo.app("io.example.a")
            repo.add(record("1.0.0", bid="io.example.a"))
            obj, logs = repo.generate()
            self.assertEqual(obj["iconURL"], PAGES + "/icon.png", bad)  # no app icon either: the site icon
            self.assertEqual(obj["apps"][0]["iconURL"], PAGES + "/icon.png", bad)
            self.assertEqual(logs, ["source.base.json: iconURL is invalid; using the default"], bad)
            self.assertValid(obj)
            # with an app icon, the invalid curated value gives way to the first app icon
            repo.app("io.example.b", icon=True)
            repo.add(record("1.0.0", bid="io.example.b"))
            obj, _ = repo.generate()
            self.assertEqual(obj["iconURL"], PAGES + "/apps/io.example.b/icon.png", bad)
            self.assertEqual([a["iconURL"] for a in obj["apps"]], [obj["iconURL"]] * 2, bad)
            self.assertValid(obj)

    def test_null_source_icon_counts_as_absent(self):
        repo = Repo(os.path.join(self._tmp.name, "nullicon"), dict(BASE, iconURL=None))
        repo.app()
        repo.add(record("1.0.0"))
        obj, logs = repo.generate()
        self.assertEqual((obj["iconURL"], obj["apps"][0]["iconURL"], logs), (PAGES + "/icon.png",) * 2 + ([],))
        self.assertValid(obj)

    def test_every_app_and_the_source_always_have_a_valid_icon(self):
        # compat F4: app.json iconURL -> apps/<bid>/icon.png -> source iconURL -> site icon
        cases = [
            # (base iconURL, app.json iconURL, icon file) -> app iconURL
            (None, "https://cdn.example.invalid/a.png", True, "https://cdn.example.invalid/a.png"),
            (None, None, True, PAGES + "/apps/%s/icon.png" % BID),
            ("https://cdn.example.invalid/s.png", None, False, "https://cdn.example.invalid/s.png"),
            ("https://cdn.example.invalid/s.png", "relative.png", False, "https://cdn.example.invalid/s.png"),
            (None, None, False, PAGES + "/icon.png"),
            ("not a url", "relative.png", False, PAGES + "/icon.png"),
        ]
        for index, (base_icon, app_icon, has_file, expected) in enumerate(cases):
            base = dict(BASE) if base_icon is None else dict(BASE, iconURL=base_icon)
            repo = Repo(os.path.join(self._tmp.name, "f4-%d" % index), base)
            repo.app(app_json={} if app_icon is None else {"iconURL": app_icon}, icon=has_file)
            repo.add(record("1.0.0"))
            obj, _ = repo.generate()
            self.assertEqual(obj["apps"][0]["iconURL"], expected, index)
            self.assertTrue(source.is_url(obj["iconURL"]), index)
            self.assertValid(obj)

    def test_description_falls_back_to_subtitle_then_name(self):
        # compat F4: app.json localizedDescription -> subtitle -> name; never empty
        cases = [
            ({"localizedDescription": "Long text.", "subtitle": "Short pitch."}, "Long text.", False),
            ({"subtitle": "Short pitch."}, "Short pitch.", False),
            ({"localizedDescription": " \n", "subtitle": " Short pitch. "}, "Short pitch.", True),
            ({"localizedDescription": 5, "name": "Curated"}, "Curated", True),
            ({"subtitle": ""}, "Demo", True),  # the newest record's name
            ({}, "Demo", False),
        ]
        for index, (app_json, expected, logged) in enumerate(cases):
            repo = Repo(os.path.join(self._tmp.name, "desc-%d" % index))
            repo.app(app_json=app_json, icon=True)
            repo.add(record("1.0.0"))
            obj, logs = repo.generate()
            self.assertEqual(self.only_app(obj)["localizedDescription"], expected, index)
            self.assertEqual(bool(logs), logged, (index, logs))
            self.assertValid(obj)

    def test_default_pages_base_is_the_canonical_site(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0"))
        obj = source.generate_source(self.repo.root, log=lambda m: None)
        self.assertEqual(obj["apps"][0]["iconURL"], "https://xuniv.github.io/alt/apps/io.example.demo/icon.png")
        self.assertEqual(source.SOURCE_URL, "https://xuniv.github.io/alt/source.json")

    def test_hidden_and_empty_apps_are_omitted_and_featured_apps_filtered(self):
        base = dict(BASE, featuredApps=["io.example.gone", "io.example.b", "io.example.hidden", "io.example.a",
                                        "io.example.b", 7])
        repo = Repo(os.path.join(self._tmp.name, "featured"), base)
        for bid in ("io.example.a", "io.example.b", "io.example.hidden", "io.example.empty"):
            repo.app(bid, icon=True)
        repo.app("io.example.hidden", app_json={"hidden": True})
        for bid in ("io.example.a", "io.example.b", "io.example.hidden"):
            repo.add(record("1.0.0", bid=bid))
        obj, _ = repo.generate()
        self.assertEqual([a["bundleIdentifier"] for a in obj["apps"]], ["io.example.a", "io.example.b"])
        self.assertEqual(obj["featuredApps"], ["io.example.b", "io.example.a"])
        self.assertValid(obj)
        repo.write("source.base.json", dict(BASE, featuredApps=["io.example.hidden"]))
        self.assertNotIn("featuredApps", repo.generate()[0])  # absent means all apps, [] would mean none

    def test_hidden_is_fail_closed(self):
        self.repo.app(app_json={"hidden": "yes"}, icon=True)
        self.repo.add(record("1.0.0"))
        self.assertEqual(self.repo.generate()[0]["apps"], [])

    def test_unreadable_app_json_raises(self):
        self.repo.app(icon=True)
        self.repo.write("apps/%s/app.json" % BID, b"{not json")
        self.repo.add(record("1.0.0"))
        with self.assertRaises(source.SourceError) as ctx:
            self.repo.generate()
        self.assertEqual(ctx.exception.rule, "source-input")
        self.repo.write("apps/%s/app.json" % BID, b"[]")
        with self.assertRaises(source.SourceError):
            self.repo.generate()

    def test_missing_or_bad_base_raises(self):
        os.unlink(os.path.join(self.repo.root, "source.base.json"))
        with self.assertRaises(source.SourceError):
            self.repo.generate()
        self.repo.write("source.base.json", b'{"name": NaN}')
        with self.assertRaises(source.SourceError):
            self.repo.generate()

    def test_bad_records_are_skipped_with_a_warning(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0"))
        bad = {
            "1.1.0": record("1.1.0", bundleIdentifier="io.example.other"),
            "1.2.0": record("1.2.0", tag="io.example.demo-v9.9.9"),
            "1.3.0": record("1.3.0", date=None),
            "1.4.0": record("1.4.0", date="2026-10-20T01:17:00.5Z"),
            "1.5.0": record("1.5.0", downloadURL="/relative.ipa"),
            "1.6.0": record("1.6.0", size=2 ** 31),
            "1.7.0": record("1.7.0", sha256="abc"),
            "1.8.0": record("1.8.0", version=""),
            "1.9.0": dict(record("1.9.0"), semver="1.9"),
            "1.10.0": record("1.10.0", minOSVersion="fifteen"),
        }
        for ver, rec in bad.items():
            self.repo.write("apps/%s/versions/%s.json" % (BID, ver), rec)
        self.repo.write("apps/%s/versions/2.0.0.json" % BID, b"{broken")
        self.repo.write("apps/not_a_bid/versions/1.0.0.json", record("1.0.0", bid="not_a_bid"))
        obj, logs = self.repo.generate()
        self.assertEqual([v["marketingVersion"] for v in self.only_app(obj)["versions"]], ["1.0.0"])
        self.assertEqual(len(logs), len(bad) + 2)
        self.assertTrue(all("skipped" in m or "ignored" in m for m in logs))
        self.assertValid(obj)

    def test_records_with_extra_sync_fields(self):
        self.repo.app(icon=True)
        self.repo.add(record("1.0.0", appJsonAssetId=5, iconUnavailable=True))
        self.assertValid(self.repo.generate()[0])

    def test_news_is_copied_when_present(self):
        news = [{"identifier": "n1", "title": "Hello", "caption": "First news.", "date": "2026-10-20",
                 "appID": BID, "notify": False}]
        repo = Repo(os.path.join(self._tmp.name, "news"), dict(BASE, news=news))
        repo.app(icon=True)
        repo.add(record("1.0.0"))
        obj, _ = repo.generate()
        self.assertEqual(obj["news"], news)
        self.assertEqual(list(obj)[-1], "news")
        self.assertValid(obj)
        repo.write("source.base.json", dict(BASE, news=[]))
        self.assertNotIn("news", repo.generate()[0])

    def test_write_source_is_deterministic(self):
        self.repo.app(app_json={"name": "Démo ✓"}, icon=True)
        self.repo.add(record("1.0.0", privacy={"NSPhotoLibraryUsageDescription": "b", "NSCameraUsageDescription": "a"}),
                      record("1.1.0"))
        out = os.path.join(self.repo.root, "source.json")
        self.assertTrue(source.write_source(self.repo.root, pages_base=PAGES, log=lambda m: None))
        with open(out, "rb") as fh:
            first = fh.read()
        self.assertFalse(source.write_source(self.repo.root, pages_base=PAGES, log=lambda m: None))
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), first)
        obj, _ = self.repo.generate()
        self.assertEqual(first, syncmod.dumps_json(obj))  # the same bytes sync commits
        self.assertIn("Démo ✓".encode("utf-8"), first)
        self.assertTrue(first.endswith(b"}\n"))
        privacy = json.loads(first)["apps"][0]["appPermissions"]["privacy"]
        self.assertEqual(list(privacy), sorted(privacy))
        alt = os.path.join(self.repo.root, "elsewhere.json")
        self.assertTrue(source.write_source(self.repo.root, pages_base=PAGES, path=alt, log=lambda m: None))
        self.assertFalse(os.path.exists(alt + ".tmp-source"))

    def test_apps_sorted_by_bundle_id(self):
        for bid in ("io.example.zeta", "io.example.alpha", "com.example.mid"):
            self.repo.app(bid, icon=True)
            self.repo.add(record("1.0.0", bid=bid))
        obj, _ = self.repo.generate()
        self.assertEqual([a["bundleIdentifier"] for a in obj["apps"]],
                         ["com.example.mid", "io.example.alpha", "io.example.zeta"])

    def test_empty_repository(self):
        obj, logs = self.repo.generate()
        self.assertEqual(obj["apps"], [])
        self.assertEqual(logs, [])
        self.assertEqual(source.validate_source(obj),
                         ["warning: source has no apps (Feather rejects an empty source)"])

    def test_default_log_writes_warnings_to_stderr(self):
        import contextlib

        self.repo.app(icon=True)
        self.repo.write("apps/%s/versions/1.0.0.json" % BID, b"{broken")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            source.generate_source(self.repo.root)
        self.assertTrue(err.getvalue().startswith("warning: apps/io.example.demo/versions/1.0.0.json"))


def valid_source():
    return {
        "name": "alt",
        "identifier": "io.github.example.alt",
        "iconURL": "https://example.invalid/icon.png",
        "tintColor": "5B6CFF",
        "featuredApps": [BID],
        "apps": [{
            "name": "Demo",
            "bundleIdentifier": BID,
            "developerName": "example",
            "localizedDescription": "Text.",
            "iconURL": "https://example.invalid/apps/demo.png",
            "tintColor": "5B6CFF",
            "category": "utilities",
            "screenshots": ["https://example.invalid/1.png"],
            "versions": [
                {"version": "1.1.0", "buildVersion": "8", "marketingVersion": "1.1.0", "date": "2026-10-21T00:00:00Z",
                 "localizedDescription": "b", "downloadURL": "https://example.invalid/b.ipa", "size": 20,
                 "sha256": "b" * 64, "minOSVersion": "15.0"},
                {"version": "1.0.0", "buildVersion": "7", "marketingVersion": "1.0.0", "date": "2026-10-20",
                 "localizedDescription": "a", "downloadURL": "https://example.invalid/a.ipa", "size": 10,
                 "sha256": "a" * 64},
            ],
            "appPermissions": {"entitlements": ["keychain-access-groups"],
                               "privacy": {"NSCameraUsageDescription": "Scan."}},
            "version": "1.1.0",
            "versionDate": "2026-10-21T00:00:00Z",
            "versionDescription": "b",
            "downloadURL": "https://example.invalid/b.ipa",
            "size": 20,
        }],
        "news": [{"identifier": "n1", "title": "t", "caption": "c", "date": "2026-10-20T09:00:00+02:00"}],
    }


class ValidateTests(unittest.TestCase):
    def errors(self, mutate):
        obj = valid_source()
        mutate(obj)
        return [e for e in source.validate_source(obj) if not e.startswith("warning")]

    def assertRejected(self, mutate, fragment):
        errors = self.errors(mutate)
        self.assertTrue(any(fragment in e for e in errors), "%r not in %r" % (fragment, errors))

    def test_valid(self):
        self.assertEqual(source.validate_source(valid_source()), [])

    def test_not_an_object(self):
        self.assertEqual(source.validate_source([]), ["source must be a JSON object"])

    def app(self, obj):
        return obj["apps"][0]

    def version(self, obj, index=0):
        return obj["apps"][0]["versions"][index]

    def test_source_level_rules(self):
        self.assertRejected(lambda o: o.pop("name"), "name is required")
        self.assertRejected(lambda o: o.update(name=" "), "name must not be empty")
        self.assertRejected(lambda o: o.pop("identifier"), "identifier is required")
        self.assertRejected(lambda o: o.update(marketplaceID="123"), "marketplaceID")
        self.assertRejected(lambda o: o.update(version="2"), "version must be an integer")
        self.assertRejected(lambda o: o.update(tintColor="#12345"), "tintColor must be 6 hex digits")
        self.assertRejected(lambda o: o.update(website="github.com/x"), "website must be an absolute")
        self.assertRejected(lambda o: o.update(headerURL="javascript:alert(1)"), "headerURL")
        self.assertRejected(lambda o: o.update(userInfo={"a": 1}), "userInfo")
        self.assertRejected(lambda o: o.update(apps={}), "apps must be a list")
        self.assertRejected(lambda o: o.update(featuredApps=BID), "featuredApps")
        self.assertEqual(self.errors(lambda o: o.update(tintColor="#5b6cff", version=2)), [])

    def test_empty_apps_is_a_warning(self):
        obj = valid_source()
        obj["apps"] = []
        obj.pop("featuredApps")
        obj.pop("news")
        self.assertEqual(source.validate_source(obj),
                         ["warning: source has no apps (Feather rejects an empty source)"])

    def test_unknown_featured_app_is_a_warning(self):
        obj = valid_source()
        obj["featuredApps"] = ["io.example.gone"]
        self.assertEqual(source.validate_source(obj), ["warning: source: featured app io.example.gone is not listed"])

    def test_strict_json_types(self):
        self.assertRejected(lambda o: self.version(o).update(extra=float("nan")), "number must be finite")
        self.assertRejected(lambda o: o.update(extra={1: "x"}), "object keys must be strings")
        self.assertRejected(lambda o: o.update(extra={"x"}), "set is not a JSON type")
        self.assertRejected(lambda o: o.update(extra="\ud800"), "not valid Unicode")

    def test_app_rules(self):
        for key in ("name", "bundleIdentifier", "developerName", "localizedDescription", "iconURL"):
            self.assertRejected(lambda o, k=key: self.app(o).pop(k), "%s is required" % key)
        self.assertRejected(lambda o: self.app(o).update(marketplaceID="1"), "marketplaceID is not allowed")
        self.assertRejected(lambda o: self.app(o).update(permissions=[]), "legacy permissions")
        self.assertRejected(lambda o: self.app(o).update(category="tools"), "category must be one of")
        self.assertRejected(lambda o: self.app(o).update(category="Games"), "category must be one of")
        self.assertRejected(lambda o: self.app(o).update(tintColor="5B6CFF80"), "tintColor")
        self.assertRejected(lambda o: self.app(o).update(iconURL="//cdn.example.invalid/x.png"), "iconURL")
        self.assertRejected(lambda o: self.app(o).update(iconURL="https://user@example.invalid/x.png"), "iconURL")
        self.assertRejected(lambda o: self.app(o).update(iconURL="https://example.invalid/a b.png"), "iconURL")
        self.assertRejected(lambda o: self.app(o).update(iconURL="https://example.invalid:x/a.png"), "iconURL")
        self.assertRejected(lambda o: self.app(o).update(size=2 ** 31), "size must be an integer")
        self.assertRejected(lambda o: self.app(o).update(versionDate="yesterday"), "versionDate")
        self.assertRejected(lambda o: self.app(o).update(beta="yes"), "beta must be a boolean")
        self.assertRejected(lambda o: o["apps"].append(copy.deepcopy(self.app(o))), "bundleIdentifier is not unique")
        self.assertRejected(lambda o: o["apps"].append("x"), "apps[1]: must be an object")

    def test_versions_rules(self):
        self.assertRejected(lambda o: self.app(o).update(versions=[]), "versions must be a non-empty list")
        self.assertRejected(lambda o: self.app(o).pop("versions"), "versions must be a non-empty list")
        self.assertRejected(lambda o: self.version(o).pop("version"), "version is required")
        self.assertRejected(lambda o: self.version(o).update(buildVersion=""), "buildVersion must not be empty")
        self.assertRejected(lambda o: self.version(o).update(buildVersion=8), "buildVersion must be a string")
        self.assertRejected(lambda o: self.version(o).pop("date"), "date is required")
        self.assertRejected(lambda o: self.version(o).pop("downloadURL"), "downloadURL is required")
        self.assertRejected(lambda o: self.version(o).update(downloadURL="ftp://x/a.ipa"), "downloadURL")
        self.assertRejected(lambda o: self.version(o).pop("size"), "size is required")
        for size in (2 ** 31, True, 20.0, "20", 0, -1):
            self.assertRejected(lambda o, s=size: self.version(o).update(size=s), "size must be an integer")
        self.assertEqual(self.errors(lambda o: self.version(o).update(size=2 ** 31 - 1)), [])
        for sha in ("a" * 63, "g" * 64, None):
            self.assertRejected(lambda o, s=sha: self.version(o).update(sha256=s), "sha256 must be 64 hex")
        self.assertEqual(self.errors(lambda o: self.version(o).update(sha256="AB" * 32)), [])
        self.assertRejected(lambda o: self.version(o).update(minOSVersion="iOS 15"), "minOSVersion")
        self.assertRejected(lambda o: self.version(o).update(maxOSVersion=17), "maxOSVersion")
        self.assertRejected(lambda o: self.app(o)["versions"].append("x"), "versions[2]: must be an object")

    def test_dates(self):
        for good in ("2026-10-20", "2026-10-20T01:02:03Z", "2026-10-20T01:02:03+02:00", "2024-02-29T23:59:59-05:30"):
            self.assertTrue(source.is_date(good), good)
        for bad in ("2026-10-20T01:02:03.123Z", "2026-10-20T01:02:03", "2026-10-20 01:02:03Z", "2026-13-01",
                    "2026-02-30", "2025-02-29T00:00:00Z", "2026-10-20T24:00:00Z", "2026-10-20T01:02:03+0200",
                    "2026-10-20T01:02:03+24:00", "20261020", "\u0662\u0660\u0662\u0666-10-20", 1792743577, None):
            self.assertFalse(source.is_date(bad), bad)
        self.assertRejected(lambda o: self.version(o).update(date="2026-10-20T01:02:03.5Z"), "date must be")

    def test_unique_version_build_pairs(self):
        def dup(o):
            self.version(o, 1).update(version="1.1.0", buildVersion="8", marketingVersion="1.0.0")
        self.assertRejected(dup, "repeats version 1.1.0 build 8")

        def dup_without_build(o):
            for v in self.app(o)["versions"]:
                v.pop("buildVersion")
                v["version"] = "1.0"
        self.assertRejected(dup_without_build, "repeats version 1.0 build -")

        def distinct_builds(o):
            self.version(o, 1).update(version="1.1.0", buildVersion="7")
        self.assertEqual(self.errors(distinct_builds), [])

    def test_order_newest_first(self):
        self.assertRejected(lambda o: self.app(o)["versions"].reverse(), "versions must be ordered newest first")
        # versions whose marketingVersion is not semver are not ordered by the validator
        self.assertEqual(self.errors(lambda o: [v.pop("marketingVersion") for v in self.app(o)["versions"]]), [])

    def test_privacy_rules(self):
        for value in (None, "", "  ", 1):
            self.assertRejected(lambda o, v=value: self.app(o)["appPermissions"]["privacy"].update(NSFooUsageDescription=v),
                                "privacy.NSFooUsageDescription must be a non-empty string")
        self.assertRejected(lambda o: self.app(o)["appPermissions"].update(privacy=[{"name": "Camera"}]),
                            "privacy[0] needs name and a non-empty usageDescription")
        self.assertEqual(self.errors(lambda o: self.app(o)["appPermissions"].update(
            privacy=[{"name": "Camera", "usageDescription": "Scan."}])), [])
        self.assertRejected(lambda o: self.app(o)["appPermissions"].update(entitlements=[""]), "entitlements[0]")
        self.assertRejected(lambda o: self.app(o)["appPermissions"].update(entitlements="x"), "entitlements must be")
        self.assertRejected(lambda o: self.app(o).update(appPermissions=[]), "appPermissions must be an object")

    def test_screenshot_rules(self):
        ok = {"iphone": ["https://example.invalid/1.png",
                         {"imageURL": "https://example.invalid/2.png", "width": 1179, "height": 2556}],
              "ipad": [{"imageURL": "https://example.invalid/3.png", "width": 2048, "height": 2732}]}
        self.assertEqual(self.errors(lambda o: self.app(o).update(screenshots=ok)), [])
        self.assertRejected(lambda o: self.app(o).update(screenshots={"ipad": ["https://example.invalid/3.png"]}),
                            "screenshots.ipad[0] needs imageURL, width and height")
        self.assertRejected(lambda o: self.app(o).update(
            screenshots={"ipad": [{"imageURL": "https://example.invalid/3.png", "width": 2048}]}),
            "screenshots.ipad[0].height")
        self.assertRejected(lambda o: self.app(o).update(screenshots=["/x.png"]), "screenshots[0] must be")
        self.assertRejected(lambda o: self.app(o).update(
            screenshots=[{"imageURL": "https://example.invalid/2.png", "width": 40000, "height": 1}]),
            "screenshots[0].width")
        self.assertRejected(lambda o: self.app(o).update(screenshots={"watch": []}), "not iphone or ipad")
        self.assertRejected(lambda o: self.app(o).update(screenshots="x"), "screenshots must be")
        self.assertRejected(lambda o: self.app(o).update(screenshotURLs=["x"]), "screenshotURLs")

    def test_news_rules(self):
        self.assertRejected(lambda o: o["news"][0].pop("caption"), "news[0]: caption is required")
        self.assertRejected(lambda o: o["news"][0].update(date="soon"), "news[0]: date must be")
        self.assertRejected(lambda o: o["news"].append(dict(o["news"][0])), "identifier n1 is not unique")
        self.assertRejected(lambda o: o["news"][0].update(notify="no"), "notify must be a boolean")
        self.assertRejected(lambda o: o["news"][0].update(url="nope"), "url must be")
        self.assertRejected(lambda o: o.update(news={}), "news: must be a list")
        obj = valid_source()
        obj["news"][0]["appID"] = "io.example.gone"
        self.assertEqual(source.validate_source(obj), ["warning: news[0]: appID io.example.gone is not listed"])

    def test_url_helper(self):
        for good in ("https://example.invalid", "http://example.invalid/a?b=c#d",
                     "https://github.com/x/y/releases/download/a-v1.0.0/A-1.0.0.ipa", "https://[::1]:8443/x"):
            self.assertTrue(source.is_url(good), good)
        for bad in ("", "example.invalid", "https:/x", "https://", "file:///etc/passwd", "HTTPS://x",
                    "https://x/\u00e9", "https://x/a\\b", "https://u:p@x/", None, 1):
            self.assertFalse(source.is_url(bad), bad)


class PipelineTests(unittest.TestCase):
    """sync, generate and validate running on the real tag and source modules."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.git = FakeGit(self.root)
        self.git.seed({"source.base.json": syncmod.dumps_json(BASE)})
        self.gh = FakeGitHub(self.git)
        self.logs = []
        self.deps = FakeToolkit()
        # everything except IPA inspection, normalization and scanning comes from the real modules
        for name in ("TagError", "SemVer", "parse_tag", "make_tag", "core_matches", "alias_for", "validate_source"):
            setattr(self.deps, name, getattr(tags, name, None) or getattr(source, name))
        self.deps.generate_source = lambda root, **kw: source.generate_source(root, log=self.logs.append, **kw)

    def tearDown(self):
        self._tmp.cleanup()

    def publish(self, tag, data, **kw):
        rel = self.gh.add_release(tag, **kw)
        self.gh.add_asset(rel, "Demo-%s.ipa" % tag.split("-v")[-1], data)
        return rel

    def test_sync_commits_a_valid_source(self):
        self.publish("io.example.demo-v1.0.0", ipa_bytes(short_version="1.0", build_version="5"))
        self.publish("io.example.demo-v1.1.0-rc.1", ipa_bytes(short_version="1.1.0", build_version="6"),
                     prerelease=True)
        self.publish("io.example.demo-v1.1.0", ipa_bytes(short_version="1.1.0", build_version="7",
                                                          privacy={"NSMicrophoneUsageDescription": "Talk."}),
                     body="Second.")
        result = syncmod.sync(self.root, gh=self.gh, git=self.git, deps=self.deps, denylist=DENY,
                              log=self.logs.append, output_path=os.path.join(self.root, "out"), environ={})
        self.assertEqual((result.apps, result.versions, result.errors), (1, 2, []))
        message, additions, _ = self.gh.commits[0]
        self.assertEqual(message, "catalog: sync 1 app(s), 2 version(s)")
        self.assertIn("apps/io.example.demo/versions/1.1.0-rc.1.json", additions)
        obj = json.loads(additions["source.json"])
        self.assertEqual(source.validate_source(obj), [])
        app = obj["apps"][0]
        self.assertEqual([(v["version"], v["buildVersion"], v["marketingVersion"]) for v in app["versions"]],
                         [("1.1.0", "7", "1.1.0"), ("1.0", "5", "1.0.0")])
        self.assertEqual(app["versions"][0]["localizedDescription"], "Second.")
        self.assertEqual(app["versions"][1]["localizedDescription"], "Version 1.0.0")
        self.assertEqual(app["iconURL"], "https://xuniv.github.io/alt/apps/io.example.demo/icon.png")
        self.assertEqual(app["appPermissions"]["privacy"], {"NSCameraUsageDescription": "Scans codes.",
                                                            "NSMicrophoneUsageDescription": "Talk."})
        self.assertEqual((app["name"], app["developerName"], app["category"]), ("Demo App", "example", "utilities"))
        # the committed tree regenerates to the same bytes, and a second sync changes nothing
        self.assertEqual(syncmod.dumps_json(source.generate_source(self.root, log=self.logs.append)),
                         additions["source.json"])
        self.git.refresh("main")
        again = syncmod.sync(self.root, gh=self.gh, git=self.git, deps=self.deps, denylist=DENY,
                             log=self.logs.append, output_path=os.path.join(self.root, "out"), environ={})
        self.assertFalse(again.changed)

    def test_cli_generate_validate_and_parse_tag_with_real_modules(self):
        deps = stagemod.Toolkit()
        out_path = os.path.join(self.root, "gh-output")

        def run(*argv):
            out, err = io.StringIO(), io.StringIO()
            code = cli.main(list(argv), deps=deps, environ={"GITHUB_OUTPUT": out_path}, out=out, err=err)
            return code, out.getvalue(), err.getvalue()

        repo = Repo(self.root)
        repo.app(icon=True)
        repo.add(record("1.0.0"))
        self.assertEqual(run("generate", "--root", self.root, "--check")[0], 1)
        self.assertEqual(run("generate", "--root", self.root)[0], 0)
        self.assertEqual(run("generate", "--root", self.root, "--check")[0], 0)
        code, out, err = run("validate", "--root", self.root)
        self.assertEqual((code, out), (0, ""), err)
        code, out, _ = run("parse-tag", "io.example.demo-v1.3.0-rc.1")
        self.assertEqual(code, 0)
        self.assertIn("prerelease=true\n", out)
        self.assertIn("alias=IO_EXAMPLE_DEMO\n", out)
        self.assertEqual(run("parse-tag", "io.example.app-v2-v1.0.0")[0], 1)
        self.assertEqual(run("alias", "io.github.nukebrowser")[1], "IO_GITHUB_NUKEBROWSER\n")
        repo.write("apps/%s/app.json" % BID, b"{")
        code, _, err = run("generate", "--root", self.root)
        self.assertEqual(code, 1)
        self.assertIn("SourceError (source-input)", err)

    def test_repository_base_generates_a_valid_source(self):
        with open(os.path.join(ROOT, "source.base.json"), "rb") as fh:
            base = json.loads(fh.read().decode("utf-8"))
        self.assertEqual(base["identifier"], "io.github.xuniv.alt")
        for key in ("name", "subtitle", "description", "website", "tintColor", "defaults"):
            self.assertIn(key, base)
        repo = Repo(os.path.join(self.root, "base"), base)
        repo.app(icon=True)
        repo.add(record("1.0.0"))
        obj, logs = repo.generate()
        self.assertEqual((logs, source.validate_source(obj)), ([], []))
        self.assertTrue(source.is_hex_color(base["defaults"]["tintColor"]))
        self.assertIn(base["defaults"]["category"], source.CATEGORIES)


SITE = os.path.join(ROOT, "site", "index.html")
ENCODED = "https%3A%2F%2Fxuniv.github.io%2Falt%2Fsource.json"


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SITE, encoding="utf-8") as fh:
            cls.html = fh.read()

    def block(self, tag):
        blocks = re.findall(r"<%s>(.*?)</%s>" % (tag, tag), self.html, re.S)
        self.assertEqual(len(blocks), 1, tag)
        return blocks[0]

    def test_site_icon_is_a_clean_opaque_1024_png(self):
        path = os.path.join(ROOT, "site", source.SITE_ICON)
        self.assertFalse(os.path.islink(path))
        with open(path, "rb") as fh:
            data = fh.read()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        chunks, off = [], 8
        while off < len(data):
            length, kind = struct.unpack_from(">I4s", data, off)
            body = data[off + 8:off + 8 + length]
            self.assertEqual(struct.unpack_from(">I", data, off + 8 + length)[0], zlib.crc32(kind + body), kind)
            chunks.append((kind, body))
            off += 12 + length
        self.assertEqual(off, len(data))
        kinds = [k for k, _ in chunks]
        # no text, time, EXIF or other metadata chunks
        self.assertEqual((kinds[0], kinds[-1], set(kinds)), (b"IHDR", b"IEND", {b"IHDR", b"IDAT", b"IEND"}))
        width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
        self.assertEqual((width, height, depth, color, interlace), (1024, 1024, 8, 2, 0))  # opaque 8-bit RGB
        stride = 1 + width * 3
        raw = zlib.decompress(b"".join(b for k, b in chunks if k == b"IDAT"))
        self.assertEqual(len(raw), height * stride)
        self.assertTrue(all(raw[y * stride] <= 4 for y in range(height)))  # valid filter types

    def test_add_source_links(self):
        self.assertEqual(urllib_quote(source.SOURCE_URL), ENCODED)
        for scheme in ("altstore", "altstore-classic", "sidestore"):
            self.assertIn('href="%s://source?url=%s"' % (scheme, ENCODED), self.html)
        self.assertIn('value="%s"' % source.SOURCE_URL, self.html)
        self.assertIn('id="copy"', self.html)

    def test_no_external_resources(self):
        self.assertNotRegex(self.html, r"(?i)<script[^>]*\bsrc=")
        self.assertNotRegex(self.html, r"(?i)<link[^>]*\bhref=\"(?!data:)")
        self.assertNotRegex(self.block("style"), r"(?i)@import|url\s*\(")
        self.assertNotRegex(self.html, r"(?i)<iframe|<object|<embed|<base\b|<form\b")
        markup = self.html.replace(self.block("script"), "").replace(self.block("style"), "")
        self.assertNotRegex(markup, r"(?i)\s(src|srcset|action|poster|data)\s*=")
        attrs = re.findall(r"""(?i)<(\w+)[^>]*\shref\s*=\s*["']([^"']*)["']""", markup)
        self.assertEqual([(t, h) for t, h in attrs if t.lower() != "a"], [("link", "data:,")])
        for href in [h for t, h in attrs if t.lower() == "a"]:
            self.assertRegex(href, r"^(altstore|altstore-classic|sidestore)://source\?url=|^https://github\.com/"
                                   r"xuniv/alt$|^source\.json$")

    def test_script_uses_text_content_only(self):
        script = self.block("script")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
                     "setTimeout(\"", "srcdoc"):
            self.assertNotIn(sink, script)
        self.assertIn('fetch("./source.json"', script)
        self.assertIn("textContent", script)
        self.assertIn('var SOURCE_URL = "%s";' % source.SOURCE_URL, script)

    def test_content_security_policy_matches_inline_code(self):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', self.html).group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("connect-src 'self'", csp)
        for tag, directive in (("script", "script-src"), ("style", "style-src")):
            digest = base64.b64encode(hashlib.sha256(self.block(tag).encode("utf-8")).digest()).decode()
            self.assertIn("%s 'sha256-%s'" % (directive, digest), csp, "update the CSP hash after editing <%s>" % tag)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)

    def test_accessibility_basics(self):
        self.assertIn('<html lang="en">', self.html)
        self.assertIn('name="viewport"', self.html)
        self.assertIn("prefers-color-scheme: dark", self.html)
        self.assertIn('<label for="source-url">', self.html)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn("<main>", self.html)
        self.assertIn(":focus-visible", self.html)


CATALOG_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "catalog.yml")


def workflow_step_script(path, step):
    """The ``run: |`` block of the step named ``step`` (the workflow is read as text; no YAML parser)."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- name: %s" % step)
    key_indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    run = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "run: |")
    if run != start + 1 or len(lines[run]) - len(lines[run].lstrip()) != key_indent:
        raise AssertionError("step %r has no literal run block right after its name" % step)
    body = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
            break
        body.append(line)
    indent = min(len(line) - len(line.lstrip()) for line in body if line.strip())
    return "\n".join(line[indent:] for line in body).rstrip() + "\n"


class PagesAssemblyTests(unittest.TestCase):
    """catalog.yml's "Assemble the site" step deploys every Pages file that source.json points at."""

    def setUp(self):
        self.bash = shutil.which("bash")
        if self.bash is None:
            self.skipTest("bash is not available")
        self._tmp = tempfile.TemporaryDirectory()
        self.script = workflow_step_script(CATALOG_WORKFLOW, "Assemble the site")

    def tearDown(self):
        self._tmp.cleanup()

    def assemble(self, name, icons, base=None, *, site=True, ok=True):
        """Generate source.json for apps (bid -> has icon.png), assemble the site, return its directory."""
        repo = Repo(os.path.join(self._tmp.name, name), base)
        for bid, has_icon in icons.items():
            repo.app(bid, icon=has_icon)
            repo.add(record("1.0.0", bid=bid))
        obj, _ = repo.generate(pages_base=source.PAGES_BASE)
        errors = [e for e in source.validate_source(obj) if not e.startswith("warning")]
        self.assertEqual(errors, [])
        repo.write("source.json", obj)
        if site:
            shutil.copytree(os.path.join(ROOT, "site"), os.path.join(repo.root, "site"), symlinks=True)
        runner_temp = os.path.join(self._tmp.name, name + "-runner")
        os.makedirs(runner_temp)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "RUNNER_TEMP": runner_temp}
        proc = subprocess.run([self.bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", self.script],
                              cwd=repo.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.stdout.decode() + proc.stderr.decode()
        if not ok:
            self.assertNotEqual(proc.returncode, 0, output)
            return output
        self.assertEqual(proc.returncode, 0, output)
        return obj, os.path.join(runner_temp, "pages")

    def assertDeployed(self, obj, out):
        """Every URL under the Pages base in source.json names a file of the assembled site."""
        urls = []

        def walk(value):
            if isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str) and value.startswith(source.PAGES_BASE + "/"):
                urls.append(value)

        walk(obj)
        self.assertTrue(urls)
        for url in urls:
            rel = url[len(source.PAGES_BASE) + 1:]
            self.assertTrue(os.path.isfile(os.path.join(out, *rel.split("/"))), url)

    def test_site_icon_is_deployed_when_no_app_has_an_icon(self):
        obj, out = self.assemble("noicons", {"io.example.a": False, "io.example.b": False})
        self.assertEqual([obj["iconURL"]] + [a["iconURL"] for a in obj["apps"]],
                         [source.PAGES_BASE + "/" + source.SITE_ICON] * 3)
        with open(os.path.join(ROOT, "site", source.SITE_ICON), "rb") as fh:
            expected = fh.read()
        with open(os.path.join(out, source.SITE_ICON), "rb") as fh:
            self.assertEqual(fh.read(), expected)
        for name in ("index.html", "source.json"):
            self.assertTrue(os.path.isfile(os.path.join(out, name)), name)
        self.assertDeployed(obj, out)

    def test_app_icons_and_the_site_icon_are_deployed_together(self):
        obj, out = self.assemble("mixed", {"io.example.a": False, "io.example.b": True})
        self.assertEqual(obj["iconURL"], source.PAGES_BASE + "/apps/io.example.b/icon.png")
        self.assertTrue(os.path.isfile(os.path.join(out, source.SITE_ICON)))
        self.assertDeployed(obj, out)

    def test_missing_site_icon_fails_the_step(self):
        output = self.assemble("nosite", {"io.example.a": False}, site=False, ok=False)
        self.assertIn("site/icon.png is missing", output)

    def test_repository_base_with_one_app(self):
        with open(os.path.join(ROOT, "source.base.json"), "rb") as fh:
            base = json.loads(fh.read().decode("utf-8"))
        obj, out = self.assemble("base", {"io.example.a": False}, base)
        self.assertDeployed(obj, out)


class RetractionTests(SourceCase):
    """Tombstones (``apps/<bid>/retracted.json``) are a signal for builders, not a generator input."""

    def test_tombstones_do_not_change_the_generated_source(self):
        self.repo.app(BID, {"name": "Demo"})
        self.repo.add(record("1.0.0"), record("1.1.0"))
        before, logs = self.repo.generate()
        self.repo.write("apps/%s/retracted.json" % BID, retract.dumps({
            "1.1.0": {"date": "2026-10-23T08:00:00Z", "reason": "deleted"},
            "0.9.0": {"date": "2026-10-22T08:00:00Z", "reason": "unpublished"}}))
        after, logs_after = self.repo.generate()
        self.assertEqual(source.dumps_source(after), source.dumps_source(before))
        self.assertEqual(logs_after, logs)

    def test_app_with_only_tombstones_is_not_listed(self):
        self.repo.app(BID)
        self.repo.write("apps/%s/retracted.json" % BID, b"{damaged")
        obj, _ = self.repo.generate()
        self.assertEqual(obj["apps"], [])


class CatalogTriggerTests(unittest.TestCase):
    """Deleting or unpublishing a release starts a catalog run, which drops the version from source.json."""

    def test_release_deleted_and_unpublished_trigger_the_catalog(self):
        with open(CATALOG_WORKFLOW, encoding="utf-8") as fh:
            text = fh.read()
        match = re.search(r"^on:\n(?:(?:  .*)?\n)*?  release:\n    types: \[([^\]]*)\]$", text, re.M)
        self.assertIsNotNone(match, "catalog.yml has no release trigger with a types list")
        types = [t.strip() for t in match.group(1).split(",")]
        self.assertIn("deleted", types)
        self.assertIn("unpublished", types)


def urllib_quote(url):
    import urllib.parse

    return urllib.parse.quote(url, safe="")


if __name__ == "__main__":
    unittest.main()
