"""Archives that ``zipfile`` reads with exceptions other than ``BadZipFile``.

A "version needed to extract" above 6.3 raises ``NotImplementedError`` and a local header name that is
flagged as UTF-8 but is not raises ``UnicodeDecodeError``. Every reader has to report such an archive
with a rule id, so that stage rejects it (exit 2) and sync takes down only the affected release.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile

from altsource import cli
from altsource import ipa as ipamod
from altsource import leaks
from altsource import normalize as norm
from altsource import stage as stagemod
from altsource import sync as syncmod
from tests import helpers as h
from tests.test_sync import BASE, DENY, FakeGit, FakeGitHub, read_bytes

ACCENTED_APP = "Payload/Démo.app"  # every name under it carries the UTF-8 flag


class ZipCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def newer_version(self, name="version.ipa", **kw):
        """An IPA whose first central directory record needs version 6.4 to extract."""
        return h.set_extract_version(h.build_ipa(h.app_entries(**kw), self.path(name)), 64)

    def bad_name(self, name="name.ipa", **kw):
        """An IPA whose Info.plist local header name is not valid UTF-8."""
        path = h.build_ipa(h.app_entries(app=ACCENTED_APP, **kw), self.path(name))
        return h.break_local_name(path, ACCENTED_APP + "/Info.plist")

    def fixtures(self):
        return (("zip-unsupported", self.newer_version()), ("zip-path-encoding", self.bad_name()))


class ReaderTests(ZipCase):
    def test_the_library_raises_other_exceptions(self):
        with self.assertRaises(NotImplementedError):
            zipfile.ZipFile(self.newer_version())
        with zipfile.ZipFile(self.bad_name()) as zf, self.assertRaises(UnicodeDecodeError):
            zf.read(ACCENTED_APP + "/Info.plist")

    def test_inspection_and_icon_extraction_raise_ipa_errors(self):
        for rule, path in self.fixtures():
            for reader in (ipamod.inspect_ipa, ipamod.extract_icon):
                with self.subTest(rule=rule, reader=reader.__name__):
                    with self.assertRaises(ipamod.IpaError) as ctx:
                        reader(path)
                    self.assertEqual(ctx.exception.rule, rule)

    def test_normalization_raises_normalize_errors(self):
        rules = {"zip-unsupported": "zip-unsupported", "zip-path-encoding": "zip-name-encoding"}
        for rule, path in self.fixtures():
            with self.subTest(rule=rule):
                out = self.path("out.ipa")
                with self.assertRaises(norm.NormalizeError) as ctx:
                    norm.normalize_ipa(path, out)
                self.assertEqual(ctx.exception.rule, rules[rule])
                self.assertIsInstance(ctx.exception, zipfile.BadZipFile)
                self.assertFalse(os.path.exists(out))
                self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".")], [])

    def test_scanning_raises_scan_errors(self):
        info = {"signature": "none", "team_ids": [], "app_dir": h.APP}
        rules = {"zip-unsupported": "zip-unsupported", "zip-path-encoding": "zip-name-encoding"}
        for rule, path in self.fixtures():
            with self.subTest(rule=rule):
                with self.assertRaises(leaks.ScanError) as ctx:
                    leaks.scan_ipa(path, denylist=DENY, info=info)
                self.assertEqual(ctx.exception.rule, rules[rule])

    def test_archive_errors_cover_the_library_exceptions(self):
        for exc in (NotImplementedError("x"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            self.assertIsInstance(exc, stagemod.ARCHIVE_ERRORS)


class StageTests(ZipCase):
    def test_stage_rejects_the_archive(self):
        for rule, path in self.fixtures():
            with self.subTest(rule=rule):
                gh = FakeGitHub()
                with self.assertRaises(stagemod.GateRejected) as ctx:
                    stagemod.stage(path, denylist=DENY, gh=gh)
                self.assertEqual([f["rule"] for f in ctx.exception.findings], [rule])
                self.assertEqual(gh.calls, [])

    def test_a_rejected_draft_is_marked_blocked(self):
        gh = FakeGitHub()
        rel = gh.add_release("io.example.demo-v1.2.3", draft=True)
        gh.add_asset(rel, "Demo-1.2.3.ipa", read_bytes(self.newer_version()))
        with self.assertRaises(stagemod.GateRejected):
            stagemod.stage_existing_draft("io.example.demo-v1.2.3", denylist=DENY, gh=gh)
        self.assertEqual(gh.releases[rel["id"]]["name"], "[blocked] io.example.demo-v1.2.3")
        self.assertEqual(stagemod.draft_tags(gh), ([], ["io.example.demo-v1.2.3"]))

    def test_cli_exits_with_the_rejection_code(self):
        env = {"ALT_DENYLIST": "\n".join(DENY)}
        for rule, path in self.fixtures():
            for argv in (["stage", path, "--dry-run"], ["scan", path]):
                with self.subTest(rule=rule, command=argv[0]):
                    out, err = io.StringIO(), io.StringIO()
                    self.assertEqual(cli.main(argv, environ=env, out=out, err=err), cli.EXIT_REJECTED)
                    self.assertNotIn("Traceback", err.getvalue())


class SyncTests(ZipCase):
    def test_only_the_affected_releases_are_taken_down(self):
        root = self.path("repo")
        os.makedirs(root)
        git = FakeGit(root)
        git.seed({"source.base.json": syncmod.dumps_json(BASE)})
        gh = FakeGitHub(git)
        good = gh.add_release("io.example.good-v1.2.3")
        gh.add_asset(good, "Good.ipa", read_bytes(h.build_ipa(h.app_entries(bundle_id="io.example.good"),
                                                              self.path("good.ipa"))))
        newer = gh.add_release("io.example.newer-v1.2.3")
        gh.add_asset(newer, "Newer.ipa", read_bytes(self.newer_version(bundle_id="io.example.newer")))
        named = gh.add_release("io.example.named-v1.2.3")
        gh.add_asset(named, "Named.ipa", read_bytes(self.bad_name(bundle_id="io.example.named")))
        output = self.path("gh-output")
        result = syncmod.sync(root, gh=gh, git=git, deps=stagemod.Toolkit(), denylist=DENY, log=lambda m: None,
                              output_path=output, environ={}, sleep=lambda s: None)
        self.assertEqual(sorted(result.blocked), ["io.example.named-v1.2.3", "io.example.newer-v1.2.3"])
        self.assertTrue(any("blocked (zip-unsupported); unpublished" in e for e in result.errors), result.errors)
        self.assertTrue(any("blocked (zip-path-encoding); unpublished" in e for e in result.errors), result.errors)
        self.assertTrue(gh.releases[newer["id"]]["draft"])
        self.assertTrue(gh.releases[named["id"]]["draft"])
        self.assertFalse(gh.releases[good["id"]]["draft"])
        self.assertEqual((result.apps, result.versions, len(gh.commits)), (1, 1, 1))
        self.assertIn("apps/io.example.good/versions/1.2.3.json", gh.commits[0][1])
        with open(output, encoding="utf-8") as fh:
            self.assertIn("blocked=2", fh.read().splitlines())


if __name__ == "__main__":
    unittest.main()
