"""Tests for the command line interface (fake GitHub layer, fake IPA tooling, no network)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from altsource import cli, retract
from altsource import stage as stagemod
from tests.test_sync import BASE, FakeGit, FakeGitHub, FakeToolkit, ipa_bytes, load_json, write_ipa
from altsource.sync import dumps_json

DENY_TEXT = "# comment\nleaky-host-0\n\nleakyuser0\n"
TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")


class Untouchable:
    """A GitHub layer that fails the test on any use."""

    def __getattr__(self, name):
        raise AssertionError("GitHub was used: %s" % name)


class CliCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.output = os.path.join(self.dir, "gh-output")
        self.env = {"ALT_DENYLIST": DENY_TEXT, "GITHUB_OUTPUT": self.output}
        self.deps = FakeToolkit()
        self.gh = FakeGitHub()

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *argv, gh=None, env=None, git=None):
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(list(argv), deps=self.deps, gh=self.gh if gh is None else gh, git=git,
                        environ=self.env if env is None else env, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def outputs(self):
        if not os.path.exists(self.output):
            return {}
        values = {}
        with open(self.output, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if "<<" in line and "=" not in line.split("<<")[0]:
                key, delim = line.split("<<", 1)
                body = []
                i += 1
                while lines[i] != delim:
                    body.append(lines[i])
                    i += 1
                values[key] = "\n".join(body)
            else:
                key, _, value = line.partition("=")
                values[key] = value
            i += 1
        return values

    def ipa(self, filename="in.ipa", **fields):
        return write_ipa(os.path.join(self.dir, filename), **fields)


class BasicCommandTests(CliCase):
    def test_parse_tag_prints_and_writes_outputs(self):
        code, out, _ = self.run_cli("parse-tag", "io.example.demo-v1.3.0-rc.1")
        self.assertEqual(code, 0)
        self.assertIn("bid=io.example.demo\n", out)
        self.assertIn("semver=1.3.0-rc.1\n", out)
        self.assertEqual(self.outputs(), {"bid": "io.example.demo", "semver": "1.3.0-rc.1",
                                          "prerelease": "true", "alias": "IO_EXAMPLE_DEMO"})

    def test_parse_tag_rejects_bad_tags(self):
        for tag in ("v1.0.0", "io.example.demo-v1.0", "io.example.app-v2-v1.0.0", "x-v1.0.0+build"):
            code, _, err = self.run_cli("parse-tag", tag)
            self.assertEqual(code, 1, tag)
            self.assertIn("does not match the grammar", err)

    def test_alias(self):
        code, out, _ = self.run_cli("alias", "io.github.nuke-browser")
        self.assertEqual((code, out), (0, "IO_GITHUB_NUKE_BROWSER\n"))

    def test_inspect_json(self):
        code, out, _ = self.run_cli("inspect", self.ipa(), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["bundle_id"], "io.example.demo")
        code, out, _ = self.run_cli("inspect", self.ipa())
        self.assertIn("bundle_id: io.example.demo", out)

    def test_normalize(self):
        dst = os.path.join(self.dir, "out.ipa")
        code, out, _ = self.run_cli("normalize", self.ipa(junk=True), dst)
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["changed"])
        self.assertTrue(os.path.exists(dst))

    def test_scan_exit_codes_and_redaction(self):
        code, out, err = self.run_cli("scan", self.ipa())
        self.assertEqual(code, 0)
        self.assertIn("gate: passed", err)
        code, out, err = self.run_cli("scan", self.ipa(payload="LEAKY-HOST-0 /Users/leakyuser0/x"))
        self.assertEqual(code, 2)
        self.assertIn("denylist block 2\n  Payload/Demo.app/Demo\n", out)
        self.assertIn("home-path block 1", out)
        self.assertNotIn("leaky", (out + err).lower())
        code, out, _ = self.run_cli("scan", self.ipa(payload="/Users/leakyuser2/x"), "--allow-home-paths")
        self.assertEqual(code, 0)
        self.assertIn("home-path warn 1", out)
        code, out, _ = self.run_cli("scan", self.ipa(broken="zip-symlink-escape"))
        self.assertEqual((code, out), (2, "zip-symlink-escape block 1\n"))

    def test_denylist_sources(self):
        deny_file = os.path.join(self.dir, "deny")
        with open(deny_file, "w", encoding="utf-8") as fh:
            fh.write("special-word\n")
        path = self.ipa(payload="special-word")
        self.assertEqual(self.run_cli("scan", path, env={})[0], 1)
        self.assertEqual(self.run_cli("scan", path, env={"ALT_DENYLIST": "\n# only a comment\n"})[0], 1)
        self.assertEqual(self.run_cli("scan", path)[0], 0)
        self.assertEqual(self.run_cli("scan", path, "--denylist-file", deny_file)[0], 2)
        code, _, err = self.run_cli("scan", path, "--denylist-file", os.path.join(self.dir, "missing"))
        self.assertEqual(code, 1)
        self.assertNotIn(self.dir, err)

    def test_safe_path(self):
        self.assertEqual(cli.safe_path("Payload/A.app/leaky-host-0.txt", ["leaky-host-0"]), "<redacted>")
        self.assertEqual(cli.safe_path("C:\\Users\\x\\a", []), "<redacted>")
        self.assertEqual(cli.safe_path("Payload/A.app/A", ["leaky-host-0"]), "Payload/A.app/A")

    def test_unknown_errors_are_terse_in_ci(self):
        def boom(path):
            raise RuntimeError("detail mentioning leaky-host-0")

        self.deps.inspect_ipa = boom
        code, _, err = self.run_cli("inspect", self.ipa(), env={"GITHUB_ACTIONS": "true"})
        self.assertEqual(code, 1)
        self.assertEqual(err, "error: RuntimeError\n")
        code, _, err = self.run_cli("inspect", self.ipa(), env={})
        self.assertIn("detail mentioning", err)

    def test_missing_module_message(self):
        exc = ModuleNotFoundError("No module named 'altsource.tags'", name="altsource.tags")

        def missing(tag):
            raise exc

        self.deps.parse_tag = missing
        code, _, err = self.run_cli("parse-tag", "a-v1.0.0")
        self.assertEqual((code, err), (1, "error: module altsource.tags is not available\n"))

    def test_module_entry_point(self):
        env = dict(os.environ, PYTHONPATH=TOOLS)
        proc = subprocess.run([sys.executable, "-m", "altsource", "--help"], capture_output=True, env=env)
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"resolve-build", proc.stdout)
        proc = subprocess.run([sys.executable, "-m", "altsource"], capture_output=True, env=env)
        self.assertEqual(proc.returncode, 1)  # usage errors never look like a gate rejection (2)
        self.assertIn(b"the following arguments are required", proc.stderr)

    def test_usage_errors_exit_1(self):
        for argv in (["stage", "--bogus", "x.ipa"], ["sync", "--unknown"], ["stage"], [],
                     ["resolve-build", "--bid", "io.example.demo"], ["no-such-command"]):
            code, out, err = self.run_cli(*argv, gh=Untouchable())
            self.assertEqual(code, 1, argv)
            self.assertEqual(out, "")
            self.assertIn("altsource: error:", err)
            self.assertIn("usage:", err)

    def test_usage_errors_hide_argument_values_in_ci(self):
        env = {"GITHUB_ACTIONS": "true"}
        code, _, err = self.run_cli("fetch", "https://leaky-host-0.example.invalid/a.ipa", "out.ipa",
                                    "extra-leaky-host-0", env=env)
        self.assertEqual(code, 1)
        self.assertIn("unrecognized arguments", err)
        self.assertNotIn("leaky-host-0", err)
        code, _, err = self.run_cli("leaky-host-0", env=env)
        self.assertEqual(code, 1)
        self.assertNotIn("leaky-host-0", err)
        code, _, err = self.run_cli("sync", "--leaky-host-0", env={})
        self.assertIn("--leaky-host-0", err)  # locally the message is complete


class StageCommandTests(CliCase):
    def test_stage_publishes_and_writes_outputs(self):
        notes = os.path.join(self.dir, "notes.md")
        with open(notes, "w", encoding="utf-8") as fh:
            fh.write("Fixes\n")
        code, out, _ = self.run_cli("stage", self.ipa(), "--bid", "io.example.demo", "--notes-file", notes)
        self.assertEqual(code, 0)
        values = self.outputs()
        self.assertEqual(values["tag"], "io.example.demo-v1.2.3")
        self.assertEqual(values["published"], "true")
        self.assertEqual(values["noop"], "false")
        self.assertIn("tag=io.example.demo-v1.2.3\n", out)
        rel = self.gh.releases[int(values["release_id"])]
        self.assertEqual(rel["body"], "Fixes")

    def test_stage_dry_run_never_touches_github(self):
        code, out, _ = self.run_cli("stage", self.ipa(), "--dry-run", gh=Untouchable())
        self.assertEqual(code, 0)
        self.assertIn("published=false\n", out)
        self.assertEqual(self.outputs()["release_id"], "")

    def test_stage_gate_rejection_exit_2(self):
        code, out, err = self.run_cli("stage", self.ipa(payload="leaky-host-0"), gh=Untouchable())
        self.assertEqual(code, 2)
        self.assertIn("gate rejected", err)
        self.assertIn("denylist block 1", err)
        self.assertNotIn("leaky-host-0", out + err)

    def test_stage_and_scan_agree_on_unscannable_ipa(self):
        from tests.test_sync import FakeIpaError

        def scan(path, **kw):
            raise FakeIpaError("zip-bomb-ratio")

        self.deps.scan_ipa = scan
        self.assertEqual(self.run_cli("scan", self.ipa())[0], 2)
        code, _, err = self.run_cli("stage", self.ipa(), gh=Untouchable())
        self.assertEqual(code, 2)
        self.assertIn("zip-bomb-ratio block 1", err)

    def test_stage_conflict_exit_3(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", b"different")
        code, _, err = self.run_cli("stage", self.ipa())
        self.assertEqual(code, 3)
        self.assertIn("conflict", err)

    def test_stage_without_denylist_fails_closed(self):
        code, _, err = self.run_cli("stage", self.ipa(), env={}, gh=Untouchable())
        self.assertEqual(code, 1)
        self.assertIn("denylist missing", err)

    def test_stage_no_publish_and_semver(self):
        code, out, _ = self.run_cli("stage", self.ipa(short_version="2.0"), "--semver", "2.0.0-beta.1",
                                    "--no-publish")
        self.assertEqual(code, 0)
        self.assertIn("tag=io.example.demo-v2.0.0-beta.1\n", out)
        self.assertIn("published=false\n", out)

    def test_stage_draft_single_and_all(self):
        a = self.gh.add_release("io.example.demo-v1.2.3", draft=True)
        self.gh.add_asset(a, "a.ipa", ipa_bytes(junk=True))
        b = self.gh.add_release("io.example.other-v1.0.0", draft=True)
        self.gh.add_asset(b, "b.ipa", ipa_bytes(bundle_id="io.example.other", short_version="1.0.0",
                                                payload="leaky-host-0"))
        c = self.gh.add_release("io.example.third-v3.0.0", draft=True)
        self.gh.add_asset(c, "c.ipa", ipa_bytes(bundle_id="io.example.third", short_version="3.0"))
        code, out, err = self.run_cli("stage-draft", "--all")
        self.assertEqual(code, 2)
        self.assertIn("io.example.demo-v1.2.3 published=true noop=false", out)
        self.assertIn("io.example.third-v3.0.0 published=true noop=false", out)
        self.assertIn("release %d: gate rejected" % b["id"], err)
        self.assertNotIn("io.example.other", err)  # the tag is not shown before the gate passed it
        values = self.outputs()
        self.assertEqual((values["staged"], values["rejected"], values["failed"]), ("2", "1", "0"))
        self.assertTrue(self.gh.releases[b["id"]]["draft"])
        os.unlink(self.output)
        code, out, _ = self.run_cli("stage-draft", "io.example.demo-v1.2.3")
        self.assertEqual(code, 0)
        self.assertEqual(self.outputs()["noop"], "true")
        self.assertEqual(self.run_cli("stage-draft")[0], 1)
        self.assertEqual(self.run_cli("stage-draft", "x-v1.0.0", "--all")[0], 1)


class StageDraftExitTests(CliCase):
    def test_exit_zero_reports_counts(self):
        a = self.gh.add_release("io.example.demo-v1.0.0", draft=True)
        self.gh.add_asset(a, "a.ipa", ipa_bytes(short_version="1.0.0"))
        b = self.gh.add_release("io.example.demo-v1.1.0", draft=True)
        self.gh.add_asset(b, "b.ipa", ipa_bytes(short_version="1.1.0", payload="leaky-host-0"))
        self.gh.add_release("io.example.demo-v1.2.0", draft=True)  # no IPA: a failure, not a rejection
        code, _, err = self.run_cli("stage-draft", "--all", "--exit-zero")
        self.assertEqual(code, 0, err)
        values = self.outputs()
        self.assertEqual((values["staged"], values["rejected"], values["failed"]), ("1", "1", "1"))
        self.assertFalse(self.gh.releases[a["id"]]["draft"])


class BlockedDraftTests(CliCase):
    def test_blocked_drafts_stop_failing_scheduled_runs(self):
        bad = self.gh.add_release("io.example.demo-v1.2.3", draft=True)
        self.gh.add_asset(bad, "a.ipa", ipa_bytes(payload="leaky-host-0"))
        code, _, err = self.run_cli("stage-draft", "--all")
        self.assertEqual(code, 2)  # reported once
        good = self.gh.add_release("io.example.demo-v1.3.0", draft=True)
        self.gh.add_asset(good, "b.ipa", ipa_bytes(short_version="1.3.0"))
        self.gh.calls.clear()
        code, out, err = self.run_cli("stage-draft", "--all")
        self.assertEqual(code, 0, err)
        self.assertIn("pending drafts: 1", err)
        self.assertIn("blocked drafts skipped: 1", err)
        self.assertIn("io.example.demo-v1.3.0 published=true", out)
        downloads = [c[1] for c in self.gh.calls if c[0] == "download_asset"]
        self.assertNotIn(bad["assets"][0]["id"], downloads)


class CatalogCommandTests(CliCase):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.dir, "repo")
        os.makedirs(self.root)
        self.git = FakeGit(self.root)
        self.git.seed({"source.base.json": dumps_json(BASE)})
        self.gh = FakeGitHub(self.git)

    def test_sync_success(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes())
        code, out, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 0, err)
        self.assertIn("changed=true\n", out)
        self.assertIn("apps=1 versions=1\n", out)
        self.assertIn("normalized=0\n", out)
        self.assertIn("retracted=0 restored=0\n", out)
        self.assertEqual(self.outputs()["changed"], "true")

    def test_sync_prints_tombstone_counts(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes())
        self.assertEqual(self.run_cli("sync", "--root", self.root, git=self.git)[0], 0)
        self.git.refresh("main")
        del self.gh.releases[rel["id"]]
        code, out, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 0, err)
        self.assertIn("retracted=1 restored=0\n", out)
        self.assertEqual(self.outputs()["retracted"], "1")
        self.assertIn("io.example.demo-v1.2.3: withdrawn (deleted); tombstone added", err)
        code, out, _ = self.run_cli("retracted", "--root", self.root, "--bid", "io.example.demo",
                                    "--version", "1.2.3")
        self.assertEqual(code, 0)

    def test_sync_prints_normalized_count(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(junk="__MACOSX/"))  # uploaded without stage
        code, out, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 0, err)
        self.assertIn("normalized=1\n", out)
        self.assertIn("IPA replaced by its normalized form", err)

    def test_sync_blocked_release_exit_2(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(payload="leaky-host-0"))
        code, out, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 2)
        self.assertIn("blocked (denylist); unpublished", err)
        self.assertNotIn("leaky-host-0", out + err)

    def test_sync_outputs_commit_and_counts_when_blocked(self):
        clean = self.gh.add_release("io.example.demo-v1.3.0")
        self.gh.add_asset(clean, "Demo.ipa", ipa_bytes(short_version="1.3.0"))
        rel = self.gh.add_release("io.example.demo-v1.2.3", body="see leaky-host-0")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes())
        code, out, _ = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 2)
        values = self.outputs()
        self.assertTrue(values["commit"])  # a deploy job keyed on the commit output still runs
        self.assertEqual((values["changed"], values["blocked"], values["errors"]), ("true", "1", "1"))
        self.assertIn("blocked=1 errors=1\n", out)

    def test_sync_exit_zero_defers_the_failure(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(payload="leaky-host-0"))
        code, out, err = self.run_cli("sync", "--root", self.root, "--exit-zero", git=self.git)
        self.assertEqual(code, 0)
        self.assertEqual(self.outputs()["blocked"], "1")
        self.assertIn("blocked (denylist); unpublished", err)

    def test_sync_exit_zero_does_not_hide_aborts(self):
        from altsource.gh import GhError

        self.gh.list_error = GhError("GET releases failed (HTTP 500)", status=500)
        self.assertEqual(self.run_cli("sync", "--root", self.root, "--exit-zero", git=self.git)[0], 1)

    def test_sync_blocked_release_exit_2_after_head_moved(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(payload="leaky-host-0"))
        self.git.push_elsewhere({"README.md": b"x\n"})
        code, out, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 2)
        self.assertIn("retrying (attempt 2)", err)

    def test_sync_rescan_flag(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes(payload="later-word"))
        self.assertEqual(self.run_cli("sync", "--root", self.root, git=self.git)[0], 0)
        self.git.refresh("main")
        env = dict(self.env, ALT_DENYLIST=DENY_TEXT + "later-word\n")
        self.assertEqual(self.run_cli("sync", "--root", self.root, git=self.git, env=env)[0], 0)
        self.assertEqual(self.run_cli("sync", "--root", self.root, "--rescan", git=self.git, env=env)[0], 2)

    def test_sync_abort_exit_1(self):
        from altsource.gh import GhError

        self.gh.list_error = GhError("GET releases failed (HTTP 500)", status=500)
        code, _, err = self.run_cli("sync", "--root", self.root, git=self.git)
        self.assertEqual(code, 1)
        self.assertIn("release listing failed", err)
        self.assertEqual(self.outputs(), {})

    def test_sync_dry_run(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3")
        self.gh.add_asset(rel, "Demo.ipa", ipa_bytes())
        code, out, err = self.run_cli("sync", "--root", self.root, "--dry-run", git=self.git)
        self.assertEqual(code, 0)
        self.assertIn("would write source.json", err)
        self.assertEqual(self.gh.mutations(), [])

    def test_sync_requires_denylist(self):
        code, _, err = self.run_cli("sync", "--root", self.root, env={}, gh=Untouchable(), git=self.git)
        self.assertEqual(code, 1)

    def test_generate_and_check(self):
        code, _, _ = self.run_cli("generate", "--root", self.root, "--check")
        self.assertEqual(code, 1)
        self.assertEqual(self.run_cli("generate", "--root", self.root)[0], 0)
        self.assertEqual(load_json(os.path.join(self.root, "source.json"))["identifier"], BASE["identifier"])
        self.assertEqual(self.run_cli("generate", "--root", self.root, "--check")[0], 0)

    def test_validate(self):
        self.assertEqual(self.run_cli("validate", "--root", self.root)[0], 1)  # no source.json yet
        self.run_cli("generate", "--root", self.root)
        self.assertEqual(self.run_cli("validate", "--root", self.root)[0], 0)
        os.makedirs(os.path.join(self.root, "apps", "io.example.demo"))
        with open(os.path.join(self.root, "apps", "io.example.demo", "app.json"), "w", encoding="utf-8") as fh:
            json.dump({"tintColor": "red"}, fh)
        code, out, _ = self.run_cli("validate", "--root", self.root)
        self.assertEqual(code, 1)
        self.assertIn("apps/io.example.demo/app.json: tintColor", out)
        self.deps.validation_errors = ["warning: zero apps"]
        with open(os.path.join(self.root, "apps", "io.example.demo", "app.json"), "w", encoding="utf-8") as fh:
            json.dump({"tintColor": "AABBCC"}, fh)
        code, _, err = self.run_cli("validate", "--root", self.root)
        self.assertEqual(code, 0)
        self.assertIn("warning: zero apps", err)


class FetchCommandTests(CliCase):
    def test_fetch_prints_digest_not_url(self):
        def fake_fetch(url, dest, sha256=None):
            with open(dest, "wb") as fh:
                fh.write(b"payload")

        self.deps.fetch = fake_fetch
        out_path = os.path.join(self.dir, "x.ipa")
        code, out, err = self.run_cli("fetch", "https://leaky-host-0.example.invalid/a.ipa", out_path)
        self.assertEqual(code, 0)
        self.assertNotIn("leaky-host-0", out + err)
        self.assertEqual(self.outputs()["size"], "7")

    def test_fetch_error_rule(self):
        class FetchError(Exception):
            rule = "private-address"

        def fake_fetch(url, dest, sha256=None):
            raise FetchError("resolved to 10.0.0.1 for leaky-host-0")

        self.deps.fetch = fake_fetch
        self.deps.FetchError = FetchError
        code, out, err = self.run_cli("fetch", "https://leaky-host-0.example.invalid/a.ipa",
                                      os.path.join(self.dir, "x.ipa"), "--sha256", "0" * 64)
        self.assertEqual(code, 1)
        self.assertEqual(err, "error: fetch rejected (private-address)\n")


class ResolveBuildTests(CliCase):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.dir, "repo")
        self.checkout = os.path.join(self.dir, "checkout")
        os.makedirs(os.path.join(self.root, "apps", "io.example.demo"))
        os.makedirs(self.checkout)
        self.app_json({"privateBuild": {"enabled": True}})
        self.env["ALT_APP_CONFIG"] = json.dumps({"repo": "someone/private-thing"})

    def app_json(self, obj):
        with open(os.path.join(self.root, "apps", "io.example.demo", "app.json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)

    def alt_json(self, obj):
        with open(os.path.join(self.checkout, ".alt.json"), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)

    def resolve(self, ref="v1.4.0", **kw):
        return self.run_cli("resolve-build", "--bid", "io.example.demo", "--ref", ref, "--checkout",
                            self.checkout, "--root", self.root, **kw)

    def test_merge_registered_config_wins(self):
        self.alt_json({"runner": "macos-15", "xcode": "26.4", "setup": ["go"], "command": "make ipa\nls",
                       "ipa_glob": "build/*.ipa", "env": {"SCHEME": "Demo", "MODE": "release"}})
        self.env["ALT_APP_CONFIG"] = json.dumps({"repo": "someone/private-thing", "build": {
            "runner": "xcode-27", "xcode": "27.0", "setup": "go xcodegen", "env": {"MODE": "ci"}}})
        json_out = os.path.join(self.dir, "resolved.json")
        code, out, err = self.run_cli(
            "resolve-build", "--bid", "io.example.demo", "--ref", "v1.4.0", "--checkout", self.checkout,
            "--root", self.root, "--json-out", json_out)
        self.assertEqual(code, 0, err)
        values = self.outputs()
        self.assertEqual(values, {"runner": "xcode-27", "xcode": "27.0", "setup": "go xcodegen",
                                  "version": "1.4.0", "tag": "io.example.demo-v1.4.0"})
        full = load_json(json_out)
        self.assertEqual(full["command"], "make ipa\nls")
        self.assertEqual(full["ipa_glob"], "build/*.ipa")
        self.assertEqual(json.loads(full["env"]), {"MODE": "ci", "SCHEME": "Demo"})
        self.assertEqual((full["runner"], full["version"], full["tag"]), ("xcode-27", "1.4.0", "io.example.demo-v1.4.0"))
        self.assertNotIn("repo", full)
        for secret in ("private-thing", "make ipa", "Demo", "build/*.ipa"):
            self.assertNotIn(secret, out + err)
            self.assertNotIn(secret, json.dumps(values))
        self.assertIn("runner=xcode-27\n", out)
        self.assertNotIn("::add-mask::", out)  # masks are only emitted inside GitHub Actions

    def test_private_values_are_masked_in_ci(self):
        self.alt_json({"command": "make ipa\n  ./pack 100%\nls", "ipa_glob": "build/*.ipa",
                       "env": {"SCHEME": "Demo", "SHORT": "1"}})
        self.env["GITHUB_ACTIONS"] = "true"
        json_out = os.path.join(self.dir, "resolved.json")
        code, out, err = self.run_cli(
            "resolve-build", "--bid", "io.example.demo", "--ref", "v1.4.0", "--checkout", self.checkout,
            "--root", self.root, "--json-out", json_out)
        self.assertEqual(code, 0, err)
        masks = [line[len("::add-mask::"):] for line in out.splitlines() if line.startswith("::add-mask::")]
        self.assertEqual(masks, ["someone/private-thing", "make ipa", "./pack 100%25", "Demo", "build/*.ipa"])
        first_plain = min(i for i, line in enumerate(out.splitlines()) if not line.startswith("::"))
        self.assertEqual(first_plain, len(masks))  # masks come before any other output
        self.assertEqual(sorted(self.outputs()), ["runner", "setup", "tag", "version", "xcode"])

    def test_defaults_and_custom_tag_pattern(self):
        self.app_json({"privateBuild": {"enabled": True, "tagPattern": r"^release-(?P<version>\d+\.\d+\.\d+)$"}})
        self.alt_json({"command": "./build.sh"})
        json_out = os.path.join(self.dir, "resolved.json")
        code, _, err = self.run_cli("resolve-build", "--bid", "io.example.demo", "--ref", "release-2.0.1",
                                    "--checkout", self.checkout, "--root", self.root, "--json-out", json_out)
        self.assertEqual(code, 0, err)
        values = self.outputs()
        self.assertEqual((values["runner"], values["xcode"], values["setup"]), ("macos-latest", "", ""))
        full = load_json(json_out)
        self.assertEqual((full["ipa_glob"], full["env"]), ("**/*.ipa", "{}"))
        self.assertEqual(values["version"], "2.0.1")
        self.assertEqual(self.resolve("v2.0.1")[0], 1)

    def test_rejections(self):
        bad = [
            {"command": "x", "runner": "ubuntu-latest"},
            {"command": "x", "runner": "macos-26-xlarge"},
            {"command": "x", "xcode": "27.0-beta"},
            {"command": "x", "setup": ["go", "curl"]},
            {"command": ""},
            {},
            {"command": "x", "ipa_glob": "../out/*.ipa"},
            {"command": "x", "ipa_glob": "/abs/*.ipa"},
            {"command": "x", "ipa_glob": "out/*.zip"},
            {"command": "x", "env": {"PATH": "/bin"}},
            {"command": "x", "env": {"GITHUB_TOKEN": "x"}},
            {"command": "x", "env": {"PYTHONPATH": "/tmp/x"}},
            {"command": "x", "env": {"GIT_SSH_COMMAND": "x"}},
            {"command": "x", "env": {"NODE_OPTIONS": "--require x"}},
            {"command": "x", "env": {"DEVELOPER_DIR": "/Applications/Other.app"}},
            {"command": "x", "env": {"lower": "x"}},
            {"command": "x", "env": {"OK": "two\nlines"}},
            {"command": "x", "unknown": 1},
        ]
        for cfg in bad:
            self.alt_json(cfg)
            code, _, err = self.resolve()
            self.assertEqual(code, 1, cfg)
            self.assertTrue(err.startswith("error: "), err)

    def test_reserved_env_names(self):
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL",
                     "SSH_AUTH_SOCK", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "BASH_ENV", "PROMPT_COMMAND",
                     "ZDOTDIR", "CDPATH", "GLOBIGNORE", "DEVELOPER_DIR", "HOMEBREW_BREW_GIT_REMOTE",
                     "XDG_CONFIG_HOME", "SSL_CERT_FILE", "HTTPS_PROXY", "DYLD_INSERT_LIBRARIES"):
            with self.assertRaises(cli.CliError, msg=name):
                cli._validate_env({name: "x"})
        self.assertEqual(cli._validate_env({"SCHEME": "Demo", "GOFLAGS": "-trimpath", "NODE_ENV": "production"}),
                         {"GOFLAGS": "-trimpath", "NODE_ENV": "production", "SCHEME": "Demo"})

    def test_error_messages_hide_private_key_names_in_ci(self):
        ci = dict(self.env, GITHUB_ACTIONS="true")
        cases = [
            ({"command": "x", "secret-ish-key": 1}, None, "has 1 unknown key(s)"),
            ({"command": "x", "env": {"PYTHONPATH": "x"}}, None, "build env entry 1: the name is reserved"),
            ({"command": "x", "env": {"AAA": "ok", "SECRETVALUEKEY": "two\nlines"}}, None,
             "build env entry 2: the value must be a single-line string"),
            ({"command": "x"}, json.dumps({"repo": "a/b", "secret-ish-key": 1}), "ALT_APP_CONFIG has 1 unknown key(s)"),
        ]
        for alt, config, expected in cases:
            self.alt_json(alt)
            env = dict(ci)
            if config:
                env["ALT_APP_CONFIG"] = config
            code, out, err = self.resolve(env=env)
            self.assertEqual(code, 1)
            self.assertIn(expected, err)
            for name in ("secret-ish-key", "PYTHONPATH", "SECRETVALUEKEY"):
                self.assertNotIn(name, out + err)
        self.alt_json({"command": "x", "secret-ish-key": 1})
        self.assertIn("secret-ish-key", self.resolve()[2])  # names are shown locally

    def test_secret_and_app_preconditions(self):
        self.alt_json({"command": "x"})
        for config in (None, "", "not json", json.dumps({"repo": "no-slash"}),
                       json.dumps({"repo": "a/b", "keys": "x"})):
            env = dict(self.env)
            if config is None:
                env.pop("ALT_APP_CONFIG")
            else:
                env["ALT_APP_CONFIG"] = config
            self.assertEqual(self.resolve(env=env)[0], 1, config)
        self.app_json({"privateBuild": {"enabled": False}})
        code, _, err = self.resolve()
        self.assertEqual(code, 1)
        self.assertIn("does not enable privateBuild", err)
        self.assertEqual(self.run_cli("resolve-build", "--bid", "io.example.app-v2", "--ref", "v1.0.0",
                                      "--checkout", self.checkout, "--root", self.root)[0], 1)


class RetractedCommandTests(CliCase):
    BID = "io.example.demo"

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.dir, "repo")
        os.makedirs(self.root)

    def tombstones(self, data):
        path = os.path.join(self.root, "apps", self.BID, "retracted.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)

    def retracted(self, *extra, ci=False):
        env = dict(self.env, GITHUB_ACTIONS="true") if ci else self.env
        return self.run_cli("retracted", "--root", self.root, "--bid", self.BID, *extra, gh=Untouchable(), env=env)

    def test_exit_codes_and_reports(self):
        self.tombstones(retract.dumps({"1.10.0": {"date": "2026-10-23T08:00:00Z", "reason": "unpublished"},
                                       "1.2.0": {"date": "2026-10-22T08:00:00Z", "reason": "deleted"}}))
        self.assertEqual(self.retracted("--version", "1.2.0"), (0, "retracted (deleted, 2026-10-22T08:00:00Z)\n", ""))
        self.assertEqual(self.retracted("--version", "1.3.0"), (4, "not retracted\n", ""))
        self.assertEqual(self.retracted(), (0, "1.2.0 deleted 2026-10-22T08:00:00Z\n"
                                               "1.10.0 unpublished 2026-10-23T08:00:00Z\n", ""))

    def test_nothing_but_the_exit_code_in_ci(self):
        self.tombstones(retract.dumps({"1.2.0": {"date": "2026-10-22T08:00:00Z", "reason": "deleted"}}))
        self.assertEqual(self.retracted("--version", "1.2.0", ci=True), (0, "", ""))
        self.assertEqual(self.retracted("--version", "1.2.1", ci=True), (4, "", ""))
        self.assertEqual(self.retracted(ci=True), (0, "", ""))
        self.assertEqual(self.outputs(), {})

    def test_missing_file_means_not_retracted(self):
        self.assertEqual(self.retracted("--version", "1.0.0", ci=True), (4, "", ""))
        self.assertEqual(self.retracted(ci=True), (4, "", ""))
        self.tombstones(retract.dumps({}))
        self.assertEqual(self.retracted(ci=True), (4, "", ""))

    def test_damaged_file_is_an_error(self):
        self.tombstones(b'{"schemaVersion": 1, "versions": {"1.0.0": "leaky-host-0"}}')
        code, out, err = self.retracted("--version", "1.2.0", ci=True)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("retracted.json is not valid", err)
        self.assertNotIn("leaky-host-0", err)

    def test_invalid_arguments(self):
        code, _, err = self.run_cli("retracted", "--root", self.root, "--bid", "../leaky-host-0",
                                    env=dict(self.env, GITHUB_ACTIONS="true"))
        self.assertEqual(code, 1)
        self.assertIn("invalid bundle identifier", err)
        self.assertNotIn("leaky-host-0", err)
        code, _, err = self.retracted("--version", "v1.0.0")
        self.assertEqual(code, 1)
        self.assertIn("not a semantic version", err)
        self.assertEqual(self.run_cli("retracted", "--root", self.root)[0], 1)  # --bid is required

    def test_module_entry_point(self):
        self.tombstones(retract.dumps({"1.2.0": {"date": "2026-10-22T08:00:00Z", "reason": "deleted"}}))
        env = dict(os.environ, PYTHONPATH=TOOLS, GITHUB_ACTIONS="true")
        for version, code in (("1.2.0", 0), ("1.2.1", 4)):
            proc = subprocess.run([sys.executable, "-m", "altsource", "retracted", "--root", self.root,
                                   "--bid", self.BID, "--version", version], capture_output=True, env=env)
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (code, b"", b""))

    def test_validate_reports_a_damaged_file(self):
        with open(os.path.join(self.root, "source.json"), "w", encoding="utf-8") as fh:
            json.dump({"apps": []}, fh)
        self.assertEqual(self.run_cli("validate", "--root", self.root)[0], 0)
        self.tombstones(retract.dumps({"1.2.0": {"date": "2026-10-22T08:00:00Z", "reason": "deleted"}}))
        self.assertEqual(self.run_cli("validate", "--root", self.root)[0], 0)
        self.tombstones(b"[]")
        code, out, _ = self.run_cli("validate", "--root", self.root)
        self.assertEqual(code, 1)
        self.assertIn("apps/io.example.demo/retracted.json: must be an object", out)


class RetractedStagingTests(CliCase):
    """Staging is an explicit operator action: a withdrawn version goes ahead, with a warning."""

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.dir, "repo")
        path = os.path.join(self.root, "apps", "io.example.demo", "retracted.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fh:
            fh.write(retract.dumps({"1.2.3": {"date": "2026-10-22T08:00:00Z", "reason": "deleted"}}))

    def test_stage_warns_about_a_withdrawn_version(self):
        code, out, err = self.run_cli("stage", self.ipa(), "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("published=true\n", out)
        self.assertIn("warning: this version was withdrawn", err)
        code, _, err = self.run_cli("stage", self.ipa("b.ipa", short_version="1.2.4"), "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertNotIn("withdrawn", err)

    def test_stage_draft_warns_about_a_withdrawn_version(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3", draft=True)
        self.gh.add_asset(rel, "a.ipa", ipa_bytes())
        code, out, err = self.run_cli("stage-draft", "io.example.demo-v1.2.3", "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("published=true\n", out)
        self.assertIn("warning: this version was withdrawn", err)
        self.assertFalse(self.gh.releases[rel["id"]]["draft"])

    def test_stage_draft_all_skips_withdrawn_versions(self):
        # stage.yml runs --all on a schedule: an unpublished version must not come back by itself
        withdrawn = self.gh.add_release("io.example.demo-v1.2.3", draft=True)
        self.gh.add_asset(withdrawn, "a.ipa", ipa_bytes())
        other = self.gh.add_release("io.example.demo-v1.2.4", draft=True)
        self.gh.add_asset(other, "b.ipa", ipa_bytes(short_version="1.2.4"))
        code, out, err = self.run_cli("stage-draft", "--all", "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("pending drafts: 1\n", err)
        self.assertIn("withdrawn drafts skipped: 1 (titled [withdrawn] <tag> or listed in retracted.json; stage "
                      "one by tag", err)
        self.assertIn("io.example.demo-v1.2.4 published=true", out)
        self.assertNotIn("1.2.3", out + err)
        self.assertTrue(self.gh.releases[withdrawn["id"]]["draft"])
        self.assertFalse(self.gh.releases[other["id"]]["draft"])
        values = self.outputs()
        self.assertEqual((values["staged"], values["withdrawn"], values["failed"]), ("1", "1", "0"))

    def test_stage_draft_all_skips_drafts_marked_withdrawn(self):
        # bin/alt retract --unpublish marks the draft, so it stays back before sync lists the version
        marked = self.gh.add_release("io.example.demo-v1.2.5", draft=True)
        marked["name"] = "[withdrawn] io.example.demo-v1.2.5"
        self.gh.add_asset(marked, "a.ipa", ipa_bytes(short_version="1.2.5"))
        code, out, err = self.run_cli("stage-draft", "--all", "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("pending drafts: 0\n", err)
        self.assertIn("withdrawn drafts skipped: 1 (", err)
        self.assertTrue(self.gh.releases[marked["id"]]["draft"])
        self.assertEqual(self.outputs()["withdrawn"], "1")
        # staging it by tag publishes it and restores the title
        code, out, err = self.run_cli("stage-draft", "io.example.demo-v1.2.5", "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertFalse(self.gh.releases[marked["id"]]["draft"])
        self.assertFalse(self.gh.releases[marked["id"]]["name"].startswith("[withdrawn]"))

    def test_stage_draft_all_keeps_drafts_back_when_tombstones_are_unreadable(self):
        with open(os.path.join(self.root, "apps", "io.example.demo", "retracted.json"), "wb") as fh:
            fh.write(b"{")
        rel = self.gh.add_release("io.example.demo-v1.2.4", draft=True)
        self.gh.add_asset(rel, "a.ipa", ipa_bytes(short_version="1.2.4"))
        other = self.gh.add_release("io.example.other-v1.0.0", draft=True)
        self.gh.add_asset(other, "b.ipa", ipa_bytes(bundle_id="io.example.other", short_version="1.0.0"))
        code, out, err = self.run_cli("stage-draft", "--all", "--root", self.root)
        self.assertEqual(code, 1)
        self.assertIn("release %d: error: the app's retracted.json is not valid; draft not staged" % rel["id"], err)
        self.assertIn("io.example.other-v1.0.0 published=true", out)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        values = self.outputs()
        self.assertEqual((values["staged"], values["withdrawn"], values["failed"]), ("1", "0", "1"))

    def test_rejected_ipa_gets_no_warning(self):
        code, _, err = self.run_cli("stage", self.ipa(payload="leaky-host-0"), "--root", self.root, gh=Untouchable())
        self.assertEqual(code, 2)
        self.assertNotIn("withdrawn", err)

    def test_damaged_tombstones_only_warn(self):
        with open(os.path.join(self.root, "apps", "io.example.demo", "retracted.json"), "wb") as fh:
            fh.write(b"{")
        code, _, err = self.run_cli("stage", self.ipa(), "--root", self.root)
        self.assertEqual(code, 0, err)
        self.assertIn("retracted.json is not valid", err)


class StageDraftLabelTests(CliCase):
    """A draft's tag is not printed before the gate passed it; messages use the release id."""

    def test_leaky_tag_in_all_mode(self):
        rel = self.gh.add_release("io.example.demo-v1.2.3-leaky-host-0", draft=True)
        self.gh.add_asset(rel, "a.ipa", ipa_bytes())
        good = self.gh.add_release("io.example.demo-v1.3.0", draft=True)
        self.gh.add_asset(good, "b.ipa", ipa_bytes(short_version="1.3.0"))
        code, out, err = self.run_cli("stage-draft", "--all")
        self.assertEqual(code, 2)
        self.assertIn("release %d: gate rejected: release tag rejected" % rel["id"], err)
        self.assertIn("io.example.demo-v1.3.0 published=true", out)
        self.assertNotIn("leaky-host-0", out + err)
        self.assertEqual(self.gh.releases[rel["id"]]["name"], "[blocked] release %d" % rel["id"])

    def test_failures_before_the_gate_name_the_release(self):
        rel = self.gh.add_release("io.example.demo-v1.2.0", draft=True)  # no IPA
        code, _, err = self.run_cli("stage-draft", "--all")
        self.assertEqual(code, 1)
        self.assertIn("release %d: error:" % rel["id"], err)

    def test_single_tag_is_not_repeated(self):
        self.gh.add_release("io.example.demo-v1.2.3-leaky-host-0", draft=True)
        code, out, err = self.run_cli("stage-draft", "io.example.demo-v1.2.3-leaky-host-0")
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("gate rejected: release tag rejected"), err)
        self.assertNotIn("leaky-host-0", out + err)

    def test_duplicate_and_blocked_drafts(self):
        a = self.gh.add_release("io.example.demo-v1.0.0", draft=True)
        self.gh.add_release("io.example.demo-v1.0.0", draft=True)
        b = self.gh.add_release("io.example.demo-v1.1.0", draft=True)
        b["name"] = "[blocked] io.example.demo-v1.1.0"
        c = self.gh.add_release("io.example.demo-v1.2.0", draft=True)
        c["name"] = "[withdrawn] io.example.demo-v1.2.0"
        self.gh.add_release("not a grammar tag", draft=True)
        self.gh.add_release("io.example.demo-v2.0.0")  # published
        self.assertEqual(cli.draft_releases(self.gh, self.deps), ([("io.example.demo-v1.0.0", a["id"])], 1, 1))
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps),
                         (["io.example.demo-v1.0.0"], ["io.example.demo-v1.1.0"]))


if __name__ == "__main__":
    unittest.main()
