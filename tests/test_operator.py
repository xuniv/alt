"""Tests for the operator command line ``bin/alt``, its pre-push hook template and the build step of
``build.yml`` that runs a private build command.

``gh``, ``ssh-keygen`` and ``age`` are fake programs on PATH that log their arguments and input; the IPA
tooling and the release API used by the stage pipeline are the in-memory fakes of ``tests.test_sync``.
Nothing touches the network or a real GitHub repository.
"""

from __future__ import annotations

import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from tests.test_sync import FakeGitHub, FakeToolkit, ipa_bytes, write_ipa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALT = os.path.join(ROOT, "bin", "alt")
HOOK_TEMPLATE = os.path.join(ROOT, "bin", "alt-hook-pre-push")
BID = "io.example.demo"
ALIAS = "IO_EXAMPLE_DEMO"
ENV = "alt-" + ALIAS
ENV_PATH = "repos/xuniv/alt/environments/" + ENV
POLICIES_PATH = ENV_PATH + "/deployment-branch-policies"
PRIVATE = "someone/private-app"
TAG = "io.example.demo-v1.2.3"
ZERO = "0" * 40
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyMaterialForTests000000000"
PRIVATE_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-private-material\n"
               "-----END OPENSSH PRIVATE KEY-----\n")


def load_alt():
    loader = importlib.machinery.SourceFileLoader("alt_operator", ALT)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # no __pycache__ next to bin/alt
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


alt = load_alt()

# a rule applies when every "match" item is an argument and every "pattern" regex finds an argument
FAKE_GH = r'''
import json, os, re, sys
state = os.environ["FAKE_GH_STATE"]
argv = sys.argv[1:]
data = sys.stdin.buffer.read()
with open(os.path.join(state, "calls.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"argv": argv, "stdin": data.decode("utf-8", "replace")}) + "\n")
with open(os.path.join(state, "rules.json"), encoding="utf-8") as fh:
    rules = json.load(fh)
for rule in rules:
    if (all(item in argv for item in rule.get("match", []))
            and all(any(re.search(p, a) for a in argv) for p in rule.get("pattern", []))):
        for option in ("--dir", "-D"):
            if option in argv and rule.get("files"):
                target = argv[argv.index(option) + 1]
                for name, content in rule["files"].items():
                    with open(os.path.join(target, name), "w", encoding="utf-8") as out:
                        out.write(content)
        out = rule.get("stdout", "")
        sys.stdout.write(out if isinstance(out, str) else json.dumps(out))
        sys.stderr.write(rule.get("stderr", ""))
        sys.exit(rule.get("code", 0))
'''

FAKE_SSH_KEYGEN = r'''
import json, os, stat, sys
args = sys.argv[1:]
key = args[args.index("-f") + 1]
mask = os.umask(0)
os.umask(mask)
with open(key, "w") as fh:
    fh.write(%r)
os.chmod(key, 0o600)
with open(key + ".pub", "w") as fh:
    fh.write(%r + "\n")
folder = os.path.dirname(key)
with open(os.path.join(os.environ["FAKE_GH_STATE"], "ssh-keygen.json"), "w") as fh:
    json.dump({"args": args, "dir": folder, "dir_mode": stat.S_IMODE(os.stat(folder).st_mode),
               "umask": mask}, fh)
''' % (PRIVATE_KEY, PUBLIC_KEY)

AGE_IDENTITY = "AGE-SECRET-KEY-1QPLACEHOLDERIDENTITYFORTESTS0000000000000000000000000000000"
AGE_RECIPIENT = "age1placeholderrecipientfortests000000000000000000000000000000"
FAKE_AGE_KEYGEN = r'''
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["-y"]:
    with open(args[1]) as fh:
        if %r not in fh.read():
            sys.exit(1)
    print(%r)
    sys.exit(0)
path = args[args.index("-o") + 1]
with open(path, "w") as fh:
    fh.write("# created: 2026-10-20T01:02:03+02:00\n# public key: %s\n%s\n")
mask = os.umask(0)
os.umask(mask)
with open(os.path.join(os.environ["FAKE_GH_STATE"], "age-keygen.json"), "w") as fh:
    json.dump({"dir": os.path.dirname(path), "umask": mask}, fh)
''' % (AGE_IDENTITY, AGE_RECIPIENT, AGE_RECIPIENT, AGE_IDENTITY)

FAKE_AGE = r'''
import base64, os, sys
args = sys.argv[1:]
if args[:2] != ["-d", "-i"] or not os.path.isfile(args[2]):
    sys.exit(2)
with open(args[3], encoding="utf-8") as fh:
    data = fh.read()
if data.startswith("encrypted-b64:"):
    sys.stdout.buffer.write(base64.b64decode(data[len("encrypted-b64:"):]))
    sys.exit(0)
if not data.startswith("encrypted:"):
    sys.stderr.write("no identity matched\n")
    sys.exit(1)
sys.stdout.write(data[len("encrypted:"):])
'''

NOT_FOUND = {"code": 1, "stdout": {"message": "Not Found", "status": "404"}, "stderr": "gh: Not Found (HTTP 404)\n"}
DEFAULT_RULES = [
    {"match": ["api", "user"], "stdout": "xuniv\n"},
    {"match": ["api", "repos/xuniv/alt"], "stdout": {"full_name": "xuniv/alt", "permissions": {"push": True}}},
    # no app has withdrawn versions, and main has no version records, unless a test says so
    dict(NOT_FOUND, match=["api"], pattern=[r"^repos/[^/]+/[^/]+/contents/apps/[^/]+/retracted\.json\?ref=main$"]),
    dict(NOT_FOUND, match=["api"],
         pattern=[r"^repos/[^/]+/[^/]+/contents/apps/[^/]+/versions/[^/]+\.json\?ref=main$"]),
    {"match": ["api"], "pattern": [r"^repos/[^/]+/[^/]+/git/trees/main\?recursive=1$"],
     "stdout": {"sha": "0" * 40, "tree": [], "truncated": False}},
]
RETRACTED_PATH = "repos/xuniv/alt/contents/apps/%s/retracted.json?ref=main" % BID
WITHDRAWN = {"1.2.3": {"date": "2026-10-22T07:13:00Z", "reason": "deleted"}}


def record_rule(version="1.2.3", bid=BID, repo="xuniv/alt"):
    """The contents API answer for main's version record apps/<bid>/versions/<version>.json."""
    path = "apps/%s/versions/%s.json" % (bid, version)
    return {"match": ["api", "repos/%s/contents/%s?ref=main" % (repo, path)],
            "stdout": {"type": "file", "encoding": "base64", "path": path,
                       "content": base64.encodebytes(b'{"tag": "placeholder"}\n').decode("ascii")}}


def retracted_rule(versions, bid=BID, repo="xuniv/alt"):
    """The contents API answer for apps/<bid>/retracted.json on main."""
    text = json.dumps({"schemaVersion": 1, "versions": versions}, indent=2, sort_keys=True) + "\n"
    return {"match": ["api", "repos/%s/contents/apps/%s/retracted.json?ref=main" % (repo, bid)],
            "stdout": {"type": "file", "encoding": "base64", "path": "apps/%s/retracted.json" % bid,
                       "content": base64.encodebytes(text.encode("utf-8")).decode("ascii")}}


class Untouchable:
    def __getattr__(self, name):
        raise AssertionError("the release API was used: %s" % name)


def is_write(argv):
    if argv[:1] == ["api"]:
        return "--method" in argv and argv[argv.index("--method") + 1] != "GET"
    return argv[:2] in (["workflow", "run"], ["secret", "set"], ["secret", "delete"], ["variable", "set"])


class OperatorCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.realpath(self._tmp.name)
        self.bin = self.mkdir("bin")
        self.state = self.mkdir("state")
        self.config = self.mkdir("config")
        self.root = self.mkdir("altrepo")
        self.home = self.mkdir("home")
        self.cache = os.path.join(self.dir, "cache")
        self.denylist = os.path.join(self.config, "ipa-denylist")
        self.write(self.denylist, "# private words\nleaky-host-0\nleakyuser0\n")
        self.script("gh", FAKE_GH)
        self.script("ssh-keygen", FAKE_SSH_KEYGEN)
        self.script("age", FAKE_AGE)
        self.script("age-keygen", FAKE_AGE_KEYGEN)
        self.env = {
            "PATH": self.bin + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.home,
            "FAKE_GH_STATE": self.state,
            "ALT_CONFIG_DIR": self.config,
            "ALT_CACHE_DIR": self.cache,
        }
        self.set_rules()
        self.deps = FakeToolkit()
        self.stage_gh = FakeGitHub()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        self._tmp.cleanup()

    # helpers -------------------------------------------------------------------------------------
    def mkdir(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(path, exist_ok=True)
        return path

    def write(self, path, text, mode=None):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def script(self, name, body):
        return self.write(os.path.join(self.bin, name), "#!%s\n%s" % (sys.executable, body), 0o755)

    def set_rules(self, *rules):
        with open(os.path.join(self.state, "rules.json"), "w", encoding="utf-8") as fh:
            json.dump(list(rules) + DEFAULT_RULES, fh)

    def calls(self):
        path = os.path.join(self.state, "calls.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def argvs(self):
        return [c["argv"] for c in self.calls()]

    def writes(self):
        return [a for a in self.argvs() if is_write(a)]

    def call(self, *prefix):
        found = [c for c in self.calls() if c["argv"][:len(prefix)] == list(prefix)]
        self.assertEqual(len(found), 1, "expected one call starting with %r in %r" % (prefix, self.argvs()))
        return found[0]

    def run_alt(self, *argv, env=None, stage_gh=None):
        out, err = io.StringIO(), io.StringIO()
        code = alt.main(list(argv), environ=self.env if env is None else env, out=out, err=err, deps=self.deps,
                        root=self.root, stage_gh=self.stage_gh if stage_gh is None else stage_gh)
        return code, out.getvalue(), err.getvalue()

    def app_json(self, obj, bid=BID):
        folder = os.path.join(self.root, "apps", bid)
        os.makedirs(folder, exist_ok=True)
        self.write(os.path.join(folder, "app.json"), json.dumps(obj))

    def read_app_json(self, bid=BID):
        with open(os.path.join(self.root, "apps", bid, "app.json"), encoding="utf-8") as fh:
            return json.load(fh)


class PreflightTests(OperatorCase):
    def test_missing_denylist_refuses_before_any_gh_call(self):
        os.unlink(self.denylist)
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("denylist not found", err)
        self.assertEqual(self.calls(), [])

    def test_empty_denylist_refuses(self):
        self.write(self.denylist, "# nothing but a comment\n\n")
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("denylist is empty", err)
        self.assertEqual(self.calls(), [])

    def test_only_the_ipa_denylist_is_read(self):
        os.unlink(self.denylist)
        self.write(os.path.join(self.config, "denylist"), "leaky-host-0\n")  # a different list
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("denylist not found", err)
        self.assertEqual(alt.Settings({"HOME": self.home}).denylist_file,
                         os.path.join(self.home, ".config", "xuniv-alt", "ipa-denylist"))

    def test_denylist_file_override(self):
        os.unlink(self.denylist)
        other = self.write(os.path.join(self.dir, "words"), "leaky-host-0\n")
        env = dict(self.env, ALT_DENYLIST_FILE=other)
        self.assertEqual(self.run_alt("build", BID, "v1.2.3", env=env)[0], 0)

    def test_other_login_is_refused_without_naming_it(self):
        self.set_rules({"match": ["api", "user"], "stdout": "personal-account\n"})
        code, out, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("not logged in as xuniv", err)
        self.assertNotIn("personal-account", out + err)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.argvs()[0], ["api", "user", "--jq", ".login"])

    def test_logged_out_is_refused(self):
        self.set_rules({"match": ["api", "user"], "code": 4, "stderr": "To get started, run gh auth login\n"})
        code, _, err = self.run_alt("status")
        self.assertEqual(code, 1)
        self.assertIn("not logged in", err)

    def test_repo_must_resolve_to_alt_repo_with_push_access(self):
        self.set_rules({"match": ["api", "repos/xuniv/alt"], "stdout": {"full_name": "xuniv/renamed"}})
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual((code, self.writes()), (1, []))
        self.assertIn("not accessible", err)
        self.set_rules({"match": ["api", "repos/xuniv/alt"],
                        "stdout": {"full_name": "xuniv/alt", "permissions": {"push": False}}})
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual((code, self.writes()), (1, []))
        self.assertIn("cannot push", err)
        self.assertEqual(self.run_alt("status")[0], 0)  # read-only commands do not need push access

    def test_owner_and_repo_overrides(self):
        self.set_rules({"match": ["api", "user"], "stdout": "example\n"},
                       {"match": ["api", "repos/example/source"],
                        "stdout": {"full_name": "example/source", "permissions": {"push": True}}})
        env = dict(self.env, ALT_OWNER="example", ALT_REPO="example/source")
        self.assertEqual(self.run_alt("build", BID, "v1.2.3", env=env)[0], 0)
        self.assertIn("example/source", self.writes()[0])
        self.assertEqual(self.run_alt("build", BID, "v1.2.3", env=dict(env, ALT_REPO="no-slash"))[0], 1)


class PublishTests(OperatorCase):
    def ipa(self, **fields):
        return write_ipa(os.path.join(self.dir, "in.ipa"), **fields)

    def test_publish_gates_uploads_a_draft_and_dispatches_stage(self):
        notes = self.write(os.path.join(self.dir, "notes.md"), "Fixes\n")
        code, out, err = self.run_alt("publish", self.ipa(junk=True), "--notes-file", notes)
        self.assertEqual(code, 0, err)
        (rel,) = self.stage_gh.releases.values()
        self.assertEqual((rel["tag_name"], rel["draft"], rel["body"]), (TAG, True, "Fixes"))
        self.assertEqual([a["name"] for a in rel["assets"]], ["Demo-App-1.2.3.ipa"])
        self.assertEqual(self.stage_gh.blobs[rel["assets"][0]["id"]], ipa_bytes())  # the normalized bytes
        self.assertNotIn("publish", [c[0] for c in self.stage_gh.calls])  # stage.yml publishes, not we
        self.assertEqual(self.writes(), [["workflow", "run", "stage.yml", "-R", "xuniv/alt", "-f", "tag=" + TAG]])
        self.assertIn("tag=%s\n" % TAG, out)
        self.assertIn("dispatched stage.yml for " + TAG, out)

    def test_defer_leaves_the_draft_for_the_schedule(self):
        code, out, _ = self.run_alt("publish", self.ipa(), "--defer")
        self.assertEqual(code, 0)
        self.assertTrue(list(self.stage_gh.releases.values())[0]["draft"])
        self.assertEqual(self.writes(), [])
        self.assertIn("waits for the next scheduled stage run", out)

    def test_gate_rejection_exits_2_without_any_upload(self):
        code, out, err = self.run_alt("publish", self.ipa(payload="LEAKY-HOST-0"))
        self.assertEqual(code, 2)
        self.assertIn("gate rejected", err)
        self.assertIn("denylist block 1", err)
        self.assertEqual(self.stage_gh.mutations(), [])
        self.assertEqual(self.writes(), [])
        self.assertNotIn("leaky-host-0", (out + err).lower())

    def test_notes_are_gated_too(self):
        notes = self.write(os.path.join(self.dir, "notes.md"), "built on /Users/leakyuser0/src\n")
        code, _, err = self.run_alt("publish", self.ipa(), "--notes-file", notes)
        self.assertEqual(code, 2)
        self.assertEqual(self.stage_gh.mutations(), [])
        self.assertNotIn("leakyuser0", err)

    def test_the_local_denylist_file_wins_over_the_environment(self):
        env = dict(self.env, ALT_DENYLIST="unrelated-word")
        self.assertEqual(self.run_alt("publish", self.ipa(payload="leaky-host-0"), env=env)[0], 2)

    def test_dry_run_runs_the_gate_and_prints_the_commands(self):
        for argv in (("--dry-run", "publish", self.ipa()), ("publish", self.ipa(), "--dry-run")):
            code, out, err = self.run_alt(*argv, stage_gh=Untouchable())
            self.assertEqual(code, 0, err)
            self.assertIn("+ gh api --method POST repos/xuniv/alt/releases", out)
            self.assertIn("assets?name=Demo-App-1.2.3.ipa", out)
            self.assertIn("+ gh workflow run stage.yml -R xuniv/alt -f tag=%s\n" % TAG, out)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.argvs()[0], ["api", "user", "--jq", ".login"])  # the login is still checked
        code, _, _ = self.run_alt("publish", self.ipa(payload="leaky-host-0"), "--dry-run", stage_gh=Untouchable())
        self.assertEqual(code, 2)

    def test_already_published_ipa_is_a_noop(self):
        rel = self.stage_gh.add_release(TAG)
        self.stage_gh.add_asset(rel, "Demo-App-1.2.3.ipa", ipa_bytes())
        code, out, _ = self.run_alt("publish", self.ipa(junk=True))
        self.assertEqual(code, 0)
        self.assertIn("already published", out)
        self.assertEqual(self.writes(), [])

    def test_conflict_exits_3(self):
        rel = self.stage_gh.add_release(TAG)
        self.stage_gh.add_asset(rel, "Demo-App-1.2.3.ipa", b"other bytes")
        code, _, err = self.run_alt("publish", self.ipa())
        self.assertEqual(code, 3)
        self.assertIn("conflict", err)
        self.assertEqual(self.writes(), [])

    def test_semver_option_and_existing_draft_reuse(self):
        path = self.ipa(short_version="2.0")
        code, out, err = self.run_alt("publish", path, "--semver", "2.0.0-beta.1", "--defer")
        self.assertEqual(code, 0, err)
        self.assertIn("tag=io.example.demo-v2.0.0-beta.1\n", out)
        self.assertEqual(self.run_alt("publish", path, "--semver", "2.0.0-beta.1")[0], 0)
        (rel,) = self.stage_gh.releases.values()
        self.assertTrue(rel["prerelease"])
        self.assertEqual(len(rel["assets"]), 1)

    def test_publishing_a_withdrawn_version_only_warns(self):
        self.set_rules(retracted_rule(WITHDRAWN))
        code, out, err = self.run_alt("publish", self.ipa())
        self.assertEqual(code, 0, err)
        self.assertIn("version 1.2.3 of %s was withdrawn (deleted, 2026-10-22T07:13:00Z); publishing it again" % BID,
                      err)
        self.assertEqual(self.writes(), [["workflow", "run", "stage.yml", "-R", "xuniv/alt", "-f", "tag=" + TAG]])
        self.assertIn(["api", RETRACTED_PATH], self.argvs())
        code, _, err = self.run_alt("publish", self.ipa(short_version="1.2.4"), "--semver", "1.2.4", "--defer")
        self.assertEqual((code, err), (0, ""))

    def test_deferring_a_withdrawn_version_says_it_needs_staging_by_tag(self):
        # scheduled stage runs skip drafts of withdrawn versions, so the schedule would never publish it
        self.set_rules(retracted_rule(WITHDRAWN))
        code, out, err = self.run_alt("publish", self.ipa(), "--defer")
        self.assertEqual(code, 0, err)
        self.assertTrue(list(self.stage_gh.releases.values())[0]["draft"])
        self.assertEqual(self.writes(), [])
        self.assertIn("version 1.2.3 of %s was withdrawn (deleted, 2026-10-22T07:13:00Z, see apps/%s/retracted.json); "
                      "scheduled stage runs skip its drafts" % (BID, BID), err)
        self.assertNotIn("waits for the next scheduled stage run", out)
        self.assertIn("draft %s stays a draft until it is staged by tag: gh workflow run stage.yml -R xuniv/alt "
                      "-f tag=%s\n" % (TAG, TAG), out)

    def test_deferring_a_version_still_listed_without_a_release_says_it_needs_staging_by_tag(self):
        # the listed release was deleted, and the catalog run has not listed the version as withdrawn yet
        self.set_rules(record_rule())
        code, out, err = self.run_alt("publish", self.ipa(), "--defer")
        self.assertEqual(code, 0, err)
        self.assertIn("version 1.2.3 of %s is still listed on main, but no published release uses its tag: the "
                      "next catalog run lists it in apps/%s/retracted.json as withdrawn" % (BID, BID), err)
        self.assertIn("draft %s stays a draft until it is staged by tag" % TAG, out)
        self.assertEqual(self.writes(), [])
        # without --defer, stage.yml publishes it right away: the record is not even looked up
        self.run_alt("publish", self.ipa())
        self.assertEqual(self.writes(), [["workflow", "run", "stage.yml", "-R", "xuniv/alt", "-f", "tag=" + TAG]])
        self.assertEqual(len([a for a in self.argvs() if a[-1].endswith("/versions/1.2.3.json?ref=main")]), 1)

    def test_local_argument_checks_come_before_gh(self):
        missing = os.path.join(self.dir, "missing.ipa")
        for argv in (("publish", missing), ("publish", self.ipa(), "--semver", "1.2"),
                     ("publish", self.ipa(), "--notes-file", missing)):
            self.assertEqual(self.run_alt(*argv)[0], 1, argv)
        self.assertEqual(self.calls(), [])


class MirrorTests(OperatorCase):
    def release_rule(self, *names, body="private notes mentioning leaky-host-0"):
        return {"match": ["api", "repos/%s/releases/tags/v1.2.3" % PRIVATE],
                "stdout": {"tag_name": "v1.2.3", "body": body,
                           "assets": [{"name": n, "state": "uploaded"} for n in names]}}

    def download_rule(self, **fields):
        return {"match": ["release", "download"], "files": {"Demo.ipa": ipa_bytes(**fields).decode("utf-8")}}

    def download_dir(self):
        argv = self.call("release", "download")["argv"]
        return argv[argv.index("--dir") + 1]

    def test_mirror_downloads_only_the_ipa_and_never_the_notes(self):
        self.set_rules(self.release_rule("Demo.ipa", "Demo-dSYMs.zip"), self.download_rule())
        code, out, err = self.run_alt("mirror", PRIVATE, "v1.2.3")
        self.assertEqual(code, 0, err)
        argv = self.call("release", "download")["argv"]
        self.assertEqual(argv[:5], ["release", "download", "v1.2.3", "-R", PRIVATE])
        self.assertEqual(argv[argv.index("--pattern") + 1], "*.ipa")
        self.assertFalse(os.path.exists(self.download_dir()))
        (rel,) = self.stage_gh.releases.values()
        self.assertEqual((rel["tag_name"], rel["body"]), (TAG, ""))
        self.assertEqual(self.writes(), [["workflow", "run", "stage.yml", "-R", "xuniv/alt", "-f", "tag=" + TAG]])
        self.assertNotIn("leaky", out + err)

    def test_mirror_takes_notes_from_a_file_and_defers(self):
        self.set_rules(self.release_rule("Demo.ipa"), self.download_rule())
        notes = self.write(os.path.join(self.dir, "notes.md"), "Public notes\n")
        code, _, _ = self.run_alt("mirror", PRIVATE, "v1.2.3", "--notes-file", notes, "--defer")
        self.assertEqual(code, 0)
        self.assertEqual(list(self.stage_gh.releases.values())[0]["body"], "Public notes")
        self.assertEqual(self.writes(), [])

    def test_mirror_defer_of_a_withdrawn_version_says_it_needs_staging_by_tag(self):
        self.set_rules(retracted_rule(WITHDRAWN), self.release_rule("Demo.ipa"), self.download_rule())
        code, out, err = self.run_alt("mirror", PRIVATE, "v1.2.3", "--defer")
        self.assertEqual(code, 0, err)
        self.assertIn("scheduled stage runs skip its drafts", err)
        self.assertIn("draft %s stays a draft until it is staged by tag" % TAG, out)
        self.assertEqual(self.writes(), [])

    def test_mirror_needs_exactly_one_ipa(self):
        for names in ((), ("A.ipa", "B.ipa"), ("A.zip",)):
            self.set_rules(self.release_rule(*names), self.download_rule())
            code, _, err = self.run_alt("mirror", PRIVATE, "v1.2.3")
            self.assertEqual(code, 1, names)
            self.assertIn("exactly one *.ipa", err)
        self.assertEqual([a for a in self.argvs() if a[:2] == ["release", "download"]], [])

    def test_rejected_mirror_cleans_up(self):
        self.set_rules(self.release_rule("Demo.ipa"), self.download_rule(payload="leaky-host-0"))
        code, _, _ = self.run_alt("mirror", PRIVATE, "v1.2.3")
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.download_dir()))
        self.assertEqual(self.stage_gh.mutations(), [])

    def test_mirroring_a_withdrawn_version_only_warns(self):
        self.set_rules(self.release_rule("Demo.ipa"), self.download_rule(), retracted_rule(WITHDRAWN))
        code, _, err = self.run_alt("mirror", PRIVATE, "v1.2.3")
        self.assertEqual(code, 0, err)
        self.assertIn("was withdrawn", err)
        self.assertEqual(self.writes(), [["workflow", "run", "stage.yml", "-R", "xuniv/alt", "-f", "tag=" + TAG]])

    def test_mirror_validates_arguments(self):
        for argv in (("mirror", "no-slash", "v1"), ("mirror", PRIVATE, "--x"), ("mirror", PRIVATE, "a..b"),
                     ("mirror", "a/b c", "v1")):
            self.assertEqual(self.run_alt(*argv)[0], 1, argv)
        self.assertEqual(self.calls(), [])


class BuildTests(OperatorCase):
    def test_build_dispatches_build_yml(self):
        self.app_json({"privateBuild": {"enabled": True}})
        code, out, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["workflow", "run", "build.yml", "-R", "xuniv/alt", "-f", "app=" + BID,
                                          "-f", "ref=v1.2.3", "-f", "publish=true"]])
        self.assertEqual(err, "")
        self.assertIn("dispatched build.yml", out)

    def test_no_publish_and_missing_private_build_warning(self):
        code, _, err = self.run_alt("build", BID, "release/2.0.0", "--no-publish")
        self.assertEqual(code, 0)
        self.assertEqual(self.writes()[0][-1], "publish=false")
        self.assertIn("does not enable privateBuild", err)

    def test_dry_run_prints_the_dispatch(self):
        code, out, _ = self.run_alt("--dry-run", "build", BID, "v1.2.3")
        self.assertEqual(code, 0)
        self.assertIn("+ gh workflow run build.yml -R xuniv/alt -f app=%s -f ref=v1.2.3 -f publish=true\n" % BID,
                      out)
        self.assertEqual(self.writes(), [])

    def test_invalid_bundle_ids_and_refs(self):
        for bid, ref in (("io.example.app-v2", "v1"), ("-x", "v1"), ("a b", "v1"), ("a;b", "v1"),
                         (BID, "-f"), (BID, "v1..2"), (BID, "v1 2"), (BID, "v1.lock"), (BID, "v1/")):
            self.assertEqual(self.run_alt("build", bid, ref)[0], 1, (bid, ref))
        self.assertEqual(self.calls(), [])

    def test_inputs_follow_the_rules_of_build_yml(self):
        # build.yml refuses these inputs, but only after the run (and its public title) exists
        long_bid = "io.example." + "a" * 145
        for bid, ref in ((BID, "v1.2.3+5"), (BID, "v" + "1" * 128), (BID, ".v1"), (BID, "v1/.x"),
                         (BID, "v1//2"), (BID, "v1."), (long_bid, "v1.2.3")):
            code, _, err = self.run_alt("build", bid, ref)
            self.assertEqual(code, 1, (bid, ref))
            self.assertIn("invalid", err)
        self.assertEqual(self.calls(), [])
        self.assertEqual(len(long_bid), 156)
        self.assertEqual(self.run_alt("build", long_bid[:-1], "v" + "1" * 127)[0], 0)

    def test_run_title_is_gated_with_the_local_denylist(self):
        for ref in ("v1.2.3-LEAKY-HOST-0", "release/leakyuser0", "a/Users/devname1/v1"):
            code, out, err = self.run_alt("build", BID, ref)
            self.assertEqual(code, 2, ref)
            self.assertIn("gate rejected: run title", err)
            for word in ("leaky", "LEAKY", "devname1"):
                self.assertNotIn(word, out + err)
        self.assertEqual(self.calls(), [])  # refused before any gh call, also the read-only ones
        os.unlink(self.denylist)
        code, _, err = self.run_alt("build", BID, "v1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("local denylist not found", err)
        self.assertEqual(self.calls(), [])


class BuildWithdrawnTests(OperatorCase):
    DISPATCH = ["workflow", "run", "build.yml", "-R", "xuniv/alt", "-f", "app=" + BID, "-f", "ref=v1.2.3",
                "-f", "publish=true"]

    def setUp(self):
        super().setUp()
        self.app_json({"privateBuild": {"enabled": True}})

    def test_a_withdrawn_version_is_refused(self):
        self.set_rules(retracted_rule(WITHDRAWN))
        for argv in (("build", BID, "v1.2.3"), ("build", BID, "v1.2.3", "--no-publish"),
                     ("--dry-run", "build", BID, "v1.2.3")):
            code, out, err = self.run_alt(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("version 1.2.3 of %s was withdrawn (deleted, 2026-10-22T07:13:00Z" % BID, err)
            self.assertIn("pass --force", err)
            self.assertNotIn("build.yml", out)
        self.assertEqual(self.writes(), [])
        self.assertIn(["api", RETRACTED_PATH], self.argvs())

    def test_force_builds_it_and_says_so(self):
        self.set_rules(retracted_rule(WITHDRAWN))
        code, out, err = self.run_alt("build", BID, "v1.2.3", "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [self.DISPATCH + ["-f", "force=true"]])
        self.assertIn("building it because of --force", err)
        self.assertIn("force=true", out)
        code, out, _ = self.run_alt("--dry-run", "build", BID, "v1.2.3", "--force")
        self.assertEqual(code, 0)
        self.assertIn("-f publish=true -f force=true\n", out)

    def test_other_versions_build_normally(self):
        self.set_rules(retracted_rule(WITHDRAWN))
        code, _, err = self.run_alt("build", BID, "v1.2.4")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.writes()[0][-1], "publish=true")  # force is only sent when given
        code, _, err = self.run_alt("build", BID, "v1.2.4", "--force")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.writes()[1][-2:], ["-f", "force=true"])

    def test_the_version_comes_from_the_tag_pattern(self):
        pattern = r"^release-(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$"
        self.app_json({"privateBuild": {"enabled": True, "tagPattern": pattern}})
        self.set_rules(retracted_rule(WITHDRAWN))
        self.assertEqual(self.run_alt("build", BID, "release-1.2.3")[0], 1)
        code, _, err = self.run_alt("build", BID, "v1.2.3")  # build.yml refuses a ref outside the pattern
        self.assertEqual(code, 0)
        self.assertIn("does not match privateBuild.tagPattern", err)
        self.assertIn("withdrawn versions were not checked", err)

    def test_a_tombstone_that_cannot_be_read_only_warns(self):
        # build.yml checks again in its first job, which holds no secret
        bad = [{"match": ["api", RETRACTED_PATH], "code": 1, "stderr": "gh: Server Error (HTTP 502)\n"},
               {"match": ["api", RETRACTED_PATH], "stdout": "not json"},
               {"match": ["api", RETRACTED_PATH], "stdout": {"type": "file", "encoding": "base64",
                                                            "content": base64.b64encode(b"{").decode()}},
               {"match": ["api", RETRACTED_PATH], "stdout": {"type": "file", "encoding": "none", "content": ""}},
               {"match": ["api", RETRACTED_PATH], "stdout": {"type": "file", "encoding": "base64",
                "content": base64.b64encode(b'{"schemaVersion": 2, "versions": {}}').decode()}}]
        for rule in bad:
            self.set_rules(rule)
            code, _, err = self.run_alt("build", BID, "v1.2.3")
            self.assertEqual(code, 0, rule)
            self.assertIn("build.yml checks withdrawn versions again", err)
            self.assertEqual(self.writes()[-1], self.DISPATCH)


class IngestTests(OperatorCase):
    URL = "https://downloads.example.invalid/files/Demo.ipa?x=1"

    def test_ingest_sends_a_repository_dispatch_through_stdin(self):
        notes = self.write(os.path.join(self.dir, "notes.md"), "  Fixes\n")
        app = self.write(os.path.join(self.dir, "app.json"), json.dumps({"name": "Demo", "category": "utilities"}))
        code, out, err = self.run_alt("ingest", self.URL, "--sha256", "AB" * 32, "--semver", "1.0.0",
                                      "--notes-file", notes, "--app-json", app)
        self.assertEqual(code, 0, err)
        call = self.call("api", "--method", "POST")
        self.assertEqual(call["argv"], ["api", "--method", "POST", "repos/xuniv/alt/dispatches", "--input", "-"])
        body = json.loads(call["stdin"])
        self.assertEqual(body, {"event_type": "ingest", "client_payload": {
            "url": self.URL, "sha256": "ab" * 32, "semver": "1.0.0", "notes": "Fixes",
            "app": {"name": "Demo", "category": "utilities"}}})
        self.assertFalse(any(self.URL in " ".join(a) for a in self.argvs()))  # never in argv
        self.assertIn("dispatched ingest", out)

    def test_minimal_ingest_and_dry_run(self):
        code, out, _ = self.run_alt("ingest", self.URL, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("+ gh api --method POST repos/xuniv/alt/dispatches --input -", out)
        self.assertIn("client_payload: url", out)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.run_alt("ingest", self.URL)[0], 0)
        self.assertEqual(json.loads(self.call("api", "--method")["stdin"])["client_payload"], {"url": self.URL})

    def test_local_checks(self):
        for argv in (("ingest", "http://downloads.example.invalid/a.ipa"),
                     ("ingest", "https://user:pw@downloads.example.invalid/a.ipa"),
                     ("ingest", "https://downloads.example.invalid/a b.ipa"),
                     ("ingest", "ftp://downloads.example.invalid/a.ipa"),
                     ("ingest", "https:///a.ipa"),
                     ("ingest", self.URL, "--sha256", "abc"),
                     ("ingest", self.URL, "--semver", "v1")):
            self.assertEqual(self.run_alt(*argv)[0], 1, argv)
        self.assertEqual(self.calls(), [])

    def test_notes_longer_than_the_workflow_accepts_are_refused(self):
        notes = self.write(os.path.join(self.dir, "notes.md"), "x" * 4001)
        code, _, err = self.run_alt("ingest", self.URL, "--notes-file", notes)
        self.assertEqual(code, 1)
        self.assertIn("at most 4000 characters", err)
        self.assertEqual(self.writes(), [])

    def test_notes_and_app_json_are_gated(self):
        notes = self.write(os.path.join(self.dir, "notes.md"), "from leaky-host-0\n")
        code, out, err = self.run_alt("ingest", self.URL, "--notes-file", notes)
        self.assertEqual(code, 2)
        self.assertIn("denylist block 1", err)
        self.assertNotIn("leaky-host-0", out + err)
        bad = self.write(os.path.join(self.dir, "app.json"), json.dumps({"tintColor": "red"}))
        self.assertEqual(self.run_alt("ingest", self.URL, "--app-json", bad)[0], 2)
        leaky = self.write(os.path.join(self.dir, "app2.json"), json.dumps({"subtitle": "leakyuser0 tools"}))
        self.assertEqual(self.run_alt("ingest", self.URL, "--app-json", leaky)[0], 2)
        self.assertEqual(self.writes(), [])


class RetractTests(OperatorCase):
    LIST_PAGE = "repos/xuniv/alt/releases?per_page=100&page=%d"
    TAG_REF = "repos/xuniv/alt/git/ref/tags/" + TAG
    CATALOG = ["workflow", "run", "catalog.yml", "-R", "xuniv/alt", "--ref", "main"]

    @staticmethod
    def rel(rid, tag=TAG, draft=False, name=None, prerelease=False):
        return {"id": rid, "tag_name": tag, "name": name or tag, "draft": draft, "prerelease": prerelease}

    def listing(self, *releases, page=1):
        return {"match": ["api", self.LIST_PAGE % page], "stdout": list(releases)}

    def standard(self, *extra, tag_present=None):
        rules = list(extra) + [record_rule(), self.listing(self.rel(11), self.rel(12, "io.example.demo-v1.2.2"),
                                                           self.rel(13, "io.example.other-v9.0.0"))]
        if tag_present is not None:
            rules.append(dict({"match": ["api", self.TAG_REF]},
                              **({"stdout": {"ref": "refs/tags/" + TAG}} if tag_present else NOT_FOUND)))
        self.set_rules(*rules)

    def log_text(self):
        path = os.path.join(self.cache, "retract.log")
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_retract_deletes_the_release_and_runs_the_catalog(self):
        self.standard()
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "DELETE", "repos/xuniv/alt/releases/11"], self.CATALOG])
        self.assertIn("published release %s deleted" % TAG, out)
        self.assertIn("dispatched catalog.yml on main: sync removes 1.2.3 from source.json and lists it in "
                      "apps/%s/retracted.json" % BID, out)
        self.assertIn("source: https://xuniv.github.io/alt/source.json\n", out)
        self.assertIn("note: 1.2.3 was the newest listed version: clients that installed it are offered 1.2.2 "
                      "as an update", out)
        self.assertNotIn("has no record", err)
        self.assertNotIn(self.TAG_REF, [a[-1] for a in self.argvs()])  # the tag is kept by default
        self.assertRegex(self.log_text(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ %s deleted\n$" % TAG)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.cache, "retract.log")).st_mode), 0o600)

    def test_delete_tag_deletes_the_tag_after_the_release(self):
        self.standard(tag_present=True)
        code, out, err = self.run_alt("retract", BID, "1.2.3", "--delete-tag", "--reason", "crashes on start")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "DELETE", "repos/xuniv/alt/releases/11"],
                                         ["api", "--method", "DELETE", "repos/xuniv/alt/git/refs/tags/" + TAG],
                                         self.CATALOG])
        self.assertIn("tag %s deleted" % TAG, out)
        self.assertTrue(self.log_text().endswith(" %s deleted, tag deleted; reason: crashes on start\n" % TAG))
        for call in self.calls():  # the reason stays on this machine
            self.assertNotIn("crashes", json.dumps(call))

    def test_delete_tag_also_works_when_the_release_is_already_gone(self):
        self.set_rules(self.listing(self.rel(12, "io.example.demo-v1.2.2")),
                       {"match": ["api", self.TAG_REF], "stdout": {"ref": "refs/tags/" + TAG}})
        code, _, err = self.run_alt("retract", BID, "1.2.3", "--delete-tag")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "DELETE", "repos/xuniv/alt/git/refs/tags/" + TAG],
                                         self.CATALOG])
        self.standard(tag_present=False)
        code, out, _ = self.run_alt("retract", BID, "1.2.3", "--delete-tag")
        self.assertEqual(code, 0)
        self.assertIn("tag %s does not exist" % TAG, out)
        self.assertEqual(self.writes()[2:], [["api", "--method", "DELETE", "repos/xuniv/alt/releases/11"],
                                             self.CATALOG])

    def test_drafts_with_the_same_tag_are_deleted_too(self):
        # a leftover draft would otherwise be published again by a scheduled stage run
        self.set_rules(self.listing(self.rel(11), self.rel(14, draft=True), self.rel(15, draft=True,
                                                                                   name="[blocked] " + TAG)))
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertEqual([a[-1] for a in self.writes()[:-1]], ["repos/xuniv/alt/releases/%d" % i for i in (11, 14, 15)])
        self.assertIn("draft release %s deleted" % TAG, out)
        self.assertIn("note: no other listed version of %s remains, so the app leaves source.json" % BID, out)

    def test_unpublish_turns_the_release_into_a_draft(self):
        self.standard()
        code, out, err = self.run_alt("retract", BID, "1.2.3", "--unpublish")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "PATCH", "repos/xuniv/alt/releases/11", "--input", "-"],
                                         self.CATALOG])
        # the mark keeps scheduled stage runs away even when the catalog run that lists it fails
        self.assertEqual(json.loads(self.call("api", "--method", "PATCH")["stdin"]),
                         {"draft": True, "name": "[withdrawn] " + TAG, "tag_name": TAG})
        self.assertIn("release %s is a draft titled [withdrawn] %s now" % (TAG, TAG), out)
        self.assertIn("sync removes 1.2.3 from source.json and lists it in apps/%s/retracted.json" % BID, out)
        self.assertIn("to publish it again: gh workflow run stage.yml -R xuniv/alt -f tag=%s" % TAG, out)
        self.assertTrue(self.log_text().endswith(" %s unpublished\n" % TAG))

    def test_unpublishing_a_pending_draft_marks_it_withdrawn(self):
        # a draft that was never listed: sync writes no tombstone, so the mark is what keeps
        # scheduled stage runs from publishing it
        self.set_rules(self.listing(self.rel(11, draft=True)))
        code, out, err = self.run_alt("retract", BID, "1.2.3", "--unpublish")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "PATCH", "repos/xuniv/alt/releases/11", "--input", "-"],
                                         self.CATALOG])
        self.assertEqual(json.loads(self.call("api", "--method", "PATCH")["stdin"]),
                         {"draft": True, "name": "[withdrawn] " + TAG, "tag_name": TAG})
        self.assertIn("draft release %s is a draft titled [withdrawn] %s now" % (TAG, TAG), out)
        self.assertIn("dispatched catalog.yml on main\n", out)
        self.assertNotIn("lists it in", out)
        self.assertIn("main has no record of 1.2.3 (source.json does not list it), so sync adds no entry for it to "
                      "apps/%s/retracted.json" % BID, err)
        self.assertNotIn("note:", out)
        self.assertTrue(self.log_text().endswith(" %s draft marked withdrawn\n" % TAG))

    def test_unpublishing_a_marked_or_blocked_draft_changes_nothing_but_runs_the_catalog(self):
        for name, said in (("[withdrawn] " + TAG, "is already marked withdrawn"),
                           ("[blocked] " + TAG, "is marked blocked by the gate; scheduled stage runs skip it")):
            self.set_rules(self.listing(self.rel(11, draft=True, name=name)))
            code, out, err = self.run_alt("retract", BID, "1.2.3", "--unpublish")
            self.assertEqual(code, 0, err)
            self.assertIn("draft release %s %s" % (TAG, said), out)
            self.assertIn("release %s is already a draft" % TAG, out)
        self.assertEqual(self.writes(), [self.CATALOG, self.CATALOG])

    def test_a_version_already_withdrawn_is_named_as_such(self):
        self.set_rules(retracted_rule(WITHDRAWN), self.listing(self.rel(11, draft=True)))
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertIn("dispatched catalog.yml on main; 1.2.3 is already listed in apps/%s/retracted.json" % BID, out)
        self.assertNotIn("has no record", err)

    def test_an_unreadable_record_gives_a_conditional_message(self):
        self.standard({"match": ["api", "repos/xuniv/alt/contents/apps/%s/versions/1.2.3.json?ref=main" % BID],
                       "code": 1, "stderr": "gh: Server Error (HTTP 500)\n"})
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertIn("could not be read: gh: Server Error (HTTP 500)", err)
        self.assertIn("dispatched catalog.yml on main: if source.json listed 1.2.3, sync removes it and lists it in "
                      "apps/%s/retracted.json" % BID, out)
        self.assertNotIn("has no record", err)

    def test_deleting_a_version_that_was_never_listed_says_builders_are_not_kept_away(self):
        self.set_rules(self.listing(self.rel(11, draft=True, name="[blocked] " + TAG)))
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertIn("draft release %s deleted" % TAG, out)
        self.assertNotIn("lists it in", out)
        self.assertIn("poll.yml, build.yml and the pre-push hook are not kept from building it again", err)

    def test_the_note_follows_what_source_json_lists(self):
        # prereleases are listed only with includePrereleases, like in source.json
        releases = (self.rel(1, "io.example.demo-v1.2.0"), self.rel(2, "io.example.demo-v1.3.0"),
                    self.rel(3, "io.example.demo-v2.0.0-beta.1", prerelease=True),
                    self.rel(4, "io.example.demo-v1.4.0", prerelease=True))  # flagged by the release only

        def note(version, app):
            self.app_json(app)
            self.set_rules(self.listing(*releases))
            code, out, err = self.run_alt("retract", BID, version)
            self.assertEqual(code, 0, err)
            return [line for line in out.splitlines() if line.startswith("note:")]

        self.assertEqual(note("1.3.0", {"name": "Demo"}), [
            "note: 1.3.0 was the newest listed version: clients that installed it are offered 1.2.0 as an update. "
            "If users installed it, also publish a fixed higher version."])
        self.assertEqual(note("2.0.0-beta.1", {"name": "Demo"}), [])  # never listed
        self.assertEqual(note("1.4.0", {"name": "Demo", "includePrereleases": False}), [])
        self.assertEqual(note("1.3.0", {"name": "Demo", "includePrereleases": True}), [])
        self.assertEqual(len(note("2.0.0-beta.1", {"name": "Demo", "includePrereleases": True})), 1)
        self.assertEqual(note("1.3.0", {"name": "Demo", "hidden": True}), [])

    def test_a_higher_version_means_no_note(self):
        self.set_rules(self.listing(self.rel(11), self.rel(16, "io.example.demo-v1.10.0"),
                                    self.rel(17, "io.example.demo-v2.0.0", draft=True)))
        code, out, _ = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0)
        self.assertNotIn("note:", out)

    def test_the_listing_is_paged(self):
        others = [self.rel(100 + i, "io.example.other-v1.0.%d" % i) for i in range(100)]
        self.set_rules(self.listing(*others), self.listing(self.rel(11), page=2))
        code, _, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes()[0][-1], "repos/xuniv/alt/releases/11")
        self.assertEqual([a[-1] for a in self.argvs() if a[-1].startswith("repos/xuniv/alt/releases?")],
                         [self.LIST_PAGE % 1, self.LIST_PAGE % 2])

    def test_dry_run_prints_every_change(self):
        self.standard(tag_present=True)
        code, out, err = self.run_alt("retract", BID, "1.2.3", "--delete-tag", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [])
        self.assertIn("+ gh api --method DELETE repos/xuniv/alt/releases/11\n", out)
        self.assertIn("+ gh api --method DELETE repos/xuniv/alt/git/refs/tags/%s\n" % TAG, out)
        self.assertIn("+ gh workflow run catalog.yml -R xuniv/alt --ref main\n", out)
        self.assertNotIn("deleted", out.replace("--method DELETE", ""))
        code, out, _ = self.run_alt("--dry-run", "retract", BID, "1.2.3", "--unpublish")
        self.assertEqual(code, 0)
        self.assertIn("+ gh api --method PATCH repos/xuniv/alt/releases/11 --input -  # draft=true, name=[withdrawn] "
                      "%s, tag_name=%s\n" % (TAG, TAG), out)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.log_text(), "")

    def test_not_found(self):
        self.set_rules(self.listing(self.rel(12, "io.example.demo-v1.2.2")),
                       dict(NOT_FOUND, match=["api", self.TAG_REF]))
        for extra in ((), ("--unpublish",), ("--delete-tag",)):
            code, _, err = self.run_alt("retract", BID, "1.2.3", *extra)
            self.assertEqual(code, 1, extra)
            self.assertIn("no release uses tag %s" % TAG, err)
        self.assertEqual(self.writes(), [])

    def test_a_failed_change_stops_before_the_catalog_run(self):
        self.standard({"match": ["api", "--method", "DELETE"], "code": 1, "stderr": "gh: Forbidden (HTTP 403)\n"})
        code, _, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", err)
        self.assertNotIn(self.CATALOG, self.argvs())
        self.assertEqual(self.log_text(), "")
        self.standard({"match": ["api", self.TAG_REF], "code": 1, "stderr": "gh: Server Error (HTTP 500)\n"})
        self.assertEqual(self.run_alt("retract", BID, "1.2.3", "--delete-tag")[0], 1)
        self.assertEqual(self.writes(), [["api", "--method", "DELETE", "repos/xuniv/alt/releases/11"]])

    def test_arguments_are_checked_before_gh(self):
        for argv in (("retract", "io.example.app-v2", "1.2.3"), ("retract", "a b", "1.2.3"),
                     ("retract", BID, "v1.2.3"), ("retract", BID, "1.2"), ("retract", BID, "1.2.3+5"),
                     ("retract", BID, "01.2.3"), ("retract", BID, "1.2.3", "--unpublish", "--delete-tag"),
                     ("retract", BID, "1.2.3", "--reason", "two\nlines"), ("retract", BID, "1.2.3", "--reason", " "),
                     ("retract", BID, "1.2.3", "--reason", "x" * 201), ("retract", BID)):
            code, _, err = self.run_alt(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("alt: error:", err)
        self.assertEqual(self.calls(), [])

    def test_login_denylist_and_push_access_are_required(self):
        self.standard()
        os.unlink(self.denylist)
        self.assertEqual(self.run_alt("retract", BID, "1.2.3")[0], 1)
        self.assertEqual(self.calls(), [])
        self.write(self.denylist, "leaky-host-0\n")
        self.standard({"match": ["api", "user"], "stdout": "personal-account\n"})
        code, out, err = self.run_alt("retract", BID, "1.2.3")
        self.assertEqual(code, 1)
        self.assertNotIn("personal-account", out + err)
        self.standard({"match": ["api", "repos/xuniv/alt"], "stdout": {"full_name": "xuniv/alt",
                                                                        "permissions": {"push": False}}})
        self.assertEqual(self.run_alt("retract", BID, "1.2.3")[0], 1)
        self.assertEqual(self.writes(), [])

    def test_source_url_follows_the_repository(self):
        self.assertEqual(alt.source_url("xuniv/alt"), "https://xuniv.github.io/alt/source.json")
        self.assertEqual(alt.source_url("Example/site"), "https://example.github.io/site/source.json")
        self.assertEqual(alt.source_url("example/example.github.io"), "https://example.github.io/source.json")


class RegisterTests(OperatorCase):
    def setUp(self):
        super().setUp()
        self.build_json = self.write(os.path.join(self.dir, "build.json"),
                                     json.dumps({"runner": "xcode-27", "command": "make ipa", "env": {"SCHEME": "Demo"}}))

    def rules(self, keys=(), created=None, *extra):
        created = created if created is not None else {"id": 77, "title": "alt-build", "read_only": True}
        self.set_rules(*extra, {"match": ["api", "repos/%s/keys?per_page=100" % PRIVATE], "stdout": list(keys)},
                       {"match": ["api", "--method", "POST", "repos/%s/keys" % PRIVATE], "stdout": created},
                       {"match": ["api", POLICIES_PATH + "?per_page=100"],
                        "stdout": {"total_count": 0, "branch_policies": []}})

    def keygen(self):
        path = os.path.join(self.state, "ssh-keygen.json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def key_post(self):
        return ["api", "--method", "POST", "repos/%s/keys" % PRIVATE, "-f", "title=alt-build", "-F",
                "read_only=true", "-f", "key=" + PUBLIC_KEY]

    def test_register_creates_a_read_only_key_and_both_secrets(self):
        self.rules()
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID, "--build-json", self.build_json,
                                      "--tag-pattern", r"^release-(?P<version>\d+\.\d+\.\d+)$")
        self.assertEqual(code, 0, err)
        info = self.keygen()
        self.assertEqual(info["args"], ["-q", "-t", "ed25519", "-N", "", "-C", "", "-f",
                                        os.path.join(info["dir"], "key")])
        self.assertEqual((info["umask"], info["dir_mode"]), (0o077, 0o700))
        self.assertFalse(os.path.exists(info["dir"]))
        self.assertEqual(self.writes(), [
            ["api", "--method", "PUT", ENV_PATH, "--input", "-"],
            ["api", "--method", "POST", POLICIES_PATH, "-f", "name=main", "-f", "type=branch"],
            self.key_post(),
            ["secret", "set", "ALT_KEY", "--env", ENV, "-R", "xuniv/alt"],
            ["secret", "set", "ALT_APP", "--env", ENV, "-R", "xuniv/alt"],
        ])
        self.assertEqual(json.loads(self.call("api", "--method", "PUT")["stdin"]), {
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}})
        self.assertEqual(self.call("secret", "set", "ALT_KEY")["stdin"], PRIVATE_KEY)
        config = json.loads(self.call("secret", "set", "ALT_APP")["stdin"])
        self.assertEqual(config, {"repo": PRIVATE, "build": {"runner": "xcode-27", "command": "make ipa",
                                                             "env": {"SCHEME": "Demo"}}})
        self.assertEqual(self.read_app_json(), {"privateBuild": {
            "enabled": True, "tagPattern": r"^release-(?P<version>\d+\.\d+\.\d+)$"}})
        self.assertIn("commit", out)
        for text in ("PRIVATE KEY", "placeholder-private-material", "make ipa"):
            self.assertNotIn(text, out + err)

    def test_secret_value_never_appears_in_arguments(self):
        self.rules()
        self.assertEqual(self.run_alt("register", PRIVATE, "--bid", BID)[0], 0)
        for argv in self.argvs():
            self.assertFalse(any("placeholder-private-material" in a or PRIVATE in a for a in argv
                                 if argv[:2] == ["secret", "set"]))
        self.assertEqual(json.loads(self.call("secret", "set", "ALT_APP")["stdin"]), {"repo": PRIVATE})

    def test_existing_environment_policy_is_kept_and_old_secrets_are_removed(self):
        self.rules((), None, {"match": ["api", POLICIES_PATH + "?per_page=100"],
                              "stdout": {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}},
                   {"match": ["secret", "list"], "stdout": [{"name": "ALT_DENYLIST"}, {"name": "ALT_KEY_" + ALIAS},
                                                            {"name": "ALT_APP_" + ALIAS},
                                                            {"name": "ALT_KEY_IO_EXAMPLE_OTHER"}]})
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 0, err)
        writes = self.writes()
        self.assertNotIn(["api", "--method", "POST", POLICIES_PATH, "-f", "name=main", "-f", "type=branch"], writes)
        self.assertEqual(writes[-2:], [["secret", "delete", "ALT_KEY_" + ALIAS, "-R", "xuniv/alt"],
                                       ["secret", "delete", "ALT_APP_" + ALIAS, "-R", "xuniv/alt"]])
        self.assertIn("old repository secret ALT_APP_%s deleted" % ALIAS, out)

    def test_other_deployment_policies_are_removed(self):
        listing = {"match": ["api", POLICIES_PATH + "?per_page=100"], "stdout": {"total_count": 3, "branch_policies": [
            {"id": 1, "name": "*", "type": "branch"}, {"id": 2, "name": "v*", "type": "tag"},
            {"id": 3, "name": "main", "type": "branch"}]}}
        self.rules((), None, listing)
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 0, err)
        policy_writes = [w for w in self.writes() if any(POLICIES_PATH in a for a in w)]
        self.assertEqual(policy_writes, [["api", "--method", "DELETE", POLICIES_PATH + "/1"],
                                         ["api", "--method", "DELETE", POLICIES_PATH + "/2"]])
        self.assertIn("deployment tag policy v* removed from environment %s" % ENV, out)
        self.assertIn("environment %s allows deployments from main only" % ENV, out)

    def test_a_wildcard_policy_is_replaced_by_main(self):
        self.rules((), None, {"match": ["api", POLICIES_PATH + "?per_page=100"],
                              "stdout": {"total_count": 1, "branch_policies": [{"id": 9, "name": "*", "type": "branch"}]}})
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes()[:3], [
            ["api", "--method", "PUT", ENV_PATH, "--input", "-"],
            ["api", "--method", "DELETE", POLICIES_PATH + "/9"],
            ["api", "--method", "POST", POLICIES_PATH, "-f", "name=main", "-f", "type=branch"]])

    def test_dry_run_prints_the_policy_changes(self):
        self.rules((), None, {"match": ["api", ENV_PATH], "stdout": {"name": ENV}},
                   {"match": ["api", POLICIES_PATH + "?per_page=100"],
                    "stdout": {"total_count": 1, "branch_policies": [{"id": 9, "name": "*", "type": "branch"}]}})
        code, out, err = self.run_alt("--dry-run", "register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 0, err)
        self.assertIn("+ gh api --method DELETE %s/9\n" % POLICIES_PATH, out)
        self.assertIn("+ gh api --method POST %s -f name=main -f type=branch\n" % POLICIES_PATH, out)
        self.assertEqual(self.writes(), [])

    def test_unverifiable_policies_stop_the_registration(self):
        for listing in ({"total_count": 101, "branch_policies": [{"id": 1, "name": "main", "type": "branch"}]},
                        {"total_count": 1, "branch_policies": [{"name": "*", "type": "branch"}]},
                        {"message": "unexpected"}):
            self.rules((), None, {"match": ["api", POLICIES_PATH + "?per_page=100"], "stdout": listing})
            code, _, err = self.run_alt("register", PRIVATE, "--bid", BID)
            self.assertEqual(code, 1, listing)
            self.assertIn("environment %s" % ENV, err)
        self.assertFalse(any(a[:2] == ["secret", "set"] for a in self.argvs()))
        self.assertFalse(any("repos/%s/keys" % PRIVATE in a for w in self.writes() for a in w))

    def test_existing_key_needs_rotate(self):
        self.rules(keys=[{"id": 5, "title": "alt-build"}])
        code, _, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 1)
        self.assertIn("--rotate", err)
        self.assertIsNone(self.keygen())
        self.assertEqual(self.writes(), [])

    def test_rotate_deletes_the_old_key_first(self):
        self.rules(keys=[{"id": 5, "title": "alt-build"}, {"id": 6, "title": "unrelated"}])
        code, _, err = self.run_alt("register", PRIVATE, "--bid", BID, "--rotate")
        self.assertEqual(code, 0, err)
        writes = self.writes()
        delete = writes.index(["api", "--method", "DELETE", "repos/%s/keys/5" % PRIVATE])
        self.assertEqual(writes[delete + 1], self.key_post())
        self.assertNotIn(["api", "--method", "DELETE", "repos/%s/keys/6" % PRIVATE], writes)

    def test_failure_removes_the_key_material_and_the_new_deploy_key(self):
        self.rules((), None, {"match": ["secret", "set", "ALT_APP"], "code": 1,
                              "stderr": "HTTP 403: Resource not accessible\n"})
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.keygen()["dir"]))
        self.assertEqual(self.writes()[-1], ["api", "--method", "DELETE", "repos/%s/keys/77" % PRIVATE])
        self.assertFalse(os.path.exists(os.path.join(self.root, "apps", BID, "app.json")))
        self.assertNotIn("placeholder-private-material", out + err)

    def test_keygen_failure_still_cleans_up(self):
        self.rules()
        self.script("ssh-keygen", FAKE_SSH_KEYGEN + "\nsys.exit(1)\n")
        code, _, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 1)
        self.assertIn("ssh-keygen failed", err)
        self.assertFalse(os.path.exists(self.keygen()["dir"]))
        self.assertEqual([w for w in self.writes() if "environments" not in " ".join(w)], [])

    def test_unconfirmed_read_only_key_is_removed(self):
        self.rules(created={"id": 77, "title": "alt-build", "read_only": False})
        code, _, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 1)
        self.assertIn("read-only", err)
        self.assertEqual(self.writes()[-1], ["api", "--method", "DELETE", "repos/%s/keys/77" % PRIVATE])
        self.assertFalse(any(a[:2] == ["secret", "set"] for a in self.argvs()))

    def test_dry_run_creates_nothing(self):
        self.rules(keys=[{"id": 5, "title": "alt-build"}])
        code, out, err = self.run_alt("register", PRIVATE, "--bid", BID, "--rotate", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIsNone(self.keygen())
        self.assertEqual(self.writes(), [])
        self.assertIn("+ gh api --method DELETE repos/%s/keys/5\n" % PRIVATE, out)
        self.assertIn("+ gh api --method POST repos/%s/keys -f title=alt-build -F read_only=true -f key=<public key>"
                      % PRIVATE, out)
        self.assertIn("+ gh api --method PUT %s --input -\n" % ENV_PATH, out)
        self.assertIn("+ gh api --method POST %s -f name=main -f type=branch\n" % POLICIES_PATH, out)
        self.assertIn("+ gh secret set ALT_KEY --env %s -R xuniv/alt < <private key>\n" % ENV, out)
        self.assertFalse(os.path.exists(os.path.join(self.root, "apps", BID)))

    def test_existing_app_json_is_kept(self):
        self.rules()
        self.app_json({"name": "Demo", "privateBuild": {"enabled": False, "windowed": True}})
        self.assertEqual(self.run_alt("register", PRIVATE, "--bid", BID)[0], 0)
        self.assertEqual(self.read_app_json(), {"name": "Demo", "privateBuild": {"enabled": True, "windowed": True}})
        self.assertIn("already enables", self.run_alt("register", PRIVATE, "--bid", BID, "--rotate")[1])

    def test_inputs_are_validated_before_gh(self):
        def build(obj):
            return self.write(os.path.join(self.dir, "b.json"), json.dumps(obj))

        cases = [
            ("register", "no-slash", "--bid", BID),
            ("register", PRIVATE, "--bid", "io.example.app-v2"),
            ("register", PRIVATE, "--bid", BID, "--tag-pattern", r"^v(\d+)$"),
            ("register", PRIVATE, "--bid", BID, "--tag-pattern", "(unclosed"),
            ("register", PRIVATE, "--bid", BID, "--build-json", build({"unknown": 1})),
            ("register", PRIVATE, "--bid", BID, "--build-json", build({"runner": "ubuntu-latest"})),
            ("register", PRIVATE, "--bid", BID, "--build-json", build({"env": {"PATH": "/bin"}})),
            ("register", PRIVATE, "--bid", BID, "--build-json", build({"ipa_glob": "../x.ipa"})),
            ("register", PRIVATE, "--bid", BID, "--build-json", build(["not", "an", "object"])),
            ("register", PRIVATE, "--bid", BID, "--build-json", os.path.join(self.dir, "missing.json")),
        ]
        for argv in cases:
            self.assertEqual(self.run_alt(*argv)[0], 1, argv)
        self.app_json({"privateBuild": "yes"})
        self.assertEqual(self.run_alt("register", PRIVATE, "--bid", BID)[0], 1)
        self.assertEqual(self.calls(), [])

    @unittest.skipUnless(shutil.which("ssh-keygen", path="/usr/bin:/bin:/usr/local/bin"), "needs ssh-keygen")
    def test_with_the_real_ssh_keygen(self):
        os.unlink(os.path.join(self.bin, "ssh-keygen"))
        self.rules()
        scratch = self.mkdir("tmp")
        with mock.patch.object(tempfile, "tempdir", scratch):
            code, out, err = self.run_alt("register", PRIVATE, "--bid", BID)
        self.assertEqual(code, 0, err)
        key_arg = [w for w in self.writes() if w[3:4] == ["repos/%s/keys" % PRIVATE]][0][-1]
        self.assertRegex(key_arg, r"^key=ssh-ed25519 [A-Za-z0-9+/]+=*$")  # no comment
        secret = self.call("secret", "set", "ALT_KEY")["stdin"]
        self.assertTrue(secret.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertEqual(os.listdir(scratch), [])
        self.assertNotIn("PRIVATE KEY", out + err)


class UnregisterTests(OperatorCase):
    def test_unregister_removes_key_environment_and_old_secrets(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.set_rules({"match": ["api", "repos/%s/keys?per_page=100" % PRIVATE],
                        "stdout": [{"id": 5, "title": "alt-build"}, {"id": 6, "title": "unrelated"}]},
                       {"match": ["api", ENV_PATH], "stdout": {"name": ENV}},
                       {"match": ["secret", "list"], "stdout": [{"name": "ALT_KEY_" + ALIAS}, {"name": "ALT_DENYLIST"}]})
        code, out, err = self.run_alt("unregister", BID, PRIVATE)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["api", "--method", "DELETE", "repos/%s/keys/5" % PRIVATE],
                                         ["api", "--method", "DELETE", ENV_PATH],
                                         ["secret", "delete", "ALT_KEY_" + ALIAS, "-R", "xuniv/alt"]])
        self.assertIn("environment %s deleted with its secrets" % ENV, out)
        self.assertIn("still enables privateBuild", out)

    def test_unregister_is_idempotent_and_reports_failures(self):
        self.set_rules({"match": ["secret", "list"], "stdout": []},
                       {"match": ["api", ENV_PATH], "code": 1, "stderr": "HTTP 404: Not Found\n"},
                       {"match": ["api", "repos/%s/keys?per_page=100" % PRIVATE], "stdout": []})
        code, out, _ = self.run_alt("unregister", BID, PRIVATE)
        self.assertEqual((code, self.writes()), (0, []))
        self.assertIn("no deploy key", out)
        self.assertIn("environment %s does not exist" % ENV, out)
        self.set_rules({"match": ["secret", "list"], "stdout": [{"name": "ALT_APP_" + ALIAS}]},
                       {"match": ["api", "--method", "DELETE", ENV_PATH], "code": 1, "stderr": "HTTP 500\n"},
                       {"match": ["api", ENV_PATH], "stdout": {"name": ENV}},
                       {"match": ["api", "repos/%s/keys?per_page=100" % PRIVATE], "code": 1,
                        "stderr": "HTTP 404: Not Found\n"})
        code, _, err = self.run_alt("unregister", BID, PRIVATE)
        self.assertEqual(code, 1)
        self.assertIn(["secret", "delete", "ALT_APP_" + ALIAS, "-R", "xuniv/alt"], self.writes())


class PayloadKeyTests(OperatorCase):
    def test_creates_the_identity_secret_and_the_recipient_variable(self):
        code, out, err = self.run_alt("payload-key")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [["secret", "set", "ALT_PAYLOAD_IDENTITY", "-R", "xuniv/alt"],
                                         ["variable", "set", "ALT_PAYLOAD_RECIPIENT", "-R", "xuniv/alt",
                                          "--body", AGE_RECIPIENT]])
        # only the key line: the creation time (with its UTC offset) and the comments stay local
        self.assertEqual(self.call("secret", "set", "ALT_PAYLOAD_IDENTITY")["stdin"], AGE_IDENTITY + "\n")
        with open(os.path.join(self.state, "age-keygen.json"), encoding="utf-8") as fh:
            info = json.load(fh)
        self.assertEqual(info["umask"], 0o077)
        self.assertFalse(os.path.exists(info["dir"]))
        self.assertNotIn("AGE-SECRET-KEY", out + err)

    def test_an_existing_key_needs_rotate(self):
        self.set_rules({"match": ["variable", "list"], "stdout": [{"name": "ALT_PAYLOAD_RECIPIENT"}]})
        code, _, err = self.run_alt("payload-key")
        self.assertEqual(code, 1)
        self.assertIn("--rotate", err)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.run_alt("payload-key", "--rotate")[0], 0)
        self.assertEqual(len(self.writes()), 2)

    def test_dry_run_creates_nothing(self):
        code, out, err = self.run_alt("payload-key", "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.writes(), [])
        self.assertIn("+ gh secret set ALT_PAYLOAD_IDENTITY -R xuniv/alt < <age identity>\n", out)
        self.assertFalse(os.path.exists(os.path.join(self.state, "age-keygen.json")))

    def test_a_failed_variable_update_says_how_to_recover(self):
        self.set_rules({"match": ["variable", "set"], "code": 1, "stderr": "HTTP 403\n"})
        code, _, err = self.run_alt("payload-key")
        self.assertEqual(code, 1)
        self.assertIn("run alt payload-key --rotate again", err)


@unittest.skipUnless(shutil.which("git"), "needs git")
class HookTests(OperatorCase):
    def setUp(self):
        super().setUp()
        gitconfig = self.write(os.path.join(self.dir, "gitconfig"), "")
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=gitconfig, GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid",
                        ALT_HOOK_INTERVAL="1")
        self.remote = os.path.join(self.dir, "remote.git")
        self.work = self.mkdir("work")
        self.git("init", "-q", "--bare", self.remote, cwd=self.dir)
        self.git("init", "-q")
        self.git("remote", "add", "origin", self.remote)
        self.write(os.path.join(self.work, "README"), "x\n")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "initial")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.hooks = os.path.join(self.work, ".git", "hooks")
        self.hook = os.path.join(self.hooks, "pre-push")
        self.chained = os.path.join(self.hooks, "pre-push.alt-chained")
        self.log = os.path.join(self.cache, "hook.log")

    def git(self, *args, cwd=None):
        proc = subprocess.run(["git"] + list(args), cwd=cwd or self.work, env=self.env, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.decode()

    def install(self, *extra):
        return self.run_alt("hook", "install", self.work, "--bid", BID, *extra)

    def run_hook(self, lines, env=None, hook=None):
        start = time.monotonic()
        proc = subprocess.run(["sh", hook or self.hook, "origin", self.remote], cwd=self.work,
                              input="".join(line + "\n" for line in lines).encode(), capture_output=True,
                              env=self.env if env is None else env)
        return proc, time.monotonic() - start

    def wait_for(self, predicate, timeout=30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.1)
        return False

    def log_text(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log, encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def builds(self):
        return [a for a in self.argvs() if a[:3] == ["workflow", "run", "build.yml"]]

    def read(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_install_renders_the_template_and_is_idempotent(self):
        code, out, err = self.install()
        self.assertEqual(code, 0, err)
        text = self.read(self.hook)
        self.assertEqual(stat.S_IMODE(os.stat(self.hook).st_mode), 0o755)
        self.assertIn("alt-pre-push-hook", text.splitlines()[1])
        self.assertIn("\nALT_BIN=%s\n" % shlex.quote(os.path.realpath(ALT)), text)
        self.assertIn("\nALT_BID=%s\n" % BID, text)
        self.assertIn("\nALT_TAG_GLOB='v*'\n", text)
        self.assertNotIn("@ALT_", text)
        self.assertEqual(subprocess.run(["sh", "-n", self.hook]).returncode, 0)
        code, out, _ = self.install()
        self.assertEqual(code, 0)
        self.assertIn("already installed", out)
        self.assertEqual(self.read(self.hook), text)
        self.assertFalse(os.path.exists(self.chained))
        self.assertEqual(self.install("--tag-glob", "release-*")[0], 0)
        self.assertIn("\nALT_TAG_GLOB='release-*'\n", self.read(self.hook))
        self.assertFalse(os.path.exists(self.chained))
        self.assertEqual(self.writes(), [])

    def test_existing_hook_is_chained_and_restored(self):
        original = "#!/bin/sh\nexit 0\n"
        self.write(self.hook, original, 0o755)
        code, out, _ = self.install()
        self.assertEqual(code, 0)
        self.assertIn("chained", out)
        self.assertEqual(self.read(self.chained), original)
        self.assertEqual(self.install()[0], 0)  # re-install keeps the chained hook
        self.assertEqual(self.read(self.chained), original)
        code, out, _ = self.run_alt("hook", "uninstall", self.work)
        self.assertEqual(code, 0)
        self.assertEqual(self.read(self.hook), original)
        self.assertFalse(os.path.exists(self.chained))
        code, out, _ = self.run_alt("hook", "uninstall", self.work)
        self.assertEqual(code, 0)
        self.assertIn("not installed", out)
        self.assertEqual(self.read(self.hook), original)

    def test_uninstall_without_a_chained_hook(self):
        self.install()
        self.assertEqual(self.run_alt("hook", "uninstall", self.work)[0], 0)
        self.assertFalse(os.path.lexists(self.hook))
        self.assertEqual(self.run_alt("hook", "uninstall", self.work)[0], 0)

    def test_install_refusals(self):
        self.write(self.hook, "#!/bin/sh\nexit 0\n", 0o755)
        self.write(self.chained, "#!/bin/sh\nexit 0\n", 0o755)
        code, _, err = self.install()
        self.assertEqual(code, 1)
        self.assertIn("by hand", err)
        os.unlink(self.chained)
        self.git("config", "core.hooksPath", os.path.join(self.dir, "shared-hooks"))
        self.assertEqual(self.install()[0], 1)
        self.git("config", "--unset", "core.hooksPath")
        self.assertEqual(self.run_alt("hook", "install", self.mkdir("plain"), "--bid", BID)[0], 1)
        for glob in ("v*'; touch x; '", "v* x", "$(x)", ""):
            self.assertEqual(self.install("--tag-glob", glob)[0], 1, glob)
        self.assertEqual(self.run_alt("hook", "install", self.work, "--bid", "a'b")[0], 1)
        self.assertEqual(self.read(self.hook), "#!/bin/sh\nexit 0\n")

    def test_install_applies_the_build_rules_to_the_bundle_identifier(self):
        code, out, err = self.run_alt("hook", "install", self.work, "--bid", "io.leaky-host-0.demo")
        self.assertEqual(code, 2)
        self.assertIn("gate rejected: bundle identifier", err)
        self.assertNotIn("leaky", out + err)
        self.assertEqual(self.run_alt("hook", "install", self.work, "--bid", "io.example." + "a" * 145)[0], 1)
        self.assertFalse(os.path.lexists(self.hook))

    def test_tags_that_build_yml_refuses_start_no_build(self):
        self.install()
        tags = ["v1.2.3+5", "v" + "1" * 128, "v1..2", "v1/.x", "v1.", "v1.lock", "v1//2", "v1\\2", "v1$x"]
        lines = ["refs/tags/%s %s refs/tags/%s %s" % (t, self.sha, t, ZERO) for t in tags]
        proc, _ = self.run_hook(lines, env=dict(self.env, ALT_HOOK_TIMEOUT="0"))
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))
        self.assertEqual(self.log_text().count("not a valid build ref; no build started"), len(tags))
        self.assertNotIn("pushed", self.log_text())
        self.assertNotIn("not on the remote", self.log_text())
        self.assertEqual(self.builds(), [])

    def test_a_tag_with_a_denylist_term_starts_no_build(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.assertEqual(self.install()[0], 0)
        installed = len(self.argvs())
        self.git("tag", "v1.2.3-leaky-host-0")
        self.git("push", "-q", "origin", "v1.2.3-leaky-host-0")
        self.assertTrue(self.wait_for(lambda: "gate rejected: run title" in self.log_text()), self.log_text())
        self.assertEqual(self.argvs()[installed:], [])  # refused before gh was asked anything

    def test_install_needs_the_denylist_and_dry_run_writes_nothing(self):
        os.unlink(self.denylist)
        self.assertEqual(self.install()[0], 1)
        self.write(self.denylist, "leaky-host-0\n")
        code, out, _ = self.install("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("+ write ", out)
        self.assertFalse(os.path.lexists(self.hook))

    def test_pushing_a_matching_tag_starts_a_build(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.assertEqual(self.install()[0], 0)
        self.git("tag", "v1.2.3")
        start = time.monotonic()
        self.git("push", "-q", "origin", "v1.2.3")
        self.assertLess(time.monotonic() - start, 10)
        self.assertTrue(self.wait_for(lambda: self.builds() and "dispatched" in self.log_text()), self.log_text())
        self.assertEqual(self.builds(), [["workflow", "run", "build.yml", "-R", "xuniv/alt", "-f", "app=" + BID,
                                          "-f", "ref=v1.2.3", "-f", "publish=true"]])
        self.assertIn("tag v1.2.3 pushed; starting alt build", self.log_text())

    def test_pushing_a_tag_of_a_withdrawn_version_builds_nothing(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.set_rules(retracted_rule(WITHDRAWN))
        self.assertEqual(self.install()[0], 0)
        code = [line for line in self.read(self.hook).splitlines() if not line.lstrip().startswith("#")]
        self.assertFalse([line for line in code if "force" in line], code)
        self.git("tag", "v1.2.3")
        self.git("push", "-q", "origin", "v1.2.3")
        self.assertTrue(self.wait_for(lambda: "was withdrawn" in self.log_text()), self.log_text())
        self.assertIn("pass --force", self.log_text())
        self.assertEqual(self.builds(), [])
        self.git("tag", "v1.2.4")  # a new version builds as usual
        self.git("push", "-q", "origin", "v1.2.4")
        self.assertTrue(self.wait_for(lambda: self.builds() and "dispatched" in self.log_text()), self.log_text())
        self.assertEqual([a[-3] for a in self.builds()], ["ref=v1.2.4"])

    def test_pushing_an_annotated_tag_starts_a_build(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.assertEqual(self.install()[0], 0)
        self.git("tag", "-a", "-m", "release", "v1.2.4")
        self.git("push", "-q", "origin", "v1.2.4")
        self.assertTrue(self.wait_for(lambda: self.builds() and "dispatched" in self.log_text()), self.log_text())
        self.assertEqual([a[-3] for a in self.builds()], ["ref=v1.2.4"])

    def test_rejected_tag_push_starts_no_build(self):
        self.app_json({"privateBuild": {"enabled": True}})
        self.git("tag", "v1.0.0")
        self.git("push", "-q", "origin", "v1.0.0")  # already on the remote, before the hook exists
        self.assertEqual(self.install()[0], 0)
        self.write(os.path.join(self.work, "README"), "y\n")
        self.git("commit", "-q", "-am", "second")
        self.git("tag", "-f", "v1.0.0")
        env = dict(self.env, ALT_HOOK_TIMEOUT="2")
        proc = subprocess.run(["git", "push", "-q", "origin", "v1.0.0"], cwd=self.work, env=env,
                              capture_output=True)
        self.assertNotEqual(proc.returncode, 0)  # the remote already has the tag at another commit
        self.assertTrue(self.wait_for(lambda: "not on the remote" in self.log_text()), self.log_text())
        self.assertEqual(self.builds(), [])

    def test_hook_returns_at_once_and_gives_up_quietly(self):
        self.install()
        env = dict(self.env, ALT_HOOK_TIMEOUT="1")
        proc, elapsed = self.run_hook(["refs/tags/v9.0.0 %s refs/tags/v9.0.0 %s" % (self.sha, ZERO)], env=env)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))
        self.assertLess(elapsed, 5)
        self.assertTrue(self.wait_for(lambda: "not on the remote" in self.log_text()), self.log_text())
        self.assertEqual(self.builds(), [])

    def test_hook_ignores_branches_other_tags_and_deletions(self):
        self.install()
        lines = ["refs/heads/main %s refs/heads/main %s" % (self.sha, ZERO),
                 "refs/tags/release-1 %s refs/tags/release-1 %s" % (self.sha, ZERO),
                 "(delete) %s refs/tags/v1.0.0 %s" % (ZERO, self.sha),
                 "refs/tags/v2 %s refs/heads/v2 %s" % (self.sha, ZERO)]
        proc, _ = self.run_hook(lines)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))
        self.assertFalse(os.path.exists(self.cache))  # nothing was started
        proc, _ = self.run_hook([])
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(os.path.exists(self.cache))

    def test_chained_hook_runs_first_and_decides_the_push(self):
        record = os.path.join(self.dir, "chained.txt")
        self.write(self.hook, '#!/bin/sh\n{ echo "args: $*"; cat; } > %s\nexit "${CHAINED_STATUS:-0}"\n'
                   % shlex.quote(record), 0o755)
        self.install()
        line = "refs/tags/v3.0.0 %s refs/tags/v3.0.0 %s" % (self.sha, ZERO)
        proc, _ = self.run_hook([line], env=dict(self.env, CHAINED_STATUS="3", ALT_HOOK_TIMEOUT="0"))
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(self.read(record), "args: origin %s\n%s\n" % (self.remote, line))
        self.assertFalse(os.path.exists(self.cache))
        proc, _ = self.run_hook([line], env=dict(self.env, ALT_HOOK_TIMEOUT="0"))
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.wait_for(lambda: "not on the remote" in self.log_text()))

    def test_unrendered_template_does_nothing(self):
        line = "refs/tags/v1.0.0 %s refs/tags/v1.0.0 %s" % (self.sha, ZERO)
        proc, _ = self.run_hook([line], hook=HOOK_TEMPLATE)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, b"", b""))
        self.assertFalse(os.path.exists(self.cache))

    @unittest.skipUnless(os.path.exists("/bin/dash") or shutil.which("dash"), "needs dash")
    def test_template_is_posix_sh(self):
        dash = shutil.which("dash") or "/bin/dash"
        self.assertEqual(subprocess.run([dash, "-n", HOOK_TEMPLATE]).returncode, 0)


class StatusDiagDoctorTests(OperatorCase):
    def test_status_lists_runs_per_workflow(self):
        self.set_rules({"match": ["run", "list", "build.yml"], "stdout": [
                           {"databaseId": 11, "displayTitle": "build io.example.demo v1.2.3", "status": "completed",
                            "conclusion": "success", "createdAt": "2026-10-21T07:13:00Z", "event": "workflow_dispatch"}]},
                       {"match": ["run", "list", "ingest.yml"], "code": 1, "stderr": "workflow not found\n"},
                       {"match": ["run", "list"], "stdout": []})
        code, out, _ = self.run_alt("status", "--limit", "3")
        self.assertEqual(code, 1)  # one listing failed
        self.assertIn("build io.example.demo v1.2.3", out)
        self.assertIn("success", out)
        self.assertIn("unavailable", out)
        self.assertIn("no runs", out)
        listed = [a for a in self.argvs() if a[:2] == ["run", "list"]]
        self.assertEqual([a[a.index("--workflow") + 1] for a in listed],
                         ["build.yml", "ingest.yml", "stage.yml", "catalog.yml"])
        self.assertTrue(all(a[a.index("--limit") + 1] == "3" for a in listed))
        self.assertEqual(self.run_alt("status", "--limit", "0")[0], 1)

    def test_status_lists_withdrawn_versions_per_app(self):
        tree = [{"path": "apps", "type": "tree"}, {"path": "apps/%s/app.json" % BID, "type": "blob"},
                {"path": "apps/%s/retracted.json" % BID, "type": "blob"},
                {"path": "apps/io.example.other/retracted.json", "type": "blob"},
                {"path": "apps/io.example.other/versions/retracted.json", "type": "blob"},
                {"path": "apps/io.example.empty/retracted.json", "type": "blob"}]
        self.set_rules({"match": ["api", "repos/xuniv/alt/git/trees/main?recursive=1"],
                        "stdout": {"tree": tree, "truncated": False}},
                       retracted_rule({"1.2.3": {"date": "2026-10-22T07:13:00Z", "reason": "deleted"},
                                       "1.10.0": {"date": "2026-10-23T01:00:00Z", "reason": "unpublished"},
                                       "v9": {}}),
                       retracted_rule({"0.1.0": {"date": "2026-10-20T00:00:00Z", "reason": "deleted\x1b[2J"}},
                                      bid="io.example.other"),
                       retracted_rule({}, bid="io.example.empty"),
                       {"match": ["run", "list"], "stdout": []})
        code, out, err = self.run_alt("status")
        self.assertEqual(code, 0, err)
        section = out[out.index("withdrawn versions (apps/*/retracted.json on main)\n"):].splitlines()[1:]
        self.assertEqual([line.split()[:3] for line in section],
                         [[BID, "1.10.0", "unpublished,"], [BID, "1.2.3", "deleted,"],
                          ["io.example.other", "0.1.0", "2026-10-20T00:00:00Z"]])
        self.assertNotIn("\x1b", out)
        self.assertEqual(self.writes(), [])

    def test_status_without_withdrawn_versions_and_when_unavailable(self):
        self.set_rules({"match": ["run", "list"], "stdout": []})
        code, out, _ = self.run_alt("status")
        self.assertEqual(code, 0)
        self.assertTrue(out.endswith("withdrawn versions (apps/*/retracted.json on main)\n  none\n"), out)
        for rule in ({"match": ["api", "repos/xuniv/alt/git/trees/main?recursive=1"], "code": 1,
                      "stderr": "gh: Server Error (HTTP 500)\n"},
                     {"match": ["api", "repos/xuniv/alt/git/trees/main?recursive=1"],
                      "stdout": {"tree": [], "truncated": True}}):
            self.set_rules(rule, {"match": ["run", "list"], "stdout": []})
            code, out, _ = self.run_alt("status")
            self.assertEqual(code, 1, rule)
            self.assertIn("withdrawn versions (apps/*/retracted.json on main)\n  unavailable: ", out)

    def test_diag_decrypts_without_writing_plain_text(self):
        self.write(os.path.join(self.config, "log-identity.txt"), "AGE-SECRET-KEY-PLACEHOLDER\n")
        self.set_rules({"match": ["run", "download", "123"], "files": {"build.log.age": "encrypted:line one\nline two\n"}})
        code, out, err = self.run_alt("diag", "123")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "line one\nline two\n")
        argv = self.call("run", "download")["argv"]
        self.assertEqual(argv[:5], ["run", "download", "123", "-R", "xuniv/alt"])
        self.assertEqual(argv[argv.index("-n") + 1], "diag")
        self.assertFalse(os.path.exists(argv[argv.index("-D") + 1]))

    def test_diag_prints_each_log_of_the_archive(self):
        self.write(os.path.join(self.config, "log-identity.txt"), "AGE-SECRET-KEY-PLACEHOLDER\n")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:  # what build.yml uploads: tar -C diag -czf - .
            for name, text in (("./git.log", b"fetched\n"), ("./build.log", b"line one\nline two")):
                info = tarfile.TarInfo(name)
                info.size = len(text)
                tar.addfile(info, io.BytesIO(text))
        payload = "encrypted-b64:" + base64.b64encode(buf.getvalue()).decode("ascii")
        self.set_rules({"match": ["run", "download", "123"], "files": {"diag.tar.gz.age": payload}})
        code, out, err = self.run_alt("diag", "123")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "== build.log ==\nline one\nline two\n== git.log ==\nfetched\n")
        damaged = "encrypted-b64:" + base64.b64encode(buf.getvalue()[:40]).decode("ascii")
        self.set_rules({"match": ["run", "download", "123"], "files": {"diag.tar.gz.age": damaged}})
        code, _, err = self.run_alt("diag", "123")
        self.assertEqual(code, 1)
        self.assertIn("damaged", err)

    def test_diag_failures(self):
        self.assertEqual(self.run_alt("diag", "12x")[0], 1)
        code, _, err = self.run_alt("diag", "123")
        self.assertEqual(code, 1)
        self.assertIn("log identity not found", err)
        self.assertEqual([a for a in self.argvs() if a[:2] == ["run", "download"]], [])
        self.write(os.path.join(self.config, "log-identity.txt"), "AGE-SECRET-KEY-PLACEHOLDER\n")
        self.set_rules({"match": ["run", "download"], "files": {"build.log.age": "garbage"}})
        code, _, err = self.run_alt("diag", "123")
        self.assertEqual(code, 1)
        self.assertIn("could not decrypt", err)
        self.set_rules({"match": ["run", "download"]})
        self.assertIn("empty", self.run_alt("diag", "123")[2])

    def doctor_rules(self, secrets=("ALT_DENYLIST", "ALT_PAYLOAD_IDENTITY"), env_secrets=("ALT_KEY", "ALT_APP"),
                     pages_code=0, state="active", branch_policy=True, policies=None):
        workflows = [{"path": ".github/workflows/%s" % w, "state": state if w == "build.yml" else "active"}
                     for w in ("catalog.yml", "stage.yml", "build.yml", "ingest.yml", "poll.yml", "ci.yml")]
        if branch_policy is True:
            policy = {"protected_branches": False, "custom_branch_policies": True}
        else:
            policy = branch_policy or None
        policies = [{"id": 1, "name": "main", "type": "branch"}] if policies is None else policies
        self.set_rules({"match": ["api", "repos/xuniv/alt/actions/permissions"], "stdout": {"enabled": True}},
                       {"match": ["api", "repos/xuniv/alt/actions/permissions/workflow"],
                        "stdout": {"default_workflow_permissions": "read"}},
                       {"match": ["api", "repos/xuniv/alt/actions/workflows?per_page=100"],
                        "stdout": {"total_count": 6, "workflows": workflows}},
                       {"match": ["api", ENV_PATH], "stdout": {"name": ENV, "deployment_branch_policy": policy}},
                       {"match": ["api", POLICIES_PATH + "?per_page=100"],
                        "stdout": {"total_count": len(policies), "branch_policies": policies}},
                       {"match": ["secret", "list", "--env", ENV], "stdout": [{"name": n} for n in env_secrets]},
                       {"match": ["secret", "list"], "stdout": [{"name": n} for n in secrets]},
                       {"match": ["variable", "list"],
                        "stdout": [{"name": "ALT_LOG_RECIPIENT"}, {"name": "ALT_PAYLOAD_RECIPIENT"}]},
                       {"match": ["api", "repos/xuniv/alt/pages"], "code": pages_code,
                        "stdout": {"build_type": "workflow"} if pages_code == 0 else {"message": "Not Found"}})

    def test_doctor_all_good(self):
        os.chmod(self.denylist, 0o600)
        self.app_json({"privateBuild": {"enabled": True}})
        self.app_json({"name": "Other"}, bid="io.example.other")
        self.write(os.path.join(self.config, "log-identity.txt"), "AGE-SECRET-KEY-PLACEHOLDER\n")
        self.doctor_rules()
        code, out, err = self.run_alt("doctor")
        self.assertEqual(code, 0, out + err)
        self.assertIn("0 problem(s)", out)
        self.assertNotIn("FAIL", out)
        self.assertEqual(self.writes(), [])

    def test_doctor_reports_each_problem(self):
        os.chmod(self.denylist, 0o644)
        self.app_json({"privateBuild": {"enabled": True}})
        self.doctor_rules(secrets=("ALT_DENYLIST", "ALT_KEY_" + ALIAS), env_secrets=("ALT_KEY",), pages_code=1,
                          state="disabled_manually")
        code, out, _ = self.run_alt("doctor")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  repository secrets: missing ALT_PAYLOAD_IDENTITY", out)
        self.assertIn("warn  1 per-app repository secret(s) of an earlier version are no longer read", out)
        self.assertIn("FAIL  environment %s: missing secret ALT_APP" % ENV, out)
        self.assertIn("not enabled build.yml", out)
        self.assertIn("FAIL  GitHub Pages deployed by Actions", out)
        self.assertIn("warn  denylist file is readable by other users", out)
        self.assertIn("4 problem(s)", out)

    def test_doctor_wants_an_environment_limited_to_main(self):
        os.chmod(self.denylist, 0o600)
        self.app_json({"privateBuild": {"enabled": True}})
        self.doctor_rules(branch_policy=False)
        code, out, _ = self.run_alt("doctor")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  environment %s: every branch may use its secrets; allow main only" % ENV, out)
        self.assertEqual(self.writes(), [])

    def test_doctor_wants_main_as_the_only_deployment_policy(self):
        os.chmod(self.denylist, 0o600)
        self.app_json({"privateBuild": {"enabled": True}})
        main = {"id": 1, "name": "main", "type": "branch"}
        cases = [
            ({}, [main, {"id": 2, "name": "*", "type": "branch"}],
             "deployment policies besides main: 1 (0 for tags); run alt register to remove them"),
            ({}, [main, {"id": 3, "name": "v*", "type": "tag"}], "deployment policies besides main: 1 (1 for tags)"),
            ({}, [{"id": 4, "name": "main", "type": "tag"}], "main is not an allowed branch"),
            ({}, [], "main is not an allowed branch"),
            ({"branch_policy": {"protected_branches": True, "custom_branch_policies": False}}, [main],
             "not limited to selected branches"),
        ]
        for options, policies, message in cases:
            self.doctor_rules(policies=policies, **options)
            code, out, _ = self.run_alt("doctor")
            self.assertEqual(code, 1, (policies, out))
            self.assertIn("FAIL  environment %s: %s" % (ENV, message), out)
        self.assertEqual(self.writes(), [])

    def test_doctor_stops_remote_checks_on_the_wrong_login(self):
        self.set_rules({"match": ["api", "user"], "stdout": "personal-account\n"})
        code, out, _ = self.run_alt("doctor")
        self.assertEqual(code, 1)
        self.assertIn("remote checks skipped", out)
        self.assertNotIn("personal-account", out)
        self.assertEqual(len(self.argvs()), 1)


class CommandLineTests(OperatorCase):
    def test_script_runs_standalone_from_any_directory(self):
        self.assertTrue(os.access(ALT, os.X_OK))
        env = {k: v for k, v in self.env.items()}
        proc = subprocess.run([sys.executable, ALT, "--help"], capture_output=True, env=env, cwd=self.dir)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for command in (b"publish", b"mirror", b"build", b"ingest", b"register", b"unregister", b"hook",
                        b"status", b"diag", b"doctor"):
            self.assertIn(command, proc.stdout)
        proc = subprocess.run([sys.executable, ALT, "build", BID, "v1.2.3"], capture_output=True, env=env,
                              cwd=self.dir)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.writes()[-1][:3], ["workflow", "run", "build.yml"])

    def test_usage_errors_exit_1(self):
        for argv in ([], ["publish"], ["build", BID], ["hook"], ["hook", "install", self.dir], ["register", PRIVATE],
                     ["status", "--limit", "x"], ["no-such-command"], ["publish", "a.ipa", "--bogus"]):
            code, out, err = self.run_alt(*argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("alt: error:", err)
            self.assertEqual(out, "")
        self.assertEqual(self.calls(), [])

    def test_missing_gh(self):
        os.unlink(os.path.join(self.bin, "gh"))
        env = dict(self.env, PATH=self.bin)
        code, _, err = self.run_alt("build", BID, "v1.2.3", env=env)
        self.assertEqual(code, 1)
        self.assertIn("gh is not installed", err)

    def test_tracked_files_carry_no_local_paths(self):
        for path in (ALT, HOOK_TEMPLATE):
            text = self.read_file(path)
            self.assertNotRegex(text, r"/Users/|/home/[a-z]")

    @staticmethod
    def read_file(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()


BUILD_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "build.yml")
FILE_COMMANDS = ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY")


def job_lines(path, job):
    """(first, end) line indexes of the job ``job`` in the workflow at ``path``."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    first = lines.index("  %s:" % job)
    end = next((i for i in range(first + 1, len(lines))
                if lines[i].startswith("  ") and not lines[i].startswith("   ") and lines[i].strip()), len(lines))
    return first, end


def step_script(path, name, job=None):
    """The ``run: |`` block of the step called ``name`` (the workflow is read as text; no YAML parser),
    optionally only within the job ``job``."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    first, end = job_lines(path, job) if job else (0, len(lines))
    start = [i for i, line in enumerate(lines) if line.strip() == "- name: %s" % name and first <= i < end]
    if len(start) != 1:
        raise AssertionError("expected one step named %r" % name)
    key_indent = len(lines[start[0]]) - len(lines[start[0]].lstrip()) + 2
    run = None
    for i in range(start[0] + 1, len(lines)):
        indent = len(lines[i]) - len(lines[i].lstrip())
        if lines[i].strip() and indent < key_indent:
            break
        if indent == key_indent and lines[i].strip() == "run: |":
            run = i
            break
    if run is None:
        raise AssertionError("step %r has no literal run block" % name)
    body = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= key_indent:
            break
        body.append(line)
    indent = min(len(line) - len(line.lstrip()) for line in body if line.strip())
    return "\n".join(line[indent:] for line in body).rstrip() + "\n"


def bash_programs():
    """bash from PATH and, on macOS, the system bash 3.2 that the step must also run under."""
    found = []
    for candidate in (shutil.which("bash"), "/bin/bash"):
        if candidate and os.path.isfile(candidate) and os.path.realpath(candidate) not in found:
            found.append(os.path.realpath(candidate))
    return found


@unittest.skipUnless(bash_programs() and shutil.which("python3"), "needs bash and python3")
class BuildStepTests(unittest.TestCase):
    """build.yml's "Build" step: the private command sees only an allowlisted environment."""

    SECRET = "sentinel-runtime-token-0"
    COMMAND = "\n".join([
        'echo "private-build-output" >> "$GITHUB_STEP_SUMMARY"',
        'echo "name=private-build-output" >> "$GITHUB_OUTPUT"',
        'echo "PRIVATE_BUILD=1" >> "$GITHUB_ENV"',
        'echo "/private/build/bin" >> "$GITHUB_PATH"',
        'echo "state=private-build-output" >> "$GITHUB_STATE"',
        'echo "::warning::private-build-annotation"',
        'echo "tokens:${ACTIONS_RUNTIME_TOKEN-}${GITHUB_TOKEN-}${ACTIONS_ID_TOKEN_REQUEST_TOKEN-}${ALT_APP_CONFIG-}"',
        'env > "$ALT_OUT/env.txt"',
        'pwd -P > "$ALT_OUT/pwd.txt"',
    ])

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.realpath(self._tmp.name)
        self.script = step_script(BUILD_WORKFLOW, "Build")
        self.temp = os.path.join(self.dir, "runner-temp")
        for sub in ("alt-build", "diag", "src", "_runner_file_commands"):
            os.makedirs(os.path.join(self.temp, sub))
        self.files = {}
        for key in FILE_COMMANDS:
            self.files[key] = os.path.join(self.temp, "_runner_file_commands", key.lower())
            open(self.files[key], "w").close()

    def tearDown(self):
        self._tmp.cleanup()

    def run_step(self, bash, command):
        with open(os.path.join(self.temp, "alt-build", "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"runner": "macos-latest", "command": command, "ipa_glob": "**/*.ipa",
                       "env": json.dumps({"SCHEME": "Demo", "LANG": "en_GB.UTF-8"})}, fh)
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.dir, "TMPDIR": self.dir,
               "LC_ALL": "C", "RUNNER_TEMP": self.temp, "VERSION": "1.2.3", "GITHUB_ACTIONS": "true",
               "GITHUB_TOKEN": self.SECRET, "ACTIONS_RUNTIME_TOKEN": self.SECRET,
               "ACTIONS_RUNTIME_URL": "https://runtime.invalid/", "ACTIONS_RESULTS_URL": "https://results.invalid/",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": self.SECRET,
               "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.invalid/", "ALT_APP_CONFIG": self.SECRET,
               "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "xuniv/alt", "GITHUB_WORKSPACE": self.dir}
        env.update(self.files)
        return subprocess.run([bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", self.script], cwd=self.dir,
                              env=env, stdin=subprocess.DEVNULL, capture_output=True)

    def read(self, *parts):
        with open(os.path.join(self.temp, *parts), encoding="utf-8") as fh:
            return fh.read()

    def test_the_command_cannot_reach_the_job_or_its_tokens(self):
        for bash in bash_programs():
            with self.subTest(bash=bash):
                proc = self.run_step(bash, self.COMMAND)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertRegex(proc.stdout.decode(), r"^build finished, exit 0, \d+ minutes\n$")
                self.assertEqual(proc.stderr, b"")
                for key, path in self.files.items():
                    self.assertEqual(os.path.getsize(path), 0, key)  # nothing reached the job
                log = self.read("diag", "build.log")
                self.assertIn("private-build-annotation", log)  # only in the private log
                self.assertIn("tokens:\n", log)
                for folder, _, names in os.walk(self.dir):
                    for name in names:
                        with open(os.path.join(folder, name), "rb") as fh:
                            self.assertNotIn(self.SECRET.encode(), fh.read(), os.path.join(folder, name))
                env = dict(line.split("=", 1) for line in self.read("out", "env.txt").splitlines() if "=" in line)
                allowed = {"PATH", "HOME", "TMPDIR", "LC_ALL", "LANG", "TERM", "CI", "VERSION", "ALT_OUT", "SCHEME",
                           "PWD", "OLDPWD", "SHLVL", "_"} | set(FILE_COMMANDS)
                self.assertLessEqual(set(env), allowed)
                self.assertNotIn("GITHUB_ACTIONS", env)
                self.assertEqual({k: env[k] for k in ("TERM", "CI", "VERSION", "SCHEME", "LANG", "LC_ALL", "HOME")},
                                 {"TERM": "dumb", "CI": "true", "VERSION": "1.2.3", "SCHEME": "Demo",
                                  "LANG": "en_GB.UTF-8", "LC_ALL": "C", "HOME": self.dir})
                self.assertEqual(env["ALT_OUT"], os.path.join(self.temp, "out"))
                for key in FILE_COMMANDS:
                    self.assertNotEqual(env[key], self.files[key])
                    self.assertFalse(os.path.exists(env[key]), key)  # the throwaway files are gone
                self.assertEqual(self.read("out", "pwd.txt").strip(), os.path.join(self.temp, "src"))
                self.assertFalse(os.path.exists(os.path.join(self.temp, "alt-build", "env.list")))

    def test_a_failing_command_fails_the_step_quietly(self):
        for bash in bash_programs():
            with self.subTest(bash=bash):
                proc = self.run_step(bash, 'echo "private-build-output"\nexit 3')
                self.assertEqual(proc.returncode, 1)
                self.assertRegex(proc.stdout.decode(), r"^build failed, exit 3, \d+ minutes\n$")
                self.assertEqual(proc.stderr, b"")
                self.assertIn("private-build-output", self.read("diag", "build.log"))
                proc = self.run_step(bash, "false | true\necho reached")  # pipefail applies to the command
                self.assertRegex(proc.stdout.decode(), r"^build failed, exit 1, ")


POLL_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "poll.yml")
CATALOG_WORKFLOW = os.path.join(ROOT, ".github", "workflows", "catalog.yml")
TOOLS = os.path.join(ROOT, "tools")


def heredoc(script, opener):
    """The body of the here-document that starts on the line ``opener`` and ends at ``PY``."""
    lines = script.splitlines()
    start = lines.index(opener)
    return "\n".join(lines[start + 1:lines.index("PY", start)]) + "\n"


class WithdrawnWorkflowCase(OperatorCase):
    """A checkout of this repository with one private build app; fake gh as in the operator tests."""

    def setUp(self):
        super().setUp()
        self.app_json({"privateBuild": {"enabled": True}})

    def retract(self, *versions, bid=BID):
        text = json.dumps({"schemaVersion": 1, "versions": {
            v: {"date": "2026-10-22T07:13:00Z", "reason": "deleted"} for v in versions}}, indent=2, sort_keys=True)
        self.write(os.path.join(self.root, "apps", bid, "retracted.json"), text + "\n")

    def damage(self, bid=BID):
        """A tombstone file that altsource.retract refuses to read."""
        self.write(os.path.join(self.root, "apps", bid, "retracted.json"), '{"schemaVersion": 1, "versions": [')


@unittest.skipUnless(shutil.which("bash") and shutil.which("python3"), "needs bash and python3")
class BuildFirstJobTests(WithdrawnWorkflowCase):
    """build.yml's app job refuses a withdrawn version unless force is set, before any secret is used."""

    def run_check(self, ref="v1.2.3", force="false"):
        script = step_script(BUILD_WORKFLOW, "Check the version", job="app")
        temp = self.mkdir("runner-temp")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.home, "RUNNER_TEMP": temp,
               "PYTHONPATH": TOOLS, "APP": BID, "REF": ref, "FORCE": force, "GITHUB_ACTIONS": "true"}
        proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script], cwd=self.root,
                              env=env, stdin=subprocess.DEVNULL, capture_output=True)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def test_a_withdrawn_version_is_refused_unless_forced(self):
        self.retract("1.2.3")
        code, out, _ = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("::error::version 1.2.3 was withdrawn (apps/%s/retracted.json); dispatch the build with "
                      "force=true" % BID, out)
        code, out, _ = self.run_check(force="true")
        self.assertEqual(code, 0, out)
        self.assertIn("::warning::version 1.2.3 was withdrawn; building it because force is set", out)

    def test_other_versions_and_apps_without_the_file_pass(self):
        self.retract("1.2.3")
        code, out, _ = self.run_check(ref="v1.2.4")
        self.assertEqual(code, 0, out)
        self.assertIn("version 1.2.4: not withdrawn", out)
        os.unlink(os.path.join(self.root, "apps", BID, "retracted.json"))
        self.assertEqual(self.run_check()[0], 0)

    def test_the_version_comes_from_the_tag_pattern(self):
        pattern = r"^app-(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$"
        self.app_json({"privateBuild": {"enabled": True, "tagPattern": pattern}})
        self.retract("1.2.3")
        self.assertEqual(self.run_check(ref="app-1.2.3")[0], 1)
        self.assertEqual(self.run_check(ref="app-1.2.4")[0], 0)
        code, out, _ = self.run_check(ref="v1.2.4")  # outside the pattern: refused here, not in a later job
        self.assertEqual(code, 1)
        self.assertIn("::error::ref does not match privateBuild.tagPattern", out)

    def test_an_unreadable_file_fails_closed(self):
        self.damage()
        code, out, err = self.run_check(ref="v1.2.4")
        self.assertEqual(code, 1)
        self.assertIn("::error::apps/%s/retracted.json could not be checked (exit 1)" % BID, out)
        self.assertIn("retracted.json is not valid", err)

    def test_validate_inputs_wants_a_boolean_force(self):
        script = step_script(BUILD_WORKFLOW, "Validate inputs", job="app")
        event = self.write(os.path.join(self.dir, "event.json"), json.dumps({"inputs": {"notes": ""}}))
        for force, expected in (("false", 0), ("true", 0), ("", 1), ("yes", 1)):
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_REF": "refs/heads/main",
                   "GITHUB_EVENT_PATH": event, "APP": BID, "REF": "v1.2.3", "PUBLISH": "true", "FORCE": force}
            proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script], cwd=self.dir,
                                  env=env, stdin=subprocess.DEVNULL, capture_output=True)
            self.assertEqual(proc.returncode, expected, (force, proc.stdout))

    def test_the_check_runs_in_the_job_without_secrets(self):
        with open(BUILD_WORKFLOW, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        first, end = job_lines(BUILD_WORKFLOW, "app")
        app_job = "\n".join(lines[first:end])
        self.assertNotIn("secrets.", app_job)
        self.assertNotRegex(app_job, r"\n    environment:")
        self.assertIn("python3 -m altsource retracted --bid", app_job)
        self.assertIn("FORCE: ${{ inputs.force }}", app_job)
        for job in ("resolve", "build"):  # every job that can read a secret comes after it
            first, end = job_lines(BUILD_WORKFLOW, job)
            self.assertRegex("\n".join(lines[first:end]), r"\n    needs: (app|\[app, resolve\])\n")
        inputs = "\n".join(lines[lines.index("      force:"):lines.index("      force:") + 4])
        self.assertIn("type: boolean", inputs)
        self.assertIn("default: false", inputs)


class PollWithdrawnTests(WithdrawnWorkflowCase):
    """The version selection of poll.yml skips withdrawn versions and never sets build.yml's force."""

    RUNS = r"^repos/xuniv/alt/actions/workflows/build\.yml/runs\?created=%3E%3D\d{4}-\d\d-\d\d&per_page=100&page=1$"

    def run_poll(self, tags, dry_run="false", released=()):
        script = heredoc(step_script(POLL_WORKFLOW, "Find new versions"), 'python3 - "$RUNNER_TEMP/tags.txt" <<\'PY\'')
        program = self.write(os.path.join(self.dir, "poll.py"), script)
        listing = self.write(os.path.join(self.dir, "tags.txt"),
                             "".join("%s\trefs/tags/%s\n" % ("a" * 40, tag) for tag in tags))
        self.set_rules({"match": ["repos/xuniv/alt/releases?per_page=100&page=1"],
                        "stdout": [{"id": i + 1, "tag_name": t, "draft": False} for i, t in enumerate(released)]},
                       {"pattern": [self.RUNS], "stdout": {"total_count": 0, "workflow_runs": []}})
        env = {"PATH": self.env["PATH"], "HOME": self.home, "FAKE_GH_STATE": self.state, "GH_TOKEN": "placeholder",
               "PYTHONPATH": TOOLS, "ALT_REPO": "xuniv/alt",
               "BID": BID, "DRY_RUN": dry_run, "ALT_DENYLIST": "leaky-host-0\n", "GITHUB_ACTIONS": "true"}
        proc = subprocess.run([sys.executable, program, listing], cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def dispatched(self):
        return [json.loads(c["stdin"]) for c in self.calls()
                if "repos/xuniv/alt/actions/workflows/build.yml/dispatches" in c["argv"]]

    def test_withdrawn_versions_are_skipped(self):
        self.retract("1.3.0", "1.2.3")
        code, out, err = self.run_poll(["v1.2.3", "v1.2.4", "v1.3.0", "v1.1.0"], released=["io.example.demo-v1.1.0"])
        self.assertEqual(code, 0, out + err)
        self.assertIn("matching tags: 4, refused: 0, withdrawn: 2, candidates: 1, dispatched: 1", out)
        self.assertEqual(self.dispatched(), [{"ref": "main", "inputs": {"app": BID, "ref": "v1.2.4",
                                                                        "publish": "true"}}])
        self.assertNotIn("1.3.0", out + err)  # counts only

    def test_without_withdrawn_versions_and_in_a_dry_run(self):
        code, out, _ = self.run_poll(["v1.2.3", "v1.2.4", "v1.3.0"], dry_run="true")
        self.assertEqual(code, 0, out)
        self.assertIn("withdrawn: 0, candidates: 3, would dispatch: 2", out)
        self.assertEqual(self.dispatched(), [])

    def test_an_unreadable_file_dispatches_nothing(self):
        self.damage()
        code, out, _ = self.run_poll(["v1.2.4"])
        self.assertEqual(code, 1)
        self.assertIn("::error::apps/<app>/retracted.json could not be checked", out)
        self.assertEqual(self.dispatched(), [])


class CatalogTriggerTests(unittest.TestCase):
    def test_deleting_or_unpublishing_a_release_starts_the_catalog(self):
        # bin/alt retract and the GitHub web UI rely on these events; retract also dispatches catalog.yml
        with open(CATALOG_WORKFLOW, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        start = lines.index("  release:")
        types = [line.strip() for line in lines[start + 1:start + 3] if line.strip().startswith("types:")]
        self.assertEqual(len(types), 1)
        listed = [t.strip() for t in types[0][len("types:"):].strip(" []").split(",")]
        self.assertIn("deleted", listed)
        self.assertIn("unpublished", listed)
        self.assertIn("  workflow_dispatch:", lines)


if __name__ == "__main__":
    unittest.main()
