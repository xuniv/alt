"""Tests for the pre-publication gate and release staging (fake GitHub layer, fake IPA tooling)."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import struct
import tempfile
import unittest
import zipfile

from altsource import stage as stagemod
from altsource.gh import GhError
from tests.test_sync import FakeGitHub, FakeToolkit, ipa_bytes, write_ipa

DENY = ["leaky-host-0", "leakyuser0"]
TAG = "io.example.demo-v1.2.3"


class StageCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.gh = FakeGitHub()
        self.deps = FakeToolkit()

    def tearDown(self):
        self._tmp.cleanup()

    def ipa(self, filename="in.ipa", **fields):
        return write_ipa(os.path.join(self.dir, filename), **fields)

    def stage(self, path, **kw):
        kw.setdefault("denylist", DENY)
        return stagemod.stage(path, gh=self.gh, deps=self.deps, sleep=lambda s: None, **kw)

    def normalized(self, **fields):
        return ipa_bytes(**fields)


class GateTests(StageCase):
    def assert_rejected(self, rule, path, **kw):
        with self.assertRaises(stagemod.GateRejected) as ctx:
            self.stage(path, **kw)
        self.assertIn(rule, [f["rule"] for f in ctx.exception.findings])
        self.assertEqual(self.gh.calls, [], "GitHub must not be called before the gate passed")
        return ctx.exception

    def test_denylist_hit_rejects_without_github_calls(self):
        exc = self.assert_rejected("denylist", self.ipa(payload="made on LEAKY-HOST-0"))
        self.assertEqual(exc.findings[0]["severity"], "block")
        self.assertNotIn("leaky-host-0", str(exc).lower())

    def test_home_path_blocks_unless_allowed(self):
        path = self.ipa(payload="/Users/leakyuser1/project")
        self.assert_rejected("home-path", path, denylist=["unrelated-word"])
        result = self.stage(path, denylist=["unrelated-word"], policy=self.deps.GatePolicy(allow_home_paths=True),
                            dry_run=True)
        self.assertEqual([w["rule"] for w in result.warnings], ["home-path"])

    def test_home_path_warnings_without_the_opt_in_attach_no_app_json(self):
        scan = self.deps.scan_ipa

        def scan_ipa(path, **kw):
            result = scan(path, **kw)
            result.findings.append({"rule": "home-path", "severity": "warn", "count": 1, "paths": []})
            return result

        self.deps.scan_ipa = scan_ipa
        result = self.stage(self.ipa())
        self.assertEqual([w["rule"] for w in result.warnings], ["home-path"])
        uploads = [c for c in self.gh.calls if c[0] == "upload_asset"]
        self.assertEqual([c[2] for c in uploads], ["Demo-App-1.2.3.ipa"])

    def test_notes_and_app_name_are_scanned(self):
        self.assert_rejected("denylist", self.ipa(), notes="built on leaky-host-0")
        exc = self.assert_rejected("denylist", self.ipa(name="leakyuser0 tools"))
        self.assertIn("<app-name>", exc.findings[-1]["paths"])

    def test_bundle_id_mismatch(self):
        self.assert_rejected("bundle-id-mismatch", self.ipa(), expected_bid="io.example.other")

    def test_version_mismatch(self):
        self.assert_rejected("version-mismatch", self.ipa(), semver="1.2.4")
        self.assert_rejected("version-mismatch", self.ipa(short_version="1.2.3b"))

    def test_invalid_semver_is_a_stage_error(self):
        with self.assertRaises(stagemod.StageError) as ctx:
            self.stage(self.ipa(), semver="1.2")
        self.assertNotIsInstance(ctx.exception, stagemod.GateRejected)
        self.assertEqual(self.gh.calls, [])

    def test_tag_grammar_refuses_ambiguous_bundle_id(self):
        self.assert_rejected("tag-grammar", self.ipa(bundle_id="io.example.app-v2"))

    def test_ipa_error_rule_is_reported(self):
        self.assert_rejected("zip-traversal", self.ipa(broken="zip-traversal"))

    def test_scanner_ipa_error_is_a_gate_rejection(self):
        import zipfile

        from tests.test_sync import FakeIpaError

        for exc, rule in ((FakeIpaError("zip-bomb-ratio"), "zip-bomb-ratio"),
                          (zipfile.BadZipFile("Bad CRC-32"), "ipa-invalid")):
            def scan(path, _exc=exc, **kw):
                raise _exc

            self.deps.scan_ipa = scan
            self.assert_rejected(rule, self.ipa())

    def test_gate_error_fails_closed(self):
        with self.assertRaises(stagemod.StageError):
            self.stage(self.ipa(), denylist=[])
        self.assertEqual(self.gh.calls, [])

    def test_dry_run_makes_no_github_calls(self):
        result = self.stage(self.ipa(short_version="1.2", junk=True), dry_run=True)
        self.assertEqual(result.tag, "io.example.demo-v1.2.0")
        self.assertIsNone(result.release_id)
        self.assertFalse(result.published)
        self.assertTrue(result.normalized_changed)
        self.assertEqual(result.asset, "Demo-App-1.2.0.ipa")
        self.assertEqual(result.sha256, hashlib.sha256(self.normalized(short_version="1.2")).hexdigest())
        self.assertEqual(self.gh.calls, [])

    def test_dry_run_without_gh_never_builds_a_client(self):
        result = stagemod.stage(self.ipa(), denylist=DENY, deps=self.deps, dry_run=True, gh=None)
        self.assertEqual(result.tag, TAG)

    def test_scan_runs_on_the_normalized_file(self):
        self.stage(self.ipa(), dry_run=True)
        self.assertTrue(self.deps.scanned[0].endswith("normalized.ipa"))


class ReleaseTests(StageCase):
    def test_new_release_is_drafted_verified_and_published(self):
        result = self.stage(self.ipa(), notes="  Fixes.  ")
        names = [c[0] for c in self.gh.calls]
        self.assertEqual(names, ["get_release_by_tag", "create_draft", "upload_asset", "list_assets", "publish"])
        create = self.gh.calls[1]
        self.assertEqual(create[1:], (TAG, "main", "Demo App 1.2.3", "Fixes.", False))
        self.assertEqual(self.gh.calls[2][2], "Demo-App-1.2.3.ipa")
        self.assertEqual(self.gh.calls[4][2:], (False, "false"))
        self.assertTrue(result.published)
        self.assertFalse(result.noop)
        self.assertEqual(result.asset, "Demo-App-1.2.3.ipa")
        rel = self.gh.releases[result.release_id]
        self.assertFalse(rel["draft"])
        self.assertEqual(rel["assets"][0]["digest"], "sha256:" + result.sha256)

    def test_prerelease_semver_marks_release_prerelease(self):
        result = self.stage(self.ipa(short_version="1.3.0"), semver="1.3.0-beta.2")
        self.assertEqual(result.tag, "io.example.demo-v1.3.0-beta.2")
        self.assertTrue(self.gh.calls[1][5])
        self.assertEqual(self.gh.calls[-1], ("publish", result.release_id, True, "false"))

    def test_no_publish_leaves_draft(self):
        result = self.stage(self.ipa(), publish=False)
        self.assertFalse(result.published)
        self.assertTrue(self.gh.releases[result.release_id]["draft"])
        self.assertNotIn("publish", [c[0] for c in self.gh.calls])

    def test_published_same_asset_is_noop(self):
        rel = self.gh.add_release(TAG)
        self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", self.normalized())
        result = self.stage(self.ipa(junk=True))
        self.assertTrue(result.noop)
        self.assertTrue(result.published)
        self.assertEqual(result.release_id, rel["id"])
        self.assertEqual(self.gh.mutations(), [])

    def test_published_different_asset_conflicts(self):
        rel = self.gh.add_release(TAG)
        self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", self.normalized(payload="older"))
        with self.assertRaises(stagemod.Conflict):
            self.stage(self.ipa())
        self.assertEqual(self.gh.mutations(), [])

    def test_draft_is_reused_and_foreign_assets_removed(self):
        rel = self.gh.add_release(TAG, draft=True)
        keep = self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", self.normalized())
        stale = self.gh.add_asset(rel, "Old.ipa", b"old")
        extra = self.gh.add_asset(rel, "notes.txt", b"x")
        result = self.stage(self.ipa())
        self.assertIn(("delete_asset", stale["id"]), self.gh.calls)
        self.assertIn(("delete_asset", extra["id"]), self.gh.calls)
        self.assertNotIn(("delete_asset", keep["id"]), self.gh.calls)
        self.assertNotIn("upload_asset", [c[0] for c in self.gh.calls])
        self.assertNotIn("create_draft", [c[0] for c in self.gh.calls])
        self.assertEqual(result.release_id, rel["id"])
        self.assertEqual(result.asset_id, keep["id"])
        self.assertTrue(result.published)

    def test_failed_upload_verification_deletes_draft(self):
        self.gh.corrupt_uploads = True
        with self.assertRaises(stagemod.StageError):
            self.stage(self.ipa())
        self.assertEqual(self.gh.calls[-1][0], "delete_release")
        self.assertEqual(self.gh.releases, {})
        self.assertNotIn("publish", [c[0] for c in self.gh.calls])

    def test_app_json_seed_is_uploaded_before_publish(self):
        seed = os.path.join(self.dir, "app.json")
        with open(seed, "w", encoding="utf-8") as fh:
            json.dump({"subtitle": "Reads codes", "category": "utilities"}, fh)
        self.stage(self.ipa(), app_json=seed)
        uploads = [c for c in self.gh.calls if c[0] == "upload_asset"]
        self.assertEqual([u[2:] for u in uploads], [("Demo-App-1.2.3.ipa", "application/octet-stream"),
                                                    ("app.json", "application/json")])
        self.assertEqual(self.gh.calls[-1][0], "publish")

    def test_home_path_opt_in_is_attached_as_app_json(self):
        policy = self.deps.GatePolicy(allow_home_paths=True)
        result = self.stage(self.ipa(payload="/Users/leakyuser3/x"), policy=policy)
        uploads = [c for c in self.gh.calls if c[0] == "upload_asset"]
        self.assertEqual([u[2] for u in uploads], ["Demo-App-1.2.3.ipa", "app.json"])
        seed = [a for a in self.gh.releases[result.release_id]["assets"] if a["name"] == "app.json"][0]
        self.assertEqual(json.loads(self.gh.blobs[seed["id"]]), {"allowHomePaths": True})

    def test_home_path_opt_in_is_merged_into_given_app_json(self):
        seed_file = os.path.join(self.dir, "app.json")
        with open(seed_file, "w", encoding="utf-8") as fh:
            json.dump({"subtitle": "Third party"}, fh)
        policy = self.deps.GatePolicy(allow_home_paths=True)
        result = self.stage(self.ipa(payload="/Users/leakyuser3/x"), policy=policy, app_json=seed_file)
        seed = [a for a in self.gh.releases[result.release_id]["assets"] if a["name"] == "app.json"][0]
        self.assertEqual(json.loads(self.gh.blobs[seed["id"]]), {"subtitle": "Third party", "allowHomePaths": True})

    def test_no_opt_in_without_home_path_findings(self):
        result = self.stage(self.ipa(), policy=self.deps.GatePolicy(allow_home_paths=True))
        self.assertEqual([a["name"] for a in self.gh.releases[result.release_id]["assets"]], ["Demo-App-1.2.3.ipa"])

    def test_invalid_or_leaky_app_json_rejects(self):
        seed = os.path.join(self.dir, "app.json")
        for payload in ({"tintColor": "#123456"}, {"subtitle": "from leaky-host-0"}, {"bogus": 1}):
            with open(seed, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            with self.assertRaises(stagemod.GateRejected):
                self.stage(self.ipa(), app_json=seed)
        self.assertEqual(self.gh.calls, [])


class RouteThreeTests(unittest.TestCase):
    """A new third-party app staged with the home-path opt-in survives the sync that follows."""

    def run_route(self, immutable):
        from altsource import sync as syncmod
        from tests.test_sync import BASE, FakeGit

        with tempfile.TemporaryDirectory() as root:
            git = FakeGit(root)
            git.seed({"source.base.json": syncmod.dumps_json(BASE)})
            gh = FakeGitHub(git)
            deps = FakeToolkit()
            ipa = write_ipa(os.path.join(root, "in.ipa"), bundle_id="io.example.third",
                            payload="/Users/leakyuser3/src")
            result = stagemod.stage(ipa, denylist=DENY, policy=deps.GatePolicy(allow_home_paths=True),
                                    gh=gh, deps=deps, sleep=lambda s: None)
            os.unlink(ipa)
            gh.releases[result.release_id]["immutable"] = immutable
            synced = syncmod.sync(root, gh=gh, git=git, deps=deps, denylist=DENY, log=lambda m: None,
                                  environ={})
            app = json.loads(gh.commits[0][1]["apps/io.example.third/app.json"])
            return result, synced, gh, app

    def test_first_release_with_opt_in_is_listed(self):
        for immutable in (False, True):
            result, synced, gh, app = self.run_route(immutable)
            self.assertEqual(synced.blocked, [], immutable)
            self.assertEqual(synced.versions, 1)
            self.assertFalse(gh.releases[result.release_id]["draft"])
            self.assertIs(app["allowHomePaths"], True)
            self.assertNotIn("unpublish", [c[0] for c in gh.calls])
            self.assertNotIn("delete_release", [c[0] for c in gh.calls])


class StageDraftTests(StageCase):
    def draft(self, data, body="Notes from the draft.", **kw):
        rel = self.gh.add_release(TAG, draft=True, body=body, **kw)
        asset = self.gh.add_asset(rel, "upload.ipa", data)
        return rel, asset

    def test_draft_is_normalized_replaced_and_published(self):
        rel, original = self.draft(ipa_bytes(junk=True))
        result = stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps,
                                               sleep=lambda s: None)
        self.assertTrue(result.published)
        self.assertTrue(result.normalized_changed)
        self.assertIn(("delete_asset", original["id"]), self.gh.calls)
        assets = self.gh.releases[rel["id"]]["assets"]
        self.assertEqual([a["name"] for a in assets], ["Demo-App-1.2.3.ipa"])
        self.assertEqual(self.gh.releases[rel["id"]]["body"], "Notes from the draft.")
        self.assertNotIn("create_draft", [c[0] for c in self.gh.calls])

    def test_unchanged_draft_asset_is_kept_and_renamed(self):
        rel, original = self.draft(self.normalized())
        result = stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps,
                                               sleep=lambda s: None)
        self.assertEqual(result.asset_id, original["id"])
        self.assertEqual(result.asset, "Demo-App-1.2.3.ipa")  # the published name is always canonical
        self.assertIn(("update_asset", original["id"], {"name": "Demo-App-1.2.3.ipa"}), self.gh.calls)
        self.assertNotIn("upload_asset", [c[0] for c in self.gh.calls])
        self.assertTrue(self.gh.releases[rel["id"]]["assets"][0]["browser_download_url"])

    def test_failed_upload_keeps_the_original_draft_asset(self):
        rel = self.gh.add_release(TAG, draft=True, body="Notes.")
        original = self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", ipa_bytes(junk=True))  # same name as the target
        self.gh.upload_failures = 1
        with self.assertRaises(GhError):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, sleep=lambda s: None)
        assets = self.gh.releases[rel["id"]]["assets"]
        self.assertEqual([(a["id"], a["name"]) for a in assets], [(original["id"], "Demo-App-1.2.3.ipa")])
        self.assertNotIn(("delete_asset", original["id"]), self.gh.calls)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        # a retry works from the untouched draft
        result = stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps,
                                               sleep=lambda s: None)
        self.assertTrue(result.published)
        self.assertEqual([a["name"] for a in self.gh.releases[rel["id"]]["assets"]], ["Demo-App-1.2.3.ipa"])
        self.assertIn(("delete_asset", original["id"]), self.gh.calls)

    def test_unfinished_upload_is_removed_before_retrying(self):
        rel = self.gh.add_release(TAG, draft=True)
        partial = self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", b"", state="starter", digest=False)
        result = self.stage(self.ipa())
        self.assertTrue(result.published)
        self.assertIn(("delete_asset", partial["id"]), self.gh.calls)
        self.assertEqual([a["name"] for a in self.gh.releases[rel["id"]]["assets"]], ["Demo-App-1.2.3.ipa"])

    def test_failed_verification_restores_reused_draft(self):
        rel, original = self.draft(ipa_bytes(junk=True))
        self.gh.corrupt_uploads = True
        with self.assertRaises(stagemod.StageError):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, sleep=lambda s: None)
        self.assertIn(rel["id"], self.gh.releases)
        self.assertEqual([a["id"] for a in self.gh.releases[rel["id"]]["assets"]], [original["id"]])
        self.assertNotIn("publish", [c[0] for c in self.gh.calls])

    def test_upload_verification_polls_until_uploaded(self):
        real = self.gh.list_assets
        polls = []

        def list_assets(release_id):
            assets = real(release_id)
            polls.append(1)
            if len(polls) == 1:
                for a in assets:
                    a.update(state="starter", digest=None)
            elif len(polls) == 2:
                for a in assets:
                    a["digest"] = None
            return assets

        self.gh.list_assets = list_assets
        sleeps = []
        result = stagemod.stage(write_ipa(os.path.join(self.dir, "p.ipa")), denylist=DENY, gh=self.gh,
                                deps=self.deps, sleep=sleeps.append)
        self.assertTrue(result.published)
        self.assertEqual(len(polls), 3)
        self.assertEqual(sleeps, [2.0, 2.0])

    def test_upload_never_verified_deletes_new_draft(self):
        def list_assets(release_id):
            return [dict(a, state="starter", digest=None) for a in self.gh.releases[release_id]["assets"]]

        self.gh.list_assets = list_assets
        with self.assertRaises(stagemod.StageError):
            stagemod.stage(write_ipa(os.path.join(self.dir, "p.ipa")), denylist=DENY, gh=self.gh,
                           deps=self.deps, sleep=lambda s: None)
        self.assertEqual(self.gh.releases, {})

    def test_failed_stale_delete_does_not_publish(self):
        rel, original = self.draft(ipa_bytes(junk=True))
        def delete_asset(asset_id):
            raise GhError("DELETE failed (HTTP 500)", status=500)

        self.gh.delete_asset = delete_asset
        with self.assertRaises(GhError):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, sleep=lambda s: None)
        self.assertTrue(self.gh.releases[rel["id"]]["draft"])
        self.assertNotIn("publish", [c[0] for c in self.gh.calls])

    def test_draft_notes_are_scanned(self):
        rel, _ = self.draft(ipa_bytes(), body="see /Users/leakyuser0/notes")
        with self.assertRaises(stagemod.GateRejected):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps)
        # the only change: the draft is marked so scheduled runs stop retrying it
        self.assertEqual(self.gh.mutations(), [("update_release", rel["id"], {"name": "[blocked] " + TAG})])

    def test_blocked_draft_is_skipped_until_staged_by_tag(self):
        rel, _ = self.draft(ipa_bytes(payload="leaky-host-0"))
        with self.assertRaises(stagemod.GateRejected):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps)
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps), ([], [TAG]))
        self.assertEqual(stagemod.pending_drafts(self.gh, self.deps), [])
        # staging it explicitly (for instance after a denylist correction) clears the mark
        result = stagemod.stage_existing_draft(TAG, denylist=["other-word"], gh=self.gh, deps=self.deps,
                                               sleep=lambda s: None)
        self.assertTrue(result.published)
        self.assertEqual(self.gh.releases[rel["id"]]["name"], "Demo App 1.2.3")

    def test_dry_run_rejection_does_not_mark(self):
        self.draft(ipa_bytes(payload="leaky-host-0"))
        with self.assertRaises(stagemod.GateRejected):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, dry_run=True)
        self.assertEqual(self.gh.mutations(), [])

    def test_draft_notes_can_be_replaced(self):
        rel, _ = self.draft(ipa_bytes(), body="see leaky-host-0")
        stagemod.stage_existing_draft(TAG, notes="Clean notes.", denylist=DENY, gh=self.gh, deps=self.deps,
                                      sleep=lambda s: None)
        self.assertEqual(self.gh.releases[rel["id"]]["body"], "Clean notes.")

    def test_draft_tag_must_match_ipa(self):
        rel = self.gh.add_release("io.example.demo-v1.2.4", draft=True)
        self.gh.add_asset(rel, "upload.ipa", ipa_bytes())
        with self.assertRaises(stagemod.GateRejected):
            stagemod.stage_existing_draft("io.example.demo-v1.2.4", denylist=DENY, gh=self.gh, deps=self.deps)

    def test_draft_needs_exactly_one_ipa(self):
        rel, _ = self.draft(ipa_bytes())
        self.gh.add_asset(rel, "second.ipa", ipa_bytes())
        with self.assertRaises(stagemod.StageError):
            stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps)
        with self.assertRaises(stagemod.StageError):
            stagemod.stage_existing_draft("io.example.none-v1.0.0", denylist=DENY, gh=self.gh, deps=self.deps)
        with self.assertRaises(stagemod.StageError):
            stagemod.stage_existing_draft("not-a-tag", denylist=DENY, gh=self.gh, deps=self.deps)

    def test_draft_app_json_asset_is_carried_over(self):
        rel, _ = self.draft(ipa_bytes())
        self.gh.add_asset(rel, "app.json", json.dumps({"subtitle": "Seed"}).encode())
        stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, sleep=lambda s: None)
        names = sorted(a["name"] for a in self.gh.releases[rel["id"]]["assets"])
        self.assertEqual(names, ["Demo-App-1.2.3.ipa", "app.json"])
        self.assertEqual([c for c in self.gh.calls if c[0] == "upload_asset"], [])  # nothing changed

    def test_draft_app_json_is_replaced_when_it_changes(self):
        rel, _ = self.draft(ipa_bytes(payload="/Users/leakyuser3/x"))
        seed = self.gh.add_asset(rel, "app.json", json.dumps({"subtitle": "Seed"}).encode())
        stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps, sleep=lambda s: None,
                                      policy=self.deps.GatePolicy(allow_home_paths=True))
        assets = {a["name"]: a for a in self.gh.releases[rel["id"]]["assets"]}
        self.assertEqual(sorted(assets), ["Demo-App-1.2.3.ipa", "app.json"])
        self.assertEqual(json.loads(self.gh.blobs[assets["app.json"]["id"]]),
                         {"subtitle": "Seed", "allowHomePaths": True})
        self.assertIn(("update_asset", seed["id"], {"name": "app.json.stale-%d" % seed["id"]}), self.gh.calls)
        self.assertIn(("delete_asset", seed["id"]), self.gh.calls)

    def test_already_published_tag_is_noop(self):
        rel = self.gh.add_release(TAG)
        self.gh.add_asset(rel, "Demo-App-1.2.3.ipa", self.normalized())
        result = stagemod.stage_existing_draft(TAG, denylist=DENY, gh=self.gh, deps=self.deps)
        self.assertTrue(result.noop)
        self.assertEqual(self.gh.mutations(), [])

    def test_pending_drafts(self):
        self.gh.add_release("io.example.b-v1.0.0", draft=True)
        self.gh.add_release("io.example.a-v1.0.0", draft=True)
        self.gh.add_release("io.example.c-v1.0.0")
        self.gh.add_release("scratch", draft=True)
        blocked = self.gh.add_release("io.example.d-v1.0.0", draft=True)
        blocked["name"] = "[blocked] io.example.d-v1.0.0"
        self.assertEqual(stagemod.pending_drafts(self.gh, self.deps), ["io.example.b-v1.0.0", "io.example.a-v1.0.0"])
        self.assertEqual(stagemod.draft_tags(self.gh, self.deps)[1], ["io.example.d-v1.0.0"])


class HelperTests(unittest.TestCase):
    def test_safe_name(self):
        self.assertEqual(stagemod.safe_name("Café Racer"), "Cafe-Racer")
        self.assertEqual(stagemod.safe_name("..hidden.."), "hidden")
        self.assertEqual(stagemod.safe_name("日本"), "App")
        self.assertEqual(stagemod.safe_name("a/b\\c"), "a-b-c")

    def test_normalize_short_version(self):
        self.assertEqual(stagemod.normalize_short_version("1"), "1.0.0")
        self.assertEqual(stagemod.normalize_short_version("1.02"), "1.2.0")
        self.assertEqual(stagemod.normalize_short_version(" 3.4.5 "), "3.4.5")
        for bad in ("", "1.2.3.4", "1.x", "1.2-beta", "١.٢"):
            with self.assertRaises(ValueError):
                stagemod.normalize_short_version(bad)

    def test_validate_app_json(self):
        self.assertEqual(stagemod.validate_app_json({
            "name": "Demo", "category": "games", "tintColor": "A1B2C3", "maxVersions": 5,
            "screenshots": ["https://example.invalid/1.png"], "includePrereleases": True,
            "privateBuild": {"enabled": True, "tagPattern": r"^release-(?P<version>\d+\.\d+\.\d+)$"},
        }), [])
        errors = stagemod.validate_app_json({
            "name": "", "category": "tools", "tintColor": "#A1B2C3", "maxVersions": True,
            "screenshots": ["ftp://x"], "hidden": "no", "extra": 1,
            "privateBuild": {"enabled": True, "tagPattern": "^v(.*)$"},
        })
        self.assertEqual(len(errors), 8)
        self.assertEqual(stagemod.validate_app_json([]), ["app.json must be a JSON object"])

    def test_toolkit_overrides_and_late_binding(self):
        kit = stagemod.Toolkit(inspect_ipa=lambda p: "fake")
        self.assertEqual(kit.inspect_ipa("x"), "fake")
        with self.assertRaises(AttributeError):
            kit.no_such_binding
        self.assertEqual(stagemod.errors_of(kit, "no_such_binding"), ())


def _tiny_ipa(path):
    """A minimal unsigned IPA: Info.plist plus a thin arm64 Mach-O header without load commands."""
    info = {
        "CFBundleIdentifier": "io.example.demo",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "7",
        "CFBundleExecutable": "Demo",
        "CFBundleName": "Demo",
        "MinimumOSVersion": "15.0",
        "CFBundlePackageType": "APPL",
    }
    macho = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        exe = zipfile.ZipInfo("Payload/Demo.app/Demo")
        exe.external_attr = 0o100755 << 16
        zf.writestr(exe, macho)


class RealModulesTests(unittest.TestCase):
    """End-to-end gate with the real sibling modules (still no network: dry run and a fake GitHub)."""

    def test_dry_run_with_real_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.ipa")
            _tiny_ipa(path)
            gh = FakeGitHub()
            result = stagemod.stage(path, denylist=DENY, dry_run=True, gh=gh)
            self.assertEqual(result.tag, TAG)
            self.assertFalse(result.published)
            self.assertEqual(gh.calls, [])

    def test_each_ipa_is_inspected_once(self):
        from unittest import mock

        from altsource import ipa as ipamod

        real = ipamod.inspect_ipa
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(ipamod, "inspect_ipa",
                                                                     side_effect=real) as spy:
            path = os.path.join(tmp, "in.ipa")
            _tiny_ipa(path)
            stagemod.stage(path, denylist=DENY, dry_run=True)
        self.assertEqual(spy.call_count, 2)  # the input and the normalized file; the scan reuses the latter

    def test_real_gate_blocks_planted_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.ipa")
            _tiny_ipa(path)
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("Payload/Demo.app/notes.txt", "built on leaky-host-0\n")
            gh = FakeGitHub()
            with self.assertRaises(stagemod.GateRejected) as ctx:
                stagemod.stage(path, denylist=DENY, gh=gh)
            self.assertIn("denylist", [f["rule"] for f in ctx.exception.findings])
            self.assertEqual(gh.calls, [])

    def test_real_gate_strips_root_itunes_metadata_and_blocks_entitlement_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.ipa")
            _tiny_ipa(path)
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("iTunesMetadata.plist", plistlib.dumps({"purchaser": "placeholder"}))
            result = stagemod.stage(path, denylist=DENY, dry_run=True)
            self.assertTrue(result.normalized_changed)
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("Payload/Demo.app/archived-expanded-entitlements.xcent", plistlib.dumps({}))
            with self.assertRaises(stagemod.GateRejected) as ctx:
                stagemod.stage(path, denylist=DENY, dry_run=True)
            self.assertEqual([f["rule"] for f in ctx.exception.findings], ["xcent"])

    def test_real_gate_home_path_severities(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "in.ipa")
            _tiny_ipa(path)
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("Payload/Demo.app/help.txt", "see /home/leakyuser1/.config and /Users/yourname/x\n")
            result = stagemod.stage(path, denylist=DENY, dry_run=True)
            self.assertEqual([(w["rule"], w["severity"]) for w in result.warnings], [("home-path", "warn")])
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("Payload/Demo.app/more.txt", "/Users/leakyuser1/src\n")
            with self.assertRaises(stagemod.GateRejected) as ctx:
                stagemod.stage(path, denylist=DENY, dry_run=True)
            self.assertIn(("home-path", "block"), [(f["rule"], f["severity"]) for f in ctx.exception.findings])


if __name__ == "__main__":
    unittest.main()
