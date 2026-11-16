import base64
import copy
import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from altsource import asspp, gh

RELEASE = {"tag_name": "4.2.4", "assets": [{"name": asspp.ASSET, "size": 123,
           "digest": "sha256:" + "a" * 64,
           "browser_download_url": "https://github.com/xuniv/Asspp/releases/download/4.2.4/Asspp-AltStore.ipa"}]}

class AssppPollTests(unittest.TestCase):
    def test_requires_the_specific_public_unsigned_variant_and_digest(self):
        self.assertEqual(asspp.candidate(RELEASE)["sha256"], "a" * 64)
        for change in ({"digest": None}, {"browser_download_url": "https://example.test/app.ipa"}, {"name": "Asspp.ipa"}):
            release = copy.deepcopy(RELEASE)
            release["assets"][0].update(change)
            self.assertIsNone(asspp.candidate(release))
        for change in ({"draft": True}, {"prerelease": True}, {"tag_name": "4.2.4/unsafe"}):
            release = copy.deepcopy(RELEASE)
            release.update(change)
            self.assertIsNone(asspp.candidate(release))

    def invoke(self, existing=False, withdrawn=False, pending=False):
        calls = []
        def api(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path.endswith("releases/latest"): return RELEASE
            if "/releases/tags/" in path:
                if existing: return {"draft": True}
                raise gh.NotFound("not found", status=404)
            if path.endswith("retracted.json"):
                if withdrawn:
                    raw = json.dumps({"versions": {"4.2.4": {"reason": "deleted"}}}).encode()
                    return {"content": base64.b64encode(raw).decode()}
                raise gh.NotFound("not found", status=404)
            if path.endswith("/runs"): return {"workflow_runs": [{"status": "queued"}] if pending else []}
            return None
        with patch.object(gh, "client", return_value=SimpleNamespace(repo="xuniv/alt")):
            result = asspp.poll(api)
        return result, calls

    def test_dispatches_only_to_the_existing_gate_with_pinned_hash(self):
        _, calls = self.invoke()
        posts = [call for call in calls if call[0] == "POST"]
        self.assertEqual(len(posts), 1)
        body = posts[0][2]["json_body"]
        self.assertEqual(body["ref"], "main")
        self.assertEqual(body["inputs"]["allow_home_paths"], "false")
        self.assertEqual(body["inputs"]["bundle_id"], asspp.BUNDLE)

    def test_never_republishes_withdrawn_existing_or_pending_versions(self):
        for arguments in ({"withdrawn": True}, {"existing": True}, {"pending": True}):
            _, calls = self.invoke(**arguments)
            self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_does_not_treat_authorization_failure_as_missing_release(self):
        def denied(*args, **kwargs): raise gh.GhError("denied", status=403)
        with self.assertRaises(gh.GhError): asspp.poll(denied)
