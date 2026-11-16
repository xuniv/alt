import base64
import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from altsource import feather, gh

RELEASE = {
    'tag_name': 'v2.9.3', 'draft': False, 'prerelease': False,
    'assets': [{'name': 'Feather-unsigned.ipa', 'size': 100,
                'digest': 'sha256:' + 'a' * 64,
                'browser_download_url': 'https://github.com/xuniv/feather/releases/download/v2.9.3/Feather-unsigned.ipa'}]
}


class FeatherPollTests(unittest.TestCase):
    def test_pins_the_source_asset_digest_and_unprefixed_catalog_version(self):
        self.assertEqual(feather.candidate(RELEASE)['semver'], '2.9.3')
        self.assertEqual(feather.candidate(RELEASE)['sha256'], 'a' * 64)
        for values in ({'digest': None}, {'digest': 1}, {'size': True}, {'size': 0},
                       {'name': 'Feather.ipa'}, {'browser_download_url': 'https://example.test/a.ipa'}):
            obj = copy.deepcopy(RELEASE)
            obj['assets'][0].update(values)
            self.assertIsNone(feather.candidate(obj))
        for values in ({'draft': True}, {'prerelease': True}, {'tag_name': 'v2.9.2'},
                       {'tag_name': '2.9.3'}, {'tag_name': 'v2.09.3'}, {'tag_name': 'v2.9.3/evil'},
                       {'tag_name': 'v2.9.3-beta.1'}, {'assets': None}):
            obj = copy.deepcopy(RELEASE)
            obj.update(values)
            self.assertIsNone(feather.candidate(obj))
        obj = copy.deepcopy(RELEASE)
        obj['assets'].append(obj['assets'][0].copy())
        self.assertIsNone(feather.candidate(obj))
        self.assertIsNone(feather.candidate(None))

    def invoke(self, existing=False, withdrawn=False, recorded=False, pending=False, corrupt=False, corrupt_list=False):
        calls = []
        def api(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path.endswith('releases/latest'): return RELEASE
            if path.endswith('/releases'):
                if corrupt_list: return [None]
                return [{'tag_name': 'thewonderofyou.Feather-v2.9.3', 'draft': True}] if existing else []
            if path.endswith('retracted.json'):
                if corrupt: return {'content': base64.b64encode(b'{"versions": []}').decode()}
                if withdrawn:
                    data = json.dumps({'versions': {'2.9.3': {'reason': 'deleted'}}}).encode()
                    return {'content': base64.b64encode(data).decode()}
                raise gh.NotFound('missing', status=404)
            if '/versions/' in path:
                if recorded: return {'content': 'record'}
                raise gh.NotFound('missing', status=404)
            if path.endswith('/runs'): return {'workflow_runs': [{'status': 'queued'}] if pending else []}
            return None
        with patch.object(gh, 'client', return_value=SimpleNamespace(repo='xuniv/alt')):
            result = feather.poll(api)
        return result, calls

    def test_only_dispatches_existing_ingest_gate_without_relaxing_policy(self):
        _, calls = self.invoke()
        posts = [c for c in calls if c[0] == 'POST']
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], 'repos/xuniv/alt/actions/workflows/ingest.yml/dispatches')
        payload = posts[0][2]['json_body']
        self.assertEqual(payload['ref'], 'main')
        listing = next(c for c in calls if c[1].endswith('/releases'))
        self.assertTrue(listing[2]['paginate'])
        self.assertEqual(payload['inputs']['bundle_id'], 'thewonderofyou.Feather')
        self.assertEqual(payload['inputs']['allow_home_paths'], 'false')
        self.assertEqual(payload['inputs']['sha256'], 'a' * 64)

    def test_does_not_restore_drafts_withdrawals_or_unreconciled_version_records(self):
        for arguments in ({'existing': True}, {'withdrawn': True}, {'recorded': True}, {'pending': True}):
            _, calls = self.invoke(**arguments)
            self.assertFalse(any(c[0] == 'POST' for c in calls))
        with self.assertRaises(gh.GhError): self.invoke(corrupt=True)
        with self.assertRaises(gh.GhError): self.invoke(corrupt_list=True)

    def test_authorization_failures_are_errors(self):
        def denied(*args, **kwargs): raise gh.GhError('denied', status=403)
        with self.assertRaises(gh.GhError): feather.poll(denied)
