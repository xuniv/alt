"""Exercise the actual workflow's app-list script, without GitHub or credentials."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FeatherPollScopeTests(unittest.TestCase):
    def invoke(self, wanted, corrupt=False):
        workflow = (ROOT / '.github/workflows/poll.yml').read_text()
        step = workflow.split('- name: List apps', 1)[1].split('\n  check:', 1)[0]
        code = textwrap.dedent(re.search(r"python3 - <<'PY'\n(.*?)          PY", step, re.S)[1])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for bid, enabled in [('thewonderofyou.Feather', False), ('io.example.private', True), ('io.example.disabled', False)]:
                app = folder / 'apps' / bid / 'app.json'
                app.parent.mkdir(parents=True)
                app.write_text('{broken' if corrupt and bid == 'thewonderofyou.Feather' else json.dumps({'name': 'Test', 'privateBuild': {'enabled': enabled}}))
            output = folder / 'outputs'
            result = subprocess.run([sys.executable, '-c', code], cwd=folder, capture_output=True, text=True,
                                    env={**os.environ, 'APP': wanted, 'GITHUB_OUTPUT': str(output), 'PYTHONPATH': str(ROOT / 'tools')})
            return result.returncode, output.read_text() if output.exists() else ''

    def test_public_feather_scope_needs_no_private_build_matrix(self):
        code, output = self.invoke('thewonderofyou.Feather')
        self.assertEqual(code, 0)
        self.assertEqual(output, 'apps=[]\ncount=0\n')

    def test_all_apps_and_private_scope_retain_private_builds(self):
        for scope in ['', 'io.example.private']:
            code, output = self.invoke(scope)
            self.assertEqual(code, 0)
            self.assertIn('io.example.private', output)
            self.assertNotIn('thewonderofyou.Feather', output)
            self.assertIn('count=1', output)

    def test_unknown_disabled_and_corrupt_apps_still_fail(self):
        for scope in ['io.example.unknown', 'io.example.disabled']:
            self.assertEqual(self.invoke(scope)[0], 1)
        self.assertEqual(self.invoke('thewonderofyou.Feather', corrupt=True)[0], 1)
