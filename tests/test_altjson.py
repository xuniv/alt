"""``.alt.json``: format 1 (a build section) and format 2 (build, gate, scope)."""

import os
import plistlib
import tempfile
import unittest

from altsource import altjson, xcodes


class AltJsonTests(unittest.TestCase):
    def test_format_1_is_a_bare_build_section(self):
        parsed = altjson.parse({"runner": "xcode-27", "command": "make"})
        self.assertEqual((parsed.format, parsed.build, parsed.home_users, parsed.scope),
                         (1, {"runner": "xcode-27", "command": "make"}, (), None))
        with self.assertRaisesRegex(altjson.AltJsonError, r"1 unknown key\(s\)$"):
            altjson.parse({"runner": "xcode-27", "gate": {}})

    def test_format_2(self):
        parsed = altjson.parse({"version": 2, "build": {"xcode": "27.2", "command": "make"},
                                "gate": {"homeUsers": ["videolanci", "VideoLanCI"]},
                                "scope": {"tagPattern": r"^v(?P<version>\d+\.\d+\.\d+)$", "minVersion": "0.2.11",
                                          "prereleases": "build", "auto": False}})
        self.assertEqual(parsed.format, 2)
        self.assertEqual(parsed.home_users, ("videolanci",))
        self.assertEqual(parsed.scope, altjson.Scope(tag_pattern=r"^v(?P<version>\d+\.\d+\.\d+)$",
                                                     min_version="0.2.11", prereleases="build", auto=False))
        self.assertEqual(altjson.parse({"version": 2}).scope, None)
        self.assertEqual(altjson.parse({"version": 2, "scope": {}}).scope, altjson.Scope())

    def test_format_2_errors_never_quote_values(self):
        for obj in ({"version": "2"}, {"version": True}, {"version": 2, "bogus-key-0": 1},
                    {"version": 2, "build": {"secret-key-0": 1}}, {"version": 2, "build": []},
                    {"version": 2, "build": {"xcode": "27"}}, {"version": 2, "gate": {"homeUsers": "x"}},
                    {"version": 2, "scope": {"auto": "yes"}}, {"version": 2, "scope": {"tagPattern": "("}}):
            with self.assertRaises(altjson.AltJsonError, msg=repr(obj)) as ctx:
                altjson.parse(obj)
            self.assertNotIn("secret-key-0", str(ctx.exception))
            self.assertNotIn("bogus-key-0", str(ctx.exception))
        with self.assertRaisesRegex(altjson.AltJsonError, "bogus-key-0"):
            altjson.parse({"version": 2, "bogus-key-0": 1}, reveal=True)

    def test_loads_limits(self):
        self.assertEqual(altjson.loads(b'{"version": 2}').format, 2)
        for raw in (b"{", b"\xff", b" " * (altjson.MAX_BYTES + 1)):
            with self.assertRaises(altjson.AltJsonError):
                altjson.loads(raw)

    def test_policy_ref(self):
        for good in ("dev", "main", "release/2026", "a.b-c_d"):
            self.assertEqual(altjson.check_policy_ref(good), good)
        for bad in ("", "-x", "a..b", "a//b", "a/", "a.lock", "a@{1}", "x" * 101, 3, None):
            with self.assertRaises(altjson.AltJsonError, msg=repr(bad)):
                altjson.check_policy_ref(bad)


class XcodeTests(unittest.TestCase):
    def app(self, version, build, name):
        return xcodes.Xcode(path="/Applications/" + name, version=version, build=build,
                            kind=xcodes.kind_of(name))

    def test_release_first_then_release_candidate_never_beta(self):
        apps = [self.app("27.2", "27B48", "Xcode_27.2_Release_Candidate.app"),
                self.app("27.1", "27A9275", "Xcode_27.1.app"),
                self.app("27.0", "27A266a", "Xcode_27.app"),
                self.app("27.3", "27C5", "Xcode_27.3_beta.app")]
        self.assertEqual(xcodes.choose(apps, "27.2").build, "27B48")
        self.assertEqual(xcodes.choose(apps, "27.2").describe(), "Xcode 27.2 (27B48, release candidate)")
        apps.append(self.app("27.2", "27B52", "Xcode_27.2.app"))
        self.assertEqual(xcodes.choose(apps, "27.2").describe(), "Xcode 27.2 (27B52)")
        apps.append(self.app("27.2.1", "27B60", "Xcode_27.2.1.app"))
        self.assertEqual(xcodes.choose(apps, "27.2").build, "27B60")
        self.assertEqual(xcodes.choose(apps, "27.0").build, "27A266a")
        for want in ("27.3", "26.4", "27", "27.2.1", ""):
            with self.assertRaises(xcodes.XcodeError, msg=want):
                xcodes.choose(apps, want)

    def test_kinds(self):
        self.assertEqual(xcodes.kind_of("Xcode_27.2_Release_Candidate.app"), xcodes.RELEASE_CANDIDATE)
        self.assertEqual(xcodes.kind_of("Xcode_27.2_RC.app"), xcodes.RELEASE_CANDIDATE)
        self.assertEqual(xcodes.kind_of("Xcode_27.1_beta_2.app"), xcodes.BETA)
        self.assertEqual(xcodes.kind_of("Xcode_27.1.app"), xcodes.RELEASE)
        self.assertEqual(xcodes.kind_of("Xcode.app"), xcodes.RELEASE)

    def test_installed_follows_symlinks_once(self):
        with tempfile.TemporaryDirectory() as apps:
            def bundle(name, version, build):
                path = os.path.join(apps, name, "Contents")
                os.makedirs(path)
                with open(os.path.join(path, "version.plist"), "wb") as fh:
                    plistlib.dump({"CFBundleShortVersionString": version, "ProductBuildVersion": build}, fh)
            bundle("Xcode_27.2_Release_Candidate.app", "27.2", "27B48")
            bundle("Xcode_27.1.app", "27.1", "27A9275")
            os.symlink(os.path.join(apps, "Xcode_27.2_Release_Candidate.app"), os.path.join(apps, "Xcode_27.2.app"))
            os.symlink(os.path.join(apps, "Xcode_27.1.app"), os.path.join(apps, "Xcode.app"))
            os.makedirs(os.path.join(apps, "Xcode_broken.app"))
            found = xcodes.installed(apps)
            self.assertEqual(sorted((a.version, a.kind) for a in found),
                             [("27.1", "release"), ("27.2", "release candidate")])
            self.assertEqual(xcodes.choose(found, "27.2").path,
                             os.path.realpath(os.path.join(apps, "Xcode_27.2_Release_Candidate.app")))
        self.assertEqual(xcodes.installed("/nonexistent-dir"), [])


if __name__ == "__main__":
    unittest.main()
