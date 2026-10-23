"""Tag grammar, SemVer precedence, version matching and secret aliases."""

from __future__ import annotations

import random
import unittest

from altsource import tags
from altsource.tags import SemVer, TagError


class ParseTagTests(unittest.TestCase):
    def test_valid_tags(self):
        cases = {
            "io.example.demo-v1.2.3": ("io.example.demo", "1.2.3"),
            "io.example.demo-v1.3.0-rc.1": ("io.example.demo", "1.3.0-rc.1"),
            "io.github.nuke-browser-v0.2.1": ("io.github.nuke-browser", "0.2.1"),
            "a-v0.0.0": ("a", "0.0.0"),
            "A1-v10.20.30": ("A1", "10.20.30"),
            "io.dev-vx-v1.0.0": ("io.dev-vx", "1.0.0"),  # "-v" without a digit is fine
            "a-v1.0.0-v2": ("a", "1.0.0-v2"),  # only one split yields a valid version
            "a-v1.0.0-0.3.7": ("a", "1.0.0-0.3.7"),
            "a-v1.0.0-x-y-z.--": ("a", "1.0.0-x-y-z.--"),
        }
        for tag, expected in cases.items():
            self.assertEqual(tags.parse_tag(tag), expected, tag)

    def test_invalid_tags(self):
        bad = [
            "", "v1.0.0", "-v1.0.0", "a-v", "a-v1", "a-v1.0", "a-v1.0.0.0", "a-v01.0.0", "a-v1.00.0",
            "a-V1.0.0", "a-1.0.0", "a-v1.0.0+build", "a-v1.0.0-rc+1", "a-v1.0.0-", "a-v1.0.0-rc..1",
            "a-v1.0.0-rc.", "a-v1.0.0-01", "a_b-v1.0.0", ".a-v1.0.0", "a.-v1.0.0", "a--v1.0.0",
            "a b-v1.0.0", "a-v1.0.0\n", " a-v1.0.0", "a-v1.0.0 ", "a-v١.0.0", "é-v1.0.0",
            "io.example.app-v2-v1.0.0",  # bundle id contains -v<digit>
            "a-v1.0.0-v2.0.0",  # ambiguous: a + 1.0.0-v2.0.0 or a-v1.0.0 + 2.0.0
        ]
        for tag in bad:
            with self.assertRaises(TagError, msg=repr(tag)):
                tags.parse_tag(tag)
        for value in (None, 1, b"a-v1.0.0"):
            with self.assertRaises(TagError):
                tags.parse_tag(value)

    def test_tag_error_is_a_value_error_with_a_rule(self):
        with self.assertRaises(ValueError) as ctx:
            tags.parse_tag("nope")
        self.assertEqual(ctx.exception.rule, "tag-grammar")

    def test_tag_re_matches_the_grammar(self):
        self.assertIsNotNone(tags.TAG_RE.match("io.example.demo-v1.2.3-beta.2"))
        self.assertIsNone(tags.TAG_RE.match("io.example.demo-v1.2.3+meta"))


class MakeTagTests(unittest.TestCase):
    def test_round_trip(self):
        for bid, ver in (("io.example.demo", "1.2.3"), ("a", "0.0.1-alpha.1"), ("a", "1.0.0-v2"),
                         ("io.dev-vx", "2.0.0")):
            tag = tags.make_tag(bid, ver)
            self.assertEqual(tag, "%s-v%s" % (bid, ver))
            self.assertEqual(tags.parse_tag(tag), (bid, ver))

    def test_accepts_semver_objects(self):
        self.assertEqual(tags.make_tag("io.example.demo", SemVer("1.0.0-rc.1")), "io.example.demo-v1.0.0-rc.1")

    def test_rejects(self):
        for bid, ver in (("", "1.0.0"), ("a-v2", "1.0.0"), ("io.app-v1x", "1.0.0"), ("a_b", "1.0.0"),
                         ("a.", "1.0.0"), ("a", "1.0"), ("a", "1.0.0+b"), ("a", "v1.0.0"),
                         ("a", "1.0.0-v2.0.0"), (None, "1.0.0")):
            with self.assertRaises(TagError, msg=(bid, ver)):
                tags.make_tag(bid, ver)

    def test_is_valid_bid(self):
        self.assertTrue(tags.is_valid_bid("io.github.nuke-browser"))
        self.assertTrue(tags.is_valid_bid("x"))
        for bid in ("", "-a", "a-", "a.v1", "io.a-v1", "a b", "a_b", None):
            self.assertEqual(tags.is_valid_bid(bid), bid == "a.v1", bid)


class SemVerTests(unittest.TestCase):
    ORDERED = [
        "0.9.9", "1.0.0-0", "1.0.0-2", "1.0.0-10", "1.0.0-B", "1.0.0-a", "1.0.0-alpha", "1.0.0-alpha.1",
        "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
        "1.0.1", "1.2.0", "1.10.0", "2.0.0", "2.1.0", "2.1.1", "10.0.0",
    ]

    def test_precedence(self):
        versions = [SemVer(v) for v in self.ORDERED]
        for low, high in zip(versions, versions[1:]):
            self.assertLess(low, high)
            self.assertGreater(high, low)
            self.assertNotEqual(low, high)
        shuffled = list(versions)
        random.Random(7).shuffle(shuffled)
        self.assertEqual([str(v) for v in sorted(shuffled)], self.ORDERED)

    def test_attributes(self):
        v = SemVer.parse("1.2.3-rc.1")
        self.assertEqual((v.major, v.minor, v.patch), (1, 2, 3))
        self.assertEqual(v.core, "1.2.3")
        self.assertEqual(v.prerelease, "rc.1")
        self.assertTrue(v.is_prerelease)
        self.assertEqual(str(v), "1.2.3-rc.1")
        self.assertEqual(repr(v), "SemVer('1.2.3-rc.1')")
        final = SemVer("1.2.3")
        self.assertIsNone(final.prerelease)
        self.assertFalse(final.is_prerelease)

    def test_equality_and_hash(self):
        self.assertEqual(SemVer("1.0.0"), SemVer("1.0.0"))
        self.assertEqual(len({SemVer("1.0.0"), SemVer("1.0.0"), SemVer("1.0.1")}), 2)
        self.assertNotEqual(SemVer("1.0.0"), "1.0.0")
        with self.assertRaises(TypeError):
            SemVer("1.0.0") < "1.0.1"  # noqa: B015

    def test_invalid(self):
        for text in ("", "1", "1.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+b", "1.0.0-a_b", "v1.0.0",
                     " 1.0.0", "1.0.0\n", "١.0.0", None, 1):
            with self.assertRaises(TagError, msg=repr(text)):
                SemVer(text)


class CoreMatchesTests(unittest.TestCase):
    def test_matches(self):
        for semver, short in (("1.2.0", "1.2"), ("1.2.0", "1.2.0"), ("1.0.0", "1"), ("1.2.3-rc.1", "1.2.3"),
                              ("1.2.3", "01.2.3"), ("0.0.0", "0"), ("1.2.3", " 1.2.3")):
            self.assertTrue(tags.core_matches(semver, short), (semver, short))
        self.assertTrue(tags.core_matches(SemVer("2.0.0"), "2.0"))

    def test_mismatches(self):
        for semver, short in (("1.2.3", "1.2.4"), ("1.2.3", "1.2.3b"), ("1.2.3", "1.2.3.0"), ("1.2.3", ""),
                              ("1.2.3", "1..3"), ("1.2.3", "1.2.٣"), ("1.2.3", "1.2.3-rc.1"),
                              ("1.2.0", "1.2.0."), ("1.2.3", None), ("1.2.3", 1.2)):
            self.assertFalse(tags.core_matches(semver, short), (semver, short))

    def test_invalid_semver_raises(self):
        with self.assertRaises(TagError):
            tags.core_matches("1.2", "1.2")


class AliasTests(unittest.TestCase):
    def test_alias(self):
        self.assertEqual(tags.alias_for("io.github.nukebrowser"), "IO_GITHUB_NUKEBROWSER")
        self.assertEqual(tags.alias_for("io.github.nuke-browser"), "IO_GITHUB_NUKE_BROWSER")
        self.assertEqual(tags.alias_for("a1.B2"), "A1_B2")
        self.assertEqual(tags.alias_for("ß.x"), "__X")  # one character in, one character out

    def test_alias_is_secret_name_safe(self):
        alias = tags.alias_for("Io.Example-App.v2")
        self.assertRegex(alias, r"^[A-Z0-9_]+$")


if __name__ == "__main__":
    unittest.main()
