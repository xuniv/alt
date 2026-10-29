"""Leak gate: byte rules in every encoding, streaming windows, structural rules, fail-closed paths."""

from __future__ import annotations

import dataclasses
import io
import json
import os
import random
import re
import struct
import sys
import tempfile
import types
import unicodedata
import unittest
import zipfile
from unittest import mock

from altsource import leaks
from altsource import normalize as norm
from tests.test_normalize import APP, INFO, MACHO, binary_plist, entry, patch_flags, write_zip

WORD = "leaky-host-0"
USER = "leakyuser0"
DENY = [WORD, "# a comment", "  "]
CLEAN_INFO = {"signature": "none", "team_ids": [], "app_dir": APP.rstrip("/")}
ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
# the rule as written in the specification (all severities), for cross-checking the streaming matcher
SPEC_HOME = re.compile(
    rb"(/Users/|/home/|[A-Za-z]:\\Users\\)(?!runner[/\\]|Shared[/\\]|builder[/\\]|runneradmin[/\\])"
    rb"[A-Za-z0-9._-]{1,64}[/\\]")


def home_hits(counts):
    return counts.get(leaks.HOME_PATH, 0) + counts.get(leaks.HOME_PATH_WARN, 0)


def base_entries():
    return [
        entry(APP + "Info.plist", binary_plist(INFO)),
        entry(APP + "Demo", MACHO, mode=0o100755),
        entry(APP + "en.lproj/Localizable.strings", b'"a" = "b";\n'),
        entry(APP + "Base.lproj/Main.storyboardc/Info.plist", b"x"),
    ]


def noise(n, seed=0):
    """``n`` pseudo-random bytes without NUL or ASCII letters (so they cannot extend a match)."""
    raw = random.Random(seed).getrandbits(8 * n).to_bytes(n, "little") if n else b""
    return raw.translate(_NOISE)


_NOISE = bytes(b if b >= 0x80 else 0x80 | b for b in range(256))


class GateCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def ipa(self, extra=(), name="app.ipa", comment=b""):
        return write_zip(os.path.join(self.dir, name), base_entries() + list(extra), comment=comment)

    def scan(self, extra=(), *, info=CLEAN_INFO, denylist=DENY, policy=None, comment=b""):
        return leaks.scan_ipa(self.ipa(extra, comment=comment), denylist=denylist, policy=policy, info=info)

    def rules(self, result):
        return {f["rule"]: f for f in result.findings}

    def assertNoMatchedBytes(self, result, *secrets):
        text = json.dumps(result.to_dict()) + repr(result)
        for secret in secrets:
            self.assertNotIn(secret.lower(), text.lower())


class CleanTests(GateCase):
    def test_clean_ipa_passes(self):
        result = self.scan()
        self.assertTrue(result.ok)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.to_dict(), {"ok": True, "findings": []})

    def test_normalized_ipa_drops_junk_that_would_leak(self):
        src = self.ipa([entry("__MACOSX/Payload/Demo.app/._Demo", ("/Users/%s/x" % USER).encode())])
        raw = leaks.scan_ipa(src, denylist=DENY, info=CLEAN_INFO)
        self.assertEqual(self.rules(raw)["home-path"]["paths"], ["__MACOSX/Payload/Demo.app/._Demo"])
        out = os.path.join(self.dir, "normalized.ipa")
        norm.normalize_ipa(src, out)
        self.assertTrue(leaks.scan_ipa(out, denylist=DENY, info=CLEAN_INFO).ok)


class DenylistTests(GateCase):
    def test_every_encoding_and_case(self):
        for codec in ENCODINGS:
            for form in (WORD, WORD.upper(), "LeAkY-HoSt-0"):
                with self.subTest(codec=codec, form=form):
                    data = noise(300) + form.encode(codec) + noise(300, 1)
                    result = self.scan([entry(APP + "Demo.bin", data)])
                    self.assertFalse(result.ok)
                    finding = self.rules(result)["denylist"]
                    self.assertEqual(finding["severity"], "block")
                    self.assertEqual(finding["count"], 1)
                    self.assertEqual(finding["paths"], [APP + "Demo.bin"])
                    self.assertNoMatchedBytes(result, WORD)

    def test_non_latin_word_in_utf16_and_decomposed_utf8(self):
        word = "\u0141eaky-ho\u0301st"  # L with stroke; o + combining acute (NFD of o-acute)
        composed = unicodedata.normalize("NFC", word)
        for data in (composed.encode("utf-16-le"), composed.encode("utf-16-be"),
                     unicodedata.normalize("NFD", composed).encode("utf-8"), composed.upper().encode("utf-8")):
            with self.subTest(data=data):
                result = self.scan([entry(APP + "strings.bin", b"\x01" + data + b"\x02")], denylist=[composed])
                self.assertEqual(self.rules(result)["denylist"]["count"], 1)

    def test_counts_and_path_samples(self):
        extra = [entry(APP + "f%d.txt" % i, (WORD + " ") * 2) for i in range(7)]
        finding = self.rules(self.scan(extra))["denylist"]
        self.assertEqual(finding["count"], 14)
        self.assertEqual(finding["paths"], [APP + "f%d.txt" % i for i in range(5)])

    def test_names_comments_and_extra_fields_are_scanned(self):
        result = self.scan([entry(APP + "%s.log" % WORD, b"clean")])
        self.assertEqual(self.rules(result)["denylist"]["paths"], [APP + "%s.log" % WORD])
        result = self.scan(comment=("built on %s" % WORD).encode())
        self.assertEqual(self.rules(result)["denylist"]["paths"], [leaks.ZIP_COMMENT_PATH])
        result = self.scan([entry(APP + "a.txt", b"x", comment=WORD.encode())])
        self.assertEqual(self.rules(result)["denylist"]["paths"], [APP + "a.txt"])
        result = self.scan([entry(APP + "b.txt", b"x", extra=b"\xff\xfe" + bytes([len(WORD), 0]) + WORD.encode())])
        self.assertEqual(self.rules(result)["denylist"]["paths"], [APP + "b.txt"])

    def test_bytes_outside_the_entries_are_scanned(self):
        path = self.ipa()
        with open(path, "rb") as fh:
            raw = fh.read()
        gap = b"/Users/%s/" % USER.encode()  # between the last entry and the central directory
        cd = raw.index(b"PK\x01\x02")
        gapped = bytearray(raw[:cd] + gap + raw[cd:])
        struct.pack_into("<I", gapped, len(gapped) - 6, cd + len(gap))  # end record: directory offset
        for data in (WORD.encode() + raw, raw + WORD.encode("utf-16-le"), bytes(gapped)):
            with self.subTest(size=len(data)):
                with open(path, "wb") as fh:
                    fh.write(data)
                result = leaks.scan_ipa(path, denylist=DENY, info=CLEAN_INFO)
                self.assertFalse(result.ok)
                self.assertEqual([f["paths"] for f in result.findings], [[leaks.ZIP_LAYOUT_PATH]])
        with open(path, "wb") as fh:
            fh.write(raw)
        self.assertTrue(leaks.scan_ipa(path, denylist=DENY, info=CLEAN_INFO).ok)

    def test_prefix_words(self):
        result = self.scan([entry(APP + "a.txt", WORD + " leaky")], denylist=["leaky", WORD])
        self.assertEqual(self.rules(result)["denylist"]["count"], 2)

    def test_literals(self):
        lits = leaks.denylist_literals(["Ab"])
        self.assertEqual(lits, sorted({b"ab", b"a\x00b"}))  # UTF-16LE minus last byte == BE minus first
        lits = leaks.denylist_literals(["\u0141x"])  # not Latin-1: both byte orders, ASCII-lowercased
        for form in ("\u0141x", "\u0142x", "\u0141X"):
            for codec in ENCODINGS:
                self.assertIn(form.encode(codec).lower(), lits)


class HomePathTests(GateCase):
    BLOCKED = ["/Users/%s/Projects/app/main.swift" % USER, "/Users/%s\\x" % USER, "/Users/user0/x",
               "/Users/username-x/x"]
    WARNED = ["/home/%s/go/pkg/mod/x" % USER, "C:\\Users\\%s\\src\\x" % USER, "c:\\Users\\%s\\" % USER]
    BENIGN = ["/Users/runner/x", "/home/runner/workspace/x", "/Users/runner/work/_temp/src/x",
              "/home/runner/work/_actions/x", "/Users/runner/work/_tool/x", "/Users/Shared/x",
              "/home/builder/x", "/home/runner/x",
              "C:\\Users\\runneradmin\\x", "/Users/", "/Users//x", ":\\Users\\%s\\" % USER,
              "1:\\Users\\%s\\" % USER, "/users/%s/" % USER, "/Users/%s" % ("x" * 65 + "/"),
              "/Users/RUNNER/x", "/Users/user/x", "/Users/YourName/Documents", "/Users/your_name/x",
              "/Users/JohnDoe/x", "/home/user/.ssh/id_rsa", "/home/Me/x", "C:\\Users\\Admin\\x",
              "/Users/<user>/x", "/Users/$USER/x", "/Users/${USER}/x", "/Users/%USER%/x"]

    def test_users_paths_block_in_every_encoding(self):
        for codec in ENCODINGS:
            for text in self.BLOCKED:
                with self.subTest(codec=codec, text=text):
                    result = self.scan([entry(APP + "Demo.bin", b"\x07" + text.encode(codec) + b"\x07")])
                    self.assertEqual([(f["rule"], f["severity"], f["count"]) for f in result.findings],
                                     [("home-path", "block", 1)])
                    self.assertFalse(result.ok)
                    self.assertNoMatchedBytes(result, USER)

    def test_linux_and_windows_paths_only_warn(self):
        for codec in ENCODINGS:
            for text in self.WARNED:
                with self.subTest(codec=codec, text=text):
                    result = self.scan([entry(APP + "Demo.bin", b"\x07" + text.encode(codec) + b"\x07")])
                    self.assertEqual([(f["rule"], f["severity"], f["count"]) for f in result.findings],
                                     [("home-path", "warn", 1)])
                    self.assertTrue(result.ok)
                    self.assertNoMatchedBytes(result, USER)

    def test_blocking_and_warning_hits_are_reported_separately(self):
        text = " ".join([self.BLOCKED[0], self.WARNED[0], self.WARNED[1]])
        result = self.scan([entry(APP + "a.txt", text)])
        self.assertFalse(result.ok)
        self.assertEqual([(f["rule"], f["severity"], f["count"], f["paths"]) for f in result.findings],
                         [("home-path", "block", 1, [APP + "a.txt"]), ("home-path", "warn", 2, [APP + "a.txt"])])
        self.assertEqual([f["severity"] for f in result.blocking], ["block"])

    def test_ci_accounts_placeholders_and_non_matches(self):
        for codec in ENCODINGS:
            for text in self.BENIGN:
                with self.subTest(codec=codec, text=text):
                    data = b"\x07" + text.encode(codec) + b"\x07"
                    self.assertEqual(self.scan([entry(APP + "Demo.bin", data)]).findings, [])

    def test_allow_home_paths_turns_it_into_a_warning(self):
        policy = leaks.GatePolicy(allow_home_paths=True)
        result = self.scan([entry(APP + "a.txt", self.BLOCKED[0])], policy=policy)
        self.assertTrue(result.ok)
        self.assertEqual(self.rules(result)["home-path"]["severity"], "warn")
        self.assertEqual(result.warnings, result.findings)
        result = self.scan([entry(APP + "a.txt", self.BLOCKED[0] + " " + self.WARNED[0])], policy=policy)
        self.assertEqual([(f["rule"], f["severity"], f["count"]) for f in result.findings],
                         [("home-path", "warn", 2)])
        result = self.scan([entry(APP + "a.txt", self.BLOCKED[0] + " " + WORD)], policy=policy)
        self.assertFalse(result.ok)
        self.assertEqual([f["rule"] for f in result.blocking], ["denylist"])

    def test_home_users_only_warn_for_their_own_accounts(self):
        policy = leaks.GatePolicy(home_users=("thirdpartyci",))
        for codec in ENCODINGS:
            with self.subTest(codec=codec):
                data = b"\x07" + "/Users/thirdpartyci/vlc/src.c /Users/ThirdPartyCI/x".encode(codec) + b"\x07"
                result = self.scan([entry(APP + "Demo.bin", data)], policy=policy)
                self.assertTrue(result.ok)
                self.assertEqual([(f["rule"], f["severity"], f["count"]) for f in result.findings],
                                 [("home-path", "warn", 2)])
                data = b"\x07" + "/Users/thirdpartyci2/a /Users/leakyuser9/b".encode(codec) + b"\x07"
                result = self.scan([entry(APP + "Demo.bin", data)], policy=policy)
                self.assertFalse(result.ok)
                self.assertEqual([(f["rule"], f["severity"], f["count"]) for f in result.blocking],
                                 [("home-path", "block", 2)])
        result = self.scan([entry(APP + "a.txt", "/Users/thirdpartyci/" + WORD)], policy=policy)
        self.assertEqual([f["rule"] for f in result.blocking], ["denylist"])  # the denylist still applies

    def test_home_user_names_are_checked(self):
        self.assertEqual(leaks.check_home_users(["videolanci", "VideoLanCI", "ci.build-1"]),
                         ("videolanci", "ci.build-1"))
        for bad in ("not-a-list", [""], [".."], ["a/b"], ["a b"], ["x" * 65], [1], ["n%d" % i for i in range(17)]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                leaks.check_home_users(bad)
            if isinstance(bad, list):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    leaks.Matcher([WORD], bad)

    def test_policy_is_a_replaceable_dataclass(self):
        policy = dataclasses.replace(leaks.GatePolicy(), allow_home_paths=True)
        self.assertTrue(policy.allow_home_paths)
        self.assertFalse(policy.allow_empty_denylist)

    def test_runner_workspace_paths_warn_in_every_encoding(self):
        # a runner home is allowed, but the build path below its workspace names the repository
        for codec in ENCODINGS:
            for prefix in ("/Users/runner/work/", "/home/runner/work/"):
                with self.subTest(codec=codec, prefix=prefix):
                    text = prefix + "private-project-0/private-project-0/Source.swift"
                    data = b"\x07" + text.encode(codec) + b"\x00" + (prefix + "x").encode(codec)
                    result = self.scan([entry(APP + "Demo.bin", data)])
                    self.assertTrue(result.ok)
                    self.assertEqual([(f["rule"], f["severity"], f["count"], f["paths"]) for f in result.findings],
                                     [("ci-workspace-path", "warn", 2, [APP + "Demo.bin"])])
                    self.assertNoMatchedBytes(result, "private-project-0")
        policy = leaks.GatePolicy(allow_home_paths=True)
        result = self.scan([entry(APP + "a.txt", "/Users/runner/work/x/x/a.swift " + self.BLOCKED[0])], policy=policy)
        self.assertEqual([(f["rule"], f["severity"]) for f in result.findings],
                         [("ci-workspace-path", "warn"), ("home-path", "warn")])
        result = self.scan([entry(APP + "a.txt", "/Users/runner/work/x/x/a.swift " + WORD)])
        self.assertEqual([(f["rule"], f["severity"]) for f in result.findings],
                         [("ci-workspace-path", "warn"), ("denylist", "block")])

    def test_xcode_build_folder_of_the_runner_warns_in_every_encoding(self):
        prefix = "/Users/runner/Library/Developer/Xcode/DerivedData/"
        for codec in ENCODINGS:
            with self.subTest(codec=codec):
                text = prefix + "Private-Project-0-abcdefgh/Build/Products/Release-iphoneos/Kit_Kit.bundle"
                data = b"\x07" + text.encode(codec) + b"\x00" + (prefix + "x").encode(codec)
                result = self.scan([entry(APP + "Demo.bin", data)])
                self.assertTrue(result.ok)
                self.assertEqual([(f["rule"], f["severity"], f["count"], f["paths"]) for f in result.findings],
                                 [("ci-workspace-path", "warn", 2, [APP + "Demo.bin"])])
                self.assertNoMatchedBytes(result, "private-project-0")
        # the caches Xcode shares between projects name none; other runner directories are not counted
        shared = " ".join(prefix + d + "/x" for d in leaks.DERIVED_DATA_SHARED)
        others = "/Users/runner/Library/Developer/Xcode/Archives/x /Users/runner/Library/Caches/x"
        result = self.scan([entry(APP + "a.txt", shared + " " + others)])
        self.assertEqual(result.findings, [])
        policy = leaks.GatePolicy(allow_home_paths=True)  # stays a warning under the opt-in
        result = self.scan([entry(APP + "a.txt", prefix + "P-1/x " + WORD)], policy=policy)
        self.assertEqual([(f["rule"], f["severity"]) for f in result.findings],
                         [("ci-workspace-path", "warn"), ("denylist", "block")])

    def test_xcode_build_folder_in_text(self):
        prefix = "/Users/runner/Library/Developer/Xcode/DerivedData/"
        self.assertEqual(leaks.scan_text(prefix + "P-abc/SourcePackages/checkouts/k/a.swift", DENY),
                         ["ci-workspace-path"])
        self.assertEqual(leaks.scan_text(prefix + "ModuleCache.noindex/ABC/x.pcm", DENY), [])
        self.assertEqual(leaks.scan_text(prefix + "ModuleCache.noindexed/x", DENY), ["ci-workspace-path"])
        self.assertEqual(leaks.scan_text("/Users/runner/Library/Developer/Xcode/Archives/x", DENY), [])
        self.assertEqual(leaks.scan_bytes((prefix + "P").encode("utf-16-le"), DENY), ["ci-workspace-path"])

    def test_runner_workspace_path_in_text(self):
        self.assertEqual(leaks.scan_text("built in /home/runner/work/x/x", []), ["ci-workspace-path"])
        self.assertEqual(leaks.scan_text("/Users/runner/work/x/ and " + WORD, DENY), ["ci-workspace-path", "denylist"])
        self.assertEqual(leaks.scan_text("/Users/runner/x and /home/runner/workspace", DENY), [])
        self.assertEqual(leaks.scan_text("/Users/runner/work/_temp/src/a.swift", DENY), [])
        self.assertEqual(leaks.scan_text("/Users/runner/work/_temporary/a.swift", DENY), ["ci-workspace-path"])
        self.assertEqual(leaks.scan_bytes("/Users/runner/work/x".encode("utf-16-be"), DENY), ["ci-workspace-path"])


class StreamingTests(GateCase):
    PLANTS = [("/Users/%s/" % USER).encode(), ("C:\\Users\\%s\\" % USER).encode(),
              ("/home/%s/x" % USER).encode("utf-16-le"), ("/Users/%s/" % USER).encode("utf-16-be"),
              ("X:\\Users\\%s\\" % USER).encode("utf-16-le"), ("X:\\Users\\%s\\" % USER).encode("utf-16-be"),
              WORD.upper().encode(), WORD.encode("utf-16-be"), WORD.encode("utf-16-le"),
              b"/Users/runner/", b"/Users/Shared/", b"/Users/runner/work/", "/home/runner/work/".encode("utf-16-le"),
              "/Users/runner/work/".encode("utf-16-be"), "/Users/runner/work/_temp/".encode("utf-16-le"),
              b"/home/runner/work/_tool/", b"/Users/runner/Library/Developer/Xcode/DerivedData/",
              "/Users/runner/Library/Developer/Xcode/DerivedData/ModuleCache.noindex/".encode("utf-16-be")]

    def test_chunked_scan_equals_whole_scan(self):
        matcher = leaks.Matcher([WORD])
        rnd = random.Random(7)
        for trial in range(60):
            parts = []
            for _ in range(rnd.randint(0, 10)):
                parts.append(noise(rnd.randint(0, 200), trial))
                parts.append(rnd.choice(self.PLANTS))
            data = b"".join(parts)
            whole = matcher.scan_bytes(data)
            for size in (1, 2, 3, 5, 64, 157, 158, 1000):
                with self.subTest(trial=trial, size=size):
                    chunks = [data[i:i + size] for i in range(0, len(data), size)]
                    self.assertEqual(matcher.scan_chunks(chunks), whole)
                    self.assertEqual(matcher.scan_stream(io.BytesIO(data), chunk_size=size), whole)

    def test_single_byte_home_rule_matches_the_specification(self):
        matcher = leaks.Matcher([])
        rnd = random.Random(3)
        ascii_plants = [p for p in self.PLANTS if b"\x00" not in p]
        for trial in range(100):
            data = b"".join(noise(rnd.randint(0, 100), trial) + rnd.choice(ascii_plants)
                            for _ in range(rnd.randint(0, 8)))
            expected = len(SPEC_HOME.findall(data))
            self.assertEqual(home_hits(matcher.scan_bytes(data)), expected)

    def test_match_straddling_the_read_boundary(self):
        for codec in ENCODINGS:
            for plant in (WORD, "/Users/%s/" % USER, "/home/runner/work/"):
                for shift in (1, 3, 9):
                    with self.subTest(codec=codec, plant=plant, shift=shift):
                        raw = plant.encode(codec)
                        cut = leaks.CHUNK - shift
                        data = noise(cut, 5) + raw + noise(4096, 6)
                        result = self.scan([entry(APP + "big.bin", data, compress=zipfile.ZIP_STORED)])
                        rule = {WORD: "denylist", "/home/runner/work/": "ci-workspace-path"}.get(plant, "home-path")
                        self.assertEqual(self.rules(result)[rule]["count"], 1)

    def test_drive_letter_in_previous_read(self):
        matcher = leaks.Matcher([])
        for codec, text in (("utf-8", "C:\\Users\\%s\\" % USER), ("utf-16-le", "C:\\Users\\%s\\" % USER),
                            ("utf-16-be", "C:\\Users\\%s\\" % USER)):
            raw = b"\x07" * 300 + text.encode(codec)
            for size in range(1, 6):
                cut = 300 + size  # the drive letter ends one read, the colon starts the next
                chunks = [raw[:cut], raw[cut:]]
                self.assertEqual(matcher.scan_chunks(chunks), {leaks.HOME_PATH_WARN: 1}, (codec, size))


class StructuralTests(GateCase):
    def test_name_based_rules(self):
        cases = {
            "provisioning-profile": [APP + "embedded.mobileprovision", APP + "PlugIns/E.appex/embedded.mobileprovision"],
            "code-signature-dir": [APP + "_CodeSignature/CodeResources"],
            "dsym": [APP + "Demo.app.dSYM/Contents/Resources/DWARF/Demo"],
            "vcs-dir": [APP + ".git/config", APP + "Res/.svn/entries"],
            "xcuserdata": [APP + "x.xcodeproj/xcuserdata/u.xcuserdatad/UserInterfaceState.xcuserstate",
                           APP + "UserInterfaceState.xcuserstate"],
            "swiftsourceinfo": [APP + "Demo.swiftsourceinfo",
                                APP + "Frameworks/K.framework/Modules/K.swiftmodule/arm64.swiftinterface"],
            "itunes-metadata": ["iTunesMetadata.plist", APP + "ITUNESMETADATA.PLIST"],
            "xcent": [APP + "archived-expanded-entitlements.xcent", APP + "PlugIns/E.appex/E.XCENT"],
        }
        for rule, names in cases.items():
            with self.subTest(rule=rule):
                result = self.scan([entry(n, b"x") for n in names])
                finding = self.rules(result)[rule]
                self.assertEqual(finding["severity"], "block")
                self.assertFalse(result.ok)
                self.assertEqual(finding["paths"], sorted(names))
                self.assertEqual(finding["count"], len(names))

    def test_names_that_only_resemble_identity_files_pass(self):
        names = [APP + "iTunesMetadata.plist.txt", APP + "notes.xcentury", APP + "a.xcent/"]
        result = self.scan([entry(n, b"x") for n in names])
        self.assertEqual([f["rule"] for f in result.findings], [])
        self.assertTrue(result.ok)

    def test_info_based_rules(self):
        info = dict(CLEAN_INFO, provisioning_profiles=[APP + "x.mobileprovision"],
                    code_signature_dirs=[APP + "_CodeSignature/"], dsym_like=[APP + "Demo.dwarf"])
        rules = self.rules(self.scan(info=info))
        self.assertEqual(rules["provisioning-profile"]["paths"], [APP + "x.mobileprovision"])
        self.assertEqual(rules["code-signature-dir"]["paths"], [APP + "_CodeSignature/"])
        self.assertEqual(rules["dsym"]["paths"], [APP + "Demo.dwarf"])

    def test_signature_states(self):
        for state, rule in (("none", None), ("adhoc", None), ("signed", "signed"), (None, "signature-unknown"),
                            ("weird", "signature-unknown")):
            with self.subTest(state=state):
                info = dict(CLEAN_INFO)
                if state is None:
                    info.pop("signature")
                else:
                    info["signature"] = state
                result = self.scan(info=info)
                self.assertEqual([f["rule"] for f in result.findings], [rule] if rule else [])
                self.assertEqual(result.ok, rule is None)
        result = self.scan(info=dict(CLEAN_INFO, signature="adhoc", team_ids=["ABCDE12345"]))
        self.assertEqual(self.rules(result)["signed"]["count"], 1)
        result = self.scan(info=dict(CLEAN_INFO, signature="signed",
                                     signatures={APP + "Demo": "signed", APP + "PlugIns/E.appex/E": "adhoc"}))
        self.assertEqual(self.rules(result)["signed"]["paths"], [APP + "Demo"])

    def test_encrypted_binaries_block(self):
        paths = [APP + "Demo", APP + "Frameworks/K.framework/K"]
        result = self.scan(info=dict(CLEAN_INFO, encrypted_macho_files=paths))
        self.assertFalse(result.ok)
        self.assertEqual([(f["rule"], f["severity"], f["count"], f["paths"]) for f in result.findings],
                         [("encrypted-binary", "block", 2, paths)])
        self.assertTrue(self.scan(info=dict(CLEAN_INFO, encrypted_macho_files=[])).ok)

    def test_encrypted_slice_found_by_inspection(self):
        from tests import helpers as h

        clear = h.macho(cryptid=0)
        encrypted = h.macho(cputype=h.CPU_ARM, cpusubtype=9, bits=32, cryptid=1)
        for exe, blocked in ((h.fat([clear, encrypted]), True), (h.fat([clear]), False), (clear, False)):
            with self.subTest(blocked=blocked):
                entries = h.app_entries(exe=exe)
                entries[h.APP + "/Frameworks/K.framework/K"] = h.macho(filetype=h.MH_DYLIB)
                result = leaks.scan_ipa(h.build_ipa(entries, os.path.join(self.dir, "e.ipa")), denylist=DENY)
                rules = self.rules(result)
                self.assertEqual("encrypted-binary" in rules, blocked)
                if blocked:
                    self.assertEqual(rules["encrypted-binary"]["paths"], [h.APP + "/Demo"])
                    self.assertFalse(result.ok)

    def test_info_object_is_accepted(self):
        info = types.SimpleNamespace(**dict(CLEAN_INFO, signature="signed"))
        self.assertEqual([f["rule"] for f in self.scan(info=info).findings], ["signed"])

    def test_localizations(self):
        extra = [entry(APP + "it.lproj/Localizable.strings", b"x"), entry(APP + "en-GB.lproj/a.strings", b"x"),
                 entry(APP + "Frameworks/K.framework/ja.lproj/a.strings", b"x"), entry(APP + "fr.lproj/")]
        result = self.scan(extra, info=dict(CLEAN_INFO, localizations=["en", "it", "de.lproj"]))
        self.assertTrue(result.ok)
        finding = self.rules(result)["localization-non-en"]
        self.assertEqual(finding["severity"], "warn")
        self.assertEqual(finding["paths"], [APP + "fr.lproj/", APP + "it.lproj/", APP + "de.lproj/"])
        self.assertEqual(finding["count"], 3)


class FailClosedTests(GateCase):
    def test_empty_denylist(self):
        for denylist in ([], ["", "  ", "# only a comment"]):
            with self.assertRaises(leaks.GateError) as ctx:
                self.scan(denylist=denylist)
            self.assertEqual(ctx.exception.rule, "denylist-missing")
        result = self.scan([entry(APP + "a.txt", WORD)], denylist=[],
                           policy=leaks.GatePolicy(allow_empty_denylist=True))
        self.assertTrue(result.ok)

    def test_inspection_runs_when_info_is_absent(self):
        calls = []
        fake = types.ModuleType("altsource.ipa")

        def inspect_ipa(path):
            calls.append(path)
            return {"signature": "signed", "team_ids": ["ABCDE12345"]}

        fake.inspect_ipa = inspect_ipa
        path = self.ipa()
        with mock.patch.dict(sys.modules, {"altsource.ipa": fake}):
            result = leaks.scan_ipa(path, denylist=DENY)
        self.assertEqual(calls, [path])
        self.assertEqual([f["rule"] for f in result.findings], ["signed"])

    def test_inspection_errors_propagate(self):
        class FakeIpaError(Exception):
            rule = "zip-symlink"

        fake = types.ModuleType("altsource.ipa")

        def inspect_ipa(path):
            raise FakeIpaError()

        fake.inspect_ipa = inspect_ipa
        with mock.patch.dict(sys.modules, {"altsource.ipa": fake}):
            with self.assertRaises(FakeIpaError):
                leaks.scan_ipa(self.ipa(), denylist=DENY)

    def test_missing_inspection_module_fails_closed(self):
        with mock.patch.dict(sys.modules, {"altsource.ipa": None}):
            with self.assertRaises(leaks.GateError) as ctx:
                leaks.scan_ipa(self.ipa(), denylist=DENY)
        self.assertEqual(ctx.exception.rule, "gate-unavailable")

    def test_archive_problems_are_archive_errors(self):
        path = self.ipa()
        patch_flags(path, 0x1)
        with self.assertRaises(leaks.ScanError) as ctx:
            leaks.scan_ipa(path, denylist=DENY, info=CLEAN_INFO)
        self.assertEqual(ctx.exception.rule, "zip-encrypted")
        self.assertIsInstance(ctx.exception, zipfile.BadZipFile)
        with self.assertRaises(leaks.ScanError) as ctx:
            self.scan([entry(APP + "zeros", b"\x00" * (2 << 20))])
        self.assertEqual(ctx.exception.rule, "zip-ratio")
        with self.assertRaises(leaks.ScanError) as ctx:
            leaks.scan_ipa(self.ipa(), denylist=DENY, info=CLEAN_INFO, limits=norm.ZipLimits(max_entries=1))
        self.assertEqual(ctx.exception.rule, "zip-entries")

    def test_corrupt_data_raises(self):
        path = self.ipa([entry(APP + "data.bin", b"A" * 64 + b"tail", compress=zipfile.ZIP_STORED)])
        with open(path, "rb") as fh:
            raw = fh.read()
        with open(path, "wb") as fh:
            fh.write(raw.replace(b"A" * 64 + b"tail", b"B" * 64 + b"tail"))
        with self.assertRaises(zipfile.BadZipFile):
            leaks.scan_ipa(path, denylist=DENY, info=CLEAN_INFO)
        with open(path, "wb") as fh:
            fh.write(b"not a zip")
        with self.assertRaises(zipfile.BadZipFile):
            leaks.scan_ipa(path, denylist=DENY, info=CLEAN_INFO)


class TextTests(unittest.TestCase):
    def test_scan_text(self):
        self.assertEqual(leaks.scan_text("Fixes a crash.", DENY), [])
        self.assertEqual(leaks.scan_text("Built on " + WORD.upper(), DENY), ["denylist"])
        self.assertEqual(leaks.scan_text("see /Users/%s/notes" % USER, DENY), ["home-path"])
        self.assertEqual(leaks.scan_text("C:\\Users\\%s\\x and %s" % (USER, WORD), DENY), ["denylist", "home-path"])
        self.assertEqual(leaks.scan_text("/Users/runner/work and /Users/Shared/x", DENY), [])
        self.assertEqual(leaks.scan_text("/Users/%s/" % USER, []), ["home-path"])
        # text written for a release blocks on every prefix, but not on placeholder names
        self.assertEqual(leaks.scan_text("see /home/%s/x" % USER, DENY), ["home-path"])
        self.assertEqual(leaks.scan_text("/home/user/.ssh, /Users/YourName/x, C:\\Users\\Admin\\", DENY), [])
        self.assertEqual(leaks.scan_text("", DENY), [])
        self.assertEqual(leaks.scan_text(None, DENY), [])
        word = "Caf\u00e9-host"
        self.assertEqual(leaks.scan_text(unicodedata.normalize("NFD", word.upper()), [word]), ["denylist"])

    def test_scan_bytes(self):
        self.assertEqual(leaks.scan_bytes(WORD.encode("utf-16-le"), DENY), ["denylist"])
        self.assertEqual(leaks.scan_bytes(b"clean", DENY), [])
        self.assertEqual(leaks.scan_bytes(("/home/%s/" % USER).encode(), DENY), ["home-path"])


class DenylistLoadingTests(unittest.TestCase):
    def test_from_env_and_file(self):
        self.assertEqual(leaks.load_denylist(environ={"ALT_DENYLIST": "a\n\n# c\n b \na\n"}), ["a", "b"])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "deny")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x\ny\n")
            self.assertEqual(leaks.load_denylist(path, environ={"ALT_DENYLIST": "z"}), ["x", "y"])
            for env in ({}, {"ALT_DENYLIST": ""}, {"ALT_DENYLIST": "# only\n\n"}):
                with self.assertRaises(leaks.GateError):
                    leaks.load_denylist(environ=env)
            with self.assertRaises(leaks.GateError):
                leaks.load_denylist(os.path.join(tmp, "missing"), environ={})


if __name__ == "__main__":
    unittest.main()
