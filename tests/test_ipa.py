"""Tests for IPA inspection: archive audit (zip attacks), bundle facts, signatures, privacy, icons."""

from __future__ import annotations

import json
import os
import plistlib
import struct
import tempfile
import unittest
import zipfile
from unittest import mock
import zlib

from altsource import ipa
from tests import helpers as h

APP = h.APP


class IpaCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.count = 0

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name=None):
        self.count += 1
        return os.path.join(self.dir, name or "app-%d.ipa" % self.count)

    def build(self, entries, **kw):
        return h.build_ipa(entries, self.path(), **kw)

    def raw(self, entries):
        return h.write_raw_zip(self.path(), entries)

    def inspect(self, entries, **kw):
        limits = kw.pop("limits", None)
        return ipa.inspect_ipa(self.build(entries, **kw), limits=limits)

    def assertRule(self, path_or_entries, rule, limits=None):
        path = path_or_entries if isinstance(path_or_entries, str) else self.build(path_or_entries)
        with self.assertRaises(ipa.IpaError) as ctx:
            ipa.inspect_ipa(path, limits=limits)
        self.assertEqual(ctx.exception.rule, rule)
        self.assertTrue(str(ctx.exception).startswith(rule))
        return ctx.exception

    def app_raw(self, *extra, plist=None):
        """Raw entries for a valid minimal app followed by ``extra``."""
        return [h.RawEntry(APP + "/Info.plist", plist or h.info_plist(), method=8),
                h.RawEntry(APP + "/Demo", h.macho(), external_attr=0o100755 << 16)] + list(extra)


class BasicTests(IpaCase):
    def test_minimal_unsigned_app(self):
        info = self.inspect(h.app_entries(display_name="Demo App"))
        self.assertEqual(info.bundle_id, "io.example.demo")
        self.assertEqual(info.short_version, "1.2.3")
        self.assertEqual(info.build_version, "7")
        self.assertEqual(info.name, "Demo App")
        self.assertEqual(info.executable, "Demo")
        self.assertEqual(info.min_os, "15.0")
        self.assertEqual(info.platforms, ["iPhoneOS"])
        self.assertEqual(info.app_dir, APP)
        self.assertEqual(info.signature, "none")
        self.assertEqual(info.entitlements, [])
        self.assertEqual(info.privacy, {})
        self.assertEqual(info.team_ids, [])
        self.assertEqual(info.macho_files, [APP + "/Demo"])
        self.assertEqual(info.macho_signatures, {APP + "/Demo": "none"})
        self.assertIsNone(info.icon)
        for key in ("extensions", "provisioning_profiles", "code_signature_dirs", "localizations", "dsym_like",
                    "encrypted_macho_files"):
            self.assertEqual(getattr(info, key), [], key)

    def test_to_dict_is_json_safe(self):
        entries = h.app_entries(extra={"NSCameraUsageDescription": "Scans codes."})
        entries[APP + "/AppIcon60x60@2x.png"] = h.png(120, 120)
        h.add_appex(entries, "Share")
        data = self.inspect(entries).to_dict()
        self.assertEqual(json.loads(json.dumps(data)), data)
        self.assertEqual(data["icon"], {"path": APP + "/AppIcon60x60@2x.png", "width": 120, "height": 120,
                                        "is_cgbi": False})
        self.assertEqual(data["extensions"][0]["kind"], "plugin")
        for key in ("bundle_id", "short_version", "build_version", "name", "executable", "min_os", "platforms",
                    "app_dir", "extensions", "privacy", "entitlements", "signature", "team_ids",
                    "provisioning_profiles", "code_signature_dirs", "localizations", "dsym_like", "icon",
                    "macho_files"):
            self.assertIn(key, data)

    def test_binary_plist_and_name_fallbacks(self):
        info = self.inspect(h.app_entries(binary=True, name="Plain"))
        self.assertEqual(info.name, "Plain")
        info = self.inspect(h.app_entries(name=None, display_name="  "))
        self.assertEqual(info.name, "")
        info = self.inspect(h.app_entries(version=None, build=None, min_os=None,
                                          extra={"CFBundleShortVersionString": 2}))
        self.assertEqual((info.short_version, info.build_version, info.min_os), ("", "", None))
        info = self.inspect(h.app_entries(bundle_id="", extra={"CFBundleSupportedPlatforms": "iPhoneOS"}))
        self.assertEqual((info.bundle_id, info.platforms), ("", []))

    def test_xml_plist_with_leading_whitespace(self):
        info = self.inspect(h.app_entries(plist=b"\n\t  " + h.info_plist()))
        self.assertEqual(info.bundle_id, "io.example.demo")

    def test_explicit_directory_entries_and_stored_members(self):
        info = self.inspect(h.app_entries(), dirs=True, compression=zipfile.ZIP_STORED)
        self.assertEqual(info.app_dir, APP)

    def test_matches_stage_fixture_shape(self):
        # the same shape the stage tests build: binary plist, header-only Mach-O, no directory entries
        info = self.inspect({APP + "/Info.plist": h.info_plist(binary=True),
                             APP + "/Demo": struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)})
        self.assertEqual((info.bundle_id, info.signature), ("io.example.demo", "none"))

    def test_junk_outside_payload_is_allowed(self):
        entries = h.app_entries()
        entries["__MACOSX/Payload/Other.app/._Info.plist"] = b"\x00\x05\x16\x07"
        entries["iTunesMetadata.plist"] = plistlib.dumps({})
        entries["Payload/.DS_Store"] = b"junk"
        self.assertEqual(self.inspect(entries).app_dir, APP)


class ArchiveTests(IpaCase):
    def test_not_a_zip(self):
        path = self.path()
        with open(path, "wb") as fh:
            fh.write(b"not a zip at all" * 10)
        self.assertRule(path, "zip-invalid")

    def test_missing_file_is_an_os_error(self):
        with self.assertRaises(OSError):
            ipa.inspect_ipa(os.path.join(self.dir, "absent.ipa"))

    def test_corrupt_member_data(self):
        path = self.raw(self.app_raw(h.RawEntry(APP + "/data.bin", b"x" * 100, crc=1234)))
        self.assertRule(path, "zip-corrupt")
        path = self.raw(self.app_raw(h.RawEntry(APP + "/data.bin", bytes(range(50)), method=8,
                                                compress_size=10)))
        self.assertRule(path, "zip-corrupt")

    def test_no_app(self):
        self.assertRule({"Payload/readme.txt": b"x"}, "ipa-no-app")
        self.assertRule({"Other/Demo.app/Info.plist": h.info_plist()}, "ipa-no-app")
        self.assertRule({"Payload/Demo.app": b"a file, not a bundle"}, "ipa-no-app")
        self.assertRule({"__MACOSX/Payload/Demo.app/Info.plist": h.info_plist()}, "ipa-no-app")

    def test_multiple_apps(self):
        entries = h.app_entries()
        entries.update(h.app_entries(app="Payload/Other.app"))
        self.assertRule(entries, "ipa-multiple-apps")

    def test_missing_or_bad_info_plist(self):
        self.assertRule({APP + "/Demo": h.macho()}, "plist-missing")
        self.assertRule({APP + "/Info.plist": b"garbage", APP + "/Demo": h.macho()}, "plist-invalid")
        self.assertRule({APP + "/Info.plist": plistlib.dumps(["array"]), APP + "/Demo": h.macho()}, "plist-invalid")
        entity = (b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY e "x">]><plist version="1.0"><dict>'
                  b'<key>CFBundleIdentifier</key><string>&e;</string></dict></plist>')
        self.assertRule({APP + "/Info.plist": entity, APP + "/Demo": h.macho()}, "plist-invalid")
        self.assertRule(h.app_entries(), "plist-too-large", limits=ipa.Limits(max_plist_size=100))
        self.assertRule({APP + "/Info.plist": ("symlink", "Other.plist"), APP + "/Other.plist": h.info_plist(),
                         APP + "/Demo": h.macho()}, "plist-missing")

    def test_executable_problems(self):
        self.assertRule(h.app_entries(plist=h.info_plist(omit=["CFBundleExecutable"])), "ipa-executable-missing")
        for bad in ("", ".", "..", "../Demo", "sub/Demo"):
            with self.subTest(executable=bad):
                entries = {APP + "/Info.plist": h.info_plist(executable=bad), APP + "/Demo": h.macho()}
                self.assertRule(entries, "ipa-executable-missing")
        self.assertRule({APP + "/Info.plist": h.info_plist()}, "ipa-executable-missing")
        self.assertRule(h.app_entries(exe=b"#!/bin/sh\necho hi\n"), "ipa-executable-invalid")
        self.assertRule(h.app_entries(exe=b"\xcf\xfa"), "ipa-executable-invalid")
        entries = h.app_entries()
        entries[APP + "/Demo"] = ("symlink", "Real")
        entries[APP + "/Real"] = h.macho()
        self.assertRule(entries, "ipa-executable-invalid")


class ZipAttackTests(IpaCase):
    def test_unsafe_names(self):
        cases = [
            (APP + "/../../evil", "zip-path-traversal"),
            ("../evil", "zip-path-traversal"),
            (APP + "/a/../../../x", "zip-path-traversal"),
            ("/etc/evil", "zip-path-absolute"),
            ("C:/evil", "zip-path-drive"),
            ("c:evil", "zip-path-drive"),
            (APP + "\\..\\evil", "zip-path-backslash"),
            (APP + "/a\\b", "zip-path-backslash"),
            (APP + "//double", "zip-path-invalid"),
            (APP + "/./dot", "zip-path-invalid"),
            (APP + "/line\nbreak", "zip-path-invalid"),
            (APP + "/Icon\r", "zip-path-invalid"),
            (APP + "/" + "x" * 1100, "zip-path-too-long"),
        ]
        for name, rule in cases:
            with self.subTest(name=name[:60]):
                err = self.assertRule(self.raw(self.app_raw(h.RawEntry(name, b"data"))), rule)
                self.assertIsNone(err.path)  # unsafe names are never echoed
                self.assertNotIn("evil", str(err))

    def test_nul_in_name(self):
        path = self.raw(self.app_raw(h.RawEntry(APP.encode() + b"/ok\x00../../evil", b"data")))
        self.assertRule(path, "zip-path-nul")

    def test_duplicate_names(self):
        path = self.raw(self.app_raw(h.RawEntry(APP + "/Demo", b"second copy")))
        self.assertRule(path, "zip-duplicate")
        path = self.raw(self.app_raw(h.RawEntry(APP + "/res", b"file"), h.RawEntry(APP + "/res/", b"",
                                                                                     external_attr=0o40755 << 16)))
        self.assertRule(path, "zip-duplicate")
        path = self.raw(self.app_raw(h.RawEntry(APP + "/res", b"file"), h.RawEntry(APP + "/res/inner", b"x")))
        self.assertRule(path, "zip-duplicate")

    def test_case_and_normalization_collisions(self):
        entries = h.app_entries()
        entries[APP + "/Readme.txt"] = b"a"
        entries[APP + "/README.txt"] = b"b"
        self.assertRule(entries, "zip-case-collision")
        entries = h.app_entries()
        entries[APP + "/Res/a"] = b"a"
        entries[APP + "/res/b"] = b"b"
        self.assertRule(entries, "zip-case-collision")
        entries = h.app_entries()
        entries[APP + "/caf\u00e9.txt"] = b"nfc"
        entries[APP + "/cafe\u0301.txt"] = b"nfd"
        self.assertRule(entries, "zip-case-collision")
        entries = h.app_entries()
        entries[APP + "/Res/a"] = b"a"
        entries[APP + "/Res/b"] = b"b"  # same directory spelled the same way is fine
        self.assertEqual(self.inspect(entries).app_dir, APP)

    def test_symlinks(self):
        ok = h.app_entries()
        ok[APP + "/Frameworks/A.framework/A"] = h.macho(filetype=h.MH_DYLIB)
        ok[APP + "/Current"] = ("symlink", "Frameworks/A.framework")
        ok[APP + "/Frameworks/B"] = ("symlink", "../Current/A")
        self.assertEqual(self.inspect(ok).app_dir, APP)
        escapes = {
            "absolute": ("symlink", "/etc/passwd"),
            "dotdot": ("symlink", "../../../../etc"),
            "to the bundle root": ("symlink", "."),
            "to the payload dir": ("symlink", ".."),
        }
        for label, link in escapes.items():
            with self.subTest(label):
                entries = h.app_entries()
                entries[APP + "/link"] = link
                self.assertRule(entries, "zip-symlink-escape")
        entries = h.app_entries()
        entries["Payload/outside"] = ("symlink", "Demo.app/Demo")
        self.assertRule(entries, "zip-symlink-escape")
        # each link stays inside on its own, but the chain leaves the bundle
        entries = h.app_entries()
        entries[APP + "/d1/d2/keep"] = b"x"
        entries[APP + "/d1/d2/y"] = ("symlink", "../../Frameworks")
        entries[APP + "/Frameworks/z"] = b"x"
        entries[APP + "/d1/d2/z"] = ("symlink", "y/../..")
        self.assertRule(entries, "zip-symlink-escape")
        loop = h.app_entries()
        loop[APP + "/a"] = ("symlink", "b")
        loop[APP + "/b"] = ("symlink", "a")
        self.assertRule(loop, "zip-symlink-invalid")
        big = h.app_entries()
        big[APP + "/link"] = ("symlink", "a/" * 600)
        self.assertRule(big, "zip-symlink-invalid")
        path = self.raw(self.app_raw(h.RawEntry(APP + "/link", b"", external_attr=0o120777 << 16)))
        self.assertRule(path, "zip-symlink-invalid")
        path = self.raw(self.app_raw(h.RawEntry(APP + "/link", b"\xff\xfe", external_attr=0o120777 << 16)))
        self.assertRule(path, "zip-symlink-invalid")

    def test_symlink_needs_unix_attributes(self):
        # without create_system 3 the mode bits mean nothing: a plain file
        path = self.raw(self.app_raw(h.RawEntry(APP + "/link", b"/etc/passwd", create_system=0,
                                                external_attr=0o120777 << 16)))
        self.assertEqual(ipa.inspect_ipa(path).app_dir, APP)

    def test_special_files(self):
        for mode in (0o010644, 0o020644, 0o060644, 0o140644, 0o040755):
            with self.subTest(mode=oct(mode)):
                path = self.raw(self.app_raw(h.RawEntry(APP + "/node", b"", external_attr=mode << 16)))
                self.assertRule(path, "zip-special-file")

    def test_directory_with_data(self):
        path = self.raw(self.app_raw(h.RawEntry(APP + "/dir/", b"payload", external_attr=0o40755 << 16)))
        self.assertRule(path, "zip-path-invalid")

    def test_encrypted_entries(self):
        for flags in (0x1, 0x41, 0x2000):
            with self.subTest(flags=flags):
                self.assertRule(self.raw(self.app_raw(h.RawEntry(APP + "/secret", b"x" * 20, flags=flags))),
                                "zip-encrypted")

    def test_compression_methods(self):
        for method in (12, 14, 93, 99):
            with self.subTest(method=method):
                self.assertRule(self.raw(self.app_raw(h.RawEntry(APP + "/blob", b"x" * 20, method=method))),
                                "zip-compression")

    def test_ratio_bomb(self):
        entries = h.app_entries()
        entries[APP + "/zeros"] = bytes(3 << 20)  # deflates about 1000:1
        err = self.assertRule(entries, "zip-bomb-ratio")
        self.assertEqual(err.path, APP + "/zeros")
        small = h.app_entries()
        small[APP + "/zeros"] = bytes(1 << 20)  # exactly at the threshold: not checked
        self.assertEqual(self.inspect(small).app_dir, APP)
        stored = h.app_entries()
        stored[APP + "/zeros"] = bytes(3 << 20)
        self.assertEqual(self.inspect(stored, compression=zipfile.ZIP_STORED).app_dir, APP)
        self.assertEqual(ipa.inspect_ipa(self.build(entries), limits=ipa.Limits(max_ratio=2000)).app_dir, APP)

    def test_declared_sizes(self):
        # sizes come from the central directory; nothing is inflated to find out
        huge = h.RawEntry(APP + "/huge", b"x", file_size=(2 << 30) + 1, compress_size=(2 << 30) // 100)
        self.assertRule(self.raw(self.app_raw(huge)), "zip-entry-size")
        self.assertRule(h.app_entries(), "zip-total-size", limits=ipa.Limits(max_total_size=500))
        self.assertRule(h.app_entries(), "zip-entry-size", limits=ipa.Limits(max_entry_size=100))

    def test_default_limits(self):
        lim = ipa.Limits()
        self.assertEqual((lim.max_entries, lim.max_total_size, lim.max_entry_size, lim.max_ratio,
                          lim.ratio_min_size, lim.max_plist_size),
                         (50_000, 4 << 30, 2 << 30, 200, 1 << 20, 8 << 20))

    def test_too_many_entries(self):
        entries = h.app_entries()
        for i in range(10):
            entries["%s/f%d" % (APP, i)] = b"x"
        self.assertRule(entries, "zip-too-many-entries", limits=ipa.Limits(max_entries=11))
        self.assertEqual(ipa.inspect_ipa(self.build(entries), limits=ipa.Limits(max_entries=12)).app_dir, APP)

    def test_overlapping_entries(self):
        shared = self.app_raw(h.RawEntry(APP + "/a", b"x" * 100),
                              h.RawEntry(APP + "/b", b"", local=False, offset_of=2))
        self.assertRule(self.raw(shared), "zip-overlap")
        spill = self.app_raw(h.RawEntry(APP + "/a", b"x" * 100, compress_size=500, file_size=500),
                             h.RawEntry(APP + "/b", b"y" * 100))
        self.assertRule(self.raw(spill), "zip-overlap")
        into_directory = self.app_raw(h.RawEntry(APP + "/a", b"x" * 100, compress_size=400, file_size=400))
        self.assertRule(self.raw(into_directory), "zip-overlap")

    def test_name_encoding(self):
        utf8 = "%s/r\u00e9sum\u00e9.txt" % APP
        flagged = self.raw(self.app_raw(h.RawEntry(utf8, b"x", flags=0x800)))
        self.assertEqual(ipa.inspect_ipa(flagged).app_dir, APP)
        unflagged = self.raw(self.app_raw(h.RawEntry(utf8.encode("utf-8"), b"x")))
        self.assertEqual(ipa.inspect_ipa(unflagged).app_dir, APP)
        collide = self.raw(self.app_raw(h.RawEntry(utf8.encode("utf-8"), b"x"),
                                        h.RawEntry(utf8.upper().replace("PAYLOAD/DEMO.APP", APP), b"y", flags=0x800)))
        self.assertRule(collide, "zip-case-collision")
        latin1 = self.raw(self.app_raw(h.RawEntry((APP + "/caf").encode() + b"\xe9", b"x")))
        self.assertRule(latin1, "zip-path-encoding")
        bad_flagged = self.raw(self.app_raw(h.RawEntry((APP + "/caf").encode() + b"\xe9", b"x", flags=0x800)))
        self.assertRule(bad_flagged, "zip-path-encoding")

    def test_unicode_path_field_must_agree(self):
        name = (APP + "/note.txt").encode()
        agree = self.raw(self.app_raw(h.RawEntry(name, b"x", extra=h.unicode_path_extra(APP + "/note.txt", name))))
        self.assertEqual(ipa.inspect_ipa(agree).app_dir, APP)
        lie = self.raw(self.app_raw(h.RawEntry(name, b"x", extra=h.unicode_path_extra("../../evil", name))))
        self.assertRule(lie, "zip-path-invalid")


class ExtensionTests(IpaCase):
    def test_plugins_and_extensionkit(self):
        entries = h.app_entries()
        h.add_appex(entries, "Share")
        h.add_appex(entries, "Widget", kind="Extensions")
        h.add_appex(entries, "Nested", app=APP + "/PlugIns/Share.appex")  # not enumerated (non-recursive)
        entries[APP + "/PlugIns/readme.txt"] = b"x"
        info = self.inspect(entries)
        self.assertEqual(info.extensions, [
            {"path": APP + "/PlugIns/Share.appex", "bundle_id": "io.example.demo.share", "kind": "plugin"},
            {"path": APP + "/Extensions/Widget.appex", "bundle_id": "io.example.demo.widget", "kind": "extensionkit"},
        ])
        self.assertEqual(len(info.macho_files), 4)

    def test_appex_without_bundle_id(self):
        entries = h.app_entries()
        h.add_appex(entries, "Share", plist=h.info_plist("", executable="Share"))
        self.assertIsNone(self.inspect(entries).extensions[0]["bundle_id"])

    def test_appex_requires_plist_and_executable(self):
        entries = h.app_entries()
        entries[APP + "/PlugIns/Share.appex/Share"] = h.macho()
        self.assertRule(entries, "plist-missing")
        entries = h.app_entries()
        bundle = h.add_appex(entries, "Widget", kind="Extensions")
        del entries[bundle + "/Widget"]
        self.assertRule(entries, "ipa-executable-missing")
        entries = h.app_entries()
        h.add_appex(entries, "Share", exe=b"plain text")
        self.assertRule(entries, "ipa-executable-invalid")


class PrivacyTests(IpaCase):
    def test_keys_and_synthesis(self):
        extra = {
            "NSCameraUsageDescription": "Scans codes.",
            "NFCReaderUsageDescription": "Reads tags.",
            "NSLocationTemporaryUsageDescriptionDictionary": {"Purpose": "Explains."},
            "NSMicrophoneUsageDescription": "",
            "NSContactsUsageDescription": "   ",
            "NSPhotoLibraryUsageDescription": 5,
            "NSUsageDescriptionFoo": "odd but matched",
            "UsageDescription": "no capture: ignored",
            "NSCameraUsage": "ignored",
            "UIBackgroundModes": ["audio"],
        }
        info = self.inspect(h.app_entries(display_name="Demo App", extra=extra))
        synth = "Used by Demo App."
        self.assertEqual(info.privacy, {
            "NFCReaderUsageDescription": "Reads tags.",
            "NSCameraUsageDescription": "Scans codes.",
            "NSContactsUsageDescription": synth,
            "NSLocationTemporaryUsageDescriptionDictionary": synth,
            "NSMicrophoneUsageDescription": synth,
            "NSPhotoLibraryUsageDescription": synth,
            "NSUsageDescriptionFoo": "odd but matched",
        })
        self.assertEqual(list(info.privacy), sorted(info.privacy))

    def test_plugins_count_extensionkit_does_not(self):
        entries = h.app_entries(extra={"NSCameraUsageDescription": "Main text.", "NSFaceIDUsageDescription": ""})
        h.add_appex(entries, "Share", extra={"NSCameraUsageDescription": "Plugin text.",
                                             "NSFaceIDUsageDescription": "Plugin face text.",
                                             "NSMotionUsageDescription": "Motion."})
        h.add_appex(entries, "Widget", kind="Extensions", extra={"NSMicrophoneUsageDescription": "Mic."})
        info = self.inspect(entries)
        self.assertEqual(info.privacy, {
            "NSCameraUsageDescription": "Main text.",
            "NSFaceIDUsageDescription": "Plugin face text.",  # a real text replaces a synthesized one
            "NSMotionUsageDescription": "Motion.",
        })

    def test_synthesized_name_falls_back(self):
        info = self.inspect(h.app_entries(name=None, extra={"NSCameraUsageDescription": ""}))
        self.assertEqual(info.privacy["NSCameraUsageDescription"], "Used by Demo.")


class SignatureTests(IpaCase):
    def entries_with(self, exe=None, framework=None):
        entries = h.app_entries(exe=exe)
        if framework is not None:
            entries[APP + "/Frameworks/Kit.framework/Kit"] = framework
            entries[APP + "/Frameworks/Kit.framework/Info.plist"] = h.info_plist("io.example.kit", executable="Kit")
        return entries

    def test_none_adhoc_signed(self):
        self.assertEqual(self.inspect(self.entries_with()).signature, "none")
        adhoc = h.macho(signature=h.code_signature())
        self.assertEqual(self.inspect(self.entries_with(adhoc)).signature, "adhoc")
        linker = h.macho(signature=h.code_signature(linker_signed=True, cms=None))
        self.assertEqual(self.inspect(self.entries_with(linker)).signature, "adhoc")
        cms = h.macho(signature=h.code_signature(cms=b"\x30\x80" + b"\x01" * 40, adhoc=False))
        self.assertEqual(self.inspect(self.entries_with(cms)).signature, "signed")
        team = h.macho(signature=h.code_signature(team_id="ABCDE12345"))
        info = self.inspect(self.entries_with(team))
        self.assertEqual((info.signature, info.team_ids), ("signed", ["ABCDE12345"]))

    def test_aggregate_is_the_worst_mach_o(self):
        signed_kit = h.macho(filetype=h.MH_DYLIB, signature=h.code_signature(cms=b"\x01" * 16, adhoc=False))
        info = self.inspect(self.entries_with(h.macho(signature=h.code_signature()), signed_kit))
        self.assertEqual(info.signature, "signed")
        self.assertEqual(info.macho_signatures, {APP + "/Demo": "adhoc",
                                                 APP + "/Frameworks/Kit.framework/Kit": "signed"})
        self.assertEqual(info.macho_files, sorted(info.macho_signatures))

    def test_fat_and_fat64_slices(self):
        for fat64 in (False, True):
            with self.subTest(fat64=fat64):
                exe = h.fat([h.macho(), h.macho(cpusubtype=h.SUB_ARM64E, signature=h.code_signature(
                    team_id="ABCDE12345"))], fat64=fat64)
                info = self.inspect(self.entries_with(exe))
                self.assertEqual(info.signature, "signed")

    def test_mach_o_found_by_magic_anywhere(self):
        entries = self.entries_with()
        entries[APP + "/resources/blob.dat"] = h.macho(filetype=h.MH_DYLIB, signature=h.code_signature())
        entries[APP + "/Java.class"] = struct.pack(">IHH", 0xCAFEBABE, 0, 52) + b"\x00" * 40
        entries[APP + "/tiny"] = b"\xcf\xfa\xed\xfe"
        info = self.inspect(entries)
        self.assertEqual(info.macho_files, [APP + "/Demo", APP + "/resources/blob.dat"])
        self.assertEqual(info.signature, "adhoc")

    def test_malformed_mach_o_anywhere_is_rejected(self):
        entries = self.entries_with()
        entries[APP + "/Frameworks/Kit.framework/Kit"] = h.macho()[:30]
        err = self.assertRule(entries, "macho-invalid")
        self.assertEqual(err.path, APP + "/Frameworks/Kit.framework/Kit")
        bad_sig = bytearray(h.macho(signature=h.code_signature()))
        struct.pack_into(">I", bad_sig, len(h.macho(signature=h.code_signature())) - 16, 0)  # padding only
        entries = self.entries_with(h.macho(signature=struct.pack(">III", 0xFADE0CC0, 9999, 0)))
        self.assertRule(entries, "macho-signature-invalid")

    def test_encrypted_mach_o_is_reported(self):
        info = self.inspect(self.entries_with(h.macho(cryptid=1)))
        self.assertEqual(info.encrypted_macho_files, [APP + "/Demo"])

    def test_one_encrypted_slice_marks_the_whole_file(self):
        clear = h.macho(cryptid=0)
        armv7 = h.macho(cputype=h.CPU_ARM, cpusubtype=h.SUB_ARMV7, bits=32, cryptid=0)
        entries = self.entries_with(h.fat([clear, h.macho(cputype=h.CPU_ARM, cpusubtype=h.SUB_ARMV7, bits=32,
                                                         cryptid=1)]))
        entries[APP + "/Frameworks/Kit.framework/Kit"] = h.fat([clear, armv7])
        entries[APP + "/Frameworks/Enc.framework/Enc"] = h.macho(filetype=h.MH_DYLIB, cryptid=3)
        info = self.inspect(entries)
        self.assertEqual(info.encrypted_macho_files, [APP + "/Demo", APP + "/Frameworks/Enc.framework/Enc"])
        self.assertEqual(self.inspect(self.entries_with(h.fat([clear, armv7]))).encrypted_macho_files, [])

    def test_large_mach_o_is_spooled(self):
        exe = h.macho(signature=h.code_signature(team_id="ABCDE12345"), body=b"\x00" * 4096)
        with mock.patch.object(ipa, "_IN_MEMORY", 1024):
            info = self.inspect(self.entries_with(exe))
        self.assertEqual(info.team_ids, ["ABCDE12345"])


class EntitlementTests(IpaCase):
    def exe(self, ents, **kw):
        return h.macho(signature=h.code_signature(entitlements=ents, **kw))

    def test_main_and_plugin_union_with_filtering(self):
        main = self.exe({"application-identifier": "io.example.demo", "com.apple.developer.team-identifier": "X",
                         "get-task-allow": False, "com.apple.security.application-groups": ["group.x"]})
        entries = h.app_entries(exe=main)
        h.add_appex(entries, "Share", exe=self.exe({"com.apple.developer.healthkit": True,
                                                    "application-identifier": "io.example.demo.share"}))
        h.add_appex(entries, "Widget", kind="Extensions", exe=self.exe({"com.apple.developer.siri": True}))
        entries[APP + "/Frameworks/Kit.framework/Kit"] = self.exe({"com.apple.developer.nfc": True})
        info = self.inspect(entries)
        self.assertEqual(info.entitlements, ["com.apple.developer.healthkit",
                                             "com.apple.security.application-groups"])
        self.assertEqual(info.team_ids, ["X"])

    def test_get_task_allow_rules(self):
        self.assertEqual(self.inspect(h.app_entries(exe=self.exe({"get-task-allow": True}))).entitlements,
                         ["get-task-allow"])
        self.assertEqual(self.inspect(h.app_entries(exe=self.exe({"get-task-allow": 0}))).entitlements,
                         ["get-task-allow"])
        entries = h.app_entries(exe=self.exe({"get-task-allow": False}))
        h.add_appex(entries, "Share", exe=self.exe({"get-task-allow": False}))
        self.assertEqual(self.inspect(entries).entitlements, [])
        entries = h.app_entries(exe=self.exe({"a": True}))
        h.add_appex(entries, "Share", exe=self.exe({"get-task-allow": False}))
        self.assertEqual(self.inspect(entries).entitlements, ["a", "get-task-allow"])

    def test_der_only_entitlements_are_listed(self):
        exe = h.macho(signature=h.code_signature(der={"com.apple.developer.nfc": True}))
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).entitlements, ["com.apple.developer.nfc"])

    def test_xml_and_der_keys_are_united(self):
        exe = h.macho(signature=h.code_signature(entitlements={"a": True, "get-task-allow": False},
                                                 der={"b": True, "get-task-allow": False}))
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).entitlements, ["a", "b"])
        exe = h.macho(signature=h.code_signature(entitlements={"get-task-allow": False},
                                                 der={"get-task-allow": True}))
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).entitlements, ["get-task-allow"])

    def test_every_fat_slice_counts(self):
        exe = h.fat([h.macho(signature=h.code_signature()),
                     h.macho(cpusubtype=h.SUB_ARM64E, signature=h.code_signature(entitlements={"second": True})),
                     h.macho(cputype=h.CPU_X86_64, cpusubtype=3,
                             signature=h.code_signature(entitlements={"third": True}))], fat64=True)
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).entitlements, ["second", "third"])

    def test_team_ids_from_der_entitlements(self):
        # DER-only entitlements still carry an extractable team identifier
        exe = h.macho(signature=h.code_signature(der={"com.apple.developer.team-identifier": "LEAKTEAM00"}))
        info = self.inspect(h.app_entries(exe=exe))
        self.assertEqual((info.team_ids, info.entitlements), (["LEAKTEAM00"], []))
        exe = h.fat([h.macho(signature=h.code_signature()), h.macho(
            cpusubtype=h.SUB_ARM64E, signature=h.code_signature(der={"application-identifier": "ABCDE12345.x"}))])
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).team_ids, ["ABCDE12345"])
        kit = h.macho(filetype=h.MH_DYLIB, signature=h.code_signature(
            der={"com.apple.developer.team-identifier": "KITTEAM000"}))
        entries = h.app_entries()
        entries[APP + "/Frameworks/Kit.framework/Kit"] = kit
        self.assertEqual(self.inspect(entries).team_ids, ["KITTEAM000"])

    def test_undecodable_der_entitlements_reject(self):
        for payload in (b"\x70\x80\x00", b"\x13\x01a", h.der_tlv(0x70, h.der_tlv(0x02, b"\x01"))):
            with self.subTest(payload=payload):
                exe = h.macho(signature=h.code_signature(der=payload))
                err = self.assertRule(h.app_entries(exe=exe), "macho-entitlements-invalid")
                self.assertEqual(err.path, APP + "/Demo")
        entries = h.app_entries()
        entries[APP + "/Frameworks/Kit.framework/Kit"] = h.macho(
            filetype=h.MH_DYLIB, signature=h.code_signature(der=b"\x13\x01a"))
        self.assertRule(entries, "macho-entitlements-invalid")

    def test_team_ids_from_entitlements(self):
        exe = self.exe({"application-identifier": "ABCDE12345.io.example.demo"})
        info = self.inspect(h.app_entries(exe=exe))
        self.assertEqual((info.team_ids, info.signature), (["ABCDE12345"], "adhoc"))
        exe = self.exe({"application-identifier": "io.example.demo"})
        self.assertEqual(self.inspect(h.app_entries(exe=exe)).team_ids, [])

    def test_invalid_entitlements_reject(self):
        self.assertRule(h.app_entries(exe=self.exe(b"<plist><array/></plist>")), "macho-entitlements-invalid")


class InventoryTests(IpaCase):
    def test_signing_debris_and_localizations(self):
        entries = h.app_entries()
        h.add_lproj(entries, "en", "Base", "it")
        entries[APP + "/sub/fr.lproj/x.strings"] = b"x"  # not at the app root
        entries[APP + "/embedded.mobileprovision"] = b"profile"
        h.add_appex(entries, "Share")
        entries[APP + "/PlugIns/Share.appex/embedded.MOBILEPROVISION"] = b"profile"
        entries[APP + "/Frameworks/K.framework/K.provisionprofile"] = b"profile"
        entries[APP + "/_CodeSignature/CodeResources"] = b"<plist/>"
        entries[APP + "/Frameworks/K.framework/_CodeSignature/CodeResources"] = b"<plist/>"
        entries[APP + "/Demo.app.dSYM/Contents/Info.plist"] = b"x"
        entries["Payload/Demo-dSYMs.dSYM.zip"] = b"zip"
        entries[APP + "/Symbols/Contents/Resources/DWARF/Demo"] = b"dwarf"
        entries[APP + "/debug.bin"] = h.macho(filetype=h.MH_DSYM)
        info = self.inspect(entries, dirs=True)
        self.assertEqual(info.localizations, ["Base.lproj", "en.lproj", "it.lproj"])
        self.assertEqual(info.provisioning_profiles, [
            APP + "/Frameworks/K.framework/K.provisionprofile",
            APP + "/PlugIns/Share.appex/embedded.MOBILEPROVISION",
            APP + "/embedded.mobileprovision",
        ])
        self.assertEqual(info.code_signature_dirs, [APP + "/Frameworks/K.framework/_CodeSignature",
                                                    APP + "/_CodeSignature"])
        self.assertEqual(info.dsym_like, [
            "Payload/Demo-dSYMs.dSYM.zip",
            APP + "/Demo.app.dSYM",
            APP + "/Symbols/Contents/Resources/DWARF/Demo",
            APP + "/debug.bin",
        ])


class IconTests(IpaCase):
    def icons_plist(self, **extra):
        return h.info_plist(extra=extra)

    def test_actool_layout_picks_the_largest(self):
        entries = h.app_entries(extra={
            "CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60"],
                                                      "CFBundleIconName": "AppIcon"}},
            "CFBundleIcons~ipad": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["AppIcon60x60", "AppIcon76x76"],
                                                           "CFBundleIconName": "AppIcon"}}})
        entries[APP + "/AppIcon60x60@2x.png"] = h.png(120, 120)
        entries[APP + "/AppIcon76x76@2x~ipad.png"] = h.cgbi_png(152, 152)
        entries[APP + "/Assets.car"] = b"car"
        info = self.inspect(entries)
        self.assertEqual((info.icon.path, info.icon.width, info.icon.height, info.icon.is_cgbi),
                         (APP + "/AppIcon76x76@2x~ipad.png", 152, 152, True))
        png = ipa.extract_icon(self.build(entries))
        w, hgt, channels, _ = h.decode_png(png)
        self.assertEqual((w, hgt, channels), (152, 152, 4))

    def test_legacy_keys_and_name_matching(self):
        entries = h.app_entries(extra={"CFBundleIconFiles": ["Icon"], "CFBundleIconFile": "Legacy.png"})
        entries[APP + "/icon@3x.PNG"] = h.png(180, 180)
        entries[APP + "/Legacy.png"] = h.png(57, 57)
        self.assertEqual(self.inspect(entries).icon.path, APP + "/icon@3x.PNG")
        entries = h.app_entries(extra={"CFBundleIconFile": "Legacy.png"})
        entries[APP + "/Legacy.png"] = h.png(57, 57)
        self.assertEqual(self.inspect(entries).icon.path, APP + "/Legacy.png")
        entries = h.app_entries(extra={"CFBundleIcons": {"CFBundlePrimaryIcon": "TV"}})
        entries[APP + "/TV@2x.png"] = h.png(64, 64)
        self.assertEqual(self.inspect(entries).icon.path, APP + "/TV@2x.png")

    def test_fallback_patterns_and_filters(self):
        entries = h.app_entries()
        entries[APP + "/AppIcon-Pro.png"] = h.png(80, 80)
        entries[APP + "/Icon-wide.png"] = h.png(100, 50)  # not square
        entries[APP + "/Assets/Icon-big.png"] = h.png(512, 512)  # not at the bundle root
        entries[APP + "/Icon-broken.png"] = b"\x89PNG\r\n\x1a\nbroken"
        entries[APP + "/Icon-link.png"] = ("symlink", "AppIcon-Pro.png")
        self.assertEqual(self.inspect(entries).icon.path, APP + "/AppIcon-Pro.png")

    def test_ties_keep_plist_order(self):
        entries = h.app_entries(extra={"CFBundleIconFiles": ["Second", "First"]})
        entries[APP + "/First.png"] = h.png(60, 60)
        entries[APP + "/Second.png"] = h.png(60, 60)
        self.assertEqual(self.inspect(entries).icon.path, APP + "/Second.png")

    def test_itunes_artwork_fallback(self):
        entries = h.app_entries()
        entries["iTunesArtwork"] = h.png(512, 512)
        info = self.inspect(entries)
        self.assertEqual((info.icon.path, info.icon.width), ("iTunesArtwork", 512))
        entries[APP + "/Icon.png"] = h.png(57, 57)
        self.assertEqual(self.inspect(entries).icon.path, APP + "/Icon.png")

    def test_no_icon(self):
        entries = h.app_entries()
        entries[APP + "/Assets.car"] = b"car"
        self.assertIsNone(self.inspect(entries).icon)
        self.assertIsNone(ipa.extract_icon(self.build(entries)))

    def test_size_limit(self):
        entries = h.app_entries()
        entries[APP + "/Icon.png"] = h.png(64, 64)
        self.assertIsNone(ipa.inspect_ipa(self.build(entries), limits=ipa.Limits(max_icon_size=100)).icon)

    def test_extract_converts_and_cleans(self):
        pixels = h.gradient(20, 20, 4, alphas=(255, 128, 0))
        entries = h.app_entries()
        entries[APP + "/Icon.png"] = h.cgbi_png(20, 20, pixels, filters=(0, 1, 2, 3, 4))
        png = ipa.extract_icon(self.build(entries))
        self.assertFalse(png[12:16] == b"CgBI")
        self.assertEqual(h.decode_png(png)[:3], (20, 20, 4))
        entries[APP + "/Icon.png"] = h.png(20, 20, pixels, ancillary=[(b"tEXt", b"Author\x00leaky-host-0")])
        png = ipa.extract_icon(self.build(entries))
        self.assertNotIn(b"leaky-host-0", png)
        self.assertEqual(h.decode_png(png)[3], pixels)

    def test_extract_skips_undecodable_candidates(self):
        entries = h.app_entries()
        broken = bytearray(h.png(200, 200))
        idat = broken.index(b"IDAT")
        broken[idat + 4:idat + 10] = b"\x00" * 6  # corrupt the zlib stream, keep the header
        entries[APP + "/Icon-large.png"] = bytes(broken)
        entries[APP + "/Icon-small.png"] = h.png(40, 40)
        path = self.build(entries)
        self.assertEqual(ipa.inspect_ipa(path).icon.path, APP + "/Icon-large.png")
        self.assertEqual(h.decode_png(ipa.extract_icon(path))[:2], (40, 40))

    def test_extract_audits_the_archive(self):
        entries = h.app_entries()
        entries[APP + "/link"] = ("symlink", "../../x")
        with self.assertRaises(ipa.IpaError):
            ipa.extract_icon(self.build(entries))

    def test_icon_basenames(self):
        info = {"CFBundleIcons": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["A", 5, "B"], "CFBundleIconName": "C"}},
                "CFBundleIcons~ipad": {"CFBundlePrimaryIcon": {"CFBundleIconFiles": ["A", "D"]}},
                "CFBundleIconFiles": ["E", "../F"], "CFBundleIconFile": "G.png"}
        self.assertEqual(ipa.icon_basenames(info), ["A", "B", "C", "D", "E", "G.png"])
        self.assertEqual(ipa.icon_basenames({"CFBundleIcons": "bad"}), [])


class ErrorTests(unittest.TestCase):
    def test_error_shape(self):
        err = ipa.IpaError("zip-bomb-ratio", path="Payload/A.app/x")
        self.assertEqual((err.rule, err.path, str(err)), ("zip-bomb-ratio", "Payload/A.app/x", "zip-bomb-ratio"))
        self.assertEqual(str(ipa.IpaError("macho-invalid", "bad cmdsize")), "macho-invalid: bad cmdsize")
        self.assertFalse(issubclass(ipa.IpaError, ValueError))

    def test_rule_ids_fit_the_pipeline_pattern(self):
        import re
        rules = re.findall(r"^([a-z]+(?:-[a-z0-9]+)+)\s{2,}", ipa.__doc__, re.M)
        self.assertGreater(len(rules), 25)
        for rule in rules:
            self.assertRegex(rule, r"^[a-z0-9][a-z0-9_.-]*$")


if __name__ == "__main__":
    unittest.main()
