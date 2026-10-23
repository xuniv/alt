"""Deterministic IPA normalization: layout, determinism, idempotency, plists and refusals."""

from __future__ import annotations

import hashlib
import os
import plistlib
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile

from altsource import normalize as norm

APP = "Payload/Demo.app/"
MACHO = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
FAT = struct.pack(">II", 0xCAFEBABE, 0) + b"\x00" * 24
INFO = {
    "CFBundleIdentifier": "io.example.demo",
    "CFBundleShortVersionString": "1.2.3",
    "CFBundleVersion": "7",
    "CFBundleExecutable": "Demo",
    "CFBundleName": "Demo",
    "MinimumOSVersion": "15.0",
    "BuildMachineOSBuild": "00A000",
}


def entry(name, data=b"", *, mode=None, date_time=(2026, 10, 23, 16, 25, 0), create_system=3,
          compress=zipfile.ZIP_DEFLATED, extra=b"", comment=b""):
    """(ZipInfo, data) for ``write_zip``; ``mode`` is the full st_mode (type and permissions)."""
    zi = zipfile.ZipInfo(name, date_time=date_time)
    zi.create_system = create_system
    if mode is None:
        mode = 0o040755 if name.endswith("/") else 0o100644
    zi.external_attr = (mode << 16) | (0x10 if name.endswith("/") else 0)
    zi.compress_type = zipfile.ZIP_STORED if name.endswith("/") else compress
    zi.extra = extra
    zi.comment = comment
    return zi, data


def write_zip(path, entries, *, comment=b""):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate names are written on purpose by some tests
        with zipfile.ZipFile(path, "w") as zf:
            for zi, data in entries:
                zf.writestr(zi, data)
            zf.comment = comment
    return path


def binary_plist(obj):
    return plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)


def xml_plist(obj):
    return plistlib.dumps(obj, fmt=plistlib.FMT_XML)


def basic_entries():
    return [
        entry(APP + "Info.plist", binary_plist(INFO)),
        entry(APP + "Demo", MACHO, mode=0o100644),  # Mach-O without exec bit
        entry(APP + "en.lproj/Localizable.strings", b'"a" = "b";\n'),
    ]


def messy_entries():
    ut = struct.pack("<HHBI", 0x5455, 5, 1, 1700000000)  # extended timestamp extra field
    return [
        entry(APP + "run.sh", b"#!/bin/sh\necho hi\n", mode=0o100700, extra=ut),
        entry(APP + "Frameworks/Lib.framework/Lib", FAT, mode=0o100755, compress=zipfile.ZIP_STORED),
        entry(APP + "Frameworks/Lib.framework/Info.plist", xml_plist(dict(INFO, CFBundleExecutable="Lib"))),
        entry(APP + "Assets/plain.plist", xml_plist({"BuildMachineOSBuild": "kept"})),
        entry(APP + "Assets/notes.txt", b"hello\n" * 50, comment=b"entry comment"),
        entry(APP + "Current", b"Assets", mode=0o120777, compress=zipfile.ZIP_STORED),
        entry(APP + ".DS_Store", b"junk"),
        entry(APP + "Assets/._notes.txt", b"appledouble"),
        entry(APP + "Assets/thumbs.db", b"junk"),
        entry("__MACOSX/", b""),
        entry("__MACOSX/Payload/._Demo.app", b"junk"),
        entry(APP + "Empty/"),
    ] + basic_entries()


def read_names(path):
    with zipfile.ZipFile(path) as zf:
        return [zi.filename for zi in zf.infolist()]


def file_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def local_headers(path):
    """Fields of every local file header, parsed from the raw bytes."""
    raw = file_bytes(path)
    with zipfile.ZipFile(path) as zf:
        offsets = [zi.header_offset for zi in zf.infolist()]
    out = []
    for offset in offsets:
        fields = struct.unpack("<IHHHHHIIIHH", raw[offset:offset + 30])
        out.append({"sig": fields[0], "flags": fields[2], "time": fields[4], "date": fields[5],
                    "extra_len": fields[10]})
    return out


def patch_flags(path, bit):
    """Set a general purpose flag bit in every local and central header."""
    raw = bytearray(file_bytes(path))
    with zipfile.ZipFile(path) as zf:
        offsets = [zi.header_offset for zi in zf.infolist()]
        cd = zf.start_dir
    for offset in offsets:
        struct.pack_into("<H", raw, offset + 6, struct.unpack_from("<H", raw, offset + 6)[0] | bit)
    pos = cd
    while raw[pos:pos + 4] == b"PK\x01\x02":
        struct.pack_into("<H", raw, pos + 8, struct.unpack_from("<H", raw, pos + 8)[0] | bit)
        n, m, k = struct.unpack_from("<HHH", raw, pos + 28)
        pos += 46 + n + m + k
    with open(path, "wb") as fh:
        fh.write(bytes(raw))


class NormalizeCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def normalize(self, entries, *, comment=b"", **kwargs):
        src = write_zip(self.path("in.ipa"), entries, comment=comment)
        dst = self.path("out.ipa")
        return norm.normalize_ipa(src, dst, **kwargs), dst

    def assertRefused(self, entries, rule):
        src = write_zip(self.path("bad.ipa"), entries)
        with self.assertRaises(norm.NormalizeError) as ctx:
            norm.normalize_ipa(src, self.path("bad-out.ipa"))
        self.assertEqual(ctx.exception.rule, rule)
        self.assertIsInstance(ctx.exception, zipfile.BadZipFile)
        self.assertFalse(os.path.exists(self.path("bad-out.ipa")))
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".")], [])  # no temp files
        return ctx.exception


class LayoutTests(NormalizeCase):
    def test_entries_sorted_with_explicit_directories_and_junk_removed(self):
        report, dst = self.normalize(messy_entries())
        names = read_names(dst)
        self.assertEqual(names, sorted(names, key=lambda n: n.encode("utf-8")))
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            parts = name.rstrip("/").split("/")
            for i in range(1, len(parts)):
                self.assertIn("/".join(parts[:i]) + "/", names)
        self.assertIn(APP + "Empty/", names)
        self.assertFalse([n for n in names if "__MACOSX" in n or ".DS_Store" in n or "/._" in n
                          or n.lower().endswith("thumbs.db")])
        self.assertEqual(report.removed, sorted([
            "__MACOSX/", "__MACOSX/Payload/._Demo.app", APP + ".DS_Store", APP + "Assets/._notes.txt",
            APP + "Assets/thumbs.db"], key=lambda n: n.encode("utf-8")))
        self.assertEqual(report.entries, len(names))

    def test_root_itunes_metadata_is_removed(self):
        report, dst = self.normalize(basic_entries() + [
            entry("iTunesMetadata.plist", xml_plist({"purchaser": "placeholder"})),
            entry(APP + "iTunesMetadata.plist", b"inside the bundle"),
        ])
        names = read_names(dst)
        self.assertNotIn("iTunesMetadata.plist", names)
        self.assertIn(APP + "iTunesMetadata.plist", names)  # only the archive root is junk; the gate blocks it
        self.assertEqual(report.removed, ["iTunesMetadata.plist"])
        self.assertTrue(norm.is_junk("ITUNESMETADATA.PLIST"))
        self.assertFalse(norm.is_junk("iTunesMetadata.plist/"))

    def test_fixed_metadata_and_modes(self):
        _, dst = self.normalize(messy_entries(), comment=b"archive comment")
        with zipfile.ZipFile(dst) as zf:
            self.assertEqual(zf.comment, b"")
            self.assertIsNone(zf.testzip())
            modes = {}
            for zi in zf.infolist():
                self.assertEqual(zi.date_time, (1980, 1, 1, 0, 0, 0), zi.filename)
                self.assertEqual(zi.create_system, 3)
                self.assertEqual(zi.extra, b"")
                self.assertEqual(zi.comment, b"")
                self.assertEqual(zi.flag_bits & 0x8, 0)  # no data descriptors
                modes[zi.filename] = zi.external_attr
                if zi.filename.endswith("/") or zi.filename == APP + "Current":
                    self.assertEqual(zi.compress_type, zipfile.ZIP_STORED, zi.filename)
                else:
                    self.assertEqual(zi.compress_type, zipfile.ZIP_DEFLATED, zi.filename)
            self.assertEqual(zf.read(APP + "Current"), b"Assets")
            self.assertEqual(zf.read(APP + "Demo"), MACHO)
        self.assertEqual(modes["Payload/"], (0o040755 << 16) | 0x10)
        self.assertEqual(modes[APP + "Empty/"], (0o040755 << 16) | 0x10)
        self.assertEqual(modes[APP + "Demo"], 0o100755 << 16)  # Mach-O gains the exec bit
        self.assertEqual(modes[APP + "Frameworks/Lib.framework/Lib"], 0o100755 << 16)
        self.assertEqual(modes[APP + "run.sh"], 0o100755 << 16)  # any exec bit -> 755
        self.assertEqual(modes[APP + "Assets/notes.txt"], 0o100644 << 16)
        self.assertEqual(modes[APP + "Info.plist"], 0o100644 << 16)
        self.assertEqual(modes[APP + "Current"], 0o120777 << 16)
        for header in local_headers(dst):
            self.assertEqual(header["sig"], 0x04034B50)
            self.assertEqual(header["extra_len"], 0)
            self.assertEqual((header["time"], header["date"]), (0, 0x21))
            self.assertEqual(header["flags"] & 0x8, 0)

    def test_contents_preserved(self):
        entries = messy_entries()
        _, dst = self.normalize(entries)
        with zipfile.ZipFile(dst) as zf:
            for zi, data in entries:
                name = zi.filename
                if norm.is_junk(name) or name.endswith("/") or name.endswith("Info.plist"):
                    continue
                self.assertEqual(zf.read(name), data, name)

    def test_unix_mode_requires_unix_creator(self):
        entries = basic_entries() + [
            entry(APP + "tool", b"#!/bin/sh\n", mode=0o100755, create_system=0),
            entry(APP + "native", MACHO, mode=0, create_system=0),
        ]
        _, dst = self.normalize(entries)
        with zipfile.ZipFile(dst) as zf:
            self.assertEqual(zf.getinfo(APP + "tool").external_attr, 0o100644 << 16)
            self.assertEqual(zf.getinfo(APP + "native").external_attr, 0o100755 << 16)

    def test_utf8_name_without_flag_is_decoded_as_utf8(self):
        placeholder = APP + "cafXY.txt"
        real = (APP + "caf\u00e9.txt").encode("utf-8")
        self.assertEqual(len(placeholder.encode("ascii")), len(real))
        src = write_zip(self.path("in.ipa"), basic_entries() + [entry(placeholder, b"x")])
        raw = file_bytes(src).replace(placeholder.encode("ascii"), real)
        with open(src, "wb") as fh:
            fh.write(raw)
        with zipfile.ZipFile(src) as zf:
            self.assertNotIn(APP + "caf\u00e9.txt", zf.namelist())  # cp437 mojibake
        norm.normalize_ipa(src, self.path("out.ipa"))
        with zipfile.ZipFile(self.path("out.ipa")) as zf:
            zi = zf.getinfo(APP + "caf\u00e9.txt")
            self.assertTrue(zi.flag_bits & 0x800)
            self.assertEqual(zf.read(zi), b"x")

    def test_in_place(self):
        src = write_zip(self.path("in.ipa"), messy_entries())
        expected = norm.normalize_ipa(src, self.path("out.ipa")).output_sha256
        report = norm.normalize_ipa(src, src)
        self.assertEqual(report.output_sha256, expected)
        self.assertEqual(norm.sha256_file(src), expected)
        self.assertEqual(sorted(os.listdir(self.dir)), ["in.ipa", "out.ipa"])

    @unittest.skipIf(os.name != "posix", "POSIX permissions")
    def test_output_permissions(self):
        src = write_zip(self.path("in.ipa"), messy_entries())
        old = os.umask(0o027)
        try:
            norm.normalize_ipa(src, self.path("new.ipa"))  # a new file gets what the umask allows
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(self.path("new.ipa")).st_mode), 0o640)
        os.chmod(src, 0o604)
        norm.normalize_ipa(src, src)  # a replaced file keeps its permissions
        self.assertEqual(stat.S_IMODE(os.stat(src).st_mode), 0o604)

    def test_report(self):
        report, dst = self.normalize(messy_entries())
        src = self.path("in.ipa")
        self.assertEqual(report.input_sha256, hashlib.sha256(file_bytes(src)).hexdigest())
        self.assertEqual(report.output_sha256, hashlib.sha256(file_bytes(dst)).hexdigest())
        self.assertEqual(report.output_size, os.path.getsize(dst))
        self.assertTrue(report.changed)
        data = report.to_dict()
        self.assertEqual(sorted(data), ["changed", "entries", "input_sha256", "output_sha256", "output_size",
                                        "plist_keys_removed", "refused", "removed"])

    def test_writer_layout_is_stable(self):
        # stored entries and empty deflated files only: independent of the zlib build
        entries = [
            entry(APP + "Info.plist", b""),
            entry(APP + "a/b/empty.txt", b""),
            entry(APP + "link", b"a/b", mode=0o120777, compress=zipfile.ZIP_STORED),
            entry(APP + "x/"),
        ]
        report, dst = self.normalize(entries)
        raw = file_bytes(dst)
        self.assertEqual(len(raw), report.output_size)
        self.assertEqual(raw[-22:-18], b"PK\x05\x06")
        self.assertEqual(raw.count(b"PK\x03\x04"), 8)
        self.assertEqual(report.output_sha256, GOLDEN_STORED_SHA256)


# normalized form of the archive in test_writer_layout_is_stable (same on every Python version)
GOLDEN_STORED_SHA256 = "4da2b43754d936612ab9362cf95466cfc00e7595f52a5aa113b82160236dfe23"


class DeterminismTests(NormalizeCase):
    def test_same_bytes_for_any_order_timestamp_compression_and_extra_fields(self):
        a = messy_entries()
        b = []
        for zi, data in reversed(messy_entries()):
            alt = zipfile.ZipInfo(zi.filename, date_time=(2001, 2, 3, 4, 5, 6))
            alt.create_system = zi.create_system
            alt.external_attr = zi.external_attr
            alt.compress_type = zipfile.ZIP_STORED
            b.append((alt, data))
        ra = norm.normalize_ipa(write_zip(self.path("a.ipa"), a), self.path("a-out.ipa"))
        rb = norm.normalize_ipa(write_zip(self.path("b.ipa"), b, comment=b"c"), self.path("b-out.ipa"))
        self.assertNotEqual(ra.input_sha256, rb.input_sha256)
        self.assertEqual(ra.output_sha256, rb.output_sha256)
        self.assertEqual(file_bytes(self.path("a-out.ipa")), file_bytes(self.path("b-out.ipa")))

    def test_idempotent(self):
        first, dst = self.normalize(messy_entries())
        second = norm.normalize_ipa(dst, self.path("again.ipa"))
        self.assertEqual(file_bytes(dst), file_bytes(self.path("again.ipa")))
        self.assertFalse(second.changed)
        self.assertEqual(second.input_sha256, first.output_sha256)
        self.assertEqual(second.removed, [])
        self.assertEqual(second.plist_keys_removed, 0)


class PlistTests(NormalizeCase):
    def test_build_machine_removed_and_format_kept(self):
        report, dst = self.normalize(messy_entries())
        self.assertEqual(report.plist_keys_removed, 2)
        with zipfile.ZipFile(dst) as zf:
            main = zf.read(APP + "Info.plist")
            framework = zf.read(APP + "Frameworks/Lib.framework/Info.plist")
            other = zf.read(APP + "Assets/plain.plist")
        self.assertTrue(main.startswith(b"bplist00"))
        self.assertEqual(plistlib.loads(main), {k: v for k, v in INFO.items() if k != "BuildMachineOSBuild"})
        self.assertTrue(framework.startswith(b"<?xml"))
        self.assertNotIn("BuildMachineOSBuild", plistlib.loads(framework))
        self.assertEqual(plistlib.loads(framework)["CFBundleExecutable"], "Lib")
        self.assertEqual(other, xml_plist({"BuildMachineOSBuild": "kept"}))  # not an Info.plist

    def test_info_plist_without_key_is_byte_identical(self):
        data = binary_plist({"CFBundleIdentifier": "io.example.demo"})
        _, dst = self.normalize([entry(APP + "Info.plist", data)])
        with zipfile.ZipFile(dst) as zf:
            self.assertEqual(zf.read(APP + "Info.plist"), data)

    def test_strip_can_be_disabled(self):
        report, dst = self.normalize(messy_entries(), strip_build_machine=False)
        self.assertEqual(report.plist_keys_removed, 0)
        with zipfile.ZipFile(dst) as zf:
            self.assertEqual(zf.read(APP + "Info.plist"), binary_plist(INFO))

    def test_strip_plist_keys(self):
        self.assertEqual(norm.strip_plist_keys(b"not a plist"), (b"not a plist", False))
        self.assertEqual(norm.strip_plist_keys(binary_plist([1, 2])), (binary_plist([1, 2]), False))
        out, changed = norm.strip_plist_keys(b"\n  " + xml_plist(INFO))  # leading whitespace
        self.assertTrue(changed)
        self.assertNotIn("BuildMachineOSBuild", plistlib.loads(out))
        self.assertTrue(out.startswith(b"<?xml"))


class RefusalTests(NormalizeCase):
    def test_signing_material_is_kept_for_the_gate(self):
        entries = basic_entries() + [
            entry(APP + "embedded.mobileprovision", b"profile"),
            entry(APP + "_CodeSignature/CodeResources", xml_plist({"files": {}})),
            entry(APP + "PlugIns/Ext.appex/embedded.mobileprovision", b"profile"),
        ]
        report, dst = self.normalize(entries)
        names = read_names(dst)
        for name in (APP + "embedded.mobileprovision", APP + "_CodeSignature/CodeResources",
                     APP + "PlugIns/Ext.appex/embedded.mobileprovision"):
            self.assertIn(name, names)
            self.assertIn(name, report.refused)
        self.assertIn(APP + "_CodeSignature/", report.refused)

    def test_entitlement_files_are_kept_for_the_gate(self):
        name = APP + "archived-expanded-entitlements.xcent"
        report, dst = self.normalize(basic_entries() + [entry(name, xml_plist({"application-identifier": "x"}))])
        self.assertIn(name, read_names(dst))
        self.assertEqual(report.refused, [name])

    def test_unsafe_names(self):
        for name in ("../evil", "/abs/path", "Payload\\Demo.app\\x", "C:temp/x", "Payload//x",
                     "Payload/./x", "Payload/Demo.app/../../x"):
            with self.subTest(name=name):
                self.assertRefused(basic_entries() + [entry(name, b"x")], "zip-path")

    def test_duplicates_and_collisions(self):
        self.assertRefused(basic_entries() + [entry(APP + "dup", b"1"), entry(APP + "dup", b"2")],
                           "zip-duplicate")
        self.assertRefused(basic_entries() + [entry(APP + "Case", b"1"), entry(APP + "case", b"2")],
                           "zip-case-collision")
        self.assertRefused(basic_entries() + [entry(APP + "Dir/x", b"1"), entry(APP + "dir/y", b"2")],
                           "zip-case-collision")
        self.assertRefused(basic_entries() + [entry(APP + "both", b"1"), entry(APP + "both/x", b"2")],
                           "zip-duplicate")

    def test_symlinks(self):
        link = dict(mode=0o120777, compress=zipfile.ZIP_STORED)
        for target in (b"../../../etc/passwd", b"/etc/passwd", b"../Other.app/x", b"", b"a\\b"):
            with self.subTest(target=target):
                self.assertRefused(basic_entries() + [entry(APP + "link", target, **link)], "zip-symlink")
        self.assertRefused(basic_entries() + [entry("Payload/link", b"Demo.app", **link)], "zip-symlink")
        self.assertRefused(basic_entries() + [entry(APP + "link", b"x" * 2000, **link)], "zip-symlink")
        # each link looks harmless on its own; followed like a file system they reach the root
        chain = [entry(APP + "a", b".", **link), entry(APP + "b", b"a/..", **link), entry(APP + "c", b"b/..", **link)]
        self.assertRefused(basic_entries() + chain[:2], "zip-symlink")
        self.assertRefused(basic_entries() + chain, "zip-symlink")
        self.assertRefused(basic_entries() + [entry(APP + "p", b"q", **link), entry(APP + "q", b"p", **link)],
                           "zip-symlink")  # loop
        self.assertRefused(basic_entries() + [entry(APP + "Assets/x", b"../../Demo.app/Info.plist", **link)],
                           "zip-symlink")  # leaves the bundle on the way
        framework = APP + "Frameworks/K.framework/"
        _, dst = self.normalize(basic_entries() + [
            entry(APP + "a/link", b"../Info.plist", **link), entry(APP + "self", b".", **link),
            entry(framework + "Versions/A/K", MACHO), entry(framework + "Versions/Current", b"A", **link),
            entry(framework + "K", b"Versions/Current/K", **link),
            entry(framework + "Headers", b"Versions/Current/Headers", **link)])
        with zipfile.ZipFile(dst) as zf:
            self.assertEqual(zf.read(APP + "a/link"), b"../Info.plist")
            self.assertEqual(zf.getinfo(APP + "self").external_attr, 0o120777 << 16)

    def test_encrypted_entries(self):
        src = write_zip(self.path("bad.ipa"), basic_entries())
        patch_flags(src, 0x1)
        with self.assertRaises(norm.NormalizeError) as ctx:
            norm.normalize_ipa(src, self.path("bad-out.ipa"))
        self.assertEqual(ctx.exception.rule, "zip-encrypted")

    def test_limits(self):
        self.assertRefused(basic_entries() + [entry(APP + "zeros", b"\x00" * (2 << 20))], "zip-ratio")
        src = write_zip(self.path("bad.ipa"), basic_entries())
        with self.assertRaises(norm.NormalizeError) as ctx:
            norm.normalize_ipa(src, self.path("bad-out.ipa"), limits=norm.ZipLimits(max_entries=2))
        self.assertEqual(ctx.exception.rule, "zip-entries")
        with self.assertRaises(norm.NormalizeError) as ctx:
            norm.normalize_ipa(src, self.path("bad-out.ipa"), limits=norm.ZipLimits(max_entry=10))
        self.assertEqual(ctx.exception.rule, "zip-entry-size")
        with self.assertRaises(norm.NormalizeError) as ctx:
            norm.normalize_ipa(src, self.path("bad-out.ipa"), limits=norm.ZipLimits(max_total=100))
        self.assertEqual(ctx.exception.rule, "zip-total-size")

    def test_error_messages_carry_no_names(self):
        exc = self.assertRefused(basic_entries() + [entry("../leaky-host-0", b"x")], "zip-path")
        self.assertNotIn("leaky-host-0", str(exc))

    def test_not_a_zip(self):
        with open(self.path("bad.ipa"), "wb") as fh:
            fh.write(b"not a zip")
        with self.assertRaises(zipfile.BadZipFile):
            norm.normalize_ipa(self.path("bad.ipa"), self.path("bad-out.ipa"))
        self.assertEqual(os.listdir(self.dir), ["bad.ipa"])


if __name__ == "__main__":
    unittest.main()
