"""Tests for the Mach-O reader: slices, signatures, entitlements (synthetic images only)."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from altsource import macho
from tests import helpers as h


def parse(data):
    return macho.parse_macho(data)


class DetectionTests(unittest.TestCase):
    def test_magics(self):
        self.assertTrue(macho.is_macho(h.macho()[:8]))
        self.assertTrue(macho.is_macho(h.macho(bits=32)[:8]))
        self.assertTrue(macho.is_macho(h.macho(big_endian=True)[:8]))
        self.assertTrue(macho.is_macho(h.fat([h.macho()])[:8]))
        self.assertTrue(macho.is_macho(h.fat([h.macho()], fat64=True)[:8]))

    def test_non_macho(self):
        java_class = struct.pack(">IHH", 0xCAFEBABE, 0, 52) + b"\x00" * 32
        self.assertFalse(macho.is_macho(java_class))
        self.assertFalse(macho.is_macho(struct.pack(">II", 0xCAFEBABE, 0)))
        self.assertFalse(macho.is_macho(b"\x89PNG\r\n\x1a\n"))
        self.assertFalse(macho.is_macho(b"\xcf\xfa\xed"))
        self.assertFalse(macho.is_macho(b""))


class ThinTests(unittest.TestCase):
    def test_unsigned_thin_variants(self):
        for kw in ({}, {"bits": 32, "cputype": h.CPU_ARM, "cpusubtype": h.SUB_ARMV7},
                   {"big_endian": True}, {"bits": 32, "big_endian": True}, {"cputype": h.CPU_X86_64, "cpusubtype": 3}):
            with self.subTest(**kw):
                m = parse(h.macho(**kw))
                self.assertFalse(m.fat)
                self.assertEqual(len(m.slices), 1)
                self.assertEqual(m.signature, "none")
                self.assertIsNone(m.entitlements)
                self.assertEqual(m.team_ids, [])
                self.assertEqual(m.slices[0].bits, kw.get("bits", 64))
                self.assertEqual(m.slices[0].big_endian, kw.get("big_endian", False))
        self.assertEqual(parse(h.macho()).slices[0].arch, "arm64")
        self.assertEqual(parse(h.macho(bits=32, cputype=h.CPU_ARM, cpusubtype=h.SUB_ARMV7)).slices[0].arch, "armv7")
        ptrauth = struct.unpack("<i", struct.pack("<I", 0x80000000 | h.SUB_ARM64E))[0]  # CPU_SUBTYPE_PTRAUTH_ABI
        self.assertEqual(parse(h.macho(cpusubtype=ptrauth)).slices[0].arch, "arm64e")

    def test_signed_variants_in_both_byte_orders(self):
        sig = h.code_signature(entitlements={"com.apple.security.app-sandbox": True})
        for kw in ({}, {"big_endian": True}, {"bits": 32}, {"bits": 32, "big_endian": True}):
            with self.subTest(**kw):
                m = parse(h.macho(signature=sig, **kw))
                self.assertEqual(m.signature, "adhoc")
                self.assertEqual(m.entitlements, {"com.apple.security.app-sandbox": True})

    def test_filetype_and_encryption(self):
        m = parse(h.macho(filetype=h.MH_DSYM, cryptid=1))
        self.assertEqual(m.filetypes, [macho.MH_DSYM])
        self.assertTrue(m.encrypted)
        self.assertFalse(parse(h.macho(cryptid=0)).encrypted)
        self.assertTrue(parse(h.macho(bits=32, cryptid=1)).encrypted)

    def test_parse_file_uses_a_memory_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bin")
            with open(path, "wb") as fh:
                fh.write(h.macho(signature=h.code_signature(team_id="ABCDE12345")))
            self.assertEqual(macho.parse_file(path).team_ids, ["ABCDE12345"])
            empty = os.path.join(tmp, "empty")
            open(empty, "wb").close()
            with self.assertRaises(macho.MachOError):
                macho.parse_file(empty)


class SignatureTests(unittest.TestCase):
    def sig(self, **kw):
        m = parse(h.macho(signature=h.code_signature(**kw)))
        return m.signature, m.slices[0].code_signature

    def test_adhoc(self):
        state, cs = self.sig()
        self.assertEqual(state, "adhoc")
        self.assertTrue(cs.adhoc)
        self.assertEqual(cs.cms_size, 0)
        self.assertEqual(cs.identifier, h.BUNDLE_ID)
        self.assertIsNone(cs.team_id)

    def test_adhoc_without_cms_slot(self):
        self.assertEqual(self.sig(cms=None)[0], "adhoc")

    def test_linker_signed(self):
        state, cs = self.sig(linker_signed=True, cms=None, requirements=False)
        self.assertEqual(state, "adhoc")
        self.assertTrue(cs.linker_signed)

    def test_cms_makes_it_signed(self):
        state, cs = self.sig(cms=b"\x30\x80" + b"\x00" * 30, adhoc=False)
        self.assertEqual(state, "signed")
        self.assertEqual(cs.cms_size, 32)

    def test_team_id_makes_it_signed(self):
        state, cs = self.sig(team_id="ABCDE12345")
        self.assertEqual(state, "signed")
        self.assertEqual(cs.team_id, "ABCDE12345")

    def test_team_offset_ignored_before_version_20200(self):
        state, cs = self.sig(team_id="ABCDE12345", cd_version=0x20100)
        self.assertEqual(state, "adhoc")
        self.assertIsNone(cs.team_id)
        for version in (0x20200, 0x20300, 0x20400):
            self.assertEqual(self.sig(team_id="ABCDE12345", cd_version=version)[1].team_id, "ABCDE12345")

    def test_alternate_code_directory(self):
        state, cs = self.sig(alternate_cd=True)
        self.assertEqual(state, "adhoc")
        self.assertEqual(cs.code_directories, 2)

    def test_fat_takes_the_worst_slice(self):
        signed = h.macho(cpusubtype=h.SUB_ARM64E, signature=h.code_signature(team_id="ABCDE12345"))
        m = parse(h.fat([h.macho(), signed]))
        self.assertEqual([s.signature for s in m.slices], ["none", "signed"])
        self.assertEqual(m.signature, "signed")
        self.assertEqual(m.team_ids, ["ABCDE12345"])

    def test_worst_signature(self):
        self.assertEqual(macho.worst_signature([]), "none")
        self.assertEqual(macho.worst_signature(["adhoc", "none"]), "adhoc")
        self.assertEqual(macho.worst_signature(["adhoc", "signed", "none"]), "signed")


class EntitlementTests(unittest.TestCase):
    ENTS = {"application-identifier": "io.example.demo", "get-task-allow": True,
            "keychain-access-groups": ["io.example.demo"]}

    def test_xml_slot_is_read(self):
        m = parse(h.macho(signature=h.code_signature(entitlements=self.ENTS)))
        self.assertEqual(m.entitlements, self.ENTS)
        self.assertEqual(m.all_entitlements, [self.ENTS])

    def test_der_slot_is_decoded_and_listed(self):
        m = parse(h.macho(signature=h.code_signature(der={"get-task-allow": True})))
        self.assertIsNone(m.entitlements)  # the XML form, as ldid and AltSign read it
        self.assertEqual(m.slices[0].code_signature.der_entitlements, {"get-task-allow": True})
        self.assertEqual(m.all_entitlements, [{"get-task-allow": True}])
        self.assertEqual(m.entitlement_errors, [])
        both = parse(h.fat([h.macho(signature=h.code_signature(entitlements={"a": True}, der={"b": True})),
                            h.macho(cpusubtype=h.SUB_ARM64E, signature=h.code_signature(der={"c": True}))]))
        self.assertEqual(both.all_entitlements, [{"a": True}, {"b": True}, {"c": True}])

    def test_der_decoding_both_forms(self):
        value = {"a": [1, -42, 300, True, False, "s"], "b": {"c": b"\x01\x02"}, "e": {}}
        self.assertEqual(macho.der_entitlements_to_dict(h.der_entitlements(value)), value)
        self.assertEqual(macho.der_entitlements_to_dict(h.der_entitlements(value, ldid=True)), value)
        self.assertEqual(macho.der_entitlements_to_dict(bytes.fromhex("70050201 01b000".replace(" ", ""))), {})
        long_value = {"k%03d" % i: "v" * 40 for i in range(20)}  # multi-byte DER lengths
        self.assertEqual(macho.der_entitlements_to_dict(h.der_entitlements(long_value)), long_value)

    def test_bad_der_is_recorded_not_fatal(self):
        for payload in (b"\x70\x80\x00", b"\x70\x03\x02\x01", h.der_tlv(0x70, h.der_tlv(0x02, b"\x01")),
                        h.der_tlv(0x70, h.der_tlv(0x02, b"\x01") + h.der_tlv(0x30, b"")), b"\x13\x01a"):
            with self.subTest(payload=payload):
                m = parse(h.macho(signature=h.code_signature(der=payload)))
                cs = m.slices[0].code_signature
                self.assertIsNone(cs.der_entitlements)
                self.assertTrue(cs.der_error)
                self.assertEqual(m.entitlement_errors, [cs.der_error])
                self.assertEqual(m.all_entitlements, [])

    def test_first_slice_with_xml_wins(self):
        a = h.macho(signature=h.code_signature(entitlements=b""))  # empty blob: skipped like ldid does
        b = h.macho(cpusubtype=h.SUB_ARM64E, signature=h.code_signature(entitlements={"b": True}))
        c = h.macho(cputype=h.CPU_X86_64, cpusubtype=3, signature=h.code_signature(entitlements={"c": True}))
        m = parse(h.fat([a, b, c]))
        self.assertEqual(m.entitlements, {"b": True})
        self.assertEqual(m.all_entitlements, [{"b": True}, {"c": True}])
        m64 = parse(h.fat([h.macho(), b], fat64=True))
        self.assertTrue(m64.fat64)
        self.assertEqual(m64.entitlements, {"b": True})

    def test_xml_with_leading_whitespace_and_trailing_nul(self):
        payload = b"\n  " + h.xml_entitlements({"a": True}) + b"\x00\x00"
        self.assertEqual(parse(h.macho(signature=h.code_signature(entitlements=payload))).entitlements, {"a": True})

    def test_invalid_xml_entitlements(self):
        entity = (b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY x "y">]>'
                  b'<plist version="1.0"><dict><key>a</key><string>&x;</string></dict></plist>')
        for payload in (b"not a plist", h.xml_entitlements(["array"]), entity):
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(macho.MachOError) as ctx:
                    parse(h.macho(signature=h.code_signature(entitlements=payload)))
                self.assertEqual(ctx.exception.rule, "macho-entitlements-invalid")


class MalformedTests(unittest.TestCase):
    def assertRule(self, data, rule):
        with self.assertRaises(macho.MachOError) as ctx:
            parse(data)
        self.assertEqual(ctx.exception.rule, rule)

    def test_truncated_and_bad_headers(self):
        good = h.macho()
        self.assertRule(good[:20], "macho-invalid")
        self.assertRule(good[:4], "macho-invalid")
        self.assertRule(b"\x00" * 64, "macho-invalid")
        too_many = bytearray(good)
        struct.pack_into("<I", too_many, 16, 500)  # ncmds
        self.assertRule(bytes(too_many), "macho-invalid")
        too_big = bytearray(good)
        struct.pack_into("<I", too_big, 20, 1 << 20)  # sizeofcmds
        self.assertRule(bytes(too_big), "macho-invalid")
        bad_cmdsize = bytearray(good)
        struct.pack_into("<I", bad_cmdsize, 36, 4)  # first load command's cmdsize
        self.assertRule(bytes(bad_cmdsize), "macho-invalid")

    def test_bad_fat_tables(self):
        good = h.fat([h.macho()])
        out_of_bounds = bytearray(good)
        struct.pack_into(">I", out_of_bounds, 8 + 12, len(good))  # size of slice 0
        self.assertRule(bytes(out_of_bounds), "macho-invalid")
        self.assertRule(good[:12], "macho-invalid")
        not_macho = bytearray(good)
        offset = struct.unpack_from(">I", good, 8 + 8)[0]
        not_macho[offset:offset + 4] = b"\x00\x00\x00\x00"
        self.assertRule(bytes(not_macho), "macho-invalid")
        overlap = h.fat([h.macho(), h.macho(cpusubtype=2)], align=4)
        table = bytearray(overlap)
        first_off = struct.unpack_from(">I", overlap, 8 + 8)[0]
        struct.pack_into(">I", table, 8 + 20 + 8, first_off + 8)  # slice 1 starts inside slice 0
        self.assertRule(bytes(table), "macho-invalid")

    def test_signature_bounds(self):
        data = bytearray(h.macho(signature=h.code_signature()))
        cmd_off = 32 + 24  # after the header and LC_UUID
        self.assertEqual(struct.unpack_from("<I", data, cmd_off)[0], h.LC_CODE_SIGNATURE)
        struct.pack_into("<I", data, cmd_off + 12, len(data))  # datasize past the end
        self.assertRule(bytes(data), "macho-signature-invalid")

    def _with_blob(self, sig):
        return h.macho(signature=sig)

    def test_superblob_rules(self):
        cd = h.code_directory()
        bad_magic = struct.pack(">III", 0xFADE0CC1, 12, 0)
        self.assertRule(self._with_blob(bad_magic), "macho-signature-invalid")
        too_many = bytearray(h.super_blob([(0, cd)]))
        struct.pack_into(">I", too_many, 8, 1000)  # count
        self.assertRule(self._with_blob(bytes(too_many)), "macho-signature-invalid")
        slots = h.super_blob([(0x20 + i, h.blob(0xFADE0000, b"")) for i in range(300)])
        self.assertRule(self._with_blob(slots), "macho-signature-invalid")
        long = bytearray(h.super_blob([(0, cd)]))
        struct.pack_into(">I", long, 4, len(long) + 1000)  # length past the data
        self.assertRule(self._with_blob(bytes(long)), "macho-signature-invalid")
        dup = h.super_blob([(5, h.blob(h.CSMAGIC_EMBEDDED_ENTITLEMENTS, b"")),
                            (5, h.blob(h.CSMAGIC_EMBEDDED_ENTITLEMENTS, b""))])
        self.assertRule(self._with_blob(dup), "macho-signature-invalid")
        blob_out = bytearray(h.super_blob([(0, cd)]))
        struct.pack_into(">I", blob_out, 16, 4096)  # offset of blob 0
        self.assertRule(self._with_blob(bytes(blob_out)), "macho-signature-invalid")
        wrong_cd = h.super_blob([(0, h.blob(0xFADE0C99, b"\x00" * 40))])
        self.assertRule(self._with_blob(wrong_cd), "macho-signature-invalid")
        short_cd = h.super_blob([(0, h.blob(h.CSMAGIC_CODEDIRECTORY, b"\x00" * 8))])
        self.assertRule(self._with_blob(short_cd), "macho-signature-invalid")
        wrong_ents = h.super_blob([(5, h.blob(0xFADE7172, b"<plist/>"))])
        self.assertRule(self._with_blob(wrong_ents), "macho-signature-invalid")

    def test_unterminated_team_id(self):
        cd = bytearray(h.code_directory(team_id="ABCDE12345"))
        cd[-1:] = b"X"  # the team id string loses its NUL
        self.assertRule(self._with_blob(h.super_blob([(0, bytes(cd))])), "macho-signature-invalid")

    def test_two_code_signature_commands(self):
        data = bytearray(h.macho(signature=h.code_signature(), uuid=True))
        uuid_off = 32
        sig_cmd = data[32 + 24:32 + 24 + 16]
        data[uuid_off:uuid_off + 16] = sig_cmd  # LC_UUID becomes a second LC_CODE_SIGNATURE ...
        struct.pack_into("<I", data, uuid_off + 4, 24)  # ... keeping its command size
        self.assertRule(bytes(data), "macho-signature-invalid")


if __name__ == "__main__":
    unittest.main()
