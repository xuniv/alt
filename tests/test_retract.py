"""Tombstone files (``apps/<bid>/retracted.json``): format, strict and lenient reading."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from altsource import retract

BID = "io.example.demo"
DATE = "2026-10-23T08:09:10Z"


class RetractCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, data, bid=BID):
        path = os.path.join(self.root, "apps", bid, "retracted.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else json.dumps(data).encode())
        return path


class FormatTests(RetractCase):
    def test_dumps_is_canonical_and_sorted(self):
        data = retract.dumps({"1.10.0": {"reason": "unpublished", "date": DATE},
                              "1.2.0": {"date": DATE, "reason": "deleted"}})
        self.assertEqual(data.decode(), (
            '{\n  "schemaVersion": 1,\n  "versions": {\n'
            '    "1.10.0": {\n      "date": "%s",\n      "reason": "unpublished"\n    },\n'
            '    "1.2.0": {\n      "date": "%s",\n      "reason": "deleted"\n    }\n  }\n}\n') % (DATE, DATE))
        self.assertEqual(retract.parse(data), {"1.10.0": {"date": DATE, "reason": "unpublished"},
                                               "1.2.0": {"date": DATE, "reason": "deleted"}})
        self.assertEqual(retract.dumps({}), b'{\n  "schemaVersion": 1,\n  "versions": {}\n}\n')

    def test_entry_and_dumps_refuse_invalid_values(self):
        self.assertEqual(retract.entry(DATE, "deleted"), {"date": DATE, "reason": "deleted"})
        for date, reason in (("2026-10-23", "deleted"), (DATE, "removed"), (None, "deleted")):
            with self.assertRaises(retract.RetractError):
                retract.entry(date, reason)
        with self.assertRaises(retract.RetractError):
            retract.dumps({"v1": {"date": DATE, "reason": "deleted"}})

    def test_rel_path_validates_the_bundle_identifier(self):
        self.assertEqual(retract.rel_path(BID), "apps/io.example.demo/retracted.json")
        for bid in ("../x", "a/b", "", "io.example-v1.app", None):
            with self.assertRaises(retract.RetractError):
                retract.rel_path(bid)

    def test_strict_parse_rejects_anything_unexpected(self):
        good = {"schemaVersion": 1, "versions": {"1.0.0": {"date": DATE, "reason": "deleted"}}}
        bad = [
            b"{not json", b"\xff", b"[]",
            {"schemaVersion": 2, "versions": {}},
            {"schemaVersion": True, "versions": {}},
            {"schemaVersion": 1.0, "versions": {}},
            {"versions": {}},
            dict(good, extra=1),
            {"schemaVersion": 1, "versions": []},
            {"schemaVersion": 1, "versions": {"1.0": {"date": DATE, "reason": "deleted"}}},
            {"schemaVersion": 1, "versions": {"1.0.0-01": {"date": DATE, "reason": "deleted"}}},
            {"schemaVersion": 1, "versions": {"1.0.0": {"date": DATE}}},
            {"schemaVersion": 1, "versions": {"1.0.0": {"date": DATE, "reason": "deleted", "x": 1}}},
            {"schemaVersion": 1, "versions": {"1.0.0": {"date": "2026-10-23T08:09:10+01:00",
                                                        "reason": "deleted"}}},
        ]
        self.assertEqual(retract.parse(json.dumps(good).encode()), good["versions"])
        for obj in bad:
            with self.subTest(obj=obj):
                data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                with self.assertRaises(retract.RetractError):
                    retract.parse(data)
        with self.assertRaises(retract.RetractError):
            retract.parse(b" " * (retract.MAX_BYTES + 1))

    def test_lenient_parse_keeps_the_readable_entries(self):
        data = json.dumps({"schemaVersion": 1, "extra": True, "versions": {
            "1.0.0": {"date": DATE, "reason": "deleted"},
            "2.0": {"date": DATE, "reason": "deleted"},
            "1.1.0": {"date": DATE, "reason": "gone"}}}).encode()
        self.assertEqual(retract.parse_lenient(data), ({"1.0.0": {"date": DATE, "reason": "deleted"}}, 3))
        self.assertEqual(retract.parse_lenient(b"{not json"), ({}, 1))
        self.assertEqual(retract.parse_lenient(b"[1]"), ({}, 1))
        self.assertEqual(retract.parse_lenient(b'{"schemaVersion": 1}'), ({}, 1))
        self.assertEqual(retract.parse_lenient(retract.dumps({"1.0.0": {"date": DATE, "reason": "deleted"}})),
                         ({"1.0.0": {"date": DATE, "reason": "deleted"}}, 0))


class LoadTests(RetractCase):
    def test_missing_file_means_nothing_is_withdrawn(self):
        self.assertEqual(retract.load(self.root, BID), set())
        self.assertFalse(retract.is_retracted(self.root, BID, "1.0.0"))

    def test_load_and_is_retracted(self):
        self.write(retract.dumps({"1.0.0": {"date": DATE, "reason": "deleted"},
                                  "1.1.0-rc.1": {"date": DATE, "reason": "unpublished"}}))
        self.assertEqual(retract.load(self.root, BID), {"1.0.0", "1.1.0-rc.1"})
        self.assertTrue(retract.is_retracted(self.root, BID, "1.0.0"))
        self.assertTrue(retract.is_retracted(self.root, BID, "1.1.0-rc.1"))
        self.assertFalse(retract.is_retracted(self.root, BID, "1.1.0"))
        self.assertFalse(retract.is_retracted(self.root, "io.example.other", "1.0.0"))
        with self.assertRaises(retract.RetractError):
            retract.is_retracted(self.root, BID, "v1.0.0")

    def test_damaged_file_fails_instead_of_allowing_everything(self):
        self.write(b'{"schemaVersion": 1, "versions": {"1.0.0": "deleted"}}')
        with self.assertRaises(retract.RetractError) as ctx:
            retract.load(self.root, BID)
        self.assertNotIn("deleted", str(ctx.exception))  # no file text in messages
        with self.assertRaises(retract.RetractError):
            retract.is_retracted(self.root, BID, "1.0.0")

    def test_invalid_bundle_identifier_is_refused_before_any_file_access(self):
        self.write(retract.dumps({"1.0.0": {"date": DATE, "reason": "deleted"}}), bid="x")
        with self.assertRaises(retract.RetractError):
            retract.load(os.path.join(self.root, "apps", "x"), "..")


if __name__ == "__main__":
    unittest.main()
