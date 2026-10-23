"""Tests for PNG probing and CgBI conversion (synthetic images; an independent decoder checks pixels)."""

from __future__ import annotations

import struct
import unittest
import zlib

from altsource import pngicon
from tests import helpers as h

ALPHAS = (255, 0, 1, 64, 127, 128, 200, 254)


def unpremultiplied(pixels: bytes) -> bytes:
    """What a straight-alpha image looks like after Apple's premultiply and our rounding inverse."""
    stored = h.premultiply(pixels)
    out = bytearray(stored)
    for i in range(0, len(out), 4):
        a = out[i + 3]
        for j in range(3):
            out[i + j] = 0 if a == 0 else min(255, (stored[i + j] * 255 + a // 2) // a)
    return bytes(out)


class HeaderTests(unittest.TestCase):
    def test_standard_and_cgbi_headers(self):
        hdr = pngicon.read_header(h.png(8, 6))
        self.assertEqual((hdr.width, hdr.height, hdr.bit_depth, hdr.color_type, hdr.cgbi), (8, 6, 8, 6, False))
        hdr = pngicon.read_header(h.cgbi_png(5, 5)[:64])
        self.assertEqual((hdr.width, hdr.height, hdr.cgbi), (5, 5, True))
        self.assertTrue(pngicon.is_cgbi(h.cgbi_png(2, 2)))
        self.assertFalse(pngicon.is_cgbi(h.png(2, 2)))
        self.assertTrue(pngicon.is_png(h.png(2, 2)))

    def test_bad_headers(self):
        good = h.png(4, 4)
        for data in (b"", b"GIF89a", good[:20], good[:8] + h.png_chunk(b"tEXt", b"a\x00b") + good[8:],
                     h.png(4, 4)[:16] + struct.pack(">II", 0, 4) + good[24:]):
            with self.subTest(data=data[:30]):
                with self.assertRaises(pngicon.PNGError):
                    pngicon.read_header(data)
        bad_type = bytearray(good)
        bad_type[25] = 5  # colour type 5 does not exist
        with self.assertRaises(pngicon.PNGError):
            pngicon.read_header(bytes(bad_type))


class StandardPngTests(unittest.TestCase):
    def test_reencode_keeps_pixels_and_drops_metadata(self):
        pixels = h.gradient(9, 7, 4, alphas=ALPHAS)
        src = h.png(9, 7, pixels, filters=(0, 1, 2, 3, 4), idat_parts=3,
                    ancillary=[(b"sRGB", b"\x00"), (b"tEXt", b"Comment\x00leaky-host-0"), (b"pHYs", b"\x00" * 9)],
                    trailing=[(b"tIME", b"\x07\xe4\x01\x01\x00\x00\x00"), (b"eXIf", b"MM\x00*")])
        out = pngicon.to_png(src)
        self.assertEqual(h.chunk_types(out), [b"IHDR", b"sRGB", b"pHYs", b"IDAT", b"IEND"])
        self.assertNotIn(b"leaky-host-0", out)
        self.assertEqual(h.decode_png(out), (9, 7, 4, pixels))
        self.assertEqual(pngicon.to_png(out), out)  # deterministic and idempotent

    def test_rgb_gray_palette_and_16_bit_pass_through(self):
        rgb = h.gradient(6, 3, 3)
        self.assertEqual(h.decode_png(pngicon.to_png(h.png(6, 3, rgb, color_type=2, filters=(4,)))), (6, 3, 3, rgb))
        gray = pngicon.to_png(h.png(5, 5, bytes(range(25)), color_type=0))
        self.assertEqual(pngicon.read_header(gray).color_type, 0)
        palette = h.png(4, 4, bytes(16), color_type=3, ancillary=[(b"PLTE", b"\x00\x00\x00\xff\xff\xff")])
        self.assertIn(b"PLTE", h.chunk_types(pngicon.to_png(palette)))
        deep = pngicon.to_png(h.png(3, 3, bytes(3 * 3 * 8), bit_depth=16))
        self.assertEqual(pngicon.read_header(deep).bit_depth, 16)
        interlaced = pngicon.to_png(h.png(10, 9, h.gradient(10, 9), interlace=True))
        self.assertEqual(pngicon.read_header(interlaced).interlace, 1)

    def test_rejects_broken_files(self):
        good = h.png(4, 4)
        cases = {
            "truncated": good[:-20],
            "no IEND": good[:-12],
            "palette without PLTE": h.png(4, 4, bytes(16), color_type=3),
            "short data": h.png(4, 4, raw_rows=b"\x00" * 10),
            "long data": h.png(4, 4, raw_rows=b"\x00" * 1000),
            "not zlib": good[:8] + h.png_chunk(b"IHDR", good[16:29]) + h.png_chunk(b"IDAT", b"garbage")
            + h.png_chunk(b"IEND", b""),
            "split IDAT": h.png(4, 4, trailing=[(b"tEXt", b"a\x00b"), (b"IDAT", b"")]),
            "no IDAT": good[:8] + h.png_chunk(b"IHDR", good[16:29]) + h.png_chunk(b"IEND", b""),
            "huge": h.png(1, 1, raw_rows=b"\x00\x00\x00\x00\x00")[:16] + struct.pack(">II", 3000, 3000)
            + h.png(1, 1)[24:],
            "bad filter byte": h.png(2, 2, raw_rows=b"\x07" + bytes(8) + b"\x00" + bytes(8)),
            "bad interlaced filter byte": h.png(2, 2, interlace=True, raw_rows=b"\x00" + bytes(4) + b"\x09"
                                                + bytes(4) + b"\x00" + bytes(8)),
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(pngicon.PNGError):
                    pngicon.to_png(data)

    def test_non_cgbi_rejected_by_cgbi_converter(self):
        with self.assertRaises(pngicon.PNGError):
            pngicon.cgbi_to_png(h.png(2, 2))


class CgbiTests(unittest.TestCase):
    def test_rgba_round_trip_every_filter(self):
        pixels = h.gradient(11, 9, 4, alphas=ALPHAS)
        for filters in ((0,), (1,), (2,), (3,), (4,), (0, 1, 2, 3, 4)):
            with self.subTest(filters=filters):
                out = pngicon.to_png(h.cgbi_png(11, 9, pixels, filters=filters))
                self.assertFalse(pngicon.is_cgbi(out))
                self.assertEqual(h.chunk_types(out), [b"IHDR", b"IDAT", b"IEND"])  # CgBI and iDOT dropped
                self.assertEqual(h.decode_png(out), (11, 9, 4, unpremultiplied(pixels)))

    def test_conversion_is_close_to_the_original(self):
        pixels = h.gradient(8, 8, 4, alphas=(255, 254, 200, 128))
        _, _, _, got = h.decode_png(pngicon.to_png(h.cgbi_png(8, 8, pixels)))
        for i in range(0, len(pixels), 4):
            a = pixels[i + 3]
            self.assertEqual(got[i + 3], a)
            for j in range(3):
                self.assertLessEqual(abs(got[i + j] - pixels[i + j]), 0 if a == 255 else 1)

    def test_transparent_pixels_become_zero(self):
        pixels = bytes([10, 20, 30, 0] * 4)
        self.assertEqual(h.decode_png(pngicon.to_png(h.cgbi_png(2, 2, pixels)))[3], bytes(16))

    def test_rgb_cgbi(self):
        pixels = h.gradient(7, 5, 3)
        out = pngicon.to_png(h.cgbi_png(7, 5, pixels, color_type=2, filters=(1, 4), flags=b"\x50\x00\x20\x06"))
        self.assertEqual(h.decode_png(out), (7, 5, 3, pixels))

    def test_interlaced_cgbi(self):
        for size in ((1, 1), (3, 2), (9, 10), (17, 5)):
            with self.subTest(size=size):
                pixels = h.gradient(size[0], size[1], 4, alphas=ALPHAS)
                out = pngicon.to_png(h.cgbi_png(size[0], size[1], pixels, interlace=True, filters=(0, 2, 4)))
                self.assertEqual(pngicon.read_header(out).interlace, 0)
                self.assertEqual(h.decode_png(out), (size[0], size[1], 4, unpremultiplied(pixels)))

    def test_zlib_wrapped_idat_is_tolerated(self):
        pixels = h.gradient(4, 4, 4)
        out = pngicon.to_png(h.cgbi_png(4, 4, pixels, zlib_wrapped=True, idot=False))
        self.assertEqual(h.decode_png(out)[3], unpremultiplied(pixels))

    def test_colour_chunks_survive(self):
        out = pngicon.to_png(h.cgbi_png(3, 3, ancillary=[(b"sRGB", b"\x00"), (b"tEXt", b"k\x00v")]))
        self.assertEqual(h.chunk_types(out), [b"IHDR", b"sRGB", b"IDAT", b"IEND"])

    def test_non_rgb_cgbi_is_rewrapped(self):
        rows = h.filter_rows(bytes(range(16)), 4, 4, 1)
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = comp.compress(rows) + comp.flush()
        data = (h.PNG_SIG + h.png_chunk(b"CgBI", b"\x50\x00\x20\x02")
                + h.png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 0, 0, 0, 0))
                + h.png_chunk(b"IDAT", raw) + h.png_chunk(b"IEND", b""))
        out = pngicon.to_png(data)
        self.assertFalse(pngicon.is_cgbi(out))
        self.assertEqual(zlib.decompress(b"".join(
            body for ctype, body in pngicon.iter_chunks(out) if ctype == b"IDAT")), rows)

    def test_bounded_inflate(self):
        rows = h.filter_rows(bytes(4 * 4 * 4), 4, 4, 4) + b"\x00" * 5000
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = comp.compress(rows) + comp.flush()
        data = (h.PNG_SIG + h.png_chunk(b"CgBI", b"\x50\x00\x20\x02")
                + h.png_chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 6, 0, 0, 0))
                + h.png_chunk(b"IDAT", raw) + h.png_chunk(b"IEND", b""))
        with self.assertRaises(pngicon.PNGError):
            pngicon.to_png(data)

    def test_bad_filter_type(self):
        good = h.cgbi_png(2, 2, filters=(0,))
        stored = h.swap_rb(h.premultiply(h.gradient(2, 2)), 4)
        rows = bytearray(h.filter_rows(stored, 2, 2, 4))
        rows[0] = 9
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        data = good[:good.index(b"IDAT") - 4] + h.png_chunk(b"IDAT", comp.compress(bytes(rows)) + comp.flush()) \
            + h.png_chunk(b"IEND", b"")
        with self.assertRaises(pngicon.PNGError):
            pngicon.to_png(data)


if __name__ == "__main__":
    unittest.main()
