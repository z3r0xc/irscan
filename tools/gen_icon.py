#!/usr/bin/env python3
"""Generate desktop/icons/icon.ico.

The mark is drawn from maths - a ring with a filled centre, on a transparent field - so
the asset is reproducible and reviewable instead of being an unexplained binary. The
palette matches the application: near-black field, near-white mark, greyscale only.

Run from the repository root: python tools/gen_icon.py
"""
import math
import pathlib
import struct

DEST = pathlib.Path("desktop/icons/icon.ico")
SIZES = [16, 32, 48, 256]
INK = (246, 246, 246, 255)
FIELD = (20, 20, 20, 255)
CLEAR = (10, 10, 10, 0)


def icon_image(size):
    px = bytearray()
    c = (size - 1) / 2.0
    outer = size * 0.44
    inner = size * 0.30
    dot = size * 0.13
    for y in range(size):
        for x in range(size):
            r = math.hypot(x - c, y - c)
            if r <= dot or inner <= r <= outer:
                px += bytes(INK)
            elif r <= outer:
                px += bytes(FIELD)
            else:
                px += bytes(CLEAR)
    return bytes(px)


def bmp_entry(size, pixels):
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    stride = size * 4
    flipped = b"".join(pixels[y * stride:(y + 1) * stride] for y in range(size - 1, -1, -1))
    mask = bytes(((size + 31) // 32) * 4 * size)
    return header + flipped + mask


def main():
    images = [bmp_entry(s, icon_image(s)) for s in SIZES]
    out = bytearray(struct.pack("<HHH", 0, 1, len(SIZES)))
    offset = 6 + 16 * len(SIZES)
    for size, data in zip(SIZES, images):
        dim = size if size < 256 else 0
        out += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for data in images:
        out += data
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_bytes(bytes(out))
    print(f"wrote {DEST} ({len(out)} bytes, sizes {SIZES})")


if __name__ == "__main__":
    main()
