"""Capture a window as a PNG, for verifying that a GUI actually renders.

Why this exists rather than a screenshot tool: the check that matters is "did the
application draw the interface", and that is only answerable from pixels. A window that
exists, is visible and has the right geometry can still be blank, so measuring the window
handle proves less than a picture of its client area.

Usage: python tools/capture-window.py <title-substring> <output.png>
"""

import ctypes
import ctypes.wintypes as wt
import struct
import sys
import zlib

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

BI_RGB = 0
DIB_RGB_COLORS = 0
PW_CLIENTONLY = 1
PW_RENDERFULLCONTENT = 2


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wt.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", wt.WORD),
        ("biBitCount", wt.WORD),
        ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]


def find_window(substring):
    """Every top-level window whose title contains `substring`, case-insensitive.

    The caller prints each one before a window is chosen. A substring match is
    silent when it is wrong: a Chrome tab whose page title happens to contain the
    product name is a perfectly good match, and the capture then succeeds while
    showing the wrong window. So the candidates are always listed, and the choice
    is ranked rather than left to whichever window EnumWindows reached first.
    """
    found = []

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def callback(hwnd, _):
        length = user32.GetWindowTextLengthW(hwnd)
        if length:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            if substring.lower() in buf.value.lower():
                found.append((hwnd, buf.value))
        return True

    user32.EnumWindows(callback, 0)
    return found


def rank_candidates(substring, candidates):
    """Exact title first, then prefix, then containment; shortest title breaks a tie.

    A launcher window carries its child's title plus a suffix, so among equally
    good matches the shortest title is the one the application named itself.
    """
    want = substring.lower()

    def rank(item):
        title = item[1].lower()
        if title == want:
            return (0, len(title))
        if title.startswith(want):
            return (1, len(title))
        return (2, len(title))

    return sorted(candidates, key=rank)


def write_png(path, width, height, bgra):
    """Encode bottom-up BGRA rows as an 8-bit RGB PNG."""
    raw = bytearray()
    for y in range(height - 1, -1, -1):
        raw.append(0)  # filter type 0
        row = bgra[y * width * 4 : (y + 1) * width * 4]
        for x in range(width):
            b, g, r = row[x * 4], row[x * 4 + 1], row[x * 4 + 2]
            raw += bytes((r, g, b))

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    open(path, "wb").write(png)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    substring, out = sys.argv[1], sys.argv[2]

    windows = find_window(substring)
    if not windows:
        print("no window matching %r" % substring)
        return 1

    # Every candidate is printed before one is chosen, so a match on the wrong
    # window shows up in the output instead of hiding behind a success.
    ranked = rank_candidates(substring, windows)
    print("%d window(s) matched %r:" % (len(ranked), substring))
    for hwnd_i, title_i in ranked:
        print("  hwnd %-10d %r" % (hwnd_i, title_i))
    if len(ranked) > 1:
        print("  -> more than one match; taking the first (%r). "
              "Pass a longer substring to disambiguate." % ranked[0][1])

    hwnd, title = ranked[0]
    print("capturing %r (hwnd %d)" % (title, hwnd))

    client = wt.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(client))
    width, height = client.right, client.bottom

    src = user32.GetDC(hwnd)
    mem = gdi32.CreateCompatibleDC(src)
    bmp = gdi32.CreateCompatibleBitmap(src, width, height)
    gdi32.SelectObject(mem, bmp)

    # PW_RENDERFULLCONTENT is required for a WebView2 surface: without it the capture
    # returns an empty composited region even though the window shows content.
    ok = user32.PrintWindow(hwnd, mem, PW_CLIENTONLY | PW_RENDERFULLCONTENT)
    if not ok:
        ok = user32.PrintWindow(hwnd, mem, 0)
    print("PrintWindow:", bool(ok))

    info = BITMAPINFO()
    info.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    info.bmiHeader.biWidth = width
    info.bmiHeader.biHeight = height
    info.bmiHeader.biPlanes = 1
    info.bmiHeader.biBitCount = 32
    info.bmiHeader.biCompression = BI_RGB

    buf = ctypes.create_string_buffer(width * height * 4)
    gdi32.GetDIBits(mem, bmp, 0, height, buf, ctypes.byref(info), DIB_RGB_COLORS)

    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(hwnd, src)

    data = buf.raw
    distinct = len(set(data[i : i + 3] for i in range(0, len(data), 4)))
    print("captured %dx%d, %d distinct colours" % (width, height, distinct))
    if distinct <= 2:
        print("WARNING: the capture is a flat fill - the window may not have rendered")

    write_png(out, width, height, data)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
