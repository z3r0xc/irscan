#!/usr/bin/env python3
"""Assert that a PE file's embedded manifest requires Administrator.

Why a dedicated check: a missing or malformed manifest does not stop the program from
running. Windows either starts it as an ordinary process - so no UAC prompt, and the scan
quietly loses the Security event log, Prefetch and protected process image paths - or
refuses to start it with "side-by-side configuration is incorrect", which names neither
the manifest nor the tool. Both failures look like something else, so a release build
verifies the resource instead of trusting it.

Reads the RT_MANIFEST resource (type 24) by walking the .rsrc directory, rather than
searching the file for a string: a string search finds the comment that quotes the level
just as happily as the real resource.
"""

import struct
import sys

RT_MANIFEST = 24


def rva_to_offset(data, sections, rva):
    for va, vsize, raw_size, raw_ptr in sections:
        if va <= rva < va + max(vsize, raw_size):
            return raw_ptr + (rva - va)
    return None


def sections_of(data, opt, opt_size, nsec):
    out = []
    base = opt + opt_size
    for i in range(nsec):
        o = base + i * 40
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
        out.append((va, vsize, raw_size, raw_ptr))
    return out


def main(path):
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        print(f"FAIL {path}: not a PE file")
        return 1
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\x00\x00":
        print(f"FAIL {path}: no PE signature")
        return 1

    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    sections = sections_of(data, opt, opt_size, nsec)

    rsrc_rva, rsrc_size = struct.unpack_from("<II", data, dd + 2 * 8)
    if rsrc_rva == 0 or rsrc_size == 0:
        print(f"FAIL {path}: no resource directory, so no manifest is embedded")
        return 1
    rsrc = rva_to_offset(data, sections, rsrc_rva)
    if rsrc is None:
        print(f"FAIL {path}: .rsrc is not mapped by any section")
        return 1

    # Three-level directory: type -> name/id -> language.
    def entries(off):
        named, ids = struct.unpack_from("<HH", data, off + 12)
        total = named + ids
        out = []
        for i in range(total):
            e = off + 16 + i * 8
            name, child = struct.unpack_from("<II", data, e)
            out.append((name, child))
        return out

    manifest = None
    for name, child in entries(rsrc):
        if name != RT_MANIFEST:
            continue
        for _n2, child2 in entries(rsrc + (child & 0x7FFFFFFF)):
            for _n3, child3 in entries(rsrc + (child2 & 0x7FFFFFFF)):
                doff = rsrc + (child3 & 0x7FFFFFFF)
                data_rva, data_size = struct.unpack_from("<II", data, doff)
                start = rva_to_offset(data, sections, data_rva)
                if start is not None:
                    manifest = data[start : start + data_size]
        break

    if manifest is None:
        print(f"FAIL {path}: resource type {RT_MANIFEST} (RT_MANIFEST) not found")
        return 1

    text = manifest.decode("utf-8", "replace")
    quoted = "level='" + "requireAdministrator" + "'"
    double = 'level="requireAdministrator"'
    if quoted not in text and double not in text:
        print(f"FAIL {path}: manifest exists but does not request requireAdministrator")
        print("      manifest:", " ".join(text.split())[:200])
        return 1
    if "uiAccess='true'" in text or 'uiAccess="true"' in text:
        print(f"FAIL {path}: uiAccess is true; the tool must not drive higher-integrity windows")
        return 1

    level_at = text.find("requestedExecutionLevel")
    print(f"PASS {path}: {manifest.__len__()} byte manifest, "
          f"{' '.join(text[level_at:level_at + 60].split())}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
