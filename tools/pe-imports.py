#!/usr/bin/env python3
"""Print the DLL names in a PE file's import directory.

Reads the PE headers, walks the import descriptor table and prints each DLL
name it finds. No dependencies; deliberately explicit rather than clever,
because this is the evidence that a release binary does not need the Visual
C++ redistributable on a clean Windows machine.
"""

import struct
import sys

# Offsets into the IMAGE_OPTIONAL_HEADER. The data directories sit at a fixed
# place for both PE32 and PE32+; only the NumberOfRvaAndSizes field moves.
_DIR_OFFSET = {0x10B: 96, 0x20B: 112}  # PE32, PE32+


def import_dlls(path):
    with open(path, "rb") as fh:
        data = fh.read()

    if data[:2] != b"MZ":
        raise ValueError("not a PE file: missing MZ signature")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("not a PE file: missing PE signature")

    machine, n_sections = struct.unpack_from("<HH", data, pe_off + 4)
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic not in _DIR_OFFSET:
        raise ValueError("unknown optional header magic 0x%x" % magic)

    # Import table entry #1 of the data directories.
    imp_rva, imp_size = struct.unpack_from("<II", data, opt_off + _DIR_OFFSET[magic] + 8)
    if imp_rva == 0:
        return []

    sec_off = opt_off + opt_size
    sections = []
    for i in range(n_sections):
        base = sec_off + i * 40
        va, vsize, raw_off = struct.unpack_from("<III", data, base + 12)[0], \
            struct.unpack_from("<I", data, base + 8)[0], \
            struct.unpack_from("<I", data, base + 20)[0]
        sections.append((va, vsize, raw_off))

    def rva_to_off(rva):
        for va, vsize, raw_off in sections:
            if va <= rva < va + max(vsize, 1):
                return raw_off + (rva - va)
        raise ValueError("RVA 0x%x is not inside any section" % rva)

    # IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the table ends with an all-zero
    # entry, so bound the walk by the directory size as well.
    names = []
    off = rva_to_off(imp_rva)
    for i in range(max(imp_size // 20, 1)):
        entry = off + i * 20
        if entry + 20 > len(data):
            break
        original_first_thunk, _ts, _fc, name_rva, first_thunk = \
            struct.unpack_from("<IIIII", data, entry)
        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        if name_rva == 0:
            continue
        s = rva_to_off(name_rva)
        end = data.index(b"\0", s)
        names.append(data[s:end].decode("ascii"))
    return names


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: pe-imports.py <file.exe> [file.exe ...]")
    for path in sys.argv[1:]:
        print(path)
        for name in import_dlls(path):
            print("  %s" % name)
        if len(sys.argv) > 2:
            print()


if __name__ == "__main__":
    main()
