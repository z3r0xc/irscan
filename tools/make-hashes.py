#!/usr/bin/env python3
"""Write SHA256SUMS.txt for a distribution folder.

One line per file, in the `sha256sum` tool's format so `sha256sum -c` works
too. SHA256SUMS.txt never lists itself: the manifest would otherwise have to
contain its own hash, which no file can do.
"""

import hashlib
import os
import sys

MANIFEST = "SHA256SUMS.txt"


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    names = sorted(
        n for n in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, n)) and n != MANIFEST
    )
    if not names:
        sys.exit("no files to hash in %s" % folder)

    lines = ["%s *%s" % (digest(os.path.join(folder, n)), n) for n in names]
    out = os.path.join(folder, MANIFEST)
    with open(out, "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
