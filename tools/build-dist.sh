#!/usr/bin/env bash
# Build the portable irscan distribution in dist/.
#
# Rebuilds the CLI, copies the one file the operator needs, refreshes the hash
# manifest, then proves the copy is self-contained and unmodified.
set -euo pipefail

# Resolve to a native Windows path. `pwd` in this environment returns an MSYS-style
# /mnt/d/... path, which cargo.exe cannot open ("manifest path does not exist"), and
# `pwd -W` is not available in this bash build. cygpath is the supported converter; the
# fallback keeps the script usable in a plain POSIX shell where paths are already native.
# Two spellings of the same directory are needed, and mixing them up is the whole
# difficulty of this script under Git Bash:
#   * bash  resolves /mnt/d/...  and does NOT see a Windows-style D:/... path;
#   * cargo.exe does the opposite - it cannot open /mnt/d/... at all.
# So `here` stays in bash's form for `cp`, and `win_root` is the form cargo and the
# tooling receive. A plain POSIX shell produces the same string for both.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$here" in
  /mnt/[A-Za-z]/*) drive="${here:5:1}"; rest="${here:7}" ;;
  /[A-Za-z]/*)     drive="${here:1:1}"; rest="${here:3}" ;;
  *)               drive=""; rest="" ;;
esac
if [ -n "$drive" ]; then
  win_root="$(echo "$drive" | tr '[:lower:]' '[:upper:]'):/$rest"
else
  win_root="$here"
fi

if [ ! -d "$here/ir-recon" ]; then
  echo "cannot locate the repository root (tried '$here')" >&2
  exit 1
fi

dist="$here/dist"
win_dist="$win_root/dist"
exe="$here/ir-recon/target/release/irscan.exe"

# Under Git Bash, `command -v cargo` misses cargo.exe on Windows, so try both spellings
# before giving up. The script has to work in the shell it is actually run from.
cargo_bin=""
for candidate in cargo cargo.exe; do
  if command -v "$candidate" >/dev/null 2>&1; then cargo_bin="$candidate"; break; fi
done
[ -n "$cargo_bin" ] || { echo "cargo not found on PATH" >&2; exit 1; }

# The tools are invoked with bash-style paths (`$here`), not Windows ones: in this
# environment only the MSYS python3 is reachable from bash, and it cannot open D:/... .
# cargo is the opposite - it needs the Windows form - which is why both spellings exist.
python_bin=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1; then python_bin="$candidate"; break; fi
done
[ -n "$python_bin" ] || { echo "python not found on PATH" >&2; exit 1; }

echo "== building irscan (release) =="
"$cargo_bin" build --release --manifest-path "$win_root/ir-recon/Cargo.toml"

echo "== staging dist/ =="
mkdir -p "$dist"
cp -f "$exe" "$dist/irscan.exe"

# SHA256SUMS.txt covers every file except itself, so verification is a fixed
# point: the manifest never lists its own hash.
echo "== writing SHA256SUMS.txt =="
"$python_bin" "$here/tools/make-hashes.py" "$dist"

echo "== proving the exe is self-contained =="
"$python_bin" "$here/tools/pe-imports.py" "$dist/irscan.exe"

# The manifest is what makes Windows ask for Administrator. Without it the tool still
# runs, still prints a report, and silently loses the Security log, Prefetch and the
# image paths of protected processes - so a release must not ship without it.
echo
echo "== proving the manifest requests Administrator =="
"$python_bin" "$here/tools/check-manifest.py" "$dist/irscan.exe"

echo
echo "== dist/ =="
ls -l "$dist"
echo
echo "Run dist/verify-hashes.ps1 to check integrity before copying to a target machine."
