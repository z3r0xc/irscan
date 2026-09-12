#!/usr/bin/env sh
# Proves that build.rs output is deterministic: the same vendored data must produce a
# byte-identical signatures.rs on every build. A non-deterministic generator would make
# "the report changed" impossible to distinguish from "the database changed".
set -eu

cd "$(dirname "$0")/.."

newest_generated() {
    find ir-recon/target -path '*/out/signatures.rs' -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | head -n1 | cut -d' ' -f2-
}

echo "building once..."
cargo build --quiet --manifest-path ir-recon/Cargo.toml
first=$(newest_generated)
if [ -z "$first" ]; then
    echo "FAIL: irscan did not generate signatures.rs"
    exit 1
fi
cp "$first" .irscan-generated-1.rs

echo "forcing regeneration..."
touch ir-recon/build.rs
cargo build --quiet --manifest-path ir-recon/Cargo.toml
second=$(newest_generated)
cp "$second" .irscan-generated-2.rs

if cmp -s .irscan-generated-1.rs .irscan-generated-2.rs; then
    echo "OK: build.rs output is deterministic ($(wc -c < .irscan-generated-1.rs) bytes)"
    rm -f .irscan-generated-1.rs .irscan-generated-2.rs
else
    echo "FAIL: build.rs output differs between two builds of identical input"
    diff .irscan-generated-1.rs .irscan-generated-2.rs | head -n 20
    exit 1
fi

# The other generator, checked the same way: regenerate from the vendored rules and
# compare against the file that is committed. A checked-in generated file that no longer
# matches its source is a file that will be edited by hand and never regenerated.
echo "checking remote_tools.rs against its source..."
if python tools/gen_remote_tools.py --check; then
    :
else
    echo "FAIL: ir-recon/src/remote_tools.rs is out of date; run tools/gen_remote_tools.py"
    exit 1
fi
