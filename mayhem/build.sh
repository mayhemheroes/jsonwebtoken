#!/usr/bin/env bash
#
# mayhem/build.sh — build jsonwebtoken's cargo-fuzz target(s) as sanitized libFuzzer
# binaries (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS) AND compile the
# project's own test suite so mayhem/test.sh only RUNS it.
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem.
# The Rust toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo
# (pinned by the Dockerfile ENV — absolute, $HOME-independent).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (in CI, online) populates the cargo registry under $CARGO_HOME.
#   - The PATCH re-run resolves crates from that cache; the rlenv runtime exports
#     CARGO_NET_OFFLINE=true for the re-run so do NOT hard-code `--offline` here.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${MAYHEM_JOBS:=$(nproc)}"
# cargo-fuzz has no --jobs flag; cargo reads parallelism from CARGO_BUILD_JOBS.
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"

cd "$SRC"

# SANITIZER off-switch (SPEC): the Dockerfile threads $SANITIZER_FLAGS (default asan+ubsan,
# halting). rustc ignores clang flags, so we DERIVE the rustc sanitizer flag from it: if
# $SANITIZER_FLAGS mentions "address" we add -Zsanitizer=address; an EMPTY value (built with
# --build-arg SANITIZER_FLAGS=) yields a natural, un-instrumented crash build.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all}"
RUST_SAN=""
CFZ_SANITIZER="none"   # cargo-fuzz's own -s flag; overridden below when ASan is requested
case "$SANITIZER_FLAGS" in
  *address*) RUST_SAN="-Zsanitizer=address"; CFZ_SANITIZER="address" ;;
esac

# DWARF < 4 contract (§6.2 item 10): clang-19 / recent rustc default to DWARF-5, which Mayhem's
# triage can't read. Thread $RUST_DEBUG_FLAGS (default: DWARF-3 + frame pointers + debuginfo) so
# every fuzz binary carries DWARF < 4 symbols. The rlenv PATCH tier may override it.
: "${RUST_DEBUG_FLAGS:=-Cdebuginfo=1 -Zdwarf-version=3 -Cforce-frame-pointers}"

export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing $RUST_SAN $RUST_DEBUG_FLAGS"

# libfuzzer-sys compiles its C++ libFuzzer runtime through the `cc` crate (clang), which
# defaults to DWARF-5. Pin the C/C++ side to DWARF-3 too so no DWARF-5 CU slips in.
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# Additive mayhem/fuzz/ crate (upstream's fuzz/ used Arbitrary derives the old fork had
# patched into upstream src/ — not additive; we author a self-contained crate instead).
FUZZ_DIR="mayhem/fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

echo "=== cargo fuzz build (image nightly, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -s "$CFZ_SANITIZER" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# Build the project's OWN test suite (lib unit tests + tests/*.rs integration tests) with the
# project's NORMAL flags (no sanitizer, no --cfg fuzzing) so mayhem/test.sh only RUNS it.
# Upstream CI runs `cargo test` per backend both WITH default features (use_pem) and with
# --no-default-features; we build both configurations of the rust_crypto backend (pure-Rust,
# compiles fully air-gapped) into SEPARATE target dirs so the fuzz RUSTFLAGS above never leak in.
# (The aws_lc_rs backend runs the same test sources against aws-lc's C implementation; it is
# deliberately not baked here — see mayhem/test.sh header.)
echo "=== building jsonwebtoken test suite (cargo test --no-run, normal flags, rust_crypto) ==="
( cd "$SRC" \
  && env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS CARGO_TARGET_DIR="$SRC/mayhem-tests-target/default" \
       cargo test --no-run --release --features rust_crypto --lib --tests \
  && env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS CARGO_TARGET_DIR="$SRC/mayhem-tests-target/no-default" \
       cargo test --no-run --release --no-default-features --features rust_crypto --lib --tests )
echo "test suite built under $SRC/mayhem-tests-target"

echo "build.sh complete"
