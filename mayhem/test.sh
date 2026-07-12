#!/usr/bin/env bash
#
# mayhem/test.sh — RUN jsonwebtoken's OWN test suite (already compiled by mayhem/build.sh via
# `cargo test --no-run` into $SRC/mayhem-tests-target) and emit a CTRF summary.
#
# Upstream CI (.github/workflows/ci.yml "tests" job) runs, per crypto backend
# (rust_crypto | aws_lc_rs): `cargo test --features <backend>` AND
# `cargo test --no-default-features --features <backend>`. We run BOTH feature
# configurations of the rust_crypto backend — the full test sources (lib unit tests +
# tests/{dangerous,hmac,lib}.rs incl. the ecdsa/eddsa/header/rsa modules). The aws_lc_rs
# backend re-runs the SAME test sources against aws-lc's C implementation; it is skipped
# here (heavy aws-lc C/cmake build in an air-gapped image, duplicate coverage of this
# crate's own code). The wasm CI job (wasm-pack, node) is likewise not runnable in-image.
#
# PATCH-grade oracle: these are real known-answer suites (sign/verify round-trips against
# fixed keys, expected-failure assertions, exact claim validation errors). A no-op /
# exit(0) patch FAILS them; neutered binaries emit no `test result:` lines, which the
# structural check below turns into an honest failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# RUN the pre-built test binaries directly (no cargo, no recompilation — build.sh compiled
# them). `cargo test --no-run` left one executable per test target (jsonwebtoken lib unit
# tests + dangerous/hmac/lib integration suites) under <config>/release/deps.
OUT="$(mktemp)"
ran=0
for cfg in default no-default; do
  TDIR="$SRC/mayhem-tests-target/$cfg/release/deps"
  [ -d "$TDIR" ] || { echo "ERROR: $TDIR missing — build.sh should have built the test suite" >&2; emit_ctrf cargo-test 0 1; exit 1; }
  for bin in "$TDIR"/jsonwebtoken-* "$TDIR"/dangerous-* "$TDIR"/hmac-* "$TDIR"/lib-*; do
    [ -f "$bin" ] && [ -x "$bin" ] || continue
    case "$bin" in *.d) continue ;; esac
    echo "=== running [$cfg] $(basename "$bin") ==="
    "$bin" 2>&1 | tee -a "$OUT"
    ran=$(( ran + 1 ))
  done
done
echo "ran $ran test binaries"

# Sum every `test result: ok. X passed; Y failed; ... Z ignored` line.
sum_field() { grep -E '^test result:' "$OUT" | sed -E "s/.* ([0-9]+) $1.*/\1/" | awk '{s+=$1} END {print s+0}'; }
PASSED=$(sum_field passed)
FAILED=$(sum_field failed)
SKIPPED=$(sum_field ignored)
: "${PASSED:=0}" "${FAILED:=0}" "${SKIPPED:=0}"
rm -f "$OUT"

# No parsed results at all (e.g. neutered binaries emitting nothing) → honest failure.
if [ "$(( PASSED + FAILED + SKIPPED ))" -eq 0 ]; then
  echo "ERROR: no 'test result:' lines parsed — test binaries produced no results" >&2
  emit_ctrf cargo-test 0 1; exit 1
fi

emit_ctrf cargo-test "$PASSED" "$FAILED" "$SKIPPED"
