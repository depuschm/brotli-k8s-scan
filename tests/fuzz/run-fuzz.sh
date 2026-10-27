#!/usr/bin/env bash
# Fuzz session for brotli-k8s-scan.sh: both targets of tests/fuzz/fuzz_scanner.py
# for a fixed time each (CI job "fuzz"; tests/run-tests.sh runs a short one).
# Offline like the test suite. Prerequisite: tests/build-fixtures.sh (x86_64).
#
# usage: tests/fuzz/run-fuzz.sh [seconds per target, default 120]
# A failure prints the input as "Base64: ..."; replay it with
#   echo '<base64>' | base64 -d > crash
#   python3 -I tests/fuzz/fuzz_scanner.py tests/.cache/pylib <target> crash
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
TESTS=$(dirname "$HERE")
PYLIB="$TESTS/.cache/pylib"
[ -d "$PYLIB/atheris" ] || { echo "atheris missing (x86_64 only): run tests/build-fixtures.sh first" >&2; exit 2; }

if [ -z "${BROTLI_TEST_OFFLINE:-}" ]; then
  export BROTLI_TEST_OFFLINE=1
  unshare -rn true 2>/dev/null && exec unshare -rn bash "$0" "$@"
  [ "${ALLOW_NETWORK:-0}" = 1 ] || { echo "cannot isolate the network (unshare -rn failed); set ALLOW_NETWORK=1 to run anyway" >&2; exit 2; }
fi

SECS=${1:-120}
SHELLS="sh bash"
command -v dash >/dev/null 2>&1 && SHELLS="$SHELLS dash"
command -v busybox >/dev/null 2>&1 && SHELLS="$SHELLS busybox"
OUT="$TESTS/.cache/fuzz"
mkdir -p "$OUT"
rc=0
for t in evaluator probe; do
  echo "== fuzz $t for ${SECS}s (probe shells: $SHELLS)"
  mkdir -p "$OUT/corpus-$t"
  (cd "$OUT" && BROTLI_FUZZ_SHELLS="$SHELLS" TMPDIR="$OUT" python3 -I "$HERE/fuzz_scanner.py" "$PYLIB" "$t" \
     -max_total_time="$SECS" -len_control=0 -max_len=2048 -print_final_stats=1 "corpus-$t") || rc=1
  rm -rf "$OUT"/brotli-fuzz.*
done
exit $rc
