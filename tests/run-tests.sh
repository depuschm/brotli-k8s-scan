#!/usr/bin/env bash
# Offline test suite. Prerequisite (needs network once): tests/build-fixtures.sh
#
# The suite re-runs itself inside a network namespace without network access
# (`unshare -rn`), so nothing can leave the machine while testing. If that is
# not possible it refuses to run unless ALLOW_NETWORK=1 is set.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
SCAN="$ROOT/brotli-k8s-scan.sh"
export BROTLI_TEST_FIXTURES="$HERE/.cache/fixtures"

[ -d "$BROTLI_TEST_FIXTURES/vuln" ] || { echo "fixtures missing: run tests/build-fixtures.sh first" >&2; exit 2; }
# physical path: the probe resolves binaries with readlink -f, so symlinks in
# the fixture path (e.g. /tmp -> /private/tmp on macOS) must be resolved too
BROTLI_TEST_FIXTURES=$(cd "$BROTLI_TEST_FIXTURES" && pwd -P)

if [ -z "${BROTLI_TEST_OFFLINE:-}" ]; then
  export BROTLI_TEST_OFFLINE=1
  if unshare -rn true 2>/dev/null; then
    exec unshare -rn bash "$0" "$@"
  elif [ "${ALLOW_NETWORK:-0}" != 1 ]; then
    echo "cannot isolate the network (unshare -rn failed); set ALLOW_NETWORK=1 to run anyway" >&2
    exit 2
  fi
  echo "WARNING: running WITH network access (ALLOW_NETWORK=1)" >&2
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
expect_has() { if grep -q -F -- "$3" "$2"; then ok "$1"; else bad "$1" "missing: $3"; fi; }
expect_not() { if grep -q -F -- "$3" "$2"; then bad "$1" "unexpected: $3"; else ok "$1"; fi; }

echo "network check"
if (exec 3<>/dev/tcp/1.1.1.1/443) 2>/dev/null; then
  if [ "${ALLOW_NETWORK:-0}" = 1 ]; then echo "  (network reachable, allowed)"; else bad "network is isolated"; fi
else ok "network is isolated"; fi

# --- rootfs mode, once per available POSIX shell ---------------------------
SHELLS="sh"
command -v dash >/dev/null 2>&1 && SHELLS="$SHELLS dash"
# BusyBox (Alpine-style images): run the probe with ONLY busybox applets in
# PATH ahead of everything else, so find/grep/awk/sed/sort are busybox too.
BB=""
if command -v busybox >/dev/null 2>&1; then
  BB="$TMP/bb"; mkdir -p "$BB"; busybox --install -s "$BB" 2>/dev/null
  SHELLS="$SHELLS busybox_sh"
fi

rootfs() {  # $1=fixture $2=shell $3..=extra args ; sets RC, OUTF
  local fx=$1 sh=$2; shift 2
  OUTF="$TMP/rootfs-$fx-$sh-$#.txt"
  local path="$PATH"
  [ "$sh" = busybox_sh ] && { sh="busybox sh"; path="$BB:$PATH"; }
  PATH="$path" BROTLI_PROBE_SHELL="$sh" bash "$SCAN" --rootfs "$BROTLI_TEST_FIXTURES/$fx" -o "$TMP/o-$fx" "$@" > "$OUTF" 2>&1
  RC=$?
}
verdict() { sed -n 's/^Verdict: //p' "$1"; }

for sh in $SHELLS; do
  echo "rootfs mode [$sh]"
  rootfs vuln "$sh";    expect_eq "vuln: verdict"   "$(verdict "$OUTF")" VULNERABLE; expect_eq "vuln: exit 1" "$RC" 1
  expect_has "vuln: node binary flagged"       "$OUTF" "[VULN  ] binary  /usr/local/bin/node"
  expect_has "vuln: libbrotlidec 1.2.0 flagged" "$OUTF" "[VULN  ] binary  /usr/lib/libbrotlidec.so.1.2.0"
  expect_has "vuln: Brotli 1.2.0 flagged"      "$OUTF" "VULN  ] python  Brotli 1.2.0"
  expect_has "vuln: brotlicffi flagged"        "$OUTF" "VULN  ] python  brotlicffi 1.2.0.1"
  expect_has "vuln: Brotli wheel .so flagged"  "$OUTF" "/site-packages/_brotli.so"
  expect_has "vuln: dpkg package listed"       "$OUTF" "dpkg: libbrotli1 1.2.0-1"
  expect_not "vuln: libbrotlicommon ignored"   "$OUTF" "libbrotlicommon"

  rootfs fixed "$sh";   expect_eq "fixed: verdict"  "$(verdict "$OUTF")" PATCHED; expect_eq "fixed: exit 0" "$RC" 0
  expect_has "fixed: node binary ok"           "$OUTF" "[OK    ] binary  /usr/local/bin/node"
  expect_has "fixed: apk package listed"       "$OUTF" "apk: brotli-libs 1.2.1-r0"
  expect_not "fixed: nothing vulnerable"       "$OUTF" "VULN"

  rootfs old109 "$sh";  expect_eq "1.0.9: vulnerable" "$(verdict "$OUTF")" VULNERABLE
  rootfs old1010 "$sh"; expect_eq "1.0.10: patched"   "$(verdict "$OUTF")" PATCHED
  rootfs static "$sh";  expect_eq "static, normal mode: not found" "$(verdict "$OUTF")" NO_BROTLI_FOUND
  rootfs static "$sh" --deep; expect_eq "static, --deep: review" "$(verdict "$OUTF")" REVIEW; expect_eq "static --deep: exit 3" "$RC" 3
  rootfs none "$sh";    expect_eq "jar only: review" "$(verdict "$OUTF")" REVIEW
done

# --- cluster mode with the fake kubectl ------------------------------------
cluster() {  # $1=label, rest = scanner args ; sets RC, REP, LOG
  local label=$1; shift
  REP="$TMP/k-$label"; LOG="$TMP/k-$label.log"
  local path="$HERE/fake-kubectl:$PATH" execpath="/usr/bin:/bin"
  [ "$TEST_SH" = "busybox sh" ] && { path="$HERE/fake-kubectl:$BB:$PATH"; execpath="$BB"; }
  BROTLI_TEST_EXEC_PATH="$execpath" BROTLI_TEST_LOG="$LOG" PATH="$path" bash "$SCAN" -o "$REP" "$@" > "$TMP/k-$label.out" 2>&1
  RC=$?
}
row() { awk -F'\t' -v img="$2" '$2 == img { print $1 }' "$1/report.tsv"; }

for sh in $SHELLS; do
  [ "$sh" = busybox_sh ] && export TEST_SH="busybox sh" || export TEST_SH="$sh"
  echo "cluster mode [$sh]"
  cluster "plain-$sh" --context test-ctx
  expect_eq "exit 1 (vulnerable found)"            "$RC" 1
  expect_eq "unique images (8, pending skipped)"   "$(($(wc -l < "$REP/report.tsv") - 1))" 8
  expect_eq "api image vulnerable"                 "$(row "$REP" registry.test/api:1.4)" VULNERABLE
  expect_eq "web image patched"                    "$(row "$REP" registry.test/web:2)" PATCHED
  expect_eq "distroless needs review"              "$(row "$REP" registry.test/distroless:1)" REVIEW
  expect_eq "1.0.9 proxy vulnerable"               "$(row "$REP" registry.test/proxy:1.0)" VULNERABLE
  expect_eq "1.0.10 proxy patched"                 "$(row "$REP" registry.test/proxy:1.1)" PATCHED
  expect_eq "static job not found without --deep"  "$(row "$REP" registry.test/job:3)" NO_BROTLI_FOUND
  expect_eq "exec mode, node 22.23.3 vulnerable"   "$(row "$REP" registry.test/exec-vuln:1)" VULNERABLE
  expect_eq "exec mode, node 22.23.4 patched"      "$(row "$REP" registry.test/exec-fixed:1)" PATCHED
  expect_has "exec mode reads node -v (vuln)"      "$REP/findings.tsv" "node v22.23.3 (/usr/local/bin/node)"
  expect_has "exec mode reads node -v (fixed)"     "$REP/findings.tsv" "node v22.23.4 (/usr/local/bin/node)"
  expect_has "workloads listed"                    "$REP/report.tsv" "shop/ReplicaSet/api-7d9f"
  expect_has "context passed to kubectl"           "$LOG" "--context test-ctx get pods --all-namespaces -o json"
  expect_eq "one exec per unique image"            "$(grep -c ' exec ' "$LOG")" 8

  cluster "deep-$sh" --deep -n batch
  expect_has "namespace passed to kubectl"         "$LOG" "get pods -n batch -o json"
  expect_eq "static job review with --deep"        "$(row "$REP" registry.test/job:3)" REVIEW
done

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
