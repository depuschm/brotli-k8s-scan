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
skip() {  # in CI (BROTLI_TEST_STRICT=1) nothing may be skipped
  if [ "${BROTLI_TEST_STRICT:-0}" = 1 ]; then bad "$1 (not allowed with BROTLI_TEST_STRICT=1)"; else printf '  skip  %s\n' "$1"; fi
}
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
case " $SHELLS " in *" dash "*) ;; *) skip "dash not installed: probe not tested with dash" ;; esac
[ -n "$BB" ] || skip "busybox not installed: probe not tested with BusyBox (Alpine)"

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
  rootfs dotnet-10.0.7 "$sh";  expect_eq ".NET 10.0.7 runtime: vulnerable (version from path)" "$(verdict "$OUTF")" VULNERABLE
  rootfs dotnet-10.0.14 "$sh"; expect_eq ".NET 10.0.14 runtime: patched (version from path)"  "$(verdict "$OUTF")" PATCHED
  if [ -d "$BROTLI_TEST_FIXTURES/dotnet8-ubuntu" ]; then
    rootfs dotnet8-ubuntu "$sh"; expect_eq "Ubuntu .NET 8.0.32 (bundled Brotli 1.0.x): vulnerable" "$(verdict "$OUTF")" VULNERABLE
    expect_has "Ubuntu .NET 8.0.32: decided by the fingerprint" "$OUTF" "[VULN  ] binary  /usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so"
    rootfs dotnet10-ubuntu-old "$sh";   expect_eq "Ubuntu .NET 10.0.13 + unpatched libbrotli1: vulnerable" "$(verdict "$OUTF")" VULNERABLE
    expect_has "Ubuntu .NET 10.0.13: reported as using the system libbrotli" "$OUTF" "uses the system libbrotli"
    rootfs dotnet10-ubuntu-fixed "$sh"; expect_eq "Ubuntu .NET 10.0.13 + patched libbrotli1: patched (version alone would say vulnerable)" "$(verdict "$OUTF")" PATCHED
    rootfs dotnet-selfcontained-ubuntu "$sh"; expect_eq "self-contained app with real .NET 8.0.32 library: vulnerable" "$(verdict "$OUTF")" VULNERABLE
  else skip "Ubuntu .NET fixtures not built"; fi
  # hostile file names must not hide a vulnerable decoder or pull in host files
  H="$TMP/hostile-$sh"; rm -rf "$H"; mkdir -p "$H/rf/usr/local/bin" "$H/rf/opt/app" "$H/zz"
  cp "$BROTLI_TEST_FIXTURES/vuln/usr/local/bin/node" "$H/rf/usr/local/bin/node"
  printf 'timedownlifeleftback\000_ERROR_FORMAT_EXUBERANT_NIBBLE\000_ERROR_FORMAT_BLOCK_SWITCH\000' > "$H/fake-patched"
  cp "$H/fake-patched" "$H/rf/usr/local/bin/$(printf 'node\t.node')"        # tab trick
  cp "$H/fake-patched" "$H/zz/decoy.node"                                    # a file in the directory the scan runs from
  : > "$H/rf/opt/app/$(printf 'x.node\ndecoy.node')"                         # newline trick: 2nd line is a relative name
  OUTF="$TMP/hostile-$sh.txt"
  if [ "$sh" = busybox_sh ]; then (cd "$H/zz" && PATH="$BB:$PATH" BROTLI_PROBE_SHELL="busybox sh" bash "$SCAN" --rootfs "$H/rf" -o "$H/out" > "$OUTF" 2>&1)
  else (cd "$H/zz" && BROTLI_PROBE_SHELL="$sh" bash "$SCAN" --rootfs "$H/rf" -o "$H/out" > "$OUTF" 2>&1); fi
  expect_eq "hostile names: a crafted file cannot hide the vulnerable node" "$(verdict "$OUTF")" VULNERABLE
  expect_has "hostile names: node still reported vulnerable" "$H/out/findings.tsv" "$(printf 'VULN\tbinary\t/usr/local/bin/node\t')"
  expect_not "hostile names: no file outside the image is read" "$H/out/findings.tsv" "decoy.node"
  expect_eq "hostile names: every finding has exactly 6 fields" "$(awk -F'\t' 'NR>1 && NF!=6' "$H/out/findings.tsv" | wc -l | tr -d ' ')" 0
  # the probe itself (not only the evaluator) must skip and count such names
  bash "$SCAN" --print-probe > "$H/probe.sh"
  if [ "$sh" = busybox_sh ]; then (cd "$H/zz" && PATH="$BB:$PATH" busybox sh "$H/probe.sh" "$H/rf" 0 0 > "$H/raw" 2>&1)
  else (cd "$H/zz" && "$sh" "$H/probe.sh" "$H/rf" 0 0 > "$H/raw" 2>&1); fi
  expect_eq "hostile names: the probe never prints a name with a tab" "$(awk -F'\t' '$1=="BIN" && NF!=3' "$H/raw" | wc -l | tr -d ' ')" 0
  expect_has "hostile names: the probe counts the 2 names it skipped" "$H/raw" "$(printf 'ODDNAMES\t2')"
  rootfs dotnet-selfcontained-synthetic-8.0.32 "$sh"; expect_eq "self-contained app, version from deps.json 8.0.32: vulnerable" "$(verdict "$OUTF")" VULNERABLE
  rootfs dotnet-selfcontained-synthetic-8.0.33 "$sh"; expect_eq "self-contained app, version from deps.json 8.0.33: patched"    "$(verdict "$OUTF")" PATCHED
  if [ -d "$BROTLI_TEST_FIXTURES/msdotnet-8.0.32" ]; then
    for v in 8.0.32:VULNERABLE 8.0.33:PATCHED 10.0.13:VULNERABLE 10.0.14:PATCHED; do
      rootfs "msdotnet-${v%%:*}" "$sh"
      expect_eq "official Microsoft .NET ${v%%:*}: ${v#*:}" "$(verdict "$OUTF")" "${v#*:}"
      sed -n 's/^  \[\(VULN  \|OK    \)\] \(binary\|dotnet\) */        decided by: \2 /p' "$OUTF" | grep -i compression | head -n 1
    done
  else skip "official Microsoft .NET runtimes not downloaded (CI downloads them)"; fi
  if [ -d "$BROTLI_TEST_FIXTURES/bunold" ]; then
    rootfs bunold "$sh";     expect_eq "official Bun 1.4.3 binary: vulnerable (fingerprint)" "$(verdict "$OUTF")" VULNERABLE
    rootfs bunfixed "$sh";   expect_eq "official Bun 1.4.4 binary: patched (fingerprint)"    "$(verdict "$OUTF")" PATCHED
    rootfs envoyold "$sh";   expect_eq "official Envoy 1.36.11, not executed: review"        "$(verdict "$OUTF")" REVIEW
    expect_has "Envoy without exec: says why and what to do" "$OUTF" "Envoy builds keep no Brotli error table, so its version decides"
    rootfs envoyfixed "$sh"; expect_eq "official Envoy 1.36.12, not executed: review"        "$(verdict "$OUTF")" REVIEW
  else skip "Envoy/Bun fixtures not built"; fi
  if [ -d "$BROTLI_TEST_FIXTURES/ubuntu-old" ]; then
    rootfs ubuntu-old "$sh";   expect_eq "Ubuntu libbrotli1 1.1.0-2build2: vulnerable"           "$(verdict "$OUTF")" VULNERABLE
    rootfs ubuntu-fixed "$sh"; expect_eq "Ubuntu libbrotli1 1.1.0-2ubuntu0.1 (backport): patched" "$(verdict "$OUTF")" PATCHED
  else skip "Ubuntu backport fixture not built"; fi
done

# --- cluster mode with the fake kubectl ------------------------------------
cluster() {  # $1=label, rest = scanner args ; sets RC, REP, LOG
  local label=$1; shift
  REP="$TMP/k-$label"; LOG="$TMP/k-$label.log"
  local path="$HERE/fake-kubectl:$HERE/fake-image-tools:$PATH" execpath="/usr/bin:/bin"
  [ "$TEST_SH" = "busybox sh" ] && { path="$HERE/fake-kubectl:$HERE/fake-image-tools:$BB:$PATH"; execpath="$BB"; }
  local sh="${TEST_SH:-sh}"
  BROTLI_PROBE_SHELL="$sh" BROTLI_IMAGE_TOOL=crane BROTLI_TEST_EXEC_PATH="$execpath" BROTLI_TEST_LOG="$LOG" PATH="$path" \
    bash "$SCAN" -o "$REP" "$@" > "$TMP/k-$label.out" 2>&1
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
  expect_has "distroless: the exec error is reported" "$REP/report.tsv" "executable file not found"
  expect_eq "1.0.9 proxy vulnerable"               "$(row "$REP" registry.test/proxy:1.0)" VULNERABLE
  expect_eq "1.0.10 proxy patched"                 "$(row "$REP" registry.test/proxy:1.1)" PATCHED
  expect_eq "static job not found without --deep"  "$(row "$REP" registry.test/job:3)" NO_BROTLI_FOUND
  expect_eq "exec mode, node 22.23.3 vulnerable"   "$(row "$REP" registry.test/exec-vuln:1)" VULNERABLE
  expect_eq "exec mode, node 22.23.4 patched"      "$(row "$REP" registry.test/exec-fixed:1)" PATCHED
  expect_has "exec mode reads node -v (vuln)"      "$REP/findings.tsv" "$(printf 'VULN\tnode\tnode v22.23.3\t')"
  expect_has "exec mode reads node -v (fixed)"     "$REP/findings.tsv" "$(printf 'OK\tnode\tnode v22.23.4\t')"
  expect_has "workloads listed"                    "$REP/report.tsv" "shop/ReplicaSet/api-7d9f"
  expect_has "context passed to kubectl"           "$LOG" "--context test-ctx get pods --all-namespaces -o json"
  expect_eq "one exec per unique image"            "$(grep -c ' exec ' "$LOG")" 8

  if [ -d "$BROTLI_TEST_FIXTURES/envoyold" ]; then
    BROTLI_TEST_PODS="$HERE/pods-runtimes.json" cluster "runtimes-$sh"
    expect_eq "exec: Envoy 1.36.11 (envoy --version) vulnerable" "$(row "$REP" registry.test/envoy:1.36.11)" VULNERABLE
    expect_eq "exec: Envoy 1.36.12 (envoy --version) patched"    "$(row "$REP" registry.test/envoy:1.36.12)" PATCHED
    expect_eq "exec: Bun 1.4.3 vulnerable"                       "$(row "$REP" registry.test/bun:1.4.3)" VULNERABLE
    expect_eq "exec: Bun 1.4.4 patched"                          "$(row "$REP" registry.test/bun:1.4.4)" PATCHED
    expect_has "exec: reads envoy --version"                     "$REP/findings.tsv" "$(printf 'VULN\tenvoy\tenvoy 1.36.11\t')"
    expect_has "exec: reads bun --version"                       "$REP/findings.tsv" "$(printf 'OK\tbun\tbun 1.4.4\t')"
  else skip "Envoy/Bun fixtures not built (exec mode)"; fi

  cluster "deep-$sh" --deep -n batch
  expect_has "namespace passed to kubectl"         "$LOG" "get pods -n batch -o json"
  expect_eq "static job review with --deep"        "$(row "$REP" registry.test/job:3)" REVIEW

  echo "cluster mode --no-exec [$sh]"
  cluster "noexec-$sh" --no-exec --sarif
  expect_eq "exit 1 (vulnerable found)"            "$RC" 1
  expect_eq "no kubectl exec at all"               "$(grep -c ' exec ' "$LOG")" 0
  expect_has "pulls by digest, not by tag"         "$LOG" "crane export registry.test/api@sha256:aaa -"
  expect_has "falls back to tag without digest"    "$LOG" "crane export registry.test/distroless:1 -"
  expect_eq "api image vulnerable"                 "$(row "$REP" registry.test/api:1.4)" VULNERABLE
  expect_eq "distroless image now scanned"         "$(row "$REP" registry.test/distroless:1)" PATCHED
  expect_eq "1.0.9 proxy vulnerable"               "$(row "$REP" registry.test/proxy:1.0)" VULNERABLE
  expect_has "workloads still listed"              "$REP/report.tsv" "web/StatefulSet/web"
done

# --- audit helpers: --print-probe and --dry-run -----------------------------
echo "audit helpers"
export TEST_SH=sh
bash "$SCAN" --print-probe > "$TMP/probe.txt"
expect_has "--print-probe prints the probe"          "$TMP/probe.txt" 'R="$1"; X="${2:-1}"; D="${3:-0}"'
expect_not "the probe contains no URLs"              "$TMP/probe.txt" "://"
BROTLI_TEST_PROBE_DUMP="$TMP/probe-ran.txt" cluster audit -n shop
if cmp -s "$TMP/probe.txt" "$TMP/probe-ran.txt"; then ok "--print-probe shows exactly the code that runs in containers"
else bad "--print-probe shows exactly the code that runs in containers"; fi
cluster dry-exec --dry-run
expect_eq "--dry-run: exit 0"                        "$RC" 0
expect_eq "--dry-run: lists 8 images to exec into"   "$(grep -c '^  exec ' "$TMP/k-dry-exec.out")" 8
expect_eq "--dry-run: no kubectl exec happened"      "$(grep -c ' exec ' "$LOG")" 0
cluster dry-pull --dry-run --no-exec
expect_eq "--dry-run --no-exec: lists 8 images to pull" "$(grep -c '^  pull ' "$TMP/k-dry-pull.out")" 8
expect_eq "--dry-run --no-exec: nothing pulled"      "$(grep -c 'crane export' "$LOG")" 0
mkdir -p "$TMP/empty-cwd"
(cd "$TMP/empty-cwd" && bash "$SCAN" --print-probe > /dev/null)
expect_eq "--print-probe writes no files"             "$(ls -A "$TMP/empty-cwd" | wc -l | tr -d ' ')" 0

# --- image mode with fake crane / docker ------------------------------------
image() {  # $1=label $2=tool, rest = scanner args ; sets RC, REP, LOG, OUTF
  local label=$1 tool=$2; shift 2
  REP="$TMP/i-$label"; LOG="$TMP/i-$label.log"; OUTF="$TMP/i-$label.out"
  BROTLI_IMAGE_TOOL="$tool" BROTLI_TEST_LOG="$LOG" PATH="$HERE/fake-image-tools:$PATH" \
    bash "$SCAN" -o "$REP" "$@" > "$OUTF" 2>&1
  RC=$?
}
echo "image mode"
image crane-one crane --image registry.test/vuln:1
expect_eq "crane: single image verdict"            "$(verdict "$OUTF")" VULNERABLE
expect_eq "crane: exit 1"                          "$RC" 1
expect_has "crane: export called"                  "$LOG" "crane export registry.test/vuln:1 -"
image crane-plat crane --image registry.test/fixed:2 --platform linux/arm64
expect_eq "crane: patched image"                   "$(verdict "$OUTF")" PATCHED
expect_has "crane: --platform passed through"      "$LOG" "crane export --platform linux/arm64 registry.test/fixed:2 -"
image docker-one docker --image registry.test/fixed:2
expect_eq "docker: patched image"                  "$(verdict "$OUTF")" PATCHED
expect_has "docker: create"                        "$LOG" "docker create registry.test/fixed:2 /nonexistent"
expect_has "docker: container removed"             "$LOG" "docker rm -f cid-fixed"
printf '# images to scan\nregistry.test/vuln:1\n\nregistry.test/fixed:2   # trailing comment\nregistry.test/nope:1\n' > "$TMP/list.txt"
image list crane --images-from "$TMP/list.txt" --image registry.test/vuln:1
expect_eq "list: 3 unique images"                  "$(($(wc -l < "$REP/report.tsv") - 1))" 3
expect_eq "list: missing image needs review"       "$(row "$REP" registry.test/nope:1)" REVIEW
expect_has "list: pull error reported"             "$REP/report.tsv" "MANIFEST_UNKNOWN"
expect_eq "list: exit 1"                           "$RC" 1
leftover=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'brotli-scan.*' -newer "$TMP/list.txt" 2>/dev/null | wc -l | tr -d ' ')
expect_eq "image mode: temporary files removed"    "$leftover" 0

# --- JSON / SARIF ------------------------------------------------------------
echo "JSON and SARIF output"
J="$TMP/k-noexec-sh/report.json"; S="$TMP/k-noexec-sh/report.sarif"
if jq -e '.images | length == 8' "$J" >/dev/null 2>&1; then ok "report.json: 8 images"; else bad "report.json: 8 images"; fi
expect_eq "report.json: summary matches report.tsv" "$(jq -r '.summary.VULNERABLE' "$J")" \
  "$(awk -F'\t' 'NR>1 && $1=="VULNERABLE"' "$TMP/k-noexec-sh/report.tsv" | wc -l | tr -d ' ')"
expect_eq "report.sarif: one result per VULN/REVIEW finding" "$(jq '.runs[0].results | length' "$S")" \
  "$(jq '[.images[].findings[] | select(.state == "VULN" or .state == "REVIEW")] | length' "$J")"
expect_eq "report.sarif: rule severity 9.2" "$(jq -r '.runs[0].tool.driver.rules[0].properties["security-severity"]' "$S")" 9.2
PYLIB="$HERE/.cache/pylib"; SCHEMA="$HERE/.cache/sarif-schema-2.1.0.json"
if [ -f "$PYLIB/.ok" ] && [ -f "$SCHEMA" ]; then
  if python3 -I -c 'import sys, json; sys.path.insert(0, sys.argv[1]); import jsonschema
jsonschema.validate(json.load(open(sys.argv[3])), json.load(open(sys.argv[2])))' "$PYLIB" "$SCHEMA" "$S" 2> "$TMP/schema.err"
  then ok "report.sarif validates against the SARIF 2.1.0 schema"
  else bad "report.sarif validates against the SARIF 2.1.0 schema" "$(tail -n 1 "$TMP/schema.err")"; fi
else skip "SARIF schema validation (helpers not built)"; fi

# --- version rules (evaluator unit tests) ----------------------------------
echo "version rules"
ev() { printf 'BEGIN\n%bEND\n' "$1" | bash "$SCAN" --evaluate-stdin | awk -F'\t' -v k="$2" '$1=="F" && $3==k { print $2; exit }'; }
expect_eq "node 22.23.3, binary not fingerprinted -> review"   "$(ev 'NODE\tv22.23.3\t/n\n' node)" REVIEW
expect_eq "node 22.23.3, vulnerable binary -> vuln"            "$(ev 'NODE\tv22.23.3\t/n\nBIN\tVULNERABLE\t/n\n' node)" VULN
expect_eq "node 22.23.3, binary has fix (backport) -> ok"      "$(ev 'NODE\tv22.23.3\t/n\nBIN\tPATCHED\t/n\n' node)" OK
expect_eq "node 24.22.1 -> ok"                                 "$(ev 'NODE\tv24.22.1\t/n\nBIN\tUNKNOWN\t/n\n' node)" OK
expect_eq "node 26.12.0 -> vuln"                               "$(ev 'NODE\tv26.12.0\t/n\nBIN\tUNKNOWN\t/n\n' node)" VULN
expect_eq "node 20 (EOL) -> vuln"                              "$(ev 'NODE\tv20.19.0\t/n\nBIN\tUNKNOWN\t/n\n' node)" VULN
expect_eq "bun 1.4.3 -> vuln"                                  "$(ev 'BUN\t1.4.3\t/b\nBIN\tUNKNOWN\t/b\n' bun)" VULN
expect_eq "bun 1.4.4 -> ok"                                    "$(ev 'BUN\t1.4.4\t/b\nBIN\tUNKNOWN\t/b\n' bun)" OK
expect_eq "envoy 1.36.11 -> vuln"                              "$(ev 'ENVOY\t1.36.11\t/e\nBIN\tUNKNOWN\t/e\n' envoy)" VULN
expect_eq "envoy 1.39.3 -> ok"                                 "$(ev 'ENVOY\t1.39.3\t/e\nBIN\tUNKNOWN\t/e\n' envoy)" OK
expect_eq "envoy 1.40.0 -> ok"                                 "$(ev 'ENVOY\t1.40.0\t/e\nBIN\tUNKNOWN\t/e\n' envoy)" OK
expect_eq ".NET 9.0.21 (path) -> vuln" "$(ev 'BIN\tUNKNOWN\t/usr/share/dotnet/shared/Microsoft.NETCore.App/9.0.21/libSystem.IO.Compression.Native.so\n' dotnet)" VULN
expect_eq ".NET 8.0.33 (path) -> ok"   "$(ev 'BIN\tUNKNOWN\t/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.33/libSystem.IO.Compression.Native.so\n' dotnet)" OK
expect_eq "Python Brotli 1.2.1 -> ok"                          "$(ev 'PY\tBrotli\t1.2.1\t/x\n' python)" OK
expect_eq "brotlicffi 1.2.0.1 -> vuln"                         "$(ev 'PY\tbrotlicffi\t1.2.0.1\t/x\n' python)" VULN
expect_eq "same binary twice: vulnerable wins over patched"    "$(ev 'BIN\tVULNERABLE\t/n\nBIN\tPATCHED\t/n\n' binary)" VULN
expect_eq "same binary twice, other order: vulnerable wins"    "$(ev 'BIN\tPATCHED\t/n\nBIN\tVULNERABLE_10X\t/n\n' binary)" VULN
expect_eq "names with control characters -> review"            "$(ev 'ODDNAMES\t3\n' names)" REVIEW
expect_eq "control characters from the container are dropped" \
  "$(printf 'BEGIN\nOS\tx\033[2Jy\r\nEND\n' | bash "$SCAN" --evaluate-stdin | awk -F'\t' '$1=="O" { print $2 }')" 'x[2Jy'

# --- YARA rules ----------------------------------------------------------------
echo "YARA rules"
if [ -f "$PYLIB/.ok" ]; then
  python3 -I "$HERE/yara_check.py" "$PYLIB" "$ROOT/yara/brotli_cve_2026_111497.yar" "$BROTLI_TEST_FIXTURES" > "$TMP/yara.out" 2>&1
  cat "$TMP/yara.out"
  pass=$((pass + $(grep -c '^  ok' "$TMP/yara.out"))); fail=$((fail + $(grep -c '^  FAIL' "$TMP/yara.out")))
  grep -q -e '^  ok' -e '^  FAIL' "$TMP/yara.out" || bad "yara_check.py ran" "$(tail -n 1 "$TMP/yara.out")"
else skip "YARA tests (helpers not built)"; fi

# --- fuzz tests: a short, fixed-seed session (tests/fuzz/run-fuzz.sh runs longer)
echo "fuzz"
FUZZ_RUNS=${BROTLI_FUZZ_RUNS:-200}
if [ -d "$PYLIB/atheris" ]; then
  FZ_SHELLS="sh"
  case " $SHELLS " in *" dash "*) FZ_SHELLS="$FZ_SHELLS dash" ;; esac
  [ -n "$BB" ] && FZ_SHELLS="$FZ_SHELLS busybox"
  for t in evaluator probe; do
    mkdir -p "$TMP/fuzz-$t"
    if (cd "$TMP/fuzz-$t" && BROTLI_FUZZ_SHELLS="$FZ_SHELLS" TMPDIR="$TMP/fuzz-$t" python3 -I "$HERE/fuzz/fuzz_scanner.py" \
          "$PYLIB" "$t" -runs="$FUZZ_RUNS" -seed=1 -len_control=0 -max_len=1024 > "$TMP/fuzz-$t.log" 2>&1)
    then ok "fuzz $t: $FUZZ_RUNS random inputs"
    else bad "fuzz $t" "$(grep -m 1 -E 'Error|error' "$TMP/fuzz-$t.log" | cut -c 1-300); input $(grep -m 1 '^Base64:' "$TMP/fuzz-$t.log")"; fi
  done
elif [ "$(uname -m)" = x86_64 ]; then skip "fuzz tests (atheris not installed: run tests/build-fixtures.sh)"
else printf '  note  fuzz tests need x86_64 (atheris has no %s wheels)\n' "$(uname -m)"; fi

echo
echo "passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
