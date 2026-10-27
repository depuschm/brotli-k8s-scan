#!/usr/bin/env bash
# brotli-k8s-scan.sh - find containers affected by CVE-2026-111497
# ("Broccoli2Shell" / "Node2Shell" / "HTTP2Shell"), an out-of-bounds write in
# the Google Brotli decoder 1.0.3-1.2.0 (fixed in 1.0.10, 1.1.1, 1.2.1).
#
# READ-ONLY: it lists pods, then runs a small inspection script (POSIX sh) in
# ONE running container per unique image via `kubectl exec`. The script only
# reads files and prints versions. Nothing is installed, changed or restarted.
#
# How it decides (two independent signals):
#  1. Version numbers: Node.js (22.23.4 / 24.22.1 / 26.12.1), Bun (1.4.4),
#     Python Brotli (1.2.1) and brotlicffi (1.2.1.0) dist-info folders.
#  2. Binary fingerprint, which also catches BUNDLED copies (Node, .NET's
#     libSystem.IO.Compression.Native.so, nginx modules, Python wheels, ...):
#     the fix added the decoder error code "_ERROR_FORMAT_BLOCK_SWITCH"
#     (1.0.x: "BLOCK_SWITCH"). A file that contains the Brotli dictionary and
#     the decoder error table but NOT that code is vulnerable. Stripped static
#     binaries may lack the error table -> reported as REVIEW (unknown version).
#
# Requirements (your machine): bash, kubectl, jq, awk.
# RBAC: get/list pods, create pods/exec.
#
# Usage:
#   ./brotli-k8s-scan.sh                      # all namespaces, current context
#   ./brotli-k8s-scan.sh -n my-namespace      # one namespace
#   ./brotli-k8s-scan.sh --context prod --deep
#   ./brotli-k8s-scan.sh --rootfs ./extracted-image   # offline: scan an
#        unpacked image filesystem (for distroless images without a shell)
#
# Options:
#   -n, --namespace NS   only this namespace (default: all namespaces)
#   --context CTX        kubectl context
#   --deep               fingerprint every executable / .so > 100 KB, not just
#                        the usual suspects (slower, finds statically linked copies)
#   -o, --out DIR        output directory (default: ./brotli-scan-<timestamp>)
#   --timeout SEC        per-container exec timeout (default 180, needs `timeout`)
#   --rootfs DIR         scan an extracted container filesystem locally instead
#   -h, --help
#
# Exit code: 0 = nothing vulnerable found, 1 = vulnerable found, 2 = usage/error,
#            3 = nothing vulnerable but some items need manual review.

set -u

NS=""; CTX=""; DEEP=0; OUT=""; TMO=180; ROOTFS=""

die() { echo "error: $*" >&2; exit 2; }
usage() { sed -n '2,/^set -u/p' "$0" | sed -e 's/^# \{0,1\}//' -e '/^set -u/d'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -n|--namespace) NS="${2:-}"; shift 2 ;;
    --context) CTX="${2:-}"; shift 2 ;;
    --deep) DEEP=1; shift ;;
    -o|--out) OUT="${2:-}"; shift 2 ;;
    --timeout) TMO="${2:-}"; shift 2 ;;
    --rootfs) ROOTFS="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

[ -n "$OUT" ] || OUT="./brotli-scan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/raw" || die "cannot create $OUT"

# ---------------------------------------------------------------------------
# Probe: runs INSIDE the container (or locally against --rootfs). POSIX sh,
# works with dash/ash/busybox. Args: $1=root prefix ("" in a container),
# $2=1 to run binaries for version info (0 in rootfs mode), $3=deep (0/1).
# Output: tab-separated records.
# ---------------------------------------------------------------------------
read -r -d '' PROBE <<'PROBE_EOF'
R="$1"; X="${2:-1}"; D="${3:-0}"
T=$(printf '\t')
S="${R:-/}"
echo "BEGIN"
f="$R/etc/os-release"; [ -r "$f" ] || f="$R/usr/lib/os-release"
[ -r "$f" ] && echo "OS${T}$(sed -n 's/^PRETTY_NAME=//p' "$f" | tr -d '"')"

# --- runtimes (only when executing inside the container) ---
if [ "$X" = 1 ]; then
  for c in node nodejs; do
    p=$(command -v "$c" 2>/dev/null) && [ -n "$p" ] && { r=$(readlink -f "$p" 2>/dev/null || echo "$p"); echo "NODE${T}$("$p" -v 2>/dev/null | head -n 1)${T}${r#$R}"; }
  done
  p=$(command -v bun 2>/dev/null) && [ -n "$p" ] && { r=$(readlink -f "$p" 2>/dev/null || echo "$p"); echo "BUN${T}$("$p" --version 2>/dev/null | head -n 1)${T}${r#$R}"; }
  p=$(command -v dotnet 2>/dev/null) && [ -n "$p" ] && "$p" --list-runtimes 2>/dev/null | while IFS= read -r l; do echo "DOTNET${T}$l"; done
  p=$(command -v curl 2>/dev/null) && [ -n "$p" ] && echo "CURL${T}$("$p" -V 2>/dev/null | head -n 1)"
  command -v rpm >/dev/null 2>&1 && rpm -qa 2>/dev/null | grep -i brotli | while IFS= read -r l; do echo "OSPKG${T}rpm${T}$l"; done
fi

# --- OS packages from package DBs (works in both modes) ---
if [ -r "$R/var/lib/dpkg/status" ]; then
  awk -v T="$T" '/^Package: /{p=$2} /^Version: /{v=$2} /^$/{if(p ~ /brotli/) print "OSPKG" T "dpkg" T p " " v; p=""; v=""} END{if(p ~ /brotli/) print "OSPKG" T "dpkg" T p " " v}' "$R/var/lib/dpkg/status"
fi
if [ -r "$R/lib/apk/db/installed" ]; then
  awk -v T="$T" '/^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)} /^$/{if(p ~ /brotli/) print "OSPKG" T "apk" T p " " v; p=""; v=""} END{if(p ~ /brotli/) print "OSPKG" T "apk" T p " " v}' "$R/lib/apk/db/installed"
fi

# --- Python packages (any venv / site-packages on the image filesystem) ---
find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type d \
  \( -iname 'brotli-*.dist-info' -o -iname 'brotli-*.egg-info' -o -iname 'brotlicffi-*.dist-info' \
     -o -iname 'brotlicffi-*.egg-info' -o -iname 'brotlipy-*.dist-info' -o -iname 'brotlipy-*.egg-info' \) -print 2>/dev/null |
while IFS= read -r d; do
  b=$(basename "$d"); b=${b%.dist-info}; b=${b%.egg-info}
  n=${b%%-*}; v=${b#*-}; v=${v%%-py*}
  echo "PY${T}$n${T}$v${T}${d#$R}"
done

# --- Java: brotli4j bundles the C library inside jars (cannot fingerprint) ---
find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type f \
  \( -iname 'brotli4j*.jar' -o -iname 'native-linux-*.jar' -o -iname 'jvmbrotli*.jar' \) -print 2>/dev/null |
while IFS= read -r j; do echo "JAR${T}${j#$R}"; done

# --- Binary fingerprinting ---
classify() {
  f="$1"
  case "$(basename "$f")" in libbrotlicommon*|libbrotlienc*) return 0 ;; esac
  # Turn every non-printable byte into a newline first: binaries contain NUL
  # bytes, and BusyBox grep (Alpine) stops reading a line at the first NUL.
  # One pass collects every relevant string; the checks below run on that.
  m=$(LC_ALL=C tr -c ' -~' '\n' < "$f" 2>/dev/null |
      LC_ALL=C grep -F -e 'timedownlifeleftback' -e 'BrotliDecoder' -e 'EXUBERANT_NIBBLE' -e 'BLOCK_SWITCH' 2>/dev/null)
  [ -n "$m" ] || return 0
  dict=0; case "$m" in *timedownlifeleftback*) dict=1 ;; esac   # Brotli code compiled in
  case "$m" in
    *_ERROR_FORMAT_BLOCK_SWITCH*)     s=PATCHED ;;
    *_ERROR_FORMAT_EXUBERANT_NIBBLE*) s=VULNERABLE ;;
    *)
      # 1.0.x error table stores bare names ("EXUBERANT_NIBBLE", "BLOCK_SWITCH")
      if printf '%s\n' "$m" | LC_ALL=C grep -q -x 'EXUBERANT_NIBBLE'; then
        if printf '%s\n' "$m" | LC_ALL=C grep -q -x 'BLOCK_SWITCH'; then s=PATCHED_10X; else s=VULNERABLE_10X; fi
      elif [ "$dict" = 1 ]; then
        s=UNKNOWN  # Brotli code present but no error table (stripped / LTO): version unknown
      else
        return 0   # only imports libbrotli symbols; the shared library is checked on its own
      fi ;;
  esac
  echo "BIN${T}$s${T}${f#$R}"
}
{
  find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type f \
    \( -name node -o -name nodejs -o -name bun -o -name envoy -o -name nginx -o -name curl -o -name dotnet \
       -o -name 'libnode.so*' -o -name 'libbrotli*' -o -name '_brotli*.so' -o -name '*brotli*.so*' \
       -o -name 'libSystem.IO.Compression.Native.so' -o -name 'libcurl.so*' -o -name '*.node' \
       -o -name 'ngx_http_brotli*' \) -print 2>/dev/null
  if [ "$D" = 1 ]; then
    find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type f -size +100k \
      \( -perm -100 -o -name '*.so' -o -name '*.so.*' \) -print 2>/dev/null
  fi
} | sort -u | while IFS= read -r f; do classify "$f"; done
echo "END"
PROBE_EOF

# ---------------------------------------------------------------------------
# Evaluator: turns probe output into findings + one verdict.
# Prints lines:  F<TAB>state<TAB>kind<TAB>what<TAB>note   and  V<TAB>verdict
# states: VULN, REVIEW, OK, INFO
# ---------------------------------------------------------------------------
evaluate() {
  awk -F'\t' '
  function vcmp(a, b,   n, m, i, x, y, ax, bx) {
    sub(/^v/, "", a); sub(/^v/, "", b)
    n = split(a, ax, /[^0-9]+/); m = split(b, bx, /[^0-9]+/)
    for (i = 1; i <= (n > m ? n : m); i++) { x = ax[i] + 0; y = bx[i] + 0; if (x < y) return -1; if (x > y) return 1 }
    return 0
  }
  function node_state(v,   p, maj) {
    sub(/^v/, "", v); split(v, p, "."); maj = p[1] + 0
    if (v == "") return "REVIEW"
    if (maj == 22) return vcmp(v, "22.23.4") < 0 ? "VULN" : "OK"
    if (maj == 24) return vcmp(v, "24.22.1") < 0 ? "VULN" : "OK"
    if (maj == 26) return vcmp(v, "26.12.1") < 0 ? "VULN" : "OK"
    if (maj >= 27) return "OK"
    return "EOL"
  }
  function add(state, kind, what, note) { nf++; FS_[nf] = state; FK[nf] = kind; FW[nf] = what; FN[nf] = note }
  $1 == "BEGIN" { began = 1 }
  $1 == "END"   { ended = 1 }
  $1 == "EXECFAIL" { add("REVIEW", "exec", $2, "could not run the probe (no shell / distroless?). Scan the image offline with --rootfs") }
  $1 == "OS"    { os = $2 }
  $1 == "NODE"  { nn++; NV[nn] = $2; NP[nn] = $3 }
  $1 == "BUN"   { bn++; BV[bn] = $2; BP[bn] = $3 }
  $1 == "BIN"   { bin[$3] = $2; binorder[++nb] = $3 }
  $1 == "PY" {
    n = tolower($2); v = $3
    if (n == "brotli")          add(vcmp(v, "1.2.1") < 0 ? "VULN" : "OK", "python", "Brotli " v " (" $4 ")", vcmp(v, "1.2.1") < 0 ? "upgrade to Brotli>=1.2.1" : "")
    else if (n == "brotlicffi") add(vcmp(v, "1.2.1.0") < 0 ? "VULN" : "OK", "python", "brotlicffi " v " (" $4 ")", vcmp(v, "1.2.1.0") < 0 ? "upgrade to brotlicffi>=1.2.1.0" : "")
    else if (n == "brotlipy")   add("REVIEW", "python", "brotlipy " v " (" $4 ")", "unmaintained, bundles old Brotli; replace with brotlicffi>=1.2.1.0")
  }
  $1 == "JAR"    { add("REVIEW", "java", $2, "jar may bundle native Brotli (brotli4j); check vendor advisory") }
  $1 == "OSPKG"  { add("INFO", "ospkg", $2 ": " $3, "distro may backport; the library file itself is fingerprinted below") }
  $1 == "DOTNET" { add("INFO", "dotnet", $2, "runtime bundles Brotli in libSystem.IO.Compression.Native.so (fingerprinted)") }
  $1 == "CURL"   { add("INFO", "curl", $2, "") }
  END {
    if (!began && nf == 0) add("REVIEW", "exec", "no probe output", "probe did not run")
    else if (began && !ended) add("REVIEW", "exec", "probe output incomplete", "timeout or interrupted")
    for (i = 1; i <= nn; i++) {
      s = node_state(NV[i]); b = (NP[i] in bin) ? bin[NP[i]] : ""
      if (b == "PATCHED" && s != "OK")       add("OK", "node", "node " NV[i] " (" NP[i] ")", "version predates fix but binary contains the fix (vendor backport)")
      else if (b ~ /^VULNERABLE/)            add("VULN", "node", "node " NV[i] " (" NP[i] ")", "upgrade to 22.23.4 / 24.22.1 / 26.12.1")
      else if (s == "VULN")                  add(b == "" ? "REVIEW" : "VULN", "node", "node " NV[i] " (" NP[i] ")", b == "" ? "old version, but binary has no embedded Brotli (uses system lib, see below)" : "upgrade to 22.23.4 / 24.22.1 / 26.12.1")
      else if (s == "EOL")                   add(b == "" ? "REVIEW" : "VULN", "node", "node " NV[i] " (" NP[i] ")", "end-of-life line, no fix will ship: move to 22/24/26")
      else                                   add("OK", "node", "node " NV[i] " (" NP[i] ")", "")
      if (NP[i] in bin) used[NP[i]] = 1
    }
    for (i = 1; i <= bn; i++) {
      v = BV[i]; b = (BP[i] in bin) ? bin[BP[i]] : ""
      if (b == "PATCHED" || (b !~ /^VULNERABLE/ && vcmp(v, "1.4.4") >= 0)) add("OK", "bun", "bun " v " (" BP[i] ")", "")
      else add("VULN", "bun", "bun " v " (" BP[i] ")", "upgrade to Bun>=1.4.4")
      if (BP[i] in bin) used[BP[i]] = 1
    }
    for (i = 1; i <= nb; i++) {
      p = binorder[i]; if (p in used) continue; s = bin[p]
      if (s == "PATCHED")             add("OK", "binary", p, "contains Brotli fix")
      else if (s == "PATCHED_10X")    add("OK", "binary", p, "Brotli 1.0.x with fix (heuristic)")
      else if (s == "VULNERABLE")     add("VULN", "binary", p, "embeds vulnerable Brotli decoder (1.1.x/1.2.x without fix)")
      else if (s == "VULNERABLE_10X") add("VULN", "binary", p, "embeds vulnerable Brotli decoder (1.0.x without fix; <1.0.3 is not affected but is ancient)")
      else                            add("REVIEW", "binary", p, "contains Brotli decoder, version not detectable (stripped). Ask vendor / rebuild")
    }
    v = "NO_BROTLI_FOUND"
    for (i = 1; i <= nf; i++) if (FS_[i] == "OK" && v == "NO_BROTLI_FOUND") v = "PATCHED"
    for (i = 1; i <= nf; i++) if (FS_[i] == "REVIEW" && v != "VULNERABLE") v = "REVIEW"
    for (i = 1; i <= nf; i++) if (FS_[i] == "VULN") v = "VULNERABLE"
    if (os != "") print "O\t" os
    for (i = 1; i <= nf; i++) print "F\t" FS_[i] "\t" FK[i] "\t" FW[i] "\t" FN[i]
    print "V\t" v
  }'
}

summarize_findings() {  # $1 = evaluated file -> one-line summary of VULN/REVIEW findings
  awk -F'\t' '$1=="F" && ($2=="VULN" || $2=="REVIEW") { s = s (s ? "; " : "") $2 ": " $4 } END { print (s ? s : "-") }' "$1"
}

# ---------------------------------------------------------------------------
# Mode 1: local rootfs
# ---------------------------------------------------------------------------
if [ -n "$ROOTFS" ]; then
  [ -d "$ROOTFS" ] || die "--rootfs: not a directory: $ROOTFS"
  R=$(cd "$ROOTFS" && pwd -P)
  ${BROTLI_PROBE_SHELL:-sh} -c "$PROBE" probe "$R" 0 "$DEEP" > "$OUT/raw/rootfs.txt" 2>/dev/null
  evaluate < "$OUT/raw/rootfs.txt" > "$OUT/raw/rootfs.eval"
  verdict=$(awk -F'\t' '$1=="V"{print $2}' "$OUT/raw/rootfs.eval")
  echo "Rootfs: $R"
  echo "Verdict: $verdict"
  awk -F'\t' '$1=="F" { printf "  [%-6s] %-7s %s%s\n", $2, $3, $4, ($5 ? "  -> " $5 : "") }' "$OUT/raw/rootfs.eval"
  case "$verdict" in VULNERABLE) exit 1 ;; REVIEW) exit 3 ;; *) exit 0 ;; esac
fi

# ---------------------------------------------------------------------------
# Mode 2: cluster
# ---------------------------------------------------------------------------
command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
command -v jq >/dev/null 2>&1 || die "jq not found"

K=(kubectl)
[ -n "$CTX" ] && K+=(--context "$CTX")
if [ -n "$NS" ]; then NSARG=(-n "$NS"); else NSARG=(--all-namespaces); fi

TIMEOUT=()
command -v timeout >/dev/null 2>&1 && TIMEOUT=(timeout "$TMO")

echo "Listing pods..." >&2
"${K[@]}" get pods "${NSARG[@]}" -o json > "$OUT/pods.json" || die "kubectl get pods failed"

# imageKey, image, namespace, pod, container, owner
jq -r '
  .items[] | select(.status.phase == "Running") | . as $p
  | (.status.containerStatuses // [])[] | select(.state.running != null)
  | [ (if (.imageID // "") != "" then .imageID else .image end),
      .image, $p.metadata.namespace, $p.metadata.name, .name,
      (($p.metadata.ownerReferences // [])[0] | if . then (.kind + "/" + .name) else "-" end) ]
  | @tsv' "$OUT/pods.json" > "$OUT/containers.tsv" || die "jq failed"

awk -F'\t' '!seen[$1]++' "$OUT/containers.tsv" > "$OUT/targets.tsv"
total=$(wc -l < "$OUT/targets.tsv" | tr -d ' ')
echo "Running containers: $(wc -l < "$OUT/containers.tsv" | tr -d ' '), unique images: $total" >&2
[ "$total" -gt 0 ] || { echo "No running containers found." >&2; exit 0; }

printf 'verdict\timage\timage_id\tsampled_namespace\tsampled_pod\tcontainer\tworkloads_using_image\tfindings\n' > "$OUT/report.tsv"

i=0
while IFS="$(printf '\t')" read -r key image ns pod ctr _owner; do
  i=$((i + 1))
  raw="$OUT/raw/$i.txt"; ev="$OUT/raw/$i.eval"; err="$OUT/raw/$i.err"
  printf '[%d/%d] %s  (%s/%s -c %s)\n' "$i" "$total" "$image" "$ns" "$pod" "$ctr" >&2
  {
    printf 'IMAGE\t%s\nKEY\t%s\nPOD\t%s/%s/%s\n' "$image" "$key" "$ns" "$pod" "$ctr"
    ${TIMEOUT[@]+"${TIMEOUT[@]}"} "${K[@]}" exec -n "$ns" "$pod" -c "$ctr" -- sh -c "$PROBE" probe "" 1 "$DEEP" < /dev/null 2> "$err"
  } > "$raw"
  if ! grep -q '^BEGIN' "$raw"; then
    printf 'EXECFAIL\t%s\n' "$(head -n 1 "$err" | tr '\t' ' ')" >> "$raw"
  fi
  evaluate < "$raw" > "$ev"
  verdict=$(awk -F'\t' '$1=="V"{print $2}' "$ev")
  users=$(awk -F'\t' -v k="$key" '$1==k { w = $3 "/" ($6 != "-" ? $6 : "pod/" $4); if (!s[w]++) out = out (out ? ", " : "") w } END { print out }' "$OUT/containers.tsv")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$verdict" "$image" "$key" "$ns" "$pod" "$ctr" "$users" "$(summarize_findings "$ev")" >> "$OUT/report.tsv"
  echo "        -> $verdict" >&2
done < "$OUT/targets.tsv"

# Detail file: every finding per image
{
  printf 'image\tstate\tkind\twhat\tnote\n'
  n=0
  while IFS="$(printf '\t')" read -r key image rest; do
    n=$((n + 1))
    awk -F'\t' -v img="$image" '$1=="F" { print img "\t" $2 "\t" $3 "\t" $4 "\t" $5 }' "$OUT/raw/$n.eval"
  done < "$OUT/targets.tsv"
} > "$OUT/findings.tsv"

echo
echo "=== Summary ($total unique images) ==="
for v in VULNERABLE REVIEW PATCHED NO_BROTLI_FOUND; do
  printf '%-16s %s\n' "$v" "$(awk -F'\t' -v v="$v" 'NR>1 && $1==v' "$OUT/report.tsv" | wc -l | tr -d ' ')"
done
echo
awk -F'\t' 'NR>1 && ($1=="VULNERABLE" || $1=="REVIEW") { printf "%-10s %s\n           used by: %s\n           %s\n", $1, $2, $7, $8 }' "$OUT/report.tsv"
echo
echo "Report:   $OUT/report.tsv   (one row per image)"
echo "Details:  $OUT/findings.tsv (every finding)"
echo "Raw:      $OUT/raw/"
[ "$DEEP" = 1 ] || echo "Tip: NO_BROTLI_FOUND only covers the usual suspects. Re-run with --deep to also fingerprint statically linked binaries."

if awk -F'\t' 'NR>1 && $1=="VULNERABLE"{f=1} END{exit !f}' "$OUT/report.tsv"; then exit 1; fi
if awk -F'\t' 'NR>1 && $1=="REVIEW"{f=1} END{exit !f}' "$OUT/report.tsv"; then exit 3; fi
exit 0
