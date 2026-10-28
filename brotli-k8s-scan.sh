#!/usr/bin/env bash
# brotli-k8s-scan.sh - find vulnerable Brotli decoders (CVE-2026-111497,
# "Broccoli2Shell" / "Node2Shell" / "HTTP2Shell") in Kubernetes clusters,
# container images and Linux filesystems. Brotli 1.0.3-1.2.0 is affected,
# fixed in 1.0.10, 1.1.1 and 1.2.1.
#
# Version numbers are not enough: patched builds often keep the old version
# string (Node.js 22.23.4 still reports Brotli 1.1.0; Ubuntu's fixed package
# is still "1.1.0"). So besides version checks this tool fingerprints the
# binaries themselves: the fix added the decoder error code
# "_ERROR_FORMAT_BLOCK_SWITCH" (1.0.x: "BLOCK_SWITCH"). A file that contains
# the Brotli decoder error table WITHOUT that code is vulnerable. This also
# finds bundled copies (Node, Bun, Python wheels, Pillow, .NET, nginx, ...).
#
# READ-ONLY. Nothing is installed, changed or restarted.
#
# Modes:
#   ./brotli-k8s-scan.sh                     cluster: kubectl exec a small sh probe
#                                            into ONE running container per image
#   ./brotli-k8s-scan.sh --no-exec           cluster, without exec: list pods, then pull
#                                            each image by digest and scan it locally
#   ./brotli-k8s-scan.sh --image REF [...]   scan container images (no cluster needed)
#   ./brotli-k8s-scan.sh --rootfs DIR        scan an unpacked filesystem; --rootfs / scans
#                                            this machine
#
# Options:
#   -n, --namespace NS    cluster modes: only this namespace (default: all)
#   --context CTX         kubectl context
#   --image REF           image to scan; repeat for several
#   --images-from FILE    file with one image reference per line
#   --platform P          image platform, e.g. linux/arm64 (image modes)
#   --deep                fingerprint every executable / .so > 100 KB, not just the
#                         usual suspects (finds statically linked copies; slower)
#   --sarif               also write report.sarif (GitHub code scanning etc.)
#   --dry-run             only list what would be scanned (pods/images); no exec, no pull
#   --print-probe         print the exact shell code that runs in containers, then exit
#   -o, --out DIR         output directory (default: ./brotli-scan-<timestamp>)
#   --timeout SEC         per-container exec timeout (default 180, needs `timeout`)
#   --version, -h/--help
#
# Requirements: bash, awk, tar. Cluster modes: kubectl, jq. Image modes: crane,
# docker or podman (set BROTLI_IMAGE_TOOL to choose). jq for report.json/.sarif.
# RBAC: get/list pods; plus create pods/exec for the default cluster mode.
#
# Output: report.tsv (one row per image), findings.tsv, report.json,
#         report.sarif (--sarif), raw/ (probe output).
# Exit code: 0 nothing vulnerable, 1 vulnerable found, 3 nothing vulnerable but
#            some items need manual review, 2 usage/error.
#
# https://github.com/depuschm/brotli-k8s-scan  (MIT)

set -u
VERSION="0.5.0"
REPO_URL="https://github.com/depuschm/brotli-k8s-scan"

NS=""; CTX=""; DEEP=0; OUT=""; TMO=180; ROOTFS=""; NOEXEC=0; SARIF=0; PLATFORM=""; EVAL_ONLY=0
PRINT_PROBE=0; DRY_RUN=0
IMAGES=(); IMAGES_FROM=""

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
    --no-exec) NOEXEC=1; shift ;;
    --image) [ -n "${2:-}" ] || die "--image needs a reference"; IMAGES+=("$2"); shift 2 ;;
    --images-from) IMAGES_FROM="${2:-}"; shift 2 ;;
    --platform) PLATFORM="${2:-}"; shift 2 ;;
    --sarif) SARIF=1; shift ;;
    --print-probe) PRINT_PROBE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --version) echo "brotli-k8s-scan $VERSION"; exit 0 ;;
    --evaluate-stdin) EVAL_ONLY=1; shift ;;   # internal: evaluate probe output from stdin (tests)
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

if [ -n "$IMAGES_FROM" ]; then
  [ -r "$IMAGES_FROM" ] || die "cannot read $IMAGES_FROM"
  while IFS= read -r l || [ -n "$l" ]; do
    l=${l%%#*}; l=$(printf '%s' "$l" | tr -d ' \t\r')
    [ -n "$l" ] && IMAGES+=("$l")
  done < "$IMAGES_FROM"
fi

if [ -n "$ROOTFS" ]; then MODE=rootfs
elif [ "${#IMAGES[@]}" -gt 0 ]; then MODE=image
else MODE=cluster; fi

if [ "$EVAL_ONLY" = 0 ] && [ "$PRINT_PROBE" = 0 ]; then
  [ -n "$OUT" ] || OUT="./brotli-scan-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$OUT/raw" || die "cannot create $OUT"
fi

HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1
[ "$SARIF" = 1 ] && [ "$HAVE_JQ" = 0 ] && die "--sarif needs jq"

# colours only for a terminal, and never with NO_COLOR set
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$(printf '\033[1;31m'); C_YEL=$(printf '\033[1;33m'); C_GRN=$(printf '\033[1;32m'); C_DIM=$(printf '\033[2m'); C_OFF=$(printf '\033[0m')
else C_RED=""; C_YEL=""; C_GRN=""; C_DIM=""; C_OFF=""; fi
paint() {  # verdict or state -> coloured text
  case "$1" in
    VULNERABLE|VULN) printf '%s%s%s' "$C_RED" "$1" "$C_OFF" ;;
    REVIEW)          printf '%s%s%s' "$C_YEL" "$1" "$C_OFF" ;;
    PATCHED|OK)      printf '%s%s%s' "$C_GRN" "$1" "$C_OFF" ;;
    *)               printf '%s%s%s' "$C_DIM" "$1" "$C_OFF" ;;
  esac
}

# ---------------------------------------------------------------------------
# Probe: runs INSIDE the container (cluster mode) or locally against an
# unpacked filesystem (image / rootfs modes). POSIX sh; works with dash and
# BusyBox ash. Args: $1=root prefix ("" in a container), $2=1 to run binaries
# for version info (0 for unpacked filesystems), $3=deep (0/1).
# Output: tab-separated records.
# ---------------------------------------------------------------------------
read -r -d '' PROBE <<'PROBE_EOF'
R="$1"; X="${2:-1}"; D="${3:-0}"
export LC_ALL=C
T=$(printf '\t')
S="${R:-/}"
# Hostile names and tool output must not be able to forge or shift a record:
# names containing control characters (tab, newline, ...) are counted and
# reported, never parsed; every other printed value is cleaned first.
CTL=$(printf '\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037\177')
clean() { printf '%s' "$1" | tr -d '\000-\037\177'; }
oddname() { case "$1" in *["$CTL"]*) return 0 ;; esac; return 1; }
# Paths from find: only complete paths below the scanned root. A name that
# contains a newline arrives in pieces; the pieces do not start with the root.
ours() { case "$1" in "$S"*) oddname "$1" && return 1; return 0 ;; esac; return 1; }
# Every file the probe reads must lie inside the scanned root: an image must
# not make us read host files through a symlink (etc/os-release -> /etc/...).
RR=""; [ -n "$R" ] && RR=$(cd "$R" 2>/dev/null && pwd -P)
inside() {  # $1 is a regular file, not a symlink, in a directory below the root
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  [ -n "$R" ] || return 0
  case "$(cd "${1%/*}/" 2>/dev/null && pwd -P)/" in "$RR"/*) return 0 ;; esac
  return 1
}
resolve() {  # prints the file to read for $1: symlinks resolved as inside the image
  p=$1; i=0
  while [ -L "$p" ]; do
    i=$((i + 1)); [ "$i" -le 8 ] || return 1
    l=$(readlink "$p" 2>/dev/null) || return 1
    case "$l" in /*) p="$R$l" ;; *) p="${p%/*}/$l" ;; esac
  done
  inside "$p" && printf '%s' "$p"
}
# Records go out with printf: some shells' echo turns \n or \t in a name or a
# version string into a real newline or tab, which would forge a record.
rec() { printf '%s\n' "$1"; }
echo "BEGIN"
f=$(resolve "$R/etc/os-release") || f=$(resolve "$R/usr/lib/os-release") || f=""
[ -n "$f" ] && rec "OS${T}$(clean "$(sed -n 's/^PRETTY_NAME=//p' "$f" | head -n 1 | tr -d '"')")"

# --- runtimes (only when executing inside the container) ---
if [ "$X" = 1 ]; then
  rt() {  # $1=record type $2=command
    p=$(command -v "$2" 2>/dev/null) && [ -n "$p" ] || return 0
    r=$(readlink -f "$p" 2>/dev/null || printf '%s' "$p")
    case "$1" in
      NODE)  v=$("$p" -v 2>/dev/null | head -n 1) ;;
      ENVOY) v=$("$p" --version 2>/dev/null | sed -n 's|.*/\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)[/-].*|\1|p' | head -n 1) ;;
      *)     v=$("$p" --version 2>/dev/null | head -n 1) ;;
    esac
    rec "$1${T}$(clean "$v")${T}$(clean "${r#$R}")"
  }
  rt NODE node; rt NODE nodejs; rt BUN bun; rt ENVOY envoy
  p=$(command -v dotnet 2>/dev/null) && [ -n "$p" ] && "$p" --list-runtimes 2>/dev/null | while IFS= read -r l; do rec "DOTNET${T}$(clean "$l")"; done
  p=$(command -v curl 2>/dev/null) && [ -n "$p" ] && rec "CURL${T}$(clean "$("$p" -V 2>/dev/null | head -n 1)")"
  command -v rpm >/dev/null 2>&1 && rpm -qa 2>/dev/null | grep -i brotli | while IFS= read -r l; do rec "OSPKG${T}rpm${T}$(clean "$l")"; done
fi

# --- OS packages from package DBs (works in both modes) ---
if f=$(resolve "$R/var/lib/dpkg/status"); then
  awk -v T="$T" 'function c(s) { gsub(/[[:cntrl:]]/, "", s); return s }
    /^Package: /{p=$2} /^Version: /{v=$2}
    /^$/{if(p ~ /brotli/) print "OSPKG" T "dpkg" T c(p) " " c(v); p=""; v=""}
    END{if(p ~ /brotli/) print "OSPKG" T "dpkg" T c(p) " " c(v)}' "$f"
fi
if f=$(resolve "$R/lib/apk/db/installed"); then
  awk -v T="$T" 'function c(s) { gsub(/[[:cntrl:]]/, "", s); return s }
    /^P:/{p=substr($0,3)} /^V:/{v=substr($0,3)}
    /^$/{if(p ~ /brotli/) print "OSPKG" T "apk" T c(p) " " c(v); p=""; v=""}
    END{if(p ~ /brotli/) print "OSPKG" T "apk" T c(p) " " c(v)}' "$f"
fi

# --- Python packages (any venv / site-packages on the filesystem) ---
find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type d \
  \( -iname 'brotli-*.dist-info' -o -iname 'brotli-*.egg-info' -o -iname 'brotlicffi-*.dist-info' \
     -o -iname 'brotlicffi-*.egg-info' -o -iname 'brotlipy-*.dist-info' -o -iname 'brotlipy-*.egg-info' \) -print 2>/dev/null |
while IFS= read -r d; do
  ours "$d" && [ -d "$d" ] || continue
  b=$(basename "$d"); b=${b%.dist-info}; b=${b%.egg-info}
  n=${b%%-*}; v=${b#*-}; v=${v%%-py*}
  rec "PY${T}$n${T}$v${T}${d#$R}"
done

# --- .NET: runtime version from *.deps.json (shared framework and self-contained
#     apps), and whether the Brotli native library next to it bundles Brotli
#     ("bundled") or uses the system libbrotli ("linked"), or is absent ---
find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type f -name '*.deps.json' -print 2>/dev/null |
while IFS= read -r j; do
  ours "$j" && inside "$j" || continue
  v=$(grep -o 'Microsoft\.NETCore\.App\.Runtime\.[A-Za-z0-9_.-]*/[0-9][0-9.]*' "$j" 2>/dev/null | head -n 1 | sed 's|.*/||')
  [ -n "$v" ] || continue
  if ! l=$(resolve "$(dirname "$j")/libSystem.IO.Compression.Native.so"); then ls=absent
  elif tr -c ' -~' '\n' < "$l" 2>/dev/null | grep -q -F 'timedownlifeleftback'; then ls=bundled
  else ls=linked; fi
  rec "DOTNETRT${T}$v${T}${j#$R}${T}$ls"
done

# --- Java: brotli4j bundles the C library inside jars (cannot fingerprint) ---
find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o -type f \
  \( -iname 'brotli4j*.jar' -o -iname 'native-linux-*.jar' -o -iname 'jvmbrotli*.jar' \) -print 2>/dev/null |
while IFS= read -r j; do ours "$j" && [ -f "$j" ] && rec "JAR${T}${j#$R}"; done

# --- Binary fingerprinting ---
classify() {
  f="$1"
  case "$(basename "$f")" in libbrotlicommon*|libbrotlienc*) return 0 ;; esac
  # Turn every non-printable byte into a newline first: binaries contain NUL
  # bytes, and BusyBox grep (Alpine) stops reading a line at the first NUL.
  # One pass collects every relevant string; the checks below run on that.
  m=$(tr -c ' -~' '\n' < "$f" 2>/dev/null |
      grep -F -e 'timedownlifeleftback' -e 'BrotliDecoder' -e 'EXUBERANT_NIBBLE' -e 'BLOCK_SWITCH' 2>/dev/null)
  [ -n "$m" ] || return 0
  dict=0; case "$m" in *timedownlifeleftback*) dict=1 ;; esac   # Brotli code compiled in
  case "$m" in
    *_ERROR_FORMAT_BLOCK_SWITCH*)     s=PATCHED ;;
    *_ERROR_FORMAT_EXUBERANT_NIBBLE*) s=VULNERABLE ;;
    *)
      # 1.0.x error table stores bare names ("EXUBERANT_NIBBLE", "BLOCK_SWITCH")
      if printf '%s\n' "$m" | grep -q -x 'EXUBERANT_NIBBLE'; then
        if printf '%s\n' "$m" | grep -q -x 'BLOCK_SWITCH'; then s=PATCHED_10X; else s=VULNERABLE_10X; fi
      elif [ "$dict" = 1 ]; then
        s=UNKNOWN  # Brotli code present but no error table (stripped / LTO): version unknown
      else
        return 0   # only imports libbrotli symbols; the shared library is checked on its own
      fi ;;
  esac
  rec "BIN${T}$s${T}${f#$R}"
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
} | sort -u | while IFS= read -r f; do ours "$f" && inside "$f" && classify "$f"; done

# --- names with control characters: never parsed above, so report them ---
n=$(find "$S" -xdev \( -path "$R/proc" -o -path "$R/sys" -o -path "$R/dev" \) -prune -o \( -type f -o -type d \) -name "*[$CTL]*" -print0 2>/dev/null | tr -cd '\000' | wc -c | tr -d ' ')
[ "${n:-0}" -gt 0 ] && rec "ODDNAMES${T}$n"
echo "END"
PROBE_EOF

[ "$PRINT_PROBE" = 1 ] && { printf '%s\n' "$PROBE"; exit 0; }

# ---------------------------------------------------------------------------
# Evaluator: probe output -> findings + one verdict. Prints
#   O<TAB>os   F<TAB>state<TAB>kind<TAB>what<TAB>note<TAB>path   V<TAB>verdict
# states: VULN, REVIEW, OK, INFO
# ---------------------------------------------------------------------------
evaluate() {
  LC_ALL=C awk -F'\t' '
  function vcmp(a, b,   n, m, i, x, y, ax, bx) {
    sub(/^v/, "", a); sub(/^v/, "", b)
    n = split(a, ax, /[^0-9]+/); m = split(b, bx, /[^0-9]+/)
    for (i = 1; i <= (n > m ? n : m); i++) { x = ax[i] + 0; y = bx[i] + 0; if (x < y) return -1; if (x > y) return 1 }
    return 0
  }
  function line(v, n,   p) { sub(/^v/, "", v); split(v, p, "."); return (n == 1) ? p[1] + 0 : (p[1] + 0) "." (p[2] + 0) }
  # runtime version rules -> OK / VULN / EOL / ""(unknown)
  function rt_state(kind, v,   maj, mm) {
    if (v == "") return ""
    if (kind == "node") {
      maj = line(v, 1)
      if (maj == 22) return vcmp(v, "22.23.4") < 0 ? "VULN" : "OK"
      if (maj == 24) return vcmp(v, "24.22.1") < 0 ? "VULN" : "OK"
      if (maj == 26) return vcmp(v, "26.12.1") < 0 ? "VULN" : "OK"
      return maj >= 27 ? "OK" : "EOL"
    }
    if (kind == "bun") return vcmp(v, "1.4.4") < 0 ? "VULN" : "OK"
    if (kind == "envoy") {
      mm = line(v, 2)
      if (mm == "1.39") return vcmp(v, "1.39.3") < 0 ? "VULN" : "OK"
      if (mm == "1.38") return vcmp(v, "1.38.6") < 0 ? "VULN" : "OK"
      if (mm == "1.37") return vcmp(v, "1.37.8") < 0 ? "VULN" : "OK"
      if (mm == "1.36") return vcmp(v, "1.36.12") < 0 ? "VULN" : "OK"
      return vcmp(v, "1.40.0") >= 0 ? "OK" : "EOL"
    }
    if (kind == "dotnet") {
      maj = line(v, 1)
      if (maj == 10) return vcmp(v, "10.0.14") < 0 ? "VULN" : "OK"
      if (maj == 9)  return vcmp(v, "9.0.22") < 0 ? "VULN" : "OK"
      if (maj == 8)  return vcmp(v, "8.0.33") < 0 ? "VULN" : "OK"
      return maj >= 11 ? "OK" : "EOL"
    }
    return ""
  }
  function fixhint(kind) {
    if (kind == "node")   return "upgrade to Node.js 22.23.4 / 24.22.1 / 26.12.1"
    if (kind == "bun")    return "upgrade to Bun 1.4.4"
    if (kind == "envoy")  return "upgrade to Envoy 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0 (Istio 1.29.9 / 1.30.6 / 1.31.2); exposed only if the Brotli decompressor is configured"
    if (kind == "dotnet") return "upgrade to .NET 8.0.33 / 9.0.22 / 10.0.14; republish self-contained apps"
    return ""
  }
  function add(state, kind, what, note, path) { nf++; FS_[nf] = state; FK[nf] = kind; FW[nf] = what; FN[nf] = note; FP[nf] = path }
  function rank(s) { return s ~ /^VULNERABLE/ ? 3 : (s ~ /^PATCHED/ ? 1 : 2) }
  # In cluster mode the probe runs on the container'"'"'s own shell and tools, which
  # can print anything: drop control characters first (terminal escapes, CR;
  # also C1 controls in UTF-8, which some terminals act on).
  { for (i = 1; i <= NF; i++) { gsub(/[[:cntrl:]]/, "", $i); gsub(/\302[\200-\237]/, "", $i) } }
  $1 == "BEGIN" { began = 1 }
  $1 == "END"   { ended = 1 }
  $1 == "EXECFAIL" { add("REVIEW", "exec", $2, "could not run the probe (no shell / distroless?). Re-run with --no-exec, or scan the image with --image", "") }
  $1 == "PULLFAIL" { add("REVIEW", "image", $2, "could not pull/unpack the image (registry login? platform?)", "") }
  $1 == "OS"    { os = $2 }
  $1 == "NODE" || $1 == "BUN" || $1 == "ENVOY" { nr++; RK[nr] = tolower($1); RV[nr] = $2; RP[nr] = $3 }
  # the same path twice (it should not happen): the worse state wins
  $1 == "BIN"   { if (!($3 in bin)) binorder[++nb] = $3; else if (rank(bin[$3]) >= rank($2)) next; bin[$3] = $2 }
  $1 == "ODDNAMES" { add("REVIEW", "names", $2 " file name(s) with control characters", "not scanned (tabs or newlines in names can mislead scanners); list them with: find ROOT -xdev -name '"'"'*[[:cntrl:]]*'"'"'", "") }
  $1 == "DOTNETRT" { nd++; DV[nd] = $2; DP[nd] = $3; DL[nd] = $4; d = $3; sub(/\/[^\/]*$/, "", d); DD[nd] = d; dver[d] = $2 }
  $1 == "PY" {
    n = tolower($2); v = $3
    if (n == "brotli")          add(vcmp(v, "1.2.1") < 0 ? "VULN" : "OK", "python", "Brotli " v, vcmp(v, "1.2.1") < 0 ? "upgrade to Brotli>=1.2.1" : "", $4)
    else if (n == "brotlicffi") add(vcmp(v, "1.2.1.0") < 0 ? "VULN" : "OK", "python", "brotlicffi " v, vcmp(v, "1.2.1.0") < 0 ? "upgrade to brotlicffi>=1.2.1.0" : "", $4)
    else if (n == "brotlipy")   add("REVIEW", "python", "brotlipy " v, "unmaintained, bundles old Brotli; replace with brotlicffi>=1.2.1.0", $4)
  }
  $1 == "JAR"    { add("REVIEW", "java", $2, "jar may bundle native Brotli (brotli4j); check vendor advisory", $2) }
  $1 == "OSPKG"  { add("INFO", "ospkg", $2 ": " $3, "distros backport fixes without changing the version; the library file itself is fingerprinted", "") }
  $1 == "DOTNET" { add("INFO", "dotnet", $2, "runtime bundles Brotli in libSystem.IO.Compression.Native.so (checked below)", "") }
  $1 == "CURL"   { add("INFO", "curl", $2, "", "") }
  END {
    if (!began && nf == 0) add("REVIEW", "exec", "no probe output", "probe did not run", "")
    else if (began && !ended) add("REVIEW", "exec", "probe output incomplete", "timeout or interrupted", "")
    # runtimes found via PATH: combine version rule with the binary fingerprint
    for (i = 1; i <= nr; i++) {
      k = RK[i]; v = RV[i]; p = RP[i]; s = rt_state(k, v); b = (p in bin) ? bin[p] : ""
      w = k " " v
      if (b == "PATCHED" || b == "PATCHED_10X") add("OK", k, w, (s == "VULN" || s == "EOL") ? "version predates fix but the binary contains it (vendor backport)" : "", p)
      else if (b ~ /^VULNERABLE/)              add("VULN", k, w, s == "EOL" ? "end-of-life line, no fix will ship" : fixhint(k), p)
      else if (s == "VULN" || s == "EOL")      add(b == "" ? "REVIEW" : "VULN", k, w, b == "" ? "old version, but no embedded Brotli found in the binary (may use the system library, see below)" : (s == "EOL" ? "end-of-life line, no fix will ship" : fixhint(k)), p)
      else if (s == "OK")                      add("OK", k, w, "", p)
      else                                     add("REVIEW", k, w, "version not readable", p)
      if (p in bin) used[p] = 1
    }
    for (i = 1; i <= nb; i++) {
      p = binorder[i]; if (p in used) continue; s = bin[p]
      # .NET shared runtime: version from the path
      dv = ""; if (match(p, /Microsoft\.NETCore\.App\/[0-9]+\.[0-9]+\.[0-9]+/)) { dv = substr(p, RSTART + 22, RLENGTH - 22) }
      pd = p; sub(/\/[^\/]*$/, "", pd)
      if (dv == "" && (pd in dver) && p ~ /libSystem\.IO\.Compression\.Native\.so$/) dv = dver[pd]
      if (s == "PATCHED")             add("OK", "binary", p, "contains Brotli fix", p)
      else if (s == "PATCHED_10X")    add("OK", "binary", p, "Brotli 1.0.x with fix", p)
      else if (s == "VULNERABLE")     add("VULN", "binary", p, "embeds vulnerable Brotli decoder (1.1.x/1.2.x without fix)" (dv != "" ? "; " fixhint("dotnet") : ""), p)
      else if (s == "VULNERABLE_10X") add("VULN", "binary", p, "embeds vulnerable Brotli decoder (1.0.x without fix)" (dv != "" ? "; " fixhint("dotnet") : ""), p)
      else if (dv != "" && rt_state("dotnet", dv) == "OK") add("OK", "dotnet", ".NET " dv, "runtime version contains the fix", p)
      else if (dv != "")              add("VULN", "dotnet", ".NET " dv, fixhint("dotnet"), p)
      else if (p ~ /(^|\/)envoy$/)    add("REVIEW", "envoy", p, "Envoy builds keep no Brotli error table, so its version decides: scan the running pod in the default cluster mode, or run envoy --version (fixed: 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0)", p)
      else                            add("REVIEW", "binary", p, "contains Brotli decoder, version not detectable (stripped). Ask vendor / rebuild", p)
    }
    for (i = 1; i <= nd; i++) {
      w = ".NET " DV[i] (DD[i] ~ /\/shared\/Microsoft\.NETCore\.App\// ? " runtime" : " (self-contained app)")
      if (DL[i] == "linked") add("INFO", "dotnet", w, "uses the system libbrotli; its patch state is that library (checked separately)", DP[i])
      else if (DL[i] == "absent") add("INFO", "dotnet", w, "no Brotli native library shipped", DP[i])
    }
    v = "NO_BROTLI_FOUND"
    for (i = 1; i <= nf; i++) if (FS_[i] == "OK" && v == "NO_BROTLI_FOUND") v = "PATCHED"
    for (i = 1; i <= nf; i++) if (FS_[i] == "REVIEW" && v != "VULNERABLE") v = "REVIEW"
    for (i = 1; i <= nf; i++) if (FS_[i] == "VULN") v = "VULNERABLE"
    if (os != "") print "O\t" os
    for (i = 1; i <= nf; i++) print "F\t" FS_[i] "\t" FK[i] "\t" FW[i] "\t" FN[i] "\t" FP[i]
    print "V\t" v
  }'
}

[ "$EVAL_ONLY" = 1 ] && { evaluate; exit 0; }

summarize_findings() {  # $1 = evaluated file -> one-line summary of VULN/REVIEW findings
  awk -F'\t' '$1=="F" && ($2=="VULN" || $2=="REVIEW") { w = $4; if ($6 != "" && index(w, $6) == 0) w = w " (" $6 ")"; s = s (s ? "; " : "") $2 ": " w } END { print (s ? s : "-") }' "$1"
}

run_probe_local() {  # $1=root dir -> probe output on stdout
  ${BROTLI_PROBE_SHELL:-sh} -c "$PROBE" probe "$1" 0 "$DEEP" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Image export (crane, docker or podman) into a temporary directory
# ---------------------------------------------------------------------------
IMG_TOOL=""
pick_image_tool() {
  if [ -n "${BROTLI_IMAGE_TOOL:-}" ]; then IMG_TOOL=$BROTLI_IMAGE_TOOL
  else for t in crane docker podman; do command -v "$t" >/dev/null 2>&1 && { IMG_TOOL=$t; break; }; done; fi
  [ -n "$IMG_TOOL" ] || die "image scanning needs crane, docker or podman (https://github.com/google/go-containerregistry/tree/main/cmd/crane)"
  command -v "$IMG_TOOL" >/dev/null 2>&1 || die "$IMG_TOOL not found"
}
export_image() {  # $1=ref $2=dest dir $3=error file ; 0 if something was unpacked
  local ref=$1 dest=$2 err=$3 cid rc
  mkdir -p "$dest"
  case "$IMG_TOOL" in
    crane)
      crane export ${PLATFORM:+--platform "$PLATFORM"} "$ref" - 2>"$err" | tar -x -f - -C "$dest" --no-same-owner 2>/dev/null
      rc=${PIPESTATUS[0]} ;;
    docker|podman)
      cid=$("$IMG_TOOL" create ${PLATFORM:+--platform "$PLATFORM"} "$ref" /nonexistent 2>"$err") || return 1
      "$IMG_TOOL" export "$cid" 2>>"$err" | tar -x -f - -C "$dest" --no-same-owner 2>/dev/null
      rc=${PIPESTATUS[0]}
      "$IMG_TOOL" rm -f "$cid" >/dev/null 2>&1 ;;
    *) echo "unsupported image tool: $IMG_TOOL" > "$err"; return 1 ;;
  esac
  [ "$rc" = 0 ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]
}
WORK=""
# shellcheck disable=SC2329  # called by the EXIT trap below
cleanup() { [ -n "$WORK" ] && [ -d "$WORK" ] && { chmod -R u+rwX "$WORK" 2>/dev/null; rm -rf "$WORK"; }; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build the target list:  key image ns pod container method ref
# ---------------------------------------------------------------------------
TAB=$(printf '\t')
: > "$OUT/containers.tsv"
case "$MODE" in
  rootfs)
    [ -d "$ROOTFS" ] || die "--rootfs: not a directory: $ROOTFS"
    R=$(cd "$ROOTFS" && pwd -P)
    printf 'rootfs:%s\t%s\t-\t-\t-\trootfs\t%s\n' "$R" "$R" "$R" > "$OUT/targets.tsv" ;;
  image)
    pick_image_tool
    : > "$OUT/targets.tsv"
    for ref in "${IMAGES[@]}"; do printf '%s\t%s\t-\t-\t-\timage\t%s\n' "$ref" "$ref" "$ref" >> "$OUT/targets.tsv"; done
    awk -F'\t' '!seen[$1]++' "$OUT/targets.tsv" > "$OUT/targets.tmp" && mv "$OUT/targets.tmp" "$OUT/targets.tsv" ;;
  cluster)
    command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
    [ "$HAVE_JQ" = 1 ] || die "jq not found"
    [ "$NOEXEC" = 1 ] && pick_image_tool
    K=(kubectl); [ -n "$CTX" ] && K+=(--context "$CTX")
    if [ -n "$NS" ]; then NSARG=(-n "$NS"); else NSARG=(--all-namespaces); fi
    echo "Listing pods..." >&2
    "${K[@]}" get pods "${NSARG[@]}" -o json > "$OUT/pods.json" || die "kubectl get pods failed"
    # imageKey, image, namespace, pod, container, owner, pullRef
    jq -r '
      .items[] | select(.status.phase == "Running") | . as $p
      | (.status.containerStatuses // [])[] | select(.state.running != null)
      | ((.imageID // "") | sub("^docker-pullable://"; "")) as $id
      | [ (if $id != "" then $id else .image end),
          .image, $p.metadata.namespace, $p.metadata.name, .name,
          (($p.metadata.ownerReferences // [])[0] | if . then (.kind + "/" + .name) else "-" end),
          (if ($id | test("@sha256:")) then $id else .image end) ]
      | @tsv' "$OUT/pods.json" > "$OUT/containers.tsv" || die "jq failed"
    method="exec"; [ "$NOEXEC" = 1 ] && method="image"
    awk -F'\t' -v m="$method" 'BEGIN { OFS = "\t" } !seen[$1]++ { print $1, $2, $3, $4, $5, m, $7 }' "$OUT/containers.tsv" > "$OUT/targets.tsv"
    echo "Running containers: $(wc -l < "$OUT/containers.tsv" | tr -d ' '), unique images: $(wc -l < "$OUT/targets.tsv" | tr -d ' ')" >&2 ;;
esac

total=$(wc -l < "$OUT/targets.tsv" | tr -d ' ')
[ "$total" -gt 0 ] || { echo "Nothing to scan (no running containers found)." >&2; exit 0; }

if [ "$DRY_RUN" = 1 ]; then
  echo "Dry run: would scan $total unique image(s); nothing was executed or pulled."
  while IFS="$TAB" read -r _key image ns pod ctr method ref; do
    case "$method" in
      exec)   printf '  exec   %s   in %s/%s -c %s\n' "$image" "$ns" "$pod" "$ctr" ;;
      image)  printf '  pull   %s   as %s\n' "$image" "$ref" ;;
      rootfs) printf '  read   %s\n' "$ref" ;;
    esac
  done < "$OUT/targets.tsv"
  echo "Target list: $OUT/targets.tsv"
  exit 0
fi

TIMEOUT=(); command -v timeout >/dev/null 2>&1 && TIMEOUT=(timeout "$TMO")

# ---------------------------------------------------------------------------
# Scan every target
# ---------------------------------------------------------------------------
printf 'verdict\timage\timage_id\tsampled_namespace\tsampled_pod\tcontainer\tworkloads_using_image\tfindings\tmethod\n' > "$OUT/report.tsv"
i=0
while IFS="$TAB" read -r key image ns pod ctr method ref; do
  i=$((i + 1))
  raw="$OUT/raw/$i.txt"; ev="$OUT/raw/$i.eval"; err="$OUT/raw/$i.err"
  case "$method" in
    exec)   printf '[%d/%d] %s  (exec %s/%s -c %s)\n' "$i" "$total" "$image" "$ns" "$pod" "$ctr" >&2 ;;
    image)  printf '[%d/%d] %s  (pull %s)\n' "$i" "$total" "$image" "$ref" >&2 ;;
    rootfs) printf '[%d/%d] %s\n' "$i" "$total" "$ref" >&2 ;;
  esac
  printf 'IMAGE\t%s\nKEY\t%s\n' "$image" "$key" > "$raw"
  case "$method" in
    exec)
      ${TIMEOUT[@]+"${TIMEOUT[@]}"} "${K[@]}" exec -n "$ns" "$pod" -c "$ctr" -- sh -c "$PROBE" probe "" 1 "$DEEP" < /dev/null >> "$raw" 2> "$err"
      xrc=$?
      if ! grep -q '^BEGIN' "$raw"; then
        # the reason may be on stderr (kubectl) or on stdout (runtime message)
        msg=$(grep -v '^[[:space:]]*$' "$err" | head -n 1)
        [ -n "$msg" ] || msg=$(sed -n '3,$p' "$raw" | grep -v '^[[:space:]]*$' | head -n 1)
        [ -n "$msg" ] || msg="kubectl exec failed with exit code $xrc"
        printf 'EXECFAIL\t%s\n' "$(printf '%s' "$msg" | tr -d '\r' | tr '\t' ' ')" >> "$raw"
      fi ;;
    image)
      [ -n "$WORK" ] || WORK=$(mktemp -d "${TMPDIR:-/tmp}/brotli-scan.XXXXXX")
      d="$WORK/rootfs"
      if export_image "$ref" "$d" "$err" < /dev/null; then
        run_probe_local "$(cd "$d" && pwd -P)" >> "$raw"
      else
        printf 'PULLFAIL\t%s\n' "$ref: $(grep -v '^[[:space:]]*$' "$err" | tail -n 1 | tr '\t' ' ')" >> "$raw"
      fi
      chmod -R u+rwX "$d" 2>/dev/null; rm -rf "$d" ;;
    rootfs)
      r=$ref; [ "$r" = / ] && r=""   # scanning this machine: no root prefix
      run_probe_local "$r" >> "$raw" ;;
  esac
  evaluate < "$raw" > "$ev"
  verdict=$(awk -F'\t' '$1=="V"{print $2}' "$ev")
  if [ "$MODE" = cluster ]; then
    users=$(awk -F'\t' -v k="$key" '$1==k { w = $3 "/" ($6 != "-" ? $6 : "pod/" $4); if (!s[w]++) out = out (out ? ", " : "") w } END { print out }' "$OUT/containers.tsv")
  else users="-"; fi
  [ "$method" = exec ] || { ns="-"; pod="-"; ctr="-"; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$verdict" "$image" "$key" "$ns" "$pod" "$ctr" "$users" "$(summarize_findings "$ev")" "$method" >> "$OUT/report.tsv"
  printf '        -> %s\n' "$(paint "$verdict")" >&2
done < "$OUT/targets.tsv"

# ---------------------------------------------------------------------------
# Reports: findings.tsv, report.json, report.sarif
# ---------------------------------------------------------------------------
{
  printf 'image\tstate\tkind\twhat\tnote\tpath\n'
  n=0
  while IFS="$TAB" read -r key image rest; do
    n=$((n + 1))
    awk -F'\t' -v img="$image" 'BEGIN { OFS = "\t" } $1=="F" { print img, $2, $3, $4, $5, $6 }' "$OUT/raw/$n.eval"
  done < "$OUT/targets.tsv"
} > "$OUT/findings.tsv"

if [ "$HAVE_JQ" = 1 ]; then
  n=0
  while IFS="$TAB" read -r verdict image key sns spod sctr users _summary method; do
    n=$((n + 1))
    jq -R -s --arg verdict "$verdict" --arg image "$image" --arg key "$key" --arg ns "$sns" --arg pod "$spod" \
          --arg ctr "$sctr" --arg users "$users" --arg method "$method" '
      split("\n") as $l
      | { image: $image, image_id: $key, verdict: $verdict, method: $method,
          os: ([$l[] | select(startswith("O\t")) | split("\t")[1]] | first // null),
          sampled: (if $method == "exec" then {namespace: $ns, pod: $pod, container: $ctr} else null end),
          workloads: (if $users == "-" or $users == "" then [] else ($users | split(", ")) end),
          findings: [ $l[] | select(startswith("F\t")) | split("\t")
                      | {state: .[1], kind: .[2], what: .[3], note: .[4], path: (.[5] // "")} ] }' "$OUT/raw/$n.eval"
  done < <(tail -n +2 "$OUT/report.tsv") | jq -s --arg v "$VERSION" --arg url "$REPO_URL" --arg mode "$MODE" \
      --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    { tool: {name: "brotli-k8s-scan", version: $v, url: $url},
      cve: "CVE-2026-111497", scanned_at: $at, mode: $mode,
      summary: (reduce .[] as $i ({VULNERABLE: 0, REVIEW: 0, PATCHED: 0, NO_BROTLI_FOUND: 0}; .[$i.verdict] += 1)),
      images: . }' > "$OUT/report.json"

  if [ "$SARIF" = 1 ]; then
    jq --arg v "$VERSION" --arg url "$REPO_URL" '
      { "$schema": "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0",
        runs: [ { tool: { driver: { name: "brotli-k8s-scan", version: $v, informationUri: $url,
          rules: [
            { id: "CVE-2026-111497", name: "VulnerableBrotliDecoder",
              shortDescription: { text: "Vulnerable Brotli decoder (CVE-2026-111497)" },
              fullDescription: { text: "Out-of-bounds write in the Google Brotli decoder 1.0.3-1.2.0. Crafted Brotli data can corrupt memory, leak memory or run code." },
              help: { text: "Upgrade Brotli to 1.0.10 / 1.1.1 / 1.2.1, Node.js to 22.23.4 / 24.22.1 / 26.12.1, Bun to 1.4.4, Python Brotli to 1.2.1, brotlicffi to 1.2.1.0, .NET to 8.0.33 / 9.0.22 / 10.0.14, then rebuild the image." },
              helpUri: "https://github.com/google/brotli/releases/tag/v1.2.1",
              defaultConfiguration: { level: "error" },
              properties: { "security-severity": "9.2", tags: ["security", "CVE-2026-111497"], precision: "high" } },
            { id: "BROTLI-REVIEW", name: "BrotliNeedsReview",
              shortDescription: { text: "Brotli decoder found, patch state could not be determined" },
              fullDescription: { text: "A Brotli decoder or a component that may bundle one was found, but its patch state could not be determined automatically." },
              helpUri: $url, defaultConfiguration: { level: "warning" },
              properties: { tags: ["security", "CVE-2026-111497"] } } ] } },
          results: [ .images[] as $img | $img.findings[] | select(.state == "VULN" or .state == "REVIEW")
            | . as $f
            | { ruleId: (if .state == "VULN" then "CVE-2026-111497" else "BROTLI-REVIEW" end),
                level: (if .state == "VULN" then "error" else "warning" end),
                message: { text: ("\($img.image): \($f.what)" + (if $f.path != "" and ($f.what | contains($f.path) | not) then " (\($f.path))" else "" end) + (if $f.note != "" then " - \($f.note)" else "" end)) },
                locations: [ { physicalLocation: { artifactLocation: { uri: ($img.image + (if (.path | startswith("/")) then .path else "" end)) } } } ],
                partialFingerprints: { "brotliFinding/v1": "\($img.image_id)|\(.kind)|\(.what)|\(.path)" } } ] } ] }' \
      "$OUT/report.json" > "$OUT/report.sarif"
  fi
fi

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
if [ "$total" = 1 ]; then
  ev="$OUT/raw/1.eval"; verdict=$(awk -F'\t' '$1=="V"{print $2}' "$ev")
  echo "Target: $(head -n 1 "$OUT/targets.tsv" | cut -f2)"
  echo "Verdict: $(paint "$verdict")"
  awk -F'\t' -v R="$C_RED" -v G="$C_GRN" -v Y="$C_YEL" -v D="$C_DIM" -v O="$C_OFF" '$1=="F" {
    c = ($2 == "VULN") ? R : ($2 == "OK") ? G : ($2 == "REVIEW") ? Y : D
    w = $4; if ($6 != "" && index(w, $6) == 0) w = w " (" $6 ")"
    printf "  [%s%-6s%s] %-7s %s%s\n", c, $2, O, $3, w, ($5 ? "  -> " $5 : "") }' "$ev"
else
  echo
  echo "=== Summary ($total unique images) ==="
  for v in VULNERABLE REVIEW PATCHED NO_BROTLI_FOUND; do
    # pad before colouring: colour codes would otherwise count as width
    printf '%s%*s %s\n' "$(paint "$v")" $((16 - ${#v})) "" "$(awk -F'\t' -v v="$v" 'NR>1 && $1==v' "$OUT/report.tsv" | wc -l | tr -d ' ')"
  done
  echo
  awk -F'\t' 'NR>1 && ($1=="VULNERABLE" || $1=="REVIEW") { print $1 "\t" $2 "\t" $7 "\t" $8 }' "$OUT/report.tsv" |
  while IFS="$TAB" read -r v img users f; do
    printf '%s %s\n' "$(paint "$v")" "$img"
    [ "$users" != "-" ] && printf '           used by: %s\n' "$users"
    f=${f//VULN:/${C_RED}VULN${C_OFF}:}; f=${f//REVIEW:/${C_YEL}REVIEW${C_OFF}:}
    printf '           %s\n' "$f"
  done
fi
echo
echo "Report:   $OUT/report.tsv"
echo "Details:  $OUT/findings.tsv"
[ -f "$OUT/report.json" ] && echo "JSON:     $OUT/report.json"
[ -f "$OUT/report.sarif" ] && echo "SARIF:    $OUT/report.sarif"
[ "$HAVE_JQ" = 0 ] && echo "(install jq to also get report.json)"
if [ "$DEEP" = 0 ] && awk -F'\t' 'NR>1 && $1=="NO_BROTLI_FOUND"{f=1} END{exit !f}' "$OUT/report.tsv"; then
  echo "Tip: NO_BROTLI_FOUND only covers the usual suspects. Re-run with --deep to also fingerprint statically linked binaries."
fi

if awk -F'\t' 'NR>1 && $1=="VULNERABLE"{f=1} END{exit !f}' "$OUT/report.tsv"; then exit 1; fi
if awk -F'\t' 'NR>1 && $1=="REVIEW"{f=1} END{exit !f}' "$OUT/report.tsv"; then exit 3; fi
exit 0
