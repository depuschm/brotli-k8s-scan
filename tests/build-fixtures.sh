#!/usr/bin/env bash
# Builds the test fixtures: real vulnerable and fixed Brotli builds assembled
# into fake container filesystems under tests/.cache/fixtures.
#
# This is the ONLY step that needs network access (git clone of google/brotli,
# PyPI wheels, Node.js binaries from the npm registry, Ubuntu packages,
# the SARIF schema). The tests themselves
# run offline: see tests/run-tests.sh.
#
# Needs: git, cmake, a C compiler (cc), python3 with pip, npm, tar, curl.
# Optional: dpkg-deb or ar (Ubuntu backport fixture).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
C="$HERE/.cache"
FX="$C/fixtures"
mkdir -p "$C"
cd "$C"

for t in git cmake cc python3 npm tar curl; do
  command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

case "$(uname -m)" in
  x86_64|amd64) NODE_ARCH=x64 ;;
  aarch64|arm64) NODE_ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 2 ;;
esac

echo "== Brotli sources"
[ -d brotli/.git ] || git clone -q https://github.com/google/brotli.git brotli
git -C brotli fetch -q --tags

build() {  # $1=tag $2=shared|static
  local t=$1 kind=$2 dir="build-$1-$2"
  [ -d "$dir" ] && return 0
  rm -rf "src-$t"; mkdir -p "src-$t"
  git -C brotli archive "$t" | tar -x -C "src-$t"
  local shared=ON; [ "$kind" = static ] && shared=OFF
  { cmake -S "src-$t" -B "$dir" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=$shared \
          -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections" &&
    cmake --build "$dir" -j4; } > "$dir.log" 2>&1 || { cat "$dir.log" >&2; rm -rf "$dir"; exit 1; }
  echo "built $t ($kind)"
}
for t in v1.0.9 v1.0.10 v1.2.0 v1.2.1; do build "$t" shared; done
build v1.2.0 static

echo "== stripped static test program (embeds Brotli 1.2.0, no symbols)"
if [ ! -f app-static ]; then
  cat > app.c <<'EOF'
#include <brotli/decode.h>
#include <stdio.h>
int main(void) { uint8_t out[64]; size_t n = sizeof out;
  BrotliDecoderResult r = BrotliDecoderDecompress(1, (const uint8_t*)"\x06", &n, out);
  printf("%d\n", (int)r); return 0; }
EOF
  cc -O2 -ffunction-sections -fdata-sections -I src-v1.2.0/c/include app.c \
     build-v1.2.0-static/libbrotlidec.a build-v1.2.0-static/libbrotlicommon.a \
     -Wl,--gc-sections -s -o app-static
fi

echo "== Python wheels"
wheel() {  # $1=dist $2=version
  local d="py-$1-$2"
  [ -d "$d/x" ] && return 0
  mkdir -p "$d"
  python3 -m pip download -q --no-deps --only-binary=:all: -d "$d" "$1==$2"
  (cd "$d" && python3 -m zipfile -e ./*.whl x)
}
wheel Brotli 1.2.0; wheel Brotli 1.2.1; wheel brotlicffi 1.2.0.1; wheel brotlicffi 1.2.1.0

echo "== Node.js binaries (npm package node-linux-$NODE_ARCH)"
nodebin() {  # $1=version
  local d="node-$1"
  [ -x "$d/package/bin/node" ] && return 0
  mkdir -p "$d"
  (cd "$d" && npm pack -q "node-linux-$NODE_ARCH@$1" >/dev/null && tar -xzf ./*.tgz)
}
nodebin 22.23.3; nodebin 22.23.4

# Optional fixtures are skipped when a download fails, unless
# BROTLI_TEST_STRICT=1 (CI), where every fixture is required.
optional_failed() {
  if [ "${BROTLI_TEST_STRICT:-0}" = 1 ]; then echo "ERROR: $1 (BROTLI_TEST_STRICT=1)" >&2; exit 1; fi
  echo "   (skipped: $1; those tests will be skipped)"
}
case "$NODE_ARCH" in x64) UARCH=amd64; MIRRORS="http://archive.ubuntu.com/ubuntu http://security.ubuntu.com/ubuntu" ;;
                     arm64) UARCH=arm64; MIRRORS="http://ports.ubuntu.com/ubuntu-ports" ;; esac
fetch_deb() {  # $1=source package $2=binary package $3=version $4=output file
  [ -s "$4" ] && return 0
  local f="${2}_${3}_${UARCH}.deb" m pfx
  pfx=$(printf '%s' "$1" | cut -c1)
  for m in $MIRRORS; do curl -fsSL -o "$4" "$m/pool/main/$pfx/$1/$f" 2>/dev/null && return 0; done
  # superseded versions disappear from the mirrors; Launchpad keeps every build
  curl -fsSL -o "$4" "https://launchpad.net/ubuntu/+archive/primary/+files/$f" 2>/dev/null && return 0
  rm -f "$4"; return 1
}
debx() {  # $1=.deb $2=dest : extract without installing
  mkdir -p "$2"
  if command -v dpkg-deb >/dev/null 2>&1; then dpkg-deb -x "$1" "$2"
  else (d=$(mktemp -d) && cd "$d" && ar x "$1" && tar -xf data.tar.* -C "$2" && rm -rf "$d"); fi
}

echo "== Ubuntu libbrotli1: unpatched 1.1.0-2build2 and the backport 1.1.0-2ubuntu0.1 (same version string)"
UBU_OK=0
mkdir -p ubuntu
if fetch_deb brotli libbrotli1 1.1.0-2build2 ubuntu/old.deb && fetch_deb brotli libbrotli1 1.1.0-2ubuntu0.1 ubuntu/fixed.deb &&
   rm -rf ubuntu/old ubuntu/fixed && debx "$PWD/ubuntu/old.deb" "$PWD/ubuntu/old" && debx "$PWD/ubuntu/fixed.deb" "$PWD/ubuntu/fixed"; then
  UBU_OK=1
else optional_failed "Ubuntu libbrotli1 packages not available"; fi

echo "== Ubuntu .NET runtimes 8.0.32 (bundles Brotli) and 10.0.13 (uses system libbrotli)"
UDN_OK=0
if [ "$UBU_OK" = 1 ] &&
   fetch_deb dotnet8 dotnet-runtime-8.0 8.0.32-0ubuntu1~24.04.1 ubuntu/dotnet8.deb &&
   fetch_deb dotnet10 dotnet-runtime-10.0 10.0.13-0ubuntu1~24.04.1 ubuntu/dotnet10.deb &&
   rm -rf ubuntu/dotnet8 ubuntu/dotnet10 && debx "$PWD/ubuntu/dotnet8.deb" "$PWD/ubuntu/dotnet8" &&
   debx "$PWD/ubuntu/dotnet10.deb" "$PWD/ubuntu/dotnet10"; then
  UDN_OK=1
else optional_failed "Ubuntu .NET runtime packages not available"; fi

echo "== Official Microsoft .NET runtimes: 8.0.32 / 8.0.33 and 10.0.13 / 10.0.14 (before / after the fix)"
MSDN_OK=0
MS_VERSIONS="8.0.32 8.0.33 10.0.13 10.0.14"
mkdir -p msdotnet
ms_ok=1
for v in $MS_VERSIONS; do
  t="msdotnet/dotnet-runtime-$v.tar.gz"
  [ -s "$t" ] && continue
  curl -fsSL -o "$t" "https://builds.dotnet.microsoft.com/dotnet/Runtime/$v/dotnet-runtime-$v-linux-$NODE_ARCH.tar.gz" 2>/dev/null ||
  curl -fsSL -o "$t" "https://dotnetcli.azureedge.net/dotnet/Runtime/$v/dotnet-runtime-$v-linux-$NODE_ARCH.tar.gz" 2>/dev/null ||
  { rm -f "$t"; ms_ok=0; }
done
if [ "$ms_ok" = 1 ]; then MSDN_OK=1; else optional_failed "Microsoft .NET runtime downloads not reachable"; fi

echo "== official Envoy 1.36.11 / 1.36.12 and Bun 1.4.3 / 1.4.4 binaries (before / after the fix)"
RT_OK=0
case "$NODE_ARCH" in x64) EARCH=x86_64; BARCH=x64 ;; arm64) EARCH=aarch_64; BARCH=aarch64 ;; esac
mkdir -p runtimes
rt_ok=1
for v in 1.36.11 1.36.12; do
  [ -s "runtimes/envoy-$v" ] || curl -fsSL -o "runtimes/envoy-$v" \
    "https://github.com/envoyproxy/envoy/releases/download/v$v/envoy-$v-linux-$EARCH" 2>/dev/null || { rm -f "runtimes/envoy-$v"; rt_ok=0; }
done
for v in 1.4.3 1.4.4; do
  if [ ! -s "runtimes/bun-$v" ]; then
    if curl -fsSL -o "runtimes/bun-$v.zip" "https://github.com/oven-sh/bun/releases/download/bun-v$v/bun-linux-$BARCH.zip" 2>/dev/null; then
      rm -rf "runtimes/bun-$v.d" && python3 -m zipfile -e "runtimes/bun-$v.zip" "runtimes/bun-$v.d" &&
        mv "$(find "runtimes/bun-$v.d" -type f -name bun | head -n 1)" "runtimes/bun-$v" && rm -rf "runtimes/bun-$v.d" "runtimes/bun-$v.zip"
    else rm -f "runtimes/bun-$v.zip"; rt_ok=0; fi
  fi
done
if [ "$rt_ok" = 1 ]; then chmod +x runtimes/*; RT_OK=1; else optional_failed "Envoy/Bun release downloads failed"; fi

echo "== test helpers: yara-python, jsonschema, SARIF 2.1.0 schema"
[ -f pylib/.ok ] || { python3 -m pip install -q --target pylib yara-python jsonschema && touch pylib/.ok; } ||
  optional_failed "pip install of yara-python/jsonschema failed"
[ -f sarif-schema-2.1.0.json ] || curl -fsSL -o sarif-schema-2.1.0.json \
  https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json ||
  optional_failed "SARIF schema download failed"

echo "== assembling fake container filesystems"
rm -rf "$FX"; mkdir -p "$FX"
put() { mkdir -p "$FX/$1/$(dirname "$2")"; cp "$3" "$FX/$1/$2"; }
so() { find "$1" -name "$2" | head -n 1; }

# vuln: Node 22.23.3, libbrotli 1.2.0, Python Brotli 1.2.0 + brotlicffi 1.2.0.1, dpkg DB
SP=app/venv/lib/python3/site-packages
put vuln usr/local/bin/node node-22.23.3/package/bin/node
put vuln usr/lib/libbrotlidec.so.1.2.0 build-v1.2.0-shared/libbrotlidec.so.1.2.0
put vuln usr/lib/libbrotlicommon.so.1.2.0 build-v1.2.0-shared/libbrotlicommon.so.1.2.0
put vuln "$SP/_brotli.so" "$(so py-Brotli-1.2.0/x '_brotli*.so')"
put vuln "$SP/brotlicffi/_brotlicffi.abi3.so" "$(so py-brotlicffi-1.2.0.1/x '*.so')"
mkdir -p "$FX/vuln/$SP/Brotli-1.2.0.dist-info" "$FX/vuln/$SP/brotlicffi-1.2.0.1.dist-info" \
         "$FX/vuln/var/lib/dpkg" "$FX/vuln/etc"
printf 'Package: libbrotli1\nStatus: install ok installed\nVersion: 1.2.0-1\n\nPackage: zlib1g\nVersion: 1:1.3\n' \
  > "$FX/vuln/var/lib/dpkg/status"
echo 'PRETTY_NAME="Test Debian"' > "$FX/vuln/etc/os-release"

# fixed: Node 22.23.4, libbrotli 1.2.1, Python Brotli 1.2.1, apk DB
put fixed usr/local/bin/node node-22.23.4/package/bin/node
put fixed usr/lib/libbrotlidec.so.1.2.1 build-v1.2.1-shared/libbrotlidec.so.1.2.1
put fixed "$SP/_brotli.so" "$(so py-Brotli-1.2.1/x '_brotli*.so')"
put fixed "$SP/brotlicffi/_brotlicffi.abi3.so" "$(so py-brotlicffi-1.2.1.0/x '*.so')"
mkdir -p "$FX/fixed/$SP/Brotli-1.2.1.dist-info" "$FX/fixed/$SP/brotlicffi-1.2.1.0.dist-info" \
         "$FX/fixed/lib/apk/db" "$FX/fixed/etc"
printf 'P:brotli-libs\nV:1.2.1-r0\n\nP:musl\nV:1.2.5-r0\n\n' > "$FX/fixed/lib/apk/db/installed"
echo 'PRETTY_NAME="Test Alpine"' > "$FX/fixed/etc/os-release"

# 1.0.x line, vulnerable and fixed
put old109 usr/lib/libbrotlidec.so.1.0.9 build-v1.0.9-shared/libbrotlidec.so.1.0.9
put old1010 usr/lib/libbrotlidec.so.1.0.10 build-v1.0.10-shared/libbrotlidec.so.1.0.10

# static: stripped binary with a generic name (only --deep finds it), padded past 100 KB
put static opt/app/server app-static
chmod +x "$FX/static/opt/app/server"
head -c 122880 /dev/zero >> "$FX/static/opt/app/server"

# none: no Brotli, but a Java jar that may bundle it
mkdir -p "$FX/none/opt/lib"; : > "$FX/none/opt/lib/brotli4j-1.16.0.jar"

# Ubuntu backport: identical version string, different patch state
if [ "$UBU_OK" = 1 ]; then
  for k in old fixed; do
    mkdir -p "$FX/ubuntu-$k"; cp -a "ubuntu/$k/." "$FX/ubuntu-$k/"
    v=1.1.0-2build2; [ "$k" = fixed ] && v=1.1.0-2ubuntu0.1
    mkdir -p "$FX/ubuntu-$k/var/lib/dpkg"
    printf 'Package: libbrotli1\nStatus: install ok installed\nVersion: %s\n\n' "$v" > "$FX/ubuntu-$k/var/lib/dpkg/status"
  done
fi

# Real .NET runtimes
if [ "$UDN_OK" = 1 ]; then
  mkdir -p "$FX/dotnet8-ubuntu/usr/lib"; cp -a ubuntu/dotnet8/usr/lib/dotnet "$FX/dotnet8-ubuntu/usr/lib/"
  for k in old fixed; do
    mkdir -p "$FX/dotnet10-ubuntu-$k/usr/lib"
    cp -a ubuntu/dotnet10/usr/lib/dotnet "$FX/dotnet10-ubuntu-$k/usr/lib/"
    cp -a "ubuntu/$k/." "$FX/dotnet10-ubuntu-$k/"
  done
  # self-contained app layout: the app's own deps.json + the real native library
  d="$FX/dotnet-selfcontained-ubuntu/app"; mkdir -p "$d"
  cp ubuntu/dotnet8/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so "$d/"
  printf '{"libraries":{"runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.32":{"type":"runtimepack"}}}\n' > "$d/myapp.deps.json"
fi
if [ "$MSDN_OK" = 1 ]; then
  for v in $MS_VERSIONS; do
    mkdir -p "$FX/msdotnet-$v/usr/share/dotnet"
    tar -xzf "msdotnet/dotnet-runtime-$v.tar.gz" -C "$FX/msdotnet-$v/usr/share/dotnet"
  done
fi

# Real Envoy and Bun binaries. Fixture names have no "-": the fake kubectl
# maps pod names like exec-envoyold-1 to the fixture "envoyold".
if [ "$RT_OK" = 1 ]; then
  for k in envoyold:envoy-1.36.11 envoyfixed:envoy-1.36.12 bunold:bun-1.4.3 bunfixed:bun-1.4.4; do
    fx=${k%%:*}; f=${k#*:}
    mkdir -p "$FX/$fx/usr/local/bin"; cp "runtimes/$f" "$FX/$fx/usr/local/bin/${f%%-*}"
  done
fi

# .NET runtime layout (SYNTHETIC: the "native lib" is the stripped static test
# program, i.e. Brotli without a readable error table, so the verdict must
# come from the runtime version in the path)
for v in 10.0.7 10.0.14; do
  d="$FX/dotnet-$v/usr/share/dotnet/shared/Microsoft.NETCore.App/$v"
  mkdir -p "$d"; cp app-static "$d/libSystem.IO.Compression.Native.so"
done

for v in 8.0.32 8.0.33; do
  d="$FX/dotnet-selfcontained-synthetic-$v/app"; mkdir -p "$d"
  cp app-static "$d/libSystem.IO.Compression.Native.so"
  printf '{"libraries":{"runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/%s":{"type":"runtimepack"}}}\n' "$v" > "$d/myapp.deps.json"
done

echo "fixtures ready in $FX"
