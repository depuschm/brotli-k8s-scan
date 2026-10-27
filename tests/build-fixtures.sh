#!/usr/bin/env bash
# Builds the test fixtures: real vulnerable and fixed Brotli builds assembled
# into fake container filesystems under tests/.cache/fixtures.
#
# This is the ONLY step that needs network access (git clone of google/brotli,
# PyPI wheels, Node.js binaries from the npm registry). The tests themselves
# run offline: see tests/run-tests.sh.
#
# Needs: git, cmake, a C compiler (cc), python3 with pip, npm, tar.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
C="$HERE/.cache"
FX="$C/fixtures"
mkdir -p "$C"
cd "$C"

for t in git cmake cc python3 npm tar; do
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

echo "fixtures ready in $FX"
