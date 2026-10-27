#!/usr/bin/env bash
# Regenerates docs/images/*.png from real data:
#   - the error-table diagram is read from Ubuntu's real libbrotlidec builds
#     before/after the fix (tests/.cache/fixtures),
#   - the terminal screenshots are the CURRENT scanner's real output against a
#     small demo cluster made of real vulnerable and fixed builds.
# Re-run after changing the scanner's output, the README pitch or the design.
#
#   tests/build-fixtures.sh            # once (network): real Brotli/Node/Python/Ubuntu/.NET builds
#   docs/images/src/build-images.sh    # fonts (network, once, cached), then offline rendering
#
# Needs: bash, node + Playwright with Chromium (npm i -g playwright &&
# npx playwright install chromium), npm (fonts), python3 + Pillow, jq, tar,
# util-linux `script`. Linux. `unshare -rn` is used to render without network.
#
# Edit the pictures in make_html.py (layout, text, colours), the demo cluster
# in demo-pods.json / demo_fixtures() below. social-preview.png has to be
# uploaded by hand: GitHub Settings -> General -> Social preview.
set -eu

SRC=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(cd "$SRC/../../.." && pwd -P)
C="$SRC/.cache"
FX="$ROOT/tests/.cache/fixtures"
OUT="$ROOT/docs/images"
die() { echo "error: $*" >&2; exit 1; }

for t in node npm python3 script tar jq; do command -v "$t" >/dev/null 2>&1 || die "$t not found"; done
python3 -c 'import PIL' 2>/dev/null || die "Pillow missing: python3 -m pip install pillow"
NPM_GLOBAL=$(npm root -g 2>/dev/null || true)
NODE_PATH="$C/node/node_modules:$NPM_GLOBAL${NODE_PATH:+:$NODE_PATH}"; export NODE_PATH
node -e "require('playwright')" 2>/dev/null ||
  die "Playwright missing: npm install --prefix '$C/node' playwright && (cd '$C/node' && npx playwright install chromium)"
for f in ubuntu-old ubuntu-fixed dotnet8-ubuntu vuln fixed; do
  [ -d "$FX/$f" ] || die "test fixture '$f' missing: run tests/build-fixtures.sh first"
done
mkdir -p "$C"

echo "== fonts (pinned versions, from npm)"
fetch_font() {  # $1=package@version $2=directory name
  [ -d "$C/fonts/$2/files" ] && return 0
  rm -rf "$C/fonts/tmp"; mkdir -p "$C/fonts/tmp"
  (cd "$C/fonts/tmp" && npm pack -q "$1" >/dev/null && tar -xzf ./*.tgz && mv package "../$2")
  rm -rf "$C/fonts/tmp"
}
fetch_font @fontsource/jetbrains-mono@5.3.0 jetbrains-mono
fetch_font @fontsource-variable/inter@5.3.0 inter

echo "== demo cluster from the test fixtures (real binaries)"
demo_fixtures() {
  local D="$C/demo-fx" SP=app/.venv/lib/python3.12/site-packages
  rm -rf "$D"; mkdir -p "$D"
  put() { mkdir -p "$D/$1/$(dirname "$2")"; cp -a "$3" "$D/$1/$2"; }
  put checkout usr/local/bin/node "$FX/vuln/usr/local/bin/node"     # Node.js 22.23.3
  put web      usr/local/bin/node "$FX/fixed/usr/local/bin/node"    # Node.js 22.23.4
  put scraper  "$SP/_brotli.cpython-312-x86_64-linux-gnu.so" "$FX/vuln/app/venv/lib/python3/site-packages/_brotli.so"
  mkdir -p "$D/scraper/$SP/Brotli-1.2.0.dist-info"
  put reports  "$SP/_brotli.cpython-312-x86_64-linux-gnu.so" "$FX/fixed/app/venv/lib/python3/site-packages/_brotli.so"
  mkdir -p "$D/reports/$SP/Brotli-1.2.1.dist-info"
  cp -a "$FX/dotnet8-ubuntu" "$D/billing"                          # Ubuntu .NET 8.0.32
  cp -a "$FX/ubuntu-fixed" "$D/logagent"                           # libbrotli1 backport
  mkdir -p "$D/ingress/usr/sbin" && cp "$(command -v ls)" "$D/ingress/usr/sbin/nginx"   # no Brotli
  cp -a "$FX/ubuntu-old" "$D/ubuntu-old"; cp -a "$FX/ubuntu-fixed" "$D/ubuntu-fixed"  # demo-crane
}
demo_fixtures

echo "== capture the scanner's real, coloured terminal output"
OFF=()
if unshare -rn true 2>/dev/null; then OFF=(unshare -rn)
else echo "   warning: unshare -rn not available, capturing with network"; fi
mkdir -p "$C/bin" "$C/run"
ln -sf "$ROOT/tests/fake-kubectl/kubectl" "$C/bin/kubectl"
ln -sf "$SRC/demo-crane" "$C/bin/crane"
capture() {  # $1=name $2=scanner arguments
  (cd "$C/run" && rm -rf brotli-scan-* &&
   BROTLI_TEST_FIXTURES="$C/demo-fx" BROTLI_TEST_PODS="$SRC/demo-pods.json" BROTLI_IMAGE_TOOL=crane PATH="$C/bin:$PATH" \
     ${OFF[@]+"${OFF[@]}"} script -q -e -c "bash '$ROOT/brotli-k8s-scan.sh' $2" "$C/cap-$1.txt" >/dev/null 2>&1) || true
  grep -q -e 'Summary' -e 'Verdict' "$C/cap-$1.txt" || die "capture '$1' failed, see $C/cap-$1.txt"
}
capture cluster ""
capture old "--image registry.example/app:2026-10-20"
capture new "--image registry.example/app:2026-10-27"

echo "== HTML"
(cd "$SRC" && python3 make_html.py "$C" "$FX")

echo "== render (offline)"
(cd "$SRC" && ${OFF[@]+"${OFF[@]}"} node render.js "$C")

echo "== compress into docs/images"
(cd "$SRC" && python3 compress.py "$C/png" "$OUT")
echo "done. Review the images, then commit docs/images/*.png."
echo "social-preview.png: upload by hand (Settings -> General -> Social preview)."
