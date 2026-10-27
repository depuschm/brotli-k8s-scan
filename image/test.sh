#!/usr/bin/env bash
# Checks a scanner image built by image/build.sh, without network: every
# container runs with --network none, except a registry on 127.0.0.1.
#
#  - the image scans every test fixture exactly like the scanner on this
#    machine (same verdicts and findings, with BusyBox instead of GNU tools)
#  - it runs as an unprivileged user with a read-only root filesystem
#  - a hostile image cannot make its tar write outside the unpack directory
#  - its own crane pulls and unpacks an image from a registry
#
# usage: image/test.sh TAG     needs: docker, python3, the test fixtures
set -u

TAG=${1:?usage: image/test.sh TAG}
HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(dirname "$HERE")
FX="$ROOT/tests/.cache/fixtures"
[ -d "$FX/vuln" ] || { echo "fixtures missing: run tests/build-fixtures.sh first" >&2; exit 2; }
W=$(mktemp -d); trap 'docker rm -f brotli-image-test-registry >/dev/null 2>&1; rm -rf "$W"' EXIT
chmod 1777 "$W"
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() {
  fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"
  [ "${GITHUB_ACTIONS:-}" = true ] && echo "::error title=image: $1::${2:-}"
  return 0
}
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
run() { docker run --rm --network none --read-only --tmpfs /tmp "$@"; }

echo "image $TAG"
expect_eq "runs as an unprivileged user" "$(run --entrypoint id "$TAG" -u)" 65532
expect_eq "scanner version matches this checkout" "$(run "$TAG" --version)" \
  "brotli-k8s-scan $(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$ROOT/brotli-k8s-scan.sh")"
for t in bash jq crane kubectl tar awk find; do
  if run --entrypoint sh "$TAG" -c "command -v $t" >/dev/null 2>&1; then ok "contains $t"; else bad "contains $t"; fi
done

echo "every fixture: same result as the scanner on this machine"
for d in "$FX"/*/; do
  f=$(basename "$d")
  bash "$ROOT/brotli-k8s-scan.sh" --rootfs "$d" -o "$W/host-$f" >/dev/null 2>&1
  run -v "$d:/scan:ro" -v "$W:/out" "$TAG" --rootfs /scan -o "/out/image-$f" >/dev/null 2>&1
  a="$(tail -n +2 "$W/host-$f/report.tsv" | cut -f1) $(cut -f2- "$W/host-$f/findings.tsv" | cksum)"
  b="$(tail -n +2 "$W/image-$f/report.tsv" 2>/dev/null | cut -f1) $(cut -f2- "$W/image-$f/findings.tsv" 2>/dev/null | cksum)"
  expect_eq "$f: $(echo "$a" | cut -d' ' -f1)" "$b" "$a"
done

echo "hostile image (BusyBox tar inside the image)"
python3 -I "$ROOT/tests/hostile_tar.py" "$W/hostile.tar" "$FX/vuln/usr/local/bin/node"
out=$(run -v "$ROOT/tests:/t:ro" -v "$W/hostile.tar:/hostile.tar:ro" \
  -e PATH=/t/fake-image-tools:/usr/local/bin:/usr/bin:/bin -e BROTLI_IMAGE_TOOL=crane \
  -e BROTLI_TEST_FIXTURES=/t/.cache/fixtures -e BROTLI_TEST_HOSTILE_TAR=/hostile.tar --entrypoint sh "$TAG" -c \
  'brotli-k8s-scan --image registry.test/hostile-tar:1 -o /tmp/o >/dev/null 2>&1; echo "rc=$?"; find /tmp -name "pwned-*"')
expect_eq "hostile image: vulnerable (exit 1), nothing written outside the unpack directory" "$out" "rc=1"

echo "real crane in the image, against a local registry"
docker run -d --rm --name brotli-image-test-registry --network host --entrypoint crane "$TAG" \
  registry serve --address 127.0.0.1:5099 >/dev/null
for _ in $(seq 1 20); do docker run --rm --network host --entrypoint crane "$TAG" catalog 127.0.0.1:5099 >/dev/null 2>&1 && break; sleep 1; done
python3 -I "$ROOT/tests/hostile_tar.py" "$W/symlinks.tar" "$FX/vuln/usr/local/bin/node" --no-dotdot
chmod 644 "$W"/*.tar
for t in hostile symlinks; do
  docker run --rm --network host -v "$W/$t.tar:/layer.tar:ro" --entrypoint crane "$TAG" \
    append -f /layer.tar -t "127.0.0.1:5099/$t:1" >/dev/null 2>&1 || bad "push test image $t to the local registry"
done
scan() {
  docker run --rm --network host --read-only --tmpfs /tmp --entrypoint sh "$TAG" -c \
    'brotli-k8s-scan --image "$0" -o /tmp/o >/dev/null 2>&1; echo "rc=$?"; find /tmp -name "pwned-*"; tail -n 1 /tmp/o/report.tsv | cut -f1' "$1" | tr '\n' ' '
}
expect_eq "crane --image: symlinks out of the image: vulnerable, nothing escaped" "$(scan 127.0.0.1:5099/symlinks:1)" "rc=1 VULNERABLE "
# crane itself refuses layers with "../" names: the scanner then reports REVIEW (pull failed)
expect_eq "crane --image: \"../\" names: review, nothing escaped" "$(scan 127.0.0.1:5099/hostile:1)" "rc=3 REVIEW "

echo
echo "image tests passed: $pass, failed: $fail"
[ "$fail" -eq 0 ]
