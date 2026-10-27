#!/usr/bin/env bash
# End-to-end test on a REAL Kubernetes cluster (kind) with a real registry,
# real `kubectl exec`, real `crane` and real `docker` pulls.
#
# Test images are built FROM scratch out of the real fixture binaries (Node.js
# 22.23.3 / 22.23.4 with their real shared libraries, Python wheels, Ubuntu's
# libbrotli1 before/after the backport) plus a static BusyBox as the shell, so
# `kubectl exec` runs the probe under BusyBox like in an Alpine image. Nothing
# is pulled from public registries except kind's own node image.
#
# Phases (E2E_PHASES, default "images cluster scan"):
#   images   build the test images, start a local registry (crane), push
#   cluster  create a kind cluster that pulls from that registry, deploy
#   scan     run the scanner in all modes and check the verdicts
#   job      run the scanner's container image as a Kubernetes Job with
#            deploy/job.yaml; needs E2E_SCANNER_IMAGE (from image/build.sh)
#
# Needs: docker, kind, kubectl, crane, jq, a static busybox ($BUSYBOX),
# and the test fixtures (tests/build-fixtures.sh). Linux. Used by CI
# (.github/workflows/test.yml, job "e2e"); downloads happen only in setup.
set -u

HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(dirname "$HERE")
SCAN="$ROOT/brotli-k8s-scan.sh"
FX="$HERE/.cache/fixtures"
PHASES=${E2E_PHASES:-images cluster scan}
W=${E2E_WORKDIR:-$(mktemp -d)}
REG=localhost:5001
NS=brotli-e2e
CLUSTER=brotli-e2e
BUSYBOX=${BUSYBOX:-$(command -v busybox || true)}

pass=0; fail=0
note() { if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::notice title=e2e::$*"; else echo "  note  $*"; fi; }
ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad()  {
  fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"
  # GitHub annotations are readable through the API even without log access
  [ "${GITHUB_ACTIONS:-}" = true ] && echo "::error title=e2e: $1::${2:-}"
  return 0
}
die() { bad "$1" "${2:-}"; finish; }
finish() { echo; echo "e2e passed: $pass, failed: $fail"; [ "$fail" -eq 0 ]; exit $?; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
expect_has() { if grep -q -F -- "$3" "$2"; then ok "$1"; else bad "$1" "missing: $3 | $(tr '\n' ' ' < "$2" | cut -c1-600)"; fi; }
row() { awk -F'\t' -v img="$2" '$2 == img { print $1 }' "$1/report.tsv"; }
has() { case " $PHASES " in *" $1 "*) return 0 ;; esac; return 1; }

for t in docker jq; do command -v "$t" >/dev/null 2>&1 || die "tool $t available"; done
has images && { command -v crane >/dev/null 2>&1 || die "tool crane available"; }
has cluster && { for t in kind kubectl; do command -v "$t" >/dev/null 2>&1 || die "tool $t available"; done; }
has job && { [ -n "${E2E_SCANNER_IMAGE:-}" ] || die "E2E_SCANNER_IMAGE set" "build it with image/build.sh TAG"; }
for f in vuln fixed ubuntu-old ubuntu-fixed; do [ -d "$FX/$f" ] || die "fixture $f present" "run tests/build-fixtures.sh first"; done
echo "work dir: $W"

# ---------------------------------------------------------------- images
build_image() {  # $1=name $2=fixture $3=shell(1/0)
  local name=$1 fx=$2 shell=$3 d="$W/img-$1"
  rm -rf "$d"; mkdir -p "$d/rootfs/bin"
  cp -a "$FX/$fx/." "$d/rootfs/"
  cp "$BUSYBOX" "$d/rootfs/bin/busybox"
  # make the real node binary runnable: copy its shared libraries
  if [ -x "$d/rootfs/usr/local/bin/node" ]; then
    ldd "$d/rootfs/usr/local/bin/node" | awk '/=> \//{print $3} /^\t\//{print $1}' | while read -r lib; do
      mkdir -p "$d/rootfs$(dirname "$lib")"; cp -L "$lib" "$d/rootfs$lib"
    done
  fi
  {
    echo 'FROM scratch'
    echo 'COPY rootfs/ /'
    [ "$shell" = 1 ] && echo 'RUN ["/bin/busybox", "--install", "-s", "/bin"]'
    echo 'ENV PATH=/usr/local/bin:/usr/bin:/bin'
    echo 'CMD ["/bin/busybox", "sleep", "86400"]'
  } > "$d/Dockerfile"
  docker build -q -t "$REG/e2e/$name:1" "$d" >/dev/null || die "docker build $name"
  docker push -q "$REG/e2e/$name:1" >/dev/null || die "docker push $name"
}

if has images; then
  echo "== images"
  [ -n "$BUSYBOX" ] && file -L "$BUSYBOX" | grep -q 'statically linked' || die "static busybox" "set BUSYBOX to a statically linked busybox"
  if ! curl -fsS -m 2 "http://$REG/v2/" >/dev/null 2>&1; then
    (PORT=5001 crane registry serve --address 0.0.0.0:5001 > "$W/registry.log" 2>&1 &)
    for _ in $(seq 1 30); do curl -fsS -m 2 "http://$REG/v2/" >/dev/null 2>&1 && break; sleep 1; done
    curl -fsS -m 2 "http://$REG/v2/" >/dev/null 2>&1 || die "local registry starts" "$(tail -n 3 "$W/registry.log")"
  fi
  build_image vuln vuln 1          # Node 22.23.3, Python Brotli 1.2.0, libbrotlidec 1.2.0
  build_image fixed fixed 1        # Node 22.23.4, Python Brotli 1.2.1, libbrotlidec 1.2.1
  build_image unpatched ubuntu-old 1    # libbrotli1 1.1.0-2build2
  build_image backport ubuntu-fixed 1   # libbrotli1 1.1.0-2ubuntu0.1 (same "1.1.0")
  build_image noshell vuln 0       # like a distroless image: no sh
  docker run --rm "$REG/e2e/vuln:1" node -v > "$W/node-v.txt" 2>&1
  expect_eq "test image runs the real node binary" "$(cat "$W/node-v.txt")" "v22.23.3"
  ok "5 test images built and pushed to $REG"
fi

# ---------------------------------------------------------------- cluster
if has cluster; then
  echo "== cluster"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  cat > "$W/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
  kind create cluster --name "$CLUSTER" --config "$W/kind.yaml" --wait 120s > "$W/kind.log" 2>&1 ||
    die "kind cluster starts" "$(tail -n 5 "$W/kind.log" | tr '\n' ' ')"
  # nodes reach the registry on the host through the docker network gateway
  gw=$(docker network inspect kind -f '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' | tr ' ' '\n' | grep -E '^[0-9.]+$' | head -n 1)
  [ -n "$gw" ] || die "kind network gateway found"
  for node in $(kind get nodes --name "$CLUSTER"); do
    docker exec "$node" mkdir -p "/etc/containerd/certs.d/$REG"
    printf 'server = "http://%s:5001"\n\n[host."http://%s:5001"]\n  capabilities = ["pull", "resolve"]\n' "$gw" "$gw" |
      docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/$REG/hosts.toml"
  done
  kubectl create namespace "$NS" >/dev/null
  for n in vuln fixed unpatched backport noshell; do
    kubectl -n "$NS" create deployment "$n" --image="$REG/e2e/$n:1" >/dev/null
  done
  kubectl -n "$NS" scale deployment vuln --replicas=2 >/dev/null
  for n in vuln fixed unpatched backport noshell; do
    if ! kubectl -n "$NS" rollout status "deployment/$n" --timeout=180s > "$W/rollout-$n.log" 2>&1; then
      kubectl -n "$NS" describe pods -l "app=$n" > "$W/describe-$n.txt" 2>&1
      die "deployment $n becomes ready" "$(grep -E 'Warning|Failed|Error' "$W/describe-$n.txt" | tail -n 4 | tr '\n' ' ')"
    fi
  done
  ok "kind cluster with 6 pods (5 images) pulling from $REG"
fi

# ---------------------------------------------------------------- scan
if has scan; then
  echo "== scan: default mode (kubectl exec, BusyBox in the pods)"
  bash "$SCAN" -n "$NS" -o "$W/exec" > "$W/exec.out" 2> "$W/exec.err"; rc=$?
  expect_eq "exec: exit 1 (vulnerable found)" "$rc" 1
  expect_eq "exec: 5 unique images (2 replicas of vuln scanned once)" "$(($(wc -l < "$W/exec/report.tsv") - 1))" 5
  expect_eq "exec: Node 22.23.3 image vulnerable"            "$(row "$W/exec" "$REG/e2e/vuln:1")" VULNERABLE
  expect_eq "exec: Node 22.23.4 image patched"               "$(row "$W/exec" "$REG/e2e/fixed:1")" PATCHED
  expect_eq "exec: Ubuntu libbrotli1 1.1.0-2build2 vulnerable" "$(row "$W/exec" "$REG/e2e/unpatched:1")" VULNERABLE
  expect_eq "exec: Ubuntu backport (also 1.1.0) patched"     "$(row "$W/exec" "$REG/e2e/backport:1")" PATCHED
  expect_eq "exec: image without a shell needs review"       "$(row "$W/exec" "$REG/e2e/noshell:1")" REVIEW
  expect_has "exec: the reason (no sh) is reported"          "$W/exec/report.tsv" "executable file not found"
  expect_has "exec: real node -v from inside the pod"        "$W/exec/findings.tsv" "$(printf 'VULN\tnode\tnode v22.23.3\t')"
  expect_has "exec: workloads listed"                        "$W/exec/report.tsv" "$NS/ReplicaSet/vuln-"
  note "exec verdicts: $(awk -F'\t' 'NR>1 {printf "%s=%s ", $2, $1}' "$W/exec/report.tsv")"

  echo "== scan: --no-exec (pull by digest with crane)"
  BROTLI_IMAGE_TOOL=crane bash "$SCAN" -n "$NS" --no-exec --sarif -o "$W/noexec" > "$W/noexec.out" 2> "$W/noexec.err"; rc=$?
  expect_eq "no-exec: exit 1" "$rc" 1
  expect_eq "no-exec: image without a shell now scanned: vulnerable" "$(row "$W/noexec" "$REG/e2e/noshell:1")" VULNERABLE
  expect_eq "no-exec: Ubuntu backport patched"               "$(row "$W/noexec" "$REG/e2e/backport:1")" PATCHED
  expect_eq "no-exec: Node 22.23.4 image patched"            "$(row "$W/noexec" "$REG/e2e/fixed:1")" PATCHED
  expect_has "no-exec: pulls by digest"                      "$W/noexec.err" "(pull $REG/e2e/vuln@sha256:"
  if jq -e '.runs[0].results | length > 0' "$W/noexec/report.sarif" >/dev/null 2>&1; then ok "no-exec: SARIF written"; else bad "no-exec: SARIF written"; fi

  echo "== scan: --dry-run"
  bash "$SCAN" -n "$NS" --dry-run -o "$W/dry" > "$W/dry.out" 2>&1; rc=$?
  expect_eq "dry-run: exit 0" "$rc" 0
  expect_eq "dry-run: lists 5 images" "$(grep -c '^  exec ' "$W/dry.out")" 5
fi

# ---------------------------------------------------------------- job
if has job; then
  echo "== job: the scanner's container image as a Kubernetes Job (deploy/job.yaml)"
  kind load docker-image "$E2E_SCANNER_IMAGE" --name "$CLUSTER" > "$W/kind-load.log" 2>&1 ||
    die "scanner image loaded into kind" "$(tail -n 2 "$W/kind-load.log")"
  sed -e "s|image: ghcr.io/depuschm/brotli-k8s-scan:.*|image: $E2E_SCANNER_IMAGE|" \
      -e "s|args: \[\].*|args: [\"-n\", \"$NS\"]|" "$ROOT/deploy/job.yaml" > "$W/job.yaml"
  grep -q "image: $E2E_SCANNER_IMAGE" "$W/job.yaml" && grep -q "args: \[\"-n\"" "$W/job.yaml" || die "job manifest prepared"
  kubectl apply -f "$W/job.yaml" > "$W/job-apply.log" 2>&1 || die "deploy/job.yaml applies" "$(tail -n 3 "$W/job-apply.log")"
  for _ in $(seq 1 120); do
    st=$(kubectl -n brotli-scan get job brotli-k8s-scan -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null)
    case "$st" in 1/*|*/1) break ;; esac; sleep 3
  done
  kubectl -n brotli-scan logs job/brotli-k8s-scan > "$W/job.log" 2>&1
  code=$(kubectl -n brotli-scan get pods -l job-name=brotli-k8s-scan \
    -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
  expect_eq "job: finished with exit 1 (vulnerable found)" "$code" 1
  jrow() { awk -F'\t' -v img="$1" '$2 == img { print $1 }' "$W/job.log"; }
  expect_eq "job: Node 22.23.3 image vulnerable"        "$(jrow "$REG/e2e/vuln:1")" VULNERABLE
  expect_eq "job: Node 22.23.4 image patched"           "$(jrow "$REG/e2e/fixed:1")" PATCHED
  expect_eq "job: Ubuntu libbrotli1 1.1.0-2build2 vulnerable" "$(jrow "$REG/e2e/unpatched:1")" VULNERABLE
  expect_eq "job: Ubuntu backport (also 1.1.0) patched" "$(jrow "$REG/e2e/backport:1")" PATCHED
  expect_eq "job: image without a shell needs review"   "$(jrow "$REG/e2e/noshell:1")" REVIEW
  expect_has "job: summary in the log (5 unique images)" "$W/job.log" "=== Summary (5 unique images) ==="
  note "job verdicts: $(awk -F'\t' '$2 ~ /e2e/ {printf "%s=%s ", $2, $1}' "$W/job.log")"
  kubectl delete -f "$W/job.yaml" --wait=false >/dev/null 2>&1
fi

if has images; then
  echo "== scan: --image with real docker and crane"
  docker rmi -f "$REG/e2e/backport:1" >/dev/null 2>&1   # force docker to pull from the registry
  BROTLI_IMAGE_TOOL=docker bash "$SCAN" --image "$REG/e2e/backport:1" -o "$W/img-docker" > "$W/img-docker.out" 2>&1; rc=$?
  expect_eq "docker --image: Ubuntu backport patched (exit 0)" "$rc" 0
  BROTLI_IMAGE_TOOL=crane bash "$SCAN" --image "$REG/e2e/unpatched:1" -o "$W/img-crane" > "$W/img-crane.out" 2>&1; rc=$?
  expect_eq "crane --image: Ubuntu 1.1.0-2build2 vulnerable (exit 1)" "$rc" 1
  expect_has "crane --image: the library file decided" "$W/img-crane.out" "[VULN  ] binary  /usr/lib/"
fi

finish
