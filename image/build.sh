#!/usr/bin/env bash
# Builds the scanner's container image for this machine's architecture
# (amd64 or arm64). There is no base image; every file in it comes from here:
#
#   brotli-k8s-scan     the scanner script of this checkout
#   bash, busybox       Ubuntu's static builds (packages bash-static and
#                       busybox-static), fetched with apt-get, which checks
#                       them against Ubuntu's signed package index
#   jq, crane, kubectl  official release binaries, checked against the
#                       hashes pinned below
#   CA certificates     from the build machine (for registry pulls)
#
# The image runs as an unprivileged user (65532). A list of every file with
# its SHA-256 is inside: /usr/share/doc/brotli-k8s-scan/CONTENTS.
#
# usage: image/build.sh TAG [VERSION]
# needs: Ubuntu (apt-get, dpkg-deb), docker, curl, sha256sum, sha512sum
# shellcheck disable=SC2034  # the per-architecture hashes below are read as ${!name}
set -euo pipefail

# Pinned releases. Update: change version and hashes together; the hashes
# come from each project's published checksums (jq: sha256sum.txt, crane:
# checksums.txt, kubectl: the "Client Binaries" table of the Kubernetes
# CHANGELOG, SHA-512 of kubernetes-client-linux-<arch>.tar.gz).
JQ_VERSION=1.8.2
JQ_SHA256_amd64=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f
JQ_SHA256_arm64=8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309
CRANE_VERSION=0.22.1
CRANE_SHA256_amd64=0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0
CRANE_SHA256_arm64=898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110
KUBECTL_VERSION=1.37.1
KUBECTL_SHA512_amd64=decde4d990d0fbf6451e65524dec42c549de3339f27005c45af8d3c61cca1de852524ebf2215c82be86d4ab2621c823f56f718b8d2c304b9100a903e696c0c32
KUBECTL_SHA512_arm64=bd57d942ec8977b1da238d2c37d01e9aced530b789773158af058c87f4b407c3a87ddc400abb33659154dafdf6b38011b252491312927a58861b979a56d8f741
# licence texts that must ship with the jq and kubectl binaries
JQ_COPYING_SHA256=ad2b4a266b2268939c1446979759706077421cf906a203aa188c6f396e8cfd74
KUBECTL_LICENSE_SHA256=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30

TAG=${1:?usage: image/build.sh TAG [VERSION]}
HERE=$(cd "$(dirname "$0")" && pwd -P)
ROOT=$(dirname "$HERE")
VERSION=${2:-$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$ROOT/brotli-k8s-scan.sh")}
ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64) CRANE_ARCH=x86_64 ;; arm64) CRANE_ARCH=arm64 ;; *) echo "unsupported architecture: $ARCH" >&2; exit 2 ;; esac
CACHE="$HERE/.cache/$ARCH"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
FS="$W/ctx/rootfs"
mkdir -p "$CACHE" "$FS"

fetch() {  # $1=url $2=file in cache $3=algorithm $4=expected hash
  local f="$CACHE/$2"
  if [ ! -f "$f" ] || ! echo "$4  $f" | "${3}sum" -c --status; then
    curl -fsSL --retry 3 -o "$f.part" "$1"
    echo "$4  $f.part" | "${3}sum" -c --quiet || { rm -f "$f.part"; echo "checksum mismatch: $1" >&2; exit 1; }
    mv "$f.part" "$f"
  fi
}

echo "== downloads ($ARCH)"
jq_sha=JQ_SHA256_$ARCH crane_sha=CRANE_SHA256_$ARCH kubectl_sha=KUBECTL_SHA512_$ARCH
fetch "https://github.com/jqlang/jq/releases/download/jq-$JQ_VERSION/jq-linux-$ARCH" "jq-$JQ_VERSION" sha256 "${!jq_sha}"
fetch "https://github.com/google/go-containerregistry/releases/download/v$CRANE_VERSION/go-containerregistry_Linux_$CRANE_ARCH.tar.gz" \
  "crane-$CRANE_VERSION.tar.gz" sha256 "${!crane_sha}"
fetch "https://dl.k8s.io/v$KUBECTL_VERSION/kubernetes-client-linux-$ARCH.tar.gz" "kubectl-$KUBECTL_VERSION.tar.gz" sha512 "${!kubectl_sha}"
fetch "https://raw.githubusercontent.com/jqlang/jq/jq-$JQ_VERSION/COPYING" "jq-$JQ_VERSION-COPYING" sha256 "$JQ_COPYING_SHA256"
fetch "https://raw.githubusercontent.com/kubernetes/kubernetes/v$KUBECTL_VERSION/LICENSE" "kubectl-$KUBECTL_VERSION-LICENSE" \
  sha256 "$KUBECTL_LICENSE_SHA256"
(cd "$W" && apt-get download -q bash-static busybox-static >/dev/null 2>&1) ||
  { echo "apt-get download bash-static busybox-static failed (Ubuntu only; run apt-get update?)" >&2; exit 1; }

echo "== root filesystem"
mkdir -p "$FS/bin" "$FS/usr/bin" "$FS/usr/sbin" "$FS/sbin" "$FS/usr/local/bin" "$FS/etc/ssl/certs" \
  "$FS/usr/share/doc/brotli-k8s-scan/licenses" "$FS/tmp"
chmod 1777 "$FS/tmp"
for p in bash-static busybox-static; do
  mkdir -p "$W/$p"; dpkg-deb -x "$W/${p}_"*.deb "$W/$p"
  cp "$W/$p/usr/share/doc/$p/copyright" "$FS/usr/share/doc/brotli-k8s-scan/licenses/$p"
done
cp "$W/bash-static/usr/bin/bash-static" "$FS/bin/bash"
BB="$W/busybox-static/usr/bin/busybox"
cp "$BB" "$FS/bin/busybox"
# BusyBox applets as symlinks at their usual places (sh, awk, find, tar, ...)
"$BB" --list-full | while read -r a; do
  [ -e "$FS/$a" ] || [ -L "$FS/$a" ] || ln -s /bin/busybox "$FS/$a"
done
cp "$CACHE/jq-$JQ_VERSION" "$FS/usr/local/bin/jq"
cp "$CACHE/jq-$JQ_VERSION-COPYING" "$FS/usr/share/doc/brotli-k8s-scan/licenses/jq"
cp "$CACHE/kubectl-$KUBECTL_VERSION-LICENSE" "$FS/usr/share/doc/brotli-k8s-scan/licenses/kubectl"
tar -xzf "$CACHE/crane-$CRANE_VERSION.tar.gz" -C "$W" crane LICENSE
cp "$W/crane" "$FS/usr/local/bin/crane"; cp "$W/LICENSE" "$FS/usr/share/doc/brotli-k8s-scan/licenses/crane"
tar -xzf "$CACHE/kubectl-$KUBECTL_VERSION.tar.gz" -C "$W" kubernetes/client/bin/kubectl
cp "$W/kubernetes/client/bin/kubectl" "$FS/usr/local/bin/kubectl"
cp "$ROOT/brotli-k8s-scan.sh" "$FS/usr/local/bin/brotli-k8s-scan"
cp "$ROOT/LICENSE" "$FS/usr/share/doc/brotli-k8s-scan/licenses/brotli-k8s-scan"
chmod 755 "$FS/bin/bash" "$FS/bin/busybox" "$FS/usr/local/bin/"*
cp -L /etc/ssl/certs/ca-certificates.crt "$FS/etc/ssl/certs/ca-certificates.crt"
printf 'root:x:0:0:root:/root:/sbin/nologin\nscanner:x:65532:65532:scanner:/tmp:/sbin/nologin\n' > "$FS/etc/passwd"
printf 'root:x:0:\nscanner:x:65532:\n' > "$FS/etc/group"
cat > "$FS/usr/share/doc/brotli-k8s-scan/README" <<EOF
brotli-k8s-scan $VERSION container image ($ARCH)
https://github.com/depuschm/brotli-k8s-scan

Components:
  brotli-k8s-scan  $VERSION  (MIT)
  bash             $(dpkg-deb -f "$W/bash-static_"*.deb Version)  Ubuntu package bash-static (GPL-3+)
  busybox          $(dpkg-deb -f "$W/busybox-static_"*.deb Version)  Ubuntu package busybox-static (GPL-2)
  jq               $JQ_VERSION  https://github.com/jqlang/jq (MIT)
  crane            $CRANE_VERSION  https://github.com/google/go-containerregistry (Apache-2.0)
  kubectl          $KUBECTL_VERSION  https://github.com/kubernetes/kubernetes (Apache-2.0)
The sources of bash and busybox are Ubuntu's source packages of the same
versions: https://launchpad.net/ubuntu/+source/bash and
https://launchpad.net/ubuntu/+source/busybox. Licence texts: licenses/.
EOF
(cd "$FS" && find . -type f ! -path ./usr/share/doc/brotli-k8s-scan/CONTENTS -print0 | sort -z | xargs -0 sha256sum |
  sed 's|  \./|  /|') > "$W/CONTENTS"
mv "$W/CONTENTS" "$FS/usr/share/doc/brotli-k8s-scan/CONTENTS"

echo "== image $TAG"
cp "$HERE/Dockerfile" "$W/ctx/Dockerfile"
docker build -q --platform "linux/$ARCH" --build-arg "VERSION=$VERSION" -t "$TAG" "$W/ctx" >/dev/null
docker run --rm --entrypoint /bin/sh "$TAG" -c \
  'brotli-k8s-scan --version && bash --version | head -n 1 && jq --version && crane version && kubectl version --client | head -n 1'
echo "built $TAG ($ARCH)"
