# The scanner's container image. Build it with image/build.sh, which
# assembles rootfs/ from checked downloads; there is no base image.
FROM scratch
ARG VERSION=dev
COPY rootfs/ /
USER 65532:65532
WORKDIR /tmp
ENV PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin HOME=/tmp
ENTRYPOINT ["/usr/local/bin/brotli-k8s-scan"]
LABEL org.opencontainers.image.title="brotli-k8s-scan" \
      org.opencontainers.image.description="Finds Brotli decoders vulnerable to CVE-2026-111497 in Kubernetes clusters, container images and filesystems" \
      org.opencontainers.image.source="https://github.com/depuschm/brotli-k8s-scan" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
