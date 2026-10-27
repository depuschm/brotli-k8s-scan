# Changelog

## Unreleased

- Tested against the official Bun 1.4.3 / 1.4.4 and Envoy 1.36.11 / 1.36.12
  release binaries. Bun: the fingerprint decides on its own. Envoy builds keep
  no decoder error table, so `envoy --version` (default cluster mode) decides;
  without `exec` Envoy is now reported as `REVIEW` with an Envoy-specific
  explanation. README: corrected the Envoy and Istio rows accordingly.

## 0.3.0 (2026-10-27)

- .NET: reads the runtime version of **self-contained apps** from their
  `*.deps.json`, and recognises runtimes that use the system `libbrotli`
  instead of a bundled copy (their patch state is that library's).
- Tested against real .NET runtimes: Ubuntu's .NET 8.0.32 (bundled Brotli,
  found vulnerable by fingerprint) and .NET 10.0.13 (system `libbrotli`), and
  in CI the official Microsoft builds 8.0.32 / 8.0.33 / 10.0.13 / 10.0.14.
- `--print-probe`: prints the exact shell code that runs inside containers
  (a test checks it is byte-identical to what is executed).
- `--dry-run`: lists the pods / images that would be scanned, touches nothing.
- GitHub Actions: tests on x86-64 and arm64 for every change; releases get
  `SHA256SUMS` and a signed build provenance attestation.
- `SECURITY.md`, namespace-scoped RBAC example.
- Terminal output: colour-coded finding states, summary columns stay aligned
  with colours on, and the `--deep` tip only appears when something was
  `NO_BROTLI_FOUND`.
- README: banner, fingerprint diagram and screenshots of real scanner output,
  reproducible with `docs/images/src/build-images.sh`; `CONTRIBUTING.md`.

## 0.2.0 (2026-10-27)

- `--no-exec`: scan a cluster without `pods/exec` by pulling each image by digest.
- `--image`, `--images-from`, `--platform`: scan container images directly
  (crane, docker or podman). `--rootfs /` scans the local machine.
- `report.json` and `--sarif` (SARIF 2.1.0, schema-validated).
- Version rules for .NET (8.0.33 / 9.0.22 / 10.0.14) and Envoy.
- YARA rules with the same fingerprint logic.
- Fix: `--rootfs /` dropped the leading `/` from reported paths.

## 0.1.0 (2026-10-27)

- First release: Kubernetes scanner with version checks and the
  `_ERROR_FORMAT_BLOCK_SWITCH` binary fingerprint; works with BusyBox images.
