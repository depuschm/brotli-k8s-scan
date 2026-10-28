# Changelog

## Unreleased

Security (hostile images; found while writing the fuzz tests):
- A file named e.g. `node<TAB>.node` with fixed-looking content could override
  the result for the real, vulnerable `/usr/local/bin/node` and turn the
  verdict into `PATCHED`. File names with control characters are no longer
  parsed; they are counted and reported as `REVIEW`. If a binary is reported
  twice, the worse state wins.
- In image, `--no-exec` and `--rootfs` scans a file name containing a newline
  could make the probe read a file from the directory the scan was started
  in, and symlinks such as `etc/os-release -> /etc/os-release` were followed
  to the host. Files outside the scanned root are no longer read.
- The probe prints records with `printf` instead of `echo` (dash's `echo`
  turns `\n` in a name into a newline), and control characters, including
  terminal escape sequences, are removed from everything the probe prints.

Tests:
- Fuzz tests with atheris (`tests/fuzz/`): random probe output against a model
  of the verdict rules, and random hostile file trees against the probe with
  `sh`, `dash`, `bash` and BusyBox. Short session in the suite, CI job `fuzz`.
- Regression tests for the cases above.

## 0.4.0 (2026-10-27)

Scanner:
- Envoy: official Envoy builds keep no decoder error table, so the version
  decides (`envoy --version` in the default cluster mode). Without `exec`
  (image and `--no-exec` scans) Envoy is now reported as `REVIEW` with an
  Envoy-specific explanation instead of a generic "stripped binary" note.
  README: the Envoy and Istio rows are corrected accordingly (Istio: not tested).
- Exec failures now report the real reason (e.g. no `sh` in the image), also
  when the container runtime prints it on standard output.

Evidence and trust:
- Tested against the official Bun 1.4.3 / 1.4.4 and Envoy 1.36.11 / 1.36.12
  release binaries; Bun is decided by its fingerprint alone.
- End-to-end test on a real Kubernetes cluster (kind) in CI: real registry,
  real `kubectl exec` (BusyBox in the pods, real `node -v`), `--no-exec` with
  real `crane` pulls by digest, `--image` with real `docker`.
- Releases attach the signed SLSA provenance as files
  (`brotli-k8s-scan.sigstore.json`, `brotli-k8s-scan.intoto.jsonl`) for
  offline verification.
- CodeQL static analysis of workflows, Python and JavaScript on every change.
- Test helpers (yara-python, jsonschema) are installed with exact versions and
  verified hashes (`tests/requirements.txt`).
- Upkeep: Dependabot (GitHub Actions, test helpers), a weekly test run without
  the download cache, OpenSSF Scorecard (workflow and badge).

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
