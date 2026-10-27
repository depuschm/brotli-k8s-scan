# brotli-k8s-scan

[![tests](https://github.com/depuschm/brotli-k8s-scan/actions/workflows/test.yml/badge.svg)](https://github.com/depuschm/brotli-k8s-scan/actions/workflows/test.yml)
![CVE-2026-111497](https://img.shields.io/badge/CVE--2026--111497-critical-red)
![license MIT](https://img.shields.io/badge/license-MIT-blue)
![dependencies: bash](https://img.shields.io/badge/dependencies-bash%20%2B%20coreutils-informational)

**Find vulnerable Brotli decoders (CVE-2026-111497, a.k.a. Broccoli2Shell /
Node2Shell / HTTP2Shell) in Kubernetes clusters, container images and Linux
machines, including the copies bundled inside Node.js, Python wheels, .NET,
nginx and other software.**

### Version numbers lie

| | Version it reports | Actually |
|---|---|---|
| Node.js 22.23.4 | bundled Brotli "1.1.0", same as vulnerable 22.23.3 | fixed |
| Ubuntu `libbrotli1 1.1.0-2ubuntu0.1` | "1.1.0", inside the affected range 1.0.3 – 1.2.0 | fixed (backport) |
| an app with its own private copy | usually nothing | ? |

Scanners that compare version numbers get these wrong. This tool also looks
**inside the binary**: the fix added a new decoder error code, and its name
(`_ERROR_FORMAT_BLOCK_SWITCH`) is compiled into every fixed decoder. No name,
no fix. [How it works](docs/how-detection-works.md).

```
$ ./brotli-k8s-scan.sh --image registry.example/base:24.04
Target: registry.example/base:24.04
Verdict: PATCHED
  [INFO  ] ospkg   dpkg: libbrotli1 1.1.0-2ubuntu0.1  -> distros backport fixes without changing the version; the library file itself is fingerprinted
  [OK    ] binary  /usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0  -> contains Brotli fix
```

## Quick start

One bash script, read-only, nothing to install in the cluster. Download a
release and verify it (see [Verify before you run](#verify-before-you-run)):

```bash
curl -fsSLO https://github.com/depuschm/brotli-k8s-scan/releases/latest/download/brotli-k8s-scan.sh
curl -fsSLO https://github.com/depuschm/brotli-k8s-scan/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x brotli-k8s-scan.sh
./brotli-k8s-scan.sh --dry-run    # shows what it would touch, touches nothing
```

| You want to scan | Command | Needs |
|---|---|---|
| a cluster | `./brotli-k8s-scan.sh` | `kubectl`, `jq`; RBAC: list pods + `pods/exec` |
| a cluster, without `exec` | `./brotli-k8s-scan.sh --no-exec` | `kubectl`, `jq`, `crane`/`docker`/`podman` with pull access; RBAC: list pods only |
| container images | `./brotli-k8s-scan.sh --image IMG [--image IMG2 ...]` or `--images-from list.txt` | `crane`, `docker` or `podman` |
| this machine | `./brotli-k8s-scan.sh --rootfs /` | nothing |
| an unpacked filesystem | `./brotli-k8s-scan.sh --rootfs ./dir` | nothing |

Useful options: `-n NAMESPACE`, `--context CTX`, `--platform linux/arm64`,
`--deep` (also fingerprint every executable and shared library > 100 KB, to find
statically linked copies), `--sarif`, `-o DIR`, `--dry-run`, `--print-probe`.

Example (cluster):

```
=== Summary (8 unique images) ===
VULNERABLE       3
REVIEW           0
PATCHED          4
NO_BROTLI_FOUND  1

VULNERABLE registry.example/api:1.4
           used by: shop/ReplicaSet/api-7d9f
           VULN: Brotli 1.2.0 (/app/venv/lib/python3/site-packages/Brotli-1.2.0.dist-info); VULN: /usr/lib/libbrotlidec.so.1.2.0; VULN: /usr/local/bin/node
VULNERABLE registry.example/proxy:1.0
           used by: ops/DaemonSet/proxy
           VULN: /usr/lib/libbrotlidec.so.1.0.9
```

## What it checks

| Component | Affected | Fixed in | How it is detected |
|---|---|---|---|
| Google Brotli (C library) | 1.0.3 – 1.2.0 | 1.0.10, 1.1.1, 1.2.1 (and distro backports) | binary fingerprint |
| Node.js | 22.x, 24.x, 26.x before the fix; 20.x and older get no fix | 22.23.4, 24.22.1, 26.12.1 | `node -v` + fingerprint |
| Bun | 1.4.3 and earlier | 1.4.4 | `bun --version` + fingerprint |
| Python `Brotli` / `brotlicffi` | ≤ 1.2.0 / ≤ 1.2.0.x | 1.2.1 / 1.2.1.0 | `*.dist-info` in every venv + fingerprint of the wheel |
| .NET | before the fix | 8.0.33, 9.0.22, 10.0.14 | fingerprint of `libSystem.IO.Compression.Native.so`, else the runtime version (framework folder or a self-contained app's `*.deps.json`); runtimes built against the system `libbrotli` (e.g. Ubuntu's .NET 10) are judged by that library |
| Envoy | 1.36 – 1.39 before the fix | 1.36.12, 1.37.8, 1.38.6, 1.39.3, 1.40.0 | `envoy --version` + fingerprint |
| Istio | 1.29 – 1.31 before the fix | 1.29.9, 1.30.6, 1.31.2 | fingerprint of the `envoy` binary in the proxy image |
| anything else with Brotli compiled in (Pillow, curl, nginx modules, Electron apps, ...) | | | binary fingerprint |

Envoy and Istio are only exposed if the Brotli decompressor is configured.
Any other process is exposed when it decompresses Brotli data it does not
control: request bodies (e.g. Express 5 / body-parser 2) and responses fetched
from other servers (`fetch()`, Python `requests` / `httpx` / `aiohttp` /
`urllib3` when Brotli is installed, curl with compression).

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | at least one vulnerable runtime, package or embedded decoder |
| `REVIEW` | Brotli found but its patch state is unknown: stripped binary, a Java jar that may bundle it, no shell for `exec`, or the image could not be pulled |
| `PATCHED` | Brotli found and every copy contains the fix |
| `NO_BROTLI_FOUND` | nothing found among the usual suspects (add `--deep` to be thorough) |

## Output

Written to `./brotli-scan-<timestamp>/` (or `-o DIR`):

| File | Content |
|---|---|
| `report.tsv` | one row per image: verdict, image, digest, workloads using it, findings |
| `findings.tsv` | every finding |
| `report.json` | the same, machine-readable (needs `jq`) |
| `report.sarif` | with `--sarif`: SARIF 2.1.0 for GitHub code scanning and other SARIF tools |
| `raw/` | raw probe output |

Exit codes: `0` nothing vulnerable, `1` vulnerable found, `3` nothing vulnerable
but items need review, `2` usage error.

Gate a build on it, and send the results to GitHub code scanning:

```yaml
- name: Scan image for CVE-2026-111497
  run: ./brotli-k8s-scan.sh --image "$IMAGE" --sarif -o brotli-scan
- name: Upload results
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: brotli-scan/report.sarif
```

## YARA rules

The same detection as YARA rules, for EDR and other YARA-capable tools:
[`yara/brotli_cve_2026_111497.yar`](yara/brotli_cve_2026_111497.yar).

```bash
yara -r yara/brotli_cve_2026_111497.yar /usr
```

`Brotli_Decoder_Vulnerable_CVE_2026_111497` and
`Brotli_Decoder_Patched_CVE_2026_111497` separate fixed and vulnerable decoders,
and `Brotli_Present_Patch_State_Unknown` flags Brotli copies without a readable
error table.

## How it works

1. **Cluster mode:** lists running pods and picks **one container per image
   digest**, then runs a small POSIX `sh` probe in it with `kubectl exec`
   (works with BusyBox/Alpine). **`--no-exec` / `--image`:** pulls the image
   and unpacks its filesystem into a temporary directory instead; nothing from
   the image is executed. The temporary directory is deleted afterwards.
2. The probe reads versions (Node.js, Bun, Envoy, .NET, Python `dist-info`,
   dpkg/apk/rpm databases) and fingerprints the usual binaries: `node`, `bun`,
   `envoy`, `nginx`, `curl`, `libbrotli*`, Python extension modules,
   `libSystem.IO.Compression.Native.so`, `*.node` addons, ... (`--deep`: every
   executable and shared library > 100 KB).
3. Results are evaluated on your machine and written to the reports.

Details and the evidence behind the fingerprint: [docs/how-detection-works.md](docs/how-detection-works.md).

## Verify before you run

A scanner that runs inside your production pods should be easy to check:

| What | How |
|---|---|
| The file is the one this repository built | `sha256sum -c SHA256SUMS --ignore-missing` and `gh attestation verify brotli-k8s-scan.sh --repo depuschm/brotli-k8s-scan` (signed build provenance from GitHub Actions) |
| Exactly what runs inside your containers | `./brotli-k8s-scan.sh --print-probe` (about 100 lines of POSIX sh; a test checks it is byte-identical to what is executed) |
| Which pods / images it would touch | `./brotli-k8s-scan.sh --dry-run` (with `--no-exec`: which images it would pull) |
| It needs no network | `unshare -rn ./brotli-k8s-scan.sh --rootfs /` works without any network access |
| The detection is correct | every change is tested in [GitHub Actions](https://github.com/depuschm/brotli-k8s-scan/actions/workflows/test.yml) on x86-64 and arm64 against real vulnerable and fixed builds (see [Tests](#tests)) |

Found a wrong verdict or a security problem? See [SECURITY.md](SECURITY.md).

## Permissions

- Default cluster mode: `get`/`list` pods and `create` on `pods/exec`. See
  [`rbac/scanner-clusterrole.yaml`](rbac/scanner-clusterrole.yaml). `pods/exec`
  is powerful: grant it only for the scan. One namespace only:
  [`rbac/scanner-role-namespaced.yaml`](rbac/scanner-role-namespaced.yaml).
- `--no-exec`: only `get`/`list` pods, plus pull access to your registries
  (`crane auth login` / `docker login`).

## Limitations

- Only the **C** Brotli library is detected. Pure Go, Rust or Java
  reimplementations do not contain it; check their own advisories.
- Java jars that bundle the native library (e.g. brotli4j) are compressed and
  are listed as `REVIEW`.
- Stripped, statically linked binaries can lose the decoder's error table; they
  are found (with `--deep`) but reported as `REVIEW`.
- Cluster modes see running pods only. CronJobs between runs or
  scaled-to-zero workloads: scan their images with `--image`.
- .NET single-file apps that embed the native library inside the executable
  are only found with `--deep`, and then as `REVIEW`.

This tool contains no exploit code and sends nothing anywhere except through
your own `kubectl` / registry tools.

## Related tools

Different tools answer different questions; they complement each other:

- [assetnote/node2shell-scanner](https://github.com/assetnote/node2shell-scanner):
  checks a running Node.js service remotely, over HTTP.
- [trailofbits/brotli-checker](https://github.com/trailofbits/brotli-checker):
  finds Brotli copies in source trees and folders; Claude Code / Codex skill.
- [jfrog/vulnerability_scanners](https://github.com/jfrog/vulnerability_scanners/tree/main/brotli2shell_cve_2026_111497):
  finds code paths in your own JavaScript / Python that decompress Brotli.

## Tests

Real vulnerable and fixed builds are assembled into fake container
filesystems, with fake `kubectl`, `crane` and `docker`:

- Brotli 1.0.9 / 1.0.10 / 1.2.0 / 1.2.1 built from source, plus a stripped static program
- Node.js 22.23.3 / 22.23.4 official binaries
- Python `Brotli` 1.2.0 / 1.2.1 and `brotlicffi` 1.2.0.1 / 1.2.1.0 wheels
- Ubuntu `libbrotli1` 1.1.0-2build2 / 1.1.0-2ubuntu0.1 (same version string, backported fix)
- .NET: Ubuntu's .NET 8.0.32 and 10.0.13 runtimes, official Microsoft runtimes
  8.0.32 / 8.0.33 / 10.0.13 / 10.0.14 (downloaded in CI), self-contained app layouts

```bash
tests/build-fixtures.sh   # once; downloads sources and binaries (needs network; BROTLI_TEST_STRICT=1 makes every fixture mandatory)
tests/run-tests.sh        # offline: re-runs itself under `unshare -rn` without network
```

The suite repeats every probe test with `sh`, `dash` and, if installed,
BusyBox (with only BusyBox tools in `PATH`, like an Alpine image). It also
validates `report.sarif` against the SARIF 2.1.0 schema and checks the YARA
rules against the same binaries. In GitHub Actions it runs on x86-64 and arm64
with every fixture mandatory, so a skipped download fails the build instead of
silently reducing coverage.

## License

MIT, see [LICENSE](LICENSE). No warranty: a clean result does not prove that a
system is not affected.
