# brotli-k8s-scan

Find containers in a Kubernetes cluster that are affected by **CVE-2026-111497**
(also called *Broccoli2Shell*, *Node2Shell* or *HTTP2Shell*), an out-of-bounds
write in the Google Brotli decoder.

One bash script, read-only, no agents to install. It also finds Brotli copies
that are **bundled inside other software** (Node.js, Python wheels, Pillow,
.NET, nginx modules, ...), which OS package scanners and most dependency
scanners do not see.

## The vulnerability in short

| Component | Affected | Fixed in |
|---|---|---|
| Google Brotli (C library) | 1.0.3 – 1.2.0 | 1.0.10, 1.1.1, 1.2.1 |
| Node.js | 22.x, 24.x, 26.x before the fix; 20.x and older get no fix | 22.23.4, 24.22.1, 26.12.1 |
| Bun | before 1.4.4 | 1.4.4 |
| Python `Brotli` | before 1.2.1 | 1.2.1 |
| Python `brotlicffi` | before 1.2.1.0 | 1.2.1.0 |

Any process that decompresses attacker-controlled Brotli data is exposed:
incoming request bodies (e.g. Express 5 / body-parser 2), and responses fetched
from untrusted servers (`fetch()`, Python `requests`/`httpx`/`aiohttp`/`urllib3`
with Brotli installed, curl with compression enabled).

References:
[Node.js 22.23.4 release](https://nodejs.org/en/blog/release/v22.23.4) ·
[google/brotli releases](https://github.com/google/brotli/releases) ·
[GHSA-9v8h-qqgm-4m35 (Python)](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)

## Quick start

Requirements on your machine: `bash`, `kubectl` (pointed at the cluster), `jq`, `awk`.

```bash
curl -fsSLO https://raw.githubusercontent.com/depuschm/brotli-k8s-scan/main/brotli-k8s-scan.sh
less brotli-k8s-scan.sh          # read it first - it runs inside your containers
chmod +x brotli-k8s-scan.sh

./brotli-k8s-scan.sh                       # all namespaces, current context
./brotli-k8s-scan.sh -n my-namespace       # one namespace
./brotli-k8s-scan.sh --context prod --deep # also fingerprint every large binary
```

Example output:

```
=== Summary (42 unique images) ===
VULNERABLE       3
REVIEW           2
PATCHED          11
NO_BROTLI_FOUND  26

VULNERABLE registry.example/api:1.4
           used by: shop/ReplicaSet/api-7d9f
           VULN: Brotli 1.2.0 (/app/venv/lib/python3.12/site-packages/Brotli-1.2.0.dist-info); VULN: /usr/local/bin/node
```

Results are written to `./brotli-scan-<timestamp>/`:

| File | Content |
|---|---|
| `report.tsv` | one row per image: verdict, image, digest, sampled pod, workloads using the image, findings |
| `findings.tsv` | every single finding |
| `raw/` | raw probe output per image |

Exit codes: `0` nothing vulnerable, `1` vulnerable found, `3` nothing vulnerable but items need review, `2` usage error.

## What it does

1. `kubectl get pods` and picks **one running container per unique image digest**.
2. Runs a small POSIX `sh` probe in that container with `kubectl exec`. The
   probe only reads files and prints versions. Nothing is installed, written,
   or restarted.
3. Evaluates the results locally.

The probe uses two independent signals:

- **Version numbers** of Node.js, Bun, Python `Brotli` / `brotlicffi`
  (from `*.dist-info` folders anywhere on the image), OS packages (dpkg, apk, rpm),
  .NET runtimes and curl.
- **A binary fingerprint.** The fix added a new decoder error code,
  `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17), whose name is compiled into
  the decoder's error table. A binary that contains the Brotli dictionary and
  the error table **but not** `_ERROR_FORMAT_BLOCK_SWITCH` has a vulnerable
  decoder (`BLOCK_SWITCH` for the 1.0.x line). This works regardless of how the
  copy got there, and it also recognises distro backports of the fix.

By default it fingerprints the usual suspects (`node`, `bun`, `envoy`, `nginx`,
`curl`, `libbrotli*`, `_brotli*.so`, `libSystem.IO.Compression.Native.so`,
`*.node` addons, `libcurl`, ...). With `--deep` it fingerprints every executable
and shared library larger than 100 KB.

### Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | at least one vulnerable runtime, package or embedded decoder found |
| `REVIEW` | could not decide: no shell in the container, a stripped binary that embeds Brotli without a readable version, or a Java jar that may bundle it |
| `PATCHED` | Brotli found and every copy contains the fix |
| `NO_BROTLI_FOUND` | nothing found among the usual suspects (use `--deep` to be thorough) |

## Images without a shell (distroless, scratch)

`kubectl exec` needs `sh` in the container, so these are reported as `REVIEW`.
Scan their filesystem offline instead:

```bash
crane export registry.example/app:1.2 - | (mkdir -p img && tar -x -C img)
# or: docker create --name x registry.example/app:1.2 && docker export x | tar -x -C img
./brotli-k8s-scan.sh --rootfs ./img --deep
```

## Permissions

The account running the scan needs `get`/`list` on `pods` and `create` on
`pods/exec`. See [`rbac/scanner-clusterrole.yaml`](rbac/scanner-clusterrole.yaml)
for a minimal ClusterRole you can bind to a user or group.

Note that `pods/exec` is a powerful permission: grant it only for the duration of the scan.

## Limitations

- Only the **C** Brotli library is detected. Pure Go, Rust or Java
  reimplementations do not contain it; check their own advisories.
- Java jars that bundle the native library (e.g. brotli4j) are compressed
  archives and cannot be fingerprinted; they are listed as `REVIEW`.
- Stripped, statically linked binaries built with dead-code elimination may
  drop the error table; they are reported as `REVIEW` (Brotli present, version unknown).
- It samples one container per image digest, so running pods only.
  Images that are not currently running (CronJobs between runs, scaled-to-zero
  deployments) are not scanned. Scan those with `--rootfs`.
- Distro packages may carry backported fixes under an old version number. The
  version is shown for information; the fingerprint of the library file decides.

This tool contains no exploit code and sends no data anywhere other than your
own `kubectl` connection.

## Tests

The tests use real vulnerable and fixed builds of Brotli (1.0.9, 1.0.10, 1.2.0,
1.2.1), Python `Brotli`/`brotlicffi` wheels and Node.js 22.23.3 / 22.23.4,
assembled into fake container filesystems, plus a fake `kubectl`.

```bash
tests/build-fixtures.sh   # once; downloads sources and binaries (needs network, git, cmake, cc, pip, npm)
tests/run-tests.sh        # offline: re-runs itself under `unshare -rn` with no network
```

The probe must work in minimal images, so the suite repeats every test with
each POSIX shell it finds: `sh`, `dash` and, if installed, BusyBox (with *only*
BusyBox applets in `PATH`, like an Alpine image).

## License

MIT, see [LICENSE](LICENSE). No warranty: a clean result does not prove that a
system is not affected.
