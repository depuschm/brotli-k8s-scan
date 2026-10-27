# Security policy

## Reporting a problem

If you find a security problem in brotli-k8s-scan, or a case where it reports
a vulnerable system as safe, please report it privately through GitHub:
**Security** tab → **Report a vulnerability**
(<https://github.com/depuschm/brotli-k8s-scan/security/advisories/new>).

Please include the scanner version (`./brotli-k8s-scan.sh --version`), the
command you ran, and, if possible, the file that was misclassified or its
package name and version.

A wrong verdict (a vulnerable decoder reported as `PATCHED`, or the other way
round) is treated as a security bug.

## Supported versions

Only the latest release gets fixes. Always use the newest release.

## What the scanner does on your systems

- It is **read-only**. It installs, changes and restarts nothing.
- Default cluster mode runs the shell code shown by `--print-probe` in one
  container per image (`kubectl exec`). That code only reads files and runs
  `--version`-style commands (`node -v`, `bun --version`, `envoy --version`,
  `dotnet --list-runtimes`, `curl -V`, `rpm -qa`).
- `--no-exec` and `--image` pull images with your own `crane` / `docker` /
  `podman` and unpack them into a temporary directory; nothing from the
  image is executed, and the directory is deleted afterwards.
- It sends nothing anywhere. All network traffic goes through your own
  `kubectl` and registry tools. `--rootfs` mode needs no network at all:
  `unshare -rn ./brotli-k8s-scan.sh --rootfs /` works.
- `--dry-run` shows which pods or images would be touched, without touching them.

## Hostile images

A container image can be built to mislead a scanner. What the scanner does
about it:

- **Image, `--no-exec` and `--rootfs` scans execute nothing** from the image
  and read only files that lie inside it: a symlink that leads out of the
  unpacked image (for example `etc/os-release -> /etc/os-release`) is not
  followed.
- **File names with control characters** (tab, newline, escape sequences)
  are not parsed; such names could otherwise forge or split the probe's
  records. They are counted, and the image is reported as `REVIEW` with
  "file name(s) with control characters". List them with
  `find ROOT -xdev -name '*[[:cntrl:]]*'`.
- **Everything the probe prints is cleaned** of control characters before it
  reaches your terminal or the reports.
- **Default cluster mode runs the container's own** `sh`, `find` and
  `node -v`. A malicious image can make those print anything, so for images
  you do not trust, use `--no-exec` or `--image`, which only read files.

These properties are fuzz-tested (`tests/fuzz/`): random file trees with
hostile names and symlinks must never hide a vulnerable binary or make the
probe read a file outside the tree.

## Verifying a download

Release files come with `SHA256SUMS` and a signed build provenance
attestation created by GitHub Actions from this repository:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify brotli-k8s-scan.sh --repo depuschm/brotli-k8s-scan
```

Releases after v0.3.0 also carry the signed provenance as files:
`brotli-k8s-scan.sigstore.json` (Sigstore bundle, e.g. for
`gh attestation verify brotli-k8s-scan.sh --repo depuschm/brotli-k8s-scan --bundle brotli-k8s-scan.sigstore.json`)
and `brotli-k8s-scan.intoto.jsonl` (the same signed SLSA provenance as an
in-toto envelope).
