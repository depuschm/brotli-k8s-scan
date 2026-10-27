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

## Verifying a download

Release files come with `SHA256SUMS` and a signed build provenance
attestation created by GitHub Actions from this repository:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify brotli-k8s-scan.sh --repo depuschm/brotli-k8s-scan
```
