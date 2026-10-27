# Contributing and maintenance

## Layout

| Path | What |
|---|---|
| `brotli-k8s-scan.sh` | the scanner: one bash script; the POSIX `sh` probe that runs in containers is the `PROBE` heredoc (`--print-probe` shows it) |
| `yara/` | the same fingerprint as YARA rules |
| `tests/` | fixture builder, offline test suite, fake `kubectl` / `crane` / `docker` |
| `docs/how-detection-works.md` | the write-up behind the fingerprint |
| `docs/images/` | README images; `docs/images/src/` regenerates them |
| `rbac/` | RBAC examples |
| `.github/workflows/` | `test.yml` (every change), `release.yml` (on a published release) |

## Tests

```bash
tests/build-fixtures.sh   # needs network once: real vulnerable/fixed Brotli, Node.js, Python, Ubuntu and .NET builds
tests/run-tests.sh        # offline: re-runs itself in a network namespace without network (unshare -rn)
```

- The suite repeats probe tests with `sh`, `dash` and BusyBox (install
  `busybox-static`); BusyBox matters because Alpine images use it.
- `BROTLI_TEST_STRICT=1` (used in CI) makes every fixture mandatory and turns
  skipped tests into failures. Microsoft's .NET downloads are only reachable
  from CI in some environments; locally they are skipped otherwise.
- Changing detection: add a real fixture (a real vulnerable and a real fixed
  build) and a test for it. Check that breaking the logic makes tests fail.
- The probe must stay POSIX `sh` and BusyBox-compatible: binaries contain NUL
  bytes and BusyBox `grep` stops at them, so strings are extracted with
  `tr -c ' -~' '\n'` first. In image and `--rootfs` mode nothing from the
  scanned filesystem may be executed.
- Lint: `shellcheck -S warning -x brotli-k8s-scan.sh tests/*.sh tests/fake-*/*`.

## README images

All images are generated from real data and can be rebuilt at any time:

```bash
tests/build-fixtures.sh            # if not done yet
docs/images/src/build-images.sh    # about 20 s; writes docs/images/*.png
```

- `fingerprint.png` reads the decoder error tables from Ubuntu's real
  `libbrotlidec.so.1.1.0` before and after the backport.
- `scan-cluster.png` and `same-version.png` are the **current** scanner's real
  coloured output against a demo cluster made of real fixture binaries
  (`docs/images/src/demo-pods.json`). Re-run after any change to the
  scanner's console output.
- Layout, text and colours: `docs/images/src/make_html.py`. Fonts are pinned
  npm packages (JetBrains Mono, Inter), rendered with Playwright/Chromium
  without network. Needs node + Playwright, python3 + Pillow.
- `social-preview.png` is not used by the README: upload it by hand in
  GitHub → Settings → General → Social preview.

## Keeping the facts current

Fixed versions appear in several places; change them together and cite the
vendor advisory in the commit message:

- `brotli-k8s-scan.sh`: `rt_state()` and `fixhint()` in the evaluator, the
  Python rules, the SARIF help text
- `README.md` (What it checks), `docs/how-detection-works.md`, `CHANGELOG.md`
- `yara/brotli_cve_2026_111497.yar` only if the fingerprint itself changes

## Releasing

1. Bump `VERSION` in `brotli-k8s-scan.sh` and add a `CHANGELOG.md` entry.
2. Open a pull request. `main` is protected: changes land only through pull
   requests with passing `lint`, `test (ubuntu-24.04)` and
   `test (ubuntu-24.04-arm)` checks.
3. After merging, publish a GitHub release with the tag `vX.Y.Z` (Releases →
   Draft a new release). `release.yml` runs all tests, checks that the script
   version matches the tag, and attaches `brotli-k8s-scan.sh`, the YARA rules,
   `SHA256SUMS` and a signed build provenance attestation.

## Reporting security problems

See [SECURITY.md](SECURITY.md); please do not open public issues for them.
