# Contributing and maintenance

## How to contribute

- **Bugs, wrong verdicts, ideas:** open an issue at
  <https://github.com/depuschm/brotli-k8s-scan/issues>. Please include the
  scanner version (`./brotli-k8s-scan.sh --version`), the command, what it
  reported and what you expected (for a binary: its package name and version).
- **Security problems**, including a vulnerable decoder reported as
  `PATCHED`: report them privately, see [SECURITY.md](SECURITY.md), not in a
  public issue.
- **Changes:** fork the repository and open a pull request against `main`.
  Discussion happens in the pull request. A change is merged when:
  - all CI checks pass (lint, tests on x86-64 and arm64, end-to-end on a
    kind cluster, container image on both architectures, fuzzing);
  - new or changed behaviour comes with a test, and the test fails without
    the change (see [Tests](#tests));
  - ShellCheck reports nothing, and the probe stays POSIX `sh` and
    BusyBox-compatible;
  - changed console output comes with rebuilt README images
    ([README images](#readme-images));
  - claims in the README and docs match what the scanner can show.
- Contributions are accepted under the project's [MIT licence](LICENSE).

## Layout

| Path | What |
|---|---|
| `brotli-k8s-scan.sh` | the scanner: one bash script; the POSIX `sh` probe that runs in containers is the `PROBE` heredoc (`--print-probe` shows it) |
| `yara/` | the same fingerprint as YARA rules |
| `tests/` | fixture builder, offline test suite, fake `kubectl` / `crane` / `docker` |
| `docs/how-detection-works.md` | the write-up behind the fingerprint |
| `docs/images/` | README images; `docs/images/src/` regenerates them |
| `rbac/` | RBAC examples |
| `image/` | the container image: `build.sh` (pinned downloads, no base image), `Dockerfile`, `test.sh` |
| `deploy/job.yaml` | the scanner as a Kubernetes Job (namespace, service account, RBAC, Job) |
| `.github/workflows/` | `test.yml` (every change), `image.yml` (image build and test on every change, publishing on a release), `release.yml` (on a published release) |

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
- Lint: `shellcheck -x brotli-k8s-scan.sh tests/*.sh tests/fuzz/*.sh image/*.sh tests/fake-*/*`
  at every severity (CI fails on any finding). Intended exceptions are
  annotated in the code with `# shellcheck disable=SCxxxx  # reason`. CI
  uses Ubuntu 24.04's ShellCheck 0.9.0, which names some checks differently
  from newer versions; a clean run with both is safest. The probe is
  checked on its own as POSIX sh:
  `./brotli-k8s-scan.sh --print-probe > /tmp/probe.sh && shellcheck -s sh /tmp/probe.sh`.
- Fuzz tests (x86-64; atheris has no arm64 wheels): `tests/run-tests.sh` runs
  200 inputs per target with a fixed seed; `tests/fuzz/run-fuzz.sh [seconds]`
  runs longer (CI job `fuzz`). A failure prints the input as `Base64: ...`;
  replay it with `python3 -I tests/fuzz/fuzz_scanner.py tests/.cache/pylib <target> <file>`.
  The `evaluator` target compares the scanner with a model of the verdict
  rules in the harness, so a rule change needs the same change there.
- Everything the probe reads from an image is hostile input: no `echo` of
  file names or versions (some shells turn `\n` into a newline), skip names
  with control characters, and read no file through a symlink that leaves
  the scanned root (see SECURITY.md, "Hostile images").
- End-to-end: `tests/e2e-kind.sh` runs against a real kind cluster (CI job
  `e2e (kind)`). Needs docker, kind, kubectl, crane and a static busybox.
  Without kind (e.g. no access to kind's node image), `E2E_PHASES=images`
  still checks the test images, a local registry and real `docker`/`crane`
  image scans. In CI it also runs the container image as a Job
  (`E2E_PHASES="images cluster scan job"`, `E2E_SCANNER_IMAGE`).
- Container image: `image/build.sh TAG` (Ubuntu with docker; builds for the
  machine's own architecture) and `image/test.sh TAG` (offline; needs the
  fixtures). CI job `image (amd64)` / `image (arm64)`.

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
- `tests/fuzz/fuzz_scanner.py`: `FIXED`, `ENVOY_FIXED`, `BUN_FIXED`, `PY_FIXED`
  (the fuzz test fails until both agree)
- `README.md` (What it checks), `docs/how-detection-works.md`, `CHANGELOG.md`
- `yara/brotli_cve_2026_111497.yar` only if the fingerprint itself changes

## Upkeep (automatic)

- **Dependabot** opens one grouped pull request a week when a pinned GitHub
  Action has a new release; the tests run on it like on any change.
- **Weekly test run** (Mondays) builds every fixture *without* the cache, so a
  dead download link (Ubuntu removes superseded packages) shows up as a
  failed run and an email, not during a release.
- **OpenSSF Scorecard** rates the repository's security practices; results in
  the Security tab and on the README badge.
- **CodeQL** analyses the workflows, Python and JavaScript on every change
  (the bash scanner is covered by ShellCheck).
- Test helpers are installed from `tests/requirements.txt` with
  `--require-hashes`; Dependabot updates it monthly (versions and hashes), or
  regenerate it by hand with the command in its header.
- **By hand:** the versions and hashes of jq, crane and kubectl in
  `image/build.sh` (Dependabot cannot see them; the header says where each
  hash comes from). bash and BusyBox in the image are Ubuntu's current
  packages at build time, so a release picks up their security updates.

## Releasing

1. Bump `VERSION` in `brotli-k8s-scan.sh`, the image tag in
   `deploy/job.yaml` and the version in the README's container examples, and
   add a `CHANGELOG.md` entry.
2. Open a pull request. `main` is protected: changes land only through pull
   requests with passing `lint`, `test (ubuntu-24.04)` and
   `test (ubuntu-24.04-arm)` checks.
3. After merging, publish a GitHub release with the tag `vX.Y.Z` (Releases →
   Draft a new release). `release.yml` runs all tests, checks that the script
   version and `deploy/job.yaml` match the tag, and attaches
   `brotli-k8s-scan.sh`, the YARA rules, `SHA256SUMS` and a signed build
   provenance attestation. It also publishes the container image
   (`ghcr.io/depuschm/brotli-k8s-scan:X.Y.Z` and `latest`) with its own
   attestation. The first time, check in GitHub → Packages that the package
   is public.

## Reporting security problems

See [SECURITY.md](SECURITY.md); please do not open public issues for them.
