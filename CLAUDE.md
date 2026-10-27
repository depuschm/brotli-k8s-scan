# Notes for Claude

Read `CONTRIBUTING.md` first: layout, tests, README images, releases.

Working rules for this repository:

- **Tests run offline.** `tests/build-fixtures.sh` is the only step that may
  download; `tests/run-tests.sh` isolates itself with `unshare -rn`. Never use
  external services to test. Run the full suite (with BusyBox if available)
  before proposing a change, and check new tests fail when the logic is broken.
- **`main` is protected** (pull request + `lint`, `test (ubuntu-24.04)`,
  `test (ubuntu-24.04-arm)`). Push to a branch and give the owner the
  pull-request link; do not try to push to `main`. Tag pushes and branch
  deletions are blocked from Claude sessions: the owner publishes releases
  (tag `vX.Y.Z`, must match `VERSION` in the script) and deletes branches.
- **Commit identity:** `depuschm <depuschm@users.noreply.github.com>`; never
  put a personal email address in a commit.
- **Changed the scanner's console output?** Rebuild the README screenshots:
  `docs/images/src/build-images.sh` (needs the test fixtures), look at every
  image before committing.
- **Facts change.** Fixed versions (Node.js, Bun, Python, .NET, Envoy, Istio)
  live in several files (see "Keeping the facts current" in
  `CONTRIBUTING.md`). Verify against vendor advisories before changing them.
- **Claims must match evidence.** The fingerprint shows a fixed or vulnerable
  decoder only when the error table is present; stripped builds are
  `REVIEW`. Do not overstate this in README, docs or images.
- Do not commit `tests/.cache/` or `docs/images/src/.cache/`.
