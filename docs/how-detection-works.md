# Version numbers lie: detecting the Brotli CVE-2026-111497 fix in any binary

CVE-2026-111497 ("Broccoli2Shell", "Node2Shell", "HTTP2Shell") is an
out-of-bounds write in the Google Brotli decoder 1.0.3 - 1.2.0. Brotli is
copied into a lot of software: Node.js, Bun, Envoy, the Python `Brotli` and
`brotlicffi` wheels, Pillow, .NET, curl, nginx modules, browsers. Every copy
has to be found and updated.

The usual way to check is to compare version numbers. For this CVE that is
unreliable in both directions:

| Binary | What its version says | Actually |
|---|---|---|
| Node.js 22.23.4 | bundles "Brotli 1.1.0" (same as vulnerable 22.23.3) | **fixed** (fix cherry-picked) |
| Ubuntu `libbrotli1 1.1.0-2ubuntu0.1` | "1.1.0" (affected range is 1.0.3 - 1.2.0) | **fixed** (backported patch) |
| A vendor app with a private copy | often no version at all | ? |

A version-based scanner reports the fixed Ubuntu library as vulnerable, and
cannot say anything about private copies.

## The fingerprint

The upstream fix (google/brotli commit `0ed4268`, "Detect and report invalid
stream earlier") does not only change code. It adds a new error code:

```c
BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17) SEPARATOR
```

The decoder's `BrotliDecoderErrorString()` turns every error code into its
name, so the **name of every error code ends up as a plain string in the
binary**. Before the fix the table has no `BLOCK_SWITCH` entry, after the fix it
has one. Any backport that cherry-picks the fix adds it too.

```
error table present, "_ERROR_FORMAT_BLOCK_SWITCH" absent   ->  vulnerable decoder
error table present, "_ERROR_FORMAT_BLOCK_SWITCH" present  ->  fixed decoder
```

Brotli 1.0.x stores bare names (`EXUBERANT_NIBBLE`, `BLOCK_SWITCH`) instead of
prefixed ones; the same logic applies. Because these are plain strings, the
check works the same on x86-64, arm64, or any other architecture, and needs
no disassembler.

You can try it with nothing but grep (GNU grep):

```bash
f=$(readlink -f "$(command -v node)")
LC_ALL=C grep -c _ERROR_FORMAT_EXUBERANT_NIBBLE "$f"   # >0: binary has a Brotli 1.1+/1.2 error table
LC_ALL=C grep -c _ERROR_FORMAT_BLOCK_SWITCH "$f"       # 0: vulnerable, >0: fixed
```

(BusyBox grep cannot see strings after a NUL byte; pipe through
`tr -c ' -~' '\n'` first. `brotli-k8s-scan.sh` does this.)

## Verified against real builds

| File | Version string | Result |
|---|---|---|
| libbrotlidec built from Brotli 1.0.9 / 1.0.10 | 1.0.9 / 1.0.10 | vulnerable / fixed |
| libbrotlidec built from Brotli 1.2.0 / 1.2.1 | 1.2.0 / 1.2.1 | vulnerable / fixed |
| Ubuntu `libbrotli1 1.1.0-2build2` / `1.1.0-2ubuntu0.1` | 1.1.0 / 1.1.0 | vulnerable / **fixed** |
| Node.js 22.23.3 / 22.23.4 (official binaries) | Brotli 1.1.0 / 1.1.0 | vulnerable / **fixed** |
| Python `Brotli` 1.2.0 / 1.2.1 wheels | 1.2.0 / 1.2.1 | vulnerable / fixed |
| Python `brotlicffi` 1.2.0.1 / 1.2.1.0 wheels | 1.2.0.1 / 1.2.1.0 | vulnerable / fixed |
| Bun 1.4.4 (official binary) | 1.4.4 | fixed |
| Pillow wheel's bundled `libbrotlidec` | 1.2.0 | vulnerable |

## Limits

- A stripped, statically linked program can lose the error table if it never
  calls `BrotliDecoderErrorString()` and the linker removes unused code. The
  Brotli static dictionary (`timedownlifeleftback...`) is still there, so the
  copy is found, but its patch state is unknown.
- Pure Go, Rust or Java reimplementations of Brotli do not contain this C code.
- Copies inside compressed archives (e.g. jars) must be unpacked first.

## Use it

- [`brotli-k8s-scan.sh`](../brotli-k8s-scan.sh): Kubernetes clusters, container
  images and Linux filesystems.
- [`yara/brotli_cve_2026_111497.yar`](../yara/brotli_cve_2026_111497.yar): the
  same logic as YARA rules, for any YARA-capable tool (EDR, Velociraptor,
  BigFix with YARA-X, ...) or simply `yara -r brotli_cve_2026_111497.yar /`.
