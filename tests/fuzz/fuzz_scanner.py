#!/usr/bin/env python3
"""Fuzz tests for brotli-k8s-scan.sh, driven by atheris (libFuzzer).

Targets
  evaluator  random probe output -> `brotli-k8s-scan.sh --evaluate-stdin`.
             Checked against a reference model of the verdict rules below,
             and for well-formed, escape-free output whatever the input.
  probe      a random file tree (hostile names, symlinks out of the tree,
             files with and without the Brotli fix markers) around one
             vulnerable node binary -> the probe, then the evaluator.
             Checked: the vulnerable binary is always found, every record
             points to a file inside the tree, no candidate file is missed,
             and names with control characters are counted, not parsed.

The scanner is a shell script, so coverage feedback comes from this harness
only: the fuzzer explores the structure of the inputs, the checks below are
the oracle.

Usage (tests/run-tests.sh runs a short session of both targets offline):
  python3 -I tests/fuzz/fuzz_scanner.py PYLIB TARGET [libFuzzer flags] [crash file]
  e.g. ... tests/.cache/pylib probe -runs=300
       ... tests/.cache/pylib evaluator -max_total_time=120
Environment: BROTLI_FUZZ_SHELLS  shells for the probe target, from
             "sh dash bash busybox" (default: "sh")
"""
import fnmatch
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

if len(sys.argv) < 3 or sys.argv[2] not in ("evaluator", "probe"):
    sys.exit(__doc__)
sys.path.insert(0, sys.argv[1])
import atheris  # noqa: E402

TARGET = sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(os.path.dirname(os.path.dirname(HERE)), "brotli-k8s-scan.sh")

# Fixed releases (keep in step with rt_state() in the scanner; see "Keeping
# the facts current" in CONTRIBUTING.md). Lines not listed: below -> end of
# life (no fix will ship), above -> fixed from the start.
FIXED = {
    b"node": ({22: "22.23.4", 24: "24.22.1", 26: "26.12.1"}, 27),
    b"dotnet": ({8: "8.0.33", 9: "9.0.22", 10: "10.0.14"}, 11),
}
ENVOY_FIXED = {"1.36": "1.36.12", "1.37": "1.37.8", "1.38": "1.38.6", "1.39": "1.39.3"}
ENVOY_FIRST_FIXED = "1.40.0"
BUN_FIXED = "1.4.4"
PY_FIXED = {b"brotli": "1.2.1", b"brotlicffi": "1.2.1.0"}

STATES = (b"PATCHED", b"PATCHED_10X", b"VULNERABLE", b"VULNERABLE_10X", b"UNKNOWN")
CTRL = re.compile(rb"[\x00-\x1f\x7f]|\xc2[\x80-\x9f]")


class Inexact(Exception):
    """A value whose awk number conversion the model does not mirror ("1e3")."""


def guard(fn, *args):
    """fn(*args), or "?" (any state) when a value is not modelled exactly."""
    try:
        return fn(*args)
    except Inexact:
        return "?"


# --- reference model of the evaluator ----------------------------------------
CLEAN_VERSION = re.compile(rb"v?[0-9]{0,6}(?:\.[0-9]{0,6}){0,5}")


def _ver(v):
    if not CLEAN_VERSION.fullmatch(v):
        raise Inexact(v)
    return v[1:] if v.startswith(b"v") else v


def vcmp(a, b):
    ax = [int(x or 0) for x in re.split(rb"[^0-9]+", _ver(a))]
    bx = [int(x or 0) for x in re.split(rb"[^0-9]+", _ver(b.encode()))]
    n = max(len(ax), len(bx))
    ax += [0] * (n - len(ax))
    bx += [0] * (n - len(bx))
    return (ax > bx) - (ax < bx)


def line(v, n):
    p = _ver(v).split(b".") + [b"", b""]
    return int(p[0] or 0) if n == 1 else "%d.%d" % (int(p[0] or 0), int(p[1] or 0))


def rt_state(kind, v):
    if v == b"":
        return ""
    if kind in FIXED:
        table, first = FIXED[kind]
        maj = line(v, 1)
        if maj in table:
            return "VULN" if vcmp(v, table[maj]) < 0 else "OK"
        return "OK" if maj >= first else "EOL"
    if kind == b"bun":
        return "VULN" if vcmp(v, BUN_FIXED) < 0 else "OK"
    if kind == b"envoy":
        mm = line(v, 2)
        if mm in ENVOY_FIXED:
            return "VULN" if vcmp(v, ENVOY_FIXED[mm]) < 0 else "OK"
        return "OK" if vcmp(v, ENVOY_FIRST_FIXED) >= 0 else "EOL"
    return ""


def rank(s):
    return 3 if s.startswith(b"VULNERABLE") else (1 if s.startswith(b"PATCHED") else 2)


def model(stream):
    """Expected findings, as (state, kind) pairs, for a probe output stream."""
    found, began, ended = [], False, False
    runtimes, bins, order, dver, dotrt = [], {}, [], {}, []
    for raw in stream.split(b"\n"):
        f = [CTRL.sub(b"", x) for x in raw.split(b"\t")]
        f += [b""] * (6 - len(f))
        t = f[0]
        if t == b"BEGIN":
            began = True
        elif t == b"END":
            ended = True
        elif t == b"EXECFAIL":
            found.append(("REVIEW", "exec"))
        elif t == b"PULLFAIL":
            found.append(("REVIEW", "image"))
        elif t in (b"NODE", b"BUN", b"ENVOY"):
            runtimes.append((t.lower(), f[1], f[2]))
        elif t == b"BIN":
            if f[2] not in bins:
                order.append(f[2])
            elif rank(bins[f[2]]) >= rank(f[1]):
                continue
            bins[f[2]] = f[1]
        elif t == b"ODDNAMES":
            found.append(("REVIEW", "names"))
        elif t == b"DOTNETRT":
            d = re.sub(rb"/[^/]*$", b"", f[2])
            dver[d] = f[1]
            dotrt.append(f[3])
        elif t == b"PY":
            n = f[1].lower()
            if n in PY_FIXED:
                c = guard(vcmp, f[2], PY_FIXED[n])
                found.append(("?" if c == "?" else "VULN" if c < 0 else "OK", "python"))
            elif n == b"brotlipy":
                found.append(("REVIEW", "python"))
        elif t == b"JAR":
            found.append(("REVIEW", "java"))
        elif t in (b"OSPKG", b"DOTNET", b"CURL"):
            found.append(("INFO", t.lower().decode()))
    if not began and not found:
        found.append(("REVIEW", "exec"))
    elif began and not ended:
        found.append(("REVIEW", "exec"))
    used = set()
    for kind, v, p in runtimes:
        s, b = guard(rt_state, kind, v), bins.get(p, b"")
        if b in (b"PATCHED", b"PATCHED_10X"):
            st = "OK"
        elif b.startswith(b"VULNERABLE"):
            st = "VULN"
        elif s == "?":
            st = "?"
        elif s in ("VULN", "EOL"):
            st = "REVIEW" if b == b"" else "VULN"
        else:
            st = "OK" if s == "OK" else "REVIEW"
        found.append((st, kind.decode()))
        if p in bins:
            used.add(p)
    for p in order:
        if p in used:
            continue
        s = bins[p]
        m = re.search(rb"Microsoft\.NETCore\.App/[0-9]+\.[0-9]+\.[0-9]+", p)
        dv = m.group(0)[22:] if m else b""
        pd = re.sub(rb"/[^/]*$", b"", p)
        if dv == b"" and pd in dver and re.search(rb"libSystem\.IO\.Compression\.Native\.so$", p):
            dv = dver[pd]
        if s in (b"PATCHED", b"PATCHED_10X"):
            found.append(("OK", "binary"))
        elif s in (b"VULNERABLE", b"VULNERABLE_10X"):
            found.append(("VULN", "binary"))
        elif dv != b"":
            s = guard(rt_state, b"dotnet", dv)
            found.append(("?" if s == "?" else "OK" if s == "OK" else "VULN", "dotnet"))
        elif re.search(rb"(^|/)envoy$", p):
            found.append(("REVIEW", "envoy"))
        else:
            found.append(("REVIEW", "binary"))
    found += [("INFO", "dotnet") for ls in dotrt if ls in (b"linked", b"absent")]
    return found


def verdict_of(states):
    states = set(states)
    for st, v in (("VULN", "VULNERABLE"), ("REVIEW", "REVIEW"), ("OK", "PATCHED")):
        if st in states:
            return v
    return "NO_BROTLI_FOUND"


def evaluate(stream):
    r = subprocess.run(["bash", SCAN, "--evaluate-stdin"], input=stream,
                       capture_output=True, timeout=60, check=False)
    assert r.returncode == 0, "evaluator exit %d: %r" % (r.returncode, r.stderr[-300:])
    out = r.stdout
    assert out.endswith(b"\n"), "output does not end with a newline"
    assert not CTRL.search(out.replace(b"\t", b"").replace(b"\n", b"")), \
        "control characters reach the output: %r" % out[:400]
    lines = out[:-1].split(b"\n")
    assert lines[-1].startswith(b"V\t"), "last line is not the verdict"
    verdict = lines[-1][2:].decode()
    assert verdict in ("VULNERABLE", "REVIEW", "PATCHED", "NO_BROTLI_FOUND"), verdict
    findings = []
    for i, ln in enumerate(lines[:-1]):
        if ln.startswith(b"O\t") and i == 0:
            continue
        f = ln.split(b"\t")
        assert f[0] == b"F" and len(f) == 6, "malformed line %r" % ln
        assert f[1] in (b"VULN", b"REVIEW", b"OK", b"INFO"), "bad state %r" % ln
        findings.append((f[1].decode(), f[2].decode()))
    assert verdict == verdict_of(st for st, _ in findings), "verdict does not follow the findings"
    return findings, verdict


# --- evaluator target -----------------------------------------------------------
PATHS = (b"/usr/local/bin/node", b"/usr/bin/envoy", b"/usr/local/bin/bun", b"/x",
         b"/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so",
         b"/usr/share/dotnet/shared/Microsoft.NETCore.App/10.0.14/libSystem.IO.Compression.Native.so",
         b"/app/libSystem.IO.Compression.Native.so", b"/app/app.deps.json", b"")
MAJORS = (0, 1, 7, 8, 9, 10, 11, 20, 22, 23, 24, 25, 26, 27, 99)
TYPES = (b"BEGIN", b"END", b"OS", b"NODE", b"BUN", b"ENVOY", b"BIN", b"PY", b"DOTNETRT",
         b"JAR", b"OSPKG", b"DOTNET", b"CURL", b"EXECFAIL", b"PULLFAIL", b"ODDNAMES")


def pick(fdp, seq):
    return seq[fdp.ConsumeIntInRange(0, len(seq) - 1)]


def _near(v):
    """v and its neighbours: each component one lower and one higher."""
    p = [int(x) for x in v.split(".")]
    out = {v}
    for i in range(len(p)):
        for d in (-1, 1):
            q = list(p)
            q[i] = max(0, q[i] + d)
            out.add(".".join(map(str, q)))
    return out


def _bounds(versions):
    return sorted(set().union(*(_near(v) for v in versions)))


# versions at and next to each fix, per record type, including the first
# release of the first line that was fixed from the start
BOUNDARIES = {
    b"NODE": _bounds(list(FIXED[b"node"][0].values()) + ["%d.0.0" % FIXED[b"node"][1]]),
    b"DOTNETRT": _bounds(list(FIXED[b"dotnet"][0].values()) + ["%d.0.0" % FIXED[b"dotnet"][1]]),
    b"ENVOY": _bounds(list(ENVOY_FIXED.values()) + [ENVOY_FIRST_FIXED]),
    b"BUN": _bounds([BUN_FIXED]),
    b"PY": _bounds(list(PY_FIXED.values())),
}


def gen_version(fdp, t):
    k = fdp.ConsumeIntInRange(0, 9)
    if k == 0:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 12))
    if k <= 5:                                                      # at a fix boundary
        v = pick(fdp, BOUNDARIES[t]).encode()
        return (b"v" + v) if fdp.ConsumeBool() else v
    parts = [pick(fdp, MAJORS)] + [fdp.ConsumeIntInRange(0, 40) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    v = ".".join(str(x) for x in parts).encode()
    return (b"v" + v) if fdp.ConsumeBool() else v


def gen_field(fdp, t, i):
    k = fdp.ConsumeIntInRange(0, 7)
    if k == 0:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 16))      # anything
    if k == 1:
        return pick(fdp, PATHS) + bytes([fdp.ConsumeIntInRange(0, 255)])
    if t == b"BIN" and i == 1:
        return pick(fdp, STATES)
    if t in (b"NODE", b"BUN", b"ENVOY", b"DOTNETRT") and i == 1 or t == b"PY" and i == 2:
        return gen_version(fdp, t)
    if t == b"PY" and i == 1:
        return pick(fdp, (b"Brotli", b"brotli", b"brotlicffi", b"BrotliCFFI", b"brotlipy", b"other"))
    if t == b"DOTNETRT" and i == 3:
        return pick(fdp, (b"bundled", b"linked", b"absent"))
    return pick(fdp, PATHS)


@atheris.instrument_func
def gen_stream(fdp):
    recs, must_vuln = [], False
    if fdp.ConsumeIntInRange(0, 9):
        recs.append(b"BEGIN")
    for _ in range(fdp.ConsumeIntInRange(0, 20)):
        t = pick(fdp, TYPES)
        nf = {b"BIN": 3, b"NODE": 3, b"BUN": 3, b"ENVOY": 3, b"PY": 4, b"DOTNETRT": 4}.get(t, 2)
        nf = max(1, nf + fdp.ConsumeIntInRange(-1, 1)) if fdp.ConsumeIntInRange(0, 7) == 0 else nf
        fields = [t] + [gen_field(fdp, t, i) for i in range(1, nf)]
        if fdp.ConsumeIntInRange(0, 15) == 0:                       # a control character in the type
            j = fdp.ConsumeIntInRange(0, len(t))
            fields[0] = t[:j] + pick(fdp, (b"\x1b", b"\r", b"\x00", b"\xc2\x9b")) + t[j:]
        rec = b"\t".join(fields)
        recs.append(rec)
        if b"\n" in rec:                                             # splits into several lines
            continue
        # a cleanly vulnerable record must make the image VULNERABLE, whatever else is there
        clean = [CTRL.sub(b"", x) for x in fields]
        if clean[0] == b"BIN" and len(clean) >= 3 and clean[1].startswith(b"VULNERABLE") and clean[1] in STATES:
            must_vuln = True
        if clean[0] == b"PY" and len(clean) >= 3 and clean[1].lower() in PY_FIXED:
            try:
                must_vuln |= vcmp(clean[2], PY_FIXED[clean[1].lower()]) < 0
            except Inexact:
                pass
    if fdp.ConsumeIntInRange(0, 9):
        recs.append(b"END")
    sep = b"\r\n" if fdp.ConsumeIntInRange(0, 15) == 0 else b"\n"
    return sep.join(recs) + sep, must_vuln


def fuzz_evaluator(data):
    fdp = atheris.FuzzedDataProvider(data)
    stream, must_vuln = gen_stream(fdp)
    findings, verdict = evaluate(stream)
    if must_vuln:
        assert verdict == "VULNERABLE", "a vulnerable record was hidden: %r" % stream
    want = model(stream)                     # "?" where a value is not modelled exactly
    same = len(findings) == len(want) and all(
        k == wk and (st == ws or ws == "?") for (st, k), (ws, wk) in zip(findings, want))
    assert same, "findings differ from the model\n in:   %r\n got:  %r\n want: %r" % (stream, findings, want)


# --- probe target ---------------------------------------------------------------
DICT, PATCH, VULN = b"timedownlifeleftback", b"_ERROR_FORMAT_BLOCK_SWITCH", b"_ERROR_FORMAT_EXUBERANT_NIBBLE"
CONTENTS = (
    b"\x7fELF\0" + DICT + b"\0" + VULN + b"\0",                        # 1.1/1.2 without the fix
    b"\x7fELF\0" + DICT + b"\0" + VULN + b"\0" + PATCH + b"\0",          # with the fix
    b"\0" + DICT + b"\0EXUBERANT_NIBBLE\0",                            # 1.0.x without the fix
    b"\0" + DICT + b"\0EXUBERANT_NIBBLE\0BLOCK_SWITCH\0",              # 1.0.x with the fix
    b"\0" + DICT + b"\0",                                              # stripped
    b"\0BrotliDecoderDecompress\0",                                    # only imports libbrotli
    b"plain text\n",
    b'PRETTY_NAME="tree-os"\nPackage: libbrotli1\nVersion: 1.1.0\n\n',  # os-release / dpkg status
)
NAMES = (b"node", b"nodejs", b"bun", b"envoy", b"nginx", b"curl", b"dotnet", b"libnode.so.127",
         b"libbrotlidec.so.1", b"libbrotlienc.so.1", b"libbrotlicommon.so.1", b"_brotli.abi3.so",
         b"x.node", b"libSystem.IO.Compression.Native.so", b"libcurl.so.4", b"ngx_http_brotli_filter_module.so",
         b"os-release", b"status", b"installed", b"Brotli-1.1.0.dist-info", b"brotlicffi-1.2.0.0.dist-info",
         b"app.deps.json", b"brotli4j-1.16.0.jar", b"proc", b"sys", b"dev", b"etc", b"usr", b"lib")
WEIRD = (b"\t", b"\n", b"\r", b"\x1b[2J", b"\x7f", b"\\n", b"\\t", b"\\c", b"\\", b" ", b"-", b"*", b"?",
         b"[", b"]", b"'", b'"', b"$(x)", b"`x`", b";", b"\xc3\xa9", b"\xff", b"\x81", b"\x88", b"..", b".")
PY_DIRS = (b"brotli-*.dist-info", b"brotli-*.egg-info", b"brotlicffi-*.dist-info", b"brotlicffi-*.egg-info",
           b"brotlipy-*.dist-info", b"brotlipy-*.egg-info")
CANDIDATES = (b"node", b"nodejs", b"bun", b"envoy", b"nginx", b"curl", b"dotnet", b"libnode.so*",
              b"libbrotli*", b"_brotli*.so", b"*brotli*.so*", b"libSystem.IO.Compression.Native.so",
              b"libcurl.so*", b"*.node", b"ngx_http_brotli*")
HOSTMARK = b"HOSTFILE-a9c4e2"                                   # in files outside the tree
SHELLS = os.environ.get("BROTLI_FUZZ_SHELLS", "sh").split()
WORK = tempfile.mkdtemp(prefix="brotli-fuzz.")
PROBE = os.path.join(WORK, "probe.sh")
with open(PROBE, "wb") as fh:
    fh.write(subprocess.run(["bash", SCAN, "--print-probe"], capture_output=True, check=True).stdout)
BBDIR = None
if "busybox" in SHELLS:
    BBDIR = os.path.join(WORK, "bb")
    os.mkdir(BBDIR)
    subprocess.run(["busybox", "--install", "-s", BBDIR], check=False)


def gen_name(fdp):
    n = pick(fdp, NAMES) if fdp.ConsumeBool() else b""
    for _ in range(fdp.ConsumeIntInRange(0, 2)):
        j = fdp.ConsumeIntInRange(0, len(n))
        n = n[:j] + pick(fdp, WEIRD) + n[j:]
    if fdp.ConsumeIntInRange(0, 5) == 0:
        n += fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 6))
    n = n.replace(b"/", b"").replace(b"\0", b"")
    return n if n not in (b"", b".", b"..") else b"f"


def protected(path, keep):
    try:
        return os.path.samefile(path, keep)
    except OSError:
        return False


@atheris.instrument_func
def gen_tree(fdp, root, outside):
    """Random tree under root; returns nothing, the oracle reads the tree back."""
    keep = os.path.join(root, b"usr/local/bin/node")
    dirs = [root, os.path.join(root, b"usr/local/bin"), os.path.join(root, b"etc")]
    for _ in range(fdp.ConsumeIntInRange(0, 24)):
        parent = pick(fdp, dirs)
        path = os.path.join(parent, gen_name(fdp))
        if os.path.lexists(path) or protected(path, keep):
            continue
        op = fdp.ConsumeIntInRange(0, 5)
        try:
            if op == 0:
                os.mkdir(path)
                dirs.append(path)
            elif op in (1, 2):
                with open(path, "wb") as fh:
                    fh.write(pick(fdp, CONTENTS))
            elif op == 3:                                            # a symlink, often out of the tree
                os.symlink(pick(fdp, (outside, os.path.join(outside, b"decoy.node"), b"/", b"/etc",
                                                b"../../../..", keep, b"node", b"x.node")), path)
            elif op == 4:                                            # a fixed-path file: symlink or file
                fixed = (b"etc/os-release", b"usr/lib/os-release", b"var/lib/dpkg/status", b"lib/apk/db/installed")
                tgt = os.path.join(root, pick(fdp, fixed))
                if not os.path.lexists(tgt):
                    os.makedirs(os.path.dirname(tgt), exist_ok=True)
                    k = fdp.ConsumeIntInRange(0, 3)
                    if k == 0:
                        with open(tgt, "wb") as fh:
                            fh.write(CONTENTS[-1])
                    else:                       # out of the tree, absolute in the image, or a loop
                        os.symlink(pick(fdp, (os.path.join(outside, b"os-release"), b"/" + pick(fdp, fixed),
                                              b"../" * fdp.ConsumeIntInRange(1, 9) + pick(fdp, fixed))), tgt)
            else:                                                    # a .NET app next to a hostile native lib
                os.mkdir(path)
                dirs.append(path)
                with open(os.path.join(path, b"app.deps.json"), "wb") as fh:
                    fh.write(b'{"Microsoft.NETCore.App.Runtime.linux-x64/8.0.32": {}}')
                os.symlink(os.path.join(outside, b"decoy.node"),
                           os.path.join(path, b"libSystem.IO.Compression.Native.so"))
        except OSError:
            pass


def has_ctrl(b):
    return bool(re.search(rb"[\x00-\x1f\x7f]", b))


def py_record(rel):
    """The PY record the probe prints for a dist-info/egg-info directory."""
    b = os.path.basename(rel)
    for suffix in (b".dist-info", b".egg-info"):
        if b.endswith(suffix):
            b = b[:-len(suffix)]
    n = b.split(b"-", 1)[0]
    v = b.split(b"-", 1)[1] if b"-" in b else b
    if b"-py" in v:
        v = v[:v.index(b"-py")]
    return (n, v, rel)


def expected_tree(root):
    """What the probe should report: candidate files with their state, Python
    package directories, odd names."""
    bins, pys, odd = {}, set(), 0
    for d, dns, fns in os.walk(root):
        rel_d = d[len(root):]
        if d != root and has_ctrl(os.path.basename(d)):
            odd += 1
        if d != root and not has_ctrl(rel_d) and \
                any(fnmatch.fnmatchcase(os.path.basename(d).lower(), pat) for pat in PY_DIRS):
            pys.add(py_record(rel_d))
        if d == root:
            dns[:] = [x for x in dns if x not in (b"proc", b"sys", b"dev")]
        for fn in fns:
            p = os.path.join(d, fn)
            st = os.lstat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            if has_ctrl(fn):
                odd += 1
            rel = rel_d + b"/" + fn
            if has_ctrl(rel) or not any(fnmatch.fnmatchcase(fn, pat) for pat in CANDIDATES):
                continue
            s = classify(p)
            if s:
                bins[rel] = s
    return bins, pys, odd


def classify(p):
    base = os.path.basename(p)
    if base.startswith((b"libbrotlicommon", b"libbrotlienc")):
        return None
    with open(p, "rb") as fh:
        m = [r for r in re.split(rb"[^ -~]", fh.read())
             if any(k in r for k in (DICT, b"BrotliDecoder", b"EXUBERANT_NIBBLE", b"BLOCK_SWITCH"))]
    if not m:
        return None
    if any(PATCH in r for r in m):
        return b"PATCHED"
    if any(VULN in r for r in m):
        return b"VULNERABLE"
    if b"EXUBERANT_NIBBLE" in m:
        return b"PATCHED_10X" if b"BLOCK_SWITCH" in m else b"VULNERABLE_10X"
    return b"UNKNOWN" if any(DICT in r for r in m) else None


def run_probe(sh, root, cwd):
    env = dict(os.environ, LC_ALL="C")
    cmd = [sh, PROBE, root, b"0", b"0"]
    if sh == "busybox":
        env["PATH"] = BBDIR + os.pathsep + env.get("PATH", "")
        cmd = ["busybox", "sh", PROBE, root, b"0", b"0"]
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, timeout=120, check=False)
    assert r.returncode == 0, "probe (%s) exit %d: %r" % (sh, r.returncode, r.stderr[-300:])
    return r.stdout


def fuzz_probe(data):
    fdp = atheris.FuzzedDataProvider(data)
    sh = pick(fdp, SHELLS)
    case = tempfile.mkdtemp(dir=WORK).encode()
    try:
        root = os.path.join(case, pick(fdp, (b"rf", b"r f", b"-rf")))       # the root's own name too
        outside = os.path.join(case, b"zz")
        os.makedirs(os.path.join(root, b"usr/local/bin"))
        os.makedirs(os.path.join(root, b"etc"))
        os.mkdir(outside)
        with open(os.path.join(root, b"usr/local/bin/node"), "wb") as fh:
            fh.write(CONTENTS[0])
        for n in (b"decoy.node", b"os-release", b"node"):                 # files the probe must never read
            with open(os.path.join(outside, n), "wb") as fh:
                fh.write(b'PRETTY_NAME="' + HOSTMARK + b'"\nPackage: libbrotli1-' + HOSTMARK + b'\n\n' + CONTENTS[1])
        gen_tree(fdp, root, outside)
        out = run_probe(sh, root, outside)
        check_probe(out, root, sh)
    finally:
        shutil.rmtree(case, ignore_errors=True)


FIELDS = {b"BEGIN": 1, b"END": 1, b"OS": 2, b"BIN": 3, b"PY": 4, b"DOTNETRT": 4, b"JAR": 2,
          b"OSPKG": 3, b"ODDNAMES": 2}


def check_probe(out, root, sh):
    lines = out.split(b"\n")
    assert lines[0] == b"BEGIN" and lines[-2:] == [b"END", b""], "%s: probe output not framed: %r" % (sh, out[-200:])
    got, got_py, odd = {}, set(), 0
    for ln in lines[1:-2]:
        f = ln.split(b"\t")
        assert FIELDS.get(f[0]) == len(f), "%s: malformed record %r" % (sh, ln)
        assert not has_ctrl(ln.replace(b"\t", b"")), "%s: control character in %r" % (sh, ln)
        assert HOSTMARK not in ln, "%s: a file outside the tree was read: %r" % (sh, ln)
        if f[0] == b"BIN":
            assert f[2] not in got, "%s: %r reported twice" % (sh, f[2])
            got[f[2]] = f[1]
        if f[0] in (b"BIN", b"PY", b"DOTNETRT", b"JAR"):
            p = f[{b"BIN": 2, b"PY": 3, b"DOTNETRT": 2, b"JAR": 1}[f[0]]]
            real = os.path.realpath(root + p)
            assert real.startswith(os.path.realpath(root) + b"/"), "%s: record leads out of the tree: %r" % (sh, ln)
        if f[0] == b"OS":
            assert f[1] in (b"", b"tree-os"), "%s: os-release from outside the tree: %r" % (sh, ln)
        if f[0] == b"DOTNETRT":
            assert f[3] == b"absent", "%s: a symlink out of the tree was read: %r" % (sh, ln)
        if f[0] == b"PY":
            got_py.add((f[1], f[2], f[3]))
        if f[0] == b"ODDNAMES":
            odd = int(f[1])
    want, want_py, want_odd = expected_tree(root)
    assert got == want, "%s: binaries differ\n got:  %r\n want: %r" % (sh, got, want)
    assert got_py == want_py, "%s: Python packages differ\n got:  %r\n want: %r" % (sh, got_py, want_py)
    assert odd == want_odd, "%s: %d odd names counted, %d in the tree" % (sh, odd, want_odd)
    assert got.get(b"/usr/local/bin/node") == b"VULNERABLE"
    findings, verdict = evaluate(out)
    assert verdict == "VULNERABLE", "%s: the vulnerable node binary was hidden (%s)" % (sh, verdict)


def main():
    argv = [sys.argv[0]] + sys.argv[3:]
    atheris.Setup(argv, fuzz_evaluator if TARGET == "evaluator" else fuzz_probe)
    try:
        atheris.Fuzz()
    finally:
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
