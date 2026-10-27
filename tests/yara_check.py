"""Offline check of yara/brotli_cve_2026_111497.yar against the test fixtures.
Usage: python3 -I tests/yara_check.py <pylib> <rules.yar> <fixtures-dir>
Prints one 'ok'/'FAIL' line per file; exit code 1 on any failure."""
import os
import sys

sys.path.insert(0, sys.argv[1])
import yara  # noqa: E402

rules = yara.compile(filepath=sys.argv[2])
fx = sys.argv[3]
V, P, U = ("Brotli_Decoder_Vulnerable_CVE_2026_111497",
           "Brotli_Decoder_Patched_CVE_2026_111497",
           "Brotli_Present_Patch_State_Unknown")
cases = [
    ("old109/usr/lib/libbrotlidec.so.1.0.9", V),
    ("old1010/usr/lib/libbrotlidec.so.1.0.10", P),
    ("vuln/usr/lib/libbrotlidec.so.1.2.0", V),
    ("fixed/usr/lib/libbrotlidec.so.1.2.1", P),
    ("vuln/usr/local/bin/node", V),
    ("fixed/usr/local/bin/node", P),
    ("vuln/app/venv/lib/python3/site-packages/_brotli.so", V),
    ("fixed/app/venv/lib/python3/site-packages/_brotli.so", P),
    ("vuln/app/venv/lib/python3/site-packages/brotlicffi/_brotlicffi.abi3.so", V),
    ("fixed/app/venv/lib/python3/site-packages/brotlicffi/_brotlicffi.abi3.so", P),
    ("static/opt/app/server", U),
    ("ubuntu-old/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0", V),
    ("ubuntu-fixed/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0", P),
    ("ubuntu-old/usr/lib/aarch64-linux-gnu/libbrotlidec.so.1.1.0", V),
    ("ubuntu-fixed/usr/lib/aarch64-linux-gnu/libbrotlidec.so.1.1.0", P),
    # official Bun / Envoy release binaries; Envoy keeps no error table
    ("bunold/usr/local/bin/bun", V),
    ("bunfixed/usr/local/bin/bun", P),
    ("envoyold/usr/local/bin/envoy", U),
    ("envoyfixed/usr/local/bin/envoy", U),
    # real .NET runtimes
    ("dotnet8-ubuntu/usr/lib/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so", V),
    ("dotnet10-ubuntu-old/usr/lib/dotnet/shared/Microsoft.NETCore.App/10.0.13/libSystem.IO.Compression.Native.so", None),
    # official Microsoft builds: the error table may be stripped (then Unknown),
    # but a vulnerable build must never look patched and vice versa
    ("msdotnet-8.0.32/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so", {V, U}),
    ("msdotnet-8.0.33/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.33/libSystem.IO.Compression.Native.so", {P, U}),
    ("msdotnet-10.0.13/usr/share/dotnet/shared/Microsoft.NETCore.App/10.0.13/libSystem.IO.Compression.Native.so", {V, U}),
    ("msdotnet-10.0.14/usr/share/dotnet/shared/Microsoft.NETCore.App/10.0.14/libSystem.IO.Compression.Native.so", {P, U}),
]
fail = 0
for rel, want in cases:
    path = os.path.join(fx, rel)
    if not os.path.exists(path):
        continue  # optional fixture (other arch / Ubuntu download skipped)
    got = sorted(m.rule for m in rules.match(path))
    if want is None:
        good = got == []
    elif isinstance(want, set):
        good = len(got) == 1 and got[0] in want
    else:
        good = got == [want]
    fail += not good
    print(f"  {'ok  ' if good else 'FAIL'}  yara: {rel} -> {','.join(got) or 'no match'}")
sys.exit(1 if fail else 0)
