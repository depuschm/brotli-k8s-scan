"""Write the HTML sources of the README images from real data.

Usage: python3 -I make_html.py <cache-dir> <fixtures-dir>

<cache-dir>     contains fonts/ and the captured terminal output cap-*.txt
                (build-images.sh prepares both) and receives the *.html files.
<fixtures-dir>  tests/.cache/fixtures; the error tables in the diagram are read
                from the real Ubuntu libbrotlidec binaries there.
"""
import html
import re
import sys
from pathlib import Path

C = Path(sys.argv[1]).resolve()
FX = Path(sys.argv[2]).resolve()
JBM = (C / "fonts/jetbrains-mono/files").as_uri()
INTER = (C / "fonts/inter/files").as_uri()

CSS = f"""
@font-face {{ font-family: 'JBM'; src: url('{JBM}/jetbrains-mono-latin-400-normal.woff2'); font-weight: 400; }}
@font-face {{ font-family: 'JBM'; src: url('{JBM}/jetbrains-mono-latin-700-normal.woff2'); font-weight: 700; }}
@font-face {{ font-family: 'InterV'; src: url('{INTER}/inter-latin-opsz-normal.woff2') format('woff2-variations'); font-weight: 100 900; }}
:root {{
  --bg: #0b0f15; --bg2: #111720; --border: #2a3340; --text: #e6edf3;
  --muted: #8b96a5; --dim: #5d6876; --red: #ff6b6b; --redbg: rgba(255,107,107,.12);
  --green: #3fd17a; --greenbg: rgba(63,209,122,.13); --yellow: #e3b341; --blue: #7cc4ff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'InterV', sans-serif; -webkit-font-smoothing: antialiased; }}
.mono {{ font-family: 'JBM', monospace; }}
/* show the characters a terminal shows: no "->" arrows or "===" bars */
.mono, .eyebrow, .chip, .table, .term, .pill {{ font-variant-ligatures: none; font-feature-settings: 'calt' 0, 'liga' 0; }}
.grid-bg {{
  background-color: var(--bg);
  background-image:
    radial-gradient(ellipse 60% 90% at 85% 50%, rgba(63,209,122,.10), transparent 70%),
    radial-gradient(ellipse 50% 80% at 10% 0%, rgba(124,196,255,.08), transparent 70%),
    linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
  background-size: auto, auto, 32px 32px, 32px 32px;
}}
.eyebrow {{ font-family: 'JBM', monospace; font-size: 15px; letter-spacing: .02em; color: var(--blue); }}
.eyebrow b {{ color: var(--red); font-weight: 700; }}
.title {{ font-family: 'InterV', sans-serif; font-weight: 800; font-variation-settings: 'opsz' 32; letter-spacing: -0.03em; }}
.tag {{ color: #c9d4df; font-weight: 500; }}
.tag em {{ font-style: normal; color: var(--green); }}
.chips {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.chip {{ font-family: 'JBM', monospace; font-size: 13px; color: #c9d4df; border: 1px solid var(--border);
        background: rgba(255,255,255,.03); border-radius: 999px; padding: 5px 12px; }}
.table {{ font-family: 'JBM', monospace; background: rgba(13,18,25,.92); border: 1px solid var(--border);
         border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,.45); overflow: hidden; }}
.table .hd {{ display: flex; justify-content: space-between; align-items: center; padding: 10px 16px;
             border-bottom: 1px solid var(--border); background: var(--bg2); font-size: 12.5px; color: var(--muted); }}
.row {{ display: flex; gap: 14px; padding: 5px 16px; font-size: 14px; color: #aab4c0; white-space: nowrap; }}
.row .off {{ color: var(--dim); width: 42px; flex: none; }}
.row.hit {{ background: var(--greenbg); color: var(--green); font-weight: 700; box-shadow: inset 3px 0 0 var(--green); }}
.row.miss {{ background: var(--redbg); color: var(--red); box-shadow: inset 3px 0 0 var(--red); font-style: italic; }}
.row.fade {{ color: var(--dim); }}
.pill {{ font-family: 'JBM', monospace; font-weight: 700; font-size: 13px; letter-spacing: .04em; border-radius: 6px; padding: 4px 10px; }}
.pill.red {{ color: var(--red); background: var(--redbg); border: 1px solid rgba(255,107,107,.35); }}
.pill.green {{ color: var(--green); background: var(--greenbg); border: 1px solid rgba(63,209,122,.35); }}
.term {{ background: #0d1117; border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
        box-shadow: 0 24px 70px rgba(0,0,0,.5); }}
.term .bar {{ display: flex; align-items: center; gap: 8px; padding: 11px 14px; background: #161b22; border-bottom: 1px solid var(--border); }}
.term .dot {{ width: 12px; height: 12px; border-radius: 50%; background: #3a4350; }}
.term .bar .t {{ margin-left: 10px; font-family: 'JBM', monospace; font-size: 12.5px; color: var(--muted); }}
.term pre {{ font-family: 'JBM', monospace; font-size: 13px; line-height: 1.55; color: #d0d7de; padding: 16px 18px 18px; white-space: pre-wrap; }}
.term .p {{ color: var(--green); }}
.term .cmd {{ color: #ffffff; font-weight: 700; }}
.term .c1 {{ color: var(--red); font-weight: 700; }}
.term .c3 {{ color: var(--yellow); font-weight: 700; }}
.term .c2 {{ color: var(--green); font-weight: 700; }}
.term .cd {{ color: var(--dim); }}
"""


def page(body: str, w: int, h: int | None = None) -> str:
    hcss = f"height:{h}px;" if h else ""
    return (f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}"
            f"html,body{{width:{w}px;{hcss}}}</style></head><body>{body}</body></html>")


# ------------------------------------------------------------- real error tables
def table_from(path: Path) -> list[str]:
    data = path.read_bytes()
    return [m.decode() for m in re.findall(rb"_(?:NO_ERROR|SUCCESS|NEEDS_MORE_[A-Z]+|ERROR_[A-Z0-9_]+)(?=\x00)", data)]


def lib(fixture: str) -> Path:
    found = sorted((FX / fixture).glob("usr/lib/*/libbrotlidec.so.1.1.0"))
    if not found:
        sys.exit(f"missing {fixture} fixture: run tests/build-fixtures.sh")
    return found[0]


old = table_from(lib("ubuntu-old"))
new = table_from(lib("ubuntu-fixed"))
KEY = "_ERROR_FORMAT_BLOCK_SWITCH"
assert KEY in new and KEY not in old, "fixtures do not show the expected difference"
i = new.index(KEY)
WINDOW = new[i - 3:i + 3]

# error codes from c/include/brotli/decode.h (unchanged by the fix; before it
# the header says "-17 code is reserved")
CODES = {"_ERROR_FORMAT_PADDING_1": -14, "_ERROR_FORMAT_PADDING_2": -15, "_ERROR_FORMAT_DISTANCE": -16,
         KEY: -17, "_ERROR_COMPOUND_DICTIONARY": -18, "_ERROR_DICTIONARY_NOT_SET": -19}
assert set(WINDOW) <= set(CODES), f"error table changed shape: {WINDOW}"


def rows(table: list[str], vulnerable: bool) -> str:
    out = ['<div class="row fade"><span class="off">…</span><span>…</span></div>']
    for name in WINDOW:
        code = CODES[name]
        if name == KEY and vulnerable:
            assert name not in table
            out.append(f'<div class="row miss"><span class="off">{code}</span><span>(reserved, no entry)</span></div>')
        elif name == KEY:
            out.append(f'<div class="row hit"><span class="off">{code}</span><span>{name}</span></div>')
        else:
            assert name in table
            out.append(f'<div class="row"><span class="off">{code}</span><span>{name}</span></div>')
    out.append('<div class="row fade"><span class="off">…</span><span>…</span></div>')
    return "".join(out)


EYEBROW = '<b>CVE-2026-111497</b> &nbsp;·&nbsp; Broccoli2Shell / Node2Shell / HTTP2Shell'
TABLE_FIXED = ('<div class="hd"><span>libbrotlidec · decoder error table</span><span class="pill green">PATCHED</span></div>'
               + rows(new, False))

# ------------------------------------------------------------- banner (1280x320)
banner = page(f"""
<div class="grid-bg" style="width:1280px;height:320px;display:flex;align-items:center;justify-content:space-between;padding:0 64px">
  <div style="display:flex;flex-direction:column;gap:18px">
    <div class="eyebrow">{EYEBROW}</div>
    <div class="title" style="font-size:68px;line-height:1">brotli-k8s-scan</div>
    <div class="tag" style="font-size:25px">Version numbers lie. <em>Check the binary.</em></div>
    <div class="chips"><span class="chip">Kubernetes</span><span class="chip">container images</span><span class="chip">Linux hosts</span><span class="chip">read-only · bash</span></div>
  </div>
  <div class="table" style="width:430px">{TABLE_FIXED}</div>
</div>""", 1280, 320)

# ------------------------------------------------------------- social preview (1280x640, GitHub's size)
chip16 = lambda t: f'<span class="chip" style="font-size:16px">{t}</span>'  # noqa: E731
social = page(f"""
<div class="grid-bg" style="width:1280px;height:640px;padding:64px 72px 56px;display:flex;flex-direction:column;justify-content:space-between">
  <div class="eyebrow" style="font-size:19px;white-space:nowrap">{EYEBROW}</div>
  <div style="display:flex;justify-content:space-between;align-items:center;gap:40px">
    <div style="display:flex;flex-direction:column;gap:26px">
      <div class="title" style="font-size:80px;line-height:1">brotli-k8s-scan</div>
      <div class="tag" style="font-size:34px;line-height:1.25">Version numbers lie.<br><em>Check the binary.</em></div>
      <div class="chips" style="gap:10px;max-width:560px">{''.join(chip16(t) for t in ['Node.js', 'Python', '.NET', 'Bun', 'Envoy'])}</div>
    </div>
    <div class="table" style="width:470px;flex:none">{TABLE_FIXED}</div>
  </div>
  <div style="display:flex;justify-content:space-between;align-items:flex-end">
    <div class="mono" style="color:var(--muted);font-size:17px">Kubernetes · container images · Linux hosts · read-only bash</div>
    <div class="mono" style="color:var(--muted);font-size:17px">github.com/depuschm/brotli-k8s-scan</div>
  </div>
</div>""", 1280, 640)

# ------------------------------------------------------------- fingerprint diagram
fingerprint = page(f"""
<div class="grid-bg" style="width:1200px;padding:48px 56px 44px">
  <div class="eyebrow">How brotli-k8s-scan tells them apart</div>
  <div class="title" style="font-size:40px;margin:10px 0 6px">Same version string. Different binary.</div>
  <div style="color:var(--muted);font-size:17px;margin-bottom:30px">Ubuntu 24.04 <span class="mono" style="color:#c9d4df">libbrotlidec.so.1.1.0</span>, before and after the CVE-2026-111497 security update. Both say “1.1.0”.</div>
  <div style="display:flex;gap:28px">
    <div style="flex:1;display:flex;flex-direction:column;gap:12px">
      <div class="mono" style="font-size:15px;color:#c9d4df">libbrotli1 <b>1.1.0-2build2</b> <span style="color:var(--dim)">· reports 1.1.0</span></div>
      <div class="table"><div class="hd"><span>decoder error table (strings in the binary)</span><span class="pill red">VULNERABLE</span></div>{rows(old, True)}</div>
    </div>
    <div style="flex:1;display:flex;flex-direction:column;gap:12px">
      <div class="mono" style="font-size:15px;color:#c9d4df">libbrotli1 <b>1.1.0-2ubuntu0.1</b> <span style="color:var(--dim)">· reports 1.1.0</span></div>
      <div class="table"><div class="hd"><span>decoder error table (strings in the binary)</span><span class="pill green">PATCHED</span></div>{rows(new, False)}</div>
    </div>
  </div>
  <div style="margin-top:26px;color:var(--muted);font-size:16px;line-height:1.55">
    The fix filled the reserved error code <span class="mono" style="color:var(--text)">-17</span>.
    Its name, <span class="mono" style="color:var(--green)">{KEY}</span>, ends up in the decoder's error table,
    so a fixed build carries it and a vulnerable one does not, whatever its version string says.
  </div>
</div>""", 1200)


# ------------------------------------------------------------- terminal screenshots
def ansi_to_html(raw: str) -> str:
    """The scanner's own colours (paint / C_* in brotli-k8s-scan.sh) -> CSS classes."""
    out, open_span = [], False
    for part in re.split(r"(\x1b\[[0-9;]*m)", raw.replace("\r", "")):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if not m:
            out.append(html.escape(part))
            continue
        if open_span:
            out.append("</span>")
            open_span = False
        cls = {"1;31": "c1", "1;33": "c3", "1;32": "c2", "2": "cd"}.get(m.group(1))
        if cls:
            out.append(f'<span class="{cls}">')
            open_span = True
    if open_span:
        out.append("</span>")
    return "".join(out)


def captured(name: str, drop_report_list: bool = False) -> str:
    lines = (C / f"cap-{name}.txt").read_text().splitlines()
    lines = [l for l in lines if not l.startswith(("Script started", "Script done"))]
    if drop_report_list:  # the list of report files adds nothing to this picture
        lines = [l for l in lines if not re.match(r"^(Report|Details|JSON|SARIF):", l.strip("\r"))]
    while lines and not lines[-1].strip("\r"):
        lines.pop()
    # the default output folder is named after the current time; pin it so that
    # rebuilding gives byte-identical images instead of churn in git
    text = re.sub(r"brotli-scan-\d{8}-\d{6}", "brotli-scan-20261027-203000", "\n".join(lines))
    return ansi_to_html(text)


def term(title: str, inner: str, w: int = 1320) -> str:
    return page(f"""
<div class="grid-bg" style="width:{w}px;padding:36px">
  <div class="term"><div class="bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="t">{title}</span></div>
  <pre>{inner}</pre></div>
</div>""", w)


def prompt(cmd: str) -> str:
    return f'<span class="p">$</span> <span class="cmd">{html.escape(cmd)}</span>\n'


scan_cluster = term("brotli-k8s-scan · cluster scan", prompt("./brotli-k8s-scan.sh") + captured("cluster"))
same_version = term("brotli-k8s-scan · same version, different verdict",
                    prompt("./brotli-k8s-scan.sh --image registry.example/app:2026-10-20") + captured("old", True)
                    + "\n\n" + prompt("./brotli-k8s-scan.sh --image registry.example/app:2026-10-27") + captured("new", True))

for name, doc in [("banner", banner), ("social-preview", social), ("fingerprint", fingerprint),
                  ("scan-cluster", scan_cluster), ("same-version", same_version)]:
    (C / f"{name}.html").write_text(doc)
print("html written to", C)
