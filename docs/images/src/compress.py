"""Shrink the rendered PNGs about 3x without visible change.

Usage: python3 -I compress.py <in-dir> <out-dir>

256-colour palette from FASTOCTREE (keeps the small accent colours exact,
unlike MEDIANCUT), applied with Floyd-Steinberg dithering so the soft
background glow does not band.
"""
import sys
from pathlib import Path

from PIL import Image, ImageChops

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
for f in sorted(src.glob("*.png")):
    im = Image.open(f).convert("RGB")
    palette = im.quantize(colors=256, method=Image.Quantize.FASTOCTREE)
    q = im.quantize(palette=palette, dither=Image.Dither.FLOYDSTEINBERG)
    q.save(dst / f.name, optimize=True)
    err = max(ImageChops.difference(im, q.convert("RGB")).convert("L").getextrema())
    print(f"{f.name:20s} {f.stat().st_size // 1024:5d} KB -> {(dst / f.name).stat().st_size // 1024:4d} KB  max colour error {err}/255")
