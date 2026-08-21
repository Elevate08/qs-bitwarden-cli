#!/usr/bin/env python3
"""Locate the plugin panel in a screenshot by its accent border.

Trimming to "any accent-coloured pixel" is not enough: the compositor draws the
focused window's border in the same accent, so a trim swallows whatever sits
behind the panel. The panel is instead found as a filled rectangle -- four
borders enclosing a region -- and the largest such rectangle is returned.

    find_panel.py <image> [--accent RRGGBB] -> "WxH+X+Y" on stdout
"""
import sys
from PIL import Image

def close(px, target, tol=26):
    return all(abs(px[i] - target[i]) <= tol for i in range(3))

def main():
    path = sys.argv[1]
    accent = (0xE6, 0x8E, 0x0D)
    if "--accent" in sys.argv:
        h = sys.argv[sys.argv.index("--accent") + 1].lstrip("#")
        accent = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

    img = Image.open(path).convert("RGB")
    w, h = img.size
    px = img.load()

    # Rows that contain a long horizontal run of accent pixels are candidate
    # top/bottom borders; the panel is wider than any window border is thick.
    MIN_RUN = 260
    runs = {}   # row -> (start, end) of its longest accent run
    for y in range(h):
        best = (0, 0, 0)
        run_start, run_len = None, 0
        for x in range(w):
            if close(px[x, y], accent):
                if run_start is None:
                    run_start = x
                run_len += 1
            else:
                if run_len > best[0]:
                    best = (run_len, run_start, x - 1)
                run_start, run_len = None, 0
        if run_len > best[0]:
            best = (run_len, run_start, w - 1)
        if best[0] >= MIN_RUN:
            runs[y] = (best[1], best[2])

    if not runs:
        sys.exit("no accent border found")

    # Pair each top edge with the furthest bottom edge sharing its extent, and
    # keep the tallest rectangle: that is the panel, not a window border.
    best_box = None
    ys = sorted(runs)
    for i, top in enumerate(ys):
        x0, x1 = runs[top]
        for bottom in reversed(ys[i + 1:]):
            bx0, bx1 = runs[bottom]
            if abs(bx0 - x0) <= 4 and abs(bx1 - x1) <= 4 and bottom - top > 120:
                box = (x1 - x0 + 1, bottom - top + 1, x0, top)
                if best_box is None or box[0] * box[1] > best_box[0] * best_box[1]:
                    best_box = box
                break

    if not best_box:
        sys.exit("no enclosed rectangle found")
    print("%dx%d+%d+%d" % best_box)

if __name__ == "__main__":
    main()
