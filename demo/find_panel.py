#!/usr/bin/env python3
"""Locate the plugin panel in a screenshot by its accent border.

Trimming to "any accent-coloured pixel" is not enough: the compositor draws the
focused window's border in the same accent, so a trim swallows whatever sits
behind the panel. The panel is instead found as a filled rectangle -- four
borders enclosing a region -- and the largest such rectangle is returned.

The accent itself is read out of the image rather than hardcoded. It is a theme
colour, so a hardcoded value silently stops matching the day the operator
changes themes -- which is exactly how this last failed, with every shot
reported as "could not locate the panel border" and no hint as to why.

    find_panel.py <image> [--accent RRGGBB] -> "WxH+X+Y" on stdout
"""
import sys
from collections import Counter
from PIL import Image

# Enough slack for antialiasing and the border's own gradient, not enough to
# merge two distinct theme colours.
TOLERANCE = 26
# The panel is wider than any window border is thick.
MIN_RUN = 260


def close(px, target, tol=TOLERANCE):
    return all(abs(px[i] - target[i]) <= tol for i in range(3))


def candidate_accents(img, limit=6):
    """Saturated colours in the image, most common first.

    The panel border is a solid run of one theme colour, so it is always among
    the most common saturated pixels. Returning several candidates means a
    highlighted row or a colourful wallpaper cannot derail the search.
    """
    w, h = img.size
    px = img.load()
    counts = Counter()
    for y in range(0, h, 2):
        for x in range(0, w, 2):
            r, g, b = px[x, y]
            if max(r, g, b) > 110 and (max(r, g, b) - min(r, g, b)) > 60:
                counts[(r, g, b)] += 1

    accents = []
    for colour, _ in counts.most_common():
        # Skip anything already covered by a candidate we kept.
        if any(close(colour, kept) for kept in accents):
            continue
        accents.append(colour)
        if len(accents) >= limit:
            break
    return accents


def find_box(img, accent):
    w, h = img.size
    px = img.load()

    # Rows that contain a long horizontal run of accent pixels are candidate
    # top/bottom borders.
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
        return None

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

    return best_box


def main():
    path = sys.argv[1]
    img = Image.open(path).convert("RGB")

    if "--accent" in sys.argv:
        h = sys.argv[sys.argv.index("--accent") + 1].lstrip("#")
        accents = [tuple(int(h[i:i+2], 16) for i in (0, 2, 4))]
    else:
        accents = candidate_accents(img)

    if not accents:
        sys.exit("no saturated colour in the image to use as an accent")

    for accent in accents:
        box = find_box(img, accent)
        if box:
            print("%dx%d+%d+%d" % box)
            return

    tried = ", ".join("#%02X%02X%02X" % a for a in accents)
    sys.exit("no enclosed rectangle found (tried %s)" % tried)


if __name__ == "__main__":
    main()
