#!/usr/bin/env bash
# Compose preview.png from the captured screenshots.
#
# The preview used to be assembled by hand, which meant adding a panel to it
# was an image-editing job and nobody could tell which screenshots a given
# preview.png was built from. This script is the recipe: run demo/capture.sh
# first, then this.
#
#   ./demo/compose-preview.sh [screenshot-dir] [output]
#
# Everything it reads is fixture data by construction -- capture.sh only ever
# runs against demo/bin/bw and demo/fixtures.json -- so nothing here can put a
# real vault into a published image.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHOTS="${1:-$REPO/docs/screenshots}"
OUT="${2:-$REPO/preview.png}"

command -v magick >/dev/null || { echo "missing required tool: magick" >&2; exit 1; }

# Sampled from the preview this replaces, so the rebuild is the same design
# rather than an approximation of it.
BG='#060400'
ACCENT='#F2A502'
TITLE='Bitwarden Vault Plugin'
# ImageMagick's own name for the face, which is not the fontconfig family
# name. `magick -list font` is the list it will accept; override if your
# machine names it differently.
FONT="${QSBW_PREVIEW_FONT:-CaskaydiaMono-NF-Bold}"
FONT_BODY="${QSBW_PREVIEW_FONT_BODY:-CaskaydiaMono-NF-Regular}"

# The callout that fills the empty corner under the first column. It is the
# one element here that is not a screenshot, so it borrows the panels' own
# vocabulary -- same accent, same square border, same black ground -- and
# earns its place by naming what the release added.
BADGE_KICKER='NEW'
BADGE_TITLE='SSH agent support'
BADGE_BODY='Serve your vault'"'"'s SSH keys to ssh
and Git. Every signature is approved
in the panel; nothing touches disk.'
BADGE_W=720
GAP=28        # between panels, and around the whole thing
TITLE_SIZE=96

# Three columns, top to bottom. The vault list carries the folder drawer
# because that shot shows both at once; the plain list would be redundant
# beside it.
# Grouped to keep the three columns near the same height -- the page is as
# tall as its tallest column, and an unbalanced one leaves a corner of empty
# black. Sends is short, so it pairs with the tall drawer; the approval screen
# pairs with settings.
COL1=(06-login 03-generator)
COL2=(02-folder-drawer 04-sends)
COL3=(05-settings 07-ssh-approval)

# Not `magick ... | grep -q`: grep exits on the first match, magick takes a
# SIGPIPE for it, and `set -o pipefail` reports the successful match as a
# failed pipeline.
grep -qx "  Font: $FONT" <<<"$(magick -list font)" || {
  echo "magick does not know the font '$FONT'." >&2
  echo "Pick one from \`magick -list font\` and set QSBW_PREVIEW_FONT." >&2
  exit 1
}

column() { # column <name>...
  local files=() f
  for f in "$@"; do
    if [ -f "$SHOTS/$f.png" ]; then files+=("$SHOTS/$f.png")
    else echo "  missing $f.png, leaving it out" >&2; fi
  done
  [ ${#files[@]} -gt 0 ] || { echo "no screenshots for a column" >&2; exit 1; }
  # -background so the gap between stacked panels is the page colour, not white.
  magick "${files[@]}" -background "$BG" -gravity north -splice "0x${GAP}" \
    -append -chop "0x${GAP}" miff:-
}

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
column "${COL1[@]}" > "$work/c1.miff"
column "${COL2[@]}" > "$work/c2.miff"
column "${COL3[@]}" > "$work/c3.miff"

# Columns side by side, each hung from the top. The gravity has to be north
# for the append itself: +append centres shorter images vertically unless told
# otherwise, which left the third column floating in the middle of the page.
magick "$work/c1.miff" "$work/c2.miff" "$work/c3.miff" \
  -background "$BG" -gravity west -splice "${GAP}x0" \
  -gravity north +append -chop "${GAP}x0" "$work/panels.png"

magick "$work/panels.png" \
  -background "$BG" \
  -gravity south -splice "0x${GAP}" \
  -gravity west  -splice "${GAP}x0" \
  -gravity east  -splice "${GAP}x0" \
  "$work/framed.png"

# The title as its own image, the width of the page, rather than annotated on
# to it. `-annotate` with a gravity places from an origin this composition
# keeps moving, and the text ended up off the left edge; a label of a known
# size cannot land anywhere but where it is appended.
WIDTH="$(magick identify -format '%w' "$work/framed.png")"
magick -size "${WIDTH}x$((TITLE_SIZE * 2))" -background "$BG" -fill "$ACCENT" \
  -font "$FONT" -pointsize "$TITLE_SIZE" -gravity center \
  label:"$TITLE" "$work/title.png"

# -depth 8: the label pushes the pipeline to 16-bit, which triples the file
# size of a flat-colour image for nothing a viewer can see.
magick "$work/title.png" "$work/framed.png" -background "$BG" -append \
  "$work/page.png"

# --- the callout ------------------------------------------------------------
#
# Drawn as its own image and composited, rather than annotated on to the page:
# it overlaps the panel above it by design, and a composite is the only way to
# put something over a region that already has pixels in it.
# No -size here: `label:` with an explicit size scales the text to fill it,
# which turned a 34pt kicker into a 500pt "NEW" across the whole badge. The
# point size governs, and the width is set once after the lines are stacked.
magick -background "$BG" -fill "$ACCENT" \
  -font "$FONT" -pointsize 34 -interword-spacing 12 \
  label:"$BADGE_KICKER" "$work/kicker.png"
magick -background "$BG" -fill "$ACCENT" \
  -font "$FONT" -pointsize 62 label:"$BADGE_TITLE" "$work/badge-title.png"
magick -background "$BG" -fill '#C8C8C8' \
  -font "$FONT_BODY" -pointsize 28 -interline-spacing 10 \
  label:"$BADGE_BODY" "$work/badge-body.png"

# Stacked left-aligned, padded, then bordered -- the border last so it wraps
# the padding rather than sitting inside it.
magick "$work/kicker.png" "$work/badge-title.png" "$work/badge-body.png" \
  -background "$BG" -gravity west -append "$work/badge-text.png"

# BADGE_W is a floor, not a crop: -extent to a width narrower than the text
# silently cuts the longest line off, which is how the body lost its last
# three characters.
TEXT_W="$(magick identify -format '%w' "$work/badge-text.png")"
[ "$TEXT_W" -gt "$BADGE_W" ] && BADGE_W="$TEXT_W"

magick "$work/badge-text.png" \
  -background "$BG" -gravity west -extent "${BADGE_W}x" \
  -gravity north -splice "0x18" -gravity south -splice "0x8" \
  -bordercolor "$BG" -border 26 \
  -bordercolor "$ACCENT" -border 3 \
  "$work/badge.png"

# Anchored to the first column: its left edge, and high enough to overlap the
# panel above by a little, which is what stops it reading as a sixth panel.
BADGE_H="$(magick identify -format '%h' "$work/badge.png")"
COL1_H="$(magick identify -format '%h' "$work/c1.miff")"
TITLE_H="$(magick identify -format '%h' "$work/title.png")"
BADGE_X="$GAP"
BADGE_Y=$((TITLE_H + COL1_H - 40))

magick "$work/page.png" "$work/badge.png" -geometry "+${BADGE_X}+${BADGE_Y}" \
  -composite -depth 8 -strip "$OUT"

magick identify "$OUT"
