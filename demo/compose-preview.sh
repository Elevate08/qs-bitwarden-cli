#!/usr/bin/env bash
# Compose preview.png from the captured screenshots.
#
# The preview used to be assembled by hand, which meant adding a panel to it
# was an image-editing job and nobody could tell which screenshots a given
# preview.png was built from. This script is the recipe: run demo/capture.sh
# first, then this.
#
#   ./demo/compose-preview.sh [screenshot-dir] [output]
#   ./demo/compose-preview.sh --badge-only        (reuse the cached base)
#
# The base -- panels and title, everything that comes from screenshots -- is
# cached beside the shots. Only the callout changes when a release wants a
# different phrase, and rebuilding six panels to redraw one banner made trying
# wordings slower than it needed to be.
#
# Everything it reads is fixture data by construction -- capture.sh only ever
# runs against demo/bin/bw and demo/fixtures.json -- so nothing here can put a
# real vault into a published image.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BADGE_ONLY=0
args=()
for a in "$@"; do
  case "$a" in
    --badge-only) BADGE_ONLY=1 ;;
    *) args+=("$a") ;;
  esac
done
SHOTS="${args[0]:-$REPO/docs/screenshots}"
OUT="${args[1]:-$REPO/preview.png}"
BASE="$SHOTS/.preview-base.png"

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
# Set either from the environment to try a phrase without touching the file:
#   QSBW_BADGE_TITLE='Now signs your commits' ./demo/compose-preview.sh --badge-only
BADGE_KICKER="${QSBW_BADGE_KICKER:-NEW}"
BADGE_TITLE="${QSBW_BADGE_TITLE:-SSH agent support}"
# Filled with the accent and lettered in the page's own black, rather than
# outlined like the panels. A seventh accent-bordered rectangle read as one
# more screenshot; this cannot be mistaken for one.
BADGE_FG="$BG"
BADGE_BG="$ACCENT"
# Width kept clear at the right of the title band for the callout. The page
# title is centred in what is left rather than in the whole width, so the gap
# between the two does not depend on how long the badge phrase happens to be
# -- and a badge that outgrows this is told to shrink rather than silently
# shunting into the title.
BADGE_ZONE=640
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

if [ "$BADGE_ONLY" = 1 ]; then
  [ -f "$BASE" ] || { echo "no cached base at $BASE; run without --badge-only first" >&2; exit 1; }
  cp "$BASE" "$work/page.png"
else
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
  magick -background "$BG" -fill "$ACCENT" -font "$FONT" \
    -pointsize "$TITLE_SIZE" label:"$TITLE" "$work/title-text.png"
  magick "$work/title-text.png" -background "$BG" -gravity center \
    -extent "$((WIDTH - BADGE_ZONE))x$((TITLE_SIZE * 2))" \
    -gravity east -splice "${BADGE_ZONE}x0" "$work/title.png"

  # -depth 8: the label pushes the pipeline to 16-bit, which triples the file
  # size of a flat-colour image for nothing a viewer can see.
  magick "$work/title.png" "$work/framed.png" -background "$BG" -append \
    "$work/page.png"

  cp "$work/page.png" "$BASE"
  # The callout straddles the bottom of the title band, which a badge-only run
  # has no way to measure -- the pieces are gone by then. Record it.
  magick identify -format '%h' "$work/title.png" > "$BASE.anchor"
fi
[ -f "$BASE.anchor" ] || { echo "no anchor beside $BASE; rebuild the base" >&2; exit 1; }
TITLE_H="$(cat "$BASE.anchor")"

# --- the callout ------------------------------------------------------------
#
# Drawn as its own image and composited, rather than annotated on to the page:
# it overlaps the panel above it by design, and a composite is the only way to
# put something over a region that already has pixels in it.
# No -size here: `label:` with an explicit size scales the text to fill it,
# which turned a 34pt kicker into a 500pt "NEW" across the whole badge. The
# point size governs, and the padding is added afterwards.
magick -background "$BADGE_BG" -fill "$BADGE_FG" \
  -font "$FONT" -pointsize 26 -interword-spacing 10 \
  label:"$BADGE_KICKER" "$work/kicker.png"
magick -background "$BADGE_BG" -fill "$BADGE_FG" \
  -font "$FONT" -pointsize 44 label:"$BADGE_TITLE" "$work/badge-title.png"

# A solid block, not an outline: the panels are all accent-bordered rectangles
# on black, so one more of those disappears among them. Inverting it -- accent
# ground, black letters -- is what makes it read as a label on the image
# rather than a part of it.
magick "$work/kicker.png" "$work/badge-title.png" \
  -background "$BADGE_BG" -gravity west -append \
  -bordercolor "$BADGE_BG" -border 22 \
  "$work/badge.png"

# Top right: the title is centred, so the corner beside it is empty, and
# hanging the badge below the band's edge lets it clip the first panel of the
# third column -- which is what keeps it looking placed rather than laid out.
PAGE_W="$(magick identify -format '%w' "$work/page.png")"
BADGE_BW="$(magick identify -format '%w' "$work/badge.png")"
BADGE_BH="$(magick identify -format '%h' "$work/badge.png")"
BADGE_X=$((PAGE_W - BADGE_BW - GAP))
# Centred in the title band rather than overlapping anything. The two
# neighbours here are both load-bearing -- the page title to its left and the
# panel header below it -- and dipping into either one cost more than the
# overlap was worth.
BADGE_Y=$(((TITLE_H - BADGE_BH) / 2))

if [ "$BADGE_BW" -gt "$((BADGE_ZONE - GAP))" ]; then
  echo "  warning: the badge is wider than the ${BADGE_ZONE}px reserved for it" >&2
  echo "  and will crowd the page title. Shorten the phrase or raise BADGE_ZONE." >&2
fi

magick "$work/page.png" "$work/badge.png" -geometry "+${BADGE_X}+${BADGE_Y}" \
  -composite -depth 8 -strip "$OUT"

magick identify "$OUT"
