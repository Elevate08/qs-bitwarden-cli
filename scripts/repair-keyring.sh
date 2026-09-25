#!/bin/bash
# Repairs a passwordless gnome-keyring file that a quick-unlock envelope made
# unreadable before the envelope was stored on one line.
#
# It used to be stored as systemd-creds prints it: base64 wrapped at 79
# columns. A passwordless keyring (Omarchy's default, from
# /usr/share/omarchy/install/user/default-keyring.sh) is a text file, and
# gnome-keyring wrote the line breaks into it verbatim. At the next login it
# refuses the whole file --
#
#   keyring was in an invalid or unrecognized format: .../Default_keyring.keyring
#
# -- and every item in that collection disappears, not just ours. This joins
# the wrapped secret of each qs-bitwarden-cli item back onto one line. Nothing
# else in the file changes, and systemd-creds reads the joined form, so quick
# unlock keeps working with nothing set up again.
#
#   scripts/repair-keyring.sh [--check | --auto] [KEYRING_FILE]
#
# KEYRING_FILE defaults to the default collection's file. --check only reports:
# exit 0 when nothing needs repair, 3 when it does. Otherwise the original is
# kept beside the file as <file>.before-repair-<time> before anything is
# written. No secret is ever printed.
#
# --auto is how the plugin runs it at every start: a missing or binary keyring
# is not an error, messages go to stderr, and the last line on stdout is
# file=skipped, file=clean or file=repaired (file=failed, exit 1, if the
# repair was refused).

set -euo pipefail
umask 077

check=0; auto=0
case "${1:-}" in --check) check=1; shift ;; --auto) auto=1; shift ;; esac
file="${1:-${XDG_DATA_HOME:-$HOME/.local/share}/keyrings/Default_keyring.keyring}"

say() { if [ "$auto" -eq 1 ]; then printf 'repair-keyring: %s\n' "$*" >&2; else printf 'repair-keyring: %s\n' "$*"; fi; }
status() { [ "$auto" -eq 0 ] || echo "file=$1"; }
die() { say "$*" >&2; status failed; exit 1; }
skip() { if [ "$auto" -eq 1 ]; then status skipped; exit 0; fi; die "$@"; }

[ -f "$file" ] || skip "no keyring file at $file"
# A keyring with a password is binary ("GnomeKeyring" header) and encrypted;
# only the passwordless text form can hold a raw line break.
first=""; IFS= read -r first < "$file" || true
[ "${first%$'\r'}" = "[keyring]" ] || skip "$file is not a passwordless (text) keyring; nothing to repair"

# Pass 1 finds the items whose `service` attribute is ours. Pass 2 walks the
# file, joining onto each of their `secret=` lines the base64-only lines that
# follow it. A key line always has an `=` before its end and base64 only ends
# in one, so a continuation cannot be mistaken for the next key. Breaks inside
# anyone else's secret are counted and left alone.
#   mode=stats    "<items repaired> <lines joined> <foreign breaks>"
#   mode=file     the repaired file
#   mode=secrets  each repaired item's joined secret, one per line
scan() {
  awk -v mode="$1" '
    function flush() { if (joining) { emit(secret); if (mode == "secrets") print substr(secret, 8) } joining = 0; secret = "" }
    function emit(s) { if (mode == "file") print s }
    FNR == 1 { pass++ }
    { sub(/\r$/, "") }
    pass == 1 {
      if ($0 ~ /^\[[0-9]+:attribute[0-9]+\]$/) { split(substr($0, 2), p, ":"); item = p[1]; name = "" }
      else if ($0 ~ /^\[/) item = ""
      else if (item != "" && $0 ~ /^name=/) name = substr($0, 6)
      else if (item != "" && name == "service" && $0 == "value=qs-bitwarden-cli") ours[item] = 1
      next
    }
    in_secret && /^[A-Za-z0-9+\/]+={0,2}$/ {
      if (cur in ours) { secret = secret $0; joining = 1; joined++; fixed[cur] = 1 }
      else { foreign++; emit($0) }
      next
    }
    { if (joining) flush(); else if (secret != "") { emit(secret); secret = "" }; in_secret = 0 }
    /^\[/ { cur = substr($0, 2, length($0) - 2) }
    /^secret=/ { in_secret = 1; if (cur in ours) { secret = $0; next } }
    { emit($0) }
    END {
      if (joining) flush(); else if (secret != "") emit(secret)
      if (mode == "stats") { n = 0; for (i in fixed) n++; printf "%d %d %d\n", n, joined + 0, foreign + 0 }
    }
  ' "$2" "$2"
}

read -r items lines foreign < <(scan stats "$file")

if [ "$foreign" -gt 0 ]; then
  say "$foreign line break(s) sit inside secrets that are not qs-bitwarden-cli's. They are left" >&2
  say "alone, and gnome-keyring will refuse $file until whatever stored them fixes them." >&2
fi
if [ "$items" -eq 0 ]; then
  [ "$auto" -eq 1 ] || say "no qs-bitwarden-cli secret in $file spans more than one line"
  status clean
  exit 0
fi
say "$items qs-bitwarden-cli secret(s) in $file are split across $((lines + items)) lines"
[ "$check" -eq 0 ] || exit 3

tmp="$(mktemp "$(dirname "$file")/.repair-keyring.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
scan file "$file" > "$tmp"

# The copy must be clean, and be the original less exactly the joined lines.
read -r left _ _ < <(scan stats "$tmp")
[ "$left" -eq 0 ] || die "the repaired copy still has a split secret; $file is unchanged"
[ "$(wc -l < "$tmp")" -eq "$(( $(wc -l < "$file") - lines ))" ] \
  || die "the repaired copy is not the original less the joined lines; $file is unchanged"

backup="$file.before-repair-$(date +%Y%m%d-%H%M%S)"
cp -p -- "$file" "$backup"
chmod --reference="$file" -- "$tmp"
mv -f -- "$tmp" "$file"
trap - EXIT
say "joined them; the original is at $backup"

# Each repaired envelope should open again. What it opens to goes to /dev/null.
if command -v systemd-creds >/dev/null 2>&1; then
  opened=0
  while IFS= read -r sealed; do
    if printf '%s' "$sealed" | systemd-creds --user decrypt --name=qs-bitwarden-unlock - - >/dev/null 2>&1; then
      opened=$((opened + 1))
    fi
  done < <(scan secrets "$backup")
  if [ "$opened" -eq "$items" ]; then
    say "each repaired envelope opens with systemd-creds"
  else
    say "$((items - opened)) of $items repaired envelope(s) did not open here; turn quick unlock off and on again for that account" >&2
  fi
fi

say "restart the computer so gnome-keyring loads the default collection again"
status repaired
