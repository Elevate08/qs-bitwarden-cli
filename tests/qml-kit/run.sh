#!/usr/bin/env bash
# Qt tests that build the plugin's own view files (the SSH approval card, the
# panel's screens) with the Omarchy shell's real UI kit. They need the kit
# installed, so they live apart from tests/qml, which runs anywhere.
#
#   tests/qml-kit/run.sh [test.qml ...]
#
# QMLTESTRUNNER picks the binary (default: the Qt6 one). Nothing of the
# caller's environment is passed on: a scratch HOME and runtime dir, no PATH,
# the offscreen platform. Skips, and says so, when the kit is not installed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
kit=${OMARCHY_SHELL_DIR:-/usr/share/omarchy/shell}
runner=${QMLTESTRUNNER:-/usr/lib/qt6/bin/qmltestrunner}

if [ ! -d "$kit/Ui" ] || [ ! -d "$kit/Commons" ]; then
  echo "qml-kit: the Omarchy shell kit is not installed at $kit; skipped"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
node "$here/kit-imports.js" "$kit" "$work/imports"
mkdir -p "$work/home" "$work/runtime"
chmod 700 "$work/runtime"

inputs=("$@")
[ ${#inputs[@]} -gt 0 ] || inputs=("$here")

status=0
for input in "${inputs[@]}"; do
  env -i HOME="$work/home" XDG_RUNTIME_DIR="$work/runtime" PATH=/nonexistent \
    QT_QPA_PLATFORM=offscreen QML_XHR_ALLOW_FILE_READ=1 \
    "$runner" -import "$work/imports" -input "$input" || status=1
done
exit $status
