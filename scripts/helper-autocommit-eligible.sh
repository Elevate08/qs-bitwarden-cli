#!/usr/bin/env bash
# Whether CI may rebuild and commit the helper binaries for this pull request.
# Prints `yes` or `no`, and the reason on stderr.
#
# Only a same-repository PR into a release branch whose every changed file is
# either ordinary (QML, JS, docs, tests: anything the build never reads) or
# plain Rust source under {agent,unlock-key,vault}/src/. This is an allow-list
# on purpose: build-agent.sh archives the whole tree and runs cargo inside
# each package, and cargo and rustup read configuration from every parent
# directory too, so a deny-list of known file names misses a repo-root
# Cargo.toml (`[patch.crates-io]`), a rust-toolchain file, and the like.
# Anything that changes what gets compiled in without the source showing it
# stays a human step: someone reads that diff before the bytes are committed.
# None of these is ever eligible, at any depth:
#   Cargo.lock, Cargo.toml (any Cargo.*), rust-toolchain, rust-toolchain.toml
#   (any rust-toolchain*), anything under a .cargo directory, build.rs,
#   .gitattributes (export-ignore and export-subst alter `git archive`),
#   scripts/build-agent.sh (the build definition, image pin included),
#   a symlink, and
#   any file inside agent/, unlock-key/ or vault/ other than src/** (tests,
#   benches and examples are not shipped, but are kept out to stay
#   conservative).
#
# Reads GITHUB_EVENT_NAME, GITHUB_BASE_REF, IS_FORK and ACTOR from the
# environment; needs the base branch fetched (checkout with fetch-depth: 0).
#
# CI runs the base branch's copy (`git show origin/<base>:<this path> | bash`),
# so a change here takes effect for pull requests opened after it merges.

set -u -o pipefail

no() { echo "helper-autocommit: $1" >&2; echo no; exit 0; }

[ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] || no "not a pull request"
[ "${IS_FORK:-false}" != "true" ] || no "fork pull requests cannot receive CI's commit"
case "${ACTOR:-}" in dependabot*) no "dependency updates are rebuilt by a person" ;; esac
case "${GITHUB_BASE_REF:-}" in release/*) ;; *) no "not a pull request into a release branch" ;; esac

base="origin/$GITHUB_BASE_REF"
git rev-parse --verify --quiet "$base" >/dev/null || no "base branch $base is not fetched"

raw="$(mktemp)" || no "could not create a temporary file"
trap 'rm -f "$raw"' EXIT
# --no-renames lists both sides of a rename; -z keeps odd file names intact.
git diff --raw --no-renames -z "$base"...HEAD >"$raw" 2>/dev/null \
  || no "could not diff against $base"

blocked=""
# `--raw -z` alternates `:<old mode> <new mode> <old sha> <new sha> <status>`
# with the path.
while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
  read -r old_mode new_mode _ <<<"${meta#:}"
  if [ "$old_mode" = "120000" ] || [ "$new_mode" = "120000" ]; then
    blocked="$blocked $path"; continue
  fi
  case "/$path" in
    */.cargo|*/.cargo/*) blocked="$blocked $path"; continue ;;
  esac
  case "${path##*/}" in
    Cargo.*|rust-toolchain*|build.rs|.gitattributes) blocked="$blocked $path"; continue ;;
  esac
  case "$path" in
    scripts/build-agent.sh) blocked="$blocked $path" ;;
    agent/src/*|unlock-key/src/*|vault/src/*) ;;
    agent/*|unlock-key/*|vault/*) blocked="$blocked $path" ;;
  esac
done <"$raw"
[ -z "$blocked" ] || no "dependencies, toolchain or build configuration changed ($(echo $blocked)); rebuild by hand"

echo "helper-autocommit: eligible" >&2
echo yes
