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
#   anything under scripts/ (the build definition, image pin included, and
#   this gate) or .github/ (the workflows that run the gate and the build),
#   a symlink, and
#   any file inside agent/, unlock-key/ or vault/ other than src/** (tests,
#   benches and examples are not shipped, but are kept out to stay
#   conservative).
#
# This decides what an honest pull request gets committed for it. It is not
# a boundary against someone who can push to the repository: a pull request
# runs its own copy of the workflows, and its author can push to its branch.
#
# Reads GITHUB_EVENT_NAME, GITHUB_BASE_REF, IS_FORK and ACTOR from the
# environment; needs the base branch fetched (checkout with fetch-depth: 0).
# BASE_SHA and HEAD_SHA, when set, are the two commits compared (CI passes the
# pull request's own, so every workflow judges the same pair whatever it has
# checked out). Without them: the remote-tracking base branch, named in full
# so that a tag called origin/<base> cannot stand in for it, and HEAD.
#
# CI runs the base branch's copy (`git show <base commit>:<this path> | bash`),
# so a change here takes effect for pull requests opened after it merges.

set -u -o pipefail

no() { echo "helper-autocommit: $1" >&2; echo no; exit 0; }

[ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] || no "not a pull request"
[ "${IS_FORK:-false}" != "true" ] || no "fork pull requests cannot receive CI's commit"
case "${ACTOR:-}" in dependabot*) no "dependency updates are rebuilt by a person" ;; esac
case "${GITHUB_BASE_REF:-}" in release/*) ;; *) no "not a pull request into a release branch" ;; esac

# A full object id or nothing: never a name git could resolve to something else.
commit_id() { [[ "$1" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; }
if [ -n "${BASE_SHA:-}" ]; then
  commit_id "$BASE_SHA" || no "BASE_SHA is not a commit id"
  base="$BASE_SHA"
else
  base="refs/remotes/origin/$GITHUB_BASE_REF"
fi
if [ -n "${HEAD_SHA:-}" ]; then
  commit_id "$HEAD_SHA" || no "HEAD_SHA is not a commit id"
  head="$HEAD_SHA"
else
  head="HEAD"
fi
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || no "the base commit ($base) is not fetched"
git rev-parse --verify --quiet "$head^{commit}" >/dev/null || no "the head commit ($head) is not fetched"

raw="$(mktemp)" || no "could not create a temporary file"
trap 'rm -f "$raw"' EXIT
# --no-renames lists both sides of a rename; -z keeps odd file names intact.
git diff --raw --no-renames -z "$base...$head" >"$raw" 2>/dev/null \
  || no "could not diff against $base"

blocked=()
# `--raw -z` alternates `:<old mode> <new mode> <old sha> <new sha> <status>`
# with the path.
while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
  read -r old_mode new_mode _ <<<"${meta#:}"
  if [ "$old_mode" = "120000" ] || [ "$new_mode" = "120000" ]; then
    blocked+=("$path"); continue
  fi
  case "/$path" in
    */.cargo|*/.cargo/*) blocked+=("$path"); continue ;;
  esac
  case "${path##*/}" in
    Cargo.*|rust-toolchain*|build.rs|.gitattributes) blocked+=("$path"); continue ;;
  esac
  case "$path" in
    scripts/*|.github/*) blocked+=("$path") ;;
    agent/src/*|unlock-key/src/*|vault/src/*) ;;
    agent/*|unlock-key/*|vault/*) blocked+=("$path") ;;
  esac
done <"$raw"
# The names are the pull request's: shell-escaped (%q), so one cannot break
# the line and start another that the runner would read as a command (`::`).
[ "${#blocked[@]}" -eq 0 ] \
  || no "dependencies, toolchain, build configuration, scripts or workflows changed ($(printf '%q ' "${blocked[@]}" | sed 's/ $//')); rebuild by hand"

echo "helper-autocommit: eligible" >&2
echo yes
