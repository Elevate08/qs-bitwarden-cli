#!/usr/bin/env bash
# Whether CI may rebuild and commit the helper binaries for this pull request.
# Prints `yes` or `no`, and the reason on stderr.
#
# Only a same-repository PR into a release branch that leaves the dependency
# set and toolchain alone. A change to Cargo.lock, Cargo.toml or
# rust-toolchain.toml changes what gets compiled in, so its rebuild stays a
# human step: someone reads that diff before the bytes are committed.
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
changed="$(git diff --name-only "$base"...HEAD -- \
  agent/Cargo.lock agent/Cargo.toml agent/rust-toolchain.toml \
  unlock-key/Cargo.lock unlock-key/Cargo.toml unlock-key/rust-toolchain.toml)" \
  || no "could not diff against $base"
[ -z "$changed" ] || no "dependencies or toolchain changed ($(echo $changed)); rebuild by hand"

echo "helper-autocommit: eligible" >&2
echo yes
