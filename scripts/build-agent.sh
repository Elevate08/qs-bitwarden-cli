#!/usr/bin/env bash
# Build the plugin's helpers reproducibly: the SSH agent (agent/) and the
# quick-unlock envelope tool (unlock-key/).
#
# The compiled helpers are committed to this repository. That is only
# defensible if anyone can rebuild them from the committed source and get the
# same bytes -- otherwise a binary is an unauditable blob that happens to sit
# next to some source code. This script is the one entry point that produces
# them, locally and
# in CI, so there is a single definition of what "the release build" means.
#
# What fixes the output bytes:
#
#   Cargo.lock              the exact dependency set          (committed, per package)
#   rust-toolchain.toml     the exact compiler                (committed, per package,
#                                                              and the same in each)
#   --target                the ABI                           (below)
#   --remap-path-prefix     build paths, which otherwise leak (below)
#   the container image     glibc, ld and strip               (PINNED_IMAGE)
#
# The last one is why a bare runner is not enough. A GNU-linked binary carries
# symbol version requirements from the glibc it built against, and `strip`
# output differs between binutils releases -- so `ubuntu-latest` drifting
# forward would change the bytes with nothing in the repository having changed.
#
# rustc does not consume SOURCE_DATE_EPOCH and embeds no build timestamp, so
# that variable is deliberately not part of this. The git commit is likewise
# not embedded: a binary tracked by the same commit that names it cannot be
# reproduced from that commit.

set -o pipefail
set -u

# The pinned build environment. Changing it means regenerating the binary and
# its checksum in the same commit.
#
# Pinned by digest rather than tag: a tag is a moving pointer, and
# `rust:1.98.0-bookworm` is rebuilt on new Debian base images, which changes
# glibc and binutils underneath an unchanged Rust version. This is the
# multi-arch manifest digest published 2026-08-25.
PINNED_IMAGE="rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SUPPORTED_TARGET="x86_64-unknown-linux-gnu"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Architecture-scoped from the start. v1 ships x86_64 only, but a flat bin/
# would have to be restructured the day a second target appears, and the
# checksum file would have to change shape with it.
OUTPUT_ARCH="x86_64-linux"
OUTPUT_DIR="$REPO_ROOT/bin/$OUTPUT_ARCH"
# Every tracked artifact, as `<package directory>:<binary name>`. Separate
# Cargo packages, each with its own manifest and lockfile: a crate added to one
# must not change the other's bytes, and in a shared package it did (the SSH
# helper went from f80366fe to 5c2fcc7b when the unlock tool was added beside
# it, with no SSH source change).
ARTIFACTS=(
  "agent:qs-bitwarden-ssh-agent"
  "unlock-key:qs-bitwarden-unlock-key"
)
# One SHA256SUMS covering every tracked artifact, in the format `sha256sum -c`
# reads, rather than a sidecar file per binary.
SUMS_FILE="$REPO_ROOT/bin/SHA256SUMS"

usage() {
  cat <<'USAGE'
Usage: scripts/build-agent.sh [--verify-reproducible] [--compare-tracked]
                              [--allow-unpinned] [--explain]

  (no flags)            Build every release helper into bin/<arch>/ and write
                        bin/SHA256SUMS.
  --verify-reproducible Build twice from two different absolute paths and
                        require byte-identical output. Writes nothing.
  --compare-tracked     Report whether every tracked binary matches a fresh
                        build of this source, without modifying the repository.
                        Exit 1 on drift, including a binary not yet tracked.
  --allow-unpinned      Permit a host-toolchain build when no container runtime
                        is available. The result is NOT reproducible and is
                        refused by --verify-reproducible.
  --explain             Say which build environment this would use and stop.
                        Runs nothing, pulls nothing, writes nothing.
USAGE
}

fail() { printf 'build-agent: %s\n' "$1" >&2; exit 1; }
note() { printf 'build-agent: %s\n' "$1" >&2; }

# --- preconditions ---------------------------------------------------------

require_lockfile() {
  local spec package channel first=""
  for spec in "${ARTIFACTS[@]}"; do
    package="${spec%%:*}"
    [ -f "$REPO_ROOT/$package/Cargo.lock" ] \
      || fail "$package/Cargo.lock is missing; a release build has no dependency set without it"
    [ -f "$REPO_ROOT/$package/rust-toolchain.toml" ] \
      || fail "$package/rust-toolchain.toml is missing; the compiler is not pinned"
    # One pinned image carries one rustc, so every package has to name it.
    channel="$(grep -oP 'channel\s*=\s*"\K[^"]+' "$REPO_ROOT/$package/rust-toolchain.toml" 2>/dev/null)"
    [ -n "$first" ] || first="$channel"
    [ "$channel" = "$first" ] \
      || fail "$package/rust-toolchain.toml pins $channel but ${ARTIFACTS[0]%%:*}/ pins $first;
       the pinned image carries one compiler, so every package must name the same one"
  done
}

# A target other than the one the committed binary is for would produce bytes
# nobody can compare against it.
require_target() {
  local target="${1:-$SUPPORTED_TARGET}"
  [ "$target" = "$SUPPORTED_TARGET" ] \
    || fail "unsupported target '$target'; this release builds only $SUPPORTED_TARGET"
}

# Are we already running inside the pinned build environment?
#
# This is the question that matters, and it is not the same as "can I start a
# container". CI runs this script *inside* the pinned image, where no
# container runtime exists and none is wanted -- an earlier version conflated
# the two and refused to build in the one environment it was written for.
#
# QSBW_PINNED_BUILD is the claim, set by the release workflow and by this
# script when it re-executes itself in a container. The compiler check below
# is the part that does not take that claim on trust: if the environment says
# it is pinned but carries a different rustc than rust-toolchain.toml names,
# the claim is wrong and the build stops.
in_pinned_environment() {
  [ "${QSBW_PINNED_BUILD:-}" = "1" ] || return 1
  local pinned actual
  pinned="$(grep -oP 'channel\s*=\s*"\K[^"]+' "$REPO_ROOT/agent/rust-toolchain.toml" 2>/dev/null)"
  actual="$(rustc --version 2>/dev/null | cut -d' ' -f2)"
  [ -n "$pinned" ] && [ "$pinned" = "$actual" ] \
    || fail "this environment claims to be the pinned one but carries rustc ${actual:-unknown}, not $pinned"

  # The compiler check alone is too weak: a host may happen to carry the same
  # rustc while its glibc and binutils -- the things the image exists to pin --
  # are entirely different. The pinned image is Debian bookworm, so verify
  # that too. It is cheap, and it catches the case of a developer setting the
  # variable on a machine that merely has the right Rust.
  local os_id os_codename
  os_id="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")"
  os_codename="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")"
  [ "$os_id" = "debian" ] && [ "$os_codename" = "bookworm" ] \
    || fail "this environment claims to be the pinned one but is ${os_id:-unknown}/${os_codename:-unknown},
       not debian/bookworm. The image pins glibc and binutils, not just the compiler."
  return 0
}

# A runtime we could use to *enter* the pinned environment from outside it.
container_runtime() {
  # Omarchy's own convention is `sudo docker`: it does not put users in the
  # docker group, because that group is equivalent to passwordless root. A
  # repository whose purpose is guarding private keys should not require that
  # to build.
  if docker info >/dev/null 2>&1; then echo "docker"; return 0; fi
  if sudo -n docker info >/dev/null 2>&1; then echo "sudo docker"; return 0; fi
  if podman info >/dev/null 2>&1; then echo "podman"; return 0; fi
  return 1
}

# Re-run this script inside the pinned image, so a local reproduction uses the
# same glibc, linker and strip that produced the committed bytes.
reexec_in_container() {
  local runtime="$1"
  shift
  note "entering the pinned image with: $runtime"
  # shellcheck disable=SC2086
  $runtime run --rm \
    -e QSBW_PINNED_BUILD=1 \
    -v "$REPO_ROOT:/work" -w /work \
    "$PINNED_IMAGE" \
    /work/scripts/build-agent.sh "$@"
}

# --- the build itself ------------------------------------------------------

# Compose the flags that remove build-path variance. The registry path is the
# one that usually leaks: dependency source paths end up in panic messages and
# debug sections, and $CARGO_HOME differs per machine and per CI runner.
rustflags_for() {
  local src="$1" cargo_home="${2:-${CARGO_HOME:-$HOME/.cargo}}"
  printf -- '--remap-path-prefix=%s=/src --remap-path-prefix=%s/registry=/registry' \
    "$src" "$cargo_home"
}

# One cargo invocation, with everything that affects output stated explicitly.
#
# The target directory must live *inside* the source root. It is remapped
# along with everything else under it, and build-script output paths reach the
# binary: a target directory somewhere else is an unremapped path that changes
# the bytes. That is not hypothetical -- the release build used a separate
# temporary directory and produced a different digest from the two builds
# --verify-reproducible had just declared identical.
#
# Every package builds into the same target directory. Each is its own Cargo
# project, so a dependency shared between them is reused only where its
# version, features and profile are identical -- the same artifact either
# package would have built alone.
build_into() {
  local src="$1" spec package
  for spec in "${ARTIFACTS[@]}"; do
    package="${spec%%:*}"
    ( cd "$src/$package" \
      && CARGO_TARGET_DIR="$src/target" \
         RUSTFLAGS="$(rustflags_for "$src")" \
         cargo build --locked --release --target "$SUPPORTED_TARGET" >&2 ) || return 1
  done
}

# Export the committed tree somewhere clean and build it there.
#
# Every mode goes through this, so a release, a reproducibility check and a
# drift comparison are literally the same procedure. They diverged once, and
# the divergence was invisible until two digests of the same source disagreed.
#
# HEAD rather than the working tree: a release artifact should not contain
# uncommitted changes, and the comparison modes have to build what the
# repository actually says.
build_clean_copy() {
  local dest="$1"
  mkdir -p "$dest" || return 1
  git -C "$REPO_ROOT" archive HEAD | tar -x -C "$dest" || return 1
  build_into "$dest" || return 1
  printf '%s/target/%s/release' "$dest" "$SUPPORTED_TARGET"
}

binary_name() { printf '%s' "${1#*:}"; }

digest() { sha256sum "$1" | cut -d' ' -f1; }

# --- modes -----------------------------------------------------------------

# Build twice from genuinely different absolute paths. Copying the source to a
# second location is the point: a path that leaked into the binary shows up
# here as a digest mismatch and nowhere else.
verify_reproducible() {
  if ! in_pinned_environment; then
    local runtime
    if runtime="$(container_runtime)"; then
      reexec_in_container "$runtime" --verify-reproducible
      return $?
    fi
    fail "not in the pinned build environment and no container runtime to enter one, so the
       system toolchain is unpinned and the result would not be reproducible. This check
       refuses to report success it cannot support. It runs in CI, which executes it inside
       the pinned image. See --allow-unpinned for a plain build that makes no such claim."
  fi
  note "building in the pinned environment"

  local work first second
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  first="$work/path-one"
  second="$work/a-considerably-longer-second-path"

  local one two spec name a b differ=0
  one="$(build_clean_copy "$first")" || fail "the first build failed"
  two="$(build_clean_copy "$second")" || fail "the second build failed"

  for spec in "${ARTIFACTS[@]}"; do
    name="$(binary_name "$spec")"
    a="$(digest "$one/$name")"
    b="$(digest "$two/$name")"
    printf '%s\n  path one: %s\n  path two: %s\n' "$name" "$a" "$b"
    if [ "$a" = "$b" ]; then
      note "$name identical across both paths: $a"
    else
      differ=1
    fi
  done
  [ "$differ" -eq 0 ] \
    || fail "the two builds differ, so something in the build path reached a binary"
}

# Report drift without touching the repository, so it is safe in a PR gate.
compare_tracked() {

  # The comparison is only worth anything from inside the pinned environment.
  # The tracked bytes were produced there, and the image pins glibc and
  # binutils as well as the compiler -- so a host build with the right rustc
  # and a different libc reports drift that does not exist. This mode is the
  # PR gate: it was the one mode that could fail for a reason having nothing
  # to do with the source it was asked about.
  if ! in_pinned_environment; then
    local runtime
    if runtime="$(container_runtime)"; then
      reexec_in_container "$runtime" --compare-tracked
      return $?
    fi
    fail "not in the pinned build environment and no container runtime to enter one. A build
       here would use the host toolchain, whose output differs from the tracked bytes for
       reasons that are not drift -- so this check refuses to report a mismatch it cannot
       stand behind. It runs in CI, which executes it inside the pinned image."
  fi
  note "comparing in the pinned environment"

  local work
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  local built spec name committed have fresh drifted=""
  built="$(build_clean_copy "$work/source")" || fail "the comparison build failed"
  # Every artifact is compared and reported before the verdict, so one drift
  # does not hide another. A binary that is not tracked yet is drift too: the
  # candidate this source builds is exactly what has to be committed.
  for spec in "${ARTIFACTS[@]}"; do
    name="$(binary_name "$spec")"
    committed="$OUTPUT_DIR/$name"
    fresh="$(digest "$built/$name")"
    if [ -f "$committed" ]; then have="$(digest "$committed")"; else have="(not tracked)"; fi
    printf '%s\n  tracked: %s\n  fresh:   %s\n' "$name" "$have" "$fresh"
    [ "$have" = "$fresh" ] || drifted="$drifted bin/$OUTPUT_ARCH/$name"
  done
  [ -z "$drifted" ] || fail "does not match a build of this source:$drifted"
  note "every tracked binary matches this source"
}

build_release() {
  local allow_unpinned="$1"
  if ! in_pinned_environment; then
    local runtime
    if runtime="$(container_runtime)"; then
      reexec_in_container "$runtime"
      return $?
    fi
    [ "$allow_unpinned" = "yes" ] || fail "not in the pinned build environment and no container runtime
       to enter one, so the system toolchain would be unpinned. Pass --allow-unpinned to build
       anyway, understanding the result is not the release artifact."
    note "WARNING: building with the host toolchain. These bytes are not reproducible"
    note "         and must not be committed as the release binary."
  fi
  mkdir -p "$OUTPUT_DIR"
  local work
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  local built spec name listed=()
  built="$(build_clean_copy "$work/source")" || fail "the build failed"
  for spec in "${ARTIFACTS[@]}"; do
    name="$(binary_name "$spec")"
    install -m 0755 "$built/$name" "$OUTPUT_DIR/$name"
    listed+=("$OUTPUT_ARCH/$name")
  done
  # Paths relative to bin/, so `sha256sum -c SHA256SUMS` works from there
  # whatever the checkout is called. One line per artifact: the panel checks
  # each binary against its own line, so one stale file never disables the
  # other's feature.
  ( cd "$REPO_ROOT/bin" && sha256sum "${listed[@]}" > "$SUMS_FILE" )
  note "wrote ${listed[*]/#/bin/} and bin/SHA256SUMS"
}

# Report the decision without acting on it. Useful for a person wondering why
# a build refused, and for tests that need to check the decision logic without
# pulling an image and running two full builds to find out.
explain() {
  if in_pinned_environment; then
    printf 'environment: pinned (building here directly)\n'
    return 0
  fi
  local runtime
  if runtime="$(container_runtime)"; then
    printf 'environment: not pinned, but reachable via %s\n' "$runtime"
    printf 'image:       %s\n' "$PINNED_IMAGE"
    return 0
  fi
  printf 'environment: not pinned and no container runtime to enter one\n'
  printf 'consequence: a build here would not be reproducible; --verify-reproducible refuses\n'
  return 0
}

# --- entry point -----------------------------------------------------------

main() {
  local mode="build" allow_unpinned="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --verify-reproducible) mode="verify" ;;
      --explain) mode="explain" ;;
      --compare-tracked) mode="compare" ;;
      --allow-unpinned) allow_unpinned="yes" ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; fail "unknown argument '$1'" ;;
    esac
    shift
  done

  require_lockfile
  require_target "${CARGO_BUILD_TARGET:-$SUPPORTED_TARGET}"
  command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"

  case "$mode" in
    explain) explain ;;
    verify) verify_reproducible ;;
    compare) compare_tracked ;;
    build) build_release "$allow_unpinned" ;;
  esac
}

main "$@"
