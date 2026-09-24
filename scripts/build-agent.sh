#!/usr/bin/env bash
# Build the plugin's helpers reproducibly: the SSH agent (agent/) and the
# quick-unlock envelope tool (unlock-key/).
#
# The helpers are committed, which is only defensible if anyone can rebuild the
# same bytes from source. This script is the single definition of the release
# build, locally and in CI. What fixes the bytes:
#
#   Cargo.lock              the exact dependency set          (committed, per package)
#   rust-toolchain.toml     the exact compiler                (committed, per package,
#                                                              and the same in each)
#   --target                the ABI                           (below)
#   --remap-path-prefix     build paths, which otherwise leak (below)
#   the container image     glibc, ld and strip               (PINNED_IMAGE)
#
# The image matters because glibc symbol versions and `strip` output change
# with the host. rustc embeds no timestamp (so no SOURCE_DATE_EPOCH), and no git
# commit is embedded: a binary cannot name the commit that tracks it.

set -o pipefail
set -u

# The pinned build environment; changing it means rebuilding and re-summing
# every binary in the same commit. By digest, not tag: the tag is rebuilt on
# new Debian bases (new glibc/binutils). Multi-arch digest of 2026-08-25.
PINNED_IMAGE="rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
SUPPORTED_TARGET="x86_64-unknown-linux-gnu"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Architecture-scoped so a second target needs no restructuring (x86_64 only
# for now).
OUTPUT_ARCH="x86_64-linux"
OUTPUT_DIR="$REPO_ROOT/bin/$OUTPUT_ARCH"
# Tracked artifacts as `<package directory>:<binary name>`. Separate packages
# and lockfiles, so a crate added to one cannot change the other's bytes.
ARTIFACTS=(
  "agent:qs-bitwarden-ssh-agent"
  "unlock-key:qs-bitwarden-unlock-key"
)
# One SHA256SUMS for every artifact, in `sha256sum -c` format.
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

# Only the target the committed binaries are for.
require_target() {
  local target="${1:-$SUPPORTED_TARGET}"
  [ "$target" = "$SUPPORTED_TARGET" ] \
    || fail "unsupported target '$target'; this release builds only $SUPPORTED_TARGET"
}

# Whether we are already inside the pinned environment (CI runs this inside
# the image, with no container runtime). QSBW_PINNED_BUILD is the claim, set by
# CI and by this script's container re-exec; the checks below verify it.
in_pinned_environment() {
  [ "${QSBW_PINNED_BUILD:-}" = "1" ] || return 1
  local pinned actual
  pinned="$(grep -oP 'channel\s*=\s*"\K[^"]+' "$REPO_ROOT/agent/rust-toolchain.toml" 2>/dev/null)"
  actual="$(rustc --version 2>/dev/null | cut -d' ' -f2)"
  [ -n "$pinned" ] && [ "$pinned" = "$actual" ] \
    || fail "this environment claims to be the pinned one but carries rustc ${actual:-unknown}, not $pinned"

  # The right rustc is not enough: also require the image's Debian bookworm,
  # since glibc and binutils are what the image pins.
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
  # Omarchy uses `sudo docker` rather than the docker group (which is
  # equivalent to passwordless root).
  if docker info >/dev/null 2>&1; then echo "docker"; return 0; fi
  if sudo -n docker info >/dev/null 2>&1; then echo "sudo docker"; return 0; fi
  if podman info >/dev/null 2>&1; then echo "podman"; return 0; fi
  return 1
}

# Re-run inside the pinned image, with the glibc, linker and strip that
# produced the committed bytes.
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

# Flags that remove build-path variance, including $CARGO_HOME's registry
# paths, which leak into panic messages and debug sections.
rustflags_for() {
  local src="$1" cargo_home="${2:-${CARGO_HOME:-$HOME/.cargo}}"
  printf -- '--remap-path-prefix=%s=/src --remap-path-prefix=%s/registry=/registry' \
    "$src" "$cargo_home"
}

# One cargo invocation with everything that affects output explicit. The
# target dir must be inside the (remapped) source root: build-script output
# paths reach the binary. All packages share it; shared dependencies are
# reused only when identical.
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

# Export HEAD (not the working tree) to a clean directory and build there.
# Every mode uses this, so release, reproducibility check and drift
# comparison are the same procedure.
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

# Build twice from different absolute paths; a leaked path shows up as a
# digest mismatch.
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

  # Only meaningful inside the pinned environment, where the tracked bytes
  # were built; a host build would report drift that does not exist.
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
  # Report every artifact before the verdict; an untracked binary is drift
  # too.
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
  # Paths relative to bin/, one line per artifact (the panel checks each
  # binary against its own line).
  ( cd "$REPO_ROOT/bin" && sha256sum "${listed[@]}" > "$SUMS_FILE" )
  note "wrote ${listed[*]/#/bin/} and bin/SHA256SUMS"
}

# Report the decision without acting on it (for people, and for tests).
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
