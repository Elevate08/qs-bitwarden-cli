#!/usr/bin/env bash
# Build the SSH agent helper reproducibly.
#
# The compiled helper is committed to this repository. That is only defensible
# if anyone can rebuild it from the committed source and get the same bytes --
# otherwise the binary is an unauditable blob that happens to sit next to some
# source code. This script is the one entry point that produces it, locally and
# in CI, so there is a single definition of what "the release build" means.
#
# What fixes the output bytes:
#
#   Cargo.lock              the exact dependency set          (committed)
#   rust-toolchain.toml     the exact compiler                (committed)
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
OUTPUT_DIR="$REPO_ROOT/bin"
OUTPUT_NAME="qs-bitwarden-ssh-agent"

usage() {
  cat <<'USAGE'
Usage: scripts/build-agent.sh [--verify-reproducible] [--check] [--allow-unpinned]

  (no flags)            Build the release helper into bin/ and write its checksum.
  --verify-reproducible Build twice from two different absolute paths and
                        require byte-identical output. Writes nothing.
  --check               Report whether bin/ matches a fresh build, without
                        modifying the repository. Exit 1 on drift.
  --allow-unpinned      Permit a host-toolchain build when no container runtime
                        is available. The result is NOT reproducible and is
                        refused by --verify-reproducible.
USAGE
}

fail() { printf 'build-agent: %s\n' "$1" >&2; exit 1; }
note() { printf 'build-agent: %s\n' "$1" >&2; }

# --- preconditions ---------------------------------------------------------

require_lockfile() {
  [ -f "$REPO_ROOT/agent/Cargo.lock" ] \
    || fail "agent/Cargo.lock is missing; a release build has no dependency set without it"
  [ -f "$REPO_ROOT/agent/rust-toolchain.toml" ] \
    || fail "agent/rust-toolchain.toml is missing; the compiler is not pinned"
}

# A target other than the one the committed binary is for would produce bytes
# nobody can compare against it.
require_target() {
  local target="${1:-$SUPPORTED_TARGET}"
  [ "$target" = "$SUPPORTED_TARGET" ] \
    || fail "unsupported target '$target'; this release builds only $SUPPORTED_TARGET"
}

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
build_into() {
  local src="$1" target_dir="$2"
  ( cd "$src/agent" \
    && CARGO_TARGET_DIR="$target_dir" \
       RUSTFLAGS="$(rustflags_for "$src")" \
       cargo build --locked --release --target "$SUPPORTED_TARGET" >&2 )
}

built_binary() {
  printf '%s/%s/release/%s' "$1" "$SUPPORTED_TARGET" "$OUTPUT_NAME"
}

digest() { sha256sum "$1" | cut -d' ' -f1; }

# --- modes -----------------------------------------------------------------

# Build twice from genuinely different absolute paths. Copying the source to a
# second location is the point: a path that leaked into the binary shows up
# here as a digest mismatch and nowhere else.
verify_reproducible() {
  local runtime
  if ! runtime="$(container_runtime)"; then
    fail "no container runtime, so the system toolchain is unpinned and the result would not be reproducible.
       This check refuses to report success it cannot support. Run it in CI, where the
       pinned image is used, or start a runtime locally. See --allow-unpinned for a
       plain build that makes no reproducibility claim."
  fi
  note "using container runtime: $runtime"

  local work first second
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  first="$work/path-one"
  second="$work/a-considerably-longer-second-path"

  for dest in "$first" "$second"; do
    mkdir -p "$dest"
    git -C "$REPO_ROOT" archive HEAD | tar -x -C "$dest" \
      || fail "could not export a clean tree; commit or stash first"
  done

  local a b
  build_into "$first" "$first/target" || fail "the first build failed"
  build_into "$second" "$second/target" || fail "the second build failed"
  a="$(digest "$(built_binary "$first/target")")"
  b="$(digest "$(built_binary "$second/target")")"

  printf 'path one: %s\npath two: %s\n' "$a" "$b"
  if [ "$a" != "$b" ]; then
    fail "the two builds differ, so something in the build path reached the binary"
  fi
  note "identical across both paths: $a"
}

# Report drift without touching the repository, so it is safe in a PR gate.
check_committed() {
  local committed="$OUTPUT_DIR/$OUTPUT_NAME"
  [ -f "$committed" ] || fail "no committed binary at bin/$OUTPUT_NAME"
  local work
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  git -C "$REPO_ROOT" archive HEAD | tar -x -C "$work"
  build_into "$work" "$work/target" || fail "the comparison build failed"
  local fresh
  fresh="$(digest "$(built_binary "$work/target")")"
  local have
  have="$(digest "$committed")"
  printf 'committed: %s\nfresh:     %s\n' "$have" "$fresh"
  [ "$have" = "$fresh" ] || fail "bin/$OUTPUT_NAME does not match a build of this source"
  note "the committed binary matches this source"
}

build_release() {
  local allow_unpinned="$1"
  local runtime
  if ! runtime="$(container_runtime)"; then
    [ "$allow_unpinned" = "yes" ] || fail "no container runtime; the system toolchain would be unpinned.
       Pass --allow-unpinned to build anyway, understanding the result is not the release artifact."
    note "WARNING: building with the host toolchain. These bytes are not reproducible"
    note "         and must not be committed as the release binary."
  fi
  mkdir -p "$OUTPUT_DIR"
  local work
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  build_into "$REPO_ROOT" "$work/target" || fail "the build failed"
  install -m 0755 "$(built_binary "$work/target")" "$OUTPUT_DIR/$OUTPUT_NAME"
  ( cd "$OUTPUT_DIR" && sha256sum "$OUTPUT_NAME" > "$OUTPUT_NAME.sha256" )
  note "wrote bin/$OUTPUT_NAME and its checksum"
}

# --- entry point -----------------------------------------------------------

main() {
  local mode="build" allow_unpinned="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --verify-reproducible) mode="verify" ;;
      --check) mode="check" ;;
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
    verify) verify_reproducible ;;
    check) check_committed ;;
    build) build_release "$allow_unpinned" ;;
  esac
}

main "$@"
