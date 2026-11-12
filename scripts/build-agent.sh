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
#   --target                the ABI, one per architecture     (below)
#   --remap-path-prefix     build paths, which otherwise leak (below)
#   the container image     glibc, ld and strip               (PINNED_IMAGE)
#
# The image matters because glibc symbol versions and `strip` output change
# with the host. Each architecture is built natively, in that architecture's
# variant of the same multi-arch image: CI uses an arm64 runner for aarch64,
# and a container runtime elsewhere can emulate one (`--platform linux/arm64`
# through qemu binfmt). No cross-linker is involved, so both builds use the
# image's own gcc, glibc and strip, and nothing is installed on top of it. rustc embeds no timestamp (so no SOURCE_DATE_EPOCH), and no git
# commit is embedded: a binary cannot name the commit that tracks it.

set -o pipefail
set -u

# The pinned build environment; changing it means rebuilding and re-summing
# every binary in the same commit. By digest, not tag: the tag is rebuilt on
# new Debian bases (new glibc/binutils). Multi-arch digest of 2026-08-25.
PINNED_IMAGE="rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
# Every architecture a release ships, as `uname -m` names it, and the Rust
# target each is built for. The panel's table (HELPER_ARCHITECTURES in
# BitwardenModel.js) must list the same ones.
SUPPORTED_ARCHES=(x86_64 aarch64)
target_for() {
  case "$1" in
    x86_64) printf 'x86_64-unknown-linux-gnu' ;;
    aarch64) printf 'aarch64-unknown-linux-gnu' ;;
    *) return 1 ;;
  esac
}
# The container platform that carries each architecture's image variant.
platform_for() {
  case "$1" in
    x86_64) printf 'linux/amd64' ;;
    aarch64) printf 'linux/arm64' ;;
    *) return 1 ;;
  esac
}
# `uname -m` spellings, normalised to the names above (or nothing).
normalise_arch() {
  case "$1" in
    x86_64|amd64) printf 'x86_64' ;;
    aarch64|arm64) printf 'aarch64' ;;
    *) return 1 ;;
  esac
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Set by select_arch from --arch, or this machine's architecture: the target,
# and the architecture-scoped output directory bin/<arch>-linux/.
ARCH=""
SUPPORTED_TARGET=""
OUTPUT_ARCH=""
OUTPUT_DIR=""
# Tracked artifacts as `<package directory>:<binary name>`. Separate packages
# and lockfiles, so a crate added to one cannot change the other's bytes.
ARTIFACTS=(
  "agent:qs-bitwarden-ssh-agent"
  "unlock-key:qs-bitwarden-unlock-key"
  "vault:qs-bitwarden-vault"
)
# One SHA256SUMS for every artifact, in `sha256sum -c` format.
SUMS_FILE="$REPO_ROOT/bin/SHA256SUMS"

usage() {
  cat <<'USAGE'
Usage: scripts/build-agent.sh [--arch x86_64|aarch64] [--verify-reproducible]
                              [--compare-tracked] [--ci] [--allow-unpinned]
                              [--explain]

  (no flags)            Build every release helper into bin/<arch>-linux/ and
                        update that architecture's lines in bin/SHA256SUMS.
  --arch ARCH           The architecture to build (default: this machine's).
                        Builds are native: outside the pinned image the
                        container runs that architecture's variant (another
                        architecture needs qemu binfmt); inside it, ARCH must
                        be the machine's own.
  --verify-reproducible Build twice from two different absolute paths and
                        require byte-identical output. Writes nothing.
  --compare-tracked     Report whether every tracked binary matches a fresh
                        build of this source, without modifying the repository.
                        Exit 1 on drift, including a binary not yet tracked.
  --ci                  All three from two builds, as CI runs them: build twice
                        and require identical output, report whether every
                        tracked binary matches, then write the build to bin/
                        and bin/SHA256SUMS as the candidate. Exit 1 if the
                        builds differ or fail, 3 if they agree but the tracked
                        binaries drifted (the candidate is written either way).
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

# The architecture to build: --arch, or this machine's. Fixes the target and
# the output directory every mode uses.
select_arch() {
  local requested="$1" host
  host="$(normalise_arch "$(uname -m)")" || host=""
  if [ -z "$requested" ]; then
    [ -n "$host" ] || fail "this machine is $(uname -m), which no release ships; pass --arch with one of: ${SUPPORTED_ARCHES[*]}"
    requested="$host"
  fi
  ARCH="$(normalise_arch "$requested")" \
    || fail "unsupported architecture '$requested'; releases ship: ${SUPPORTED_ARCHES[*]}"
  SUPPORTED_TARGET="$(target_for "$ARCH")"
  OUTPUT_ARCH="$ARCH-linux"
  OUTPUT_DIR="$REPO_ROOT/bin/$OUTPUT_ARCH"
}

# Only the target the committed binaries are for.
require_target() {
  local target="${1:-$SUPPORTED_TARGET}"
  [ "$target" = "$SUPPORTED_TARGET" ] \
    || fail "unsupported target '$target'; this build is for $SUPPORTED_TARGET (--arch $ARCH)"
}

# Inside the image the build is native: the image has no cross-linker, and
# installing one would put an unpinned package into the release bytes.
require_native() {
  local host
  host="$(normalise_arch "$(uname -m)")" || host="$(uname -m)"
  [ "$host" = "$ARCH" ] \
    || fail "this $host environment cannot build $ARCH natively. Run the script outside the
       image with --arch $ARCH, so the container runtime starts the $(platform_for "$ARCH") variant
       (on another architecture that needs qemu binfmt), or build on a $ARCH machine."
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
    --platform "$(platform_for "$ARCH")" \
    -e QSBW_PINNED_BUILD=1 \
    -v "$REPO_ROOT:/work" -w /work \
    "$PINNED_IMAGE" \
    /work/scripts/build-agent.sh --arch "$ARCH" "$@"
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

# Replace this architecture's lines in bin/SHA256SUMS and keep every other
# architecture's, sorted by path. Paths are relative to bin/, one line per
# artifact (the panel checks each binary against its own line).
write_sums() {
  local kept="" listed=("$@")
  if [ -f "$SUMS_FILE" ]; then
    kept="$(grep -v "  $OUTPUT_ARCH/" "$SUMS_FILE" || true)"
  fi
  ( cd "$REPO_ROOT/bin" \
    && { [ -z "$kept" ] || printf '%s\n' "$kept"; sha256sum "${listed[@]}"; } \
       | LC_ALL=C sort -k2 > "$SUMS_FILE.new" ) \
    && mv "$SUMS_FILE.new" "$SUMS_FILE"
}

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
  require_native
  note "building $ARCH in the pinned environment"

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
  require_native
  note "comparing $ARCH in the pinned environment"

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
  require_native
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
  write_sums "${listed[@]}" || fail "could not write bin/SHA256SUMS"
  note "wrote ${listed[*]/#/bin/} and their lines in bin/SHA256SUMS"
}

# --verify-reproducible, --compare-tracked and the release build in one pass:
# two builds instead of four. The comparison reads bin/ before the candidate
# replaces it.
ci_build() {
  if ! in_pinned_environment; then
    local runtime
    if runtime="$(container_runtime)"; then
      reexec_in_container "$runtime" --ci
      return $?
    fi
    fail "not in the pinned build environment and no container runtime to enter one"
  fi
  require_native
  note "building $ARCH twice in the pinned environment"

  local work one two spec name a b have differ=0 drifted="" listed=()
  work="$(mktemp -d)" || fail "could not create a work directory"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" EXIT
  one="$(build_clean_copy "$work/path-one")" || fail "the first build failed"
  two="$(build_clean_copy "$work/a-considerably-longer-second-path")" || fail "the second build failed"

  for spec in "${ARTIFACTS[@]}"; do
    name="$(binary_name "$spec")"
    a="$(digest "$one/$name")"
    b="$(digest "$two/$name")"
    if [ -f "$OUTPUT_DIR/$name" ]; then have="$(digest "$OUTPUT_DIR/$name")"; else have="(not tracked)"; fi
    printf '%s\n  path one: %s\n  path two: %s\n  tracked:  %s\n' "$name" "$a" "$b" "$have"
    [ "$a" = "$b" ] || differ=1
    [ "$have" = "$a" ] || drifted="$drifted bin/$OUTPUT_ARCH/$name"
  done
  [ "$differ" -eq 0 ] || fail "the two builds differ, so something in the build path reached a binary"
  note "every helper is identical across both paths"

  mkdir -p "$OUTPUT_DIR"
  for spec in "${ARTIFACTS[@]}"; do
    name="$(binary_name "$spec")"
    install -m 0755 "$one/$name" "$OUTPUT_DIR/$name"
    listed+=("$OUTPUT_ARCH/$name")
  done
  write_sums "${listed[@]}" || fail "could not write bin/SHA256SUMS"
  note "wrote the candidate: ${listed[*]/#/bin/} and their lines in bin/SHA256SUMS"

  if [ -n "$drifted" ]; then
    note "does not match a build of this source:$drifted"
    return 3
  fi
  note "every tracked binary matches this source"
}

# Report the decision without acting on it (for people, and for tests).
explain() {
  printf 'arch:        %s (%s, bin/%s/)\n' "$ARCH" "$SUPPORTED_TARGET" "$OUTPUT_ARCH"
  if in_pinned_environment; then
    printf 'environment: pinned (building here directly)\n'
    return 0
  fi
  local runtime
  if runtime="$(container_runtime)"; then
    printf 'environment: not pinned, but reachable via %s\n' "$runtime"
    printf 'image:       %s (%s)\n' "$PINNED_IMAGE" "$(platform_for "$ARCH")"
    return 0
  fi
  printf 'environment: not pinned and no container runtime to enter one\n'
  printf 'consequence: a build here would not be reproducible; --verify-reproducible refuses\n'
  return 0
}

# --- entry point -----------------------------------------------------------

main() {
  local mode="build" allow_unpinned="no" arch=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --arch) [ $# -ge 2 ] || { usage >&2; fail "--arch needs a value"; }
              arch="$2"; shift ;;
      --arch=*) arch="${1#--arch=}" ;;
      --verify-reproducible) mode="verify" ;;
      --explain) mode="explain" ;;
      --compare-tracked) mode="compare" ;;
      --ci) mode="ci" ;;
      --allow-unpinned) allow_unpinned="yes" ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; fail "unknown argument '$1'" ;;
    esac
    shift
  done

  select_arch "$arch"
  require_lockfile
  require_target "${CARGO_BUILD_TARGET:-$SUPPORTED_TARGET}"
  command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"

  case "$mode" in
    explain) explain ;;
    verify) verify_reproducible ;;
    compare) compare_tracked ;;
    ci) ci_build ;;
    build) build_release "$allow_unpinned" ;;
  esac
}

main "$@"
