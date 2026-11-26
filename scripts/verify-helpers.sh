#!/usr/bin/env bash
# Check the bundled helper binaries in bin/. Two independent checks:
#
#   --attestations  bin/SHA256SUMS, then GitHub's build-provenance attestation
#                   for each of the six binaries (needs `gh`, signed in),
#                   bound to this checkout's HEAD (and to the exact tag when
#                   HEAD is one). This proves the bytes are workflow-vouched
#                   for that commit and ref; it does not prove this commit's
#                   source produced them. Only --rebuild / --compare-tracked
#                   makes that source-to-bytes comparison.
#   --rebuild       Rebuild from this checkout's HEAD in the digest-pinned image
#                   and compare with the tracked bytes. Works on any commit.
#                   Delegates to scripts/build-agent.sh --compare-tracked.
#   --compare-tracked
#                   The same byte comparison without the wording of a rebuild.
#
# No flags runs both checks. Nothing here writes to the repository, and this
# script adds no sudo of its own (build-agent.sh may use `sudo -n docker`; see
# there).
set -euo pipefail

REPO="Elevate08/qs-bitwarden-cli"
SIGNER="$REPO/.github/workflows/release.yml"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPERS=(qs-bitwarden-ssh-agent qs-bitwarden-unlock-key qs-bitwarden-vault)
ARCHES=(x86_64 aarch64)

usage() {
  cat <<'USAGE'
Usage: scripts/verify-helpers.sh [--attestations] [--rebuild] [--compare-tracked] [--arch x86_64|aarch64|all]

  (no flags)      Both checks below.
  --attestations  sha256sum --strict -c bin/SHA256SUMS, then `gh attestation
                  verify` each bin/<arch>-linux/<helper> (all six) against this
                  repository, its release.yml workflow and this checkout's
                  HEAD (plus refs/tags/<tag> when HEAD is exactly a tag),
                  printing the tag and commit each attestation names.
  --rebuild       scripts/build-agent.sh --arch ARCH --compare-tracked: rebuild in
                  the pinned container image and require byte-identical output.
                  Needs a container runtime usable without a password prompt
                  (docker or podman) and a regular clone, not a linked git
                  worktree; aarch64 on an x86_64 machine needs qemu binfmt.
  --compare-tracked
                  scripts/build-agent.sh --arch ARCH --compare-tracked, without
                  the rebuild wording: compare the tracked bytes with a fresh
                  build. Same runtime requirements as --rebuild.
  --arch ARCH     Which architecture to build (default: this machine's).
                  Attestations are always checked for every architecture.
USAGE
}

do_attest=0 do_rebuild=0 do_compare=0 arch=""
while [ $# -gt 0 ]; do
  case "$1" in
    --attestations) do_attest=1 ;;
    --rebuild) do_rebuild=1 ;;
    --compare-tracked) do_compare=1 ;;
    --arch) [ $# -ge 2 ] || { usage >&2; exit 2; }; arch="$2"; shift ;;
    --arch=*) arch="${1#--arch=}" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'verify-helpers: unknown argument %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ "$do_attest$do_rebuild$do_compare" != "000" ] || { do_attest=1; do_rebuild=1; }

failed=()
pass() { printf 'PASS  %s\n' "$1"; }
# A failed check, and optionally what to do about it.
flunk() { printf 'FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '      %s\n' "$2"; failed+=("$1"); }

if [ "$do_attest" = 1 ]; then
  echo "== checksums (bin/SHA256SUMS)"
  if (cd "$ROOT/bin" && sha256sum --strict -c SHA256SUMS); then pass "SHA256SUMS"; else flunk "SHA256SUMS"; fi

  echo "== provenance attestations ($SIGNER)"
  head="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null || true)"
  tag=""
  if [ -n "$head" ]; then
    tag="$(git -C "$ROOT" describe --exact-match --tags HEAD 2>/dev/null || true)"
  fi
  if ! command -v gh >/dev/null 2>&1; then
    flunk "attestations" "gh is not installed; install the GitHub CLI (https://cli.github.com)"
  elif ! gh auth status >/dev/null 2>&1; then
    flunk "attestations" "gh is not signed in; run 'gh auth login' (any GitHub account works)"
  elif [ -z "$head" ]; then
    flunk "attestations" "this checkout has no HEAD commit to bind the attestations to"
  else
    # Bind the attestation to this checkout, not to any release of this
    # repository: --source-digest is the commit, --source-ref the tag when
    # HEAD is exactly one. The digest comparison below is belt and braces for
    # older gh versions.
    verify_args=(--repo "$REPO" --signer-workflow "$SIGNER" --deny-self-hosted-runners
      --source-digest "$head")
    [ -z "$tag" ] || verify_args+=(--source-ref "refs/tags/$tag")
    for a in "${ARCHES[@]}"; do
      for h in "${HELPERS[@]}"; do
        bin="bin/$a-linux/$h"
        # One binary can carry several attestations: unchanged bytes are
        # attested again by each release that ships them.
        if out="$(gh attestation verify "$ROOT/$bin" "${verify_args[@]}" \
            --format json --jq '.[].verificationResult.signature.certificate
              | "\(.sourceRepositoryRef) @ \(.sourceRepositoryDigest)"' 2>&1)" \
           && [ -n "$out" ]; then
          unbound=""
          while IFS= read -r binding; do
            [ "${binding##* @ }" = "$head" ] || unbound="$binding"
          done <<< "$out"
          if [ -z "$unbound" ]; then
            pass "$bin"
            printf '%s\n' "$out" | sed 's/^/      /'
          else
            flunk "$bin" "an attestation names ${unbound##* @ }, not this checkout's $head"
            printf '%s\n' "$out" | sed 's/^/      /'
          fi
        else
          flunk "$bin"
          printf '%s\n' "$out" | sed 's/^/      /'
        fi
      done
    done
  fi
fi

if [ "$do_rebuild" = 1 ]; then
  if [ "$arch" = all ]; then rebuild=("${ARCHES[@]}"); else rebuild=("${arch:-$(uname -m)}"); fi
  for a in "${rebuild[@]}"; do
    echo "== reproducible rebuild ($a)"
    # The container mounts only this directory; a linked worktree's .git
    # points outside it.
    if [ -f "$ROOT/.git" ]; then
      flunk "rebuild $a" "this checkout is a linked git worktree, which the container cannot read; run from a regular clone"
      continue
    fi
    explain="$("$ROOT/scripts/build-agent.sh" --arch "$a" --explain 2>&1 || true)"
    if [[ "$explain" == *"no container runtime"* ]]; then
      flunk "rebuild $a" "no container runtime usable without a password prompt; see scripts/build-agent.sh --explain"
      continue
    fi
    if "$ROOT/scripts/build-agent.sh" --arch "$a" --compare-tracked; then
      pass "rebuild $a"
    else
      flunk "rebuild $a"
    fi
  done
fi

if [ "$do_compare" = 1 ]; then
  if [ "$arch" = all ]; then check=("${ARCHES[@]}"); else check=("${arch:-$(uname -m)}"); fi
  for a in "${check[@]}"; do
    echo "== tracked bytes ($a)"
    if [ -f "$ROOT/.git" ]; then
      flunk "tracked $a" "this checkout is a linked git worktree, which the container cannot read; run from a regular clone"
      continue
    fi
    explain="$("$ROOT/scripts/build-agent.sh" --arch "$a" --explain 2>&1 || true)"
    if [[ "$explain" == *"no container runtime"* ]]; then
      flunk "tracked $a" "no container runtime usable without a password prompt; see scripts/build-agent.sh --explain"
      continue
    fi
    if "$ROOT/scripts/build-agent.sh" --arch "$a" --compare-tracked; then
      pass "tracked $a"
    else
      flunk "tracked $a"
    fi
  done
fi

echo
if [ ${#failed[@]} -eq 0 ]; then
  echo "verify-helpers: all checks passed"
else
  printf 'verify-helpers: %d check(s) failed:\n' "${#failed[@]}"
  printf '  - %s\n' "${failed[@]}"
  exit 1
fi
