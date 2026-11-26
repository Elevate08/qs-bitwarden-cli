# Reviewing qs-bitwarden-cli

For marketplace and security reviewers. It lists what the plugin bundles, how
to check that the bundled binaries come from this source, and where each
capability an automated scan flags lives, why it is there and what limits it.
Code is cited by function or identifier name, so search for it.

## What is bundled, and why

Three Rust helpers, prebuilt for x86_64 and aarch64 Linux in
`bin/x86_64-linux/` and `bin/aarch64-linux/` (six ELF files), with one
`bin/SHA256SUMS`. Source: `agent/`, `unlock-key/`, `vault/`, each with its own
`Cargo.lock` and `rust-toolchain.toml`. They run as the shell's user; the
plugin never starts them with elevated privileges. Each sets `RLIMIT_CORE=0`
and `PR_SET_DUMPABLE=0` at startup (`harden_process`), refuses to run if that
fails, and checks it in its self-test.

| Helper | What it does | Boundary |
|---|---|---|
| `qs-bitwarden-vault` | Holds the unlocked session key and item secrets outside the shell process, so a shell core dump does not contain them. Its `exec` request runs whatever argv its parent sends (it refuses an empty argv, invalid environment names, an unknown capture or source, a duplicate run id, and too many runs); in practice that is `bw` and the panel's own scripts. It also starts `timeout` + `wl-copy` to copy, and `wtype` for auto-type, so those secrets never pass through the shell. | Talks to the shell that started it over stdin/stdout, with no socket. It authenticates no peer, so a same-UID process can open the shell's end of that pipe through `/proc` and speak the protocol; see [docs/vault-helper.md](docs/vault-helper.md#how-the-shell-talks-to-it). |
| `qs-bitwarden-ssh-agent` | Optional, off by default. Serves vault SSH keys to `ssh`/`git`, holding private keys in memory only. | Listens only on a unix socket in `$XDG_RUNTIME_DIR/qs-bitwarden-cli/` (mode 600, directory 700). It refuses any connection whose peer uid differs, including an identity listing, and signing needs the user's approval in the panel (grants are scoped and revocable; the five-minute cooldown is panel-side). [docs/ssh-agent.md](docs/ssh-agent.md) |
| `qs-bitwarden-unlock-key` | Encrypts and decrypts the quick-unlock (PIN, fingerprint, FIDO2) envelope. | A short-lived filter in shell pipelines: secrets in via environment variables, envelope on stdin, result on stdout. See the README section "How quick unlock stores your password". |

None of them opens a TCP or UDP socket. The agent enables tokio's `net`
feature only for its unix socket (`tokio::net::UnixListener`). The shipped
binaries import no `connect`, `getaddrinfo` or `sendto`, and unlock-key and
vault pull in no networking crates. `bw` itself (not bundled) is the program
that talks to the Bitwarden server.

Before it uses a helper, the panel runs `helperInspectCommand`
(`BitwardenModel.js`): the file must exist, be executable, be an ELF for this
machine's architecture, match its own `bin/SHA256SUMS` line (a missing
`bin/SHA256SUMS` is a distinct `checksum=missing` refusal, not an unchecked
pass), and pass its self-test. If the shipped binary is
missing or fails, a local development build (such as `agent/target/debug/`) is
used instead when present, with the same checks except the checksum. This
catches stale or partial files, not tampering, because the checksum file sits
next to the binary. Provenance below is the check with an independent root of
trust.

`qs-bitwarden-unlock-key` requires the account in the environment for every
write (`create`, `add`, `remove`, `rotate`, `mark-stale`). `add --method
fingerprint` refuses a terminal, because that envelope contains the data key;
only a pipe or redirected stdout gets it. `remove --method fingerprint` is
refused: fingerprint removal deletes the whole envelope. The envelope JSON is
written once into a buffer sized for it, rather than grown through
reallocations that would leave copies of the key.

## Source-to-binary provenance

**In CI.** `scripts/build-agent.sh` defines the release build: `--locked`
dependencies, a pinned toolchain, path remapping, and the digest-pinned
`rust:1.98.0-bookworm` image (`PINNED_IMAGE`). The `.github/workflows/agent-build.yml` job
"byte-identical across build paths" runs `build-agent.sh --ci` natively on an
x86_64 and an arm64 runner. It builds each helper twice from different paths
and fails if the two builds differ or if the committed bytes differ from them.
The image digest is checked to be identical in every workflow and in
`build-agent.sh`, so a workflow-only edit cannot swap the image unnoticed. A
fork PR still uploads its candidate, but its drift check now fails rather than
passing with a warning; the candidate has to be committed by a maintainer.
On pushes and tags, the job "reviewer rebuild (container re-exec)" runs
`scripts/verify-helpers.sh --rebuild` on a plain runner, the path described
below. On a
`v*` tag, `.github/workflows/release.yml` repeats those gates against the
tag, checks every binary against `SHA256SUMS`, and runs the shipped bytes on
plain runners. Then, in the only job with attestation permission ("attest and
publish"), it creates a GitHub build-provenance attestation for all six
binaries and attaches them to the release as `<name>-<arch>-linux` with SBOMs,
dependency reports and debug symbols.

Before a draft is made public, `.github/workflows/publish-on-master.yml`
re-downloads its assets, requires exactly the expected asset names (refusing
anything foreign), compares every helper and `SHA256SUMS` with the tag's
`bin/`, and re-verifies each attestation for that tag's commit and ref. A
re-run of `release.yml` prunes foreign assets instead of leaving them beside
the real ones. `.github/workflows/master-verify.yml` is read-only and runs
`--compare-tracked` on every push to `master`, so a Dependabot lockfile bump
cannot land with a stale `bin/` unobserved.

`bin/` is an exact allow-list: `SHA256SUMS` plus the six helper paths, regular
files only, no symlinks, no seventh helper inside an architecture directory.
`release.yml` and `helper-rebuild.yml` both enforce it.

One CI path writes binaries: `.github/workflows/helper-rebuild.yml`. For a
same-repository PR into a `release/**` branch whose Rust changes are only plain
source under `agent/src/`, `unlock-key/src/` or `vault/src/`, it commits the pinned-image rebuild to the PR branch.
Fork PRs are excluded, and so are runs triggered by Dependabot (`github.actor`). `scripts/helper-autocommit-eligible.sh`,
taken from the base branch, decides which PRs qualify. Its rule is
deny-by-default: any change to `.github/**`, `deny.toml`, anything under
`scripts/`, a Cargo or toolchain file, `.cargo`, `build.rs`, `.gitattributes`,
a symlink, or a file inside a package other than `src/**` makes the PR
ineligible; ordinary QML, JS, docs, tests and `bin/` are allowed.
The workflow checks out the PR head with `persist-credentials: false` and
passes the token only on the final `git push`, so it is not left in
`.git/config`. `release.yml`'s gates rebuild from the tagged source, and a
release only attests bytes that matched that rebuild. `deny.toml` denies
duplicate crate versions (only the proc-macro `syn` is skipped), so a second
crypto implementation cannot enter the graph as a warning.

Release tags are unsigned annotated refs and mutable. Whether the `release`
environment admits only `v*` tags and requires a reviewer lives in repository
settings, not in this tree, as do branch protection and CODEOWNERS
enforcement; a tag-pusher who edits the gate workflow in the same commit is
caught by review, not by cryptography. Attestation covers the six helper
binaries only: `Panel.qml`, `Service.qml` and `BitwardenModel.js` execute with
full user privileges and are not attested, and `omarchy plugin update` pulls
the default branch. The report tools are pinned except for the SBOM generator:
`cargo-deny` is a digest-checked static binary, while `cargo-cyclonedx` is
still `cargo install`ed from crates.io because no published digest is
available.

**Check it yourself.** One command does both checks below:

```bash
scripts/verify-helpers.sh                    # checksums + attestations + rebuild (this arch)
scripts/verify-helpers.sh --attestations     # needs `gh`, signed in to any account
scripts/verify-helpers.sh --rebuild --arch all
```

- *Attestation*: for each binary, `gh attestation verify` against this
  repository with `release.yml` as the signer workflow (`REPO` and `SIGNER` in
  the script), `--deny-self-hosted-runners`, `--source-digest` set to this
  checkout's `HEAD`, and `--source-ref refs/tags/<tag>` when `HEAD` is exactly
  a tag. The script also compares the commit each attestation names against
  `HEAD` and prints the tag and commit. A binary whose bytes did not change
  across releases carries several attestations, and the script lists all of
  them. This proves the bytes were workflow-vouched for that commit and ref;
  it does **not** prove this commit's source produced them. `--rebuild` /
  `--compare-tracked` is the source-to-bytes check. Helpers rebuilt on a
  branch fail the attestation until that branch is tagged.
- *Rebuild*: `scripts/build-agent.sh --arch <arch> --compare-tracked`
  rebuilds `HEAD` in the pinned image and requires byte-identical output.
  It works on any commit. It needs `docker` or `podman` usable without a
  password prompt; Rust is needed on the host only for a build outside the
  image. Run it from a regular clone: in a linked `git worktree` the container
  cannot see the repository, and the script stops. aarch64 on an x86_64 host
  needs qemu binfmt. `build-agent.sh --explain` shows which environment it
  would use without building anything (it only probes `docker info`, then
  `sudo -n docker info`, then `podman info`).

More detail: [docs/ssh-agent.md](docs/ssh-agent.md#verifying-the-helper) and
[docs/vault-helper.md](docs/vault-helper.md#verifying-the-shipped-binary).

## Flagged capabilities

### Bundled executables: `bin/*/qs-bitwarden-*`

They exist for the reasons above. They are bounded by the provenance checks
above and by the panel's check before use. When no usable shipped or local
build is found, only that helper's feature is disabled: the SSH agent, quick
unlock, or vault access. For the vault, the shell-held fallback is opt-in
(`allowVaultWithoutHelper`).

### Privilege and package management: dependency install

All in `BitwardenModel.js` unless named otherwise.

- `DEPENDENCIES`: the only packages the panel offers to install:
  `bitwarden-cli`, `jq` and `wtype` (`wtype` only while auto-type is on), all
  from the official repositories (`aur: false`). The fourth entry, `fprintd`,
  is set up by Omarchy (see below). The panel does not install it as a package.
- `isPlainPackageName`: package names must match
  `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, otherwise no command is built.
- `installPackagesCommand`: the normal path is `omarchy install app`,
  Omarchy's own installer. It runs Omarchy's `omarchy-pkg-add`, which installs
  with pacman's `--noconfirm` and asks for the sudo password itself.
- `confirmedInstallCommand`: pacman without `--noconfirm`, in a visible
  floating terminal (`omarchy launch floating terminal`). It is used only when
  `installNeedsConfirmation` finds that a package would replace an installed
  one, the one question `omarchy-pkg-add` cannot put to the user. Today that means
  `bitwarden-cli` needing `nodejs-lts-jod` where another `nodejs` is installed,
  so pacman itself asks the user. The README describes this; the scan flagged
  that line as `README.md:38` at 8e1ab7b.
- `dependencyInstallHint`: the Install button's tooltip shows which of the two
  commands it will run.
- These run only from the setup screen's **Install** buttons (`Panel.qml`
  calls `installOne` / `installMissing` in `Service.qml`), never on their own.
  The plugin never sees the sudo password, which goes to sudo in the terminal.

Not flagged, but of the same kind: `fingerprintSetupCommand`
(`BitwardenModel.js`) and `fidoSetupCommand` (`FidoModel.js`, run from
`FidoUnlock.qml`) open Omarchy's own fingerprint and FIDO2 enrolment in a
floating terminal when the user clicks that setup action. Any password prompt
there comes from Omarchy's script.

### Privilege: `container_runtime` in `scripts/build-agent.sh`

Flagged as `scripts/build-agent.sh:191` at 8e1ab7b. This is a developer and
reviewer build script. The plugin never runs it. When the script looks for a
container runtime (`container_runtime`) it tries `docker`, then docker through
sudo with `-n`, which never prompts, so it only succeeds where sudo is already
cached or passwordless, then `podman`. Omarchy setups use docker through sudo
rather than the docker group, which is root-equivalent. `--explain` reports the
choice without building anything; it only runs those probes.

## Other things a reviewer may look for

- Item URLs open with `xdg-open`, http and https only (`normalizeOpenableUrl`).
- A `bw` run gets two Node preloads from the plugin directory through
  `NODE_OPTIONS`: `bw-login-code.js` (hands bw the two-step code without an
  argv) and `bw-fast-exit.js` (skips bw's idle time after it answers). They load
  in any Node process in those commands but act only inside bw. The exceptions
  are `bw --version`, which has no work for them, and `bw serve`, where
  `bw-fast-exit.js` must not act on the server process; the generator's `bw`
  commands therefore run without `NODE_OPTIONS`.

## What the plugin does not do

Checked against this commit's source (QML, JS, shell scripts, helper crates):

- It runs no privileged command (sudo, pkexec, setcap, systemctl) except in the
  user-started install and setup terminals above.
- It never passes `--noconfirm` itself (Omarchy's installer does, as above),
  and it never installs from the AUR or runs `yay`, `paru` or `makepkg`.
- The helpers open no TCP or UDP sockets. The panel's one `curl`
  (`generateServeRequestCommand`) talks to the local `bw serve` unix socket
  with `--noproxy '*'`.
- It keeps no vault copy of its own. bw's encrypted cache lives in bw's data
  directory (for added accounts, inside
  `~/.local/share/qs-bitwarden-cli/accounts/<slot>`), and attachments you
  download are written decrypted to your Downloads directory
  (`xdg-user-dir DOWNLOAD`, else `~/Downloads`).

As of this commit, what it writes outside its own directory is user-owned and
outside system paths:

- the keyring (session key, quick-unlock envelope; see README), and its entry
  in `~/.config/omarchy/shell.json`;
- `$XDG_RUNTIME_DIR/qs-bitwarden-cli/`, and per-prompt
  `$XDG_RUNTIME_DIR/qsbw-pinentry-<random>/` (prompt.json and an `answer.sock`
  unix socket) and `$XDG_RUNTIME_DIR/qsbw-pinentry-ui-<hash>/` (a generated
  shell.qml and symlinks), both from pinentry;
- `~/.local/state/qs-bitwarden-cli/` and `~/.local/share/qs-bitwarden-cli/`,
  including bw's data for added accounts (`accounts/<slot>`, passed to bw as
  `BITWARDENCLI_APPDATA_DIR`);
- `${XDG_DATA_HOME:-~/.local/share}/keyrings/Default_keyring.keyring`:
  `scripts/repair-keyring.sh --auto`, run at every start, rewrites it only when
  it holds an entry gnome-keyring refuses to load, keeping a
  `.before-repair-<time>` backup beside it. It takes an exclusive `flock`,
  re-checks the file's inode/size/mtime and hash immediately before the
  rename, and aborts with the file unchanged if anything wrote meanwhile. The
  plugin also stores a split envelope just before the script runs, so a start
  can include a keyring write even when the repair finds nothing to join;
- on request only: `~/.config/hypr/bindings.lua` (the auto-type keybind:
  appended on enable under an exclusive `flock`, refusing a symlink, creating
  the file if hyprland.lua loads it and it is
  missing; removed by rewriting through a temporary file renamed into place), the Downloads directory
  (`xdg-user-dir DOWNLOAD`, else `~/Downloads`) for attachments, staged in a
  `.qsbw-*` directory, and `~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent`.
