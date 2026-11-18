# Reviewing qs-bitwarden-cli

For marketplace and security reviewers. It lists what the plugin bundles, how
to check that the bundled binaries come from this source, and where each
capability an automated scan flags lives, why it is there and what limits it.
Line numbers are for this commit.

## What is bundled, and why

Three Rust helpers, prebuilt for x86_64 and aarch64 Linux in
`bin/x86_64-linux/` and `bin/aarch64-linux/` (six ELF files), with one
`bin/SHA256SUMS`. Source: `agent/`, `unlock-key/`, `vault/`, each with its own
`Cargo.lock` and `rust-toolchain.toml`. All three run as the user who runs the
shell, never as root, and set `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at
startup. The vault helper refuses to run if that fails, and the other two check
it in their self-test.

| Helper | What it does | Boundary |
|---|---|---|
| `qs-bitwarden-vault` | Holds the unlocked session key and item secrets outside the shell process, so a shell core dump does not contain them. It runs the commands the shell asks it to run (`bw`, `wl-copy`), so the secrets they need never pass through the shell. It has no allowlist of its own: it trusts only its parent. | Talks only to the shell that started it, over stdin/stdout. [docs/vault-helper.md](docs/vault-helper.md) |
| `qs-bitwarden-ssh-agent` | Optional, off by default. Serves vault SSH keys to `ssh`/`git`, holding private keys in memory only. | Listens only on a unix socket in `$XDG_RUNTIME_DIR/qs-bitwarden-cli/` (mode 600, directory 700). It refuses signing for a peer with a different uid, and signing needs the user's approval in the panel (grants are scoped and revocable). [docs/ssh-agent.md](docs/ssh-agent.md) |
| `qs-bitwarden-unlock-key` | Encrypts and decrypts the quick-unlock (PIN, fingerprint, FIDO2) envelope. | A short-lived filter in shell pipelines: secrets in via environment variables, envelope on stdin, result on stdout. See the README section "How quick unlock stores your password". |

None of them contains TCP or UDP socket code. `bw` itself (not bundled) is the program that talks to the Bitwarden server.

Before it uses a helper, the panel checks that the file exists, is executable,
is for the right architecture, matches its `bin/SHA256SUMS` line, and passes
its self-test (`BitwardenModel.js:5958-5972`). That catches stale or partial
files, not tampering, because the checksum file sits next to the binary. Provenance below is the
check with an independent root of trust.

## Source-to-binary provenance

**In CI.** `scripts/build-agent.sh` defines the release build: `--locked`
dependencies, a pinned toolchain, path remapping, and the digest-pinned
`rust:1.98.0-bookworm` image (`PINNED_IMAGE`). The `.github/workflows/agent-build.yml` job
"byte-identical across build paths" runs `build-agent.sh --ci` natively on an
x86_64 and an arm64 runner. It builds each helper twice from different paths
and fails if the two builds differ or if the committed bytes differ from them. On a
`v*` tag, `.github/workflows/release.yml` repeats those gates against the
tag, checks every binary against `SHA256SUMS`, and runs the shipped bytes on
plain runners. Then, in the only job with attestation permission ("attest and
publish"), it creates a GitHub build-provenance attestation for all six
binaries and attaches them to the release as `<name>-<arch>-linux` with SBOMs,
dependency reports and debug symbols.

One CI path writes binaries: `.github/workflows/helper-rebuild.yml`. For a
same-repository PR into a `release/**` branch whose Rust changes are only plain
source under `*/src/`, it commits the pinned-image rebuild to the PR branch.
`scripts/helper-autocommit-eligible.sh`, run from the base branch, decides
which PRs qualify. Changes to Cargo files, the toolchain, `build.rs`, `.cargo` or the build
script are always rebuilt by hand. Either way, a release only attests bytes
that the gates above rebuilt from the tagged source.

**Check it yourself.** One command does both checks below:

```bash
scripts/verify-helpers.sh                    # checksums + attestations + rebuild (this arch)
scripts/verify-helpers.sh --attestations     # needs `gh`, signed in to any account
scripts/verify-helpers.sh --rebuild --arch all
```

- *Attestation*: for each binary,
  `gh attestation verify bin/<arch>-linux/<name> --repo Elevate08/qs-bitwarden-cli --signer-workflow Elevate08/qs-bitwarden-cli/.github/workflows/release.yml`.
  The script prints the tag and commit that each attestation names. A binary whose bytes did
  not change across releases carries several attestations, and the script lists all of them. This
  covers released bytes only: helpers rebuilt on a branch fail it until that
  branch is tagged.
- *Rebuild*: `scripts/build-agent.sh --arch <arch> --compare-tracked`
  rebuilds `HEAD` in the pinned image and requires byte-identical output.
  It works on any commit. It needs `cargo` on `PATH` (checked before the
  container starts) and `docker` or `podman` usable without a password
  prompt. aarch64 on an x86_64 host needs qemu binfmt. `build-agent.sh --explain`
  shows which environment it would use, without running anything.

More detail: [docs/ssh-agent.md](docs/ssh-agent.md#verifying-the-helper) and
[docs/vault-helper.md](docs/vault-helper.md#verifying-the-shipped-binary).

## Flagged capabilities

### Bundled executables: `bin/*/qs-bitwarden-*`

They exist for the reasons above. They are bounded by the provenance checks
above and by the panel's check before use. A helper that is missing or fails
its check disables only its own feature: the SSH agent, quick unlock, or
vault access. For the vault, the shell-held fallback is opt-in
(`allowVaultWithoutHelper`).

### Privilege and package management: dependency install

- `BitwardenModel.js:5145-5176`: `DEPENDENCIES`, the only packages the
  panel offers to install: `bitwarden-cli`, `jq` and `wtype` (`wtype` only
  while auto-type is on), all from the official repositories (`aur: false`).
  The fourth entry, `fprintd`, is set up by Omarchy (see below). The panel
  does not install it as a package.
- `BitwardenModel.js:7200-7202`: package names must match
  `^[A-Za-z0-9][A-Za-z0-9._+-]*$`, otherwise no command is built.
- `BitwardenModel.js:7206-7213`: the normal path is
  `omarchy install app <name> <pkgs>`, Omarchy's own installer, which asks
  for the sudo password itself.
- `BitwardenModel.js:7220-7229`: `sudo pacman -S --needed <pkgs>` in a
  visible floating terminal (`omarchy launch floating terminal`), **without
  `--noconfirm`**. It is used only when `installNeedsConfirmation`
  (`BitwardenModel.js:7232-7239`) finds that a package would replace an installed one. Today
  that means `bitwarden-cli` needing `nodejs-lts-jod` where another `nodejs` is installed, so
  pacman itself asks the user. The README describes this at `README.md:38`.
- `BitwardenModel.js:7249-7253`: the Install button's tooltip shows which
  of the two commands it will run.
- These run only from the setup screen's **Install** buttons
  (`Panel.qml:2336`, `Panel.qml:2364` -> `Service.qml:5320-5348`), never on
  their own. The plugin never sees the sudo password, which goes to sudo in the
  terminal.

Not flagged, but of the same kind: `omarchy setup security fingerprint`
(`BitwardenModel.js:7258-7261`, `Service.qml:5358-5361`) and
`omarchy setup security fido2` (`FidoModel.js:15-18`, `FidoUnlock.qml:394`)
open Omarchy's own enrolment in a floating terminal when the user clicks
that setup action. Any sudo prompt there comes from Omarchy's script.

### Privilege: `scripts/build-agent.sh:191` (`sudo -n docker info`)

This is a developer and reviewer build script. The plugin never runs it. When the script
looks for a container runtime it tries `docker`, then `sudo -n docker`
(`-n` never prompts, so it only succeeds where sudo is already cached or
passwordless), then `podman`. Omarchy setups use `sudo docker` rather than the
docker group, which is root-equivalent. `--explain` reports the choice
without running anything.

## What the plugin does not do

Checked against this commit's source (QML, JS, shell scripts, helper crates):

- It never runs `sudo`, `pkexec`, `setcap` or `systemctl`, except for the user-started
  install and setup terminals above.
- It never passes `--noconfirm`, and it never installs from the AUR or runs
  `yay`, `paru` or `makepkg`.
- It never runs the helpers as root, and the helpers never open TCP/UDP
  sockets. The panel's one `curl` (`BitwardenModel.js:7621`) talks to
  the local `bw serve` unix socket with `--noproxy '*'`.
- It does not keep its own copy of the vault on disk. The session key and the
  quick-unlock envelope are kept in the user's keyring (see README).

Outside its own directory, everything it writes is user-owned and outside
system paths. That includes the keyring, its entry in `~/.config/omarchy/shell.json`,
`$XDG_RUNTIME_DIR/qs-bitwarden-cli/`, `~/.local/state/qs-bitwarden-cli/`,
`~/.local/share/qs-bitwarden-cli/` and, only when you ask for it,
`~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent`.
