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
| `qs-bitwarden-vault` | Holds the unlocked session key and item secrets outside the shell process, so a shell core dump does not contain them. Its `exec` request runs whatever argv its parent sends (it refuses only an empty argv or invalid environment names); in practice that is `bw` and the panel's own scripts. It also starts `timeout` + `wl-copy` to copy, and `wtype` for auto-type, so those secrets never pass through the shell. | Talks only to the shell that started it, over stdin/stdout, and trusts only that parent. [docs/vault-helper.md](docs/vault-helper.md) |
| `qs-bitwarden-ssh-agent` | Optional, off by default. Serves vault SSH keys to `ssh`/`git`, holding private keys in memory only. | Listens only on a unix socket in `$XDG_RUNTIME_DIR/qs-bitwarden-cli/` (mode 600, directory 700). It refuses signing for a peer with a different uid, and signing needs the user's approval in the panel (grants are scoped and revocable). [docs/ssh-agent.md](docs/ssh-agent.md) |
| `qs-bitwarden-unlock-key` | Encrypts and decrypts the quick-unlock (PIN, fingerprint, FIDO2) envelope. | A short-lived filter in shell pipelines: secrets in via environment variables, envelope on stdin, result on stdout. See the README section "How quick unlock stores your password". |

None of them opens a TCP or UDP socket. The agent enables tokio's `net`
feature only for its unix socket (`tokio::net::UnixListener`). The shipped
binaries import no `connect`, `getaddrinfo` or `sendto`, and unlock-key and
vault pull in no networking crates. `bw` itself (not bundled) is the program
that talks to the Bitwarden server.

Before it uses a helper, the panel runs `helperInspectCommand`
(`BitwardenModel.js`): the file must exist, be executable, be an ELF for this
machine's architecture, match its own `bin/SHA256SUMS` line (checked only when
`bin/SHA256SUMS` exists), and pass its self-test. If the shipped binary is
missing or fails, a local development build (such as `agent/target/debug/`) is
used instead when present, with the same checks except the checksum. This
catches stale or partial files, not tampering, because the checksum file sits
next to the binary. Provenance below is the check with an independent root of
trust.

## Source-to-binary provenance

**In CI.** `scripts/build-agent.sh` defines the release build: `--locked`
dependencies, a pinned toolchain, path remapping, and the digest-pinned
`rust:1.98.0-bookworm` image (`PINNED_IMAGE`). The `.github/workflows/agent-build.yml` job
"byte-identical across build paths" runs `build-agent.sh --ci` natively on an
x86_64 and an arm64 runner. It builds each helper twice from different paths
and fails if the two builds differ or if the committed bytes differ from them.
On pushes and tags, the job "reviewer rebuild (container re-exec)" runs
`scripts/verify-helpers.sh --rebuild` on a plain runner, the path described
below. On a
`v*` tag, `.github/workflows/release.yml` repeats those gates against the
tag, checks every binary against `SHA256SUMS`, and runs the shipped bytes on
plain runners. Then, in the only job with attestation permission ("attest and
publish"), it creates a GitHub build-provenance attestation for all six
binaries and attaches them to the release as `<name>-<arch>-linux` with SBOMs,
dependency reports and debug symbols.

One CI path writes binaries: `.github/workflows/helper-rebuild.yml`. For a
same-repository PR into a `release/**` branch whose Rust changes are only plain
source under `agent/src/`, `unlock-key/src/` or `vault/src/`, it commits the pinned-image rebuild to the PR branch.
Fork PRs are excluded, and so are runs triggered by Dependabot (`github.actor`). `scripts/helper-autocommit-eligible.sh`,
taken from the base branch, decides which PRs qualify. The workflow itself runs
on `pull_request`, so a same-repository PR that edits `helper-rebuild.yml`
could bypass that gate; such an edit is visible in the PR's diff. Changes to
Cargo files, the toolchain, `build.rs`, `.cargo` or the build script are always
rebuilt by hand. Either way, `release.yml`'s gates rebuild from the tagged
source, and a release only attests bytes that matched that rebuild.

**Check it yourself.** One command does both checks below:

```bash
scripts/verify-helpers.sh                    # checksums + attestations + rebuild (this arch)
scripts/verify-helpers.sh --attestations     # needs `gh`, signed in to any account
scripts/verify-helpers.sh --rebuild --arch all
```

- *Attestation*: for each binary, `gh attestation verify` against this
  repository with `release.yml` as the signer workflow (`REPO` and `SIGNER` in
  the script). The script prints the tag and commit that each attestation
  names. A binary whose bytes did not change across releases carries several
  attestations, and the script lists all of them. This covers released bytes
  only: helpers rebuilt on a branch fail it until that branch is tagged.
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
- Every `bw` run gets two Node preloads from the plugin directory through
  `NODE_OPTIONS`: `bw-login-code.js` (hands bw the two-step code without an
  argv) and `bw-fast-exit.js` (skips bw's idle time after it answers). They load
  in any Node process in those commands but act only inside bw.
- Node's compile cache for `bw` (`NODE_COMPILE_CACHE`, Node 22.1+) is an
  opt-in setting, `bwCompileCache`, **off by default**. Off, the plugin runs
  no check, creates no directory, and removes the variable from the
  environment of every `bw` and `node` it starts (`bwEnv`,
  `generatorServeEnv`, `withoutCompileCache`), so a value the shell inherited
  is never honoured. On:
  - *What is written.* Node, not the plugin, writes V8's compiled form of the
    JavaScript files `bw` loads (its bundle, its modules and the two
    preloads) to `<cache home>/qs-bitwarden-cli/node-compile-cache/`, about
    11 MB in 1,630 files for bw 2026.2.0, when a `bw` exits. The cache home is
    `XDG_CACHE_HOME`, or `~/.cache` when that is unset or empty; one that is
    relative or has a `..` or a control character in it means no cache. No
    account, item or session data goes into it, and every account shares it.
    The plugin itself only creates the two directories (and the cache home,
    if that one level is missing), mode 0700.
  - *Why it matters.* Node loads that code into `bw`, which is given the
    master password and the session key. A program running as the user that
    can write there can run code in `bw`, as it already can by changing the
    preloads in the plugin's directory or putting another `bw` on `PATH`.
  - *How it is checked* (`bwCompileCacheCommand`, run with a cleared
    environment and the path as an argument): on the path with symlinks
    resolved, every directory up to `/` must belong to the user or root and
    be writable by no one else; the plugin's directory and the cache
    directory must be real directories of the user's that no one else can
    write to (made with `mkdir -m 700` and checked again); the path must be
    printable ASCII (the cache is not used when the path has non-ASCII
    characters: QML could not read such bytes back reliably); and everything
    already inside must be a regular file or directory owned by the user and
    not group- or world-writable, with no symlink (one `find`, no `-L`,
    stopped at the first offender, given 5 seconds). The exact line the check
    printed is what `bw` is given (`bwCompileCacheAccepted`); nothing is
    repaired, and a failed check means `bw` runs without the cache, with a
    note on the setting's row.
  - *When.* At shell start with the setting on, when the setting is turned
    on, and when an unlock is submitted (password, PIN, fingerprint, FIDO2
    and the pinentry all end in `unlockVaultWithPassword`). A vault that
    opens with no unlock submitted (a terminal sign-in, a login, a session
    found open) is checked as it opens, unless one of the three checks above
    was started in the two minutes before and no opening has used it yet:
    one check serves one opening (`recheckBwCompileCacheOnOpen`). A new check
    withdraws the previous answer until it has its own, so a `bw` started in
    those ~20 ms runs without the cache: after a submitted unlock that is
    none of the reads that follow (`bw` takes about a second to unlock);
    after an opening checked as it opens it is the first reads of the list,
    organizations and folders. A lock or an envelope job queued earlier has
    the variable set again as its process starts
    (`refreshBwCompileCacheIn`), so a withdrawn directory is not used by it
    either. Between checks the directory is not looked at again: if it is
    deleted meanwhile, Node recreates it with the default umask, inside the
    plugin's 0700 directory if that is still there, and the next check
    judges it. Under a umask that leaves new directories group-writable
    (002), the directory Node makes inside the cache for its own version is
    one the next check refuses, so there the cache is used until the next
    check and not after; `chmod -R go-w` on it, or a umask of 022 or 077 for
    the shell, puts that right.
  - *Which launches use it.* Only `bw` itself, in the commands started with
    `bwEnv()`: status, login, unlock, lock, logout, sync, the list, get,
    create, edit, delete, send and generate commands, attachment download,
    and the generator's `bw serve`. These never do, setting on or off: the
    pinentry and its probe (`pinentryEnvironment`); the `bw -v` version probe;
    `bw login`/`bw unlock` in the terminal hand-off (the launcher's
    environment has the variable removed and the script the terminal runs
    starts with `unset NODE_COMPILE_CACHE`, since a terminal started by the
    session manager does not get the launcher's environment); the `bw logout`
    that retires a signed-out account's slot; and every `node -e` check the
    plugin's scripts run (the list and save validators, the writer that hands
    SSH keys to the agent, the attachment claim and open checks, the SSH
    public-key export), which are started as `env -u NODE_COMPILE_CACHE node`
    even where they share a script with a cached `bw`.
    `tests/bw-compile-cache.test.js` holds this inventory and fails when a
    script that starts `bw` or `node` is not in it.
  - Turning the setting off stops using the cache at the next `bw` start and
    leaves the directory; [docs/uninstall.md](docs/uninstall.md) removes it.

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
  `.before-repair-<time>` backup beside it;
- on request only: `~/.config/hypr/bindings.lua` (the auto-type keybind:
  appended on enable, creating the file if hyprland.lua loads it and it is
  missing; removed by rewriting through a temporary file renamed into place), the Downloads directory
  (`xdg-user-dir DOWNLOAD`, else `~/Downloads`) for attachments, staged in a
  `.qsbw-*` directory, `~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent`, and,
  with the `bwCompileCache` setting on, `<cache home>/qs-bitwarden-cli/`
  (two directories made by the plugin; the compiled code in them is written
  by Node, see above).
