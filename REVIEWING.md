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
- Besides `bw` (not bundled), two things in the plugin reach the network,
  each behind a setting that is on by default and makes no request when off:
  - *Website icons* (`showWebsiteIcons`). The shell process itself fetches
    `<icon service>/<host>/icon.png` with QML's `XMLHttpRequest`
    (`ItemIcon.qml`), for logins only. `iconServiceUrl` gives the service:
    `icons.bitwarden.net` or `.eu` for Bitwarden's cloud, `<server>/icons`
    for the account's own server (over `http` if that is how the server is
    configured). `websiteIconHost` gives the host: the first URI's plain
    ASCII host name or IPv4 address, lower-cased, and nothing else of the
    item, so the request names a saved site (internal names and private
    addresses included) and can be shaped by a vault entry no further. No
    URL is ever built from a vault value alone, so an item cannot make the
    panel request a `file:`, `qrc:` or LAN address. The service can: Qt
    follows its redirects to any `http` or `https` address (not from
    `https` to `http`, and not to `file:`), so a self-hosted or
    impersonated icon endpoint can make the panel send one blind `GET`
    elsewhere. Qt sends its stock `User-Agent` (`Mozilla/5.0`) and keeps
    the service's cookies in memory until the shell exits; there is no
    disk cache. The answer is drawn only if it is a PNG, JPEG, GIF, ICO or
    WebP of at most 128 KiB by its first bytes (`websiteIconDataUrl`), is
    kept in memory for the open vault and dropped at lock
    (`forgetWebsiteIcons`), and a missing icon logs nothing. The bytes are
    a website's own favicon passed on by the service, decoded in the shell
    process by Qt's decoder for that format.
  - *The update check* (`checkForUpdates`): one `curl` a day to
    `api.github.com`, HTTPS only also across redirects, a fixed URL, nothing
    of the vault (`updateCheckCommand`).
- Every `bw` run gets two Node preloads from the plugin directory through
  `NODE_OPTIONS`: `bw-login-code.js` (hands bw the two-step code without an
  argv) and `bw-fast-exit.js` (skips bw's idle time after it answers). They load
  in any Node process in those commands but act only inside bw.
- Node's compile cache for `bw` (`NODE_COMPILE_CACHE`, Node 22.1+) is an
  opt-in setting, `bwCompileCache`, **off by default**. Off, the plugin runs
  no check, creates no directory, and removes the variable from the
  environment it gives every `bw` and `node` it starts (`bwEnv`,
  `generatorServeEnv`, `withoutCompileCache`), so a value the shell inherited
  is not passed on. That is as far as the plugin's hand reaches: most of
  those launches are `bash -c` scripts, and a startup file named by
  `BASH_ENV` in the session (the user's own, or a program's running as the
  user) that exports the variable sets it again inside them, as it could
  set any other. The script the terminal hand-off runs starts its `bw`
  through `env -u NODE_COMPILE_CACHE` as well as unsetting it, which covers
  one made readonly there. On, a `bw` that is handed the master password or a
  login's credentials still never uses it; the rest may:
  - *What is written.* Node, not the plugin, writes V8's compiled form of the
    JavaScript files `bw` loads (its bundle, its modules and the two
    preloads) to `<cache home>/qs-bitwarden-cli/node-compile-cache/`, about
    11 MB in 1,630 files for bw 2026.2.0, when a `bw` exits. The cache home is
    `XDG_CACHE_HOME`, or `~/.cache` when that is unset or empty; one that is
    relative or has a `..` or a control character in it means no cache. No
    account, item or session data goes into it, and every account shares it.
    The plugin itself only creates the two directories (and the cache home,
    if that one level is missing), mode 0700, and sets that mode on the two
    when a check passes.
  - *Why it matters.* Node loads that code into `bw`. The `bw` runs that
    use the cache are given the session key (or nothing); the ones given the
    master password run without it. A program running as the user that can
    write there can run code in those `bw` runs, as it already can by
    changing the preloads in the plugin's directory or putting another `bw`
    on `PATH`.
  - *How it is checked* (`bwCompileCacheCommand`, run with a cleared
    environment and the path as an argument): the path as given, and again
    with symlinks resolved, must be printable ASCII (the cache is not used
    when the path has non-ASCII characters: QML could not read such bytes
    back reliably); on the resolved path, every directory up to `/` must
    belong to the user or root and be writable by no one else; the plugin's
    directory and the cache directory must be real directories of the user's
    that no one else can write to (made with `mkdir -m 700` if missing, and
    checked again); and everything already in the plugin's directory must be
    a regular file or directory owned by the user and not group- or
    world-writable, with no symlink (one `find`, no `-L`, stopped at the
    first offender, given 5 seconds). The exact line the check printed is
    what `bw` is given (`bwCompileCacheAccepted`). The plugin's directory
    must hold nothing but the cache directory: with `XDG_CACHE_HOME` pointed
    at the data or state home, `qs-bitwarden-cli` there is where the
    plugin's accounts or learned picks live, and the check refuses it
    untouched. A refused check changes no existing file or mode: what is
    already there is judged before anything is made, and `bw` then runs
    without the cache, with a note on the setting's row. A check that fails
    part-way (a `mkdir` or the final `chmod` itself failing) may leave the
    empty directories it created or one of the two modes already set, and one already running when the setting
    is turned off finishes; its answer is not used. A path that passed has
    its two directories set to exactly 0700 (`chmod 00700`, which also
    clears a setgid bit inherited from the cache home). They hold the cache
    and nothing else, so tightening them touches nothing of anyone
    else's, and it is what keeps a cleared `~/.cache` from
    switching the cache off for good: Node recreates the directories with
    the default umask, and the next check makes them private again.
  - *When.* At shell start with the setting on, when the setting is turned
    on, and every time the vault becomes unlocked, whichever way
    (`onStatusChanged`). That is all: nothing is carried from one check to
    the next, and there is no timer or grace period. A new check withdraws
    the previous answer until it has its own, so the first reads of an
    opening (the list, organizations and folders, started in the same
    moment) run without the cache, and what follows the ~20 ms check uses
    it. A check that ends after the setting was turned off starts nothing
    more (`startBwCompileCacheProbe` reads the setting and whether a
    question is still open each time it runs, deferred or not).
  - *State.* `bwCompileCacheDir` (the accepted path, or ""),
    `bwCompileCacheState` (off, pending, accepted, refused: for the row's
    note) and `bwCompileCacheProbeSeq` (tells a late answer from the current
    one). The first two are reset by every new check and by the setting
    turning off; none of them is per account or per vault, so a lock or an
    account switch has nothing to clear, and the next opening checks afresh.
  - *An environment built before its `bw` starts* (a queued lock or envelope
    job, a run waiting for the vault helper, a local start put off behind
    the previous run's cleanup) is settled at the start, in one place for
    each way a `VaultProcess` can run: `vaultStart()` as it hands the run to
    the helper, and `VaultProcess.launchLocal()` as it hands it to a local
    process. Both call `bwEnvAtStart()`, which replaces a directory the
    environment names with what holds at that moment (nothing, if the
    setting was turned off or a check is running) and leaves a removed
    variable removed. So a run queued while a check was still running
    starts without the cache even if the check has passed by then: a lost
    saving, never an unchecked directory. The generator's `bw serve`, the one plain `Process`
    that may use the cache, reads its environment as a binding when it
    starts.
  - *Between checks* the directory is not looked at again. A device and
    inode comparison before each `bw` start was considered and not done:
    QML has no way to stat a path without starting a process, and a process
    per `bw` start would cost what the cache saves while still leaving a gap
    before Node opens the directory. What is left: if the cache directory is
    deleted while the vault is open, Node recreates it with the default
    umask inside the plugin's directory, which is 0700, so no one else can
    reach it whatever the umask. If the plugin's directory is deleted too,
    Node recreates both by umask, and until the next check (the next
    opening, or the setting toggled) the cache is as private as the cache
    home and the umask make it: under umask 022 others can read compiled
    code and write nothing; under umask 002 with a cache home the group can
    enter, group members could write there. The next check refuses a
    directory or anything in it that is group- or world-writable, and
    otherwise makes both private again.
  - *umask 002.* Node makes its own per-version directory inside the cache
    group-writable under such a umask, and the next check refuses the cache
    for that, private parent or not; `chmod -R go-w` on the cache directory,
    or a umask of 022 or 077 for the shell, puts that right.
  - *`BW_PASSWORD`.* The plugin never sets `BW_PASSWORD` for a launch that
    may use the cache. It sets it, replacing one already exported in the
    session that started the shell, for two launches only, neither cached.
    One is the API-key login's script (`authEnv` with the password, from
    `loginProcessEnv`), whose `bw login --apikey` and `bw unlock
    --passwordenv BW_PASSWORD` both get the plugin's value. The other is
    the FIFO writer (`authPasswordWriterProc`: a `bash` that execs
    `timeout`, which runs a second `bash` whose `printf` writes the value
    into the FIFO), and no `bw` at all. For unlocking and for an email login
    the `bw` process is started earlier with `authEnv("")`, which leaves the
    variable alone, and reads the password from that FIFO through
    `--passwordfile`: that `bw` still inherits an exported `BW_PASSWORD`,
    as does every other `bw` launch, cached or not, and makes no use of it.
  - *Which launches use it.* Only `bw` itself, and only where it is given no
    password: status, lock, logout, sync, the list, get, create, edit,
    delete, send and generate commands, attachment download, and the
    generator's `bw serve` (`bwEnv()`, `generatorServeEnv()`). These never
    do, setting on or off: `bw unlock` and the process kept waiting for it,
    every `bw login` (email, device verification, API key) and the password
    check (`bwSecretEnv()`: `authEnv`, `loginProcessEnv`, `verifyWithBw`);
    the pinentry and its probe (`pinentryEnvironment`); the `bw -v` version
    probe; `bw login`/`bw unlock` in the terminal hand-off (the launcher's
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
  - Turning the setting off stops using the cache at the next `bw` start
    (one already waiting to start included) and leaves the directory;
    [docs/uninstall.md](docs/uninstall.md) says where it is.

## What the plugin does not do

Checked against this commit's source (QML, JS, shell scripts, helper crates):

- It runs no privileged command (sudo, pkexec, setcap, systemctl) except in the
  user-started install and setup terminals above.
- It never passes `--noconfirm` itself (Omarchy's installer does, as above),
  and it never installs from the AUR or runs `yay`, `paru` or `makepkg`.
- The helpers open no TCP or UDP sockets. Of the panel's two `curl` calls,
  one (`generateServeRequestCommand`) talks to the local `bw serve` unix
  socket with `--noproxy '*'`; the other is the update check below.
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
