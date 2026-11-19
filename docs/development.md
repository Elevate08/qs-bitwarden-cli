# Development

Linting and the test suite.

Omarchy plugins are Qt6/Quickshell, so lint with the **Qt6** `qmllint` --
`/usr/bin/qmllint` on Arch is the Qt5 binary from `qt5-declarative` and exits
255 with no diagnostics on this file. The `qs.*` modules resolve only when the
import path contains a directory named `qs`:

```bash
mkdir -p /tmp/qs-imports && ln -sfn /usr/share/omarchy/shell /tmp/qs-imports/qs
/usr/lib/qt6/bin/qmllint -I /tmp/qs-imports *.qml
```

Remaining `unqualified` and `missing-property` warnings are baseline Quickshell
noise -- the stock Omarchy plugins report the same categories -- as are the
`signal-handler-parameters` warnings on `Process.onExited`, whose
`QProcess::ExitStatus` argument qmllint cannot see.

Validate the manifest against the schema the shell enforces:

```bash
omarchy plugin validate .
```

---

## Tests

Regression suites need Node (and jq for the SSH-items suite). Each suite's
header says what it covers; run them all the way CI does:

```bash
for t in tests/*.test.js; do node "$t" || echo "FAILED: $t"; done
```

The helpers have their own Rust tests:

```bash
cargo test --manifest-path agent/Cargo.toml
cargo test --manifest-path unlock-key/Cargo.toml
cargo test --manifest-path vault/Cargo.toml
```

Shared helpers live in `tests/harness.js`: `loadModule()` evaluates a
`.pragma library` file and exposes its top-level names, `createSuite()` records
and reports checks, and `readPluginSource()` returns QML as text. The vault
lives in `Service.qml` (loaded once per shell) and `Panel.qml` is the per-monitor
view; for `Panel.qml`, `readPluginSource()` returns the vault followed by the
view with `root.vault.` folded back to `root.`, and `service-host.test.js` keeps
that fold exact. `tests/legacy-keyring.js` writes the pre-envelope keyring
entries that migration tests start from.

Multi-monitor behaviour can be checked on a single screen with a headless
output, which gives the shell a second bar and the plugin a second view:

```bash
hyprctl output create headless QSBWTEST
omarchy-shell io.github.elevate08.qs-bitwarden-cli vaultHost   # views: 2
hyprctl dispatch 'hl.dsp.focus({ monitor = "QSBWTEST" })'       # move focus there
hyprctl output remove QSBWTEST
```

The performance suite generates invented 100-item/0.25 MiB, 500-item/1 MiB,
2,000-item/5 MiB and 5,000-item/14 MiB vaults. It reports p95 JSON parsing,
filtering and contextual-match times over 20 warm samples and fails on broad
regressions. It measures only in-process work after `bw` returns, so network,
server and CLI startup latency should be measured separately on the target
machine.

On 2026-11-19 (Node 22.23.3, three runs each) the contextual-match p95 went
from 14.4-15.4 ms to 8.9-9.2 ms on the 5,000-item tier and from 6.7 ms to
5.3 ms on the 2,000-item tier, when `hasWholeWord()` stopped building a
RegExp for a word of lowercase ASCII letters, digits and hyphens that is
not in the lowercased title (any other word still builds one); the two smaller tiers moved
within their noise (about 2 ms and under 1 ms), and parse and filter did not
change.

Opening the panel used to run that match twice: once on the window the panel
already knew (`ensureItemsFresh()`), and again when the compositor named the
focused one. `handleActiveWindowDetected()` now keys an answer by its inputs
(`Model.contextMatchKey()`: the window's data, and a count that
`onItemsChanged` / `onAssociationsChanged` move whenever the list or the
learned picks are replaced) and matches only for a question it has not just
answered. In Node, same machine and fixtures (2026-11-19, p95 of 40 opens,
matching only): an open from another window than last time went from two
passes to one, 14.8 ms to 6.9 ms at 5,000 items, 5.3 ms to 2.5 ms at 2,000
and 1.2 ms to 0.6 ms at 500; an open from the same window, nothing having
changed, from two passes to none (0.01 ms). Two passes remain only when
both hold: the answer for the window last seen is stale (the learned picks
were replaced since; a list reload refreshes it at once) and the open is
from a different window, the stale one being matched first. A window whose data JSON cannot spell exactly (a number
that is not finite) is given no key and matched on every pass in which it is
the window being matched (so once, when only the newly focused window is
such a one and the answer for the window last seen is current), and an empty
list clears the suggestions, as the vault purge does. The list is still
rebuilt on both passes. The suite's two `open` columns report this, and
`tests/context-match.test.js` checks the counts and, over 400 random opens,
reloads, picks and toggles, that what is shown is what a fresh match gives.

The 2026-08-24 auth benchmark used Bitwarden CLI 2026.2.0 and three runs with a
deliberately invalid password. A normal unlock took 2,641 ms median from submit
to result; after a three-second prewarm while the password screen was already
open, it took 1,026 ms -- a 1,615 ms / 61.1% reduction. These figures are a
same-machine comparison, not a universal latency promise.

On the same machine and CLI (2026-09-25), `bw status` printed its answer at
about 1.3 s and exited at about 3.2 s: after `processResponse()` records the
exit code, rxjs timers keep Node alive. With `bw-fast-exit.js` preloaded, on a
real vault, `status` and the `list` commands took about 0.8 s (items 1.6 s)
instead of 2.7-3.0 s, and `get item`/`password`/`totp` 1.25 s instead of
3.1 s, each with identical output and exit code. `tests/bw-fast-exit.test.js`
covers the guard that keeps the preload to `bw` itself.

Node's compile cache (`NODE_COMPILE_CACHE`) is the opt-in `bwCompileCache`
setting, off by default. With it on, `bwEnv()` gives `bw` the directory
`Model.bwCompileCacheCommand()` printed once it had checked it; with it off,
while a check is running and after one that failed, `bwEnv()` removes the
variable instead, so an inherited one is never used. A `bw` that is given
the master password or a login's credentials (`bwSecretEnv()`: unlock and
the process waiting for it, every login, the password check) never gets it.
Measured on 2026-11-19 (same machine, CLI 2026.2.0, Node 22.23.3, vault
locked, both preloads, no `BW_SESSION`, a scratch cache home on the runtime
tmpfs, 11 interleaved runs each, medians): `bw status` as
`Model.statusCommand()` runs it took 656 ms without and 543 ms with (113 ms,
17%), `bw --version` 647 ms and 529 ms (118 ms, 18%), with identical output
and exit code. Only those two commands were timed, and neither against an
open vault; the saving is in Node loading `bw`'s 1,600 modules, which every
`bw` command does first, so about a tenth of a second per start is what to
expect. The waits that get it are the ones a cached `bw` is behind: saving,
deleting and creating items, folders and sends, a sync, a list refresh
after the first of an opening, opening an item's details, TOTP and
password reads, attachment downloads, the generator and the status polls.
Unlocking and logging in do not: those `bw` runs are never cached, and the
list read an unlock starts runs before that opening's check has answered.
(The production version probe, `bw -v` in `bwVersionCommand()`, is one of
the launches that never gets the cache; `--version` is here only as a
second benchmark.)

Which launches get it, and which never do (unlock, login, the password
check, the pinentry, `bw -v`, the terminal hand-off, the slot-removal `bw
logout`, every `node -e` check), is listed in [REVIEWING.md](../REVIEWING.md)
and held by the inventory in `tests/bw-compile-cache.test.js`: a model
function whose script starts `bw` or `node` and is not listed there fails
the suite. Add a new one to the inventory with the environment it runs in; a
`node -e` goes through `NODE_UNCACHED`, and a `bw` that is handed a password
through `bwSecretEnv()`.

The check itself (`bash`, `id`, `realpath`, a `stat` per directory up to `/`,
one `find` over the plugin's directory) took 19 ms over a filled cache of
1,631 entries (median of 21, same tmpfs) and 24 ms the first time, when it
makes the directories; both on tmpfs, not timed on a disk. It runs at shell
start, when the setting is turned on, and every time the vault becomes
unlocked; nothing else is remembered between checks. A new check withdraws
the last answer until it has its own, so the reads an opening starts run
without the cache. An environment built before its `bw` starts is settled
at the start (`bwEnvAtStart()`, called by `vaultStart()` and
`VaultProcess.launchLocal()`), so a directory since withdrawn is never
delivered. Checking before every `bw` start was not done: QML cannot stat a
path without a process, each start would wait on one, and the directory
could still change between that check and Node opening it. Instead the
directory is not looked at between checks; REVIEWING.md says what that
leaves. A shell with a umask of 002 loses the cache at the second check:
Node's own version directory inside it is then group-writable.

`tests/bw-compile-cache.test.js` needs a directory whose whole ancestor chain
is the user's or root's for its filesystem cases. Whether a directory is one
is decided by the tests themselves with plain `fs` calls
(`privateScratchDir()` in `tests/harness.js`: `$XDG_RUNTIME_DIR`, then
`$RUNNER_TEMP`, the account's home, the tests directory), never by the check
under test: a scratch directory made there must then be accepted, and a
check that refuses it fails the suite. Only where none of those qualifies
are the filesystem cases skipped, with a line saying so
(`QSBW_TEST_NO_TRUSTED_DIR=1` forces that). The end-to-end shells' home is
under `/tmp`, which the check refuses, so `tests/e2e/accounts.e2e.js` gives
two extra shells a cache home found the same way (setting off, then on) and
reads what the stand-in `bw` was started with from `bw.log.cache`; the
setting-on shell is skipped, also with a line, only where there is no such
directory.

`bw-login-code.js`, the other preload, gives `bw login` the two-step code from
`QSBW_CODE` in place of the `--qsbw-code-from-env` placeholder, so the code is
in `bw`'s parsed arguments but not in `/proc/<pid>/cmdline`.
`tests/bw-login-code.test.js` checks both, and that every case it does not
handle leaves the placeholder for `bw` to refuse.

Some suites need Qt rather than Node -- which any machine running the plugin
already has. They cover the things only a real Qt can answer: that Escape
reaches the panel from inside a text field, how Qt itself decides to draw a
string (which is what makes a vault value markup or text), and how wide the
kit's Button actually renders a given label in the shell's font.

That last one, `tst_row_widths.qml`, reads the panel's own QML and measures
every row of buttons against the width of the panel they sit in. It needs to
read those files from inside QML, which Qt gates behind an env var:

```bash
QML_XHR_ALLOW_FILE_READ=1 QT_QPA_PLATFORM=offscreen \
  /usr/lib/qt6/bin/qmltestrunner -input tests/qml
```

Note the **Qt6** binary. A bare `qmltestrunner` on Arch is the Qt5 one from
`qt5-declarative`; it reports `Library import requires a version` and exits 1
with no test output at all. If a run prints nothing whatsoever, that is why.

`QT_ASSUME_STDERR_HAS_CONSOLE=1` is worth adding while debugging a QML test --
without it `console.log()` from inside QML is silently dropped.

### End to end

`tests/e2e/accounts.e2e.js` runs the real `Service.qml` in a headless
Quickshell and drives it over a test-only IPC target (`tests/e2e/config/`,
never loaded by a real shell): signing two accounts in, a PIN each, switching,
a shell restart, logging out. `bw`, `secret-tool` and `systemd-creds` are
stand-ins from `tests/e2e/bin/`; the committed unlock tool, `argon2`, `jq`
and `node` run for real. It builds its own HOME, XDG and runtime directories
under `/tmp` and passes nothing of your environment on, so it cannot touch
your vault, keyring or shell. It is named `*.e2e.js` so the loop above skips
it, and needs `quickshell`:

```bash
node tests/e2e/accounts.e2e.js
```

`tests/e2e/ssh-lock.e2e.js` (about 15 s) runs the same shell with the SSH
agent on and an SSH key in the stand-in vault. A client signs under a grant,
then the vault closes without the lock button: the vault helper is killed with
a `bw status` in flight, and later `bw` reports the vault locked. Each time
the same client must get no signature. It also needs `ssh-keygen`:

```bash
node tests/e2e/ssh-lock.e2e.js
```

`tests/e2e/helper-stops.e2e.js` (about a minute) checks that the vault never
moves into the shell because the vault helper is gone: killed four times, the
helper is left stopped with the vault locked, and "check again" brings it
back; a helper missing at start leaves the vault locked and runs no vault
command, unless `allowVaultWithoutHelper` is set. `--settle` adds four kills a
minute apart, which must not add up (about 5 minutes more):

```bash
node tests/e2e/helper-stops.e2e.js
```

`KEEP_E2E=1` keeps the temporary directory (the shell log, the stand-in
`bw`'s call log and keyring) for a failed run. CI runs both in the **panel
end-to-end** job: a digest-pinned Arch image with packages from a dated,
signature-checked Arch Linux Archive snapshot, as an unprivileged user, with
a read-only token and no secrets, along with `lock-on-unload` and
`helper-stops`. Moving the snapshot date means moving the
image digest with it, so the keyring and the packages stay from the same day.
