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

The 2026-08-24 auth benchmark used Bitwarden CLI 2026.2.0 and three runs with a
deliberately invalid password. A normal unlock took 2,641 ms median from submit
to result; after a three-second prewarm while the password screen was already
open, it took 1,026 ms -- a 1,615 ms / 61.1% reduction. These figures are a
same-machine comparison, not a universal latency promise.

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

`KEEP_E2E=1` keeps the temporary directory (the shell log, the stand-in
`bw`'s call log and keyring) for a failed run. CI runs it in the **panel
end-to-end** job: a digest-pinned Arch image with packages from a dated,
signature-checked Arch Linux Archive snapshot, as an unprivileged user, with
a read-only token and no secrets. Moving the snapshot date means moving the
image digest with it, so the keyring and the packages stay from the same day.
