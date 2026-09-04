# Development

Linting and the test suite.

Omarchy plugins are Qt6/Quickshell, so lint with the **Qt6** `qmllint` --
`/usr/bin/qmllint` on Arch is the Qt5 binary from `qt5-declarative` and exits
255 with no diagnostics on this file. The `qs.*` modules resolve only when the
import path contains a directory named `qs`:

```bash
mkdir -p /tmp/qs-imports && ln -sfn /usr/share/omarchy/shell /tmp/qs-imports/qs
/usr/lib/qt6/bin/qmllint -I /tmp/qs-imports Panel.qml FormPickerRow.qml
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

Regression suites require Node; the SSH-items boundary suite also exercises jq:

```bash
node tests/auth.test.js             # unlock/login commands, and that no credential reaches argv
node tests/auth-prewarm.test.js     # private FIFO lifecycle, byte-exact password delivery, and cancellation
node tests/context-match.test.js    # window-title matching and learned suggestions
node tests/setup-settings.test.js   # dependency probe, settings writer, PIN crypto
node tests/ssh-items.test.js         # bounded out-of-process vault sanitization and SSH private-key exclusion
node tests/first-run.test.js        # a fresh install with no `bw` yet: the setup gate, the
                                    # sequence that follows the install, and what the
                                    # in-panel install button asks for
node tests/generator.test.js        # generator option clamping and strength
node tests/folders.test.js          # folder parsing, filtering and assignment
node tests/sends.test.js            # Send payloads, parsing, and argv-safety
node tests/collections.test.js      # organization collections and item ownership
node tests/items.test.js            # item parsing, and that a list entry can build the detail view
node tests/attachments.test.js      # attachment metadata, that a vault file name cannot escape ~/Downloads,
                                    # that a symlink cannot redirect a download, and the transfer ceilings
node tests/handoff-urls.test.js     # session-handoff file path, and which URI schemes may be opened
node tests/rich-text.test.js        # vault text is drawn as text, never parsed as markup
node tests/session-boot.test.js     # a remembered session dies with the boot that minted it
node tests/stream-limits.test.js    # every stream the shell reads is capped by its producer
node tests/lock-state.test.js       # the auto-lock survives a suspend, the timings are clamped
                                    # on the way in, and a read of a vault that has since closed
                                    # is refused rather than rendered
node tests/lock-triggers.test.js    # locking on screen lock and on suspend, and the window in
                                    # which a terminal login's session key is accepted
node tests/hardening.test.js        # `--` before every server-chosen id, the custom-server check,
                                    # and that logging out takes the learned suggestions with it
node tests/buffer-scrub.test.js     # emptying the pipe buffers a lock used to leave full, and the
                                    # deadline and size ceiling on every generator-port request
node tests/initial-load.test.js     # items render before folders, organizations and status refresh
node tests/performance.test.js      # deterministic small/typical/large/stress vault guardrails
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

---
