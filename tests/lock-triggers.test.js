#!/usr/bin/env node
// Tests for the two events that lock the vault without waiting out the
// auto-lock countdown, and for the window in which a terminal login's session
// key is accepted.
//
//   node tests/lock-triggers.test.js

const fs = require("fs")
const path = require("path")
const { execFileSync } = require("child_process")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.screenLockStateCommand = screenLockStateCommand
  exports.screenIsLocked = screenIsLocked
  exports.screenLockPollMs = screenLockPollMs
  exports.sleepMonitorCommand = sleepMonitorCommand
  exports.sleepSignalToken = sleepSignalToken
  exports.wakeSignalToken = wakeSignalToken
  exports.sessionHandoffReadCommand = sessionHandoffReadCommand
  exports.handoffWindowOpen = handoffWindowOpen
  exports.handoffWindowMs = handoffWindowMs
  exports.groupedSettings = groupedSettings
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// -------------------------------------------------------------------------
// Screen lock
// -------------------------------------------------------------------------

// Only "true" is locked. A shell with the lock plugin disabled answers
// "Target not found." and exits non-zero; that is "no answer", and a vault
// that reads it as "locked" would relock itself every few seconds forever.
const LOCK_ANSWERS = [
  ["true", true],
  ["true\n", true],
  ["  true  ", true],
  ["false", false],
  ["", false],
  ["Target not found.", false],
  ["TRUE", false],
  ["truthy", false],
  [null, false],
  [undefined, false],
]

for (const [raw, want] of LOCK_ANSWERS) {
  check(`screenIsLocked(${JSON.stringify(raw)}) is ${want}`,
    Model.screenIsLocked(raw) === want, String(Model.screenIsLocked(raw)))
}

const lockCmd = Model.screenLockStateCommand()
check("screen lock state is asked of the shell's own lock plugin",
  lockCmd.join(" ").includes("omarchy-shell lock isLocked"), lockCmd.join(" "))

check("screen lock state bounds what it will read back",
  /head -c \d+/.test(lockCmd.join(" ")), lockCmd.join(" "))

check("screen lock poll is a sane interval",
  Model.screenLockPollMs() >= 1000 && Model.screenLockPollMs() <= 15000,
  String(Model.screenLockPollMs()))

// -------------------------------------------------------------------------
// Suspend
// -------------------------------------------------------------------------

const sleepScript = Model.sleepMonitorCommand()[2]

check("suspend is taken from logind's PrepareForSleep",
  sleepScript.includes("PrepareForSleep") && sleepScript.includes("org.freedesktop.login1"),
  sleepScript)

// Without a delay inhibitor logind announces the sleep and suspends without
// waiting, so the lock would be racing the freeze.
check("a delay inhibitor is held so the lock lands before the freeze",
  sleepScript.includes("--what=sleep") && sleepScript.includes("--mode=delay"),
  sleepScript)

// sed quits on the match, but the monitor would then keep the pipeline open
// until it next wrote -- which is on the far side of the suspend. Killing it
// is what lets the inhibitor be released and the loop come round again.
check("the monitor is killed rather than left to a broken pipe",
  sleepScript.includes("kill \"$g\""), sleepScript)

check("the loop never exits, so a failure cannot become a hot restart",
  sleepScript.includes("while :; do") && /sleep 300/.test(sleepScript) && /sleep 5/.test(sleepScript),
  sleepScript)

check("sed is unbuffered, so the token is not held back past the suspend",
  /sed -une/.test(sleepScript), sleepScript)

// The end-to-end behaviour, against stubs standing in for gdbus and
// systemd-inhibit: the announcement has to produce exactly one token, the
// inhibitor has to be released about a second later, and the loop has to come
// round for the suspend after this one.
const os = require("os")
const work = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-lock-"))
try {
  const log = path.join(work, "inhibit.log")
  fs.writeFileSync(log, "")

  // Real gdbus is a single process, so the stub execs its wait rather than
  // backgrounding it -- otherwise the stub would leak a child that the real
  // thing does not have.
  fs.writeFileSync(path.join(work, "gdbus"), `#!/bin/bash
echo "Monitoring signals on object /org/freedesktop/login1 owned by org.freedesktop.login1"
echo "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (false,)"
echo "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)"
exec sleep 600
`)
  fs.writeFileSync(path.join(work, "systemd-inhibit"), `#!/bin/bash
while [[ "$1" == --* ]]; do shift; done
echo "ACQUIRED $(date +%s%3N)" >> "${log}"
"$@"; rc=$?
echo "RELEASED $(date +%s%3N)" >> "${log}"
exit $rc
`)
  for (const f of ["gdbus", "systemd-inhibit"]) fs.chmodSync(path.join(work, f), 0o755)

  const script = path.join(work, "cmd.sh")
  fs.writeFileSync(script, sleepScript)

  let out = ""
  try {
    out = execFileSync("bash", ["-c",
      `PATH=${work}:$PATH timeout 4 bash ${script}`], { encoding: "utf8" })
  } catch (e) {
    out = String(e.stdout || "")   // timeout always kills it; that is the point
  }

  const tokens = out.split("\n").map(s => s.trim()).filter(Boolean)

  check("an announcement produces the sleep token",
    tokens[0] === Model.sleepSignalToken(), JSON.stringify(tokens))

  check("resuming produces the wake token",
    tokens[1] === Model.wakeSignalToken(), JSON.stringify(tokens))

  // A `false` announcement is a resume, not a sleep. Two tokens per cycle, so
  // an odd count would mean the resume line matched as well.
  check("only a true announcement counts as a sleep",
    tokens.filter(t => t === Model.sleepSignalToken()).length
      === tokens.filter(t => t === Model.wakeSignalToken()).length
      || tokens[tokens.length - 1] === Model.sleepSignalToken(),
    JSON.stringify(tokens))

  // The bug this shape exists to avoid: the loop coming round only once.
  check("the loop detects more than one suspend per session",
    tokens.filter(t => t === Model.sleepSignalToken()).length >= 2,
    JSON.stringify(tokens))

  const entries = fs.readFileSync(log, "utf8").trim().split("\n").filter(Boolean)
  const acquired = entries.filter(l => l.startsWith("ACQUIRED")).length
  const released = entries.filter(l => l.startsWith("RELEASED")).length

  check("an inhibitor is taken for every cycle",
    acquired >= 2 && released >= 1 && acquired - released <= 1,
    entries.join(" | "))

  // Held about a second past the announcement, which is well inside logind's
  // InhibitDelayMaxSec (5s by default) and long enough for the panel to drop
  // the key and for the keyring clear it spawns to finish.
  const firstAcquire = Number(entries[0].split(" ")[1])
  const firstRelease = Number(entries.find(l => l.startsWith("RELEASED")).split(" ")[1])
  const held = firstRelease - firstAcquire
  check("the inhibitor is released promptly, not held across the suspend",
    held >= 900 && held < 4000, `${held}ms`)
} finally {
  fs.rmSync(work, { recursive: true, force: true })
}

// -------------------------------------------------------------------------
// Session handoff window
// -------------------------------------------------------------------------

const NOW = 1_700_000_000_000
const WINDOW = Model.handoffWindowMs()

check("the window is closed when no terminal login was ever launched",
  Model.handoffWindowOpen(0, NOW) === false, "0")

check("the window is open right after launching one",
  Model.handoffWindowOpen(NOW, NOW) === true, "same instant")

check("the window is still open partway through a slow login",
  Model.handoffWindowOpen(NOW - WINDOW / 2, NOW) === true, "half the window")

check("the window is open at the boundary",
  Model.handoffWindowOpen(NOW - WINDOW, NOW) === true, "exactly the window")

check("the window is closed past the boundary",
  Model.handoffWindowOpen(NOW - WINDOW - 1, NOW) === false, "one ms past")

// A clock stepped backwards is evidence the clock moved, not that the login
// was recent, so it must not reopen the window.
check("a clock stepped backwards closes the window rather than reopening it",
  Model.handoffWindowOpen(NOW + 60_000, NOW) === false, "start in the future")

check("a window long enough for a real 2FA login",
  WINDOW >= 5 * 60 * 1000, `${WINDOW}ms`)

const expecting = Model.sessionHandoffReadCommand(true)[2]
const discarding = Model.sessionHandoffReadCommand(false)[2]

check("an expected handoff is read out",
  expecting.includes("head -c"), expecting)

check("an unexpected handoff is not read out",
  !discarding.includes("head -c"), discarding)

// Not reading it is not the same as leaving it there. A live session key in
// the runtime directory is the worse of the two outcomes.
check("an unexpected handoff is still removed",
  discarding.includes("rm -f"), discarding)

check("an expected handoff is removed once consumed",
  expecting.includes("rm -f"), expecting)

// Both forms, run for real against a planted file.
{
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-handoff-"))
  try {
    const dir = path.join(runtime, "qs-bitwarden-cli")
    fs.mkdirSync(dir)
    const file = path.join(dir, "session-handoff")
    const KEY = "A".repeat(88)

    for (const [label, script, wantOut] of [
      ["expected", expecting, KEY],
      ["unexpected", discarding, ""],
    ]) {
      fs.writeFileSync(file, KEY)
      const out = execFileSync("bash", ["-c", script],
        { encoding: "utf8", env: { ...process.env, XDG_RUNTIME_DIR: runtime } })
      check(`an ${label} handoff returns ${wantOut ? "the key" : "nothing"}`,
        out.trim() === wantOut, JSON.stringify(out))
      check(`an ${label} handoff leaves no file behind`,
        !fs.existsSync(file), "file still present")
    }
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true })
  }
}

// -------------------------------------------------------------------------
// Both settings reach the settings screen
// -------------------------------------------------------------------------

const keys = Model.groupedSettings().map(e => e.key)
for (const k of ["lockOnScreenLock", "lockOnSuspend"]) {
  check(`${k} appears in the settings screen`, keys.includes(k), keys.join(", "))
  const entry = Model.groupedSettings().find(e => e.key === k)
  check(`${k} is a toggle in the Security group`,
    entry.type === "bool" && entry.group === "security", JSON.stringify(entry))
}

// The manifest is what the shell reads defaults from, so the two have to agree.
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"))
for (const k of ["lockOnScreenLock", "lockOnSuspend"]) {
  check(`${k} has a manifest default`,
    manifest.barWidget.defaults[k] === true, JSON.stringify(manifest.barWidget.defaults[k]))
  check(`${k} has a manifest schema entry`,
    manifest.barWidget.schema.some(e => e.key === k && e.type === "boolean"), k)
}

// -------------------------------------------------------------------------

if (failures.length) {
  console.error(`\n${failures.length} failure(s):\n`)
  for (const f of failures) console.error(`  ${f}\n`)
  process.exit(1)
}
console.log(`lock-triggers.test.js: ${pass} checks passed`)
