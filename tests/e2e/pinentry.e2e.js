#!/usr/bin/env node
// End to end: the master password and the PIN typed into pinentry. A headless
// shell (shell.js) with the real vault helper (built at vault/target/debug)
// and the stand-in bin/pinentry, which answers each request from a file the
// test writes. No window opens.
//
// - Unlock with the master password through pinentry, the account's email
//   carrying a `%` so SETDESC's encoding and the password's decoding both
//   matter; a wrong password asks again with the reason; a cancel returns to
//   the locked screen without an error.
// - The same for the PIN.
// - What the shell holds of it: nothing typed in its fields.
// - Without the vault helper pinentry is not offered and the typed unlock
//   still works.
// - Pinentry ended from the panel's side (the panel asked for, the vault
//   locked, the helper killed): the question that asked is freed, and an
//   answer that arrives after the cancel is not left with the helper.
//
// Needs the built vault helper (cargo build --manifest-path vault/Cargo.toml
// --locked) and what shell.js needs. Name scenarios (helper, pin, fallback,
// cancel, late, probe, missing) to run only those.
//
//   node tests/e2e/pinentry.e2e.js [scenario ...]

const { createSuite, repoRoot } = require("../harness")
const { createShell, pluginWithBuiltHelper, helperPid, sleep } = require("./shell")
const fs = require("fs")
const os = require("os")
const path = require("path")

const { check, done, failures } = createSuite("e2e-pinentry")
const only = process.argv.slice(2)
const wanted = name => only.length === 0 || only.includes(name)

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-pinentry-e2e-"))
const answers = path.join(scratch, "answers")
const log = path.join(scratch, "log")
const email = "a%b@x"
const password = "pw-" + email
// Pinentry's data is percent-encoded: the % of the password is %25.
const encoded = "pin:pw-a%25b@x"

const answer = (...lines) => fs.writeFileSync(answers, lines.join("\n") + "\n")
const asked = () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8").split("\n").filter(Boolean) : [])
const reset = () => { fs.writeFileSync(log, "") }

function run(label, plugin, withHelper) {
  // Without a helper the vault is held in the shell only when allowed.
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log, QSBW_E2E_ALLOW_NO_HELPER: withHelper ? "0" : "1" }
  })
  const { q, expect } = shell
  let failed = null
  try {
    shell.start()
    q("open")
    expect(`${label}: starts signed out`, s => s.status === "unauthenticated")
    expect(`${label}: pinentry is not reported missing`, s => s.pinentry.missing === false)
    q("login", email, password)
    expect(`${label}: signs in`, s => s.status === "unlocked")
    expect(`${label}: the account is known by its email`, s => s.email === email)
    expect(`${label}: the vault helper is ${withHelper ? "up" : "not used"}`,
      s => s.helper === (withHelper ? "active" : "fallback"))
    q("lock")
    expect(`${label}: locks`, s => s.status === "locked")

    if (!withHelper) {
      expect(`${label}: pinentry is not offered without the helper`, s => s.pinentry.available === false)
      reset()
      q("unlockPinentry")
      shell.expect(`${label}: asking for it changes nothing`, s => s.status === "locked" && !s.pinentry.active)
      check(`${label}: and no pinentry was started`, asked().length === 0, asked().join("|"))
      q("unlock", password)
      expect(`${label}: the typed unlock still works`, s => s.status === "unlocked")
      return
    }

    expect(`${label}: pinentry is offered`, s => s.pinentry.available === true)

    // The master password.
    reset()
    answer(encoded)
    q("unlockPinentry")
    expect(`${label}: the master password typed into pinentry unlocks`, s => s.status === "unlocked")
    check(`${label}: pinentry is told to give up on its own`, asked().includes("SETTIMEOUT 120"), asked().join("|"))
    check(`${label}: the description names the account, % encoded`,
      asked().includes("SETDESC Unlock Bitwarden for a%25b@x"), asked().join("|"))
    check(`${label}: the shell holds nothing typed`, shell.state().typed === "||", shell.state().typed)
    expect(`${label}: pinentry is done`, s => !s.pinentry.active && !s.pinentry.declined)
    q("lock")
    expect(`${label}: locks again`, s => s.status === "locked")

    // A wrong password asks again, with the reason, then a right one.
    reset()
    answer("pin:wrong", encoded)
    q("unlockPinentry")
    expect(`${label}: a wrong password, then the right one, unlocks`, s => s.status === "unlocked")
    const requests = asked()
    check(`${label}: pinentry was asked twice, the second time with the reason`,
      requests.filter(l => l === "GETPIN").length === 2
        && requests.filter(l => l === "SETERROR That is not your master password.").length === 1, requests.join("|"))
    q("lock")
    expect(`${label}: locks`, s => s.status === "locked")

    // A cancel: back to the locked screen, nothing said.
    reset()
    answer("cancel")
    q("unlockPinentry")
    expect(`${label}: a cancel leaves the vault locked, quietly`,
      s => s.status === "locked" && s.error === "" && !s.pinentry.active && !s.pinentry.declined && s.pinentry.available)
    check(`${label}: it asked once`, asked().filter(l => l === "GETPIN").length === 1, asked().join("|"))

    // A pinentry that dies (or is killed): not remembered. The next attempt
    // opens pinentry again; the field is used only once picked.
    reset()
    answer("crash")
    q("unlockPinentry")
    expect(`${label}: a pinentry that fails says so and stays offered`,
      s => s.status === "locked" && !s.pinentry.active && !s.pinentry.declined && s.pinentry.available
        && /stopped before answering/.test(s.pinentry.notice))
    reset()
    answer(encoded)
    q("unlockPinentry")
    expect(`${label}: trying again opens pinentry and unlocks`, s => s.status === "unlocked" && s.pinentry.notice === "")
    check(`${label}: it was asked again`, asked().filter(l => l === "GETPIN").length === 1, asked().join("|"))
    q("lock")
    expect(`${label}: locks`, s => s.status === "locked")
    reset()
    answer("crash")
    q("unlockPinentry")
    expect(`${label}: fails again`, s => !s.pinentry.active && /stopped before answering/.test(s.pinentry.notice))
    q("declinePinentry")
    expect(`${label}: the field, once picked, is used and says what that costs`,
      s => s.pinentry.declined && !s.pinentry.available && /stays in the shell's memory/.test(s.pinentry.notice))
    q("unlock", password)
    expect(`${label}: and the typed unlock works`, s => s.status === "unlocked")
    q("lock")
    expect(`${label}: locks, and pinentry is offered again`, s => s.status === "locked" && s.pinentry.available
      && !s.pinentry.declined && s.pinentry.notice === "")
  } catch (e) {
    failed = e
    check(`${label}: ran to the end`, false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error(`--- ${label} shell log (tail) ---\n` + shell.logTail())
    shell.cleanup()
  }
}

// The PIN, in a shell of its own: a second account would not add to this.
function runPin(plugin) {
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log }
  })
  const { q, expect } = shell
  let failed = null
  try {
    shell.start()
    q("open")
    expect("pin: starts signed out", s => s.status === "unauthenticated")
    q("login", "a@x", "pw-a@x")
    expect("pin: signs in", s => s.status === "unlocked")
    q("setPin", "111111", "pw-a@x")
    expect("pin: a PIN is set", s => s.pinConfigured && s.pinReady)
    q("lock")
    expect("pin: locks", s => s.status === "locked")

    reset()
    answer("pin:111111")
    q("pinUnlockPinentry")
    expect("pin: the PIN typed into pinentry unlocks", s => s.status === "unlocked")
    check("pin: it was asked for as a PIN", asked().includes("SETPROMPT PIN:"), asked().join("|"))
    check("pin: the shell holds nothing typed", shell.state().typed === "||", shell.state().typed)
    q("lock")
    expect("pin: locks again", s => s.status === "locked")

    reset()
    answer("pin:222222", "pin:111111")
    q("pinUnlockPinentry")
    expect("pin: a wrong PIN, then the right one, unlocks", s => s.status === "unlocked")
    const requests = asked()
    check("pin: the second request carries the count",
      requests.filter(l => l === "GETPIN").length === 2 && requests.includes("SETERROR Incorrect PIN (1 of 5)"),
      requests.join("|"))
    q("lock")
    expect("pin: locks", s => s.status === "locked")

    // Shorter than the floor: asked again with the field's message, not counted.
    reset()
    answer("pin:12", "pin:111111")
    q("pinUnlockPinentry")
    expect("pin: a short PIN, then the right one, unlocks", s => s.status === "unlocked")
    const shortRequests = asked()
    check("pin: the short one was asked again with the length, and counted as nothing",
      shortRequests.filter(l => l === "GETPIN").length === 2
        && shortRequests.some(l => /^SETERROR PIN must be at least \d+ digits$/.test(l))
        && !shortRequests.some(l => /Incorrect PIN/.test(l)), shortRequests.join("|"))
    q("lock")
    expect("pin: locks", s => s.status === "locked")

    reset()
    answer("cancel")
    q("pinUnlockPinentry")
    expect("pin: a cancel leaves it locked and says nothing",
      s => s.status === "locked" && !s.pinentry.active && s.pinUnlockError === "" && s.error === "")
  } catch (e) {
    failed = e
    check("pin: ran to the end", false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error("--- pin shell log (tail) ---\n" + shell.logTail())
    shell.cleanup()
  }
}

// Pinentry ended from the panel's side. Signed in with an item that asks
// for the master password, asked from the list (copying its password), where
// reopening the panel does not change the screen.
function runCancels(plugin) {
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log }
  })
  const { q, expect } = shell
  const data = path.join(shell.home, ".config", "Bitwarden CLI")
  let failed = null
  try {
    fs.mkdirSync(data, { recursive: true })
    fs.writeFileSync(path.join(data, "fake-item-reprompt"), "1")
    shell.start()
    q("open")
    q("login", "a@x", "pw-a@x")
    expect("cancel: signs in, on the list", s => s.status === "unlocked" && s.screen === "main" && s.items.length === 1)

    // The panel asked for while pinentry asks: the panel wins, and the
    // question is free to ask again.
    q("copyFirst")
    expect("cancel: copying asks for the master password", s => s.reprompt.pending && !s.reprompt.busy)
    answer("hang")
    q("repromptPinentry")
    expect("cancel: the question waits on pinentry", s => s.reprompt.busy && s.pinentry.active && !s.opened)
    q("open")
    expect("cancel: reopening ends pinentry and frees the question, still asked",
      s => !s.pinentry.active && s.opened && s.reprompt.pending && !s.reprompt.busy && s.reprompt.error === "")
    reset()
    answer("pin:pw-a@x")
    q("repromptPinentry")
    expect("cancel: asked again, the right password does the copy", s => !s.reprompt.pending && !s.reprompt.busy)
    check("cancel: pinentry was asked again", asked().filter(l => l === "GETPIN").length === 1, asked().join("|"))

    // The vault locked while pinentry asks: pinentry ends with it.
    q("copyFirst")
    expect("lock: copying asks again", s => s.reprompt.pending && !s.reprompt.busy)
    answer("hang")
    q("repromptPinentry")
    expect("lock: the question waits on pinentry", s => s.reprompt.busy && s.pinentry.active)
    q("lock")
    expect("lock: locking ends pinentry and the question",
      s => s.status === "locked" && !s.pinentry.active && !s.reprompt.pending && !s.reprompt.busy)

    // The vault helper killed while pinentry asks for the master password:
    // a failure, said so, with no field offered while the helper restarts.
    reset()
    answer("hang")
    q("unlockPinentry")
    expect("helper: pinentry asks to unlock", s => s.pinentry.active && s.helper === "active")
    const pid = helperPid(shell.pid())
    check("helper: the helper runs", pid > 0, "")
    if (pid) process.kill(pid, "SIGKILL")
    const seen = new Set()
    const after = expect("helper: pinentry ends as a failure, said so, and the helper is back", s => {
      seen.add(s.pinentry.entry)
      return !s.pinentry.active && s.helper === "active" && /stopped before answering/.test(s.pinentry.notice)
    })
    check("helper: no field was offered meanwhile", !seen.has("field"), [...seen].join())
    check("helper: nothing typed reached the shell", after && after.typed === "||" && after.status === "locked", after && after.typed)
    reset()
    answer("pin:pw-a@x")
    q("unlockPinentry")
    expect("helper: trying again opens pinentry and unlocks", s => s.status === "unlocked" && s.pinentry.notice === "")
  } catch (e) {
    failed = e
    check("cancel: ran to the end", false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error("--- cancel shell log (tail) ---\n" + shell.logTail())
    shell.cleanup()
  }
}

// A `bash` first in PATH that runs the panel's pinentry script with SIGTERM
// ignored (and so its pinentry too): a cancel's kill then lands too late, as
// when pinentry was already answering. Everything else is the real bash.
function termIgnoringBash(dir) {
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, "bash"), [
    "#!/usr/bin/bash",
    'case "${2:-}" in *"coproc PE"*) trap "" TERM ;; esac',
    'exec /usr/bin/bash "$@"',
    ""
  ].join("\n"), { mode: 0o755 })
  return dir
}

// An answer that arrives after the panel cancelled pinentry is not left with
// the helper.
function runLate(plugin) {
  const release = path.join(scratch, "release")
  const wrap = termIgnoringBash(path.join(scratch, "late-bin"))
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log, FAKE_PINENTRY_RELEASE: release,
                   PATH: `${wrap}:${path.join(__dirname, "bin")}:/usr/local/bin:/usr/bin:/bin` }
  })
  const { q, expect } = shell
  const data = path.join(shell.home, ".config", "Bitwarden CLI")
  let failed = null
  try {
    fs.rmSync(release, { force: true })
    fs.mkdirSync(data, { recursive: true })
    fs.writeFileSync(path.join(data, "fake-item-reprompt"), "1")
    shell.start()
    q("open")
    q("login", "a@x", "pw-a@x")
    expect("late: signs in", s => s.status === "unlocked" && s.items.length === 1)
    q("copyFirst")
    expect("late: copying asks for the master password", s => s.reprompt.pending)
    reset()
    answer("held:pw-a@x")
    q("repromptPinentry")
    const asking = expect("late: pinentry asks", s => s.pinentry.active && s.pinentryName !== "")
    const name = asking && asking.pinentryName
    q("open")
    expect("late: reopening cancels it", s => !s.pinentry.active && !s.reprompt.busy && s.opened)
    // The answer, after the cancel and inside the helper's grace before KILL.
    fs.writeFileSync(release, "")
    for (let i = 0; i < 100 && !asked().includes("released"); i++) sleep(100)
    check("late: pinentry answered after the cancel", asked().includes("released"), asked().join("|"))
    sleep(1500)
    q("checkHeld", name)
    const s = expect("late: the helper answers the check", s => s.held !== "")
    check("late: the answer is not held under the cancelled run's name", s && s.held === "none", s && s.held)
    check("late: and was used for nothing", s && s.reprompt.pending, JSON.stringify(s && s.reprompt))
  } catch (e) {
    failed = e
    check("late: ran to the end", false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error("--- late shell log (tail) ---\n" + shell.logTail())
    shell.cleanup()
  }
}

// The probe for pinentry killed as the shell starts (a `bash` first in PATH
// that waits before running it): pinentry is still used, not the field.
function runProbeKilled(plugin) {
  const pids = path.join(scratch, "probe-pids")
  const wrap = path.join(scratch, "probe-bin")
  fs.mkdirSync(wrap, { recursive: true })
  fs.writeFileSync(path.join(wrap, "bash"), [
    "#!/usr/bin/bash",
    // The probe alone (Model.pinentryProbeCommand(): bash -c <script> _ <program>).
    'if [ "$#" -eq 4 ] && [[ "$2" == "command -v -- \\"\\$1\\""* ]]; then echo "$$" >> "$QSBW_PROBE_PIDS"; sleep 600; fi',
    'exec /usr/bin/bash "$@"',
    ""
  ].join("\n"), { mode: 0o755 })
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log, QSBW_PROBE_PIDS: pids,
                   PATH: `${wrap}:${path.join(__dirname, "bin")}:/usr/local/bin:/usr/bin:/bin` }
  })
  const { q, expect } = shell
  let failed = null
  try {
    fs.rmSync(pids, { force: true })
    shell.start()
    for (let i = 0; i < 100 && !fs.existsSync(pids); i++) sleep(100)
    const probes = fs.existsSync(pids) ? fs.readFileSync(pids, "utf8").split("\n").filter(Boolean) : []
    check("probe: the probe was started", probes.length > 0, "")
    for (const pid of probes) { try { process.kill(Number(pid), "SIGKILL") } catch (e) {} }
    q("open")
    q("login", "a@x", "pw-a@x")
    expect("probe: signs in", s => s.status === "unlocked")
    q("lock")
    expect("probe: a killed probe leaves pinentry offered, not the field",
      s => s.status === "locked" && s.pinentry.available === true)
    reset()
    answer("pin:pw-a@x")
    q("unlockPinentry")
    expect("probe: and pinentry unlocks", s => s.status === "unlocked")
    check("probe: pinentry was asked", asked().filter(l => l === "GETPIN").length === 1, asked().join("|"))
  } catch (e) {
    failed = e
    check("probe: ran to the end", false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error("--- probe shell log (tail) ---\n" + shell.logTail())
    shell.cleanup()
  }
}

// A pinentry that is really not installed: the probe's own answer says so,
// and the panel's field is the way in, with no pinentry started.
function runMissing(plugin) {
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log,
                   QSBW_E2E_PINENTRY: path.join(scratch, "no-such-pinentry") }
  })
  const { q, expect } = shell
  let failed = null
  try {
    shell.start()
    q("open")
    q("login", "a@x", "pw-a@x")
    expect("missing: signs in", s => s.status === "unlocked")
    q("lock")
    expect("missing: the probe says pinentry is missing, and the field is the way in",
      s => s.status === "locked" && s.helper === "active" && s.pinentry.missing === true && s.pinentry.entry === "field")
    reset()
    q("unlock", "pw-a@x")
    expect("missing: the typed unlock works", s => s.status === "unlocked")
    check("missing: no pinentry was started", asked().length === 0, asked().join("|"))
  } catch (e) {
    failed = e
    check("missing: ran to the end", false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error("--- missing shell log (tail) ---\n" + shell.logTail())
    shell.cleanup()
  }
}

function withoutHelper(into) {
  fs.cpSync(repoRoot, into, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      return !/^\.git(\/|$)/.test(rel) && !/(^|\/)target(\/|$)/.test(rel)
        && rel !== "bin/x86_64-linux/qs-bitwarden-vault"
    }
  })
  return into
}

try {
  if (wanted("helper")) run("helper", pluginWithBuiltHelper(path.join(scratch, "plugin-helper")), true)
  if (wanted("pin")) runPin(pluginWithBuiltHelper(path.join(scratch, "plugin-pin")))
  if (wanted("fallback")) run("fallback", withoutHelper(path.join(scratch, "plugin-fallback")), false)
  if (wanted("cancel")) runCancels(pluginWithBuiltHelper(path.join(scratch, "plugin-cancel")))
  if (wanted("late")) runLate(pluginWithBuiltHelper(path.join(scratch, "plugin-late")))
  if (wanted("probe")) runProbeKilled(pluginWithBuiltHelper(path.join(scratch, "plugin-probe")))
  if (wanted("missing")) runMissing(pluginWithBuiltHelper(path.join(scratch, "plugin-missing")))
} finally {
  fs.rmSync(scratch, { recursive: true, force: true })
}
done()
