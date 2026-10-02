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
//
// Needs the built vault helper (cargo build --manifest-path vault/Cargo.toml
// --locked) and what shell.js needs.
//
//   node tests/e2e/pinentry.e2e.js

const { createSuite, repoRoot } = require("../harness")
const { createShell, pluginWithBuiltHelper } = require("./shell")
const fs = require("fs")
const path = require("path")

const { check, done, failures } = createSuite("e2e-pinentry")

const scratch = fs.mkdtempSync("/tmp/qsbw-pinentry-e2e-")
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
  const shell = createShell("e2e-pinentry", check, {
    plugin, env: { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log }
  })
  const { q, expect } = shell
  let failed = null
  try {
    shell.start()
    q("open")
    expect(`${label}: starts signed out`, s => s.status === "unauthenticated")
    expect(`${label}: pinentry is found on PATH`, s => s.pinentry.found === true)
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
  run("helper", pluginWithBuiltHelper(path.join(scratch, "plugin-helper")), true)
  runPin(pluginWithBuiltHelper(path.join(scratch, "plugin-pin")))
  run("fallback", withoutHelper(path.join(scratch, "plugin-fallback")), false)
} finally {
  fs.rmSync(scratch, { recursive: true, force: true })
}
done()
