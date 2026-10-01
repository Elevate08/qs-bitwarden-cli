#!/usr/bin/env node
// Typed secrets in pinentry (Service.qml, "Typed secrets in pinentry"): the
// flows are run here against a stand-in vault (the state they read and write,
// a pinentry process that answers when the test says so); the wiring that
// cannot be run is checked in the source.
//
//   node tests/pinentry-service.test.js

const { createSuite, functionBody, loadModule, read } = require("./harness")

const Model = loadModule()
const service = read("Service.qml")
const body = name => functionBody(service, name)
const { check, eq, done } = createSuite("pinentry-service")

const names = ["requestPinentry", "onPinentryExited", "beginPinentry", "endPinentry", "cancelPinentry",
  "resumeFromPinentry", "unlockWithPinentry", "unlockPinWithPinentry", "retryPinentryPin", "releaseHeldPin",
  "submitRepromptWithPinentry", "submitReprompt", "forgetHeldPassword", "forgetHeldAfter", "onUnlockOutput"]

function makeVault(extra) {
  const v = {
    Model, Qt: { callLater: f => f() },
    usePinentry: true, pinentryFound: true, pinentryBroken: false, vaultHelperActive: true,
    get pinentryAvailable() { return this.usePinentry && this.pinentryFound && !this.pinentryBroken && this.vaultHelperActive },
    pinentryProgramName: "pinentry", userEmail: "me@example.com",
    pinentryActive: false, pinentryRun: null, pinentryView: null, pinentryWasOpen: false, pinentryReturning: false,
    pinentryMasterName: "", pinentryNotice: "", heldPinName: "",
    status: "locked", errorMessage: "", isUnlocking: false, masterPassword: "", pinEntry: "", pinUnlockError: "",
    pinReady: true, pinBusy: false, pinUnlockSubmitted: false, sshAuthSurfaceActive: true,
    pendingUnlockFrom: "", pendingUnlockPassword: "", pendingPinForMigration: "", fingerprintFromEnvelope: false,
    pinFromEnvelope: false, fidoFromEnvelope: false, restored: 0,
    repromptPending: false, repromptBusy: false, repromptError: "", repromptItemId: "", repromptEpoch: 1,
    vaultEpoch: 1, repromptCallback: null, repromptVerifiedId: "", repromptActionId: "", detailItem: null,
    opened: true, seq: 0, forgotten: [], unlocks: [], pinSubmits: [], shows: 0, verifies: [],
    proc: { running: false, runId: 0, command: null, capture: "", starts: [] },
    newHeldName() { this.seq += 1; return "pw" + this.seq },
    forgetVaultSecret(name) { this.forgotten.push(name) },
    restoreScreenFocus() { this.restored += 1 },
    unlockVaultWithPassword(p) { this.unlocks.push(p) },
    submitPinUnlock(p) { this.pinSubmits.push(p); this.pinUnlockSubmitted = this.submitTakesIt },
    submitTakesIt: true,
    verifyMasterPassword(pw, cb) { this.verifies.push(pw); this.verifyDone = cb },
    prepareUnlock() {}, clearRepromptGrant() {},
    view: null,
    eachView(fn) { fn(this.view) },
    get presenter() { return this.view }
  }
  Object.defineProperty(v, "pinentryProc", { get() { return this.proc } })
  v.view = { hidePopout() { v.opened = false }, showPopout() { v.opened = true; v.shows += 1 } }
  Object.assign(v, extra || {})
  v.root = v
  const make = new Function("root", "with (root) {\n" + names.map(body).join("\n")
    + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")
  Object.assign(v, make(v))
  return v
}

// The run's end as the process reports it.
function finish(v, code, held, stderr) {
  v.proc.running = false
  v.onPinentryExited(code, held, stderr || "")
}

// --- the master password unlock -------------------------------------------------------

{
  const v = makeVault()
  // `proc.running = true` is the start: record the command it was given.
  Object.defineProperty(v.proc, "running", {
    configurable: true, get() { return this._r === true },
    set(value) { if (value) this.starts.push({ command: this.command, capture: this.capture }); this._r = value }
  })
  v.unlockWithPinentry()
  const run = v.proc.starts[0]
  check("an unlock starts a pinentry run that the helper holds", run && /^pinentry:pw\d+$/.test(run.capture), JSON.stringify(run))
  check("the run is the pinentry script, asking for the account's master password",
    run && run.command[1] === Model.pinentryCommand("pinentry", {})[1] && run.command[4] === "pinentry"
      && /me@example\.com/.test(run.command[6]) && run.command[7] === "Master password:" && run.command[8] === "",
    JSON.stringify(run && run.command.slice(3)))
  check("the panel is hidden meanwhile and the unlock is not yet started",
    v.pinentryActive && !v.opened && v.unlocks.length === 0, "")
  const name = run.capture.slice("pinentry:".length)
  finish(v, 0, true)
  eq("the held name, not the password, goes to the unlock", v.unlocks.join(), Model.heldSecretRef(name))
  check("nothing typed is in the shell's fields", v.masterPassword === "" && v.pinEntry === "", "")
  check("the unlock remembers the name for a retry and the panel comes back",
    v.pinentryMasterName === name && v.opened && v.shows === 1 && !v.pinentryActive && v.pinentryReturning, "")
  check("coming back is a resume, not a fresh open", v.resumeFromPinentry() === true && v.restored === 1
    && v.resumeFromPinentry() === false, "")

  // `bw` refuses it: forgotten, and asked for again with the reason.
  v.proc.starts.length = 0
  v.isUnlocking = true
  v.pendingUnlockPassword = Model.heldSecretRef(name)
  v.onUnlockOutput("", "Invalid master password.", 1)
  check("a refused password is forgotten", v.forgotten.includes(name) && v.pendingUnlockPassword === "", v.forgotten.join())
  check("and pinentry asks again with an error, in a new run",
    v.proc.starts.length === 1 && v.proc.starts[0].command[8] === "That is not your master password."
      && v.proc.starts[0].capture !== run.capture, JSON.stringify(v.proc.starts))
  check("no error is shown in the panel for it", v.errorMessage === "" || /not logged in/.test(v.errorMessage), v.errorMessage)

  // Cancelled: back to the unlock screen, nothing said.
  const second = v.proc.starts[0].capture.slice("pinentry:".length)
  v.unlocks.length = 0
  finish(v, 1, false)
  check("a cancel starts nothing, forgets the name, says nothing and restores the panel",
    v.unlocks.length === 0 && v.forgotten.includes(second) && v.errorMessage === "" && v.opened && !v.pinentryActive
      && !v.pinentryBroken, "")
}

// --- when pinentry cannot be used ---------------------------------------------------------

{
  const v = makeVault({ vaultHelperActive: false })
  let started = false
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return false }, set() { started = true } })
  v.unlockWithPinentry()
  check("without the vault helper nothing is run and nothing changes", !started && !v.pinentryActive && v.opened
    && v.unlocks.length === 0, "")
  check("it is not available then", v.pinentryAvailable === false, "")
  check("nor when turned off or not installed",
    makeVault({ usePinentry: false }).pinentryAvailable === false && makeVault({ pinentryFound: false }).pinentryAvailable === false, "")
}

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockWithPinentry()
  finish(v, 4, false, "")
  check("a failed run turns pinentry off for the session and says why",
    v.pinentryBroken && !v.pinentryAvailable && /did not start/.test(v.pinentryNotice) && v.opened && v.unlocks.length === 0,
    v.pinentryNotice)
  v.pinentryBroken = false
  v.unlockWithPinentry()
  finish(v, 126, false, "unknown capture")
  check("a helper that does not know the capture is a failure, so the field comes back", v.pinentryBroken, "")
  v.pinentryBroken = false
  v.unlockWithPinentry()
  finish(v, 1, false, "the vault helper stopped")
  check("a helper that stopped is not read as a cancel", v.pinentryBroken, "")
  v.pinentryBroken = false
  v.unlockWithPinentry()
  finish(v, 3, false, "")
  check("an empty answer asks for a password and is not a failure",
    v.errorMessage === "Master password required" && !v.pinentryBroken, v.errorMessage)
}

// --- a run in the way, and being cancelled --------------------------------------------------

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockWithPinentry()
  const name = v.pinentryRun.name
  v.cancelPinentry()
  check("cancelling stops the run, forgets its name and brings the panel back",
    !v.proc.running && v.forgotten.includes(name) && v.opened && !v.pinentryActive && v.pinentryRun === null, "")
  v.onPinentryExited(1, false, "")
  check("the cancelled run's own exit changes nothing", v.errorMessage === "" && !v.pinentryBroken, "")
  v.proc.runId = 5
  let answer = null
  v.requestPinentry("unlock", "", r => { answer = r })
  check("a run still ending is not started over", answer && answer.state === "unavailable", JSON.stringify(answer))
}

// --- the PIN ---------------------------------------------------------------------------------

{
  const v = makeVault()
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  v.unlockPinWithPinentry()
  check("the PIN is asked for by pinentry, with the PIN prompt",
    v.proc.command[7] === "PIN:" && /PIN/.test(v.proc.command[6]) && /^pinentry:pw\d+$/.test(v.proc.capture), JSON.stringify(v.proc.command.slice(5)))
  const name = v.proc.capture.slice("pinentry:".length)
  finish(v, 0, true)
  eq("the PIN's name goes to the PIN unlock", v.pinSubmits.join(), Model.heldSecretRef(name))
  check("the PIN is not in the shell's field", v.pinEntry === "", "")
  v.proc.starts = []

  // A PIN under the minimum: the same message as the field, asked for again,
  // and no attempt counted.
  const s = makeVault({ pinAttempts: 0, wrong: 0, countWrongPin() { this.wrong += 1 } })
  Object.defineProperty(s.proc, "running", { configurable: true, get() { return this._r === true }, set(x) {
    if (x) s.proc.starts.push({ command: s.proc.command, capture: s.proc.capture }); this._r = x } })
  s.unlockPinWithPinentry()
  check("the PIN run carries the unlock minimum", s.proc.starts[0].command[9] === String(Model.pinUnlockMinLength()),
    JSON.stringify(s.proc.starts[0].command.slice(5)))
  finish(s, Model.pinentryExitCodes().short, false)
  check("a short PIN is not submitted and not counted",
    s.pinSubmits.length === 0 && s.wrong === 0 && s.pinAttempts === 0, "")
  check("it asks again with the field's message",
    s.proc.starts.length === 2 && s.pinUnlockError === "PIN must be at least " + Model.pinUnlockMinLength() + " digits"
      && s.proc.starts[1].command[8] === s.pinUnlockError, JSON.stringify(s.proc.starts[1]))
  check("a master password run has no minimum", makeVault().proc && (() => {
    const m = makeVault()
    Object.defineProperty(m.proc, "running", { configurable: true, get() { return false }, set() {} })
    m.unlockWithPinentry()
    return m.proc.command[9] === "0"
  })(), "")

  // The unlock was not taken up: nothing else would forget it.
  const w = makeVault({ submitTakesIt: false })
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.unlockPinWithPinentry()
  const unused = w.proc.capture.slice("pinentry:".length)
  finish(w, 0, true)
  check("a PIN the unlock did not take up is forgotten", w.forgotten.includes(unused), w.forgotten.join())
  w.heldPinName = "p9"
  check("a PIN in use is released once, and reported", w.releaseHeldPin() === true && w.releaseHeldPin() === false
    && w.forgotten.includes("p9"), "")
}

// --- the re-prompt ---------------------------------------------------------------------------

{
  const v = makeVault({ status: "unlocked", repromptPending: true, repromptItemId: "i1", repromptItemName: "Bank" })
  Object.defineProperty(v.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  let acted = false
  v.repromptCallback = () => { acted = true }
  v.submitRepromptWithPinentry()
  const first = v.proc.capture.slice("pinentry:".length)
  check("the confirmation runs pinentry for the master password",
    /^pinentry:pw\d+$/.test(v.proc.capture) && /master password/i.test(v.proc.command[6]) && v.repromptBusy, JSON.stringify(v.proc.command.slice(5)))
  finish(v, 0, true)
  eq("the held name is what is verified", v.verifies.join(), Model.heldSecretRef(first))
  v.proc.capture = ""
  v.verifyDone(false)
  check("a wrong password is forgotten and pinentry asks again with the reason",
    v.forgotten.includes(first) && /^pinentry:/.test(v.proc.capture) && v.proc.command[8] === "That is not your master password."
      && !acted, v.proc.capture)
  const second = v.proc.capture.slice("pinentry:".length)
  finish(v, 0, true)
  v.verifyDone(true)
  check("a right one is forgotten and runs the action", v.forgotten.includes(second) && acted && !v.repromptPending, "")
  check("no field of the shell held it", v.masterPassword === "" && v.pinEntry === "", "")

  const w = makeVault({ status: "unlocked", repromptPending: true, repromptItemId: "i1" })
  Object.defineProperty(w.proc, "running", { configurable: true, get() { return this._r === true }, set(x) { this._r = x } })
  w.submitRepromptWithPinentry()
  finish(w, 1, false)
  check("cancelling leaves the question open and quiet",
    w.repromptPending && !w.repromptBusy && w.repromptError === "" && w.verifies.length === 0, "")
  w.submitRepromptWithPinentry()
  finish(w, 4, false)
  check("a pinentry that fails says so and frees the question for the field",
    w.repromptBusy === false && /did not start/.test(w.repromptError) && w.pinentryBroken, w.repromptError)
}

// --- the wiring ------------------------------------------------------------------------------------

const flows = ["unlockWithPinentry", "unlockPinWithPinentry", "submitRepromptWithPinentry", "requestPinentry", "onPinentryExited"]
  .map(body).join("\n")
check("no pinentry flow writes what was typed into the shell's fields",
  !/\b(masterPassword|pinEntry|loginPassword|pinSetupMaster|fpSetupMaster)\s*=[^=]/.test(flows), flows)
check("the run asks the helper to hold the answer",
  /pinentryProc\.capture = "pinentry:" \+ name/.test(body("requestPinentry"))
    && /Model\.pinentryCommand\(pinentryProgramName/.test(body("requestPinentry")), body("requestPinentry"))
check("the process is a VaultProcess with no session and no output collector",
  /VaultProcess \{\s*id: pinentryProc\s*vault: root\s*session: false\s*stderr: VaultCollector[^\n]*\n\s*onExited/.test(service)
    && !/id: pinentryProc[\s\S]{0,200}stdout:/.test(service), "")
check("the unlock hands the held name to the password flow",
  /unlockVaultWithPassword\(Model\.heldSecretRef\(r\.name\)\)/.test(body("unlockWithPinentry")), body("unlockWithPinentry"))
check("the PIN unlock takes a held PIN, in place of the field, for both its paths",
  /function submitPinUnlock\(heldPin\)/.test(service)
    && /env\[Model\.pinEnvVar\(\)\] = held \|\|/.test(body("submitPinUnlock"))
    && /if \(!held && String\(pinEntry \|\| ""\)\.length < Model\.pinUnlockMinLength\(\)\)/.test(body("submitPinUnlock"))
    && /heldPinName \? Model\.heldSecretRef\(root\.heldPinName\) : root\.pinEntry/.test(service), body("submitPinUnlock"))
check("a held PIN is forgotten when the envelope answers, and a held PIN for a migration after it",
  /releaseHeldPin\(\)/.test(body("onEnvelopePinResult")) && /forgetHeldPassword\(pin\)/.test(body("migrateLegacyPin"))
    && /forgetHeldPassword\(pendingPinForMigration\)/.test(body("onUnlockOutput")), "")
check("an accepted master password is forgotten once its stored copy has been dealt with",
  /storeAcceptedMasterPassword\(pendingUnlockPassword, forgetHeldAfter\(pendingUnlockPassword\)\)/.test(body("onUnlockSuccess")), "")
check("a failed delivery, an abandoned unlock and a dismissed SSH popup forget it too",
  /forgetHeldPassword\(pendingUnlockPassword\)/.test(body("onAuthPasswordWriterExited"))
    && /forgetHeldPassword\(pendingUnlockPassword\)/.test(body("abandonAuthSecrets"))
    && /forgetHeldPassword\(root\.pendingUnlockPassword\)/.test(body("clearSshPopupUnlockState"))
    && /cancelPinentry\(\)/.test(body("clearSshPopupUnlockState")), "")
check("a lock, another method's unlock and the panel being asked for end a pinentry",
  /cancelPinentry\(\)/.test(body("dropVaultState")) && /cancelPinentry\(\)/.test(body("onUnlockSuccess"))
    && /cancelPinentry\(\)/.test(body("open")), "")
check("hiding the panel for pinentry is not a close; coming back is a resume",
  /else if \(!pinentryActive\) \{\s*clearRepromptGrant\(\)/.test(service) && /!resumeFromPinentry\(\)/.test(service), "")
check("a pinentry run never runs in the shell: without the helper it is refused",
  /capture\.indexOf\("pinentry:"\) === 0[\s\S]{0,200}proc\.finish\(/.test(body("vaultStart"))
    && body("vaultStart").indexOf("pinentry:") < body("vaultStart").indexOf("runLocally"), body("vaultStart"))
check("the verification of a held password is the existing one",
  /verifyMasterPassword\(pw, function\(ok\)/.test(body("submitReprompt")), "")
check("pinentry counts as an auth surface while it is up, and covers the SSH popup",
  /sshAuthSurfaceActive: opened \|\| sshApprovalPopupOpen \|\| pinentryActive/.test(service)
    && /!vault\.pinentryActive/.test(read("SshApprovalPopup.qml")), "")

// --- the screens --------------------------------------------------------------------------------------

const form = read("UnlockForm.qml")
check("the unlock form hides its fields when pinentry takes the typing, and offers it for both typed methods",
  /pinentryOffered: form\.vault\.pinentryAvailable === true\s*&& \(method === "pin" \|\| method === "password"\)/.test(form)
    && /form\.method === "pin" && !form\.pinentryOffered/.test(form)
    && /form\.method === "password" && !form\.pinentryOffered/.test(form)
    && /form\.vault\.unlockPinWithPinentry\(\)/.test(form) && /form\.vault\.unlockWithPinentry\(\)/.test(form), "")
check("the fields stay as the fallback, with the reason when pinentry failed",
  /id: passwordField/.test(form) && /id: pinField/.test(form) && /form\.vault\.pinentryNotice/.test(form), "")
{
  const use = (form.match(/function useMethod\(name\) \{[\s\S]*?\n  \}/) || [""])[0]
  check("picking PIN or Password opens pinentry straight away",
    /if \(form\.pinentryOffered\) \{\s*form\.submitCurrentMethod\(\)\s*return\s*\}/.test(use)
      && use.indexOf("form.pinentryOffered") > use.indexOf("form.chosen = name"), use)
}
check("Enter on the locked screen opens pinentry",
  /status === "locked" && unlockForm\.pinentryOffered\) \{\s*unlockForm\.submitCurrentMethod\(\)/.test(read("Panel.qml")), "")
const confirm = read("RepromptConfirm.qml")
check("the re-prompt question asks pinentry when it can, and keeps its field otherwise",
  /usePinentry: vault\.pinentryAvailable === true/.test(confirm) && /visible: !confirm\.usePinentry/.test(confirm)
    && /vault\.submitRepromptWithPinentry\(\)/.test(confirm) && /id: passwordField/.test(confirm), "")

// --- settings -----------------------------------------------------------------------------------------

check("the setting defaults on and an override program is read from shell.json",
  Model.boolSetting("usePinentry", undefined) === true && Model.boolSetting("usePinentry", false) === false
    && /Model\.pinentryProgram\(setting\("pinentryProgram", ""\)\)/.test(service), "")

done()
