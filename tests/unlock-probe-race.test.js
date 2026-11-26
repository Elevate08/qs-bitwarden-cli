#!/usr/bin/env node
// #110: a panel-open status probe or remembered-session lookup landing while a
// quick unlock (PIN / fingerprint envelope open) runs must not cancel it
// silently, a dropped open must not wedge the next PIN, and a password that
// never reached `bw` must not read as a wrong one.
//
//   node tests/unlock-probe-race.test.js

const { createSuite, functionBody, loadModule, read } = require("./harness")
const { spawnSync } = require("child_process")

const Model = loadModule()
const service = read("Service.qml")
const { check, eq, done } = createSuite("unlock-probe-race")

function bind(v, names) {
  for (const n of names) {
    const body = functionBody(service, n)
    if (!body) throw new Error("missing function " + n)
    v[n] = new Function("scope", "with(scope){" + body + "\nreturn " + n + "}")(v)
  }
}

function vault(extra) {
  const v = {}
  Object.assign(v, {
    Model, Qt: { callLater: f => f() },
    status: "locked", sshAuthSurfaceActive: true, pinReady: true, isUnlocking: false,
    pinUnlockSubmitted: false, pinBusy: false, pinEntry: "123456", pinUnlockError: "",
    heldPinName: "", fingerprintAuthorized: false, fingerprintMessage: "", fingerprintError: "",
    loginSubmitted: false, unlockSubmitted: false, statusRecheckAfterUnlock: false, statusChecks: 0,
    quickUnlockAvailable: true, accountId: "id", activeSlot: "default", vaultEpoch: 3,
    envelopeSummary: { pin: {}, fingerprint: {} }, envelopeJobs: [], envelopeJob: null,
    envelopeProc: { running: false, outputHeld: true }, envelopeStdout: { text: "" },
    logoutPending: false, allCredentialsClearPending: false, forgotten: [], seq: 0,
    pinUnlockProc: { running: false, runId: 0 },
    newHeldName() { return "pw" + (++this.seq) },
    forgetVaultSecret(name) { this.forgotten.push(name) },
    clearProcessCollectorSoon() {}, finishScrubRun() { return false },
    envelopeTool() { return "/synthetic/tool" },
    envelopeAccount() { return { slot: "default", id: "id", server: "https://synthetic.invalid" } },
    runStatusCheck: () => { v.statusChecks++ },
    onEnvelopePinResult: () => { v.pinUnlockSubmitted = false; v.pinBusy = false }
  }, extra || {})
  v.root = v
  bind(v, ["forgetHeldPassword", "queueEnvelopeJob", "pumpEnvelopeJobs", "onEnvelopeJobExited",
    "authAttemptInFlight", "unlockJobInFlight", "envelopeUnlockJobPending", "recheckStatusAfterUnlock",
    "onPinJobDropped", "submitPinUnlock", "releaseHeldPin", "openEnvelopeForFingerprint",
    "cancelEnvelopeUnlockJobs"])
  return v
}

// --- the status guard sees the quick-unlock phase ---------------------------
{
  const v = vault()
  eq("idle: no attempt in flight", v.authAttemptInFlight(), false)
  v.submitPinUnlock()
  eq("a queued/running PIN envelope open is an attempt in flight", v.authAttemptInFlight(), true)
  eq("the typed-unlock flag is still false during it", v.unlockSubmitted, false)
  const w = vault()
  w.queueEnvelopeJob({ command: ["x"], writes: true })
  eq("a maintenance write is not an unlock attempt", w.authAttemptInFlight(), false)
  const f = vault()
  f.openEnvelopeForFingerprint()
  eq("a fingerprint envelope open is an attempt in flight", f.authAttemptInFlight(), true)
  const l = vault({ pinUnlockSubmitted: true })
  eq("the legacy PIN run counts too", l.authAttemptInFlight(), true)
}

const statusFinished = functionBody(service, "onStatusFinished")
check("a deferred status is asked for again after the quick unlock",
  /authAttemptInFlight\(\)\)\s*\{[\s\S]{0,200}statusRecheckAfterUnlock = true[\s\S]{0,40}return/.test(statusFinished),
  statusFinished.slice(0, 600))
check("the guard still precedes every branch that drops state",
  statusFinished.indexOf("authAttemptInFlight") < statusFinished.indexOf("dropVaultState"))

// --- the recheck runs once, and not over a typed unlock ---------------------
{
  const v = vault({ statusRecheckAfterUnlock: true })
  v.unlockSubmitted = true
  v.recheckStatusAfterUnlock()
  eq("no recheck while a typed unlock runs", v.statusChecks, 0)
  v.unlockSubmitted = false
  v.recheckStatusAfterUnlock()
  v.recheckStatusAfterUnlock()
  eq("one recheck once nothing is in flight", v.statusChecks, 1)
}
{
  // A failed PIN open: the deferred status is re-probed from the exit.
  const v = vault()
  v.submitPinUnlock()
  v.pumpEnvelopeJobs()
  v.envelopeProc.running = false
  v.statusRecheckAfterUnlock = true
  v.onEnvelopeJobExited(3)
  eq("a finished open triggers the deferred recheck", v.statusChecks, 1)
}

// --- a dropped open frees the next PIN ---------------------------------------
for (const how of ["queued", "running"]) {
  const v = vault()
  const held = "\u0000qsbw-held:pinentry1"
  if (how === "queued") v.envelopeProc.running = true // another write holds the slot
  v.submitPinUnlock(held)
  eq(how + ": submit took the PIN", v.pinBusy && v.pinUnlockSubmitted, true)
  if (how === "running") {
    v.pumpEnvelopeJobs()
    eq("running: the open started", v.envelopeJob !== null, true)
    v.vaultEpoch += 1
    v.envelopeProc.running = false
    v.onEnvelopeJobExited(0)
  } else {
    v.vaultEpoch += 1
    v.envelopeProc.running = false
    v.pumpEnvelopeJobs()
  }
  eq(how + ": busy flag released", v.pinBusy, false)
  eq(how + ": submitted flag released", v.pinUnlockSubmitted, false)
  check(how + ": the user is told to try again", /interrupted/.test(v.pinUnlockError), v.pinUnlockError)
  check(how + ": the held PIN is forgotten", v.forgotten.includes("pinentry1"), v.forgotten.join())
  v.pinEntry = "123456"
  v.submitPinUnlock()
  eq(how + ": the next PIN is accepted, not ignored", v.pinBusy && (v.envelopeJob !== null || v.envelopeJobs.length === 1), true)
}
{
  // A deliberate cancel has cleaned up; its late exit must not reset a new attempt.
  const v = vault()
  v.submitPinUnlock()
  v.pumpEnvelopeJobs()
  v.envelopeJob.cancelled = true
  v.pinBusy = false
  v.pinUnlockSubmitted = false
  v.pinEntry = "654321"
  v.submitPinUnlock()
  v.envelopeProc.running = false
  v.onEnvelopeJobExited(143)
  eq("a cancelled run's exit leaves the new attempt busy", v.pinBusy, true)
  eq("and still marked submitted", v.pinUnlockSubmitted, true)
}
{
  const v = vault({ fingerprintAuthorized: true })
  v.envelopeProc.running = true
  v.openEnvelopeForFingerprint()
  v.vaultEpoch += 1
  v.envelopeProc.running = false
  v.pumpEnvelopeJobs()
  eq("a dropped fingerprint open clears the authorization", v.fingerprintAuthorized, false)
  check("and says to try again", /interrupted/.test(v.fingerprintError), v.fingerprintError)
}

// --- a remembered session is not trusted until bw status says so -------------
{
  const v = vault({ session: "", rememberSession: false, epochOperationIsStale: () => false,
    beginInitialVaultLoad() {}, restartStaleStatusProbe() {} })
  bind(v, ["onKeyringLookupFinished"])
  v.submitPinUnlock()
  const epoch = v.vaultEpoch
  v.onKeyringLookupFinished("stale-token\n")
  eq("the token is adopted", v.session, "stale-token")
  eq("the epoch is untouched, so the queued unlock stays valid", v.vaultEpoch, epoch)
  v.pumpEnvelopeJobs()
  check("and the unlock job starts", v.envelopeJob !== null)
  v.onKeyringLookupFinished("another-token")
  check("replacing an earlier session still invalidates its reads", v.vaultEpoch === epoch + 1)
}

// --- a password that never reached bw is not a wrong password ---------------
{
  const v = vault({
    errorMessage: "", pendingUnlockPassword: "\u0000qsbw-held:pwX", pendingUnlockFrom: "pin",
    pinFromEnvelope: true, fingerprintFromEnvelope: false, fidoFromEnvelope: false,
    pinentryMasterName: "", pendingPinForMigration: "", prepared: 0,
    prepareUnlock: () => { v.prepared++ }, onUnlockSuccess() { this.success = true }
  })
  bind(v, ["onUnlockOutput"])
  v.onUnlockOutput("", "", 0)
  check("exit 0 with no output at all is a delivery failure",
    /Could not deliver the password/.test(v.errorMessage), v.errorMessage)
  check("it is not reported as an invalid password", !/invalid|not your master/i.test(v.errorMessage))
  check("the held password is forgotten", v.forgotten.includes("pwX"), v.forgotten.join())
  eq("the envelope origin is cleared, so no password-changed notice follows", v.pinFromEnvelope, false)
  eq("a new attempt is prepared", v.prepared, 1)
  eq("it never counted as success", v.success, undefined)
  v.errorMessage = ""
  v.onUnlockOutput("", "Invalid master password.", 1)
  check("a real refusal keeps its own message", /not your master password/.test(v.errorMessage), v.errorMessage)
}

// --- the FIFO writer refuses an absent password ------------------------------
{
  const cmd = Model.authPasswordWriteCommand("unlock")
  for (const [label, env] of [["unset", {}], ["empty", { BW_PASSWORD: "" }]]) {
    const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", timeout: 5000,
      env: Object.assign({ PATH: process.env.PATH, XDG_RUNTIME_DIR: "/nonexistent-qsbw" }, env) })
    eq("writer with " + label + " password exits 3 at once", r.status, 3)
  }
}

// --- a cancelled open still releases a held-back status ----------------------
for (const how of ["queued", "waiting for the helper", "running"]) {
  const v = vault({ vaultWaiting: [], vaultKill() {} })
  if (how === "queued") v.envelopeProc.running = true // another write holds the slot
  v.submitPinUnlock()
  if (how !== "queued") v.pumpEnvelopeJobs()
  v.envelopeProc.runId = 0 // no helper run id yet
  if (how === "running") { v.envelopeProc.running = true; v.envelopeProc.runId = 7 }
  v.statusRecheckAfterUnlock = true // the startup status was held back
  v.pinUnlockSubmitted = false // every caller clears it first
  v.cancelEnvelopeUnlockJobs()
  if (how === "running") {
    eq(how + ": no recheck while the cancelled run is still exiting", v.statusChecks, 0)
    v.envelopeProc.running = false
    v.onEnvelopeJobExited(143)
  }
  eq(how + ": the held-back status is asked for once", v.statusChecks, 1)
  eq(how + ": the flag is cleared", v.statusRecheckAfterUnlock, false)
}
{
  const v = vault({ vaultWaiting: [], vaultKill() {} })
  v.statusRecheckAfterUnlock = true
  v.unlockSubmitted = true // a typed unlock took over
  v.cancelEnvelopeUnlockJobs()
  eq("a typed unlock in flight still defers the recheck", v.statusChecks, 0)
  eq("and the flag is kept for later", v.statusRecheckAfterUnlock, true)
}

{
  const body = functionBody(service, "clearSshPopupUnlockState")
  check("the popup clears the submitted flag before cancelling, so the recheck can run",
    body.indexOf("pinUnlockSubmitted = false") !== -1
      && body.indexOf("pinUnlockSubmitted = false") < body.indexOf("cancelEnvelopeUnlockJobs()"))
}

// --- an exit belongs to the run that produced it (JS-1) ---------------------
const vaultProcess = read("VaultProcess.qml")

// The `function (...) { ... }` at or after `from`, braces balanced.
function functionAt(src, from) {
  const start = src.indexOf("function", from)
  let depth = 0
  for (let i = src.indexOf("{", start); i !== -1 && i < src.length; i++) {
    if (src[i] === "{") depth++
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1)
  }
  return ""
}

// VaultProcess's own start/finish/launchLocal/killLocal and its real
// Process.onExited over a stand-in scope, so the run generations are exercised
// rather than described.
function makeVaultProcess(v, qt) {
  const names = ["start", "runLocally", "launchLocal", "finish", "killLocal"]
  const bodies = names.map(n => functionBody(vaultProcess, n))
  if (bodies.some(b => !b)) throw new Error("VaultProcess is missing a run function")
  const clock = qt || { callLater: f => f() }
  const local = { running: false, exiting: false, launchedSeq: 0, command: [], environment: {},
    stdinEnabled: false }
  const proc = {
    Model, vault: v, command: [], environment: {}, running: false, stdinText: "",
    capture: "plain", session: false, inject: {}, sessionHeld: false,
    outputHeld: false, runId: 0, finishing: false, startSeq: 0, runSeq: 0,
    localSeq: 0, finishSeq: 0, exits: [],
    stdout: { text: "", streamFinished() {} },
    stderr: { text: "", streamFinished() {} },
    started() {},
    exited(code) { this.exits.push(code) }
  }
  const make = new Function("scope", "local", "Qt", "proc",
    "with(scope){" + bodies.join("\n") + "\nreturn {"
      + names.map(n => n + ": " + n).join(",") + "}}")
  Object.assign(proc, make(proc, local, clock, proc))
  proc.local = local

  // The real handler, with the ids it uses (collectors) and the local
  // Process's own properties in scope.
  const exitAt = vaultProcess.indexOf("onExited: function(")
  const exitBody = functionAt(vaultProcess, exitAt)
  if (!exitBody) throw new Error("VaultProcess is missing local.onExited")
  const localOut = { text: "" }
  const localErr = { text: "" }
  const exitScope = Object.create(proc)
  Object.defineProperty(exitScope, "command", { get: () => local.command })
  Object.defineProperty(exitScope, "launchedSeq", { get: () => local.launchedSeq })
  Object.defineProperty(exitScope, "exiting", {
    get: () => local.exiting,
    set: value => { local.exiting = value }
  })
  const exit = new Function("scope", "local", "localOut", "localErr", "Qt", "proc",
    "with(scope){ return (" + exitBody + ")}")(exitScope, local, localOut, localErr, clock, proc)
  local.exit = code => exit(code, 0)
  local.out = localOut
  local.err = localErr
  return proc
}

{
  const v = vault({
    vaultHelperState: "active", vaultHelperActive: true,
    vaultRunSeq: 0, vaultRuns: {}, vaultWaiting: [], vaultQueries: {},
    session: "", heldSessionMarker: Model.vaultHeldSession()
  })
  v.vaultHelperProc = { running: true, lines: [], write(line) { this.lines.push(line) } }
  bind(v, ["vaultStart", "onVaultHelperLine"])
  const proc = makeVaultProcess(v)

  proc.running = true
  proc.command = ["bw", "unlock", "A"]
  proc.start()
  const seqA = proc.runSeq
  eq("run A is held with its own start generation", v.vaultRuns[1].seq, seqA)
  eq("and with the process that started it", v.vaultRuns[1].proc === proc, true)

  // A is cancelled, but its helper has not answered yet.
  proc.running = false

  proc.running = true
  proc.command = ["bw", "unlock", "B"]
  proc.start()
  const seqB = proc.runSeq
  check("run B has a newer generation than the cancelled run", seqB !== seqA, `${seqA} vs ${seqB}`)
  eq("both runs stay held until their exits arrive", Object.keys(v.vaultRuns).length, 2)

  const accepted = []
  const acceptExit = () => {
    if (proc.finishSeq === seqB) accepted.push(proc.stdout.text)
  }

  // A's delayed exit arrives after B started: it must be ignored, not
  // finished against B.
  v.onVaultHelperLine(JSON.stringify({ type: "exit", id: 1, code: 0,
    out: "A-password", err: "", session: false, held: false }))
  acceptExit()
  eq("a cancelled run's delayed exit is not stamped on its replacement", proc.finishSeq === seqB, false)
  eq("and it leaves the replacement's run held", proc.runId, 2)
  eq("with the replacement still running", proc.running, true)
  eq("its output is not accepted for the run that replaced it", accepted.length, 0)

  // B's own exit is.
  v.onVaultHelperLine(JSON.stringify({ type: "exit", id: 2, code: 0,
    out: "B-password", err: "", session: false, held: false }))
  acceptExit()
  eq("the replacement's exit is stamped with its own generation", proc.finishSeq, seqB)
  eq("and its output is accepted", JSON.stringify(accepted), JSON.stringify(["B-password"]))
}

// A delayed local exit belongs to the child that produced it, not to the run
// that replaced it: a killed child still on its way out must not have a new
// launch overwrite its generation, its exit must not clear the newer run, and
// cancelling that newer run must still kill it (JS-1).
{
  const pending = []
  const clock = { callLater: f => pending.push(f) }
  const drain = () => { const now = pending.splice(0); now.forEach(f => f()) }
  const v = vault()
  v.vaultStart = p => p.runLocally({})
  bind(v, ["vaultKill"])
  const proc = makeVaultProcess(v, clock)

  proc.running = true
  proc.command = ["bw", "list", "A"]
  proc.start()
  const seqA = proc.runSeq
  eq("a local run captures the generation it launched with", proc.local.launchedSeq, seqA)

  // The caller cancels A while its child is still alive, then starts B before
  // A's exit arrives.
  v.vaultKill(proc)
  eq("cancelling A marks its child as exiting", proc.local.exiting, true)
  eq("A's child is asked to stop", proc.local.running, false)

  proc.running = true
  proc.command = ["bw", "list", "B"]
  proc.start()
  const seqB = proc.runSeq
  check("the replacement has its own generation", seqB !== seqA, `${seqA} vs ${seqB}`)
  drain()
  eq("the replacement waits for the old child's exit", proc.local.running, false)
  eq("so the old child's generation is still the one it will report", proc.local.launchedSeq, seqA)

  // The old child's exit finally arrives through the real onExited handler.
  proc.stdout.text = "B-output"
  proc.local.out.text = "A-output"
  proc.local.exit(0)
  eq("a delayed old local exit leaves the newer run's runId", proc.runId, -1)
  eq("and its running flag", proc.running, true)
  eq("and its collector", proc.stdout.text, "B-output")
  eq("and it emits no exit for the newer run", proc.exits.length, 0)

  // The replacement then starts with its own generation.
  drain()
  eq("the replacement starts once the old child has exited", proc.local.running, true)
  eq("with its own generation", proc.local.launchedSeq, seqB)
  eq("and the newer run is still held", proc.runId, -1)
  eq("with its collector untouched", proc.stdout.text, "B-output")

  v.vaultKill(proc)
  eq("cancelling the newer run still kills its local child", proc.local.running, false)
  eq("and marks that child as exiting", proc.local.exiting, true)
}

function processBlock(id, next) {
  return service.slice(service.indexOf("id: " + id), service.indexOf("id: " + next))
}
check("unlockProc compares the ended generation before accepting a submission",
  /finishSeq !== root\.unlockExpectedSeq/.test(processBlock("unlockProc", "logoutProc")),
  processBlock("unlockProc", "logoutProc"))
check("statusProc ignores an exit from a cancelled probe",
  /finishSeq !== root\.statusRunSeq/.test(processBlock("statusProc", "sessionHandoffProc")),
  processBlock("statusProc", "sessionHandoffProc"))
check("keyringLookupProc ignores an exit from a cancelled lookup",
  /finishSeq !== root\.keyringLookupRunSeq/.test(processBlock("keyringLookupProc", "keyringStoreProc")),
  processBlock("keyringLookupProc", "keyringStoreProc"))
const runStatus = functionBody(service, "runStatusCheck")
check("the status run captures its generation and process sequence when started",
  /statusReadEpoch = vaultEpoch/.test(runStatus) && /statusRunSeq = statusProc\.startSeq/.test(runStatus),
  runStatus)
const beginRead = functionBody(service, "beginVaultRead")
check("the item read captures its generation when started",
  /listReadEpoch = vaultEpoch/.test(beginRead), beginRead)
check("the handlers compare the captured generation, not the latest stamp",
  /statusReadEpoch[\s\S]{0,200}?vaultEpoch/.test(statusFinished)
    && /listReadEpoch[\s\S]{0,200}?vaultEpoch/.test(functionBody(service, "onListFinished")),
  statusFinished)
check("a locked-screen prewarm is not mistaken for a submitted unlock",
  /unlockPrewarmActive/.test(functionBody(service, "prepareUnlock"))
    && /unlockPrewarmActive = false/.test(functionBody(service, "unlockVaultWithPassword")),
  functionBody(service, "prepareUnlock") + "\n" + functionBody(service, "unlockVaultWithPassword"))

done()
