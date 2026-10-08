#!/usr/bin/env node
// Behavioral advisory regressions. REVIEW_SOURCE_ROOT permits the same tests
// to execute the immutable baseline's functions, without expecting new APIs.
const { createSuite, functionBody } = require("./harness")
const fs = require("fs")
const path = require("path")
const { spawnSync } = require("child_process")
const os = require("os")
const sourceRoot = process.env.REVIEW_SOURCE_ROOT || path.join(__dirname, "..")
const read = file => fs.readFileSync(path.join(sourceRoot, file), "utf8")
const src = read("BitwardenModel.js").replace(/^\.pragma library\s*$/m, "")
const exportsList = [...src.matchAll(/^(?:function\s+(\w+)|var\s+(\w+))/gm)].map(m => m[1] || m[2])
const Model = new Function(src + "\nreturn {" + exportsList.join(",") + "}")()
const service = read("Service.qml")
const { check, eq, done } = createSuite("quick-unlock-cleanup")
function bind(v, text, names) {
  const bodies = names.map(n => functionBody(text, n))
  if (bodies.some(b => !b)) throw new Error("test requires an existing baseline function")
  for (let i = 0; i < names.length; i++) {
    v[names[i]] = new Function("scope", "with(scope){" + bodies[i] + "\nreturn " + names[i] + "}")(v)
  }
}
function vault() {
  const v = {
    Model, Qt: { callLater: f => f() }, console: { log() {}, warn() {} },
    status: "locked", sshAuthSurfaceActive: false, pinUnlockSubmitted: true, pinBusy: true,
    fingerprintAuthorized: true, pinAttempts: 1, pendingUnlockFrom: "", pinFromEnvelope: false,
    heldPinName: "", pinEntry: "", pendingPinForMigration: "", session: "", readEpochs: {},
    forgotten: [], unlocks: [], refreshes: 0, activeSlot: "default", vaultEpoch: 4,
    logoutPending: false, allCredentialsClearPending: false,
    envelopeJobs: [], envelopeJob: null, envelopeProc: { running: false, outputHeld: true },
    envelopeStdout: { text: "" }, seq: 0,
    newHeldName() { return "pw" + (++this.seq) },
    forgetVaultSecret(name) { this.forgotten.push(name) },
    unlockVaultWithPassword(value) { this.unlocks.push(value) },
    releaseHeldPin() { return false }, countWrongPin() {}, retryPinentryPin() {},
    clearProcessCollectorSoon() {}, finishScrubRun() { return false },
    vaultKill(proc) { this.vaultWaiting = this.vaultWaiting.filter(p => p !== proc) }, vaultWaiting: [],
    refreshEnvelope() { this.refreshes++ }, pinUnlockProc: { running: false, runId: 0 }, keyringLookupMasterProc: {},
    cancelPinentry() {}, resetPinentryChoice() {}, cancelFingerprintUnlock() {}, cancelFidoUnlock() {},
    cancelAttachmentDownloads() {}, forgetVault() {}, resetItemForm() {}, dropVaultSecrets() {},
    quickUnlockAvailable: true, accountId: "synthetic-id", quickUnlockEnabledAt: {},
    quickUnlockEnableGraceMs: 60000, reconciledMethods: {},
    quickUnlockPurgeAttempts: {}, quickUnlockPurgePending: {}, quickUnlockPurgeMaxAttempts: 3,
    quickUnlockPurgeFailures: {}, errorMessage: "",
    quickUnlockMethodGeneration: {}, quickUnlockAccountGeneration: {}, pendingPurges: [],
    settings: { pinUnlock: false, fingerprintUnlock: true, fidoUnlock: true },
    envelopeTool() { return "/synthetic/tool" },
    envelopeAccount() { return { slot: this.activeSlot, id: this.accountId, server: "https://synthetic.invalid" } }
  }
  v.root = v
  bind(v, service, ["forgetHeldPassword", "onEnvelopePinResult", "onPinUnlockResult",
    "onFingerprintPasswordRetrieved", "queueEnvelopeJob", "pumpEnvelopeJobs", "onEnvelopeJobExited",
    "dropVaultState", "quickUnlockSettingOff", "reconcileDisabledMethods", "openEnvelopeForFingerprint", "noteQuickUnlockEnabled", "dropEnvelopeState"])
  // Optional additions are exercised through their existing callers.
  for (const name of ["cancelEnvelopeUnlockJobs", "onQuickUnlockPurgeDone", "queueQuickUnlockPurge", "reportQuickUnlockPurgeFailure"]) {
    if (functionBody(service, name)) bind(v, service, [name])
  }
  return v
}
// Closing during a legacy PIN run must not allow a new submission to rename
// the capture that owns the first run's held master password.
{
  const v = vault()
  Object.assign(v, { sshAuthSurfaceActive: true, pinReady: true, isUnlocking: false,
    pinBusy: false, pinEntry: "123456", envelopeSummary: null, pendingUnlockPassword: "",
    syncLoginFieldsToState() {}, clearLoginAttempt() {} })
  bind(v, service, ["submitPinUnlock", "abandonAuthSecrets"])
  v.submitPinUnlock()
  v.pinUnlockProc.runId = 1
  const capture = v.pinUnlockProc.capture
  v.abandonAuthSecrets()
  eq("abandoned legacy PIN remains busy until its process exits", v.pinBusy, true)
  v.pinEntry = "654321"
  v.submitPinUnlock()
  eq("resubmission preserves the in-flight legacy capture", v.pinUnlockProc.capture, capture)
  v.pinUnlockProc.running = false
  v.pinUnlockProc.runId = 0
  v.onPinUnlockResult(0, Model.heldSecretRef(capture.slice(7)))
  check("abandoned legacy answer is forgotten", v.forgotten.includes(capture.slice(7)))
  eq("legacy exit releases busy state", v.pinBusy, false)
}
// VaultProcess keeps its runId after a kill request; only finish releases it.
// Exercise the real cancellation/result paths while its helper exit is delayed.
for (const cleanup of ["dismiss", "dismiss twice", "dismiss then panel close"]) {
  for (const exitCode of [143, 0]) {
    const v = vault(); const starts = []; const held = new Set()
    Object.assign(v, { sshAuthSurfaceActive: true, pinReady: true, isUnlocking: false,
      pinBusy: false, pinAttempts: 0, pinMaxAttempts: 5, pinEntry: "123456",
      envelopeSummary: null, pendingUnlockPassword: "", cancelAuthPrewarm() {},
      syncLoginFieldsToState() {}, clearLoginAttempt() {} })
    bind(v, service, ["submitPinUnlock", "clearSshPopupUnlockState", "abandonAuthSecrets",
      "countWrongPin", "releaseHeldPin", "heldOutput"])
    v.forgetVaultSecret = name => { v.forgotten.push(name); held.delete(name) }
    // Model the process boundary, including the running-change start guard.
    let running = false
    v.pinUnlockProc = { runId: 0, capture: "plain", outputHeld: false,
      get running() { return running },
      set running(value) {
        if (running === value) return
        running = value
        if (value && this.runId === 0) {
          this.runId = starts.length + 1
          starts.push(this.capture)
        }
      }
    }
    const finish = code => {
      if (code === 0) held.add(starts[starts.length - 1].slice(7))
      v.pinUnlockProc.outputHeld = code === 0
      v.pinUnlockProc.runId = 0
      running = false
      v.onPinUnlockResult(code, v.heldOutput(v.pinUnlockProc, ""))
    }
    const label = `${cleanup}, exit ${exitCode}`
    v.submitPinUnlock()
    const capture = v.pinUnlockProc.capture
    v.clearSshPopupUnlockState()
    if (cleanup === "dismiss twice") v.clearSshPopupUnlockState()
    if (cleanup === "dismiss then panel close") v.abandonAuthSecrets()
    eq(`${label}: kill awaits the original exit`, v.pinUnlockProc.runId, 1)
    eq(`${label}: cancellation stays busy until exit`, v.pinBusy, true)
    // A newly opened auth surface may submit before the cancelled run exits.
    v.sshAuthSurfaceActive = true
    v.pinEntry = "654321"
    v.submitPinUnlock()
    eq(`${label}: original process is still the only run`, starts.length, 1)
    eq(`${label}: pending run retains capture ownership`, v.pinUnlockProc.capture, capture)
    eq(`${label}: pending run has no replacement submission`, v.pinUnlockSubmitted, false)
    finish(exitCode)
    eq(`${label}: cancellation does not charge a PIN attempt`, v.pinAttempts, 0)
    eq(`${label}: cancelled result does not unlock`, v.unlocks.length, 0)
    if (exitCode === 0) eq(`${label}: abandoned held output is forgotten`, held.size, 0)
    eq(`${label}: exit releases busy`, v.pinBusy, false)
    v.pinEntry = "654321"
    v.submitPinUnlock()
    eq(`${label}: next attempt actually starts`, starts.length, 2)
    finish(0)
    eq(`${label}: next correct PIN unlocks`, v.unlocks.length, 1)
    eq(`${label}: next correct PIN retains its own password`,
      v.unlocks[0], Model.heldSecretRef(starts[1].slice(7)))
  }
}
// A queued legacy process is running with no id until the helper starts it.
// Generic panel cleanup must preserve its ownership; popup cancellation can
// release it immediately because no started process will send an exit.
{
  const v = vault()
  Object.assign(v, { sshAuthSurfaceActive: true, pinReady: true, isUnlocking: false,
    pinBusy: false, pinEntry: "123456", envelopeSummary: null, pendingUnlockPassword: "",
    cancelAuthPrewarm() {}, syncLoginFieldsToState() {}, clearLoginAttempt() {} })
  bind(v, service, ["submitPinUnlock", "abandonAuthSecrets", "clearSshPopupUnlockState"])
  v.submitPinUnlock()
  const capture = v.pinUnlockProc.capture
  eq("waiting legacy run has no exit id yet", v.pinUnlockProc.runId, 0)
  v.abandonAuthSecrets()
  eq("waiting legacy run remains busy", v.pinBusy, true)
  v.pinEntry = "654321"
  v.submitPinUnlock()
  eq("waiting legacy run keeps its capture", v.pinUnlockProc.capture, capture)
  v.clearSshPopupUnlockState()
  eq("cancelling a never-started legacy run releases busy", v.pinBusy, false)
  eq("never-started cancellation cannot accept a result", v.pinUnlockSubmitted, false)
}
const ref = Model.heldSecretRef("late-master")
for (const method of ["envelope PIN", "legacy PIN", "fingerprint", "FIDO2"]) {
  for (const active of [false, true]) {
    const v = vault()
    v.sshAuthSurfaceActive = active
    if (method === "envelope PIN") v.onEnvelopePinResult(0, ref)
    else if (method === "legacy PIN") v.onPinUnlockResult(0, ref)
    else if (method === "fingerprint") v.onFingerprintPasswordRetrieved(ref)
    else {
      const f = { Model, vault: v, assertProc: {}, assertStdout: { text: "" },
        assertMode: "envelope", scanning: true, authorized: false, busyRetries: 0,
        abandonedAtMs: 0, message: "", legacyStored: false, unlocked: value => v.unlocks.push(value) }
      v.heldOutput = () => ref
      bind(f, read("FidoUnlock.qml"), ["onAssertExited"])
      f.onAssertExited(0)
    }
    eq(`${method}, ${active ? "live" : "abandoned"}: unlock count`, v.unlocks.length, active ? 1 : 0)
    eq(`${method}, ${active ? "live" : "abandoned"}: held password ownership`,
      v.forgotten.includes("late-master"), !active)
  }
}
for (const invalidate of ["lock", "account switch", "epoch change"]) {
  const v = vault()
  v.envelopeProc.running = true // An unrelated write is in flight.
  v.openEnvelopeForFingerprint()
  const keptWrite = { command: ["synthetic-purge"], writes: true }
  v.queueEnvelopeJob(keptWrite)
  if (invalidate === "lock") v.dropVaultState()
  else if (invalidate === "account switch") v.activeSlot = "0123456789abcdef"
  else v.vaultEpoch++
  v.envelopeProc.running = false
  v.pumpEnvelopeJobs()
  check(`${invalidate}: queued open never starts; maintenance write still runs`,
    v.envelopeProc.command && v.envelopeProc.command[0] === "synthetic-purge",
    JSON.stringify(v.envelopeProc.command))
}
for (const reason of ["old account", "old epoch", "logout"]) {
  const v = vault()
  let accepted = 0
  v.queueEnvelopeJob({ command: ["synthetic-open"], holdOutput: true, secretOutput: true, unlock: true,
    onDone() { accepted++ } })
  const name = v.envelopeJob.heldName
  if (reason === "old account") v.activeSlot = "0123456789abcdef"
  else if (reason === "old epoch") v.vaultEpoch++
  else v.logoutPending = true
  v.envelopeProc.running = false
  v.onEnvelopeJobExited(0)
  eq(`${reason}: stale held result is not delivered`, accepted, 0)
  check(`${reason}: stale held result is forgotten`, v.forgotten.includes(name), v.forgotten.join())
}
{
  const v = vault(); const later = []
  v.Qt.callLater = f => later.push(f)
  v.envelopeProc.runId = 0
  v.openEnvelopeForFingerprint()
  v.vaultWaiting = [v.envelopeProc]
  v.queueEnvelopeJob({ command: ["synthetic-reseal"], writes: true })
  v.dropVaultState()
  while (later.length) later.shift()()
  eq("helper-waiting auth open is removed from the helper waiting list", v.vaultWaiting.length, 0)
  eq("cancelling a helper-waiting open resumes preserved reseal work",
    v.envelopeProc.command[0], "synthetic-reseal")
}
{
  const v = vault()
  const queued = []
  v.queueEnvelopeJob = job => queued.push(job)
  v.reconcileDisabledMethods()
  eq("disabled PIN queues a purge", queued.length, 1)
  queued.shift().onDone(1)
  check("failed purge is surfaced", /could not|failed|way in/i.test(v.errorMessage), v.errorMessage)
  for (let i = 0; i < 12; i++) {
    v.reconcileDisabledMethods()
    if (queued.length) queued.shift().onDone(1)
  }
  // Track actual invocations separately from the drained queue.
  const retry = vault(); let attempts = 0
  retry.queueEnvelopeJob = job => { attempts++; queued.push(job) }
  for (let i = 0; i < 12; i++) {
    retry.reconcileDisabledMethods()
    if (queued.length) queued.shift().onDone(1)
  }
  eq("failed cleanup receives bounded retries", attempts, 3)
  const success = vault(); let successfulAttempts = 0
  success.queueEnvelopeJob = job => { successfulAttempts++; queued.push(job) }
  success.reconcileDisabledMethods(); queued.shift().onDone(0)
  success.reconcileDisabledMethods()
  eq("successful cleanup is reconciled once", successfulAttempts, 1)
  eq("successful cleanup has no failure notice", success.errorMessage, "")
}
{
  const v = vault(); const queued = []; const later = []
  v.queueEnvelopeJob = job => queued.push(job)
  v.Qt.callLater = f => later.push(f)
  v.reconcileDisabledMethods()
  queued.shift().onDone(1)
  v.noteQuickUnlockEnabled("pin")
  while (later.length) later.shift()()
  eq("a delayed purge retry cannot remove a newly enabled method", queued.length, 0)
}
{
  const v = vault()
  v.envelopeProc.running = true
  v.reconcileDisabledMethods()
  v.noteQuickUnlockEnabled("pin")
  v.queueEnvelopeJob({ command: ["synthetic-setup"], writes: true })
  v.envelopeProc.running = false
  v.pumpEnvelopeJobs()
  eq("a queued old purge cannot remove a newly enabled method", v.envelopeProc.command[0], "synthetic-setup")
}
// A discarded maintenance job must settle, including a last allowed attempt.
for (const attempts of [0, 2]) {
  const v = vault(); const key = "default:pin"
  v.quickUnlockPurgeAttempts[key] = attempts
  v.queueEnvelopeJob({ command: ["blocked-write"], writes: true })
  v.reconcileDisabledMethods()
  eq(`switch at attempt ${attempts}: purge is queued behind a write`, v.envelopeJobs.length, 1)
  const abandoned = v.envelopeJobs[0]
  v.dropEnvelopeState()
  v.activeSlot = "0123456789abcdef"
  v.activeSlot = "default"; v.accountId = "synthetic-id"
  v.reconcileDisabledMethods()
  eq(`switch at attempt ${attempts}: returning queues a fresh purge`, v.envelopeJobs.length, 1)
  check(`switch at attempt ${attempts}: replacement differs from discarded purge`, v.envelopeJobs[0] !== abandoned, "")
}
// Failure schedules a retry behind an already queued add-method write. The
// add's completion enables PIN before that retry gets its turn to dispatch.
{
  const v = vault(); const later = []; const key = "default:pin"
  v.Qt.callLater = f => later.push(f)
  v.reconcileDisabledMethods()
  const obsolete = v.envelopeJob
  let wrap = false
  v.queueEnvelopeJob({ command: ["add-pin"], writes: true,
    onDone() { wrap = true; v.noteQuickUnlockEnabled("pin") } })
  v.envelopeProc.running = false; v.onEnvelopeJobExited(1)
  while (later.length) later.shift()()
  eq("add-method write runs before automatic retry", v.envelopeProc.command[0], "add-pin")
  eq("automatic retry is waiting behind add-method", v.envelopeJobs.length, 1)
  v.envelopeProc.running = false; v.onEnvelopeJobExited(0)
  while (later.length) later.shift()()
  // Any purge dispatched here would remove the newly stored wrap.
  if (v.envelopeJob) { wrap = false; v.envelopeProc.running = false; v.onEnvelopeJobExited(0) }
  eq("reenabled wrap survives queued obsolete retry", wrap, true)
  obsolete.onDone(0)
  eq("obsolete successful completion cannot reconcile newly enabled PIN", !!v.reconciledMethods[key], false)
  v.quickUnlockEnabledAt.pin = 0
  v.reconcileDisabledMethods()
  check("a later disable can dispatch a fresh purge", !!v.envelopeJob, "")
  if (v.envelopeJob) {
    const fresh = v.envelopeJob
    obsolete.onDone(1)
    check("obsolete failure cannot clear fresh pending ownership", v.quickUnlockPurgePending[key] === fresh, "")
    eq("obsolete failure cannot report a new cleanup error", v.errorMessage, "")
    v.envelopeProc.running = false; v.onEnvelopeJobExited(0)
    eq("fresh purge can reconcile", !!v.reconciledMethods[key], true)
  }
}
for (const code of [0, 1]) for (const priorAttempts of [0, 2]) {
  const v = vault(); const later = []; const key = "default:pin"
  v.quickUnlockPurgeAttempts[key] = priorAttempts
  v.Qt.callLater = f => later.push(f)
  v.reconcileDisabledMethods()
  const obsolete = v.envelopeJob
  v.dropEnvelopeState()
  v.activeSlot = "0123456789abcdef"; v.accountId = "other-synthetic-id"
  v.envelopeProc.running = false; v.onEnvelopeJobExited(code)
  while (later.length) later.shift()()
  eq(`switched account at attempt ${priorAttempts}: old completion ${code} does not reconcile`, !!v.reconciledMethods[key], false)
  check(`switched account at attempt ${priorAttempts}: old completion ${code} cannot retry`, v.envelopeJob === null, "")
  eq(`switched account at attempt ${priorAttempts}: old completion ${code} cannot report failure`, v.errorMessage, "")
  v.activeSlot = "default"; v.accountId = "synthetic-id"
  v.reconcileDisabledMethods()
  check(`return at attempt ${priorAttempts} after completion ${code}: cleanup remains retriable`, !!v.envelopeJob, "")
  obsolete.onDone(0)
  check(`return at attempt ${priorAttempts} after completion ${code}: obsolete completion cannot settle replacement`,
    v.quickUnlockPurgePending[key] === v.envelopeJob, "")
}
// Execute the real purge builder with a synthetic keyring executable. The
// real secret-tool is unreachable even if the tested script is incorrect.
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-purge-regression-"))
try {
  fs.writeFileSync(path.join(scratch, "secret-tool"), `#!/bin/bash
case "$1" in
 lookup) case "$LOOKUP_CASE" in
   present) cat "$SYNTHETIC_ENVELOPE"; exit 0;;
   absent) exit 1;;
   failed) echo 'synthetic service unavailable' >&2; exit 1;;
   newline-error) printf '\\n' >&2; exit 1;;
   killed) kill -KILL $$;;
   invalid-status) exit 2;;
   empty-success) exit 0;;
   present-newline-error) cat "$SYNTHETIC_ENVELOPE"; printf '\\n' >&2; exit 0;;
   present-error) cat "$SYNTHETIC_ENVELOPE"; echo "synthetic warning" >&2; exit 0;;
 esac ;;
 clear) case "$PURGE_CASE" in present) exit 0;; absent) exit 1;; failed) echo 'synthetic service unavailable' >&2; exit 1;; newline-error) printf '\\n' >&2; exit 1;; killed) kill -KILL $$;; esac ;;
esac
`, { mode: 0o755 })
  for (const [kind, ok] of [["present", true], ["absent", true], ["failed", false], ["newline-error", false], ["killed", false]]) {
    const command = Model.quickUnlockPurgeCommand("/synthetic/tool", ["default"], "pin")
    const r = spawnSync(command[0], command.slice(1), { encoding: "utf8", timeout: 5000,
      env: { PATH: `${scratch}:/usr/bin:/bin`, HOME: scratch, LOOKUP_CASE: "absent", PURGE_CASE: kind } })
    eq(`legacy purge ${kind}: success disposition`, r.status === 0, ok)
  }
  fs.writeFileSync(path.join(scratch, "systemd-creds"), "#!/bin/bash\ncat\n", { mode: 0o755 })
  const tool = path.join(scratch, "unlock-tool")
  fs.writeFileSync(tool, `#!/bin/bash
case "$1" in
 inspect) cat;;
 remove) jq '.pin = null';;
 verify) cat >/dev/null;;
 *) exit 2;;
esac
`, { mode: 0o755 })
  // Store is intercepted too; no fallback to a real keyring executable.
  const stub = path.join(scratch, "secret-tool")
  fs.writeFileSync(stub, fs.readFileSync(stub, "utf8").replace(' clear)',
    ' store) cat > "$SYNTHETIC_ENVELOPE";;\n clear)'))
  const envelope = path.join(scratch, "envelope")
  const initial = JSON.stringify({ account: { id: "synthetic", server: "https://synthetic.invalid" }, pin: { wrap: "synthetic" } })
  for (const legacy of ["present", "absent"]) {
    for (const [kind, ok] of [["present", true], ["absent", true], ["failed", false],
      ["newline-error", false], ["killed", false], ["invalid-status", false], ["empty-success", false], ["present-error", false], ["present-newline-error", false]]) {
      fs.writeFileSync(envelope, initial)
      const command = Model.quickUnlockPurgeCommand(tool, ["default"], "pin")
      const r = spawnSync(command[0], command.slice(1), { encoding: "utf8", timeout: 5000,
        env: { PATH: `${scratch}:/usr/bin:/bin`, HOME: scratch, LOOKUP_CASE: kind,
          PURGE_CASE: legacy, SYNTHETIC_ENVELOPE: envelope } })
      eq(`envelope lookup ${kind}, legacy ${legacy}: success disposition`, r.status === 0, ok)
      eq(`envelope lookup ${kind}, legacy ${legacy}: stored wrap disposition`,
        JSON.parse(fs.readFileSync(envelope, "utf8")).pin !== null, kind !== "present")
    }
  }

} finally { fs.rmSync(scratch, { recursive: true, force: true }) }
done()
