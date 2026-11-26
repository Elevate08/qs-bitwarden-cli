#!/usr/bin/env node
// When Service.qml runs the envelope commands (the commands themselves are
// tested in unlock-envelope.test.js):
//
//   - the stored password comes only from one typed and accepted by `bw`;
//   - an enable form's password is a check and stores nothing new;
//   - a password changed elsewhere re-seals rather than dropping methods;
//   - one envelope process at a time, and logout outlasts them all.
//
//   node tests/unlock-envelope-service.test.js

const { createSuite, functionBody, loadModule, read } = require("./harness")
const Model = loadModule()
const path = require("path")

const service = read("Service.qml")
const panel = read("Panel.qml")
const manifest = JSON.parse(read("manifest.json"))

const { check, eq, done } = createSuite("unlock-envelope-service")

const bodyOf = name => functionBody(service, name)

// -------------------------------------------------------------------------
// One writer
// -------------------------------------------------------------------------

// Calls, not mentions: comments name it too.
const callers = service.split("\n").filter(l => !/^\s*\/\//.test(l))
  .join("\n").match(/storeAcceptedMasterPassword\(/g).length
const unlockSuccess = bodyOf("onUnlockSuccess")
check("a typed, accepted password reaches the writer from the unlock path",
  /if \(pendingUnlockPassword && pendingUnlockFrom === ""\) \{[\s\S]{0,200}?storeAcceptedMasterPassword\(pendingUnlockPassword[,)]/
    .test(unlockSuccess), unlockSuccess)
check("a quick unlock's password never does",
  !/pendingUnlockFrom === "(pin|fingerprint|fido)"[\s\S]{0,120}storeAcceptedMasterPassword/.test(service),
  "a method-produced password is stored")
check("the only other caller is an enable form, after bw has checked the password",
  callers === 3 // the definition, onUnlockSuccess, addQuickUnlockMethodWith
    && /verifyWithBw\(pw, function\(ok\)[\s\S]{0,200}?storeAcceptedMasterPassword\(pw/.test(bodyOf("addQuickUnlockMethodWith")),
  `${callers} occurrences`)

const loginOutput = bodyOf("onLoginOutput")
check("a login hands its typed password over before clearing it",
  /pendingUnlockPassword = String\(loginPassword \|\| ""\)\s*\n\s*pendingUnlockFrom = ""\s*\n\s*loginPassword = ""/
    .test(loginOutput), loginOutput.slice(loginOutput.indexOf("rememberTwoFactorMethod"), 2000))
check("the writer creates, replaces or rotates, and nothing else",
  /unlockEnvelopeCreateCommand/.test(bodyOf("storeAcceptedMasterPassword"))
    && /kind: "rotate"/.test(bodyOf("storeAcceptedMasterPassword"))
    && !/secret-tool store/.test(service),
  bodyOf("storeAcceptedMasterPassword"))
check("the old plaintext fingerprint writer is gone",
  !/keyringStoreMasterProc|masterToStore|onMasterPasswordStored/.test(service), "still referenced")

// -------------------------------------------------------------------------
// Enable forms check; they do not store
// -------------------------------------------------------------------------

const fpSetup = bodyOf("submitFingerprintSetup")
check("fingerprint setup adds a wrap through the master-password check",
  /addQuickUnlockMethod\(typed, \{ kind: "add-fingerprint" \}/.test(fpSetup), fpSetup)
check("and drops the typed password as soon as it is handed over",
  /var typed = fpSetupMaster\s*\n\s*fpSetupMaster = ""/.test(fpSetup), fpSetup)
check("a wrong password is named as such",
  /root\.fpError = root\.quickUnlockErrorText\(why,/.test(fpSetup)
    && /why === "wrong-password"\) return "That is not your master password\."/.test(bodyOf("quickUnlockErrorText")), fpSetup)
check("setup asks to confirm, not to store",
  /placeholderText: "Confirm your master password\.\.\."/.test(panel)
    && !/Needed once, to store for fingerprint unlock/.test(panel), "old copy")
check("with no envelope, bw checks the password and its new session is adopted",
  /Model\.bwVerifyPasswordCommand\(\)/.test(bodyOf("verifyWithBw"))
    && /root\.session = s\s*\n\s*root\.storeCurrentSession\(\)/.test(bodyOf("verifyWithBw")),
  bodyOf("verifyWithBw"))

// -------------------------------------------------------------------------
// A password changed elsewhere
// -------------------------------------------------------------------------

const unlockOutput = bodyOf("onUnlockOutput")
check("a refused envelope password keeps fingerprint unlock and holds the old password",
  /pendingUnlockFrom === "fingerprint" && fingerprintFromEnvelope\) \{[\s\S]{0,600}?rotationOldPassword = pendingUnlockPassword/
    .test(unlockOutput)
    && !/fingerprintFromEnvelope\) \{[\s\S]{0,400}?requestMasterCredentialClear/.test(unlockOutput),
  unlockOutput.slice(0, 1600))
const writer = bodyOf("storeAcceptedMasterPassword")
check("the next typed unlock rotates with it, keeping every method",
  /if \(oldPassword\)[\s\S]{0,300}?kind: "rotate", auth: \{ kind: "master" \}/.test(writer), writer)
check("without it, fingerprint's wrap can supply the key",
  /envelopeSummary\.fingerprint\)[\s\S]{0,200}?kind: "rotate", auth: \{ kind: "fingerprint" \}/.test(writer), writer)
check("otherwise the envelope is only marked stale, and nothing is dropped",
  /kind: "mark-stale"/.test(writer) && !/remove/.test(writer), writer)
check("the held old password is taken once, and cleared when no typed unlock uses it",
  /oldPassword = rotationOldPassword\s*\n\s*rotationOldPassword = ""/.test(writer)
    && /\} else \{\s*forgetHeldPassword\(rotationOldPassword\)\s*rotationOldPassword = ""/.test(unlockSuccess)
    && /rotationOldPassword = ""/.test(bodyOf("dropEnvelopeState")),
  writer.slice(0, 400))

// A master password a quick unlock produced is held by reference; it goes once
// nothing needs it.
check("a held reference is forgotten by name, and plain text is left alone",
  /var name = Model\.heldSecretName\(value\)\s*if \(name\) forgetVaultSecret\(name\)/.test(bodyOf("forgetHeldPassword")),
  bodyOf("forgetHeldPassword"))
check("a quick unlock's password is forgotten when the unlock succeeds, unless the legacy PIN migration or a floor re-wrap still needs it",
  /migrateLegacyPin\(pendingUnlockPassword, pendingPinForMigration\)[\s\S]{0,500}?if \(pendingUnlockFrom !== ""\) forgetHeldPassword\(pendingUnlockPassword\)/
    .test(unlockSuccess),
  unlockSuccess)
check("the legacy PIN migration forgets it when it ends, on every path",
  /!quickUnlockAvailable\) \{\s*forgetHeldPassword\(password\)/.test(bodyOf("migrateLegacyPin"))
    && /onDone: function\(code\) \{\s*root\.forgetHeldPassword\(password\)/.test(bodyOf("migrateLegacyPin"))
    && /function\(\) \{\s*root\.forgetHeldPassword\(password\)/.test(bodyOf("migrateLegacyPin")),
  bodyOf("migrateLegacyPin"))
check("a refused unlock forgets the password, except the one kept for a re-seal",
  /if \(!fromEnvelope\) \{\s*forgetHeldPassword\(pendingUnlockPassword\)\s*pendingUnlockPassword = ""/.test(unlockOutput)
    && /rotationOldPassword = pendingUnlockPassword/.test(unlockOutput),
  unlockOutput)
check("the kept old password is forgotten when the re-seal ends",
  /var finish = function\(ok\) \{\s*root\.forgetHeldPassword\(oldPassword\)/.test(writer), writer)
check("an unlock that returns no key, or whose password never reached bw, forgets it too",
  /if \(!s\) \{\s*forgetHeldPassword\(pendingUnlockPassword\)/.test(unlockSuccess)
    && /forgetHeldPassword\(pendingUnlockPassword\)\s*pendingUnlockPassword = ""\s*if \(unlockProc\.running\)/.test(bodyOf("onAuthPasswordWriterExited")),
  "")

// -------------------------------------------------------------------------
// Review findings, 2026-09-22 (/code-review of release/1.10.1)
// -------------------------------------------------------------------------

// 1. A changed password with no method set up used to leave an envelope that
//    nothing could open again, and every enable form calling the right password
//    wrong. With only the master wrap there is nothing to keep: recreate.
check("a master-only envelope is recreated when bw accepts a password it refuses",
  /else if \(!root\.envelopeHasMethods\(\)\) \{[\s\S]{0,700}?unlockEnvelopeCreateCommand\(tool, account\), env, finish\)/
    .test(writer), writer)
check("and an unread summary counts as having methods, so nothing is dropped on a guess",
  /if \(!envelopeSummary\) return envelopeChecked \? false : true/.test(bodyOf("envelopeHasMethods")),
  bodyOf("envelopeHasMethods"))
check("a stale envelope is named as stale at an enable form, not as a wrong password",
  /envelopeSummary\.stale \? "stale" : "wrong-password"/.test(bodyOf("addQuickUnlockMethodWith"))
    && /why === "stale"[\s\S]{0,200}?has not caught up yet/.test(bodyOf("quickUnlockErrorText")), "")
// 2. The account id outlived logout, binding the next account's password to it.
check("logout forgets which account the envelope belonged to",
  /accountId = ""\s*\n\s*accountServer = ""/.test(bodyOf("dropEnvelopeState")), bodyOf("dropEnvelopeState"))
// 3. bw could mint a session after the vault locked, and the panel adopted it.
check("a session bw mints after the vault locked is not adopted",
  /beginEpochOperation\("bwVerify"\)/.test(bodyOf("verifyWithBw"))
    && /epochOperationIsStale\("bwVerify"\) \|\| root\.logoutPending \|\| root\.status !== "unlocked"\) \{[\s\S]{0,60}?s = ""[\s\S]{0,40}?done\(false\)/
      .test(bodyOf("verifyWithBw")), bodyOf("verifyWithBw"))
// 4. Removal returned early without a summary, so an abandoned setup's wrap
//    written on the no-envelope path stayed.
check("removing a method does not wait for a summary to exist",
  !/if \(!envelopeSummary\) return/.test(bodyOf("removeQuickUnlockMethod")), bodyOf("removeQuickUnlockMethod"))
// 5. A failed bw status never called back, leaving setup forms busy forever.
check("an account that cannot be learned still answers its caller",
  /function withEnvelopeAccount\(then, otherwise\)[\s\S]{0,600}?else if \(otherwise\) \{\s*otherwise\(\)/.test(service)
    && /\}, function\(\) \{ finish\(false\) \}\)/.test(writer)
    && /\}, function\(\) \{ done\(false, "failed", 0\) \}\)/.test(bodyOf("addQuickUnlockMethodWith")), "")

// -------------------------------------------------------------------------
// One at a time, and logout last
// -------------------------------------------------------------------------

check("envelope jobs run one at a time",
  /if \(envelopeProc\.running \|\| envelopeJob !== null \|\| envelopeJobs\.length === 0\) return/
    .test(bodyOf("pumpEnvelopeJobs")), bodyOf("pumpEnvelopeJobs"))
check("a job's secrets are dropped the moment it starts",
  /envelopeProc\.environment = Object\.assign\(\{\}, job\.accountEnv \|\| \{\}, job\.env \|\| \{\}\)\s*\n\s*job\.env = null/.test(bodyOf("pumpEnvelopeJobs"))
    && /envelopeProc\.environment = \{\}/.test(bodyOf("onEnvelopeJobExited")),
  bodyOf("pumpEnvelopeJobs"))
check("every job carries the account in its environment, not its argv",
  /job\.accountEnv = Model\.envelopeAccountEnv\(envelopeAccount\(\)\)/.test(bodyOf("queueEnvelopeJob")),
  bodyOf("queueEnvelopeJob"))
check("a job that printed the password has its collector scrubbed",
  /job\.secretOutput\) clearProcessCollectorSoon\(envelopeProc\)/.test(bodyOf("onEnvelopeJobExited")),
  bodyOf("onEnvelopeJobExited"))

// -------------------------------------------------------------------------
// Reading, migrating, and saying what it costs
// -------------------------------------------------------------------------

check("fingerprint unlock reads the envelope when it has a fingerprint wrap",
  /envelopeSummary\.fingerprint\) \{\s*openEnvelopeForFingerprint\(\)/.test(bodyOf("onFingerprintResult")),
  bodyOf("onFingerprintResult"))
check("and falls back to the legacy entry only for the start before migration",
  /\(code === 7 \|\| code === E\.absent\) && root\.legacyFingerprintStored/.test(bodyOf("openEnvelopeForFingerprint")),
  bodyOf("openEnvelopeForFingerprint"))
check("migration runs once per session, and only when everything it needs is there",
  /legacyMigrationAttempted \|\| !legacyFingerprintStored \|\| !quickUnlockAvailable \|\| !accountId/
    .test(bodyOf("maybeMigrateLegacyFingerprint")), bodyOf("maybeMigrateLegacyFingerprint"))
check("the account comes from bw status",
  /accountId = st\.userId\s*\n\s*accountServer = st\.serverUrl/.test(service), "")
check("argon2 and systemd-creds are probed at start",
  /root\.inspectQuickUnlockPrereqs\(\)/.test(service)
    && /quickUnlockAvailable: unlockKeyReady && quickUnlockPrereqs\.ready/.test(service), "")
check("forgetting fingerprint deletes the envelope, whose key its wrap exposed, as well as any legacy entry",
  /requestMasterCredentialClear\(\)[\s\S]{0,300}?envelopeSummary\.fingerprint\) \{\s*removeQuickUnlockMethod\(\{ kind: "delete" \}\)/
    .test(bodyOf("forgetFingerprintUnlock")) && !/method: "fingerprint"/.test(bodyOf("forgetFingerprintUnlock")),
  bodyOf("forgetFingerprintUnlock"))
check("and says so when a PIN or key went with it",
  /s\.fingerprint && \(s\.pin \|\| \(Array\.isArray\(s\.fido\) && s\.fido\.length > 0\)\)/.test(bodyOf("fingerprintForgottenText"))
    && /stored password was deleted, so set up PIN or security-key unlock again/.test(bodyOf("fingerprintForgottenText"))
    && /flashNotification\(notice\)/.test(bodyOf("forgetFingerprintUnlock")), bodyOf("fingerprintForgottenText"))
check("a wrap from a cancelled setup deletes the envelope, since it exposes the key",
  /epochOperationIsStale\("fingerprintAdd"\)[\s\S]{0,500}?deleteEnvelopeForAccount\(/
    .test(bodyOf("submitFingerprintSetup")), bodyOf("submitFingerprintSetup"))
// The setup names the account it began for; a switch before the write lands
// must not move the delete to the account that became active, and the add's
// completion must still arrive so that delete is queued at all.
{
  const bind = (v, names) => {
    for (const n of names) {
      const body = functionBody(service, n)
      if (!body) throw new Error("missing function " + n)
      v[n] = new Function("scope", "with(scope){" + body + "\nreturn " + n + "}")(v)
    }
  }
  const v = {
    Model, Qt: { callLater: f => f() },
    quickUnlockAvailable: true, quickUnlockUnavailableReason: "",
    accountId: "user-a", accountServer: "https://a.invalid",
    activeSlot: "default", vaultEpoch: 1, fpSetupMaster: "synthetic-master",
    fpBusy: false, fpSetupActive: true, fpError: "", legacyFingerprintStored: false,
    fingerprintStored: false, currentScreen: "fingerprint", refreshes: 0,
    envelopeJobs: [], envelopeJob: null, logoutPending: false, allCredentialsClearPending: false,
    envelopeProc: { running: false, command: [], environment: {}, outputHeld: false, runId: 0 },
    envelopeStdout: { text: "" },
    envelopeAccount() { return { id: this.accountId, server: this.accountServer, slot: this.activeSlot } },
    envelopeTool() { return "/synthetic/tool" },
    beginEpochOperation() {},
    epochOperationIsStale() { return this.activeSlot !== "default" },
    refreshEnvelope() { this.refreshes++ },
    finishScrubRun() { return false },
    clearProcessCollectorSoon() {},
    recheckStatusAfterUnlock() {},
    forgetHeldPassword() {},
    withEnvelopeAccount(then) { then() },
    noteQuickUnlockEnabled() {},
    requestMasterCredentialClear() {},
    recomputeFingerprintStored() {},
    writeSetting() {},
    flashNotification() {}
  }
  v.root = v
  bind(v, ["submitFingerprintSetup", "addQuickUnlockMethod", "addQuickUnlockMethodWith",
    "queueEnvelopeJob", "pumpEnvelopeJobs", "onEnvelopeJobExited", "deleteEnvelopeForAccount",
    "writeEnvelope"])
  v.submitFingerprintSetup()
  const addJob = v.envelopeJob
  eq("the fingerprint add starts for the active account", addJob && addJob.command.join(" ").includes("fingerprint"), true)
  eq("the fingerprint add completes after a slot change", addJob.alwaysDone, true)

  // A switch between the add and its completion.
  v.activeSlot = "0123456789abcdef"
  v.accountId = "user-b"
  v.accountServer = "https://b.invalid"
  v.vaultEpoch += 1
  // Deliver the add's success through the real exit path.
  v.envelopeProc.running = false
  v.onEnvelopeJobExited(0)

  const job = v.envelopeJob
  eq("a stale enrolment deletes the envelope of the account it began for",
    job && JSON.stringify(job.command), JSON.stringify(Model.unlockEnvelopeDeleteForAccountCommand("/synthetic/tool",
      { id: "user-a", server: "https://a.invalid", slot: "default" })))
  eq("with that account's slot, not the active one", job && job.slot, "default")
  eq("and that account's environment", job && JSON.stringify(job.accountEnv),
    JSON.stringify(Model.envelopeAccountEnv({ id: "user-a", server: "https://a.invalid" })))
  check("the delete is not for the account that became active",
    job && job.slot !== v.activeSlot && !JSON.stringify(job.command).includes("user-b"))
  eq("no delete is queued for the new account either", v.envelopeJobs.length, 0)
}
check("the fingerprint retry write keeps the same completion guarantee",
  /root\.writeEnvelope\(command, again, function\(added, addCode\) \{[\s\S]{0,150}?\}, undefined, \{ alwaysDone: alwaysDone \}\)/
    .test(bodyOf("addQuickUnlockMethodWith")), bodyOf("addQuickUnlockMethodWith"))
check("the PIN add does not outlive a switch, where its cleanup would target the new account",
  !/alwaysDone/.test(bodyOf("submitPinSetup")), bodyOf("submitPinSetup"))

check("settings state the floor rule where it applies",
  /fingerprintUnlock \|\| !fingerprintStored\) return ""[\s\S]{0,200}?only as protected as/
    .test(bodyOf("settingNote"))
    && /root\.vault\.settingNote\(modelData\)/.test(panel), bodyOf("settingNote"))

// -------------------------------------------------------------------------
// PIN
// -------------------------------------------------------------------------

const pinSetup = bodyOf("submitPinSetup")
check("PIN setup adds a wrap through the master-password check, with the PIN in the environment",
  /addQuickUnlockMethod\(typed, \{ kind: "add-pin" \}, pin,/.test(pinSetup)
    && /pin\[Model\.pinEnvVar\(\)\] = pinSetupPin/.test(pinSetup), pinSetup)
check("PIN rules: validated first, numeric, the setup floor",
  /Model\.validatePin\(pinSetupPin, pinSetupConfirm\)/.test(pinSetup), pinSetup)
check("a wrong master password is named as such",
  /root\.pinError = root\.quickUnlockErrorText\(why,/.test(pinSetup), pinSetup)
check("the old PIN-blob writer is gone",
  !/pinStoreProc|onPinStored|Model\.pinStoreCommand/.test(service), "still referenced")
const pinUnlock = bodyOf("submitPinUnlock")
check("PIN unlock opens the envelope when it has a PIN wrap",
  /envelopeSummary\.pin\)[\s\S]{0,300}?kind: "pin"/.test(pinUnlock), pinUnlock)
check("a wrong PIN counts against the attempts, as before",
  /code === 3\) \{\s*countWrongPin\(\)/.test(bodyOf("onEnvelopePinResult"))
    && /pinAttempts >= pinMaxAttempts\) \{[\s\S]{0,300}?clearPin\(\)/.test(bodyOf("countWrongPin")),
  bodyOf("onEnvelopePinResult"))
check("an envelope answer is only acted on for a live, submitted unlock",
  /pinUnlockSubmitted && sshAuthSurfaceActive && status === "locked"/.test(bodyOf("onEnvelopePinResult")),
  bodyOf("onEnvelopePinResult"))
check("a legacy blob's PIN is held only until that unlock settles, then migrated",
  /pendingPinForMigration = heldPin \? [^\n]*: String\(pinEntry \|\| ""\)/.test(bodyOf("onPinUnlockResult"))
    && /pendingUnlockFrom === "pin" && !pinFromEnvelope && pendingPinForMigration && pendingUnlockPassword\) \{\s*migrateLegacyPin/
      .test(unlockSuccess)
    && /pendingPinForMigration = ""/.test(unlockSuccess)
    && /pendingPinForMigration = ""/.test(unlockOutput),
  bodyOf("onPinUnlockResult"))
check("a PIN whose password was changed elsewhere is kept, and feeds the re-seal",
  /pendingUnlockFrom === "pin" && pinFromEnvelope\) \{[\s\S]{0,600}?rotationOldPassword = pendingUnlockPassword/
    .test(unlockOutput), unlockOutput.slice(0, 2400))
check("removing the PIN removes its wrap as well as any legacy blob",
  /requestPinCredentialClear\(\)[\s\S]{0,200}?removeQuickUnlockMethod\(\{ kind: "remove", method: "pin" \}\)/
    .test(bodyOf("clearPin")), bodyOf("clearPin"))
const pinEntry = manifest.barWidget.schema.find(e => e.key === "pinUnlock")
check("the PIN option describes the envelope, not a ciphertext of its own",
  pinEntry && /stored once, encrypted/.test(pinEntry.description) && /Argon2id/.test(pinEntry.description),
  pinEntry && pinEntry.description)

// -------------------------------------------------------------------------
// FIDO2
// -------------------------------------------------------------------------

check("a key whose password was changed elsewhere is kept, and feeds the re-seal",
  /pendingUnlockFrom === "fido" && fidoFromEnvelope\) \{[\s\S]{0,600}?rotationOldPassword = pendingUnlockPassword/
    .test(unlockOutput), "")
check("the enable path that touches a key shares the master-password check and bw fallback",
  /function addQuickUnlockMethodWith\(password, makeCommand, extraEnv, done(, options)?\)/.test(service)
    && /addQuickUnlockMethodWith\(password, function\(tool, account\) \{\s*return Model\.unlockEnvelopeUpdateCommand/
      .test(bodyOf("addQuickUnlockMethod")),
  bodyOf("addQuickUnlockMethod"))
check("the FIDO flag is cleared with the others",
  /fidoFromEnvelope = false/.test(bodyOf("dropEnvelopeState"))
    && /fidoFromEnvelope = false/.test(unlockSuccess), "")
const fidoEntry = manifest.barWidget.schema.find(e => e.key === "fidoUnlock")
check("the FIDO2 option describes the key's secret, not a stored password behind a gate",
  fidoEntry && /stored once, encrypted/.test(fidoEntry.description)
    && /nothing is registered again/.test(fidoEntry.description)
    && !/Stores your master password in the OS login keyring/.test(fidoEntry.description),
  fidoEntry && fidoEntry.description)

const fpEntry = manifest.barWidget.schema.find(e => e.key === "fingerprintUnlock")
check("the fingerprint option no longer says the password is stored as-is",
  fpEntry && /stored once, encrypted/.test(fpEntry.description)
    && !/Stores your master password in the OS login keyring/.test(fpEntry.description),
  fpEntry && fpEntry.description)

// -------------------------------------------------------------------------
// The keyring repair at start
// -------------------------------------------------------------------------

{
  const loaded = bodyOf("onAccountRegistryLoaded")
  check("the keyring repair is queued as soon as the accounts are known",
    /accountsLoaded = true\s*repairKeyring\(\)/.test(loaded), loaded)
  const repair = bodyOf("repairKeyring")
  check("once per start, through the envelope queue, for every account",
    /if \(keyringRepairQueued\) return/.test(repair) && /queueEnvelopeJob\(/.test(repair)
      && /Model\.keyringRepairCommand\(sshAgentPluginDir, slots\)/.test(repair), repair)
  check("a repaired file is announced on the desktop",
    /r\.file === "repaired"[\s\S]{0,200}execDetached\(Model\.repairedKeyringNoticeCommand\(\)\)/
      .test(bodyOf("onKeyringRepaired")), "")
}

// -------------------------------------------------------------------------
// A method turned off is removed from every account
// -------------------------------------------------------------------------
//
// The settings are shared switches; each account's envelope has its own
// ways in. Turning one off used to remove only the account on screen's.

const pinChanged = service.slice(service.indexOf("onPinUnlockChanged:"), service.indexOf("onPinUnlockChanged:") + 700)
const fpChanged = service.slice(service.indexOf("onFingerprintUnlockChanged:"), service.indexOf("onFingerprintUnlockChanged:") + 1500)
const fidoSrc = read("FidoUnlock.qml")
const fidoArmed = fidoSrc.slice(fidoSrc.indexOf("onArmedChanged:"), fidoSrc.indexOf("onArmedChanged:") + 900)
check("turning PIN off purges it from every account", /purgeQuickUnlockMethod\("pin"\)/.test(pinChanged), pinChanged)
check("turning fingerprint off purges it from every account",
  /purgeQuickUnlockMethod\("fingerprint"\)/.test(fpChanged), fpChanged)
check("and the notice is settled from the summary before the purge empties it",
  /var notice = fingerprintForgottenText\(\)[\s\S]{0,200}?purgeQuickUnlockMethod\("fingerprint"\)\s*flashNotification\(notice\)/.test(fpChanged), fpChanged)
check("startup reconciliation queues an all-slot fingerprint purge, not only the active account",
  /!started \|\| !accountsLoaded[\s\S]{0,400}?purgeQuickUnlockMethod\("fingerprint"\)/.test(fpChanged)
    && /!started \|\| !accountsLoaded[\s\S]{0,400}?forgetFingerprintUnlock\(\)/.test(fpChanged),
  fpChanged)
check("a cancelled fingerprint enrolment deletes the whole envelope, not just its wrap",
  /epochOperationIsStale\("fingerprintAdd"\)[\s\S]{0,500}?deleteEnvelopeForAccount\(/
    .test(bodyOf("submitFingerprintSetup")), bodyOf("submitFingerprintSetup"))
check("the fingerprint purge deletes the envelope instead of storing one without the wrap",
  /method === "fingerprint"\) \{[\s\S]{0,200}?keyringClearEntryScript\(keyringEntryName\(KEYRING_ENVELOPE, slot\)\) \+ " \|\| exit 1; exit 0; "/
    .test(read("BitwardenModel.js")), "")
check("turning FIDO2 off purges it from every account",
  /vault\.purgeQuickUnlockMethod\("fido"\)/.test(fidoArmed), fidoArmed)
check("the purge names every account slot the panel holds",
  /accountRegistry\.accounts\[i\]\.slot/.test(bodyOf("accountSlotsForPurge"))
    && /var slots = accountSlotsForPurge\(\)/.test(bodyOf("purgeQuickUnlockMethod"))
    && /queueQuickUnlockPurge\(slots, method,/.test(bodyOf("purgeQuickUnlockMethod"))
    && /Model\.quickUnlockPurgeCommand\(envelopeTool\(\), slots, method\)/.test(bodyOf("queueQuickUnlockPurge"))
    && /writes:\s*true/.test(bodyOf("queueQuickUnlockPurge")),
  bodyOf("purgeQuickUnlockMethod"))
check("a purge asked for before the unlock tool is ready runs once it is",
  /pendingPurges/.test(bodyOf("purgeQuickUnlockMethod")) && /runPendingPurges\(\)/.test(bodyOf("envelopeReadinessChanged")),
  bodyOf("envelopeReadinessChanged"))

// A setting turned off in shell.json while the shell was stopped.
const refresh = bodyOf("refreshEnvelope")
const reconcile = bodyOf("reconcileDisabledMethods")
check("every envelope read reconciles methods whose setting is off",
  /reconcileDisabledMethods\(\)/.test(refresh), refresh)
check("only a setting explicitly false counts as off, never one not loaded yet",
  /settings\[name\] === false/.test(bodyOf("quickUnlockSettingOff")), bodyOf("quickUnlockSettingOff"))
check("a method just enabled is not taken for off while its setting write lands",
  /quickUnlockEnabledAt\[c\.method\]/.test(reconcile) && /quickUnlockEnableGraceMs/.test(reconcile)
    && /noteQuickUnlockEnabled\("pin"\)/.test(bodyOf("submitPinSetup"))
    && /noteQuickUnlockEnabled\("fingerprint"\)/.test(bodyOf("submitFingerprintSetup"))
    && /noteQuickUnlockEnabled\("fido"\)/.test(fidoSrc),
  reconcile)
check("a method that is off is purged even with no envelope entry for it, which clears its legacy entry",
  !/present/.test(reconcile) && !/summary/.test(reconcile)
    && /if \(!quickUnlockSettingOff\(c\.setting\)\) continue/.test(reconcile)
    && /accountSlotsForPurge\(\)[\s\S]{0,100}?queueQuickUnlockPurge\(slots, c\.method, key\)/.test(reconcile),
  reconcile)
check("an account with no envelope at all is reconciled too",
  /code === Model\.envelopeExitCodes\(\)\.absent\) \{\s*root\.reconcileDisabledMethods\(\)/.test(refresh), refresh)
check("successful cleanup is reconciled; retries of a failure have a bound",
  /reconciledMethods\[key\]\) continue/.test(reconcile)
    && /quickUnlockPurgeMaxAttempts/.test(bodyOf("queueQuickUnlockPurge")), reconcile)

// A successful PIN open below the current PIN Argon2 floor re-wraps it with
// the PIN and password still in hand (QK-3).
const pinFloor = new Function("Model",
  functionBody(service, "pinWrapBelowFloor") + "\nreturn pinWrapBelowFloor")(Model)
const floor = Model.ENVELOPE_ARGON2
eq("a current-floor PIN wrap needs no re-wrap",
  pinFloor({ pin: { m: floor.m, t: floor.t } }), false)
eq("an older 64 MiB / 3-pass PIN wrap needs one",
  pinFloor({ pin: { m: 65536, t: 3 } }), true)
eq("one below either floor dimension needs one",
  pinFloor({ pin: { m: floor.m, t: floor.t - 1 } }) && pinFloor({ pin: { m: floor.m - 1, t: floor.t } }), true)
eq("no PIN wrap needs none", pinFloor({ pin: null }), false)
const rewrap = bodyOf("rewrapPinAtFloor")
check("the re-wrap uses the existing add-pin job and the current floor",
  /kind: "add-pin"/.test(rewrap)
    && /Model\.unlockEnvelopeUpdateCommand/.test(rewrap)
    && /Model\.keyringSecretEnvVar\(\)\] = master/.test(rewrap)
    && /Model\.pinEnvVar\(\)\] = pinValue/.test(rewrap)
    && /secretOutput: true/.test(rewrap),
  rewrap)
check("an add-method write treats the envelope it prints as secret too",
  /queueEnvelopeJob\(\{\s*command: command, env: env, secretOutput: true, writes: true/.test(bodyOf("addQuickUnlockMethodWith")),
  bodyOf("addQuickUnlockMethodWith"))
check("the successful unlock starts the re-wrap before dropping the password",
  /pendingUnlockFrom === "pin" && pinFromEnvelope[\s\S]{0,600}?rewrapPinAtFloor\(pendingUnlockPassword, root\.pinRewrapPin\)/
    .test(unlockSuccess)
    && /pinWrapBelowFloor\(envelopeSummary\)/.test(bodyOf("onEnvelopePinResult")),
  unlockSuccess)

// A pinentry capture with no helper cannot run; its synthetic failure answers
// for the start that asked, not whichever run replaced it by callback time.
const vaultStart = bodyOf("vaultStart")
check("a synthetic missing-pinentry finish carries the run it answers for",
  /var seq = proc\.runSeq[\s\S]{0,200}?proc\.finish\(Model\.pinentryExitCodes\(\)\.missing, "", "no vault helper", false, false, seq\)/
    .test(vaultStart),
  vaultStart)

done()
