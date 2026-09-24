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

const { createSuite, functionBody, read } = require("./harness")
const path = require("path")

const service = read("Service.qml")
const panel = read("Panel.qml")
const manifest = JSON.parse(read("manifest.json"))

const { check, done } = createSuite("unlock-envelope-service")

const bodyOf = name => functionBody(service, name)

// -------------------------------------------------------------------------
// One writer
// -------------------------------------------------------------------------

// Calls, not mentions: comments name it too.
const callers = service.split("\n").filter(l => !/^\s*\/\//.test(l))
  .join("\n").match(/storeAcceptedMasterPassword\(/g).length
const unlockSuccess = bodyOf("onUnlockSuccess")
check("a typed, accepted password reaches the writer from the unlock path",
  /if \(pendingUnlockPassword && pendingUnlockFrom === ""\) \{\s*storeAcceptedMasterPassword\(pendingUnlockPassword\)/
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
  /var oldPassword = rotationOldPassword\s*\n\s*rotationOldPassword = ""/.test(writer)
    && /\} else \{\s*rotationOldPassword = ""/.test(unlockSuccess)
    && /rotationOldPassword = ""/.test(bodyOf("dropEnvelopeState")),
  writer.slice(0, 400))

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
  /envelopeProc\.environment = job\.env \|\| \{\}\s*\n\s*job\.env = null/.test(bodyOf("pumpEnvelopeJobs"))
    && /envelopeProc\.environment = \{\}/.test(bodyOf("onEnvelopeJobExited")),
  bodyOf("pumpEnvelopeJobs"))
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
check("forgetting fingerprint removes its wrap as well as any legacy entry",
  /requestMasterCredentialClear\(\)[\s\S]{0,200}?removeQuickUnlockMethod\(\{ kind: "remove", method: "fingerprint" \}\)/
    .test(bodyOf("forgetFingerprintUnlock")), bodyOf("forgetFingerprintUnlock"))
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
check("PIN rules are unchanged: validated first, numeric, 4 minimum",
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
  /pendingPinForMigration = String\(pinEntry \|\| ""\)/.test(bodyOf("onPinUnlockResult"))
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
  /function addQuickUnlockMethodWith\(password, makeCommand, extraEnv, done\)/.test(service)
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

done()
