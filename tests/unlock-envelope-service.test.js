#!/usr/bin/env node
// How the vault service uses the quick-unlock envelope. The envelope commands
// themselves are exercised for real in tests/unlock-envelope.test.js; this
// file pins the rules about *when* they run, which live in Service.qml:
//
//   - the stored password comes only from a password somebody typed and `bw`
//     accepted -- never from one a quick-unlock method produced;
//   - an enable form's master password is a check, and stores nothing new;
//   - a password changed elsewhere re-seals the envelope rather than dropping
//     methods;
//   - one envelope process runs at a time, and logout outlasts all of them.
//
//   node tests/unlock-envelope-service.test.js

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const service = fs.readFileSync(path.join(repoRoot, "Service.qml"), "utf8")
const panel = fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8")
const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "manifest.json"), "utf8"))

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${String(detail).slice(0, 400)}`)

// The body of a QML function, by brace matching.
function bodyOf(name) {
  const start = service.indexOf(`function ${name}(`)
  if (start < 0) return ""
  let depth = 0
  for (let i = service.indexOf("{", start); i < service.length; i++) {
    if (service[i] === "{") depth++
    else if (service[i] === "}" && --depth === 0) return service.slice(start, i + 1)
  }
  return ""
}

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
  callers === 3 // the definition, onUnlockSuccess, addQuickUnlockMethod
    && /verifyWithBw\(pw, function\(ok\)[\s\S]{0,200}?storeAcceptedMasterPassword\(pw/.test(bodyOf("addQuickUnlockMethod")),
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
  /wrong-password[\s\S]{0,80}That is not your master password/.test(fpSetup), fpSetup)
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
  /wrong-password[\s\S]{0,80}That is not your master password/.test(pinSetup), pinSetup)
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

const fpEntry = manifest.barWidget.schema.find(e => e.key === "fingerprintUnlock")
check("the fingerprint option no longer says the password is stored as-is",
  fpEntry && /stored once, encrypted/.test(fpEntry.description)
    && !/Stores your master password in the OS login keyring/.test(fpEntry.description),
  fpEntry && fpEntry.description)

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`unlock-envelope-service: ${pass} passed`)
