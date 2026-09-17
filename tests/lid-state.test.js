#!/usr/bin/env node
// Tests for the closed-lid rule: the fingerprint reader is on the laptop body,
// so a shut lid must take "Unlock with Fingerprint" off the screen while leaving
// everything else -- the master password, and a FIDO2 key on a cable -- alone.
//
//   node tests/lid-state.test.js

const fs = require("fs")
const path = require("path")
const root = path.join(__dirname, "..")
const read = f => fs.readFileSync(path.join(root, f), "utf8")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

const lid = read("LidState.qml")
const service = read("Service.qml")
const panel = read("Panel.qml")
const sshUnlock = read("SshUnlockScreen.qml")
// Both surfaces draw the shared form, so its own gating is what takes the
// option off either screen.
const unlockForm = read("UnlockForm.qml")

// --- the detector ------------------------------------------------------------

check("the lid is read from Omarchy's own detector",
  /command:\s*\[[^\]]*omarchy-hw-laptop-closed/.test(lid),
  "expected the omarchy-hw-laptop-closed command")
// Its exit status is the answer: 0 when closed. Anything else (no lid, no
// detector) reads as open, which is the safe direction -- a reader that turns
// out to be reachable beats one that never appears.
check("closed is the zero exit status, and anything else reads as open",
  /onExited:\s*function\([^)]*\)\s*\{\s*lid\.closed = \([^)]*=== 0\)/.test(lid),
  "expected `closed = (exitCode === 0)`")

// --- the poll ----------------------------------------------------------------

check("the poll is gated on the vault being live",
  /running:\s*lid\.vault && lid\.vault\.live/.test(lid),
  "an unattached vault must start nothing")
check("and on a panel or SSH prompt actually being on screen",
  /running:[^\n]*lid\.vault\.opened \|\| lid\.vault\.sshAuthSurfaceActive/.test(lid),
  "nothing to decide while neither surface is up")
// The panel picks its unlock buttons the moment it opens, so a reading from
// minutes ago must not be what it decides from.
check("the gate opening triggers a fresh reading",
  /onRunningChanged:\s*if \(running\) lid\.refresh\(\)/.test(lid),
  "expected a refresh when the gate opens")

// --- how the vault uses it ---------------------------------------------------

check("the vault instantiates it and hands it itself",
  /LidState\s*\{\s*id:\s*lidState\s*vault:\s*root/.test(service),
  "LidState must be instantiated with `vault: root`")
check("the vault exposes the reading as lidClosed",
  /readonly property bool lidClosed:\s*lidState\.closed/.test(service),
  "expected `lidClosed` on the vault")
check("a closed lid drops fingerprint readiness",
  /readonly property bool fingerprintReady:[^\n]*&& !lidClosed/.test(service),
  "fingerprintReady must carry the lid, or nothing that offers the option would hide")

// The option is offered by one button in the shared form, and the form only
// draws it while the fingerprint is the offered method -- which reads
// fingerprintReady. The auto-arm goes through startFingerprintUnlock, whose
// guard reads the same property.
check("the shared form offers the fingerprint only while it is ready",
  /if \(name === "fingerprint"\) return form\.vault\.fingerprintReady/.test(unlockForm)
    && /visible: form\.fieldsOffered && form\.method === "fingerprint"/.test(unlockForm),
  "the fingerprint button must follow fingerprintReady")
check("a lid closed mid-scan ends the scan it put out of reach",
  /onLidClosedChanged: if \(lidClosed && fingerprintScanning\) cancelFingerprintUnlock\(\)/.test(service),
  "the first reading can land after the auto-arm has already started a scan")
check("and arming refuses while it is not ready",
  /function startFingerprintUnlock\(\)\s*\{\s*if \(!fingerprintReady/.test(service),
  "startFingerprintUnlock must refuse on !fingerprintReady")

// --- what the lid must NOT touch ---------------------------------------------
//
// The user asked for the fingerprint option to go, "no matter if the FIDO2
// unlock is enabled and configured or not": the two are independent, and a key
// on a cable does not care about the lid.

check("the FIDO2 option is not gated on the lid",
  !/fidoReady[^\n]*lidClosed/.test(service)
    && /if \(name === "fido"\) return form\.vault\.fidoReady/.test(unlockForm)
    && !/fido[\s\S]{0,120}lidClosed/.test(unlockForm),
  "the FIDO2 button must stay independent of the lid")
check("enrolment state is untouched, so the setting still reflects what is stored",
  /property bool fingerprintStored: false/.test(service)
    && /case "fingerprintUnlock": return fingerprintUnlock && fingerprintStored/.test(service),
  "the lid must not change whether a password is stored, nor what the toggle reads")

if (failures.length) {
  console.error(`FAIL ${failures.length}\n`)
  for (const f of failures) console.error(`  x ${f}\n`)
  process.exit(1)
}
console.log(`ok ${pass}`)
