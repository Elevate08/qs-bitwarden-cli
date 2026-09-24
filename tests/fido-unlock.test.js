#!/usr/bin/env node
// FIDO2 unlock: the probe that maps registered credentials to plugged-in keys,
// the Omarchy setup hand-off, and FidoUnlock.qml turning one touch into the
// key's hmac-secret for the envelope's FIDO wrap. The pipelines themselves run
// for real, against a stand-in fido2-assert, in tests/unlock-envelope.test.js.
//
//   node tests/fido-unlock.test.js

const { createSuite, loadModule, read, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const path = require("path")

const Fido = loadModule("FidoModel.js")

const { check, done } = createSuite("fido-unlock")

// --- no PAM stack any more -------------------------------------------------
const rawFidoUnlockEarly = read("FidoUnlock.qml")
check("no PAM stack ships with the plugin",
  !fs.existsSync(path.join(repoRoot, "pam")), "pam/ still exists")
check("the controller holds no PAM conversation",
  !/Quickshell\.Services\.Pam|PamContext/.test(rawFidoUnlockEarly), "PamContext is still in FidoUnlock.qml")

// --- the probe --------------------------------------------------------------
const probe = Fido.fidoProbeCommand()
check("the probe is one shell invocation",
  Array.isArray(probe) && probe[0] === "bash" && probe[1] === "-c" && probe.length === 3,
  JSON.stringify(probe && probe.slice(0, 2)))
const probeScript = probe[2] || ""
check("the probe caps its own output",
  probeScript.includes("head -c " + Fido.FIDO_MAX_PROBE_BYTES),
  probeScript)
check("the probe checks for libfido2's tools, which pam-u2f itself depends on",
  probeScript.includes("command -v fido2-assert") && probeScript.includes("command -v fido2-token"),
  probeScript)
// Finding which key holds a credential must cost no touch and release no
// secret. An hmac-secret request for a credential a key does not hold waits
// for a touch before saying so (measured), so it is never used to search.
check("the probe finds credentials with a silent assertion",
  /fido2-assert -G -t up=false/.test(probeScript), probeScript)
check("and never asks for an hmac-secret while searching",
  !/fido2-assert[^|;]* -h\b/.test(probeScript), probeScript)
check("it reads only this user's line of the authfile",
  /awk -F: -v u="\$\(id -un\)" '\$1 == u/.test(probeScript), probeScript)
check("the relying party is pam-u2f's default, the one the registration was made for",
  /__rp="pam:\/\/\$\(hostname/.test(probeScript), probeScript)
check("the probe requires a regular, non-empty, non-symlink authfile",
  probeScript.includes("[ -f '" + Fido.FIDO_AUTHFILE + "' ]")
    && probeScript.includes("[ -s '" + Fido.FIDO_AUTHFILE + "' ]")
    && probeScript.includes("[ ! -L '" + Fido.FIDO_AUTHFILE + "' ]"),
  probeScript)
check("the probe asks fido2-token for a present device",
  probeScript.includes("fido2-token -L"),
  probeScript)
check("the probe carries no secret and never touches the keyring",
  probe.every(a => !/QSBW_SECRET|QSBW_PIN|secret-tool|password/i.test(String(a))),
  JSON.stringify(probe))

// --- parsing ----------------------------------------------------------------
const all = Fido.parseFidoProbe("fido_installed=1\nfido_registered=1\nfido_token=1\n")
check("installed + registered + present is applicable, but not ready without a credential found on the key",
  all.ready === false && all.applicable === true,
  JSON.stringify(all))

const noToken = Fido.parseFidoProbe("fido_installed=1\nfido_registered=1\nfido_token=0\n")
check("registered but no device plugged in is not ready",
  noToken.ready === false && noToken.applicable === true,
  JSON.stringify(noToken))

const noReg = Fido.parseFidoProbe("fido_installed=1\nfido_registered=0\nfido_token=1\n")
check("a device but no registration is not ready",
  noReg.ready === false && noReg.applicable === true,
  JSON.stringify(noReg))

const none = Fido.parseFidoProbe("fido_installed=0\nfido_registered=0\nfido_token=0\n")
check("nothing present is neither ready nor applicable",
  none.ready === false && none.applicable === false,
  JSON.stringify(none))

check("an empty probe answer is not read as ready",
  Fido.parseFidoProbe("").ready === false && Fido.parseFidoProbe("").applicable === false,
  JSON.stringify(Fido.parseFidoProbe("")))
check("a malformed probe answer is not read as ready",
  Fido.parseFidoProbe("garbage\n=1\nfido_installed\n").ready === false,
  JSON.stringify(Fido.parseFidoProbe("garbage\n=1\nfido_installed\n")))
check("trailing whitespace and blank lines are tolerated",
  Fido.parseFidoProbe("  fido_installed=1 \r\n\n fido_registered=1\n\r\n fido_token=1\n rp=pam://h \n cred=QUJD|+presence|/dev/hidraw1 \n").ready === true,
  "")

// Readiness now also needs a usable credential on a plugged-in key.
const base = "fido_installed=1\nfido_registered=1\nfido_token=1\nrp=pam://host\n"
const withCred = Fido.parseFidoProbe(base + "cred=QUJD|+presence|/dev/hidraw2\n")
check("a credential on a plugged-in key is usable, and ready",
  withCred.ready === true && withCred.usable.length === 1 && withCred.usable[0].device === "/dev/hidraw2"
    && withCred.rp === "pam://host", JSON.stringify(withCred))
const absentKey = Fido.parseFidoProbe(base + "cred=QUJD|+presence|-\n")
check("a registered credential whose key is not plugged in is not usable",
  absentKey.ready === false && absentKey.usable.length === 0 && absentKey.credentials.length === 1,
  JSON.stringify(absentKey))
const pinCred = Fido.parseFidoProbe(base + "cred=QUJD|+presence+pin|/dev/hidraw2\n")
check("a registration that asks for the key's PIN is listed but never used",
  pinCred.ready === false && pinCred.pinOnly === true && pinCred.credentials[0].needsPin === true,
  JSON.stringify(pinCred))
check("so is one that asks for user verification",
  Fido.parseFidoProbe(base + "cred=QUJD|+verification|/dev/hidraw2\n").pinOnly === true, "")
check("a credential id that is not base64 is dropped",
  Fido.parseFidoProbe(base + "cred=a'b|+presence|/dev/hidraw2\n").credentials.length === 0, "")
check("a relying party that is not pam://<host> is not trusted",
  Fido.parseFidoProbe(base.replace("rp=pam://host", "rp=https://evil") + "cred=QUJD|+presence|/dev/x\n").ready === false,
  "")

// --- setup hand-off ---------------------------------------------------------
const setup = Fido.fidoSetupCommand()
check("setup hands off to Omarchy's own FIDO2 installer in a floating terminal",
  setup.slice(0, 5).join(" ") === "omarchy launch floating terminal with"
    && setup[5] === "presentation"
    && setup.slice(6).join(" ") === "omarchy setup security fido2",
  setup.join(" "))
const remove = Fido.fidoRemoveCommand()
check("removal hands off to Omarchy too, so the system's own prompts are unwired with it",
  remove.slice(6).join(" ") === "omarchy remove security fido2",
  remove.join(" "))

// --- the keyring entry, and the vault wiring --------------------------------


const Model = loadModule()

check("the FIDO entry is its own keyring account, not the fingerprint's",
  Model.KEYRING_FIDO === "fido_password",
  Model.KEYRING_FIDO)

const hasCmd = Model.keyringHasFidoPasswordCommand().join(" ")
check("the presence check reads the FIDO account and never the fingerprint's",
  hasCmd.includes("service 'qs-bitwarden-cli'") && hasCmd.includes("account 'fido_password'")
    && !hasCmd.includes("master_password"),
  hasCmd)

const clearCmd = Model.keyringClearFidoPasswordCommand().join(" ")
check("clearing reaches the FIDO account",
  clearCmd.includes("fido_password") && !clearCmd.includes("master_password"),
  clearCmd)

// Logging out has to take every credential the plugin holds, and the FIDO
// entry is one of them.
check("logging out sweeps the FIDO entry with the rest",
  Model.keyringClearAllCommand().join("\n").includes("fido_password"),
  "the logout sweep does not name account=fido_password")

const fidoRow = Model.SETTINGS_SCHEMA.find(e => e.key === "fidoUnlock")
check("the settings row opens the FIDO setup form",
  !!fidoRow && fidoRow.type === "bool" && fidoRow.group === "security" && fidoRow.action === "fido",
  JSON.stringify(fidoRow))
// Deliberately no `requires`: there is no dependency-probe key for FIDO2, and
// gating the row on one that does not exist would leave it permanently inert.
// The setup screen decides whether the machine can do FIDO2 at all.
check("the row is not gated on a dependency key that does not exist",
  !!fidoRow && fidoRow.requires === undefined,
  JSON.stringify(fidoRow && fidoRow.requires))

check("fidoUnlock defaults off and refuses a non-boolean from shell.json",
  Model.boolSetting("fidoUnlock", undefined) === false
    && Model.boolSetting("fidoUnlock", "false") === false
    && Model.boolSetting("fidoUnlock", true) === true,
  JSON.stringify([
    Model.boolSetting("fidoUnlock", undefined),
    Model.boolSetting("fidoUnlock", "false"),
    Model.boolSetting("fidoUnlock", true),
  ]))

const panelSrc = readPluginSource("Panel.qml")
check("the settings toggle opens the FIDO setup instead of flipping the flag",
  /modelData\.action === "fido"[\s\S]{0,200}beginFidoSetup\(\)/.test(panelSrc),
  "the ToggleSwitch handler has no fido case")
check("keyboard activation reaches the same FIDO actions",
  /e\.action === "fido"[\s\S]{0,200}beginFidoSetup\(\)/.test(panelSrc),
  "activateSettingRow has no fido case")
check("the toggle reflects a stored FIDO password, not just the setting",
  /case "fidoUnlock": return fidoUnlock && fidoStored/.test(panelSrc),
  "settingValue has no fido case")
const rawPanel = read("Panel.qml")
// Quick unlock is forgotten only by turning its setting off: no Forget
// button on the locked screen or anywhere else in the panel.
check("no Forget Fingerprint or Forget FIDO2 Key button anywhere in the panel",
  !/Forget Fingerprint|Forget FIDO2|ForgetFidoButton/.test(rawPanel), "a Forget button is back")
check("turning the settings off is what forgets them",
  /modelData\.action === "fingerprint"[\s\S]{0,120}if \(checked\) root\.vault\.forgetFingerprintUnlock\(\)/.test(rawPanel)
    && /modelData\.action === "fido"[\s\S]{0,120}if \(checked\) root\.vault\.forgetFidoUnlock\(\)/.test(rawPanel),
  "the settings toggles no longer forget")

// The locked screen and the SSH popup draw the same UnlockForm, so the button
// is declared once and both surfaces get it.
const rawUnlockForm = read("UnlockForm.qml")
check("the shared unlock form offers the key only when it can actually unlock",
  /visible: form\.fieldsOffered && form\.method === "fido"[\s\S]{0,700}onClicked: form\.vault\.startFidoUnlock\(\)/.test(rawUnlockForm)
    && /if \(name === "fido"\) return form\.vault\.fidoReady/.test(rawUnlockForm),
  "the unlock form has no FIDO button, or offers it without fidoReady")
check("both the panel and the SSH popup draw that form",
  /UnlockForm \{/.test(rawPanel)
    && /UnlockForm \{/.test(read("SshUnlockScreen.qml")),
  "a surface that draws its own unlock controls will drift from the other")
check("a plugged-in key leads, then the reader, then PIN, then the password",
  /var order = \["fido", "fingerprint", "pin", "password"\]/.test(rawUnlockForm)
    && /methodAvailable\("fido"\) \? "fido"/.test(rawUnlockForm),
  "the key the user is holding should not sit behind another method")
const rawFidoUnlock = read("FidoUnlock.qml")
const rawService = read("Service.qml")
check("readiness is probed on startup, not only when the setting changes",
  /Component\.onCompleted: if \(armed\) refresh\(\)/.test(rawFidoUnlock),
  "a setting already true at build time fires no onArmedChanged, so nothing would probe")
check("arming re-probes when the key is not known to be ready",
  /function armPresenceUnlock\(\)[\s\S]{0,500}?if \(fidoUnlock\) fidoUnlocker\.refresh\(\)/.test(rawService),
  "a key plugged in since the last probe must not be missed by the lock screen")
check("a verified key says the vault is unlocking rather than asking again",
  /message = "[^"]*Key verified"/.test(rawFidoUnlock)
    && !/message = "[^"]*Key verified, unlocking/.test(rawFidoUnlock)
    && /readonly property bool fidoAuthorized: fidoUnlocker\.authorized/.test(rawService),
  "the button has to cover the gap between the touch and the unlock")
// A key holds an abandoned request until its own presence timeout, so opening
// the panel again inside that window meets a device that is simply busy.
check("a failure too fast to be an answer is retried, not reported",
  /function deviceStillBusy\(\)[\s\S]{0,400}?busyRetries < busyRetryLimit[\s\S]{0,200}?startedAtMs\) < busyFailureMs[\s\S]{0,200}?abandonedAtMs\) < busyWindowMs/.test(rawFidoUnlock)
    && /exitCode === codes\.assert \|\| exitCode === codes\.noSecret\) \{\s*if \(deviceStillBusy\(\)\) \{\s*retryAfterBusy\(\)/.test(rawFidoUnlock),
  "a busy key fails fast with FIDO_ERR_UNSUPPORTED_OPTION, which is not what happened")
check("only an abandoned request starts that window",
  /function cancelUnlock\(\)[\s\S]{0,300}?if \(assertProc\.running\) \{\s*abandonedAtMs = Date\.now\(\)/.test(rawFidoUnlock),
  "a request that ended on its own leaves the key free")
check("the retry stops when the screen that wanted it is gone",
  /id: busyRetryTimer[\s\S]{0,500}?status !== "locked"[\s\S]{0,120}?sshAuthSurfaceActive[\s\S]{0,120}?busyRetries = 0/.test(rawFidoUnlock),
  "a closed panel must not keep re-arming the key")
check("a successful touch clears the busy state",
  /exitCode === codes\.legacyUsed\) \{\s*busyRetries = 0\s*abandonedAtMs = 0/.test(rawFidoUnlock),
  "the next lock must start from a clean count")
check("locking with the panel open arms whichever gate is about to be offered",
  /function lockVault\(\)[\s\S]{0,1200}?if \(sshAuthSurfaceActive\) armPresenceUnlock\(\)/.test(rawService)
    && !/function lockVault\(\)[\s\S]{0,1200}?if \(sshAuthSurfaceActive\) startFingerprintUnlock\(\)/.test(rawService),
  "arming the reader with a key plugged in sends the touch to the focused field")
check("the form arms the method it offers, so no caller has to remember to",
  /function armOfferedMethod\(\)[\s\S]{0,400}?startFidoUnlock\(\)[\s\S]{0,120}?startFingerprintUnlock\(\)/
    .test(read("UnlockForm.qml")),
  "a presence method on screen with nothing waiting behind it is the bug this prevents")
check("only one presence gate is ever armed",
  /function startFidoUnlock\(\)[\s\S]{0,300}?cancelFingerprintUnlock\(\)/.test(rawService)
    && /function startFingerprintUnlock\(\)[\s\S]{0,500}?fidoUnlocker\.releaseSurface\(\)/.test(rawService),
  "two armed gates mean two devices waiting, and the second touch answers nothing")
check("a method that stops being offered takes its device with it",
  /onMethodChanged:[\s\S]{0,300}?releaseFidoUnlock\(\)[\s\S]{0,120}?cancelFingerprintUnlock\(\)/
    .test(read("UnlockForm.qml")),
  "an unplugged key or a shut lid must not leave a reader waiting behind the next screen")
check("stepping back from the key keeps its request but drops the touch",
  /function releaseSurface\(\)[\s\S]{0,700}?scanning = false[\s\S]{0,120}?authorized = false/.test(rawFidoUnlock)
    && /onOpenedChanged[\s\S]{0,400}?fidoUnlocker\.releaseSurface\(\)/.test(rawService)
    && !/onOpenedChanged[\s\S]{0,400}?cancelFidoUnlock\(\)/.test(rawService),
  "aborting buys nothing -- the key holds the request either way -- and loses the touch")
check("a returning screen adopts the request rather than asking twice",
  /function startUnlock\(\)[\s\S]{0,500}?if \(assertProc\.running\) \{[\s\S]{0,200}?scanning = true/.test(rawFidoUnlock),
  "a second request to a key already holding one is refused by the device")
check("the setup screen hands off to Omarchy when no key is registered",
  /vault\.runFidoSetup\(\)/.test(read("FidoSetupScreen.qml")),
  "FidoSetupScreen has no Omarchy hand-off")

// --- the password the touch produces -----------------------------------------
//
//
// The assert collector holds the password on success: taken, then scrubbed,
// and on the lock-time scrub list.
const controllerSrc = rawFidoUnlock
check("the assert process's collector is scrubbed on lock, like every other secret read",
  /function secretProcesses\(\)\s*\{\s*return \[assertProc\]/.test(controllerSrc),
  "assertProc must be scrubbed, or the master password would outlive the lock in its buffer")
check("and after every answer",
  /var out = String\(assertStdout\.text \|\| ""\)\s*\n\s*if \(vault\) vault\.clearProcessCollectorSoon\(assertProc\)/
    .test(controllerSrc), "")
check("its command is set fresh before every run, never left to the scrub's leftover",
  /assertProc\.command = target\.mode === "envelope"[\s\S]{0,200}?assertProc\.running = true/.test(controllerSrc)
    && !/if \(!assertProc\.running\) assertProc\.running = true/.test(controllerSrc), "")
check("which key holds the credential is asked again before each touch",
  /startAfterProbe = true\s*\n\s*if \(!probeProc\.running\) probeProc\.running = true/.test(controllerSrc)
    && /if \(startAfterProbe\) \{\s*startAfterProbe = false\s*if \(scanning\) launchAssert\(\)/.test(controllerSrc),
  "a replugged key lands on another hidraw node")
check("a credential with a wrap is preferred; the plaintext entry only migrates",
  /mode: "envelope"[\s\S]{0,400}?if \(legacyStored && usable\.length > 0 && probe\.rp\)[\s\S]{0,100}?mode: "legacy"/
    .test(controllerSrc), "")
check("a migrating touch drops the plaintext entry once the envelope has it",
  /var migrated = exitCode === 0 && mode === "legacy"\s*if \(migrated\) \{[\s\S]{0,250}?legacyStored = false/.test(controllerSrc), "")
check("a PIN-requiring registration gets a reason, not a failed touch",
  /if \(probe\.pinOnly\)[\s\S]{0,200}?asks for its PIN/.test(controllerSrc), "")
check("setup is a master-password check and one touch, through the vault's shared path",
  /vault\.addQuickUnlockMethodWith\(typed, function\(tool, account\) \{\s*return Model\.fidoEnrollCommand\(tool, account, target\)/
    .test(controllerSrc)
    && /var typed = setupMaster\s*\n\s*setupMaster = ""/.test(controllerSrc), "")
check("a wrap whose setup was abandoned, locked or logged out mid-write is removed",
  /vault\.epochOperationIsStale\("fidoAdd"\) \|\| !setupActive\)[\s\S]{0,200}?removeQuickUnlockMethod\(\{ kind: "remove", method: "fido", cred: target\.cred \}\)/
    .test(controllerSrc)
    && /if \(busy && vault\) vault\.invalidateEpochOperation\("fidoAdd"\)/.test(controllerSrc), "")
check("forgetting removes every FIDO wrap as well as the plaintext entry",
  /function forget\([\s\S]{0,300}?removeQuickUnlockMethod\(\{ kind: "remove", method: "fido", cred: creds\[i\]\.cred \}\)[\s\S]{0,200}?requestClear\(\)/
    .test(controllerSrc), "")
check("the old store and lookup processes are gone",
  !/id: storeProc|id: lookupProc|keyringStoreFidoPasswordCommand|keyringLookupFidoPasswordCommand/.test(controllerSrc), "")

// --- the key's request is torn down with the fingerprint's -----------------
//
//
// A key answers one request at a time, so wherever the vault drops a pending
// fingerprint attempt it must drop the FIDO2 one too.
const serviceSrc = read("Service.qml")
const cancelSites = [
  ["the panel closing", /function close\(\)[\s\S]*?cancelFingerprintUnlock\(\)\s*cancelFidoUnlock\(\)/],
  ["the panel closing from onOpenedChanged", /onOpenedChanged:[\s\S]*?cancelFingerprintUnlock\(\)\s*cancelFidoUnlock\(\)/],
  ["the SSH popup unloading", /function clearSshPopupUnlockState\(\)[\s\S]*?cancelFingerprintUnlock\(\)\s*cancelFidoUnlock\(\)/],
  ["a password unlock taking over", /function unlockVaultWithPassword\([\s\S]*?cancelFingerprintUnlock\(\)\s*cancelFidoUnlock\(\)/],
  ["dropping the vault state on lock", /function dropVaultState\(\)[\s\S]*?cancelFingerprintUnlock\(\)\s*cancelFidoUnlock\(\)/],
]
for (const [where, re] of cancelSites) {
  check(`the FIDO2 attempt is cancelled when ${where}`,
    re.test(serviceSrc),
    "a conversation left waiting holds the authenticator and breaks the next one")
}
check("logging out drops the FIDO2 attempt too",
  /function forgetStoredCredentials\(\)[\s\S]*?fidoUnlocker\.reset\(\)/.test(serviceSrc),
  "reset() cancels a live conversation and clears the state")

done()
