#!/usr/bin/env node
// Tests for the FIDO2 unlock helpers: the plugin-local PAM stack, the readiness
// probe, and the Omarchy setup hand-off.
//
// The property under test that matters most is that the shipped PAM stack can
// actually be loaded by Quickshell from inside the plugin directory -- i.e. it
// carries a single `auth` rule for pam_u2f against Omarchy's global authfile,
// and no `include`/`account` line that could only resolve under /etc/pam.d.
//
//   node tests/fido-unlock.test.js

const fs = require("fs")
const path = require("path")

const Fido = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "FidoModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.fidoPamConfigName = fidoPamConfigName
  exports.fidoPamDirectory = fidoPamDirectory
  exports.fidoAuthfile = fidoAuthfile
  exports.fidoSetupCommand = fidoSetupCommand
  exports.fidoRemoveCommand = fidoRemoveCommand
  exports.fidoProbeCommand = fidoProbeCommand
  exports.parseFidoProbe = parseFidoProbe
  exports.FIDO_PAM_DIR = FIDO_PAM_DIR
  exports.FIDO_PAM_CONFIG = FIDO_PAM_CONFIG
  exports.FIDO_AUTHFILE = FIDO_AUTHFILE
  exports.FIDO_MAX_PROBE_BYTES = FIDO_MAX_PROBE_BYTES
`)(Fido)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

// --- the PAM stack ----------------------------------------------------------
const pamDir = path.join(__dirname, "..", Fido.FIDO_PAM_DIR)
const pamPath = path.join(pamDir, Fido.FIDO_PAM_CONFIG)
check("the PAM directory is plugin-relative, not absolute",
  typeof Fido.FIDO_PAM_DIR === "string" && Fido.FIDO_PAM_DIR.charAt(0) !== "/"
    && Fido.FIDO_PAM_DIR.indexOf("..") === -1,
  Fido.FIDO_PAM_DIR)
check("the stack file exists where Quickshell will look for it",
  fs.existsSync(pamPath) && fs.statSync(pamPath).isFile(),
  pamPath)

const pamText = fs.existsSync(pamPath) ? fs.readFileSync(pamPath, "utf8") : ""
const pamRules = pamText.split("\n")
  .map(line => line.replace(/#.*$/, "").trim())
  .filter(line => line !== "")

check("the stack is a single auth rule",
  pamRules.length === 1 && /^auth\s+/.test(pamRules[0]),
  JSON.stringify(pamRules))
check("PamContext only reads auth, so no account/session/password rule is shipped",
  !pamRules.some(r => /^(account|session|password)\s/.test(r)),
  JSON.stringify(pamRules))
// An `include` in this stack would be resolved inside the plugin directory by
// pam_start_confdir, where system-local-login does not exist -- so it must not
// appear at all.
check("no include rule that could only resolve under /etc/pam.d",
  !pamRules.some(r => /\binclude\b/.test(r)),
  JSON.stringify(pamRules))
check("the rule names pam_u2f with a required control flag",
  /\bauth\s+required\s+pam_u2f\.so\b/.test(pamRules[0] || ""),
  pamRules[0])
check("the rule reads Omarchy's global authfile",
  (pamRules[0] || "").includes("authfile=" + Fido.FIDO_AUTHFILE),
  pamRules[0])
check("the rule asks pam-u2f to cue the touch prompt",
  /\bcue\b/.test(pamRules[0] || ""),
  pamRules[0])
// The relying party must stay pam-u2f's default, because that is what Omarchy's
// single registration was created for; pinning it here would break sudo's too.
check("the rule pins no origin/appid",
  !/\borigin=|\bappid=/.test(pamRules[0] || ""),
  pamRules[0])

// --- the probe --------------------------------------------------------------
const probe = Fido.fidoProbeCommand()
check("the probe is one shell invocation",
  Array.isArray(probe) && probe[0] === "bash" && probe[1] === "-c" && probe.length === 3,
  JSON.stringify(probe && probe.slice(0, 2)))
const probeScript = probe[2] || ""
check("the probe caps its own output",
  probeScript.includes("head -c " + Fido.FIDO_MAX_PROBE_BYTES),
  probeScript)
check("the probe checks for the pam-u2f tools",
  probeScript.includes("command -v pamu2fcfg") && probeScript.includes("command -v fido2-token"),
  probeScript)
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
check("installed + registered + present is ready",
  all.ready === true && all.applicable === true,
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
  Fido.parseFidoProbe("  fido_installed=1 \r\n\n fido_registered=1\n\r\n fido_token=1\n").ready === true,
  JSON.stringify(Fido.parseFidoProbe("  fido_installed=1 \r\n\n fido_registered=1\n\r\n fido_token=1\n")))

// --- setup hand-off ---------------------------------------------------------
const setup = Fido.fidoSetupCommand()
check("setup hands off to Omarchy's own FIDO2 installer in a floating terminal",
  setup.slice(0, 5).join(" ") === "omarchy launch floating terminal with"
    && setup[5] === "presentation"
    && setup.slice(6).join(" ") === "omarchy setup security fido2",
  setup.join(" "))
const remove = Fido.fidoRemoveCommand()
check("removal hands off to Omarchy too, so sudo and polkit are unwired with it",
  remove.slice(6).join(" ") === "omarchy remove security fido2",
  remove.join(" "))

// --- naming -----------------------------------------------------------------
check("the configured name is the file that is actually shipped",
  Fido.fidoPamConfigName() === Fido.FIDO_PAM_CONFIG
    && fs.existsSync(path.join(pamDir, Fido.fidoPamConfigName())),
  Fido.fidoPamConfigName())

// --- the keyring entry, and the vault wiring --------------------------------

const { readPluginSource } = require("./plugin-source")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.keyringStoreFidoPasswordCommand = keyringStoreFidoPasswordCommand
  exports.keyringLookupFidoPasswordCommand = keyringLookupFidoPasswordCommand
  exports.keyringClearFidoPasswordCommand = keyringClearFidoPasswordCommand
  exports.keyringHasFidoPasswordCommand = keyringHasFidoPasswordCommand
  exports.keyringClearAllCommand = keyringClearAllCommand
  exports.SETTINGS_SCHEMA = SETTINGS_SCHEMA
  exports.boolSetting = boolSetting
  exports.KEYRING_FIDO = KEYRING_FIDO
`)(Model)

check("the FIDO entry is its own keyring account, not the fingerprint's",
  Model.KEYRING_FIDO === "fido_password",
  Model.KEYRING_FIDO)

const hasCmd = Model.keyringHasFidoPasswordCommand().join(" ")
check("the presence check reads the FIDO account and never the fingerprint's",
  hasCmd.includes("service 'qs-bitwarden-cli'") && hasCmd.includes("account 'fido_password'")
    && !hasCmd.includes("master_password"),
  hasCmd)

const lookupCmd = Model.keyringLookupFidoPasswordCommand().join(" ")
check("the retrieval reads the FIDO account",
  lookupCmd.includes("account 'fido_password'") && !lookupCmd.includes("master_password"),
  lookupCmd)

const clearCmd = Model.keyringClearFidoPasswordCommand().join(" ")
check("clearing reaches the FIDO account",
  clearCmd.includes("fido_password") && !clearCmd.includes("master_password"),
  clearCmd)

const storeCmd = Model.keyringStoreFidoPasswordCommand()
check("the store takes the password from the environment, never argv",
  storeCmd[2].includes("QSBW_SECRET") && storeCmd[2].includes("account 'fido_password'")
    && storeCmd[2].includes("FIDO2 unlock") && !storeCmd[2].includes("master_password"),
  storeCmd[2])

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
const rawPanel = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
check("the locked screen's Forget FIDO2 Key is declared once and placed twice",
  (rawPanel.match(/ForgetFidoButton \{/g) || []).length === 2
    && /component ForgetFidoButton: Button \{[\s\S]{0,300}Forget FIDO2 Key[\s\S]{0,220}onClicked: root\.vault\.forgetFidoUnlock\(\)/
      .test(rawPanel),
  "both slots must share one declaration")
check("with a Forget Fingerprint beside it, it takes its own centred line",
  /anchors\.horizontalCenter: parent\.horizontalCenter\s*spacing: Style\.space\(8\)\s*ForgetFidoButton \{\s*visible: root\.vault\.fidoStored && root\.vault\.fingerprintStored/
    .test(rawPanel),
  "the three must read as one centred block")
check("without one, it takes the empty slot inline instead",
  /ForgetFidoButton \{\s*visible: root\.vault\.fidoStored && !root\.vault\.fingerprintStored/.test(rawPanel),
  "a machine with no fingerprint configured must not strand the button on its own line")

// The locked screen and the SSH popup draw the same UnlockForm, so the button
// is declared once and both surfaces get it.
const rawUnlockForm = fs.readFileSync(path.join(__dirname, "..", "UnlockForm.qml"), "utf8")
check("the shared unlock form offers the key only when it can actually unlock",
  /visible: form\.fieldsOffered && form\.method === "fido"[\s\S]{0,700}onClicked: form\.vault\.startFidoUnlock\(\)/.test(rawUnlockForm)
    && /if \(name === "fido"\) return form\.vault\.fidoReady/.test(rawUnlockForm),
  "the unlock form has no FIDO button, or offers it without fidoReady")
check("both the panel and the SSH popup draw that form",
  /UnlockForm \{/.test(rawPanel)
    && /UnlockForm \{/.test(fs.readFileSync(path.join(__dirname, "..", "SshUnlockScreen.qml"), "utf8")),
  "a surface that draws its own unlock controls will drift from the other")
check("a plugged-in key leads, then the reader, then PIN, then the password",
  /var order = \["fido", "fingerprint", "pin", "password"\]/.test(rawUnlockForm)
    && /methodAvailable\("fido"\) \? "fido"/.test(rawUnlockForm),
  "the key the user is holding should not sit behind another method")
const rawFidoUnlock = fs.readFileSync(path.join(__dirname, "..", "FidoUnlock.qml"), "utf8")
const rawService = fs.readFileSync(path.join(__dirname, "..", "Service.qml"), "utf8")
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
    && /if \(result !== PamResult\.Success && deviceStillBusy\(\)\)[\s\S]{0,80}?retryAfterBusy\(\)/.test(rawFidoUnlock),
  "pam_u2f reports a busy key as 'not recognised', which is not what happened")
check("only an abandoned conversation starts that window",
  /function cancelUnlock\(\)[\s\S]{0,300}?if \(pam\.active\) abandonedAtMs = Date\.now\(\)/.test(rawFidoUnlock),
  "a conversation that ended on its own leaves the key free")
check("the retry stops when the screen that wanted it is gone",
  /id: busyRetryTimer[\s\S]{0,500}?status !== "locked"[\s\S]{0,120}?sshAuthSurfaceActive[\s\S]{0,120}?busyRetries = 0/.test(rawFidoUnlock),
  "a closed panel must not keep re-arming the key")
check("a verified touch clears the busy state",
  /busyRetries = 0[\s\S]{0,80}?abandonedAtMs = 0[\s\S]{0,80}?authorized = true/.test(rawFidoUnlock),
  "the next lock must start from a clean count")
check("locking with the panel open arms whichever gate is about to be offered",
  /function lockVault\(\)[\s\S]{0,1200}?if \(sshAuthSurfaceActive\) armPresenceUnlock\(\)/.test(rawService)
    && !/function lockVault\(\)[\s\S]{0,1200}?if \(sshAuthSurfaceActive\) startFingerprintUnlock\(\)/.test(rawService),
  "arming the reader with a key plugged in sends the touch to the focused field")
check("the form arms the method it offers, so no caller has to remember to",
  /function armOfferedMethod\(\)[\s\S]{0,400}?startFidoUnlock\(\)[\s\S]{0,120}?startFingerprintUnlock\(\)/
    .test(fs.readFileSync(path.join(__dirname, "..", "UnlockForm.qml"), "utf8")),
  "a presence method on screen with nothing waiting behind it is the bug this prevents")
check("only one presence gate is ever armed",
  /function startFidoUnlock\(\)[\s\S]{0,300}?cancelFingerprintUnlock\(\)/.test(rawService)
    && /function startFingerprintUnlock\(\)[\s\S]{0,500}?fidoUnlocker\.releaseSurface\(\)/.test(rawService),
  "two armed gates mean two devices waiting, and the second touch answers nothing")
check("a method that stops being offered takes its device with it",
  /onMethodChanged:[\s\S]{0,300}?releaseFidoUnlock\(\)[\s\S]{0,120}?cancelFingerprintUnlock\(\)/
    .test(fs.readFileSync(path.join(__dirname, "..", "UnlockForm.qml"), "utf8")),
  "an unplugged key or a shut lid must not leave a reader waiting behind the next screen")
check("stepping back from the key keeps its conversation but drops the touch",
  /function releaseSurface\(\)[\s\S]{0,700}?scanning = false[\s\S]{0,120}?authorized = false/.test(rawFidoUnlock)
    && /onOpenedChanged[\s\S]{0,400}?fidoUnlocker\.releaseSurface\(\)/.test(rawService)
    && !/onOpenedChanged[\s\S]{0,400}?cancelFidoUnlock\(\)/.test(rawService),
  "aborting buys nothing -- the key holds the request either way -- and loses the touch")
check("a returning screen adopts the conversation rather than asking twice",
  /function startUnlock\(\)[\s\S]{0,500}?if \(pam\.active\) \{[\s\S]{0,200}?scanning = true/.test(rawFidoUnlock),
  "a second request to a key already holding one is refused by the device")
check("the setup screen hands off to Omarchy when no key is registered",
  /vault\.runFidoSetup\(\)/.test(fs.readFileSync(path.join(__dirname, "..", "FidoSetupScreen.qml"), "utf8")),
  "FidoSetupScreen has no Omarchy hand-off")

// --- the lock-time scrub, and re-arming after it ------------------------------
//
// Locking the vault empties every collector that could hold a secret by running
// that process once with an empty command, and the replacement stays in place.
// A read that is not re-armed before its next run therefore prints nothing --
// which is exactly how FIDO2 unlock came to sit on "Key verified, unlocking..."
// forever while the keyring was never read. The fingerprint path re-arms its
// own lookup for the same reason; this pins that FIDO2 does too.
const controllerSrc = fs.readFileSync(path.join(__dirname, "..", "FidoUnlock.qml"), "utf8")
check("the FIDO lookup's collector is scrubbed on lock, like every other secret read",
  /function secretProcesses\(\)\s*\{\s*return \[lookupProc\]/.test(controllerSrc),
  "lookupProc must be scrubbed, or the master password would outlive the lock in its buffer")
check("and the command is re-armed before the lookup is run again",
  /lookupProc\.command = Model\.keyringLookupFidoPasswordCommand\(\)[\s\S]{0,140}lookupProc\.running = true/
    .test(controllerSrc),
  "onResult must restore the lookup command before re-running it; the scrub left it empty")
check("no lookup run is left depending on the scrub's leftover command",
  !/if \(!lookupProc\.running\) lookupProc\.running = true/.test(controllerSrc),
  "a bare `running = true` re-runs the empty scrub command and reads nothing")

// --- the PAM conversation is torn down with the fingerprint's -----------------
//
// A FIDO2 authenticator answers one conversation at a time, so a conversation
// left waiting for a touch from a closed panel makes the next one fail -- and
// the panel says so, with "Key not recognised". Every place the vault drops a
// pending fingerprint attempt has to drop the FIDO2 one beside it.
const serviceSrc = fs.readFileSync(path.join(__dirname, "..", "Service.qml"), "utf8")
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

if (failures.length) {
  console.error(`FAIL ${failures.length}\n`)
  for (const f of failures) console.error(`  x ${f}\n`)
  process.exit(1)
}
console.log(`ok ${pass}`)
