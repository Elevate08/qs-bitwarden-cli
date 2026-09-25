#!/usr/bin/env node
// The setup dependency probe and the settings writer, including cases a fully
// set-up machine cannot exercise (missing tools, fprintd without a finger).
//
//   node tests/setup-settings.test.js

const { createSuite, functionBody, loadModule, read, readPluginSource } = require("./harness")
const { legacyKeyring } = require("./legacy-keyring")
const path = require("path")
const panelSrc = readPluginSource("Panel.qml")

const Model = loadModule()

const { check, done } = createSuite("setup-settings")
const byKey = (deps, k) => deps.items.find(d => d.key === k)
const dependencyProbe = Model.dependencyCheckCommand()[2]
const sshCliSupport = Model.sshCliSupport

// KeyboardPanel applies focusTarget after the panel's own open handler. Keep
// that final open-time choice aligned with the locked screen's PIN-first UI.
check("a locked panel focuses whichever field the offered unlock method uses",
  /focusTarget:[\s\S]{0,800}unlockForm\.focusField\s*\?\s*unlockForm\.focusField\s*:\s*keyCatcher/.test(panelSrc),
  "focusTarget must follow UnlockForm.focusField, which is the PIN field when PIN unlock leads")

// --- everything present -----------------------------------------------------
const all = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("all present: nothing required is missing",
  Model.missingRequired(all).length === 0,
  `got [${Model.missingRequired(all).map(d => d.key)}]`)
check("all present: fprintd reported ready", byKey(all, "fprintd").ready === true, "expected ready")
check("jq is a required dependency alongside bw",
  byKey(all, "jq") && byKey(all, "jq").required === true && byKey(all, "jq").pkg === "jq",
  JSON.stringify(byKey(all, "jq")))
check("the dependency probe checks for jq before vault reads",
  dependencyProbe.includes("command -v jq"),
  dependencyProbe)
check("the dependency probe captures the bw CLI version for SSH gating",
  /bw\s+--version|bw\s+-v/.test(dependencyProbe),
  dependencyProbe)
check("SSH_CLI_MIN_VERSION is the verified floor",
  Model.SSH_CLI_MIN_VERSION === "2025.1.2",
  String(Model.SSH_CLI_MIN_VERSION))
check("sshCliSupport marks 2025.1.2 as supported",
  sshCliSupport("2025.1.2") === "supported",
  JSON.stringify(sshCliSupport("2025.1.2")))
check("sshCliSupport marks 2025.1.1 as unsupported",
  sshCliSupport("2025.1.1") === "unsupported",
  JSON.stringify(sshCliSupport("2025.1.1")))
check("sshCliSupport treats malformed versions as unknown",
  sshCliSupport("development-build") === "unknown",
  JSON.stringify(sshCliSupport("development-build")))
check("sshCliSupport treats a missing version as unknown",
  sshCliSupport("") === "unknown",
  JSON.stringify(sshCliSupport("")))
check("SSH surfaces stay hidden until the probe confirms a supported CLI",
  Model.sshUiAvailable(all, true) === true
    && Model.sshUiAvailable(all, false) === false,
  JSON.stringify({ checked: Model.sshUiAvailable(all, true), unchecked: Model.sshUiAvailable(all, false) }))
const oldCli = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.1\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("an unsupported CLI hides SSH but still reports why on the bw row",
  Model.sshUiAvailable(oldCli, true) === false
    && byKey(oldCli, "bw").note.includes("2025.1.2")
    && byKey(oldCli, "bw").note.includes("2025.1.1"),
  JSON.stringify(byKey(oldCli, "bw")))
const unreadableCli = Model.parseDependencies(
  "bw=1\nbw_version=development-build\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("an unreadable CLI version hides SSH rather than assuming support",
  Model.sshUiAvailable(unreadableCli, true) === false
    && unreadableCli.sshCliStatus === "unknown"
    && byKey(unreadableCli, "bw").note !== "",
  JSON.stringify({ status: unreadableCli.sshCliStatus, bw: byKey(unreadableCli, "bw") }))

check("bw version metadata is preserved for feature gating",
  byKey(all, "bw") && byKey(all, "bw").version === "2025.1.2" && all.sshCliStatus === "supported",
  JSON.stringify({ bw: byKey(all, "bw"), sshCliStatus: all.sshCliStatus }))

// --- the case that matters: a required tool is absent -----------------------
const noBw = Model.parseDependencies(
  "bw=0\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
const missing = Model.missingRequired(noBw)
check("missing bw is reported as required",
  missing.length === 1 && missing[0].key === "bw" && missing[0].pkg === "bitwarden-cli",
  `got [${missing.map(d => d.key + ":" + d.pkg)}]`)
check("missing bw is not marked installed", byKey(noBw, "bw").installed === false, "expected false")
const noJq = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=0\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
const missingNoJq = Model.missingRequired(noJq)
check("missing jq is reported as required",
  missingNoJq.length === 1 && missingNoJq[0].key === "jq" && missingNoJq[0].pkg === "jq",
  `got [${missingNoJq.map(d => d.key + ":" + d.pkg)}]`)
check("missing jq does not alter optional dependency semantics",
  byKey(noJq, "fprintd").required === false,
  JSON.stringify(byKey(noJq, "fprintd")))
check("supported bw without jq blocks the vault list until setup finishes",
  Model.vaultListMode(noJq) === "blocked"
    && Model.vaultListBlockedMessage(noJq).includes("jq"),
  `${Model.vaultListMode(noJq)} / ${Model.vaultListBlockedMessage(noJq)}`)

// On a CLI older than the malformed-SSH-item fix, a failed read names the fix;
// attribution comes from the probed version, never the read's output.
const rawCliFailure = "TypeError: Cannot read properties of null (reading 'keyFingerprint') for item work-ssh"
check("a list failure on a pre-2026.8.0 CLI names the release that fixes it",
  Model.vaultListFailureMessage(rawCliFailure, all, "sanitized").includes("2026.8.0"),
  Model.vaultListFailureMessage(rawCliFailure, all, "sanitized"))
check("the failure message never echoes raw CLI output",
  !Model.vaultListFailureMessage(rawCliFailure, all, "sanitized").includes("keyFingerprint")
    && !Model.vaultListFailureMessage(rawCliFailure, all, "sanitized").includes("TypeError")
    && !Model.vaultListFailureMessage(rawCliFailure, all, "sanitized").includes("work-ssh"),
  Model.vaultListFailureMessage(rawCliFailure, all, "sanitized"))
const fixedCli = Model.parseDependencies(
  "bw=1\nbw_version=2026.8.0\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("a list failure on a fixed CLI does not blame the SSH-item bug",
  !Model.vaultListFailureMessage(rawCliFailure, fixedCli, "sanitized").includes("2026.8.0"),
  Model.vaultListFailureMessage(rawCliFailure, fixedCli, "sanitized"))
check("a blocked list reports the missing tool instead of the SSH hint",
  Model.vaultListFailureMessage(rawCliFailure, noJq, "blocked").includes("jq")
    && !Model.vaultListFailureMessage(rawCliFailure, noJq, "blocked").includes("2026.8.0"),
  Model.vaultListFailureMessage(rawCliFailure, noJq, "blocked"))

// An optional tool going missing must not trigger the blocking wizard.
const noFprintd = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=0\nfingerprint_ready=0\nomarchy=1")
check("missing optional tool does not block setup",
  Model.missingRequired(noFprintd).length === 0,
  `got [${Model.missingRequired(noFprintd).map(d => d.key)}]`)

// --- fprintd installed but no finger enrolled -------------------------------
const noFinger = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=0\nomarchy=1")
check("fprintd on PATH without an enrolled finger is installed-but-not-ready",
  byKey(noFinger, "fprintd").installed === true && byKey(noFinger, "fprintd").ready === false,
  `installed=${byKey(noFinger, "fprintd").installed} ready=${byKey(noFinger, "fprintd").ready}`)

const oldBw = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.1\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("older bw versions remain installed but are marked unsupported for SSH",
  byKey(oldBw, "bw").installed === true
    && byKey(oldBw, "bw").version === "2025.1.1"
    && oldBw.sshCliStatus === "unsupported"
    && byKey(oldBw, "bw").note.includes(Model.SSH_CLI_MIN_VERSION),
  JSON.stringify({ bw: byKey(oldBw, "bw"), sshCliStatus: oldBw.sshCliStatus }))
check("older bw with jq still uses the sanitized list path for ordinary items",
  Model.vaultListMode(oldBw) === "sanitized",
  JSON.stringify({ mode: Model.vaultListMode(oldBw), deps: oldBw }))

const unknownBw = Model.parseDependencies(
  "bw=1\nbw_version=development-build\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("unknown bw versions are reported separately from unsupported ones",
  byKey(unknownBw, "bw").installed === true
    && byKey(unknownBw, "bw").version === ""
    && unknownBw.sshCliStatus === "unknown",
  JSON.stringify({ bw: byKey(unknownBw, "bw"), sshCliStatus: unknownBw.sshCliStatus }))
check("unknown bw with jq still uses the sanitized list path and never falls back to a raw legacy read",
  Model.vaultListMode(unknownBw) === "sanitized",
  JSON.stringify({ mode: Model.vaultListMode(unknownBw), deps: unknownBw }))

// --- malformed / empty probe output -----------------------------------------
for (const [label, raw] of [["empty", ""], ["garbage", "???\n=\nbw\n"]]) {
  const d = Model.parseDependencies(raw)
  check(`${label} probe output degrades to all-missing`,
    d.items.length === Model.DEPENDENCIES.length && d.items.every(i => !i.installed),
    `got ${d.items.length} items, installed=[${d.items.filter(i => i.installed).map(i => i.key)}]`)
}

// --- settings writer --------------------------------------------------------
// Values must reach shell.json as real JSON types; the writer runs via bash
// (to cap stderr), so the script is checked.
const writeScript = (k, v, t) => Model.settingWriteCommand(k, v, t)[2]

// --- colorized menu-bar icon setting ----------------------------------------
const colorizeIcon = Model.SETTINGS_SCHEMA.find(e => e.key === "colorizeIcon")
check("colorized icon setting is declared in General", !!colorizeIcon
  && colorizeIcon.group === "general"
  && colorizeIcon.type === "bool",
  JSON.stringify(colorizeIcon))
check("colorized icon defaults off", !!colorizeIcon && colorizeIcon.defaultValue === false,
  JSON.stringify(colorizeIcon))
check("colorized icon accepts only actual booleans",
  Model.boolSetting("colorizeIcon", true) === true
    && Model.boolSetting("colorizeIcon", false) === false
    && Model.boolSetting("colorizeIcon", "true") === false
    && Model.boolSetting("colorizeIcon", 1) === false,
  "malformed colorizeIcon input was accepted")

check("boolean settings accept actual JSON booleans",
  Model.boolSetting("fingerprintUnlock", true) === true
    && Model.boolSetting("fingerprintUnlock", false) === false,
  "actual booleans were not preserved")
check("malformed strings cannot enable opt-in credential storage",
  Model.boolSetting("fingerprintUnlock", "false") === false
    && Model.boolSetting("pinUnlock", "true") === false,
  "a string enabled an opt-in unlock method")
check("malformed lock settings fail back to their secure defaults",
  Model.boolSetting("lockOnScreenLock", "false") === true
    && Model.boolSetting("lockOnSuspend", 0) === true,
  "a malformed setting disabled locking")

check("int setting is written with --json",
  writeScript("autoLockMinutes", 15, "int")
    .includes("omarchy bar set io.github.elevate08.qs-bitwarden-cli 'autoLockMinutes' '15' --json"),
  writeScript("autoLockMinutes", 15, "int"))

for (const [v, want] of [[true, "true"], [false, "false"]]) {
  const script = writeScript("closeOnCopy", v, "bool")
  check(`bool ${v} is written as ${want}`,
    script.includes(`'closeOnCopy' '${want}' --json`), `got ${script}`)
}
check("a zero int is written as 0, not dropped",
  writeScript("autoLockMinutes", 0, "int").includes("'autoLockMinutes' '0' --json"),
  writeScript("autoLockMinutes", 0, "int"))

// stderr from `omarchy bar set` is collected by the panel, so it needs the same
// producer-side cap as every other stream the long-lived shell buffers.
check("setting writer caps its diagnostic stderr",
  writeScript("autoLockMinutes", 15, "int").includes("exec 2> >(head -c 8192 >&2)"),
  writeScript("autoLockMinutes", 15, "int"))

// Every schema key must exist in the manifest, or the settings screen would
// write a key the plugin never reads.
const manifest = JSON.parse(read("manifest.json"))
const manifestKeys = new Set(manifest.barWidget.schema.map(e => e.key))
for (const entry of Model.SETTINGS_SCHEMA) {
  check(`schema key '${entry.key}' exists in manifest.json`,
    manifestKeys.has(entry.key), `manifest has [${[...manifestKeys]}]`)
}
const colorizeManifest = manifest.barWidget.schema.find(e => e.key === "colorizeIcon")
check("manifest colorized icon schema matches the model contract",
  !!colorizeManifest
    && colorizeManifest.type === "boolean"
    && colorizeManifest.label === colorizeIcon.label
    && colorizeManifest.description === colorizeIcon.description
    && colorizeManifest.defaultValue === false
    && manifest.barWidget.defaults.colorizeIcon === false,
  JSON.stringify({ model: colorizeIcon, manifest: colorizeManifest }))

// --- install command --------------------------------------------------------
check("no packages yields no command", Model.installPackagesCommand([]) === null, "expected null")
const inst = Model.installPackagesCommand(["bitwarden-cli", "wl-clipboard"])
check("install goes through Omarchy's own floating-terminal installer",
  inst.slice(0, 3).join(" ") === "omarchy install app" && inst[4] === "bitwarden-cli wl-clipboard",
  inst.join(" "))

// The package list lands in an unquoted expansion inside omarchy-install-app,
// so anything that is not a plain package name must not reach it.
check("install refuses a package name that is not one",
  Model.installPackagesCommand(["bitwarden-cli; rm -rf /"]) === null,
  JSON.stringify(Model.installPackagesCommand(["bitwarden-cli; rm -rf /"])))

// The probe must be a single process, not one per tool.
check("dependency probe is one shell invocation",
  Model.dependencyCheckCommand()[0] === "bash" && Model.dependencyCheckCommand().length === 3,
  JSON.stringify(Model.dependencyCheckCommand().slice(0, 2)))


// --- settings grouping ------------------------------------------------------
const grouped = Model.groupedSettings()
check("grouping keeps every setting",
  grouped.length === Model.SETTINGS_SCHEMA.length,
  `${grouped.length} vs ${Model.SETTINGS_SCHEMA.length}`)
check("exactly one header per group",
  grouped.filter(e => e.groupLabel !== "").length === Model.SETTINGS_GROUPS.length,
  `got ${grouped.filter(e => e.groupLabel !== "").length} headers`)
check("entries are contiguous within a group",
  JSON.stringify(grouped.map(e => e.group)) ===
    JSON.stringify(grouped.map(e => e.group).slice().sort(
      (a, b) => Model.SETTINGS_GROUPS.findIndex(g => g.id === a) - Model.SETTINGS_GROUPS.findIndex(g => g.id === b))),
  grouped.map(e => e.group).join(","))
check("grouping does not mutate the schema",
  Model.SETTINGS_SCHEMA.every(e => e.groupLabel === undefined), "schema was mutated")

// --- PIN validation ---------------------------------------------------------
// The stored item is sealed to this machine, but a program running as the
// user can decrypt it and guess offline on every core (about 17 guesses a
// second on a 16-thread laptop): 4 digits fell in minutes. Six is the floor.
check("minimum PIN length is 6", Model.pinMinLength() === 6, String(Model.pinMinLength()))
check("recommended PIN length is 8", Model.pinRecommendedLength() === 8, String(Model.pinRecommendedLength()))
check("a PIN set before the floor was raised still unlocks",
  Model.pinUnlockMinLength() === 4 && /Model\.pinUnlockMinLength\(\)/.test(functionBody(readPluginSource("Panel.qml"), "submitPinUnlock")),
  String(Model.pinUnlockMinLength()))

check("a 4-digit PIN is refused", Model.validatePin("1234", "1234") !== "", Model.validatePin("1234", "1234"))
check("a 5-digit PIN is refused", Model.validatePin("12345", "12345") !== "", Model.validatePin("12345", "12345"))
check("the refusal names the floor", Model.validatePin("12345", "12345").includes("6 digits"), Model.validatePin("12345", "12345"))
// Between the floor and the recommendation: allowed, and flagged.
check("a 6-digit PIN validates", Model.validatePin("123456", "123456") === "", Model.validatePin("123456", "123456"))
check("but 6 digits is flagged weak", Model.isPinWeak("123456"), "expected weak")
check("and 7 digits is flagged weak", Model.isPinWeak("1234567"), "expected weak")
check("8 digits is not flagged", !Model.isPinWeak("12345678"), Model.pinWeakWarning("12345678"))
check("longer than 8 is not flagged", !Model.isPinWeak("1234567890"), Model.pinWeakWarning("1234567890"))

// No warning while still typing towards a good PIN, or it would flash on
// every keystroke from the first digit onwards.
check("nothing is flagged before the floor is even reached",
  !Model.isPinWeak("") && !Model.isPinWeak("1") && !Model.isPinWeak("12345"),
  "expected no warning below the minimum")

// The warning has to carry the actual number and the offline attack it is
// about, not a vague 'weak' or a one-core figure.
check("the warning names the search space for 6 digits",
  Model.pinWeakWarning("123456").includes("1,000,000") && Model.pinWeakWarning("123456").includes("6-digit"),
  Model.pinWeakWarning("123456"))
check("the warning says the stored item can be copied and guessed offline",
  Model.pinWeakWarning("123456").includes("copy the stored item"), Model.pinWeakWarning("123456"))
check("the warning's time is the measured offline rate",
  Model.pinWeakWarning("123456").includes("about 16 hours") && Model.pinWeakWarning("1234567").includes("about 7 days"),
  Model.pinWeakWarning("123456") + " / " + Model.pinWeakWarning("1234567"))
check("the warning points at the recommendation",
  Model.pinWeakWarning("123456").includes("8 or more") && Model.pinWeakWarning("123456").includes("about 2 months"),
  Model.pinWeakWarning("123456"))
check("the guess times scale by ten per digit",
  Model.pinGuessTime(4) === "about 10 minutes" && Model.pinGuessTime(5) === "about 2 hours",
  Model.pinGuessTime(4) + " / " + Model.pinGuessTime(5))
// The same figures wherever the cost is described.
const manifestPin = JSON.parse(read("manifest.json")).barWidget.schema.find(e => e.key === "pinUnlock").description
const schemaPin = Model.SETTINGS_SCHEMA.find(e => e.key === "pinUnlock").description
for (const [where, text] of [["manifest", manifestPin], ["settings screen", schemaPin],
                             ["README", read("README.md")], ["features doc", read("docs/features.md")]]) {
  check(`the ${where} gives the offline guess time, not the old one-core figure`,
    text.includes("16 hours") && !/9 days for 6|2 hours of one CPU core|4 is the floor/.test(text), where)
}
for (const [pin, confirm, wantErr] of [
  ["12345",  "12345",  true],   // too short
  ["123456", "123456", false],  // the minimum is accepted
  ["12345678901234", "12345678901234", false], // longer is allowed, no upper bound
  ["12a456", "12a456", true],   // non-digits refused
  ["",       "",       true],
  ["123456", "654321", true],   // mismatch
]) {
  const err = Model.validatePin(pin, confirm)
  check(`validatePin(${JSON.stringify(pin)}, ${JSON.stringify(confirm)})`,
    (err !== "") === wantErr, `err=${JSON.stringify(err)}`)
}
check("confirm is optional when omitted", Model.validatePin("123456") === "", Model.validatePin("123456"))

// --- legacy PIN blob -------------------------------------------------------
// Read only, to migrate it; must match what older versions wrote.
const store = legacyKeyring(Model).storePin()[2]

const unlock = Model.pinUnlockCommand()[2]
check("unlock decrypts with the PIN-derived key",
  unlock.includes("openssl enc -d") && unlock.includes("env:QSBW_PIN"), unlock)
check("unlock fails loudly when the lookup fails (pipefail)",
  unlock.includes("set -o pipefail"), unlock)
check("unlock iteration count matches store",
  unlock.match(/-iter\s+(\d+)/)[1] === store.match(/-iter\s+(\d+)/)[1],
  `${unlock.match(/-iter\s+(\d+)/)[1]} vs ${store.match(/-iter\s+(\d+)/)[1]}`)
check("unlock uses the same explicit PBKDF2 digest as store",
  unlock.includes("-md sha256"), unlock)

done()
