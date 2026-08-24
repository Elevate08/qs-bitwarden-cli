#!/usr/bin/env node
// Tests for the setup wizard's dependency probe and the settings writer.
//
// The interesting cases are the ones that cannot be exercised on a machine
// where everything is already installed: a missing required tool, and fprintd
// being present but having no enrolled finger.
//
//   node tests/setup-settings.test.js

const fs = require("fs")
const path = require("path")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseDependencies = parseDependencies
  exports.missingRequired = missingRequired
  exports.dependencyCheckCommand = dependencyCheckCommand
  exports.settingWriteCommand = settingWriteCommand
  exports.boolSetting = boolSetting
  exports.installPackagesCommand = installPackagesCommand
  exports.SETTINGS_SCHEMA = SETTINGS_SCHEMA
  exports.DEPENDENCIES = DEPENDENCIES
  exports.groupedSettings = groupedSettings
  exports.SETTINGS_GROUPS = SETTINGS_GROUPS
  exports.validatePin = validatePin
  exports.pinMinLength = pinMinLength
  exports.pinRecommendedLength = pinRecommendedLength
  exports.pinWeakWarning = pinWeakWarning
  exports.isPinWeak = isPinWeak
  exports.pinStoreCommand = pinStoreCommand
  exports.pinUnlockCommand = pinUnlockCommand
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const byKey = (deps, k) => deps.items.find(d => d.key === k)

// --- everything present -----------------------------------------------------
const all = Model.parseDependencies(
  "bw=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
check("all present: nothing required is missing",
  Model.missingRequired(all).length === 0,
  `got [${Model.missingRequired(all).map(d => d.key)}]`)
check("all present: fprintd reported ready", byKey(all, "fprintd").ready === true, "expected ready")

// --- the case that matters: a required tool is absent -----------------------
const noBw = Model.parseDependencies(
  "bw=0\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=1\nomarchy=1")
const missing = Model.missingRequired(noBw)
check("missing bw is reported as required",
  missing.length === 1 && missing[0].key === "bw" && missing[0].pkg === "bitwarden-cli",
  `got [${missing.map(d => d.key + ":" + d.pkg)}]`)
check("missing bw is not marked installed", byKey(noBw, "bw").installed === false, "expected false")

// An optional tool going missing must not trigger the blocking wizard.
const noFprintd = Model.parseDependencies(
  "bw=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=0\nfingerprint_ready=0\nomarchy=1")
check("missing optional tool does not block setup",
  Model.missingRequired(noFprintd).length === 0,
  `got [${Model.missingRequired(noFprintd).map(d => d.key)}]`)

// --- fprintd installed but no finger enrolled -------------------------------
const noFinger = Model.parseDependencies(
  "bw=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=0\nomarchy=1")
check("fprintd on PATH without an enrolled finger is installed-but-not-ready",
  byKey(noFinger, "fprintd").installed === true && byKey(noFinger, "fprintd").ready === false,
  `installed=${byKey(noFinger, "fprintd").installed} ready=${byKey(noFinger, "fprintd").ready}`)

// --- malformed / empty probe output -----------------------------------------
for (const [label, raw] of [["empty", ""], ["garbage", "???\n=\nbw\n"]]) {
  const d = Model.parseDependencies(raw)
  check(`${label} probe output degrades to all-missing`,
    d.items.length === Model.DEPENDENCIES.length && d.items.every(i => !i.installed),
    `got ${d.items.length} items, installed=[${d.items.filter(i => i.installed).map(i => i.key)}]`)
}

// --- settings writer --------------------------------------------------------
// Values must reach shell.json as real JSON types, not strings, or `setting()`
// hands the panel a string where it expects a number or a bool.
// The writer runs through bash so its diagnostic stderr can be capped, so the
// assertions read the script rather than an argv list.
const writeScript = (k, v, t) => Model.settingWriteCommand(k, v, t)[2]

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
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"))
const manifestKeys = new Set(manifest.barWidget.schema.map(e => e.key))
for (const entry of Model.SETTINGS_SCHEMA) {
  check(`schema key '${entry.key}' exists in manifest.json`,
    manifestKeys.has(entry.key), `manifest has [${[...manifestKeys]}]`)
}

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
check("minimum PIN length is 4", Model.pinMinLength() === 4, String(Model.pinMinLength()))
check("recommended PIN length is 6", Model.pinRecommendedLength() === 6, String(Model.pinRecommendedLength()))

// A short PIN is allowed -- the point is that it is flagged, not blocked.
check("a 4-digit PIN still validates", Model.validatePin("1234", "1234") === "", Model.validatePin("1234", "1234"))
check("a 5-digit PIN still validates", Model.validatePin("12345", "12345") === "", Model.validatePin("12345", "12345"))
check("but 4 digits is flagged weak", Model.isPinWeak("1234"), "expected weak")
check("and 5 digits is flagged weak", Model.isPinWeak("12345"), "expected weak")
check("6 digits is not flagged", !Model.isPinWeak("123456"), Model.pinWeakWarning("123456"))
check("longer than 6 is not flagged", !Model.isPinWeak("1234567890"), Model.pinWeakWarning("1234567890"))

// No warning while still typing towards a good PIN, or it would flash on
// every keystroke from the first digit onwards.
check("nothing is flagged before the floor is even reached",
  !Model.isPinWeak("") && !Model.isPinWeak("1") && !Model.isPinWeak("123"),
  "expected no warning below the minimum")

// The warning has to carry the actual number, not a vague 'weak'.
check("the warning names the search space for 4 digits",
  Model.pinWeakWarning("1234").includes("10,000") && Model.pinWeakWarning("1234").includes("4-digit"),
  Model.pinWeakWarning("1234"))
check("the warning names the search space for 5 digits",
  Model.pinWeakWarning("12345").includes("100,000"), Model.pinWeakWarning("12345"))
check("the warning points at the recommendation",
  Model.pinWeakWarning("1234").includes("6 or more"), Model.pinWeakWarning("1234"))
for (const [pin, confirm, wantErr] of [
  ["123",    "123",    true],   // too short
  ["1234",   "1234",   false],  // the minimum is accepted
  ["12345678901234", "12345678901234", false], // longer is allowed, no upper bound
  ["12a4",   "12a4",   true],   // non-digits refused
  ["",       "",       true],
  ["1234",   "4321",   true],   // mismatch
]) {
  const err = Model.validatePin(pin, confirm)
  check(`validatePin(${JSON.stringify(pin)}, ${JSON.stringify(confirm)})`,
    (err !== "") === wantErr, `err=${JSON.stringify(err)}`)
}
check("confirm is optional when omitted", Model.validatePin("1234") === "", Model.validatePin("1234"))

// --- PIN crypto command shape ----------------------------------------------
// The whole point of PIN unlock over fingerprint unlock is that the keyring
// holds ciphertext, not the master password. Guard that property.
const store = Model.pinStoreCommand()[2]
check("store derives a key from the PIN rather than saving it",
  store.includes("openssl enc") && store.includes("-pbkdf2") && store.includes("env:QSBW_PIN"), store)
check("store uses a high iteration count",
  /-iter\s+(\d+)/.test(store) && Number(store.match(/-iter\s+(\d+)/)[1]) >= 600000, store)
check("store pins PBKDF2 to SHA-256 instead of relying on an OpenSSL default",
  store.includes("-md sha256"), store)
check("store salts the ciphertext", store.includes("-salt"), store)
check("store reports encryption failures instead of saving an empty blob",
  store.includes("set -o pipefail"), store)
check("store pipes straight into the keyring, never through argv",
  store.includes("secret-tool store") && !store.includes("$QSBW_SECRET\" secret-tool"), store)
check("neither PIN nor secret appears as a literal argument",
  !store.includes("--pass ") && store.includes("-pass env:"), store)

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

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
