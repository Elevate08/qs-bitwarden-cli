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
  exports.installPackagesCommand = installPackagesCommand
  exports.SETTINGS_SCHEMA = SETTINGS_SCHEMA
  exports.DEPENDENCIES = DEPENDENCIES
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
check("int setting is written with --json",
  JSON.stringify(Model.settingWriteCommand("autoLockMinutes", 15, "int"))
    === JSON.stringify(["omarchy","bar","set","qs-bitwarden-cli","autoLockMinutes","15","--json"]),
  JSON.stringify(Model.settingWriteCommand("autoLockMinutes", 15, "int")))

for (const [v, want] of [[true, "true"], [false, "false"]]) {
  const cmd = Model.settingWriteCommand("closeOnCopy", v, "bool")
  check(`bool ${v} is written as ${want}`, cmd[5] === want, `got ${cmd[5]}`)
}
check("a zero int is written as 0, not dropped",
  Model.settingWriteCommand("autoLockMinutes", 0, "int")[5] === "0",
  Model.settingWriteCommand("autoLockMinutes", 0, "int")[5])

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
check("install runs in a terminal and quotes each package",
  inst[2].includes("omarchy launch terminal") && inst[2].includes("'bitwarden-cli'") && inst[2].includes("'wl-clipboard'"),
  inst[2])

// The probe must be a single process, not one per tool.
check("dependency probe is one shell invocation",
  Model.dependencyCheckCommand()[0] === "bash" && Model.dependencyCheckCommand().length === 3,
  JSON.stringify(Model.dependencyCheckCommand().slice(0, 2)))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
