#!/usr/bin/env node
// The SSH agent is opt-in, and "opted in" is not the same as "usable". These
// tests cover the four settings, the explicit disabled/enabled/error setup
// state, the managed UWSM fragment lifecycle, and the advisory SSH_AUTH_SOCK
// diagnostics -- which must never decide whether the companion runs.
//
//   node tests/ssh-agent-setup.test.js

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.SETTINGS_SCHEMA = SETTINGS_SCHEMA
  exports.SETTINGS_GROUPS = SETTINGS_GROUPS
  exports.groupedSettings = groupedSettings
  exports.settingSchemaEntry = settingSchemaEntry
  exports.boolSetting = boolSetting
  exports.intSetting = intSetting
  exports.sshAgentSetupState = sshAgentSetupState
  exports.sshAgentApprovalWindowMax = sshAgentApprovalWindowMax
  exports.visibleSettings = visibleSettings
  exports.sshUiAvailable = sshUiAvailable
  exports.sshAgentSocketPath = sshAgentSocketPath
  exports.uwsmFragmentDisplayPath = uwsmFragmentDisplayPath
  exports.uwsmFragmentContent = uwsmFragmentContent
  exports.uwsmInspectCommand = uwsmInspectCommand
  exports.uwsmWriteCommand = uwsmWriteCommand
  exports.uwsmRemoveCommand = uwsmRemoveCommand
  exports.parseUwsmInspection = parseUwsmInspection
  exports.parseUwsmActionResult = parseUwsmActionResult
  exports.sshAuthSockDiagnostic = sshAuthSockDiagnostic
  exports.sshAuthSockTerminalCheck = sshAuthSockTerminalCheck
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "manifest.json"), "utf8"))
const manifestSchema = manifest.barWidget.schema
const manifestDefaults = manifest.barWidget.defaults
const manifestEntry = key => manifestSchema.find(e => e.key === key)
const modelEntry = key => Model.settingSchemaEntry(key)

// -------------------------------------------------------------------------
// The four settings, consistent across manifest, model schema and defaults
// -------------------------------------------------------------------------

const expected = [
  { key: "sshAgentEnabled", type: "bool", manifestType: "boolean", defaultValue: false },
  { key: "sshAgentUnlockOnDemand", type: "bool", manifestType: "boolean", defaultValue: false },
  { key: "sshAgentApprovalPopup", type: "bool", manifestType: "boolean", defaultValue: false },
  { key: "sshAgentApprovalWindowSec", type: "int", manifestType: "integer", defaultValue: 120 }
]

for (const want of expected) {
  const m = manifestEntry(want.key)
  const s = modelEntry(want.key)
  check(`manifest declares ${want.key}`, !!m, "missing from manifest.barWidget.schema")
  check(`model schema declares ${want.key}`, !!s, "missing from SETTINGS_SCHEMA")
  if (!m || !s) continue
  eq(`${want.key} manifest type`, m.type, want.manifestType)
  eq(`${want.key} model type`, s.type, want.type)
  eq(`${want.key} manifest default`, m.defaultValue, want.defaultValue)
  eq(`${want.key} model default`, s.defaultValue, want.defaultValue)
  eq(`${want.key} defaults block`, manifestDefaults[want.key], want.defaultValue)
  check(`${want.key} has a description in the manifest`,
    typeof m.description === "string" && m.description.length > 0, JSON.stringify(m))
  check(`${want.key} has a description in the model schema`,
    typeof s.description === "string" && s.description.length > 0, JSON.stringify(s))
}

// The window is a bounded grant length, and the bound is the design's, not a
// number the settings screen happens to draw.
const windowManifest = manifestEntry("sshAgentApprovalWindowSec")
const windowModel = modelEntry("sshAgentApprovalWindowSec")
eq("approval window minimum is 0", windowModel && windowModel.min, 0)
eq("approval window maximum is 900", windowModel && windowModel.max, Model.sshAgentApprovalWindowMax())
eq("approval window maximum is the documented cap", Model.sshAgentApprovalWindowMax(), 900)
eq("manifest agrees on the window minimum", windowManifest && windowManifest.min, 0)
eq("manifest agrees on the window maximum", windowManifest && windowManifest.max, 900)
check("the approval window says what 0 means",
  windowModel && typeof windowModel.zeroLabel === "string" && windowModel.zeroLabel.length > 0,
  JSON.stringify(windowModel))

// -------------------------------------------------------------------------
// Reading the settings back
// -------------------------------------------------------------------------

eq("the agent is off when the setting is absent", Model.boolSetting("sshAgentEnabled", undefined), false)
eq("the agent is off when shell.json holds junk", Model.boolSetting("sshAgentEnabled", "yes please"), false)
eq("the agent is on only for a real boolean", Model.boolSetting("sshAgentEnabled", true), true)
eq("unlock-on-demand is off by default", Model.boolSetting("sshAgentUnlockOnDemand", undefined), false)
eq("the centered approval popup is off by default", Model.boolSetting("sshAgentApprovalPopup", undefined), false)
eq("the centered approval popup accepts true", Model.boolSetting("sshAgentApprovalPopup", true), true)
eq("the centered approval popup rejects junk", Model.boolSetting("sshAgentApprovalPopup", "yes"), false)

eq("the approval window defaults to 120", Model.intSetting("sshAgentApprovalWindowSec", undefined), 120)
eq("the approval window keeps a valid value", Model.intSetting("sshAgentApprovalWindowSec", 300), 300)
eq("the approval window clamps above the cap", Model.intSetting("sshAgentApprovalWindowSec", 99999), 900)
eq("0 disables grants rather than reading as unset", Model.intSetting("sshAgentApprovalWindowSec", 0), 0)
eq("a negative window falls back to the default", Model.intSetting("sshAgentApprovalWindowSec", -30), 120)
eq("a non-numeric window falls back to the default", Model.intSetting("sshAgentApprovalWindowSec", "soon"), 120)

// -------------------------------------------------------------------------
// The SSH Agent settings group
// -------------------------------------------------------------------------

const sshGroup = Model.SETTINGS_GROUPS.find(g => g.id === "sshAgent")
check("there is an SSH Agent settings group", !!sshGroup, JSON.stringify(Model.SETTINGS_GROUPS))
const grouped = Model.groupedSettings()
eq("grouping still covers every schema entry", grouped.length, Model.SETTINGS_SCHEMA.length)
const sshRows = grouped.filter(e => e.group === "sshAgent")
eq("the SSH Agent group holds exactly the four settings", sshRows.length, 4)
eq("the group header is drawn once", sshRows.filter(e => e.groupLabel).length, 1)
eq("the enabled toggle leads the group", sshRows[0].key, "sshAgentEnabled")
check("grouping did not mutate the schema",
  Model.SETTINGS_SCHEMA.every(e => e.groupLabel === undefined), "schema was mutated")

// The SSH settings are only offered once the dependency probe has confirmed a
// CLI that can decrypt SSH key items -- the same gate the SSH type filter
// uses. Offering a toggle that cannot work is worse than not offering it.
const supportedDeps = { items: [], sshCliStatus: "supported" }
const oldDeps = { items: [], sshCliStatus: "unsupported" }
const unknownDeps = { items: [], sshCliStatus: "unknown" }

const shown = Model.visibleSettings(supportedDeps, true)
eq("a supported CLI shows every setting", shown.length, Model.SETTINGS_SCHEMA.length)
check("a supported CLI shows the SSH group header",
  shown.filter(e => e.group === "sshAgent" && e.groupLabel).length === 1, "no header")

for (const [label, deps, checked] of [
  ["an unsupported CLI", oldDeps, true],
  ["an unreadable CLI version", unknownDeps, true],
  ["an unfinished probe", supportedDeps, false]
]) {
  const rows = Model.visibleSettings(deps, checked)
  eq(`${label} hides the SSH settings`, rows.filter(e => e.group === "sshAgent").length, 0)
  eq(`${label} keeps every other setting`, rows.length, Model.SETTINGS_SCHEMA.length - 4)
  check(`${label} still draws every remaining group header`,
    rows.filter(e => e.groupLabel).length === new Set(rows.map(e => e.group)).size,
    JSON.stringify(rows.filter(e => e.groupLabel).map(e => e.groupLabel)))
}

check("hiding the group does not mutate the schema",
  Model.SETTINGS_SCHEMA.every(e => e.groupLabel === undefined), "schema was mutated")

// -------------------------------------------------------------------------
// Disabled / enabled / error setup state
// -------------------------------------------------------------------------

const state = opts => Model.sshAgentSetupState(opts)

eq("off is disabled", state({ enabled: false, supervisable: false, phase: "disabled", errorCode: "" }).state,
  "disabled")
eq("off while a helper still winds down is still disabled",
  state({ enabled: false, supervisable: false, phase: "restarting", errorCode: "MALFORMED" }).state, "disabled")
check("disabled reports no error",
  state({ enabled: false, supervisable: false, phase: "disabled", errorCode: "" }).message.length > 0,
  "no message")

const running = state({ enabled: true, supervisable: true, phase: "ready", errorCode: "" })
eq("a completed handshake is enabled", running.state, "enabled")
eq("a running helper is not busy", running.busy, false)

for (const phase of ["starting", "handshaking"]) {
  const s = state({ enabled: true, supervisable: true, phase: phase, errorCode: "" })
  eq(`${phase} is still the enabled state`, s.state, "enabled")
  eq(`${phase} reports as busy`, s.busy, true)
}

for (const phase of ["backoff", "restarting"]) {
  const s = state({ enabled: true, supervisable: true, phase: phase, errorCode: "EXITED" })
  eq(`${phase} after a failure is an error`, s.state, "error")
}

const crashed = state({ enabled: true, supervisable: true, phase: "failed", errorCode: "CRASH_LOOP" })
eq("a crash loop is an error", crashed.state, "error")
check("a crash loop explains itself", crashed.message.indexOf("keeps failing") >= 0, crashed.message)

// XDG_RUNTIME_DIR is the one thing the companion genuinely cannot do without,
// and the design says refuse rather than fall back to a guessable path.
const noRuntime = state({ enabled: true, supervisable: false, phase: "disabled", errorCode: "" })
eq("enabled with no runtime directory is an error", noRuntime.state, "error")
check("the runtime-directory error names the cause",
  /runtime directory/i.test(noRuntime.message), noRuntime.message)

// -------------------------------------------------------------------------
// Client routing is never a setup state
// -------------------------------------------------------------------------

const routingIrrelevant = ["/run/user/1000/qs-bitwarden-cli/ssh-agent.sock", "/run/user/1000/gcr/ssh", ""]
for (const sock of routingIrrelevant) {
  const s = state({
    enabled: true, supervisable: true, phase: "ready", errorCode: "", sshAuthSock: sock
  })
  eq(`SSH_AUTH_SOCK=${JSON.stringify(sock)} does not change the setup state`, s.state, "enabled")
}

// -------------------------------------------------------------------------
// SSH_AUTH_SOCK is advisory, and says which agent the session actually has
// -------------------------------------------------------------------------

const RT = "/run/user/1000"
const ours = Model.sshAgentSocketPath(RT)
eq("the socket path is deterministic", ours, "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock")
eq("no runtime directory means no socket path", Model.sshAgentSocketPath(""), "")
eq("a relative runtime directory means no socket path", Model.sshAgentSocketPath("run/user/1000"), "")

const diag = (sock, rt) => Model.sshAuthSockDiagnostic(sock, rt === undefined ? RT : rt)

eq("a matching socket is reported as matching", diag(ours).state, "matches")
eq("an unset socket is reported as unset", diag("").state, "unset")
eq("an undefined socket is reported as unset", diag(undefined).state, "unset")
eq("a different socket points elsewhere", diag("/run/user/1000/gcr/ssh").state, "elsewhere")

const owners = [
  ["/run/user/1000/gcr/ssh", "GNOME Keyring"],
  ["/run/user/1000/keyring/ssh", "GNOME Keyring"],
  ["/home/u/.1password/agent.sock", "1Password"],
  ["/run/user/1000/gnupg/S.gpg-agent.ssh", "GPG Agent"],
  ["/run/user/1000/.bitwarden-ssh-agent.sock", "Bitwarden Desktop"],
  ["/tmp/ssh-XXhqZ3kR/agent.4242", "OpenSSH ssh-agent"]
]
for (const [sock, owner] of owners) {
  const d = diag(sock)
  eq(`${sock} is attributed to ${owner}`, d.owner, owner)
  eq(`${sock} points elsewhere`, d.state, "elsewhere")
  check(`${sock} names its owner in the message`, d.message.indexOf(owner) >= 0, d.message)
}

const unknownOwner = diag("/some/other/agent.sock")
eq("an unrecognised socket still points elsewhere", unknownOwner.state, "elsewhere")
check("an unrecognised socket is not attributed to anyone",
  unknownOwner.owner === "", unknownOwner.owner)

// The panel only sees the graphical session's environment. Anything it says
// about routing has to be offered as a hint the user can check themselves.
for (const sock of [ours, "", "/run/user/1000/gcr/ssh"]) {
  const d = diag(sock)
  check(`the ${d.state} diagnostic offers the terminal check`,
    d.terminalCheck === Model.sshAuthSockTerminalCheck(), d.terminalCheck)
  check(`the ${d.state} diagnostic never claims to be authoritative`,
    !/\b(must|required|cannot start|will not start)\b/i.test(d.message), d.message)
}
check("the terminal check is the documented one",
  Model.sshAuthSockTerminalCheck().indexOf("ssh-add -L") >= 0
  && Model.sshAuthSockTerminalCheck().indexOf("SSH_AUTH_SOCK") >= 0,
  Model.sshAuthSockTerminalCheck())

// With no runtime directory there is nothing to compare against, so the
// diagnostic must not claim the session points somewhere wrong.
eq("no runtime directory yields no verdict", diag(ours, "").state, "unknown")

// -------------------------------------------------------------------------
// The managed UWSM fragment, exercised against a real filesystem
// -------------------------------------------------------------------------

const os = require("os")
const { spawnSync } = require("child_process")

const FRAGMENT_REL = ".config/uwsm/env.d/50-qs-bitwarden-ssh-agent"
check("the display path is the documented one",
  Model.uwsmFragmentDisplayPath() === "~/" + FRAGMENT_REL, Model.uwsmFragmentDisplayPath())

const content = Model.uwsmFragmentContent()
check("the fragment exports SSH_AUTH_SOCK",
  content.indexOf('export SSH_AUTH_SOCK=') >= 0, content)
check("the fragment defers XDG_RUNTIME_DIR to login time",
  content.indexOf('${XDG_RUNTIME_DIR}') >= 0, content)
check("the fragment marks itself as plugin-owned",
  /qs-bitwarden-cli/.test(content) && /^#/m.test(content), content)

function inTempHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-uwsm-"))
  try { return fn(home) } finally { fs.rmSync(home, { recursive: true, force: true }) }
}
const run = (cmd, home) =>
  spawnSync(cmd[0], cmd.slice(1), { env: { HOME: home, PATH: "/usr/bin:/bin" }, encoding: "utf8" })
const inspect = home => Model.parseUwsmInspection(run(Model.uwsmInspectCommand(), home).stdout)
const fragmentAt = home => path.join(home, FRAGMENT_REL)

inTempHome(home => {
  eq("a fresh home has no fragment", inspect(home).state, "absent")

  const written = run(Model.uwsmWriteCommand(), home)
  eq("writing a fresh fragment succeeds", Model.parseUwsmActionResult(written.status, written.stdout).ok, true)
  eq("the fragment is now recognised as managed", inspect(home).state, "managed")
  eq("the file holds exactly the managed content",
    fs.readFileSync(fragmentAt(home), "utf8"), content)

  const mode = fs.statSync(fragmentAt(home)).mode & 0o777
  check("the fragment is not writable by group or other", (mode & 0o022) === 0, mode.toString(8))
  const dirMode = fs.statSync(path.dirname(fragmentAt(home))).mode & 0o777
  check("the created parent is not writable by group or other", (dirMode & 0o022) === 0, dirMode.toString(8))

  const again = run(Model.uwsmWriteCommand(), home)
  eq("rewriting an identical fragment is not an error",
    Model.parseUwsmActionResult(again.status, again.stdout).ok, true)

  const removed = run(Model.uwsmRemoveCommand(), home)
  eq("removing a managed fragment succeeds", Model.parseUwsmActionResult(removed.status, removed.stdout).ok, true)
  check("the fragment is gone", !fs.existsSync(fragmentAt(home)), "still present")
  eq("removal leaves the state absent", inspect(home).state, "absent")

  const removeAgain = run(Model.uwsmRemoveCommand(), home)
  eq("removing an absent fragment is not an error",
    Model.parseUwsmActionResult(removeAgain.status, removeAgain.stdout).ok, true)
})

// Somebody else's file at the managed path is never replaced or deleted.
inTempHome(home => {
  fs.mkdirSync(path.dirname(fragmentAt(home)), { recursive: true })
  const foreign = 'export SSH_AUTH_SOCK="/run/user/1000/my-own-agent.sock"\n'
  fs.writeFileSync(fragmentAt(home), foreign)

  const state = inspect(home)
  eq("hand-written content is recognised as foreign", state.state, "foreign")
  eq("foreign content is not offered for removal", state.removable, false)
  check("foreign content comes with cleanup instructions",
    state.message.indexOf(Model.uwsmFragmentDisplayPath()) >= 0, state.message)

  const written = run(Model.uwsmWriteCommand(), home)
  const outcome = Model.parseUwsmActionResult(written.status, written.stdout)
  eq("writing refuses to replace foreign content", outcome.ok, false)
  eq("the refusal is reported as a conflict", outcome.code, "FOREIGN")
  eq("the foreign file is untouched", fs.readFileSync(fragmentAt(home), "utf8"), foreign)

  const removed = run(Model.uwsmRemoveCommand(), home)
  eq("removal refuses to delete foreign content",
    Model.parseUwsmActionResult(removed.status, removed.stdout).ok, false)
  eq("the foreign file survives removal", fs.readFileSync(fragmentAt(home), "utf8"), foreign)
})

// A symlink at the managed path is refused outright rather than followed: it
// would otherwise be an arbitrary-write primitive into whatever it targets.
inTempHome(home => {
  const target = path.join(home, "target-file")
  fs.writeFileSync(target, "original\n")
  fs.mkdirSync(path.dirname(fragmentAt(home)), { recursive: true })
  fs.symlinkSync(target, fragmentAt(home))

  eq("a symlink is recognised as a symlink", inspect(home).state, "symlink")
  eq("a symlink is not offered for removal", inspect(home).removable, false)

  const written = run(Model.uwsmWriteCommand(), home)
  const outcome = Model.parseUwsmActionResult(written.status, written.stdout)
  eq("writing refuses to follow a symlink", outcome.ok, false)
  eq("the symlink refusal has its own code", outcome.code, "SYMLINK")
  eq("the symlink target is untouched", fs.readFileSync(target, "utf8"), "original\n")
  check("the symlink itself is untouched", fs.lstatSync(fragmentAt(home)).isSymbolicLink(), "no longer a symlink")

  const removed = run(Model.uwsmRemoveCommand(), home)
  eq("removal refuses to follow a symlink",
    Model.parseUwsmActionResult(removed.status, removed.stdout).ok, false)
  check("the symlink survives removal", fs.lstatSync(fragmentAt(home)).isSymbolicLink(), "removed")
  eq("the symlink target survives removal", fs.readFileSync(target, "utf8"), "original\n")
})

// A directory at the managed path is not a fragment either.
inTempHome(home => {
  fs.mkdirSync(fragmentAt(home), { recursive: true })
  eq("a directory at the path is foreign", inspect(home).state, "foreign")
  eq("writing refuses a directory",
    Model.parseUwsmActionResult(run(Model.uwsmWriteCommand(), home).status, "").ok, false)
})

// No HOME is a refusal, not a write into an unexpected place.
{
  const noHome = spawnSync("bash", Model.uwsmInspectCommand().slice(1),
    { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  eq("no HOME is reported rather than guessed", Model.parseUwsmInspection(noHome.stdout).state, "no-home")
  const w = spawnSync("bash", Model.uwsmWriteCommand().slice(1),
    { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" })
  eq("writing without HOME fails closed", Model.parseUwsmActionResult(w.status, w.stdout).ok, false)
}

// Every outcome the panel can show has to say a logout is what applies it.
for (const [status, out] of [[0, "written\n"]]) {
  const r = Model.parseUwsmActionResult(status, out)
  check("a successful write tells the user to log out and back in",
    /log ?out/i.test(r.message) && /log ?in/i.test(r.message), r.message)
  check("a successful write explicitly rules out a shell restart",
    /restart\w*\s+the\s+shell\s+is\s+not\s+enough/i.test(r.message), r.message)
}

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`ssh-agent-setup: ${pass} passed`)
