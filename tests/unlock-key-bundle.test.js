#!/usr/bin/env node
// The quick-unlock tool ships as committed bytes beside the SSH helper and is
// checked the same way before the panel trusts it: present, executable, the
// right architecture, matching its own line of bin/SHA256SUMS, passing its
// self-test, and writing the envelope format this panel reads. Any failure
// disables PIN, fingerprint and FIDO2 unlock -- and nothing else. The master
// password never depends on it.
//
// The development fallback is unlock-key/target/debug/, which CI's panel job
// builds before running this file.
//
//   node tests/unlock-key-bundle.test.js

const fs = require("fs")
const { readPluginSource } = require("./plugin-source")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.unlockKeyBundledRelative = unlockKeyBundledRelative
  exports.unlockKeyDevelopmentRelative = unlockKeyDevelopmentRelative
  exports.unlockKeyEnvelopeVersion = unlockKeyEnvelopeVersion
  exports.unlockKeyInspectCommand = unlockKeyInspectCommand
  exports.parseUnlockKeyInspection = parseUnlockKeyInspection
  exports.unlockKeyReady = unlockKeyReady
  exports.unlockKeySourceLabel = unlockKeySourceLabel
  exports.isQuickUnlockSetting = isQuickUnlockSetting
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

// -------------------------------------------------------------------------
// The shipped artifact is really in the repository
// -------------------------------------------------------------------------

const bundled = path.join(repoRoot, "bin", "x86_64-linux", "qs-bitwarden-unlock-key")
const development = path.join(repoRoot, "unlock-key", "target", "debug", "qs-bitwarden-unlock-key")
const sums = path.join(repoRoot, "bin", "SHA256SUMS")

check("the unlock tool is tracked in the repository", fs.existsSync(bundled), bundled)
check("it is executable", fs.existsSync(bundled) && (fs.statSync(bundled).mode & 0o111) !== 0,
  "the shipped tool is not executable, so a fresh clone cannot run it")
check("it is a real ELF binary",
  fs.existsSync(bundled) && fs.readFileSync(bundled).subarray(0, 4).toString("latin1") === "\x7fELF",
  "no ELF magic")
const sumLines = fs.existsSync(sums) ? fs.readFileSync(sums, "utf8").trim().split("\n") : []
const recorded = sumLines.find(l => l.endsWith("  x86_64-linux/qs-bitwarden-unlock-key")) || ""
check("it has its own line in SHA256SUMS", recorded !== "", sumLines.join(" | "))
if (fs.existsSync(bundled) && recorded) {
  const actual = spawnSync("sha256sum", [bundled], { encoding: "utf8" }).stdout.split(" ")[0]
  eq("the tracked binary matches its line", actual, recorded.split(/\s+/)[0])
}

// -------------------------------------------------------------------------
// Where the panel looks
// -------------------------------------------------------------------------

eq("the bundled path is architecture-scoped",
  Model.unlockKeyBundledRelative(), "bin/x86_64-linux/qs-bitwarden-unlock-key")
eq("the development path is cargo's debug output for its own package",
  Model.unlockKeyDevelopmentRelative(), "unlock-key/target/debug/qs-bitwarden-unlock-key")
eq("the panel reads envelope v1", Model.unlockKeyEnvelopeVersion(), 1)
check("the source in use is nameable",
  /shipped/.test(Model.unlockKeySourceLabel("bundled"))
    && /local|not the shipped/.test(Model.unlockKeySourceLabel("development")),
  Model.unlockKeySourceLabel("development"))

// -------------------------------------------------------------------------
// The inspection, run against real files
// -------------------------------------------------------------------------

function inTemp(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-unlock-bundle-"))
  try { return fn(dir) } finally { fs.rmSync(dir, { recursive: true, force: true }) }
}
const inspect = (pluginDir) => {
  const cmd = Model.unlockKeyInspectCommand(pluginDir)
  const run = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } })
  return Model.parseUnlockKeyInspection(run.stdout)
}
// A binary to copy into fixtures: the shipped one when it is tracked, the
// local build otherwise.
const sample = fs.existsSync(bundled) ? bundled : development

{
  const result = inspect(repoRoot)
  eq("this checkout's unlock tool is usable", result.state, "ok")
  eq("and it is the shipped one when one is tracked",
    result.source, fs.existsSync(bundled) ? "bundled" : "development")
  check("its version is reported", /^\d+\.\d+\.\d+$/.test(result.version), result.version)
  eq("its envelope version is the panel's", result.protocol, 1)
  eq("its self-test passed", result.selfTest, "pass")
  eq("quick unlock would be offered", Model.unlockKeyReady(result), true)
}

inTemp(dir => {
  const result = inspect(dir)
  eq("a missing tool is reported", result.state, "missing")
  eq("and quick unlock stays off", Model.unlockKeyReady(result), false)
  check("the message says how to get one", /cargo build --manifest-path unlock-key/.test(result.message),
    result.message)
})

check("a sample binary exists to build fixtures from", fs.existsSync(sample),
  "neither a tracked tool nor unlock-key/target/debug -- run `cargo build` in unlock-key/")

if (fs.existsSync(sample)) {
  // A local build with nothing shipped: the development loop keeps working.
  inTemp(dir => {
    const target = path.join(dir, "unlock-key", "target", "debug")
    fs.mkdirSync(target, { recursive: true })
    fs.copyFileSync(sample, path.join(target, "qs-bitwarden-unlock-key"))
    fs.chmodSync(path.join(target, "qs-bitwarden-unlock-key"), 0o755)
    const result = inspect(dir)
    eq("a development build is usable", result.state, "ok")
    eq("and is identified as such", result.source, "development")
    eq("no checksum is claimed for it", result.checksum, "unchecked")
  })

  // Shipped but stale: its line names other bytes.
  inTemp(dir => {
    const target = path.join(dir, "bin", "x86_64-linux")
    fs.mkdirSync(target, { recursive: true })
    fs.copyFileSync(sample, path.join(target, "qs-bitwarden-unlock-key"))
    fs.chmodSync(path.join(target, "qs-bitwarden-unlock-key"), 0o755)
    fs.writeFileSync(path.join(dir, "bin", "SHA256SUMS"),
      "0".repeat(64) + "  x86_64-linux/qs-bitwarden-unlock-key\n")
    const result = inspect(dir)
    eq("a stale shipped tool is refused", result.state, "checksum-mismatch")
    eq("and quick unlock stays off", Model.unlockKeyReady(result), false)
  })

  // Shipped and correct, beside a stale SSH helper line: the SSH agent's
  // problem is not quick unlock's.
  inTemp(dir => {
    const target = path.join(dir, "bin", "x86_64-linux")
    fs.mkdirSync(target, { recursive: true })
    const copy = path.join(target, "qs-bitwarden-unlock-key")
    fs.copyFileSync(sample, copy)
    fs.chmodSync(copy, 0o755)
    const digest = spawnSync("sha256sum", [copy], { encoding: "utf8" }).stdout.split(" ")[0]
    fs.writeFileSync(path.join(dir, "bin", "SHA256SUMS"),
      "f".repeat(64) + "  x86_64-linux/qs-bitwarden-ssh-agent\n"
      + digest + "  x86_64-linux/qs-bitwarden-unlock-key\n")
    const result = inspect(dir)
    eq("a stale SSH helper line does not disable quick unlock", result.state, "ok")
    eq("its own line matches", result.checksum, "match")
  })
}

// The panel, not the shell, decides whether an envelope format is one it
// can read.
{
  const newer = Model.parseUnlockKeyInspection("state=ok\nsource=bundled\nversion=0.2.0\nprotocol=2\n")
  eq("an envelope format the panel does not read is refused", newer.state, "protocol-mismatch")
  check("and the message says to reinstall", /Reinstall/.test(newer.message), newer.message)
}

// -------------------------------------------------------------------------
// Only quick unlock depends on it
// -------------------------------------------------------------------------

for (const key of ["fingerprintUnlock", "pinUnlock", "fidoUnlock"]) {
  eq(`${key} goes through the unlock tool`, Model.isQuickUnlockSetting(key), true)
}
for (const key of ["rememberSession", "sshAgentEnabled", "autoLockMinutes"]) {
  eq(`${key} does not`, Model.isQuickUnlockSetting(key), false)
}

const service = readPluginSource("Service.qml")
check("the tool is inspected at every start, not only when an option is on",
  /root\.inspectUnlockKey\(\)/.test(service),
  "a password login would not know whether it can store the envelope")
check("a missing tool blocks switching quick unlock on",
  /function quickUnlockToolMissing[\s\S]{0,500}?Model\.isQuickUnlockSetting[\s\S]{0,300}?unlockKeyReady/.test(service),
  "the settings toggles are not tied to the tool's inspection")
check("but never blocks switching one off",
  /function quickUnlockToolMissing[\s\S]{0,700}?return !settingValue\(entry\)/.test(service),
  "an option that is on could not be turned off, stranding its stored credential")
check("the blocked toggle says why, and that the password still works",
  /function settingBlockedReason[\s\S]{0,400}?unlockKeyHelper\.message[\s\S]{0,100}?master password still unlocks/.test(service),
  "an inert toggle with no reason")
check("the settings screen shows that reason",
  /root\.vault\.settingBlockedReason\(modelData\)/.test(fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8")),
  "the reason is computed but never drawn")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`unlock-key-bundle: ${pass} passed`)
