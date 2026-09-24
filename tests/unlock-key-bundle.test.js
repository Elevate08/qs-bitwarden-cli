#!/usr/bin/env node
// The quick-unlock tool is checked like the SSH helper before use: present,
// executable, right architecture, its own SHA256SUMS line, passing self-test,
// and the envelope format this panel reads. A failure disables only quick
// unlock. The development fallback is unlock-key/target/debug/.
//
//   node tests/unlock-key-bundle.test.js

const { createSuite, loadModule, read, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const Model = loadModule()

const { check, eq, done } = createSuite("unlock-key-bundle")

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
  Model.UNLOCK_KEY_BUNDLED_RELATIVE, "bin/x86_64-linux/qs-bitwarden-unlock-key")
eq("the development path is cargo's debug output for its own package",
  Model.UNLOCK_KEY_DEVELOPMENT_RELATIVE, "unlock-key/target/debug/qs-bitwarden-unlock-key")
eq("the panel reads envelope v1", Model.UNLOCK_KEY_ENVELOPE_VERSION, 1)

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
  eq("quick unlock would be offered", Model.helperReady(result), true)
}

inTemp(dir => {
  const result = inspect(dir)
  eq("a missing tool is reported", result.state, "missing")
  eq("and quick unlock stays off", Model.helperReady(result), false)
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
    eq("and quick unlock stays off", Model.helperReady(result), false)
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
  /function quickUnlockToolMissing[\s\S]{0,500}?Model\.isQuickUnlockSetting[\s\S]{0,300}?quickUnlockAvailable/.test(service)
    && /readonly property bool quickUnlockAvailable: unlockKeyReady && quickUnlockPrereqs\.ready/.test(service),
  "the settings toggles are not tied to the tool's inspection")
check("but never blocks switching one off",
  /function quickUnlockToolMissing[\s\S]{0,700}?return !settingValue\(entry\)/.test(service),
  "an option that is on could not be turned off, stranding its stored credential")
check("the blocked toggle says why, and that the password still works",
  /function settingBlockedReason[\s\S]{0,400}?quickUnlockUnavailableReason[\s\S]{0,100}?master password still unlocks/.test(service),
  "an inert toggle with no reason")
check("the settings screen shows that reason",
  /root\.vault\.settingBlockedReason\(modelData\)/.test(read("Panel.qml")),
  "the reason is computed but never drawn")

done()
