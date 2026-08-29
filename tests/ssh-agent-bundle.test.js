#!/usr/bin/env node
// The plugin ships a compiled helper, so the panel checks it before trusting
// it: that it exists, is executable, is the right architecture, matches its
// recorded checksum, passes its own self-test, and speaks the protocol this
// panel does. Every one of those can fail on a real machine -- a partial
// clone, an LFS placeholder, a stale artifact after `git pull`, a helper from
// a newer plugin version -- and each must disable only this optional feature.
//
// Be clear about what the checksum is for. bin/SHA256SUMS sits beside the
// binary and beside the QML that reads it, so anyone able to replace one can
// replace the others. It is not tamper detection. It catches corruption,
// truncation, and staleness, which are the failures that actually happen.
//
//   node tests/ssh-agent-bundle.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.sshAgentBundledRelative = sshAgentBundledRelative
  exports.sshAgentDevelopmentRelative = sshAgentDevelopmentRelative
  exports.sshAgentHelperCandidates = sshAgentHelperCandidates
  exports.sshAgentHelperInspectCommand = sshAgentHelperInspectCommand
  exports.parseSshAgentHelperInspection = parseSshAgentHelperInspection
  exports.sshAgentHelperReady = sshAgentHelperReady
  exports.sshAgentHelperSourceLabel = sshAgentHelperSourceLabel
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

// -------------------------------------------------------------------------
// The shipped artifact is really in the repository
// -------------------------------------------------------------------------

const bundled = path.join(repoRoot, "bin", "x86_64-linux", "qs-bitwarden-ssh-agent")
const sums = path.join(repoRoot, "bin", "SHA256SUMS")

check("the helper is tracked in the repository", fs.existsSync(bundled), bundled)
check("its checksum is tracked beside it", fs.existsSync(sums), sums)
check("it is executable", fs.existsSync(bundled) && (fs.statSync(bundled).mode & 0o111) !== 0,
  "the shipped helper is not executable, so a fresh clone cannot run it")
check("it is not a Git LFS placeholder",
  fs.existsSync(bundled) && !/git-lfs/.test(fs.readFileSync(bundled).subarray(0, 200).toString("latin1")),
  "an LFS smudge would leave a text pointer where the binary should be")
check("it is a real ELF binary",
  fs.existsSync(bundled) && fs.readFileSync(bundled).subarray(0, 4).toString("latin1") === "\x7fELF",
  "no ELF magic")

const recorded = fs.existsSync(sums) ? fs.readFileSync(sums, "utf8").trim() : ""
check("the checksum file records a path relative to bin/",
  /^[0-9a-f]{64}\s+x86_64-linux\/qs-bitwarden-ssh-agent$/.test(recorded),
  recorded)
if (fs.existsSync(bundled) && recorded) {
  const actual = spawnSync("sha256sum", [bundled], { encoding: "utf8" }).stdout.split(" ")[0]
  eq("the tracked binary matches its tracked checksum", actual, recorded.split(/\s+/)[0])
}

// -------------------------------------------------------------------------
// Which helper the panel picks
// -------------------------------------------------------------------------

eq("the bundled path is architecture-scoped",
  Model.sshAgentBundledRelative(), "bin/x86_64-linux/qs-bitwarden-ssh-agent")
eq("the development path is cargo's debug output",
  Model.sshAgentDevelopmentRelative(), "agent/target/debug/qs-bitwarden-ssh-agent")

const candidates = Model.sshAgentHelperCandidates("/opt/bw")
eq("both candidates are offered", candidates.length, 2)
eq("the shipped helper is preferred", candidates[0].path, "/opt/bw/bin/x86_64-linux/qs-bitwarden-ssh-agent")
eq("the development build is the fallback", candidates[1].path, "/opt/bw/agent/target/debug/qs-bitwarden-ssh-agent")
eq("the preferred one is labelled", candidates[0].source, "bundled")
eq("the fallback is labelled", candidates[1].source, "development")
check("every candidate path is absolute",
  candidates.every(c => c.path.charAt(0) === "/"), JSON.stringify(candidates))
eq("no plugin directory yields no candidates", Model.sshAgentHelperCandidates("").length, 0)
eq("a traversing plugin directory yields no candidates",
  Model.sshAgentHelperCandidates("/opt/../etc").length, 0)

// A development build being present must not hide a broken shipped one from
// the diagnostics, but it should still let the panel run.
check("the source in use is nameable",
  Model.sshAgentHelperSourceLabel("bundled").length > 0
    && Model.sshAgentHelperSourceLabel("development").length > 0,
  "a user cannot tell which helper is running")
check("the development label says it is not the shipped artifact",
  /develop|local|built/i.test(Model.sshAgentHelperSourceLabel("development")),
  Model.sshAgentHelperSourceLabel("development"))

// -------------------------------------------------------------------------
// The inspection, run against real files
// -------------------------------------------------------------------------

function inTemp(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-bundle-"))
  try { return fn(dir) } finally { fs.rmSync(dir, { recursive: true, force: true }) }
}
const inspect = (pluginDir) => {
  const cmd = Model.sshAgentHelperInspectCommand(pluginDir)
  const run = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } })
  return Model.parseSshAgentHelperInspection(run.stdout)
}

// The real repository: a tracked helper that should pass every check.
{
  const result = inspect(repoRoot)
  eq("the shipped helper is usable", result.state, "ok")
  eq("and is identified as the bundled one", result.source, "bundled")
  check("its version is reported", /^\d+\.\d+\.\d+$/.test(result.version), result.version)
  eq("its protocol version is reported", result.protocol, 1)
  eq("its checksum is confirmed", result.checksum, "match")
  eq("its self-test passed", result.selfTest, "pass")
  eq("the panel would enable the feature", Model.sshAgentHelperReady(result), true)
}

// Nothing there at all.
inTemp(dir => {
  const result = inspect(dir)
  eq("a missing helper is reported", result.state, "missing")
  eq("and the feature stays off", Model.sshAgentHelperReady(result), false)
  check("the message says what to do", /build|install|clone/i.test(result.message), result.message)
})

// Present but not executable -- a clone from an archive that dropped modes.
inTemp(dir => {
  const target = path.join(dir, "bin", "x86_64-linux")
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o644)
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true })
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  eq("a non-executable helper is reported", result.state, "not-executable")
  eq("and the feature stays off", Model.sshAgentHelperReady(result), false)
})

// Corrupt or truncated -- a partial clone, or an interrupted download.
inTemp(dir => {
  const target = path.join(dir, "bin", "x86_64-linux")
  fs.mkdirSync(target, { recursive: true })
  const copy = path.join(target, "qs-bitwarden-ssh-agent")
  fs.copyFileSync(bundled, copy)
  fs.truncateSync(copy, 4096)
  fs.chmodSync(copy, 0o755)
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  check("a truncated helper is refused", result.state !== "ok", JSON.stringify(result))
  eq("the checksum is what catches it", result.checksum, "mismatch")
  eq("and the feature stays off", Model.sshAgentHelperReady(result), false)
  check("the message names staleness or corruption",
    /stale|corrupt|match|update/i.test(result.message), result.message)
})

// A Git LFS placeholder where the binary should be.
inTemp(dir => {
  const target = path.join(dir, "bin", "x86_64-linux")
  fs.mkdirSync(target, { recursive: true })
  fs.writeFileSync(path.join(target, "qs-bitwarden-ssh-agent"),
    "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 1210560\n", { mode: 0o755 })
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  check("an LFS placeholder is refused", result.state !== "ok", JSON.stringify(result))
  eq("and the feature stays off", Model.sshAgentHelperReady(result), false)
})

// A development build with no shipped artifact: the dev loop must keep working.
inTemp(dir => {
  const target = path.join(dir, "agent", "target", "debug")
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o755)
  const result = inspect(dir)
  eq("a development build is usable", result.state, "ok")
  eq("and is identified as such", result.source, "development")
  eq("the feature is enabled from it", Model.sshAgentHelperReady(result), true)
  check("no checksum is claimed for an untracked build",
    result.checksum === "unchecked", result.checksum)
})

// Both present: the shipped artifact wins, but a broken one does not strand
// a developer who has a working local build.
inTemp(dir => {
  const shipped = path.join(dir, "bin", "x86_64-linux")
  fs.mkdirSync(shipped, { recursive: true })
  fs.writeFileSync(path.join(shipped, "qs-bitwarden-ssh-agent"), "not a binary\n", { mode: 0o755 })
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const dev = path.join(dir, "agent", "target", "debug")
  fs.mkdirSync(dev, { recursive: true })
  fs.copyFileSync(bundled, path.join(dev, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(dev, "qs-bitwarden-ssh-agent"), 0o755)
  const result = inspect(dir)
  eq("a broken shipped helper falls back to the development build", result.state, "ok")
  eq("and says which one it used", result.source, "development")
})

// -------------------------------------------------------------------------
// Failure isolation
// -------------------------------------------------------------------------

// The settings diagnostics live in SshAgentSettings.qml; the supervision that
// feeds them is still in Panel.qml. Both, or a check lands on whichever half
// happens to hold its pattern today.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml"]
  .map(file => fs.readFileSync(path.join(repoRoot, file), "utf8"))
  .join("\n")
check("the helper is inspected before the supervisor is allowed to start",
  /sshAgentHelperReady\(/.test(panelSrc), "nothing gates startup on the inspection")
check("a failed inspection disables only the agent",
  /sshAgentSupervisable[\s\S]{0,400}?sshAgentHelperReady|sshAgentHelperReady[\s\S]{0,400}?sshAgentSupervisable/.test(panelSrc),
  "the inspection result does not feed the supervisable gate")
check("the source in use is shown in the settings diagnostics",
  /sshAgentHelperSourceLabel\(/.test(panelSrc),
  "a user cannot tell whether they are running the shipped or the local helper")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`ssh-agent-bundle: ${pass} passed`)
