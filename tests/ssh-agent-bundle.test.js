#!/usr/bin/env node
// The shipped helper is checked before use (exists, executable, architecture,
// checksum, self-test, protocol), and any failure (partial clone, LFS
// placeholder, stale binary) disables only the SSH feature. SHA256SUMS sits
// beside the binary, so it catches corruption and staleness, not tampering.
//
//   node tests/ssh-agent-bundle.test.js

const { createSuite, loadModule, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const Model = loadModule()
// The architecture these tests run on, and its shipped bin/ directory.
const HOST_ARCH = Model.helperArchitecture({ x64: "x86_64", arm64: "aarch64" }[process.arch] || process.arch)
const HOST_DIR = HOST_ARCH ? Model.HELPER_ARCHITECTURES[HOST_ARCH].dir : "unsupported-linux"

const { check, eq, done } = createSuite("ssh-agent-bundle")

// -------------------------------------------------------------------------
// The shipped artifact is really in the repository
// -------------------------------------------------------------------------

const bundled = path.join(repoRoot, "bin", HOST_DIR, "qs-bitwarden-ssh-agent")
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

// SHA256SUMS names every shipped helper, one line each.
const sumLines = fs.existsSync(sums) ? fs.readFileSync(sums, "utf8").trim().split("\n") : []
check("every checksum line records a path relative to bin/",
  sumLines.length > 0 && sumLines.every(l => /^[0-9a-f]{64}  (x86_64|aarch64)-linux\/[a-z0-9-]+$/.test(l)),
  sumLines.join(" | "))
const recorded = sumLines.find(l => l.endsWith(`  ${HOST_DIR}/qs-bitwarden-ssh-agent`)) || ""
check("the SSH helper has its own line", recorded !== "", sumLines.join(" | "))
if (fs.existsSync(bundled) && recorded) {
  const actual = spawnSync("sha256sum", [bundled], { encoding: "utf8" }).stdout.split(" ")[0]
  eq("the tracked binary matches its tracked checksum", actual, recorded.split(/\s+/)[0])
}

// -------------------------------------------------------------------------
// Which helper the panel picks
// -------------------------------------------------------------------------

eq("the bundled path is architecture-scoped",
  Model.helperBundledRelative(Model.SSH_AGENT_HELPER_SPEC, "x86_64"), "bin/x86_64-linux/qs-bitwarden-ssh-agent")
eq("and aarch64 has its own directory",
  Model.helperBundledRelative(Model.SSH_AGENT_HELPER_SPEC, "aarch64"), "bin/aarch64-linux/qs-bitwarden-ssh-agent")
eq("arm64 is aarch64", Model.helperArchitecture("arm64"), "aarch64")
eq("amd64 is x86_64", Model.helperArchitecture("amd64"), "x86_64")
eq("an architecture no release ships has no shipped path",
  Model.helperBundledRelative(Model.SSH_AGENT_HELPER_SPEC, "riscv64"), "")
eq("nor a crafted one", Model.helperBundledRelative(Model.SSH_AGENT_HELPER_SPEC, "../x86_64"), "")
eq("the machine bytes are x86_64's and aarch64's",
  Model.HELPER_ARCHITECTURES.x86_64.elfMachine + "," + Model.HELPER_ARCHITECTURES.aarch64.elfMachine, "3e,b7")
eq("the development path is cargo's debug output",
  Model.SSH_AGENT_DEVELOPMENT_RELATIVE, "agent/target/debug/qs-bitwarden-ssh-agent")

const candidates = Model.helperCandidates("/opt/bw", Model.SSH_AGENT_HELPER_SPEC, "x86_64")
eq("both candidates are offered", candidates.length, 2)
eq("the shipped helper is preferred", candidates[0].path, "/opt/bw/bin/x86_64-linux/qs-bitwarden-ssh-agent")
eq("the development build is the fallback", candidates[1].path, "/opt/bw/agent/target/debug/qs-bitwarden-ssh-agent")
eq("the preferred one is labelled", candidates[0].source, "bundled")
eq("the fallback is labelled", candidates[1].source, "development")
check("every candidate path is absolute",
  candidates.every(c => c.path.charAt(0) === "/"), JSON.stringify(candidates))
eq("no plugin directory yields no candidates", Model.helperCandidates("", Model.SSH_AGENT_HELPER_SPEC, "x86_64").length, 0)
eq("a traversing plugin directory yields no candidates",
  Model.helperCandidates("/opt/../etc", Model.SSH_AGENT_HELPER_SPEC, "x86_64").length, 0)
eq("aarch64 is offered its own build",
  Model.helperCandidates("/opt/bw", Model.SSH_AGENT_HELPER_SPEC, "aarch64")[0].path,
  "/opt/bw/bin/aarch64-linux/qs-bitwarden-ssh-agent")
const unsupported = Model.helperCandidates("/opt/bw", Model.SSH_AGENT_HELPER_SPEC, "riscv64")
eq("an unshipped architecture is offered only the local build", unsupported.length, 1)
eq("which is the development one", unsupported[0].source, "development")
eq("a shipped helper with no reported architecture launches nothing",
  Model.helperPath("/opt/bw", Model.SSH_AGENT_HELPER_SPEC, "bundled", ""), "")

// Every architecture the panel knows is tracked, with its own checksum line
// and the machine byte the inspection expects.
for (const arch of Object.keys(Model.HELPER_ARCHITECTURES)) {
  for (const name of ["qs-bitwarden-ssh-agent", "qs-bitwarden-unlock-key", "qs-bitwarden-vault"]) {
    const rel = `${Model.HELPER_ARCHITECTURES[arch].dir}/${name}`
    const file = path.join(repoRoot, "bin", rel)
    const present = fs.existsSync(file)
    check(`bin/${rel} is tracked`, present, file)
    if (!present) continue
    const bytes = fs.readFileSync(file)
    eq(`bin/${rel} is an ELF for ${arch}`,
      bytes.subarray(0, 4).toString("latin1") + bytes[18].toString(16),
      "\x7fELF" + Model.HELPER_ARCHITECTURES[arch].elfMachine)
    const line = sumLines.find(l => l.endsWith(`  ${rel}`)) || ""
    const digest = spawnSync("sha256sum", [file], { encoding: "utf8" }).stdout.split(" ")[0]
    eq(`bin/${rel} matches its own SHA256SUMS line`, line.split(/\s+/)[0], digest)
  }
}

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
  eq("the panel would enable the feature", Model.helperReady(result), true)
}

// Nothing there at all.
inTemp(dir => {
  const result = inspect(dir)
  eq("a missing helper is reported", result.state, "missing")
  eq("and the feature stays off", Model.helperReady(result), false)
  check("the message says what to do", /build|install|clone/i.test(result.message), result.message)
})

// Present but not executable -- a clone from an archive that dropped modes.
inTemp(dir => {
  const target = path.join(dir, "bin", HOST_DIR)
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o644)
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true })
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  eq("a non-executable helper is reported", result.state, "not-executable")
  eq("and the feature stays off", Model.helperReady(result), false)
})

// Corrupt or truncated -- a partial clone, or an interrupted download.
inTemp(dir => {
  const target = path.join(dir, "bin", HOST_DIR)
  fs.mkdirSync(target, { recursive: true })
  const copy = path.join(target, "qs-bitwarden-ssh-agent")
  fs.copyFileSync(bundled, copy)
  fs.truncateSync(copy, 4096)
  fs.chmodSync(copy, 0o755)
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  check("a truncated helper is refused", result.state !== "ok", JSON.stringify(result))
  eq("the checksum is what catches it", result.checksum, "mismatch")
  eq("and the feature stays off", Model.helperReady(result), false)
  check("the message names staleness or corruption",
    /stale|corrupt|match|update/i.test(result.message), result.message)
})

// A Git LFS placeholder where the binary should be.
inTemp(dir => {
  const target = path.join(dir, "bin", HOST_DIR)
  fs.mkdirSync(target, { recursive: true })
  fs.writeFileSync(path.join(target, "qs-bitwarden-ssh-agent"),
    "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 1210560\n", { mode: 0o755 })
  fs.copyFileSync(sums, path.join(dir, "bin", "SHA256SUMS"))
  const result = inspect(dir)
  check("an LFS placeholder is refused", result.state !== "ok", JSON.stringify(result))
  eq("and the feature stays off", Model.helperReady(result), false)
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
  eq("the feature is enabled from it", Model.helperReady(result), true)
  check("no checksum is claimed for an untracked build",
    result.checksum === "unchecked", result.checksum)
})

// Both present: the shipped artifact wins, but a broken one does not strand
// a developer who has a working local build.
inTemp(dir => {
  const shipped = path.join(dir, "bin", HOST_DIR)
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

// The inspection reads the architecture from `uname -m`; a stand-in
// reports another machine.
const inspectAs = (pluginDir, machine) => {
  const fake = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-uname-"))
  try {
    fs.writeFileSync(path.join(fake, "uname"), `#!/bin/sh\necho ${machine}\n`, { mode: 0o755 })
    const cmd = Model.sshAgentHelperInspectCommand(pluginDir)
    const run = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: { PATH: fake + ":/usr/bin:/bin" } })
    return Model.parseSshAgentHelperInspection(run.stdout)
  } finally { fs.rmSync(fake, { recursive: true, force: true }) }
}

eq("the inspection reports this machine's architecture", inspect(repoRoot).arch, HOST_ARCH)

// On another architecture the panel looks in that architecture's directory,
// and a binary for this one there is refused by its machine byte.
inTemp(dir => {
  const other = HOST_ARCH === "aarch64" ? "x86_64" : "aarch64"
  const target = path.join(dir, "bin", Model.HELPER_ARCHITECTURES[other].dir)
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o755)
  const result = inspectAs(dir, other === "aarch64" ? "aarch64" : "x86_64")
  eq("a binary for another processor is refused", result.state, "wrong-architecture")
  eq("the other architecture is reported", result.arch, other)
  check("the message names the processor", /processor/.test(result.message), result.message)
  const arm64 = inspectAs(dir, other === "aarch64" ? "arm64" : "amd64")
  eq("the other spelling of the machine finds the same directory", arm64.state, "wrong-architecture")
})

// A machine no release ships: say so, rather than "missing".
inTemp(dir => {
  const result = inspectAs(dir, "riscv64")
  eq("an unshipped architecture is reported as such", result.state, "unsupported-architecture")
  eq("with no architecture to launch from", result.arch, "")
  check("the message says which builds exist and how to build one",
    /x86_64 and aarch64/.test(result.message) && /cargo build/.test(result.message), result.message)
  eq("and the feature stays off", Model.helperReady(result), false)
})

// But a local build still serves it.
inTemp(dir => {
  const target = path.join(dir, "agent", "target", "debug")
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o755)
  const result = inspectAs(dir, "riscv64")
  eq("an unshipped architecture can use a local build", result.state, "ok")
  eq("identified as the development one", result.source, "development")
  check("and it launches from its own path",
    Model.helperPath(dir, Model.SSH_AGENT_HELPER_SPEC, result.source, result.arch).endsWith("agent/target/debug/qs-bitwarden-ssh-agent"),
    JSON.stringify(result))
})

// -------------------------------------------------------------------------
// Failure isolation
// -------------------------------------------------------------------------

// SHA256SUMS lists every shipped helper. Checking the whole file would let a
// stale unlock tool disable the SSH agent -- the two features have nothing to
// do with each other, so each helper is checked against its own line only.
inTemp(dir => {
  const target = path.join(dir, "bin", HOST_DIR)
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o755)
  fs.writeFileSync(path.join(target, "qs-bitwarden-unlock-key"), "stale\n", { mode: 0o755 })
  fs.writeFileSync(path.join(dir, "bin", "SHA256SUMS"), recorded + "\n"
    + "0".repeat(64) + `  ${HOST_DIR}/qs-bitwarden-unlock-key\n`)
  const result = inspect(dir)
  eq("another helper's stale line does not disable this one", result.state, "ok")
  eq("and this one's own line still matches", result.checksum, "match")
})

// The other direction: a SHA256SUMS that simply omits this helper. A plain
// `sha256sum -c` passes for a file the list does not mention.
inTemp(dir => {
  const target = path.join(dir, "bin", HOST_DIR)
  fs.mkdirSync(target, { recursive: true })
  fs.copyFileSync(bundled, path.join(target, "qs-bitwarden-ssh-agent"))
  fs.chmodSync(path.join(target, "qs-bitwarden-ssh-agent"), 0o755)
  fs.writeFileSync(path.join(dir, "bin", "SHA256SUMS"),
    "0".repeat(64) + `  ${HOST_DIR}/qs-bitwarden-unlock-key\n`)
  const result = inspect(dir)
  eq("a checksum file with no line for this helper is a mismatch", result.checksum, "mismatch")
  eq("so the shipped helper is refused", result.state, "checksum-mismatch")
})

// The settings diagnostics live in SshAgentSettings.qml; the supervision that
// feeds them is still in Panel.qml. Both, or a check lands on whichever half
// happens to hold its pattern today.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml"]
  .map(readPluginSource)
  .join("\n")
check("the helper is inspected before the supervisor is allowed to start",
  /helperReady\(sshAgentHelper\)/.test(panelSrc), "nothing gates startup on the inspection")
check("a failed inspection disables only the agent",
  /sshAgentSupervisable[\s\S]{0,400}?helperReady\(sshAgentHelper\)|helperReady\(sshAgentHelper\)[\s\S]{0,400}?sshAgentSupervisable/.test(panelSrc),
  "the inspection result does not feed the supervisable gate")
check("the source in use is shown in the settings diagnostics",
  /sshAgentHelperSourceLabel\(/.test(panelSrc),
  "a user cannot tell whether they are running the shipped or the local helper")

done()
