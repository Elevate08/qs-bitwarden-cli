#!/usr/bin/env node
// End to end, GHSA-wrwr-vr5r-56hv #1: what a shell crash with the vault open
// leaves in its core dump. A headless shell (shell.js) signs in to a fake
// account whose item carries marker secrets, then is crashed with SIGSEGV,
// and its core, fetched with `coredumpctl`, is searched for them.
//
// - With the vault helper: the session key, the password and the note are
//   not in the shell's core, while text the shell does hold (the item's
//   name) is, so the core is real. A crashed helper leaves no core at all.
// - Opening the item and not revealing anything leaves the password and the
//   note out of the core too; revealing one field puts only that field in.
// - Without it (the fallback): they are in the core, which shows this test
//   can see a leak.
//
// Needs systemd-coredump (core_pattern piping to it) and `coredumpctl`, plus
// what shell.js needs. The cores it creates hold only fake secrets. Not run
// in CI: a container has no systemd-coredump.
//
//   node tests/e2e/crash.e2e.js
//
// The secrets it looks for are handed to the fake `bw` in files, not through
// the shell's environment: a core includes the environment.

const { createSuite, repoRoot } = require("../harness")
const { createShell, sleep } = require("./shell")
const fs = require("fs")
const path = require("path")
const crypto = require("crypto")
const { spawnSync } = require("child_process")

const { check, done, failures } = createSuite("e2e-crash")

const pattern = fs.readFileSync("/proc/sys/kernel/core_pattern", "utf8")
if (!/systemd-coredump/.test(pattern) || spawnSync("coredumpctl", ["--version"]).status !== 0) {
  console.error("e2e-crash: needs systemd-coredump and coredumpctl")
  process.exit(1)
}

const marker = label => `qsbw-crash-${label}-${crypto.randomBytes(6).toString("hex")}`

// In the shell's memory a secret may be UTF-8 (process I/O) or UTF-16 (a
// QML/JavaScript string): look for both.
function contains(core, text) {
  return core.includes(Buffer.from(text, "utf8")) || core.includes(Buffer.from(text, "utf16le"))
}

// Quickshell's own crash handler forks to report a crash, and systemd keeps
// the core under the pid it names in the shell's log.
function crashedPid(shellLog) {
  for (let i = 0; i < 120; i++) {
    const m = /Quickshell has crashed under pid (\d+)/.exec(fs.readFileSync(shellLog, "utf8"))
    if (m) return Number(m[1])
    sleep(250)
  }
  return 0
}

// The core systemd-coredump kept for `pid`, once it has processed it.
function fetchCore(pid, into) {
  for (let i = 0; i < 120; i++) {
    const r = spawnSync("coredumpctl", ["dump", String(pid), "--output", into, "--no-pager", "-q"], { encoding: "utf8" })
    if (r.status === 0 && fs.existsSync(into) && fs.statSync(into).size > 0) return fs.readFileSync(into)
    sleep(500)
  }
  return null
}

function hasCoreEntry(pid) {
  const r = spawnSync("coredumpctl", ["list", String(pid), "--no-pager", "--no-legend"], { encoding: "utf8" })
  return r.status === 0 && r.stdout.trim() !== ""
}

function childHelperPid(parent) {
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue
    try {
      const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8")
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
      if (ppid === parent && /^qs-bitwarden-va/.test(fs.readFileSync(`/proc/${entry}/comm`, "utf8"))) return Number(entry)
    } catch (e) {}
  }
  return 0
}

// The plugin without its vault helper, for the fallback run.
function pluginWithoutHelper(into) {
  fs.cpSync(repoRoot, into, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      return !/^\.git(\/|$)/.test(rel) && !/(^|\/)target(\/|$)/.test(rel)
        && rel !== "bin/x86_64-linux/qs-bitwarden-vault"
    }
  })
  return into
}

// `reveal`: what the person does with the item before the crash: nothing
// (null), or opens it and reveals this field ("password" or "notes").
// `openOnly`: opens it and reveals nothing.
// The plugin with the helper built in vault/target/debug in place of the
// shipped one, which is rebuilt by CI and so may lack a newer request.
function pluginWithLocalHelper(into) {
  const built = "vault/target/debug/qs-bitwarden-vault"
  if (!fs.existsSync(path.join(repoRoot, built))) {
    console.error("e2e-crash: build the helper first: cargo build --manifest-path vault/Cargo.toml --locked")
    process.exit(1)
  }
  fs.cpSync(repoRoot, into, {
    recursive: true,
    filter: src => {
      const rel = path.relative(repoRoot, src)
      if (/^\.git(\/|$)/.test(rel) || rel === "bin/x86_64-linux/qs-bitwarden-vault") return false
      if (/(^|\/)target(\/|$)/.test(rel)) return ["vault/target", "vault/target/debug", built].includes(rel)
      return true
    }
  })
  return into
}

function run(label, plugin, withHelper, reveal = null, openOnly = false) {
  const secrets = { password: marker("password"), note: marker("note") }
  const shell = createShell("e2e-crash", check, { plugin, coreDumps: true })
  // Given to the fake bw in its data directory, never through the shell's
  // environment (which a core includes).
  const data = path.join(shell.home, ".config", "Bitwarden CLI")
  fs.mkdirSync(data, { recursive: true })
  fs.writeFileSync(path.join(data, "fake-item-password"), secrets.password)
  fs.writeFileSync(path.join(data, "fake-item-notes"), secrets.note)
  const corePath = path.join(shell.root, "shell.core")
  let failed = null
  try {
    shell.start()
    // Unlocking runs only while the panel is open, as a person would.
    shell.q("open")
    shell.q("login", "a@x", "pw-a@x")
    shell.expect(`${label}: signed in`, s => s.status === "unlocked" && s.items.join() === "Login of a@x")
    shell.expect(`${label}: the vault helper is ${withHelper ? "up" : "not used"}`,
      s => s.helper === (withHelper ? "active" : "fallback"))
    const session = fs.readFileSync(path.join(data, "fake-session"), "utf8").trim()
    check(`${label}: bw minted a session key`, session.length >= 32, session.length)

    if (withHelper) {
      // The helper itself: SIGSEGV, and nothing may be kept for it.
      const helper = childHelperPid(shell.pid())
      check(`${label}: the helper runs under the shell`, helper > 0, "")
      if (helper) {
        process.kill(helper, "SIGSEGV")
        sleep(3000)
        check(`${label}: a crashed helper leaves no core dump`, !hasCoreEntry(helper), `pid ${helper}`)
      }
      // Losing it locks the vault; it restarts, and the vault unlocks again.
      shell.expect(`${label}: losing the helper locks the vault`, s => s.status === "locked")
      shell.expect(`${label}: the helper comes back`, s => s.helper === "active")
      shell.q("unlock", "pw-a@x")
      shell.expect(`${label}: and the vault unlocks again`, s => s.status === "unlocked" && s.items.length === 1)
    }
    const key = fs.readFileSync(path.join(data, "fake-session"), "utf8").trim()
    if (openOnly || reveal) {
      shell.q("openFirst")
      shell.expect(`${label}: the item is open`, s => s.screen === "detail" && s.detail && s.detail.name === "Login of a@x")
      if (reveal) {
        shell.q("reveal", reveal)
        shell.expect(`${label}: the ${reveal} is revealed`, s => s.revealed.includes(reveal))
      }
      const open = shell.state()
      check(`${label}: ${withHelper ? "the detail is the secret-free view" : "the detail is built from the list"}`,
        open.detail.withheld === withHelper, JSON.stringify(open.detail))
    }

    process.kill(shell.pid(), "SIGSEGV")
    const pid = crashedPid(shell.shellLog)
    const core = pid ? fetchCore(pid, corePath) : null
    check(`${label}: the shell's crash left a core dump`, core !== null, `no core for pid ${pid}`)
    if (core) {
      check(`${label}: the core holds what the shell does (the item's name)`, contains(core, "Login of a@x"), "")
      const expected = withHelper ? false : true
      check(`${label}: the session key is ${expected ? "" : "not "}in the core`, contains(core, key) === expected, "")
      // With the helper only a revealed value may be there; without it, both.
      const inCore = name => withHelper ? reveal === name : true
      check(`${label}: the password is ${inCore("password") ? "" : "not "}in the core`,
        contains(core, secrets.password) === inCore("password"), "")
      check(`${label}: the note is ${inCore("notes") ? "" : "not "}in the core`,
        contains(core, secrets.note) === inCore("notes"), "")
    }
  } catch (e) {
    failed = e
    check(`${label}: ran to the end`, false, String(e && e.message))
  } finally {
    if (failed || failures.length) console.error(`--- ${label} shell log (tail) ---\n` + shell.logTail())
    try { fs.rmSync(corePath, { force: true }) } catch (e) {}
    shell.cleanup()
  }
}

run("helper", repoRoot, true)
const local = fs.mkdtempSync("/tmp/qsbw-crash-local-")
try {
  const plugin = pluginWithLocalHelper(path.join(local, "plugin"))
  run("helper, item opened", plugin, true, null, true)
  run("helper, password revealed", plugin, true, "password")
  run("helper, notes revealed", plugin, true, "notes")
} finally {
  fs.rmSync(local, { recursive: true, force: true })
}
const copy = fs.mkdtempSync("/tmp/qsbw-crash-plugin-")
try {
  run("fallback", pluginWithoutHelper(path.join(copy, "plugin")), false)
} finally {
  fs.rmSync(copy, { recursive: true, force: true })
}
done()
