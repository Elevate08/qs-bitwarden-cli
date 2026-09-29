#!/usr/bin/env node
// Live smoke test of the installed plugin in your running Omarchy shell,
// driven over its IPC target. It never types, reads or prints a secret: the
// steps that need you (unlocking, copying a password) are prompts it waits
// on. Not part of CI.
//
// Checks that the vault helper runs under the shell, hardened, with the
// shipped bytes; that every `bw` the panel runs is started by the helper
// (with the session in its environment), never by the shell; that a copied
// password comes from the helper, is marked sensitive and clears on time;
// that a lock is reflected; and that the journal shows no script errors.
//
//   node tests/live/smoke.js [plugin-dir]
//
// plugin-dir defaults to ~/.config/omarchy/plugins/io.github.elevate08.qs-bitwarden-cli.

const fs = require("fs")
const os = require("os")
const path = require("path")
const crypto = require("crypto")
const { spawnSync } = require("child_process")

const pluginDir = process.argv[2] || path.join(os.homedir(), ".config/omarchy/plugins/io.github.elevate08.qs-bitwarden-cli")
const TARGET = "io.github.elevate08.qs-bitwarden-cli"
const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
const startedAt = Math.floor(Date.now() / 1000)

let passed = 0
let failed = 0
function check(label, ok, detail) {
  if (ok) { passed++; console.log(`  ok    ${label}`) }
  else { failed++; console.log(`  FAIL  ${label}${detail ? `\n        ${detail}` : ""}`) }
}
const say = text => console.log(`\n${text}`)
const run = (cmd, args) => spawnSync(cmd, args, { encoding: "utf8", timeout: 20000 })
const ipc = (...args) => String(run("omarchy-shell", [TARGET, ...args]).stdout || "").trim()

// --- processes -------------------------------------------------------------

function procs() {
  const out = []
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue
    try {
      const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8")
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
      const comm = fs.readFileSync(`/proc/${entry}/comm`, "utf8").trim()
      const cmdline = fs.readFileSync(`/proc/${entry}/cmdline`, "utf8").split("\0").filter(Boolean)
      out.push({ pid: Number(entry), ppid, comm, cmdline })
    } catch (e) {}
  }
  return out
}
function ancestors(pid, table) {
  const byPid = new Map(table.map(p => [p.pid, p]))
  const chain = []
  let p = byPid.get(pid)
  while (p && p.ppid > 1 && chain.length < 64) {
    chain.push(p.ppid)
    p = byPid.get(p.ppid)
  }
  return chain
}
const envHas = (pid, name) => {
  try { return fs.readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").some(v => v.startsWith(name + "=")) }
  catch (e) { return null }
}

function findShell(table) {
  return table.find(p => p.comm === "quickshell" && p.cmdline.includes("/usr/share/omarchy/shell"))
}
function findHelper(table, shell) {
  return table.find(p => p.ppid === shell.pid && /^qs-bitwarden-va/.test(p.comm))
}
// `bw` is a Node script: `node /usr/bin/bw ...` (or its bw.js).
const isBw = p => /(^|\/)node$/.test(p.cmdline[0] || "") && /(^|\/)(bw|bw\.js)$/.test(p.cmdline[1] || "")

// --- the steps ---------------------------------------------------------------

say("1. The helper")
let table = procs()
const shell = findShell(table)
check("the Omarchy shell is running", Boolean(shell), "no quickshell for /usr/share/omarchy/shell")
if (!shell) process.exit(1)
const helper = findHelper(table, shell)
check("the vault helper runs as the shell's child", Boolean(helper),
  "no qs-bitwarden-vault under the shell: is the plugin on a version with it, and was the shell restarted?")
if (!helper) process.exit(1)
check("it is the plugin's shipped binary", helper.cmdline[0] === path.join(pluginDir, "bin/x86_64-linux/qs-bitwarden-vault"), helper.cmdline[0])
const limits = fs.readFileSync(`/proc/${helper.pid}/limits`, "utf8")
check("its core limit is 0, soft and hard", /Max core file size\s+0\s+0\s/.test(limits), limits.split("\n").find(l => /core/.test(l)))
check("its memory and environment cannot be read (non-dumpable)", envHas(helper.pid, "PATH") === null, "")
const sums = fs.readFileSync(path.join(pluginDir, "bin/SHA256SUMS"), "utf8")
const digest = crypto.createHash("sha256").update(fs.readFileSync(path.join(pluginDir, "bin/x86_64-linux/qs-bitwarden-vault"))).digest("hex")
check("its bytes match bin/SHA256SUMS", sums.includes(`${digest}  x86_64-linux/qs-bitwarden-vault`), digest)

say("2. Unlocked")
if (ipc("status") !== "unlocked") {
  console.log("  >> Unlock the vault in the panel now (any method). Waiting up to 3 minutes...")
  for (let i = 0; i < 180 && ipc("status") !== "unlocked"; i++) sleep(1000)
}
check("the vault is unlocked", ipc("status") === "unlocked", ipc("status"))

say("3. Every bw run comes from the helper")
ipc("sync")
const seen = new Map()
for (let i = 0; i < 100; i++) {
  table = procs()
  for (const p of table.filter(isBw)) if (!seen.has(p.pid)) {
    seen.set(p.pid, { chain: ancestors(p.pid, table), session: envHas(p.pid, "BW_SESSION") })
  }
  sleep(100)
}
check("a sync started bw", seen.size > 0, "no bw process seen in 10 s")
const direct = [...seen].filter(([, v]) => !v.chain.includes(helper.pid))
check("every bw was started by the helper, none by the shell", direct.length === 0,
  direct.map(([pid, v]) => `bw ${pid}: ancestors ${v.chain.join(" <- ")}`).join("; "))
check("and got the session in its environment", [...seen.values()].some(v => v.session === true), "")

say("4. Copying a password")
const clearSec = (() => {
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), ".config/omarchy/shell.json"), "utf8"))
    const find = o => {
      if (!o || typeof o !== "object") return null
      if (o.clearClipboardSec !== undefined && JSON.stringify(o).includes("qs-bitwarden")) return o.clearClipboardSec
      for (const v of Object.values(o)) { const r = find(v); if (r !== null) return r }
      return null
    }
    const found = find(cfg)
    return Number(found === null ? 30 : found)
  } catch (e) { return 30 }
})()
const sensitive = () => /x-kde-passwordManagerHint/.test(String(run("wl-paste", ["--list-types"]).stdout || ""))
console.log("  >> In the panel, copy a password (Enter on a login). Waiting up to 2 minutes...")
let copier = null
for (let i = 0; i < 240 && !copier; i++) {
  table = procs()
  const wlcopy = table.find(p => p.comm === "wl-copy" && sensitive())
  if (wlcopy) copier = { pid: wlcopy.pid, chain: ancestors(wlcopy.pid, table) }
  else sleep(500)
}
check("a sensitive copy appeared on the clipboard", Boolean(copier), "none in 2 minutes")
if (copier) {
  check("its wl-copy was started by the helper", copier.chain.includes(helper.pid), copier.chain.join(" <- "))
  if (clearSec > 0) {
    console.log(`  .. waiting ${clearSec + 3} s for the timed clear`)
    sleep((clearSec + 3) * 1000)
    check(`the clipboard no longer holds it after ${clearSec} s`, !sensitive(), "")
  }
}

say("5. Locking")
ipc("lock")
let locked = false
for (let i = 0; i < 20 && !locked; i++) { locked = ipc("status") === "locked"; if (!locked) sleep(500) }
check("the vault locks", locked, ipc("status"))
table = procs()
check("the helper keeps running for the next unlock", Boolean(findHelper(table, shell)), "")

say("6. The journal")
const journal = String(run("journalctl", ["--user", "--since", `@${startedAt}`, "--no-pager", "-o", "cat"]).stdout || "")
const bad = journal.split("\n").filter(l => /ReferenceError|TypeError|is not a function|Crash protection is off|vault helper (exited|refused)/.test(l))
check("no script errors or helper trouble since this test started", bad.length === 0, bad.slice(0, 5).join("\n        "))

console.log(`\nlive smoke: ${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
