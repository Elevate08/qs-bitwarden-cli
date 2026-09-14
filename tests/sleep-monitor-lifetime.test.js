#!/usr/bin/env node
// Exercise owner death, not timeout's process-group termination. All logind
// and inhibitor commands are stubs; these tests never inhibit or suspend Linux.
const assert = require("node:assert/strict")
const fs = require("node:fs")
const { readPluginSource } = require("./plugin-source")
const os = require("node:os")
const path = require("node:path")
const { spawn } = require("node:child_process")

const root = path.join(__dirname, "..")
const model = fs.readFileSync(path.join(root, "BitwardenModel.js"), "utf8")
const command = new Function(model.replace(/^\.pragma library\s*$/m, "")
  + "\nreturn sleepMonitorCommand()")()
const panel = readPluginSource("Panel.qml")
assert.match(panel.slice(panel.indexOf("id: sleepMonitorProc"),
  panel.indexOf("command: Model.sleepMonitorCommand()")), /stdinEnabled:\s*true/)

const work = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-lifetime-"))
const pause = ms => new Promise(resolve => setTimeout(resolve, ms))
async function until(predicate, label) {
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    if (predicate()) return
    await pause(20)
  }
  throw new Error(`Timed out: ${label}`)
}

function groupMembers(group) {
  const result = []
  for (const pid of fs.readdirSync("/proc").filter(p => /^\d+$/.test(p))) {
    try {
      const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8")
      const fields = raw.slice(raw.lastIndexOf(")") + 2).split(" ")
      // A dead child may await reaping by the host's subreaper; it no longer
      // holds descriptors or an inhibitor. Do not confuse that with a leak.
      if (Number(fields[2]) === group && fields[0] !== "Z") result.push(Number(pid))
    } catch (error) {
      if (error.code !== "ENOENT" && error.code !== "ESRCH") throw error
    }
  }
  return result
}

async function checkLifetime(mode, signal) {
  // This separate owner mirrors Quickshell's stdin pipe without letting the
  // test runner's own cleanup hide a leak when that owner is killed.
  const ownerCode = `
    const { spawn } = require('node:child_process');
    const child = spawn(${JSON.stringify(command[0])}, ${JSON.stringify(command.slice(1))},
      { stdio: ['pipe', 'ignore', 'ignore'] });
    child.on('error', e => { console.error(e); process.exit(1); });
    child.on('spawn', () => console.log(child.pid));
    child.on('exit', () => { child.stdin.destroy(); process.exit(0); });
    process.on('SIGUSR1', () => child.stdin.end());
    setInterval(() => {}, 1000);
  `
  const ready = path.join(work, `${mode}-${signal || "EOF"}.ready`)
  const owner = spawn(process.execPath, ["-e", ownerCode], {
    env: { ...process.env, PATH: `${work}:${process.env.PATH}`, QSBW_MONITOR_READY: ready },
    stdio: ["ignore", "pipe", "inherit"]
  })
  let output = ""
  let group
  owner.stdout.on("data", data => { output += data })
  try {
    await until(() => /^\d+\n/.test(output), "monitor startup")
    group = Number(output.trim())
    await until(() => fs.existsSync(ready) && fs.readFileSync(ready, "utf8").trim(), "gdbus startup")
    assert.notEqual(group, owner.pid, "monitor must have its own process group")
    const before = groupMembers(group)
    assert.ok(before.includes(group), "monitor leader owns the private group")
    assert.ok(before.includes(Number(fs.readFileSync(ready, "utf8"))), "gdbus belongs to the same group")
    if (mode === "pipe") owner.kill("SIGUSR1")
    else if (mode === "owner") owner.kill(signal)
    else process.kill(group, signal) // Only the direct child, not -group.
    await until(() => groupMembers(group).length === 0, `${mode} ${signal || "EOF"}: descendants exit`)
    console.log(`PASS ${mode} ${signal || "EOF"}: cleaned ${before.length} processes`)
  } finally {
    // Emergency cleanup is after the assertion, so it cannot make a broken
    // implementation pass. Only the private group created by this test is hit.
    if (group && groupMembers(group).length) {
      try { process.kill(-group, "SIGKILL") } catch (e) { if (e.code !== "ESRCH") throw e }
    }
    owner.kill("SIGKILL")
    owner.stdout.destroy()
  }
}

async function main() {
  fs.writeFileSync(path.join(work, "gdbus"),
    '#!/bin/bash\nprintf "%s\\n" "$$" > "$QSBW_MONITOR_READY"\nexec sleep 600\n', { mode: 0o755 })
  fs.writeFileSync(path.join(work, "systemd-inhibit"),
    '#!/bin/bash\nwhile [[ "$1" == --* ]]; do shift; done\n"$@"\n', { mode: 0o755 })
  try {
    await checkLifetime("pipe")
    for (const signal of ["SIGTERM", "SIGKILL"]) {
      await checkLifetime("child", signal)
      await checkLifetime("owner", signal)
    }
  } finally {
    fs.rmSync(work, { recursive: true, force: true })
  }
}
main().catch(error => { console.error(error); process.exitCode = 1 })
