#!/usr/bin/env node
// Exercise the actual paste command with a private wl-paste stand-in. Never
// connect to the session clipboard; every child has a bounded test lifetime.
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn, spawnSync } = require("child_process")
const { read, functionBody, createSuite } = require("./harness")
const { check, done } = createSuite("line-field-process")
const source = read("LineField.qml")
const pasteCommand = new Function("pasteByteCap", "pasteTimeoutSec",
  functionBody(source, "pasteCommand") + "; return pasteCommand(false)")
// Use the field's own cancellation path, rather than duplicating its signal.
const cancel = new Function("pasteProc", "finishPaste",
  "let pasteEpoch = 0; " + functionBody(source, "invalidatePaste") + "; invalidatePaste()")
// The field's destruction path, with Quickshell.execDetached run for real.
const groupKill = new Function("pasteProc", "Quickshell",
  "let pasteEpoch = 0; " + functionBody(source, "killPasteGroup") + "; killPasteGroup()")
const work = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-paste-test-"))
fs.writeFileSync(path.join(work, "wl-paste"), `#!/usr/bin/python3
import os, signal, time
with open(os.environ['QSBW_TEST_PID'], 'w') as f:
    f.write(str(os.getpid()))
if os.environ['QSBW_TEST_MODE'] == 'finite':
    os.write(1, b'x' * 100000)
else:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(1, b'partial')
    while True: time.sleep(1)
`, { mode: 0o700 })
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const active = new Set()
let runs = 0

function run(mode, duration) {
  const command = pasteCommand(65536, duration)
  const pidFile = path.join(work, mode + "-" + duration + "-" + (++runs) + ".pid")
  const proc = spawn(command[0], command.slice(1), {
    detached: true,
    env: { PATH: work + ":/usr/bin", QSBW_TEST_MODE: mode, QSBW_TEST_PID: pidFile },
    stdio: ["ignore", "pipe", "ignore"],
  })
  active.add(proc.pid)
  let output = ""
  proc.stdout.on("data", chunk => { output += chunk.toString() })
  const result = new Promise((resolve, reject) => {
    proc.on("error", reject)
    proc.on("close", (code, signal) => resolve({ code, signal, output }))
  })
  // This independent watchdog also cleans up the pre-fix orphaned pipeline.
  const guard = setTimeout(() => {
    try { process.kill(-proc.pid, "SIGKILL") } catch {}
  }, 2000)
  return { proc, pidFile, result, guard }
}

function live(pid) {
  try {
    // Zombies cannot keep reading or hold a pipe open.
    return !fs.readFileSync(`/proc/${pid}/stat`, "utf8").includes(") Z ")
  } catch { return false }
}

async function finish(job) {
  const result = await job.result
  clearTimeout(job.guard)
  const pid = Number(fs.readFileSync(job.pidFile, "utf8"))
  for (let n = 0; n < 50 && live(pid); n++) await delay(10)
  check("the clipboard child stops", !live(pid), "a producer outlived its supervisor")
  try { process.kill(-job.proc.pid, "SIGKILL") } catch {}
  active.delete(job.proc.pid)
  return result
}

async function main() {
  try {
    const finite = await finish(run("finite", 1))
    check("a finite paste succeeds", finite.code === 0, JSON.stringify(finite))
    check("the shell receives at most 64 KiB", finite.output.length === 65536, finite.output.length)

    const started = Date.now()
    const timed = await finish(run("stalled", 0.2))
    check("a stalled paste expires before the watchdog", Date.now() - started < 1500, Date.now() - started)
    check("a timeout fails instead of accepting partial output", timed.code !== 0, JSON.stringify(timed))

    const canceled = run("stalled", 10)
    for (let n = 0; n < 100 && !fs.existsSync(canceled.pidFile); n++) await delay(10)
    check("the producer started before cancellation", fs.existsSync(canceled.pidFile), canceled.pidFile)
    cancel({ running: true, signal: number => canceled.proc.kill(number) }, () => {})
    const cancelStarted = Date.now()
    const result = await finish(canceled)
    check("cancellation stops the pipeline promptly", Date.now() - cancelStarted < 1500, Date.now() - cancelStarted)
    check("cancellation is a failed paste", result.code !== 0, JSON.stringify(result))

    // Quickshell's Process destructor SIGKILLs only timeout (QProcess::kill).
    // Without the group kill the stand-in outlives it; with it, nothing does.
    for (const useGroupKill of [false, true]) {
      const job = run("stalled", 10)
      for (let n = 0; n < 100 && !fs.existsSync(job.pidFile); n++) await delay(10)
      const pid = Number(fs.readFileSync(job.pidFile, "utf8"))
      // The orphans hold stdout open, so wait for timeout's exit, not for close,
      // and disarm the watchdog that would otherwise reap them for us.
      clearTimeout(job.guard)
      const exited = new Promise(resolve => job.proc.on("exit", resolve))
      process.kill(job.proc.pid, "SIGKILL")
      await exited
      await delay(100)
      if (!useGroupKill) {
        check("SIGKILL of timeout alone orphans the clipboard child", live(pid), "the bug this guards against is gone")
      } else {
        const execDetached = argv => { spawnSync(argv[0], argv.slice(1)) }
        groupKill({ running: true, processId: job.proc.pid, payload: "x" }, { execDetached })
        for (let n = 0; n < 50 && live(pid); n++) await delay(10)
        check("the group kill reaps the clipboard child", !live(pid), "a producer outlived its field")
      }
      clearTimeout(job.guard)
      try { process.kill(-job.proc.pid, "SIGKILL") } catch {}
      active.delete(job.proc.pid)
    }
  } finally {
    for (const pid of active) { try { process.kill(-pid, "SIGKILL") } catch {} }
    fs.rmSync(work, { recursive: true, force: true })
  }
  done()
}
main().catch(error => { console.error(error); process.exitCode = 1 })
