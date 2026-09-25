#!/usr/bin/env node
// What a lock leaves behind: `bw lock` and the keyring clear are checked and
// retried rather than fired and forgotten, a suspend waits for them, turning
// "remember session" off removes the stored session, and an unload with it
// off locks.
//
//   node tests/lock-cleanup.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const Model = loadModule()
const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)
const { check, done } = createSuite("lock-cleanup")

// --- `bw lock` ---------------------------------------------------------------

check("lock and account switch both go through the checked lock",
  /requestBwLock\(\)/.test(body("lockVault")) && /requestBwLock\(\)/.test(body("leaveActiveAccount"))
    && !/lockProc\.running\s*=\s*true/.test(body("lockVault"))
    && !/lockProc\.running\s*=\s*true/.test(body("leaveActiveAccount")),
  body("lockVault") + "\n" + body("leaveActiveAccount"))
check("each lock keeps the environment it was asked with (the account being left)",
  /env:\s*bwEnv\(\)/.test(body("requestBwLock"))
    && /lockProc\.environment\s*=\s*run\.env/.test(body("runBwLockStep")),
  body("requestBwLock") + "\n" + body("runBwLockStep"))
const lockBlock = src.slice(src.indexOf("id: lockProc"), src.indexOf("id: lockProc") + 400)
check("the lock process has no environment binding a switch could change under a retry",
  !/environment:\s*root\.bwEnv\(\)/.test(lockBlock) && /onBwLockExited\(exitCode/.test(lockBlock), lockBlock)
const exited = body("onBwLockExited")
check("a failed lock is retried once, then checked with bw status",
  /run\.attempts\s*>=\s*2\)\s*run\.checking\s*=\s*true/.test(exited)
    && /Model\.statusCommand\(\)/.test(body("runBwLockStep")), exited)
check("a lock bw status still reports unlocked is reported to the user",
  /st\s*&&\s*st\.unlocked[\s\S]{0,300}errorMessage\s*=/.test(exited), exited)
check("the session held for the retry is dropped once the lock settles",
  /lockRun\s*=\s*null/.test(body("finishBwLock")) && /lockProc\.environment\s*=\s*\{\}/.test(body("finishBwLock")),
  body("finishBwLock"))

// --- the remembered session's clear ---------------------------------------------

check("the session clear's exit status is read, retried once and reported",
  /onSessionClearExited\(exitCode\)/.test(src.slice(src.indexOf("id: keyringClearProc"), src.indexOf("id: keyringClearProc") + 300))
    && /run\.attempt\s*<\s*2/.test(body("onSessionClearExited"))
    && /errorMessage\s*=/.test(body("onSessionClearExited")),
  body("onSessionClearExited"))

// The clear against a stand-in keyring: exit 0 only once nothing is left.
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-clear-"))
  try {
    const bin = path.join(dir, "bin")
    const store = path.join(dir, "store")
    fs.mkdirSync(bin)
    fs.mkdirSync(store)
    // One file per `account` attribute; `clear` can be told to fail, as a
    // locked collection's matches are skipped.
    fs.writeFileSync(path.join(bin, "secret-tool"), `#!/bin/bash
cmd="$1"; shift
account=""; while [ $# -gt 0 ]; do case "$1" in account) account="$2"; shift 2;; *) shift;; esac; done
f="$STORE_DIR/$account"
case "$cmd" in
  clear) [ -n "$KEEP" ] && exit 1; [ -f "$f" ] || exit 1; rm -f "$f" ;;
  search) [ -f "$f" ] && printf 'secret = %s\\n' "$(cat "$f")"; exit 0 ;;
  *) exit 2 ;;
esac
`, { mode: 0o755 })
    const run = (extra) => spawnSync("bash", ["-c", Model.keyringClearCommand("default")[2]],
      { env: Object.assign({ PATH: `${bin}:/usr/bin:/bin`, STORE_DIR: store }, extra || {}), encoding: "utf8" })
    fs.writeFileSync(path.join(store, "session"), "boot token")
    check("a cleared session reports success", run().status === 0, "")
    check("and it is gone", !fs.existsSync(path.join(store, "session")), "")
    check("nothing to clear is success too, not a failure", run().status === 0, "")
    fs.writeFileSync(path.join(store, "session"), "boot token")
    const kept = run({ KEEP: "1" })
    check("an entry still there after the clear is a failure", kept.status !== 0, String(kept.status))
    check("and the check prints nothing (the search output holds the secret)",
      kept.stdout === "" && !String(kept.stderr).includes("token"), JSON.stringify(kept))
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

// --- a suspend waits for the lock ---------------------------------------------------

const sleepSignal = body("onSleepSignal")
check("a suspend while unlocked locks and holds the suspend until the lock settles",
  /suspendLockPending\s*=\s*true[\s\S]*lockVault\(\)[\s\S]*maybeAckSleep\(\)/.test(sleepSignal), sleepSignal)
check("a suspend with nothing to lock is let go at once",
  /status\s*!==\s*"unlocked"\)\s*\{\s*ackSleep\(\)/.test(sleepSignal), sleepSignal)
check("the ack waits for bw lock and the keyring clear",
  /lockRun\s*!==\s*null\s*\|\|\s*lockQueue\.length\s*>\s*0/.test(body("maybeAckSleep"))
    && /sessionClearRun\s*!==\s*null\s*\|\|\s*sessionClearSlots\.length\s*>\s*0/.test(body("maybeAckSleep")),
  body("maybeAckSleep"))
check("both of them ask for the ack when they finish",
  /maybeAckSleep\(\)/.test(body("finishBwLock")) && /maybeAckSleep\(\)/.test(body("onSessionClearExited")), "")
check("the ack is written to the monitor's stdin",
  /sleepMonitorProc\.write\(Model\.sleepAckLine\(\)\)/.test(body("ackSleep")), body("ackSleep"))

// --- remember session ---------------------------------------------------------------

const rememberChanged = src.slice(src.indexOf("onRememberSessionChanged:"), src.indexOf("onRememberSessionChanged:") + 300)
check("turning remember session off removes the stored session",
  /rememberSession\)\s*return[\s\S]*requestSessionCredentialClear\(\)/.test(rememberChanged), rememberChanged)
check("and a start with it off removes one left from before",
  /if\s*\(!rememberSession\)\s*requestSessionCredentialClear\(\)/.test(body("refreshAccountCredentials")),
  body("refreshAccountCredentials"))
const destruction = src.slice(src.indexOf("Component.onDestruction:"), src.indexOf("Component.onDestruction:") + 800)
check("an unload while unlocked with the session not remembered locks bw",
  /root\.session\s*&&\s*!root\.rememberSession[\s\S]{0,120}execDetached\(\{\s*command:\s*Model\.lockCommand\(\),\s*environment:\s*root\.bwEnv\(\)/.test(destruction),
  destruction)

done()
