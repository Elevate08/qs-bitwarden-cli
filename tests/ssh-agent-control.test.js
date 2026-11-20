#!/usr/bin/env node
// Supervision of the SSH companion, which the panel never waits on: path
// resolution, the minimal environment, the bounded NDJSON reader and the
// restart state machine, then the handshake with the real helper.
//
//   node tests/ssh-agent-control.test.js

const { createSuite, loadModule, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn } = require("child_process")

const Model = loadModule()

const { check, eq, done, failures } = createSuite("ssh-agent-control")

// -------------------------------------------------------------------------
// Absolute, plugin-relative helper path
// -------------------------------------------------------------------------

eq("plugin dir from a file URL",
  Model.pluginDirFromUrl("file:///home/u/.config/omarchy/plugins/bw/"),
  "/home/u/.config/omarchy/plugins/bw")
eq("plugin dir keeps a percent-encoded segment",
  Model.pluginDirFromUrl("file:///home/u/my%20plugins/bw/"), "/home/u/my plugins/bw")
eq("plugin dir accepts a bare absolute path", Model.pluginDirFromUrl("/opt/bw/"), "/opt/bw")
eq("plugin dir refuses a non-file scheme", Model.pluginDirFromUrl("qrc:/bw/"), "")
eq("plugin dir refuses an encoded traversal", Model.pluginDirFromUrl("file:///opt/bw/%2e%2e/etc/"), "")
eq("plugin dir refuses a non-string", Model.pluginDirFromUrl(null), "")

eq("plugin dir loses trailing slashes", Model.cleanAbsoluteDir("/opt/bw//"), "/opt/bw")
eq("plugin dir refuses a relative path", Model.cleanAbsoluteDir("opt/bw"), "")
eq("plugin dir refuses a dot segment", Model.cleanAbsoluteDir("/opt/../etc"), "")

// The source is chosen by the bundle inspection (see ssh-agent-bundle.test.js),
// and the command follows it rather than guessing. Launching an unvetted
// binary would defeat the point of inspecting one.
const helperCmd = Model.sshAgentHelperCommand("/opt/bw", "development")
eq("helper runs directly with no shell and no arguments", helperCmd.length, 1)
eq("helper command is the absolute helper path", helperCmd[0],
  "/opt/bw/agent/target/debug/qs-bitwarden-ssh-agent")
eq("the shipped helper is launched when that is what was accepted",
  Model.sshAgentHelperCommand("/opt/bw", "bundled", "x86_64")[0],
  "/opt/bw/bin/x86_64-linux/qs-bitwarden-ssh-agent")
eq("on aarch64, its own build",
  Model.sshAgentHelperCommand("/opt/bw", "bundled", "aarch64")[0],
  "/opt/bw/bin/aarch64-linux/qs-bitwarden-ssh-agent")
eq("the shipped helper with no reported architecture launches nothing",
  Model.sshAgentHelperCommand("/opt/bw", "bundled", "").length, 0)
eq("no accepted source launches nothing", Model.sshAgentHelperCommand("/opt/bw", "").length, 0)
eq("helper command is empty without a plugin dir", Model.sshAgentHelperCommand("", "bundled").length, 0)

// -------------------------------------------------------------------------
// Minimal environment
// -------------------------------------------------------------------------

const env = Model.sshAgentHelperEnv("/run/user/1000")
eq("helper environment carries only XDG_RUNTIME_DIR", Object.keys(env).sort().join(","), "XDG_RUNTIME_DIR")
eq("helper environment points at the runtime dir", env.XDG_RUNTIME_DIR, "/run/user/1000")
eq("helper environment refuses a relative runtime dir", Model.sshAgentHelperEnv("run/user/1000"), null)

// -------------------------------------------------------------------------
// Bounded NDJSON reader
// -------------------------------------------------------------------------

eq("hello is the versioned v1 handshake", Model.sshAgentHelloLine(), '{"v":1,"type":"hello"}\n')
eq("shutdown is a versioned v1 line", Model.sshAgentShutdownLine(), '{"v":1,"type":"shutdown"}\n')

eq("an empty line is ignored rather than fatal", Model.parseAgentEvent("").code, "EMPTY")
eq("malformed JSON fails closed", Model.parseAgentEvent("{not json").code, "MALFORMED")
eq("a wrong version fails closed", Model.parseAgentEvent('{"v":2,"type":"ready"}').code, "VERSION_MISMATCH")
eq("a missing version fails closed", Model.parseAgentEvent('{"type":"ready"}').code, "VERSION_MISMATCH")
eq("an unknown type fails closed", Model.parseAgentEvent('{"v":1,"type":"exec"}').code, "UNKNOWN_TYPE")
eq("a non-object line fails closed", Model.parseAgentEvent('"ready"').code, "MALFORMED")
eq("a ready missing its socket path fails closed",
  Model.parseAgentEvent('{"v":1,"type":"ready","fifoPath":"/f","agentVersion":"1"}').code, "MALFORMED")

const overlong = '{"v":1,"type":"error","message":"' + "x".repeat(Model.SSH_AGENT_MAX_LINE_BYTES) + '"}'
eq("an overlong line fails closed before parsing", Model.parseAgentEvent(overlong).code, "LINE_TOO_LONG")
const multibyte = '{"v":1,"type":"error","message":"' + "é".repeat(Model.SSH_AGENT_MAX_LINE_BYTES - 100) + '"}'
eq("the line cap counts bytes, not characters", Model.parseAgentEvent(multibyte).code, "LINE_TOO_LONG")
const justUnder = JSON.stringify({ v: 1, type: "error", code: "X", message: "y".repeat(1024), recoverable: true })
eq("a line under the cap still parses", Model.parseAgentEvent(justUnder).ok, true)

// -------------------------------------------------------------------------
// Supervision state machine
// -------------------------------------------------------------------------

const readyLine = JSON.stringify({
  v: 1, type: "ready", socketPath: "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock",
  fifoPath: "/run/user/1000/qs-bitwarden-cli/ssh-keys.fifo", agentVersion: "0.1.0"
})

function drive(state, events) {
  const actions = []
  for (const ev of events) {
    const step = Model.sshAgentReduce(state, ev)
    state = step.state
    actions.push(step.action)
  }
  return { state, actions, last: actions[actions.length - 1] }
}

function reachReady(t) {
  return drive(Model.sshAgentInitialState(), [
    { kind: "enabled", value: true, nowMs: t },
    { kind: "started", nowMs: t + 1 },
    { kind: "line", line: readyLine, nowMs: t + 2 }
  ])
}

const initial = Model.sshAgentInitialState()
eq("the supervisor starts disabled", initial.phase, "disabled")
check("the signing gate starts closed", initial.gateOpen === false, JSON.stringify(initial))

const inert = drive(Model.sshAgentInitialState(), [
  { kind: "started", nowMs: 0 },
  { kind: "line", line: readyLine, nowMs: 1 },
  { kind: "exited", exitCode: 1, nowMs: 2 },
  { kind: "restartTimer", nowMs: 3 }
])
eq("disabled mode stays disabled", inert.state.phase, "disabled")
check("disabled mode starts nothing", inert.actions.every(a => !a.start && !a.writeHello),
  JSON.stringify(inert.actions))
check("disabled mode never opens the gate", inert.state.gateOpen === false, JSON.stringify(inert.state))

const enabled = drive(Model.sshAgentInitialState(), [{ kind: "enabled", value: true, nowMs: 0 }])
eq("enabling starts the helper", enabled.last.start, true)
eq("enabling moves to starting", enabled.state.phase, "starting")
check("enabling does not open the gate before the handshake", enabled.state.gateOpen === false,
  JSON.stringify(enabled.state))

const handshaking = drive(enabled.state, [{ kind: "started", nowMs: 1 }])
eq("a started helper is sent hello", handshaking.last.writeHello, true)
eq("a started helper is handshaking", handshaking.state.phase, "handshaking")
check("the gate stays closed while handshaking", handshaking.state.gateOpen === false,
  JSON.stringify(handshaking.state))

const live = reachReady(0)
eq("a v1 ready completes the handshake", live.state.phase, "ready")
check("ready opens the signing gate", live.state.gateOpen === true, JSON.stringify(live.state))
eq("ready records the socket path", live.state.socketPath, "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock")
eq("ready records the fifo path", live.state.fifoPath, "/run/user/1000/qs-bitwarden-cli/ssh-keys.fifo")
eq("ready records the agent version", live.state.agentVersion, "0.1.0")
check("no reduction ever asks QML to wait",
  live.actions.every(a => !("wait" in a) && !("waitMs" in a)), JSON.stringify(live.actions))

const garbage = drive(reachReady(0).state, [{ kind: "line", line: "not json at all", nowMs: 100 }])
eq("a malformed line closes the gate", garbage.state.gateOpen, false)
eq("a malformed line stops the helper", garbage.last.stop, true)
eq("a malformed line is reported", garbage.state.errorCode, "MALFORMED")

const blank = drive(reachReady(0).state, [{ kind: "line", line: "", nowMs: 100 }])
eq("a blank line is ignored", blank.state.phase, "ready")
check("a blank line leaves the gate open", blank.state.gateOpen === true, JSON.stringify(blank.state))

const loadFailed = drive(reachReady(0).state, [{
  kind: "line", nowMs: 100,
  line: JSON.stringify({ v: 1, type: "load_failed", epoch: 7 })
}])
eq("a load failure stays ready so the panel can retry", loadFailed.state.phase, "ready")
eq("a load failure reaches the panel", loadFailed.last.message.type, "load_failed")
check("a load failure does not close the signing gate", loadFailed.state.gateOpen === true,
  JSON.stringify(loadFailed.state))

const secondReady = drive(reachReady(0).state, [{ kind: "line", line: readyLine, nowMs: 100 }])
eq("a duplicate ready is a protocol violation", secondReady.state.errorCode, "PROTOCOL")
check("a duplicate ready closes the gate", secondReady.state.gateOpen === false,
  JSON.stringify(secondReady.state))

const earlyEvent = drive(handshaking.state, [{
  kind: "line", nowMs: 5, line: JSON.stringify({ v: 1, type: "locked", epoch: 1 })
}])
eq("an event before ready is a protocol violation", earlyEvent.state.errorCode, "PROTOCOL")

const stalled = drive(handshaking.state, [{ kind: "handshakeTimeout", nowMs: 9999 }])
eq("a stalled handshake is bounded", stalled.state.errorCode, "HANDSHAKE_TIMEOUT")
eq("a stalled handshake stops the helper", stalled.last.stop, true)
check("a stalled handshake keeps the gate closed", stalled.state.gateOpen === false,
  JSON.stringify(stalled.state))

const eof = drive(reachReady(0).state, [{ kind: "exited", exitCode: 0, nowMs: 100 }])
eq("stdout EOF closes the gate", eof.state.gateOpen, false)
eq("stdout EOF schedules a restart", eof.last.restartInMs, Model.sshAgentRestartDelayMs(1))
eq("stdout EOF backs off", eof.state.phase, "backoff")

const restarted = drive(eof.state, [{ kind: "restartTimer", nowMs: 200 }])
eq("the backoff timer restarts the helper", restarted.last.start, true)
eq("the backoff timer returns to starting", restarted.state.phase, "starting")

eq("backoff step 1", Model.sshAgentRestartDelayMs(1), 500)
eq("backoff step 3", Model.sshAgentRestartDelayMs(3), 2000)
check("backoff is capped", Model.sshAgentRestartDelayMs(50) === 30000,
  String(Model.sshAgentRestartDelayMs(50)))
check("backoff never goes negative", Model.sshAgentRestartDelayMs(0) >= 0,
  String(Model.sshAgentRestartDelayMs(0)))

// A crash loop: every run dies immediately, so nothing ever counts as healthy.
let loop = Model.sshAgentInitialState()
let loopActions = []
let clock = 0
loop = Model.sshAgentReduce(loop, { kind: "enabled", value: true, nowMs: clock }).state
for (let i = 0; i < Model.SSH_AGENT_MAX_RESTARTS + 2; i++) {
  clock += 10
  loop = Model.sshAgentReduce(loop, { kind: "started", nowMs: clock }).state
  clock += 10
  const step = Model.sshAgentReduce(loop, { kind: "exited", exitCode: 101, nowMs: clock })
  loop = step.state
  loopActions.push(step.action)
  if (loop.phase !== "backoff") break
  clock += 10
  loop = Model.sshAgentReduce(loop, { kind: "restartTimer", nowMs: clock }).state
}
eq("a crash loop stops restarting", loop.phase, "failed")
eq("a crash loop is reported", loop.errorCode, "CRASH_LOOP")
check("a crash loop leaves the gate closed", loop.gateOpen === false, JSON.stringify(loop))
eq("a crash loop schedules no further restart", loopActions[loopActions.length - 1].restartInMs, -1)
check("a crash loop is bounded by the restart cap",
  loopActions.filter(a => a.restartInMs > 0).length === Model.SSH_AGENT_MAX_RESTARTS,
  String(loopActions.filter(a => a.restartInMs > 0).length))

const failedIgnores = drive(loop, [
  { kind: "restartTimer", nowMs: clock + 1000 },
  { kind: "started", nowMs: clock + 1001 }
])
eq("a failed supervisor stays failed", failedIgnores.state.phase, "failed")
check("a failed supervisor starts nothing", failedIgnores.actions.every(a => !a.start),
  JSON.stringify(failedIgnores.actions))

// The real-world loop: start, handshake, die, repeat. A handshake must not
// reset the failure count, or such a helper restarts forever.
{
  let crashy = Model.sshAgentInitialState()
  let scheduled = 0
  let t = 0
  crashy = Model.sshAgentReduce(crashy, { kind: "enabled", value: true, nowMs: t }).state
  for (let i = 0; i < Model.SSH_AGENT_MAX_RESTARTS + 3; i++) {
    t += 10
    crashy = Model.sshAgentReduce(crashy, { kind: "started", nowMs: t }).state
    t += 10
    crashy = Model.sshAgentReduce(crashy, { kind: "line", line: readyLine, nowMs: t }).state
    // Serves for well under the healthy threshold, then dies.
    t += 1500
    const step = Model.sshAgentReduce(crashy, { kind: "exited", exitCode: 137, nowMs: t })
    crashy = step.state
    if (step.action.restartInMs >= 0) scheduled++
    if (crashy.phase !== "backoff") break
    t += 10
    crashy = Model.sshAgentReduce(crashy, { kind: "restartTimer", nowMs: t }).state
  }
  eq("a helper that handshakes then dies still trips the bound", crashy.phase, "failed")
  eq("that loop is bounded by the same restart cap", scheduled, Model.SSH_AGENT_MAX_RESTARTS)
}

// -------------------------------------------------------------------------
// Served elsewhere
// -------------------------------------------------------------------------
//
// A helper that loses the runtime lock to another process exits like a crash;
// the panel probes the lock, and a held lock is its own state, not CRASH_LOOP.

const retryElsewhere = Model.SSH_AGENT_ELSEWHERE_RETRY_MS
check("the elsewhere retry is slow, not a backoff step",
  retryElsewhere >= 10000 && retryElsewhere <= 120000, String(retryElsewhere))

const elsewhere = drive(enabled.state, [
  { kind: "started", nowMs: 1 },
  { kind: "exited", exitCode: 1, lockHeld: true, nowMs: 2 }
])
eq("a start that lost the lock is served elsewhere", elsewhere.state.phase, "elsewhere")
eq("and says so", elsewhere.state.errorCode, "ELSEWHERE")
eq("it does not count as a failure", elsewhere.state.failures, 0)
eq("it retries on the slow interval", elsewhere.last.restartInMs, retryElsewhere)
check("the gate stays closed and nothing is claimed", elsewhere.state.gateOpen === false
  && elsewhere.state.socketPath === "" && elsewhere.state.fifoPath === "", JSON.stringify(elsewhere.state))

let patient = elsewhere.state
for (let i = 0; i < Model.SSH_AGENT_MAX_RESTARTS * 3; i++) {
  patient = Model.sshAgentReduce(patient, { kind: "restartTimer", nowMs: 10 + i * 2 }).state
  patient = Model.sshAgentReduce(patient, { kind: "started", nowMs: 11 + i * 2 }).state
  patient = Model.sshAgentReduce(patient, { kind: "exited", exitCode: 1, lockHeld: true, nowMs: 12 + i * 2 }).state
}
eq("waiting on another agent never becomes a crash loop", patient.phase, "elsewhere")
eq("however long it waits", patient.failures, 0)

const retried = drive(elsewhere.state, [{ kind: "restartTimer", nowMs: 100 }])
eq("the retry starts the helper again", retried.last.start, true)
eq("from the starting phase", retried.state.phase, "starting")

const freed = drive(elsewhere.state, [
  { kind: "restartTimer", nowMs: 100 },
  { kind: "started", nowMs: 101 },
  { kind: "line", line: readyLine, nowMs: 102 }
])
eq("once the lock is free the helper comes up normally", freed.state.phase, "ready")
eq("and the elsewhere message clears", freed.state.errorCode, "")

const realCrash = drive(elsewhere.state, [
  { kind: "restartTimer", nowMs: 100 },
  { kind: "started", nowMs: 101 },
  { kind: "exited", exitCode: 1, lockHeld: false, nowMs: 102 }
])
eq("a failure with the lock free is an ordinary failure", realCrash.state.phase, "backoff")
eq("and counts", realCrash.state.failures, 1)

const afterReady = drive(reachReady(0).state, [{ kind: "exited", exitCode: 1, lockHeld: true, nowMs: 5 }])
eq("a run that reached ready cannot have lost the lock, whatever the probe says", afterReady.state.phase, "backoff")

const elsewhereSetup = Model.sshAgentSetupState({ enabled: true, supervisable: true, phase: "elsewhere", errorCode: "ELSEWHERE" })
check("settings explain that another process is serving the agent",
  elsewhereSetup.state === "error" && /another/i.test(elsewhereSetup.message) && !/keeps failing/i.test(elsewhereSetup.message),
  JSON.stringify(elsewhereSetup))

// The probe itself, against a real lock.
check("no runtime directory, no probe", Model.sshAgentLockProbeCommand("") === null
  && Model.sshAgentLockProbeCommand("relative/dir") === null, "expected null")
check("only the probe's conflict code means held",
  Model.sshAgentLockHeld(75) === true && Model.sshAgentLockHeld(0) === false
    && Model.sshAgentLockHeld(1) === false && Model.sshAgentLockHeld(127) === false, "exit codes")
{
  const { spawnSync } = require("child_process")
  const rt = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-lock-"))
  const dir = path.join(rt, "qs-bitwarden-cli")
  const lock = path.join(dir, "ssh-agent.lock")
  const probe = () => {
    const cmd = Model.sshAgentLockProbeCommand(rt)
    return spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8" }).status
  }
  try {
    fs.mkdirSync(dir, { mode: 0o700 })
    check("a missing lock file reads as free", Model.sshAgentLockHeld(probe()) === false, "expected free")
    check("and the probe does not create it -- the helper refuses a lock file it did not make 0600",
      !fs.existsSync(lock), "probe created the lock file")
    fs.writeFileSync(lock, "", { mode: 0o600 })
    check("an unheld lock reads as free", Model.sshAgentLockHeld(probe()) === false, "expected free")
    const holder = spawnSync("bash", ["-c", `flock -n "$1" bash -c 'echo held' ; true`, "_", lock], { encoding: "utf8" })
    check("the test can take the lock at all", /held/.test(holder.stdout), holder.stderr)
    const held = require("child_process").spawn("flock", [lock, "sleep", "5"], { stdio: "ignore" })
    const until = Date.now() + 3000
    let heldCode = 0
    while (Date.now() < until) {
      heldCode = probe()
      if (Model.sshAgentLockHeld(heldCode)) break
      spawnSync("sleep", ["0.05"])
    }
    check("a lock held by another process reads as held", Model.sshAgentLockHeld(heldCode) === true, "exit " + heldCode)
    held.kill("SIGKILL")
    const statAfter = fs.statSync(lock)
    check("probing leaves the lock file's mode alone", (statAfter.mode & 0o777) === 0o600, (statAfter.mode & 0o777).toString(8))
    fs.rmSync(lock)
    fs.symlinkSync("/etc/hostname", lock)
    check("a symlinked lock is never opened", Model.sshAgentLockHeld(probe()) === false, "expected free without following")
  } finally {
    fs.rmSync(rt, { recursive: true, force: true })
  }
}

{
  const vaultSrc = readPluginSource("Panel.qml")
  check("the helper's exit goes through the lock probe rather than straight to the reducer",
    /id: sshAgentProc[\s\S]{0,900}onExited: function\(exitCode\) \{\s*sshAgentTerminateTimer\.stop\(\)\s*root\.onSshAgentHelperExited\(exitCode\)/.test(vaultSrc),
    "sshAgentProc.onExited must call onSshAgentHelperExited")
  check("the probe's answer travels with the exit it explains",
    /id: sshAgentLockProbeProc[\s\S]{0,300}kind: "exited", exitCode: root\.sshAgentPendingExitCode,\s*lockHeld: Model\.sshAgentLockHeld\(exitCode\)/.test(vaultSrc),
    "probe exit must report lockHeld")
}

// A helper that ran healthily for a long time is not a crash loop.
const healthy = drive(reachReady(0).state, [{ kind: "exited", exitCode: 0, nowMs: 10 * 60 * 1000 }])
eq("a long healthy run resets the backoff", healthy.last.restartInMs, Model.sshAgentRestartDelayMs(1))
eq("a long healthy run keeps supervising", healthy.state.phase, "backoff")

const disabledMidflight = drive(reachReady(0).state, [{ kind: "enabled", value: false, nowMs: 100 }])
eq("disabling stops the helper", disabledMidflight.last.stop, true)
eq("disabling cancels a pending restart", disabledMidflight.last.cancelRestart, true)
eq("disabling returns to disabled", disabledMidflight.state.phase, "disabled")
check("disabling closes the gate", disabledMidflight.state.gateOpen === false,
  JSON.stringify(disabledMidflight.state))

const reEnabled = drive(loop, [{ kind: "enabled", value: false, nowMs: 1 }, { kind: "enabled", value: true, nowMs: 2 }])
eq("re-enabling clears the crash-loop failure", reEnabled.state.errorCode, "")
eq("re-enabling starts the helper again", reEnabled.last.start, true)

const stoppingExit = drive(garbage.state, [{ kind: "exited", exitCode: 143, nowMs: 200 }])
eq("an exit after a protocol stop still backs off", stoppingExit.state.phase, "backoff")
eq("an exit after a protocol stop keeps its error", stoppingExit.state.errorCode, "MALFORMED")

// -------------------------------------------------------------------------
// Real child processes
// -------------------------------------------------------------------------

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-agent-"))
const runtimeDir = path.join(tmpRoot, "run")
fs.mkdirSync(runtimeDir, { mode: 0o700 })

function runHelper(command, environment, opts) {
  return new Promise(resolve => {
    const child = spawn(command[0], command.slice(1), {
      env: environment, stdio: ["pipe", "pipe", "pipe"]
    })
    let state = Model.sshAgentInitialState()
    state = Model.sshAgentReduce(state, { kind: "enabled", value: true, nowMs: 0 }).state
    let buffered = ""
    let settled = false
    // The state at the moment the handshake landed. The exit that follows
    // clears the helper's advertised paths by design, so what `ready` carried
    // has to be captured while it is still true.
    let readyState = null
    const messages = []
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(guard)
      try { child.kill("SIGKILL") } catch (e) {}
      resolve({ state, readyState, messages })
    }
    const guard = setTimeout(finish, 5000)

    const started = Model.sshAgentReduce(state, { kind: "started", nowMs: 1 })
    state = started.state
    if (started.action.writeHello) child.stdin.write(Model.sshAgentHelloLine())

    child.stdout.on("data", chunk => {
      buffered += chunk.toString("utf8")
      let nl
      while ((nl = buffered.indexOf("\n")) >= 0) {
        const line = buffered.slice(0, nl)
        buffered = buffered.slice(nl + 1)
        const step = Model.sshAgentReduce(state, { kind: "line", line: line, nowMs: Date.now() })
        state = step.state
        if (step.action.message) messages.push(step.action.message)
        if (step.action.stop) { try { child.kill("SIGTERM") } catch (e) {} }
        if (state.phase === "ready" && !readyState) {
          readyState = state
          if (opts && opts.stopOnReady) child.stdin.end()
        }
      }
    })
    child.on("exit", code => {
      state = Model.sshAgentReduce(state, { kind: "exited", exitCode: code, nowMs: Date.now() }).state
      finish()
    })
    child.on("error", () => finish())
  })
}

const realHelper = path.join(repoRoot, "agent", "target", "debug", "qs-bitwarden-ssh-agent")

async function processTests() {
  if (fs.existsSync(realHelper)) {
    const realRun = await runHelper([realHelper], Model.sshAgentHelperEnv(runtimeDir), { stopOnReady: true })
    check("the real helper completes the v1 handshake with only XDG_RUNTIME_DIR",
      realRun.readyState !== null, JSON.stringify(realRun.state))
    const readyReal = realRun.readyState || { socketPath: "", fifoPath: "", agentVersion: "" }
    check("the real helper reported a socket under the runtime dir",
      readyReal.socketPath.indexOf(runtimeDir) === 0,
      readyReal.socketPath + " (expected under " + runtimeDir + ")")
    check("the real helper reported a fifo under the runtime dir",
      readyReal.fifoPath.indexOf(runtimeDir) === 0,
      readyReal.fifoPath + " (expected under " + runtimeDir + ")")
    check("the real helper reported a version", /^\d+\.\d+\.\d+$/.test(readyReal.agentVersion),
      readyReal.agentVersion)
    check("closing stdin exits the real helper", realRun.state.phase === "backoff",
      "phase " + realRun.state.phase)
    eq("the real helper leaves the gate closed once it is gone", realRun.state.gateOpen, false)
    check("the real helper removed its socket on the way out",
      !fs.existsSync(readyReal.socketPath), "socket still present at " + readyReal.socketPath)
  } else {
    failures.push("the real helper binary is missing\n    build it with: cargo build --manifest-path agent/Cargo.toml --locked")
  }
}

// -------------------------------------------------------------------------
// The ordinary vault must not depend on the helper
// -------------------------------------------------------------------------

// The panel is three QML files now -- the SSH settings sections and the
// approval screen have their own. A check that reads only the largest one
// silently narrows as markup moves out of it.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml"]
  .map(readPluginSource)
  .join("\n")
check("the supervisor keeps stdin open and parses stdout by line from startup",
  /id:\s*sshAgentProc[\s\S]{0,400}?stdinEnabled:\s*true[\s\S]{0,200}?stdout:\s*SplitParser/.test(panelSrc),
  "sshAgentProc has no open stdin or no SplitParser attached")
check("the supervisor uses a minimal environment",
  /id:\s*sshAgentProc[\s\S]{0,600}?clearEnvironment:\s*true/.test(panelSrc),
  "sshAgentProc does not clear its environment")

// The helper removes its socket and FIFO when its control channel closes, not
// on a signal, so stopping asks first.
check("stopping the helper sends the shutdown line, then closes its control channel",
  /function stopSshAgentHelper\(\)[\s\S]{0,600}?sshAgentShutdownLine\(\)\)\s*sshAgentProc\.stdinEnabled = false/.test(panelSrc),
  "the stop path never sends shutdown or never closes stdin")
check("termination is a backstop behind a grace period",
  /sshAgentTerminateTimer[\s\S]{0,300}?onTriggered:\s*if \(sshAgentProc\.running\) sshAgentProc\.running = false/.test(panelSrc),
  "nothing terminates a helper that ignores the shutdown request")
check("starting the helper reopens its control channel",
  /function startSshAgentHelper\(\)[\s\S]{0,300}?stdinEnabled = true/.test(panelSrc),
  "a restarted helper would have no control channel")

processTests().then(() => {
  done()
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }) } catch (e) {}
})
