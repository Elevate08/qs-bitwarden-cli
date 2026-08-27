#!/usr/bin/env node
// The panel supervises the SSH companion; it never waits on it. These tests
// cover the pure supervision logic (path resolution, the minimal environment,
// the bounded NDJSON reader, and the restart state machine) and then drive
// that logic with real child processes -- a fake helper and, when it has been
// built, the real one -- so the handshake is proven across the process
// boundary rather than against a mock.
//
//   node tests/ssh-agent-control.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.pluginDirFromUrl = pluginDirFromUrl
  exports.sshAgentHelperPath = sshAgentHelperPath
  exports.sshAgentHelperCommand = sshAgentHelperCommand
  exports.sshAgentHelperEnv = sshAgentHelperEnv
  exports.sshAgentHelloLine = sshAgentHelloLine
  exports.sshAgentShutdownLine = sshAgentShutdownLine
  exports.parseAgentEvent = parseAgentEvent
  exports.sshAgentRestartDelayMs = sshAgentRestartDelayMs
  exports.sshAgentInitialState = sshAgentInitialState
  exports.sshAgentReduce = sshAgentReduce
  exports.sshAgentMaxRestarts = sshAgentMaxRestarts
  exports.sshAgentHandshakeTimeoutMs = sshAgentHandshakeTimeoutMs
  exports.sshAgentMaxLineBytes = sshAgentMaxLineBytes
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

// -------------------------------------------------------------------------
// Absolute, plugin-relative helper path
// -------------------------------------------------------------------------

eq("plugin dir from a file URL",
  Model.pluginDirFromUrl("file:///home/u/.config/omarchy/plugins/bw/"),
  "/home/u/.config/omarchy/plugins/bw")
eq("plugin dir keeps a percent-encoded segment",
  Model.pluginDirFromUrl("file:///home/u/my%20plugins/bw/"), "/home/u/my plugins/bw")
eq("plugin dir accepts a bare absolute path", Model.pluginDirFromUrl("/opt/bw/"), "/opt/bw")
eq("plugin dir refuses a relative URL", Model.pluginDirFromUrl("plugins/bw"), "")
eq("plugin dir refuses a non-file scheme", Model.pluginDirFromUrl("qrc:/bw/"), "")
eq("plugin dir refuses traversal", Model.pluginDirFromUrl("file:///opt/bw/../../etc/"), "")
eq("plugin dir refuses an encoded traversal", Model.pluginDirFromUrl("file:///opt/bw/%2e%2e/etc/"), "")
eq("plugin dir refuses an empty url", Model.pluginDirFromUrl(""), "")
eq("plugin dir refuses a non-string", Model.pluginDirFromUrl(null), "")

eq("helper path is plugin-relative and absolute",
  Model.sshAgentHelperPath("/opt/bw"), "/opt/bw/agent/target/debug/qs-bitwarden-ssh-agent")
eq("helper path refuses a relative plugin dir", Model.sshAgentHelperPath("opt/bw"), "")
eq("helper path refuses an empty plugin dir", Model.sshAgentHelperPath(""), "")

const helperCmd = Model.sshAgentHelperCommand("/opt/bw")
eq("helper runs directly with no shell and no arguments", helperCmd.length, 1)
eq("helper command is the absolute helper path", helperCmd[0],
  "/opt/bw/agent/target/debug/qs-bitwarden-ssh-agent")
check("helper command never goes through a shell",
  !helperCmd.some(a => /^(?:ba)?sh$/.test(path.basename(String(a)))), JSON.stringify(helperCmd))
eq("helper command is empty without a plugin dir", Model.sshAgentHelperCommand("").length, 0)

// -------------------------------------------------------------------------
// Minimal environment
// -------------------------------------------------------------------------

const env = Model.sshAgentHelperEnv("/run/user/1000")
eq("helper environment carries only XDG_RUNTIME_DIR", Object.keys(env).sort().join(","), "XDG_RUNTIME_DIR")
eq("helper environment points at the runtime dir", env.XDG_RUNTIME_DIR, "/run/user/1000")
for (const banned of ["PATH", "HOME", "BW_SESSION", "BW_PASSWORD", "QSBW_SECRET", "SSH_AUTH_SOCK"]) {
  check("helper environment omits " + banned, !(banned in env), JSON.stringify(env))
}
eq("helper environment refuses a relative runtime dir", Model.sshAgentHelperEnv("run/user/1000"), null)
eq("helper environment refuses an empty runtime dir", Model.sshAgentHelperEnv(""), null)

// -------------------------------------------------------------------------
// Bounded NDJSON reader
// -------------------------------------------------------------------------

eq("hello is the versioned v1 handshake", Model.sshAgentHelloLine(), '{"v":1,"type":"hello"}\n')
eq("shutdown is a versioned v1 line", Model.sshAgentShutdownLine(), '{"v":1,"type":"shutdown"}\n')

const ready = Model.parseAgentEvent(JSON.stringify({
  v: 1, type: "ready", socketPath: "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock",
  fifoPath: "/run/user/1000/qs-bitwarden-cli/ssh-keys.fifo", agentVersion: "0.1.0"
}))
eq("ready parses", ready.ok, true)
eq("ready keeps its socket path", ready.message.socketPath, "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock")
eq("ready keeps its agent version", ready.message.agentVersion, "0.1.0")

eq("an empty line is ignored rather than fatal", Model.parseAgentEvent("").code, "EMPTY")
check("an empty line does not fail closed", Model.parseAgentEvent("").fatal === false,
  JSON.stringify(Model.parseAgentEvent("")))
eq("malformed JSON fails closed", Model.parseAgentEvent("{not json").code, "MALFORMED")
check("malformed JSON is fatal", Model.parseAgentEvent("{not json").fatal === true, "not fatal")
eq("a wrong version fails closed", Model.parseAgentEvent('{"v":2,"type":"ready"}').code, "VERSION_MISMATCH")
eq("a missing version fails closed", Model.parseAgentEvent('{"type":"ready"}').code, "VERSION_MISMATCH")
eq("an unknown type fails closed", Model.parseAgentEvent('{"v":1,"type":"exec"}').code, "UNKNOWN_TYPE")
eq("a non-object line fails closed", Model.parseAgentEvent('"ready"').code, "MALFORMED")
eq("a ready missing its socket path fails closed",
  Model.parseAgentEvent('{"v":1,"type":"ready","fifoPath":"/f","agentVersion":"1"}').code, "MALFORMED")

const overlong = '{"v":1,"type":"error","message":"' + "x".repeat(Model.sshAgentMaxLineBytes()) + '"}'
eq("an overlong line fails closed before parsing", Model.parseAgentEvent(overlong).code, "LINE_TOO_LONG")
const multibyte = '{"v":1,"type":"error","message":"' + "é".repeat(Model.sshAgentMaxLineBytes() - 100) + '"}'
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

const badVersion = drive(Model.sshAgentInitialState(), [
  { kind: "enabled", value: true, nowMs: 0 },
  { kind: "started", nowMs: 1 },
  { kind: "line", line: '{"v":2,"type":"ready","socketPath":"/s","fifoPath":"/f","agentVersion":"9"}', nowMs: 2 }
])
eq("a version mismatch stops the helper", badVersion.last.stop, true)
eq("a version mismatch is reported", badVersion.state.errorCode, "VERSION_MISMATCH")
check("a version mismatch keeps the gate closed", badVersion.state.gateOpen === false,
  JSON.stringify(badVersion.state))

const garbage = drive(reachReady(0).state, [{ kind: "line", line: "not json at all", nowMs: 100 }])
eq("a malformed line closes the gate", garbage.state.gateOpen, false)
eq("a malformed line stops the helper", garbage.last.stop, true)
eq("a malformed line is reported", garbage.state.errorCode, "MALFORMED")

const tooLong = drive(reachReady(0).state, [{ kind: "line", line: overlong, nowMs: 100 }])
eq("an overlong line closes the gate", tooLong.state.gateOpen, false)
eq("an overlong line is reported", tooLong.state.errorCode, "LINE_TOO_LONG")

const blank = drive(reachReady(0).state, [{ kind: "line", line: "", nowMs: 100 }])
eq("a blank line is ignored", blank.state.phase, "ready")
check("a blank line leaves the gate open", blank.state.gateOpen === true, JSON.stringify(blank.state))

const passthrough = drive(reachReady(0).state, [{
  kind: "line", nowMs: 100,
  line: JSON.stringify({ v: 1, type: "keys_loaded", epoch: 7, keyCount: 2, skipped: [] })
}])
eq("a live event stays ready", passthrough.state.phase, "ready")
eq("a live event reaches the panel", passthrough.last.message.type, "keys_loaded")

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
eq("backoff step 2", Model.sshAgentRestartDelayMs(2), 1000)
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
for (let i = 0; i < Model.sshAgentMaxRestarts() + 2; i++) {
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
  loopActions.filter(a => a.restartInMs > 0).length === Model.sshAgentMaxRestarts(),
  String(loopActions.filter(a => a.restartInMs > 0).length))

const failedIgnores = drive(loop, [
  { kind: "restartTimer", nowMs: clock + 1000 },
  { kind: "started", nowMs: clock + 1001 }
])
eq("a failed supervisor stays failed", failedIgnores.state.phase, "failed")
check("a failed supervisor starts nothing", failedIgnores.actions.every(a => !a.start),
  JSON.stringify(failedIgnores.actions))

// The loop that actually happens in practice: the helper starts fine, answers
// the handshake, serves briefly, and dies -- over and over. Completing a
// handshake must not wipe the failure history, or a helper that crashes a
// second after every start is restarted forever.
{
  let crashy = Model.sshAgentInitialState()
  let scheduled = 0
  let t = 0
  crashy = Model.sshAgentReduce(crashy, { kind: "enabled", value: true, nowMs: t }).state
  for (let i = 0; i < Model.sshAgentMaxRestarts() + 3; i++) {
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
  eq("that loop is reported as a crash loop", crashy.errorCode, "CRASH_LOOP")
  eq("that loop is bounded by the same restart cap", scheduled, Model.sshAgentMaxRestarts())
  check("that loop leaves the gate closed", crashy.gateOpen === false, JSON.stringify(crashy))
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

const disabledDuringBackoff = drive(eof.state, [{ kind: "enabled", value: false, nowMs: 150 }])
eq("disabling during backoff cancels the restart", disabledDuringBackoff.last.cancelRestart, true)
eq("disabling during backoff is disabled", disabledDuringBackoff.state.phase, "disabled")

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
    const guard = setTimeout(finish, (opts && opts.timeoutMs) || 5000)

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

function writeFakeHelper(name, body) {
  const file = path.join(tmpRoot, name)
  fs.writeFileSync(file, "#!/usr/bin/env node\n" + body, { mode: 0o700 })
  return file
}

const fakeReady = writeFakeHelper("fake-ready.js", `
process.stdin.resume()
let seen = ""
process.stdin.on("data", d => {
  seen += d.toString()
  if (seen.indexOf('"hello"') >= 0) {
    process.stdout.write(JSON.stringify({ v: 1, type: "ready",
      socketPath: "/run/fake/ssh-agent.sock", fifoPath: "/run/fake/ssh-keys.fifo",
      agentVersion: "0.0.0-fake" }) + "\\n")
    seen = ""
  }
})
process.stdin.on("end", () => process.exit(0))
`)

const fakeGarbage = writeFakeHelper("fake-garbage.js", `
process.stdin.resume()
process.stdout.write("this is not ndjson\\n")
setTimeout(() => process.exit(0), 2000)
`)

const fakeSilent = writeFakeHelper("fake-silent.js", `
process.stdin.resume()
setTimeout(() => process.exit(0), 60000)
`)

const fakeCrash = writeFakeHelper("fake-crash.js", `process.exit(9)`)

const fakeFlood = writeFakeHelper("fake-flood.js", `
process.stdin.resume()
let seen = ""
process.stdin.on("data", d => {
  seen += d.toString()
  if (seen.indexOf('"hello"') >= 0) {
    process.stdout.write('{"v":1,"type":"error","code":"X","message":"' + "z".repeat(200000) + '"}\\n')
    seen = ""
  }
})
`)

const realHelper = path.join(repoRoot, "agent", "target", "debug", "qs-bitwarden-ssh-agent")

async function processTests() {
  const nodeBin = process.execPath

  const okRun = await runHelper([nodeBin, fakeReady], Model.sshAgentHelperEnv(runtimeDir), { stopOnReady: true })
  check("a fake helper completes the handshake", okRun.readyState !== null, JSON.stringify(okRun.state))
  eq("a fake helper opens the gate on ready", okRun.readyState && okRun.readyState.gateOpen, true)
  eq("a fake helper reports its version", okRun.readyState && okRun.readyState.agentVersion, "0.0.0-fake")
  eq("closing stdin ends the fake helper and closes the gate", okRun.state.gateOpen, false)

  const garbageRun = await runHelper([nodeBin, fakeGarbage], Model.sshAgentHelperEnv(runtimeDir))
  eq("a garbage-emitting helper fails closed", garbageRun.state.errorCode, "MALFORMED")
  check("a garbage-emitting helper never opens the gate", garbageRun.state.gateOpen === false,
    JSON.stringify(garbageRun.state))

  const floodRun = await runHelper([nodeBin, fakeFlood], Model.sshAgentHelperEnv(runtimeDir))
  eq("an overlong helper line fails closed", floodRun.state.errorCode, "LINE_TOO_LONG")

  const crashRun = await runHelper([nodeBin, fakeCrash], Model.sshAgentHelperEnv(runtimeDir))
  eq("a helper that dies at once backs off", crashRun.state.phase, "backoff")
  check("a helper that dies at once leaves the gate closed", crashRun.state.gateOpen === false,
    JSON.stringify(crashRun.state))

  const silentRun = await runHelper([nodeBin, fakeSilent], Model.sshAgentHelperEnv(runtimeDir), { timeoutMs: 1200 })
  eq("a silent helper never opens the gate", silentRun.state.gateOpen, false)
  eq("a silent helper stays in the handshake", silentRun.state.phase, "handshaking")

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

const panelSrc = fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8")
check("the supervisor Process is tracked, not detached",
  !/execDetached\([^)]*sshAgent/i.test(panelSrc), "found execDetached for the ssh agent")
check("the supervisor keeps stdin open", /id:\s*sshAgentProc[\s\S]{0,400}?stdinEnabled:\s*true/.test(panelSrc),
  "sshAgentProc has no stdinEnabled: true")
check("the supervisor parses stdout by line from startup",
  /id:\s*sshAgentProc[\s\S]{0,600}?stdout:\s*SplitParser/.test(panelSrc),
  "sshAgentProc has no SplitParser attached")
check("the supervisor uses a minimal environment",
  /id:\s*sshAgentProc[\s\S]{0,600}?clearEnvironment:\s*true/.test(panelSrc),
  "sshAgentProc does not clear its environment")

// The helper cleans up its socket and FIFO when its control channel closes,
// and not when it is signalled. A stop that goes straight to SIGTERM leaves
// both behind for the next start to reclaim, so the supervisor has to ask
// before it terminates.
check("stopping the helper closes its control channel first",
  /function stopSshAgentHelper\(\)[\s\S]{0,600}?stdinEnabled = false/.test(panelSrc),
  "the stop path never closes stdin")
check("stopping the helper sends the shutdown line",
  /function stopSshAgentHelper\(\)[\s\S]{0,600}?sshAgentShutdownLine\(\)/.test(panelSrc),
  "the stop path never sends shutdown")
check("termination is a backstop behind a grace period",
  /sshAgentTerminateTimer[\s\S]{0,300}?onTriggered:\s*if \(sshAgentProc\.running\) sshAgentProc\.running = false/.test(panelSrc),
  "nothing terminates a helper that ignores the shutdown request")
check("starting the helper reopens its control channel",
  /function startSshAgentHelper\(\)[\s\S]{0,300}?stdinEnabled = true/.test(panelSrc),
  "a restarted helper would have no control channel")

processTests().then(() => {
  if (failures.length) {
    console.error(`\n${failures.length} failed, ${pass} passed\n`)
    failures.forEach(f => console.error(`  FAIL ${f}`))
    process.exit(1)
  }
  console.log(`ssh-agent-control: ${pass} passed`)
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }) } catch (e) {}
})
