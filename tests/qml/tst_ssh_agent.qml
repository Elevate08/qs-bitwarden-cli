import QtQuick
import QtTest
import "../../BitwardenModel.js" as Model

// The supervision logic runs inside QML's own JavaScript engine, not Node's.
// These cases re-prove the properties the panel depends on -- the inert
// default, the one transition that opens the signing gate, and the bounded
// failure paths -- against that engine, and check that the reducer never asks
// the caller to wait for anything.
TestCase {
  name: "SshAgent"

  readonly property string readyLine: JSON.stringify({
    v: 1, type: "ready", socketPath: "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock",
    fifoPath: "/run/user/1000/qs-bitwarden-cli/ssh-keys.fifo", agentVersion: "0.1.0"
  })

  function drive(state, events) {
    var actions = []
    for (var i = 0; i < events.length; i++) {
      var step = Model.sshAgentReduce(state, events[i])
      state = step.state
      actions.push(step.action)
    }
    return { state: state, actions: actions, last: actions[actions.length - 1] }
  }

  function ready() {
    return drive(Model.sshAgentInitialState(), [
      { kind: "enabled", value: true, nowMs: 0 },
      { kind: "started", nowMs: 1 },
      { kind: "line", line: readyLine, nowMs: 2 }
    ])
  }

  function test_disabled_supervisor_starts_nothing() {
    var run = drive(Model.sshAgentInitialState(), [
      { kind: "started", nowMs: 0 },
      { kind: "line", line: readyLine, nowMs: 1 },
      { kind: "restartTimer", nowMs: 2 }
    ])
    compare(run.state.phase, "disabled")
    compare(run.state.gateOpen, false)
    for (var i = 0; i < run.actions.length; i++) {
      verify(!run.actions[i].start)
      verify(!run.actions[i].writeHello)
    }
  }

  function test_handshake_opens_the_signing_gate() {
    var run = ready()
    compare(run.state.phase, "ready")
    compare(run.state.gateOpen, true)
    compare(run.state.socketPath, "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock")
    compare(run.state.agentVersion, "0.1.0")
  }

  function test_reductions_never_ask_qml_to_wait() {
    var run = ready()
    for (var i = 0; i < run.actions.length; i++) {
      verify(run.actions[i].wait === undefined)
      verify(run.actions[i].waitMs === undefined)
      verify(typeof run.actions[i].restartInMs === "number")
    }
  }

  function test_helper_is_launched_by_absolute_plugin_path() {
    var dir = Model.pluginDirFromUrl("file:///home/u/.config/omarchy/plugins/bw/")
    compare(dir, "/home/u/.config/omarchy/plugins/bw")
    var cmd = Model.sshAgentHelperCommand(dir)
    compare(cmd.length, 1)
    compare(cmd[0].charAt(0), "/")
    verify(cmd[0].indexOf("/home/u/.config/omarchy/plugins/bw/") === 0)
    compare(Model.sshAgentHelperCommand(Model.pluginDirFromUrl("file:///opt/bw/../etc/")).length, 0)
  }

  function test_helper_environment_is_minimal() {
    var env = Model.sshAgentHelperEnv("/run/user/1000")
    var keys = []
    for (var k in env) keys.push(k)
    compare(keys.length, 1)
    compare(keys[0], "XDG_RUNTIME_DIR")
    compare(Model.sshAgentHelperEnv("relative/dir"), null)
  }

  function test_bad_output_closes_the_gate() {
    var cases = [
      { line: "not json", code: "MALFORMED" },
      { line: '{"v":2,"type":"locked","epoch":1}', code: "VERSION_MISMATCH" },
      { line: '{"v":1,"type":"exec"}', code: "UNKNOWN_TYPE" },
      { line: readyLine, code: "PROTOCOL" }
    ]
    for (var i = 0; i < cases.length; i++) {
      var run = drive(ready().state, [{ kind: "line", line: cases[i].line, nowMs: 100 }])
      compare(run.state.errorCode, cases[i].code)
      compare(run.state.gateOpen, false)
      compare(run.last.stop, true)
    }
  }

  function test_overlong_output_is_rejected_by_bytes() {
    var filler = new Array(Model.sshAgentMaxLineBytes()).join("é")
    var run = drive(ready().state, [{
      kind: "line", nowMs: 100,
      line: '{"v":1,"type":"error","code":"X","message":"' + filler + '"}'
    }])
    compare(run.state.errorCode, "LINE_TOO_LONG")
    compare(run.state.gateOpen, false)
  }

  function test_blank_output_is_ignored() {
    var run = drive(ready().state, [{ kind: "line", line: "", nowMs: 100 }])
    compare(run.state.phase, "ready")
    compare(run.state.gateOpen, true)
  }

  function test_stalled_handshake_is_bounded() {
    var run = drive(Model.sshAgentInitialState(), [
      { kind: "enabled", value: true, nowMs: 0 },
      { kind: "started", nowMs: 1 },
      { kind: "handshakeTimeout", nowMs: Model.sshAgentHandshakeTimeoutMs() }
    ])
    compare(run.state.errorCode, "HANDSHAKE_TIMEOUT")
    compare(run.state.gateOpen, false)
    compare(run.last.stop, true)
  }

  function test_eof_closes_the_gate_and_backs_off() {
    var run = drive(ready().state, [{ kind: "exited", exitCode: 0, nowMs: 100 }])
    compare(run.state.gateOpen, false)
    compare(run.state.phase, "backoff")
    compare(run.last.restartInMs, Model.sshAgentRestartDelayMs(1))
  }

  function test_crash_loop_stops_restarting() {
    var state = Model.sshAgentReduce(Model.sshAgentInitialState(),
      { kind: "enabled", value: true, nowMs: 0 }).state
    var scheduled = 0
    var clock = 0
    for (var i = 0; i < Model.sshAgentMaxRestarts() + 2; i++) {
      clock += 10
      state = Model.sshAgentReduce(state, { kind: "started", nowMs: clock }).state
      clock += 10
      var step = Model.sshAgentReduce(state, { kind: "exited", exitCode: 101, nowMs: clock })
      state = step.state
      if (step.action.restartInMs >= 0) scheduled++
      if (state.phase !== "backoff") break
      clock += 10
      state = Model.sshAgentReduce(state, { kind: "restartTimer", nowMs: clock }).state
    }
    compare(state.phase, "failed")
    compare(state.errorCode, "CRASH_LOOP")
    compare(state.gateOpen, false)
    compare(scheduled, Model.sshAgentMaxRestarts())
  }

  function test_backoff_is_capped() {
    verify(Model.sshAgentRestartDelayMs(1) < Model.sshAgentRestartDelayMs(2))
    compare(Model.sshAgentRestartDelayMs(99), Model.sshAgentRestartDelayMs(100))
  }

  function test_disabling_stops_everything() {
    var run = drive(ready().state, [{ kind: "enabled", value: false, nowMs: 100 }])
    compare(run.state.phase, "disabled")
    compare(run.state.gateOpen, false)
    compare(run.last.stop, true)
    compare(run.last.cancelRestart, true)
  }

  function test_reenabling_clears_a_crash_loop() {
    var failed = Model.sshAgentInitialState()
    failed.phase = "failed"
    failed.errorCode = "CRASH_LOOP"
    failed.failures = Model.sshAgentMaxRestarts() + 1
    var run = drive(failed, [{ kind: "enabled", value: true, nowMs: 0 }])
    compare(run.state.phase, "starting")
    compare(run.state.errorCode, "")
    compare(run.last.start, true)
  }
}
