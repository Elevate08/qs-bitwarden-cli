// A headless Quickshell running the real Service.qml behind the test-only IPC
// target in config/shell.qml, in a fresh temporary HOME, XDG and runtime dir,
// with an environment built from scratch. Everything outside the plugin is a
// stand-in from bin/ (`bw`, `secret-tool`, `systemd-creds`, desktop tools);
// the plugin's helpers, `argon2`, `jq` and `node` run for real. No network.
//
// Shared by the end-to-end suites.

const { repoRoot } = require("../harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn, spawnSync } = require("child_process")

const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)

const which = name => spawnSync("bash", ["-c", `command -v ${name}`], { encoding: "utf8" }).stdout.trim()

// `suite`: createSuite()'s check. `options.plugin`: the plugin tree to load
// (the checkout by default). `options.env`: extra environment.
// `options.coreDumps`: start the shell with core dumps allowed.
function createShell(name, check, options = {}) {
  const missing = ["quickshell", "argon2", "jq", "node", "cmp"].filter(tool => !which(tool))
  if (missing.length) {
    console.error(`${name}: cannot run without ${missing.join(", ")}`)
    process.exit(1)
  }

  // A short root: the IPC socket lives under the runtime dir, and a Unix
  // socket path is limited to 108 bytes.
  const root = fs.mkdtempSync(path.join(os.platform() === "linux" ? "/tmp" : os.tmpdir(), "qsbw-e2e-"))
  const config = path.join(root, "config")
  const home = path.join(root, "home")
  const runtime = path.join(root, "run")
  const keyring = path.join(root, "keyring")
  const bwLog = path.join(root, "bw.log")
  const shellLog = path.join(root, "shell.log")
  fs.cpSync(path.join(__dirname, "config"), config, { recursive: true })
  fs.symlinkSync(options.plugin || repoRoot, path.join(config, "plugin"))
  for (const d of [home, runtime, keyring]) fs.mkdirSync(d, { mode: 0o700 })

  const env = Object.assign({
    PATH: `${path.join(__dirname, "bin")}:/usr/local/bin:/usr/bin:/bin`,
    HOME: home,
    USER: os.userInfo().username,
    LANG: "C.UTF-8",
    XDG_RUNTIME_DIR: runtime,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    QT_QPA_PLATFORM: "offscreen",
    FAKE_BW_LOG: bwLog,
    FAKE_KEYRING: keyring,
    FAKE_SESSION_STORE_DELAY: "1"
  }, options.env || {})

  let shell = null
  function ipc(target, ...args) {
    const r = spawnSync("quickshell", ["ipc", "-p", config, "call", target, ...args],
      { env, encoding: "utf8", timeout: 20000 })
    return { ok: r.status === 0, out: String(r.stdout || "").trim() }
  }
  const q = (...args) => ipc("qsbwtest", ...args).out
  const product = (...args) => ipc("io.github.elevate08.qs-bitwarden-cli", ...args).out
  const state = () => { try { return JSON.parse(q("state")) } catch (e) { return null } }

  function start() {
    const out = fs.openSync(shellLog, "a")
    // `exec` keeps quickshell at the spawned pid, the one a crash test signals.
    const command = options.coreDumps
      ? ["bash", ["-c", 'ulimit -S -c "$(ulimit -H -c)" 2>/dev/null; exec quickshell -p "$1"', "_", config]]
      : ["quickshell", ["-p", config]]
    shell = spawn(command[0], command[1], { env, stdio: ["ignore", out, out], detached: true })
    fs.closeSync(out)
    for (let i = 0; i < 120; i++) {
      if (ipc("qsbwtest", "state").ok) return
      sleep(250)
    }
    throw new Error("the shell never answered on IPC")
  }

  function stop() {
    if (!shell) return
    try { process.kill(-shell.pid, "SIGTERM") } catch (e) {}
    for (let i = 0; i < 40 && shell.exitCode === null && shell.signalCode === null; i++) {
      if (spawnSync("kill", ["-0", String(shell.pid)]).status !== 0) break
      sleep(100)
    }
    try { process.kill(-shell.pid, "SIGKILL") } catch (e) {}
    shell = null
  }

  // The shell's own way out (`quickshell kill`): it unloads the config, so
  // the service's Component.onDestruction runs, which a SIGTERM does not.
  // Unlike stop(), the process group is left alone: a command the shell
  // started detached on its way out is in it and must be left to finish.
  function quit() {
    if (!shell) return
    spawnSync("quickshell", ["kill", "-p", config], { env, encoding: "utf8", timeout: 20000 })
    for (let i = 0; i < 100 && spawnSync("kill", ["-0", String(shell.pid)]).status === 0; i++) sleep(100)
    shell = null
  }

  // Waits up to 30 s for the vault to reach a state.
  function expect(label, predicate) {
    let s = null
    for (let i = 0; i < 120; i++) {
      s = state()
      if (s && predicate(s)) { check(label, true, ""); return s }
      sleep(250)
    }
    check(label, false, "last state: " + JSON.stringify(s))
    return s
  }

  function scriptErrors() {
    return fs.readFileSync(shellLog, "utf8").split("\n")
      .filter(l => /ReferenceError|TypeError|is not a function|Cannot read property/.test(l))
  }

  function logTail() {
    try { return fs.readFileSync(shellLog, "utf8").split("\n").slice(-40).join("\n") } catch (e) { return "" }
  }

  function cleanup() {
    stop()
    if (!process.env.KEEP_E2E) fs.rmSync(root, { recursive: true, force: true })
  }

  return {
    root, config, home, keyring, bwLog, shellLog, env,
    start, stop, quit, cleanup, q, product, state, expect, scriptErrors, logTail,
    pid: () => (shell ? shell.pid : 0)
  }
}

module.exports = { createShell, sleep }
