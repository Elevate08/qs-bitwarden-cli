#!/usr/bin/env node
// The plugin's pinentry (pinentry/omarchy-pinentry): the Assuan server
// side, against a stand-in for its Quickshell prompt (QSBW_PINENTRY_TEST_UI)
// that answers as the test says. No window opens. Covers the handshake, the
// encoding of what is typed in the `D` lines, cancel and timeout, SETERROR
// on a retry, the private directory (its modes, that it is gone after every
// end, a kill included, and that one a SIGKILL left is swept by the next
// run), the panel's own pinentry script and the vault helper in front of it,
// and that the frontend is the only program: found from the plugin's
// directory, checked with its own `--check`, and never replaced by another
// pinentry when it cannot run.
//
//   node tests/omarchy-pinentry.test.js

const { createSuite, loadModule, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn, spawnSync } = require("child_process")

const { check, eq, done } = createSuite("omarchy-pinentry")
const Model = loadModule()

const frontend = path.join(repoRoot, "pinentry", "omarchy-pinentry")
const scratch = fs.mkdtempSync(path.join(os.platform() === "linux" ? "/tmp" : os.tmpdir(), "qsbw-ope-"))
const runtime = path.join(scratch, "run")
fs.mkdirSync(runtime, { mode: 0o700 })
const uiLog = path.join(scratch, "ui.log")
const answerFile = path.join(scratch, "answer")

// The stand-in prompt. Logs one JSON line per start: what prompt.json said,
// the modes of the directory and the file, its argv and pid. Then does what
// $FAKE_UI_ANSWER's file says: `answer:<text>` (sent as the real prompt
// sends it), `cancel`, `hang` (connects, never answers), `crash` (exits
// without connecting), `close` (connects, then closes without a line) or
// `raw:<line>` (sent as written).
const fakeUi = path.join(scratch, "fake-ui")
fs.writeFileSync(fakeUi, `#!/usr/bin/env node
const fs = require("fs"), net = require("net"), path = require("path")
const dir = process.env.QSBW_PINENTRY_DIR
const ask = JSON.parse(fs.readFileSync(path.join(dir, "prompt.json"), "utf8"))
const what = fs.readFileSync(process.env.FAKE_UI_ANSWER, "utf8")
const core = (fs.readFileSync("/proc/self/limits", "utf8").match(/^Max core file size\\s+(\\S+)\\s+(\\S+)/m) || []).slice(1).join("/")
fs.appendFileSync(process.env.FAKE_UI_LOG, JSON.stringify({ ask, argv: process.argv.slice(1), pid: process.pid,
  dirMode: fs.statSync(dir).mode & 0o777, fileMode: fs.statSync(path.join(dir, "prompt.json")).mode & 0o777,
  dir, core, crashHandler: process.env.QS_DISABLE_CRASH_HANDLER || "", desc: process.env.QSBW_PE_DESC || "" }) + "\\n")
if (what === "crash") process.exit(3)
const s = net.connect(path.join(dir, "answer.sock"), () => {
  if (what.startsWith("answer:")) s.end("D " + encodeURIComponent(what.slice(7)) + "\\n")
  else if (what.startsWith("raw:")) s.end(what.slice(4) + "\\n")
  else if (what === "cancel") s.end("CANCEL\\n")
  else if (what === "close") s.end()
})
s.on("close", () => { if (what !== "hang") process.exit(0) })
s.on("error", () => process.exit(1))
setInterval(() => {}, 1000)
`, { mode: 0o755 })

const baseEnv = Object.assign({}, process.env, {
  XDG_RUNTIME_DIR: runtime, QSBW_PINENTRY_TEST_UI: fakeUi, FAKE_UI_LOG: uiLog, FAKE_UI_ANSWER: answerFile
})

const sleep = ms => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
const alive = pid => { try { process.kill(pid, 0); return true } catch (e) { return false } }
const uiStarts = () => fs.existsSync(uiLog)
  ? fs.readFileSync(uiLog, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)) : []
const leftovers = () => fs.readdirSync(runtime).filter(n => n.startsWith("qsbw-pinentry-"))

// One Assuan session: `lines` sent at once, the replies returned.
function session(lines, answer, opts = {}) {
  fs.writeFileSync(answerFile, answer || "cancel")
  fs.writeFileSync(uiLog, "")
  const r = spawnSync(frontend, [], { input: lines.map(l => l + "\n").join(""), env: Object.assign({}, baseEnv, opts.env || {}),
    timeout: opts.timeout || 20000 })
  return { code: r.status, out: r.stdout, lines: r.stdout.toString("utf8").split("\n").filter(Boolean), err: String(r.stderr) }
}

// --- the handshake ----------------------------------------------------------------

let r = session(["OPTION ttyname=/dev/pts/1", "SETTITLE Bitwarden", "SETDESC Unlock", "SETPROMPT PIN:", "SETOK OK",
  "SETCANCEL Cancel", "SETKEYINFO x", "SETTIMEOUT 120", "NOP", "GETINFO pid", "GETINFO flavor", "GETINFO nothing",
  "FROBNICATE", "RESET", "BYE"])
eq("it greets first", r.lines[0], "OK Pleased to meet you")
eq("every setting is acknowledged", r.lines.slice(1, 10).join("|"), Array(9).fill("OK").join("|"))
check("GETINFO pid answers with a pid", /^D \d+$/.test(r.lines[10]) && r.lines[11] === "OK", r.lines.join("|"))
eq("GETINFO flavor", r.lines.slice(12, 14).join("|"), "D omarchy|OK")
check("an unknown GETINFO and an unknown command are errors",
  /^ERR 83886360 /.test(r.lines[14]) && /^ERR 83886355 /.test(r.lines[15]), r.lines.join("|"))
eq("RESET and BYE", r.lines.slice(16).join("|"), "OK|OK closing connection")
eq("it exits 0 after BYE", r.code, 0)
eq("no prompt was started without GETPIN", uiStarts().length, 0)
r = session(["CONFIRM", "MESSAGE", "BYE"])
check("CONFIRM is a cancel, MESSAGE is acknowledged",
  /^ERR 83886179 /.test(r.lines[1]) && r.lines[2] === "OK", r.lines.join("|"))

// --- answers ------------------------------------------------------------------------

const ask = (extra = []) => ["SETTITLE Bitwarden", "SETDESC Unlock Bitwarden for 100%25@x.com", "SETPROMPT Master password:"]
  .concat(extra, ["GETPIN", "BYE"])

r = session(ask(), "answer:hunter2")
eq("an answer comes back as a D line and OK", r.lines.slice(4).join("|"), "D hunter2|OK|OK closing connection")
{
  const start = uiStarts()[0] || {}
  eq("the prompt gets the description decoded", start.ask && start.ask.description, "Unlock Bitwarden for 100%@x.com")
  eq("and the prompt text", start.ask && start.ask.prompt, "Master password:")
  check("nothing of the prompt is in the prompt's argv",
    Array.isArray(start.argv) && !JSON.stringify(start.argv).includes("x.com"), JSON.stringify(start.argv))
  eq("the private directory is 0700 and the prompt file 0600", `${(start.dirMode || 0).toString(8)}|${(start.fileMode || 0).toString(8)}`, "700|600")
  check("the private directory is under XDG_RUNTIME_DIR", String(start.dir).startsWith(runtime + "/qsbw-pinentry-"), start.dir)
  eq("and is gone afterwards", leftovers().join(","), "")
  eq("Quickshell's crash handler is off for the prompt", start.crashHandler, "1")
}
{
  // As under the vault helper: no core files, soft or hard.
  fs.writeFileSync(answerFile, "cancel")
  fs.writeFileSync(uiLog, "")
  spawnSync("bash", ["-c", 'ulimit -S -c 0 && ulimit -H -c 0 && exec "$0"', frontend],
    { input: "SETDESC d\nGETPIN\nBYE\n", env: baseEnv, timeout: 20000 })
  eq("the prompt inherits a zero core-file limit", (uiStarts()[0] || {}).core, "0/0")
}

r = session(ask(), "answer:a%b\rc\nd+e")
eq("%, CR and LF are percent-encoded, + is not", r.lines[4], "D a%25b%0Dc%0Ad+e")
r = session(ask(), "answer:t\tab\u007f")
eq("every other control byte is encoded too", r.lines[4], "D t%09ab%7F")
r = session(ask(), "answer:pässwörd€")
eq("non-ASCII is passed as UTF-8, as pinentry does", r.lines[4], "D pässwörd€")
r = session(ask(), "answer:%25")
eq("an answer that is itself an escape is not decoded twice", r.lines[4], "D %2525")
r = session(ask(), "answer:")
eq("an empty answer is OK with no data", r.lines.slice(4, 6).join("|"), "OK|OK closing connection")
{
  const long = "é" + "x%".repeat(1500)
  r = session(ask(), "answer:" + long)
  const data = r.lines.filter(l => l.startsWith("D "))
  check("a long answer is split into lines under Assuan's limit",
    data.length > 1 && data.every(l => Buffer.byteLength(l) + 1 <= 1000), data.map(l => Buffer.byteLength(l)).join(","))
  const joined = data.map(l => l.slice(2)).join("")
  eq("and the lines join back to it", joined.replace(/%25/g, "%"), long)
  check("no escape is split across lines", data.every(l => !/%.?$/.test(l)), "")
}
{
  // Continuation bytes never split a line; a run longer than any UTF-8
  // sequence must still be split, not written past the line's buffer.
  r = session(ask(), "raw:D " + "%80".repeat(2000))
  const data = []
  let at = 0
  for (let end; (end = r.out.indexOf(0x0a, at)) !== -1; at = end + 1) {
    const line = r.out.subarray(at, end)
    if (line[0] === 0x44 && line[1] === 0x20) data.push(line)
  }
  check("a long run of continuation bytes is split under Assuan's limit",
    data.length > 1 && data.every(l => l.length + 1 <= 1000), data.map(l => l.length).join(","))
  const bytes = Buffer.concat(data.map(l => l.subarray(2)))
  eq("and every byte survives", `${bytes.length}|${bytes.every(b => b === 0x80)}`, "2000|true")
}
r = session(ask(), "raw:D %zz")
check("a malformed answer from the prompt is an error, not data",
  /^ERR 83886081 /.test(r.lines[4]) && !r.lines.some(l => l.startsWith("D ")), r.lines.join("|"))
r = session(ask(["SETDESC a%zzb\u0001c\u007fd"]), "cancel")
eq("a description with a malformed escape is shown as written, controls dropped",
  (uiStarts()[0] || {}).ask && uiStarts()[0].ask.description, "a%zzbcd")

// --- cancel, failure, timeout -----------------------------------------------------------

r = session(ask(), "cancel")
check("Escape is pinentry's cancel", /^ERR 83886179 Operation cancelled/.test(r.lines[4]), r.lines.join("|"))
eq("nothing left behind after a cancel", leftovers().join(","), "")
r = session(ask(), "crash")
check("a prompt that dies without answering is a failure, not a cancel",
  /^ERR 83886081 /.test(r.lines[4]), r.lines.join("|"))
r = session(ask(), "close")
check("so is one that closes the socket without a word", /^ERR 83886081 /.test(r.lines[4]), r.lines.join("|"))
{
  const t0 = Date.now()
  r = session(ask(["SETTIMEOUT 1"]), "hang")
  const took = Date.now() - t0
  check("SETTIMEOUT runs out as pinentry's timeout", /^ERR 83886142 Timeout/.test(r.lines[5]), r.lines.join("|"))
  check("after about the time asked", took >= 900 && took < 8000, String(took))
  const start = uiStarts()[0] || {}
  sleep(200)
  check("the prompt is closed when it times out", start.pid && !alive(start.pid), String(start.pid))
  eq("and its directory removed", leftovers().join(","), "")
}

// --- what a SIGKILL left behind ----------------------------------------------------------

{
  // Siblings as earlier runs would leave them: one whose pid is gone, one
  // with no pid in its prompt.json, one whose pid is alive (this test), one
  // with no prompt.json made long ago, one made just now (another run between
  // mkdtemp and its write), and a symlink to a directory holding a dead pid,
  // which must not be followed.
  const dead = spawnSync("true").pid
  const sibling = (name, pid) => {
    const dir = path.join(runtime, "qsbw-pinentry-" + name)
    fs.mkdirSync(dir, { mode: 0o700 })
    if (pid !== undefined) fs.writeFileSync(path.join(dir, "prompt.json"), JSON.stringify({ description: "x", pid }), { mode: 0o600 })
    return dir
  }
  sibling("DEAD01", dead)
  sibling("NOPID1", null)
  const live = sibling("LIVE01", process.pid)
  const old = sibling("OLD001")
  fs.utimesSync(old, new Date(Date.now() - 120000), new Date(Date.now() - 120000))
  const fresh = sibling("NEW001")
  const target = path.join(scratch, "elsewhere")
  fs.mkdirSync(target, { mode: 0o700 })
  fs.writeFileSync(path.join(target, "prompt.json"), JSON.stringify({ pid: dead }))
  fs.symlinkSync(target, path.join(runtime, "qsbw-pinentry-LINK01"))
  r = session(ask(), "cancel")
  eq("the next run removes what a killed one left, keeps a live run's and never follows a link",
    leftovers().sort().join(","), "qsbw-pinentry-LINK01,qsbw-pinentry-LIVE01,qsbw-pinentry-NEW001")
  check("the link's target is untouched", fs.existsSync(path.join(target, "prompt.json")), "")
  check("the prompt file names its pid", /^\d+$/.test(String((uiStarts()[0] || { ask: {} }).ask.pid)), JSON.stringify(uiStarts()[0]))
  fs.rmSync(live, { recursive: true })
  fs.rmSync(fresh, { recursive: true })
  fs.unlinkSync(path.join(runtime, "qsbw-pinentry-LINK01"))
}

// --- SETERROR on a retry ----------------------------------------------------------------

fs.writeFileSync(answerFile, "cancel")
r = session(["SETDESC d", "SETERROR Wrong PIN%0Atry again", "GETPIN", "GETPIN", "BYE"], "cancel")
{
  const starts = uiStarts()
  eq("the error is shown with the next GETPIN", starts[0] && starts[0].ask.error, "Wrong PIN\ntry again")
  eq("and not again with the one after", starts[1] && starts[1].ask.error, "")
  eq("a GETPIN sent while one is open waits for it", r.lines.filter(l => /^ERR 83886179/.test(l)).length, 2)
}

// --- the end of the script ------------------------------------------------------------------

// `how`: a signal for the frontend (the script's EXIT trap sends SIGTERM),
// or "parent" for a SIGKILL of the process that started it.
function killedMidPrompt(how) {
  fs.writeFileSync(answerFile, "hang")
  fs.writeFileSync(uiLog, "")
  const starter = `const c = require("child_process").spawn(${JSON.stringify(frontend)}, [], { stdio: ["pipe", "ignore", "ignore"] });`
    + ` c.stdin.write("SETDESC d\\nGETPIN\\n"); setInterval(() => {}, 1000)`
  const child = how === "parent"
    ? spawn(process.execPath, ["-e", starter], { env: baseEnv, stdio: "ignore" })
    : spawn(frontend, [], { env: baseEnv, stdio: ["pipe", "pipe", "ignore"] })
  if (how !== "parent") child.stdin.write("SETDESC d\nGETPIN\n")
  return new Promise(resolve => {
    let tries = 0
    const wait = setInterval(() => {
      const start = uiStarts()[0]
      if (!start && ++tries < 100) return
      clearInterval(wait)
      child.on("exit", () => {
        // The frontend notices a lost parent within a second.
        setTimeout(() => resolve({ start, left: leftovers() }), how === "parent" ? 1800 : 200)
      })
      child.kill(how === "parent" ? "SIGKILL" : how)
    }, 50)
  })
}

async function lifetimes() {
  for (const how of ["SIGTERM", "SIGHUP", "SIGPIPE", "parent"]) {
    const k = await killedMidPrompt(how)
    check(`${how} mid-prompt closes the prompt`, k.start && !alive(k.start.pid), JSON.stringify(k.start))
    eq(`${how} mid-prompt removes the private directory`, k.left.join(","), "")
  }
}

// --- --check -------------------------------------------------------------------------------

function checks() {
  const env = Object.assign({}, baseEnv)
  delete env.XDG_RUNTIME_DIR
  eq("--check fails without a runtime dir", spawnSync(frontend, ["--check"], { env }).status, 1)
  eq("--check passes with one (and the stand-in prompt)", spawnSync(frontend, ["--check"], { env: baseEnv }).status, 0)
  const noUi = Object.assign({}, baseEnv, { QSBW_PINENTRY_TEST_UI: "", WAYLAND_DISPLAY: "" })
  const c = spawnSync(frontend, ["--check"], { env: noUi, encoding: "utf8" })
  check("--check fails without a Wayland display, and says why", c.status === 1 && /Wayland/.test(c.stderr), c.stderr)
  const noKit = Object.assign({}, baseEnv, { QSBW_PINENTRY_TEST_UI: "", WAYLAND_DISPLAY: "wayland-x", OMARCHY_SHELL_DIR: path.join(scratch, "nokit") })
  eq("--check fails without the shell kit", spawnSync(frontend, ["--check"], { env: noKit }).status, 1)
  // The card's field is the panel's LineField, never an editable TextInput
  // (tests/line-field.test.js), so the prompt's config links it beside the kit.
  const src = fs.readFileSync(frontend, "utf8")
  const card = fs.readFileSync(path.join(repoRoot, "pinentry", "PinentryCard.qml"), "utf8")
  check("the prompt's field is the panel's LineField",
    /import "\.\."/.test(card) && /LineField \{[\s\S]*?password: !root\.revealed/.test(card)
      && /want\("LineField\.qml", path\.join\(path\.dirname\(here\), "LineField\.qml"\)\)/.test(src)
      && /"LineField\.qml is missing"/.test(src),
    "the prompt would type into a field that reads every clipboard offer")
  const st = fs.statSync(frontend)
  check("the frontend is executable in the checkout", (st.mode & 0o111) !== 0, (st.mode & 0o777).toString(8))
}

// --- through the panel's pinentry script -------------------------------------------------------

const exits = Model.pinentryExitCodes()
function script(answer, opts = {}, program = frontend) {
  fs.writeFileSync(answerFile, answer)
  fs.writeFileSync(uiLog, "")
  const argv = Model.pinentryCommand(program, Object.assign({ title: "Bitwarden", prompt: "PIN:" }, opts))
  const r = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", timeout: 20000,
    env: Object.assign({}, baseEnv, Model.pinentryEnvironment(opts)) })
  return { code: r.status, out: r.stdout, starts: uiStarts() }
}

function throughScript() {
  let s = script("answer:p%w\nd")
  eq("the panel's script takes the frontend's answer", `${s.code}|${s.out}`, "0|p%25w%0Ad")
  s = script("cancel")
  eq("a cancel is the script's cancel", `${s.code}|${s.out}`, `${exits.cancelled}|`)
  s = script("crash")
  eq("a prompt that died is the script's failure (the panel offers its field)", s.code, exits.failed)
  s = script("answer:12", { minLength: 4 })
  eq("a PIN under the minimum exits short", `${s.code}|${s.out}`, `${exits.short}|`)
  s = script("answer:1%%%", { minLength: 4 })
  eq("each encoded % counts as one character", `${s.code}|${s.out}`, "0|1%25%25%25")
  s = script("answer:ü", { minLength: 2 })
  eq("a non-ASCII character counts as one", s.code, exits.short)
  s = script("cancel", { description: "Unlock Bitwarden for you@example.com", error: "Wrong PIN" })
  eq("the description reaches the prompt from the environment",
    s.starts[0] && `${s.starts[0].ask.description}|${s.starts[0].ask.error}`, "Unlock Bitwarden for you@example.com|Wrong PIN")
  // The script asks SETTIMEOUT 120 itself; the stand-in prompt here hangs, so
  // the frontend's own timeout must be what ends it: shorten it by wrapping.
  const wrapped = path.join(scratch, "short-timeout")
  // Its arguments go through, so the script's `--check` reaches the frontend.
  fs.writeFileSync(wrapped, `#!/usr/bin/bash\n# SETTIMEOUT 120 becomes 1.\nexec "${frontend}" "$@" < <(sed -u 's/^SETTIMEOUT 120$/SETTIMEOUT 1/')\n`, { mode: 0o755 })
  s = script("hang", {}, wrapped)
  eq("a prompt left open times out as the script's cancel", `${s.code}|${s.out}`, `${exits.cancelled}|`)
  eq("no private directory survives the script", leftovers().join(","), "")
}

// --- the only program -------------------------------------------------------------------------

function only() {
  const bundled = Model.omarchyPinentryPath(repoRoot)
  eq("the frontend's path is derived from the plugin's directory", bundled, frontend)
  eq("whatever else is passed", Model.omarchyPinentryPath(repoRoot, false), frontend)
  eq("and is empty for a plugin dir that is not a clean absolute path", Model.omarchyPinentryPath("plugins/x"), "")
  eq("or one with a parent step in it", Model.omarchyPinentryPath(repoRoot + "/../x"), "")
  check("it travels as an argument, never as script text",
    Model.pinentryCommand(bundled, {})[4] === bundled && !Model.pinentryCommand(bundled, {})[2].includes(bundled)
      && Model.pinentryProbeCommand(bundled)[4] === bundled && !Model.pinentryProbeCommand(bundled)[2].includes(bundled), "")
  eq("a path that is not absolute is not passed", Model.pinentryCommand("-x", {})[4], "")

  // A PATH with stand-ins for pinentry-qt and pinentry that record their
  // name, then act as the e2e stand-in: the script must never run them.
  const marker = path.join(scratch, "ran")
  const fake = path.join(repoRoot, "tests", "e2e", "bin", "pinentry")
  const bin = fs.mkdtempSync(path.join(scratch, "bin-"))
  for (const n of ["pinentry-qt", "pinentry"]) {
    fs.writeFileSync(path.join(bin, n), `#!/usr/bin/bash\necho ${n} >> "${marker}"\nexec /usr/bin/bash "${fake}" "$@"\n`, { mode: 0o755 })
  }
  for (const t of ["head", "tail", "mv", "sleep", "node", "sed", "env"]) {
    const where = spawnSync("bash", ["-c", `command -v ${t}`], { encoding: "utf8" }).stdout.trim()
    if (where) fs.symlinkSync(where, path.join(bin, t))
  }
  const fakeAnswers = path.join(scratch, "fake-answers")
  const ran = (extraEnv, where = bundled) => {
    fs.writeFileSync(marker, "")
    fs.writeFileSync(fakeAnswers, "pin:x\n")
    fs.writeFileSync(answerFile, "answer:y")
    fs.writeFileSync(uiLog, "")
    const env = Object.assign({}, baseEnv, { PATH: bin, FAKE_PINENTRY_ANSWERS: fakeAnswers }, extraEnv || {})
    const argv = Model.pinentryCommand(where, { title: "t", prompt: "p" })
    const r = spawnSync("/usr/bin/bash", argv.slice(1), { encoding: "utf8", timeout: 20000, env })
    const pr = Model.pinentryProbeCommand(where)
    const pb = spawnSync("/usr/bin/bash", pr.slice(1), { encoding: "utf8", timeout: 5000, env })
    return `${r.status}|${r.stdout}|${fs.readFileSync(marker, "utf8").trim()}|${uiStarts().length}|${pb.stdout.trim()}`
  }
  const missing = `${exits.missing}|||0|missing`
  eq("the frontend runs and answers, the probe finds it", ran(), "0|y||1|found")
  eq("unable to run (no runtime dir): missing, and no other pinentry runs",
    ran({ XDG_RUNTIME_DIR: "" }), missing)
  eq("unable to run (no display, no kit): missing, and no other pinentry runs",
    ran({ QSBW_PINENTRY_TEST_UI: "", WAYLAND_DISPLAY: "", OMARCHY_SHELL_DIR: path.join(scratch, "nokit") }), missing)
  eq("no display alone: missing", ran({ QSBW_PINENTRY_TEST_UI: "", WAYLAND_DISPLAY: "" }), missing)
  {
    // quickshell missing: a display and the kit are not enough.
    const kit = path.join(scratch, "kit")
    for (const d of ["Commons", "Ui"]) {
      fs.mkdirSync(path.join(kit, d), { recursive: true })
      fs.writeFileSync(path.join(kit, d, "qmldir"), "")
    }
    eq("no quickshell: missing",
      ran({ QSBW_PINENTRY_TEST_UI: "", WAYLAND_DISPLAY: "wayland-test", OMARCHY_SHELL_DIR: kit }), missing)
  }
  // node missing: `env node` fails, so --check does.
  const noNode = fs.mkdtempSync(path.join(scratch, "bin-"))
  for (const n of fs.readdirSync(bin)) if (n !== "node") fs.symlinkSync(fs.realpathSync(path.join(bin, n)), path.join(noNode, n))
  eq("without node: missing, and no other pinentry runs", ran({ PATH: noNode }), missing)
  eq("a plugin dir that gives no path: missing", ran({}, Model.omarchyPinentryPath("plugins/x")), missing)
}

// --- through the vault helper ---------------------------------------------------------------

const helper = path.join(repoRoot, "vault", "target", "debug", "qs-bitwarden-vault")

function throughHelper() {
  return new Promise(resolve => {
    fs.writeFileSync(answerFile, "answer:p%w\nd+é")
    const request = (id, argv, extra) => JSON.stringify(Object.assign({ type: "exec", v: 1, id, argv, env: {}, inject: {} }, extra))
    const askCmd = Model.pinentryCommand(Model.omarchyPinentryPath(repoRoot), { title: "Bitwarden", prompt: "PIN:" })
    const show = ["bash", "-c", "printf '%s' \"$PW\""]
    const child = spawn(helper, [], { stdio: ["pipe", "pipe", "ignore"], env: baseEnv })
    const requests = [request(1, askCmd, { capture: "pinentry:pin" }), request(2, show, { inject: { PW: "secret:pin" } })]
    const replies = {}
    let next = 0
    let buffer = ""
    const send = () => child.stdin.write(requests[next++] + "\n")
    child.stdout.on("data", chunk => {
      buffer += chunk
      let at
      while ((at = buffer.indexOf("\n")) !== -1) {
        const m = JSON.parse(buffer.slice(0, at))
        buffer = buffer.slice(at + 1)
        if (m.type !== "exit") continue
        replies[m.id] = m
        if (next < requests.length) send()
        else child.stdin.end()
      }
    })
    child.on("close", () => {
      check("the helper holds the frontend's answer and tells the panel nothing of it",
        replies[1] && replies[1].code === 0 && replies[1].held === true && replies[1].out === "", JSON.stringify(replies[1]))
      eq("decoded exactly as typed", replies[2] && replies[2].out, "p%w\nd+é")
      resolve()
    })
    setTimeout(() => child.kill("SIGKILL"), 20000).unref()
    send()
  })
}

async function main() {
  await lifetimes()
  checks()
  throughScript()
  only()
  if (fs.existsSync(helper)) await throughHelper()
  else console.log("omarchy-pinentry: skipping the helper checks, the helper is not built (cargo build --manifest-path vault/Cargo.toml --locked)")
  eq("nothing is left in the runtime dir", leftovers().join(","), "")
  fs.rmSync(scratch, { recursive: true, force: true })
  done()
}
main()
