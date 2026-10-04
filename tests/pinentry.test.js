#!/usr/bin/env node
// The pinentry script (Model.pinentryCommand()): what it sends a pinentry,
// how it tells an answer from a cancel and from an empty answer, and that the
// answer reaches the vault helper's held secret decoded. Runs against the
// stand-in tests/e2e/bin/pinentry; no window opens.
//
//   node tests/pinentry.test.js

const { createSuite, loadModule, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawn, spawnSync } = require("child_process")

const { check, eq, done } = createSuite("pinentry")
const Model = loadModule()

const fake = path.join(repoRoot, "tests", "e2e", "bin", "pinentry")
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-pinentry-"))
const answers = path.join(dir, "answers")
const log = path.join(dir, "log")

// One run of the script against the stand-in. `answer` is the stand-in's
// next GETPIN answer (see the stand-in's header).
function run(answer, opts = {}, program = fake) {
  fs.writeFileSync(answers, answer + "\n")
  fs.writeFileSync(log, "")
  const argv = Model.pinentryCommand(program, Object.assign({ title: "Bitwarden", prompt: "Master password:" }, opts))
  const r = spawnSync(argv[0], argv.slice(1), {
    encoding: "utf8", timeout: 20000,
    env: Object.assign({}, process.env, { FAKE_PINENTRY_ANSWERS: answers, FAKE_PINENTRY_LOG: log })
  })
  return { code: r.status, out: r.stdout, err: r.stderr, log: fs.readFileSync(log, "utf8").split("\n").filter(Boolean) }
}

// --- the answer ---------------------------------------------------------------

const exits = Model.pinentryExitCodes()
let r = run("pin:hunter2")
eq("an answer is printed and the script exits 0", `${r.code}|${r.out}`, "0|hunter2")
check("the stand-in was asked for a PIN once and nothing else was kept in the log",
  r.log.filter(l => l === "GETPIN").length === 1 && !r.log.some(l => /hunter2/.test(l)), r.log.join("|"))

// What the script prints is still percent-encoded; the helper decodes it.
r = run("pin:a%25b%0Ac%0Dd+e")
eq("the data is passed on exactly as pinentry encoded it", r.out, "a%25b%0Ac%0Dd+e")

r = run("cancel")
eq("a cancel exits 1 and prints nothing", `${r.code}|${r.out}`, `${exits.cancelled}|`)
r = run("empty")
eq("an empty answer is told apart from a cancel", `${r.code}|${r.out}`, `${exits.empty}|`)
check("a cancel and an empty answer differ", exits.cancelled !== exits.empty, "")
// SETTIMEOUT ran out: pinentry says GPG_ERR_TIMEOUT (62), from source 5 as
// the stand-in sends it. Nobody answered, which is a cancel, not a failure
// that would offer the panel's field.
r = run("timeout")
eq("pinentry's own timeout (ERR 83886142) is a cancel", `${r.code}|${r.out}`, `${exits.cancelled}|`)
check("the timeout asked for is the one the script waits past",
  r.log.includes("SETTIMEOUT 120") && /read -r -t 150 /.test(Model.pinentryCommand(fake, {})[2]), r.log.join("|"))
r = run("error")
eq("an error that is not a cancel is a failure", `${r.code}|${r.out}`, `${exits.failed}|`)
r = run("crash")
eq("a pinentry that dies without answering is a failure", `${r.code}|${r.out}`, `${exits.failed}|`)
r = run("pin:x", {}, path.join(dir, "no-such-pinentry"))
eq("a missing program is reported", `${r.code}|${r.out}`, `${exits.missing}|`)
check("nothing typed reaches stderr", !/hunter2/.test(run("pin:hunter2").err), "")

// --- a PIN that is too short ---------------------------------------------------------

r = run("pin:12", { minLength: 4 })
eq("a PIN under the minimum exits short and prints nothing", `${r.code}|${r.out}`, `${exits.short}|`)
r = run("pin:%25%25", { minLength: 4 })
eq("an encoded % counts as one character, so two are short", `${r.code}|${r.out}`, `${exits.short}|`)
r = run("pin:%25%25%0A%0D", { minLength: 4 })
eq("four characters, encoded, are enough", `${r.code}|${r.out}`, "0|%25%25%0A%0D")
r = run("pin:1234", { minLength: 4 })
eq("the minimum itself passes", `${r.code}|${r.out}`, "0|1234")
r = run("pin:1", {})
eq("no minimum, no check", `${r.code}|${r.out}`, "0|1")
r = run("empty", { minLength: 4 })
eq("an empty answer is still empty, not short", r.code, exits.empty)
check("short differs from the other codes",
  new Set(Object.values(exits)).size === Object.values(exits).length, JSON.stringify(exits))

// --- what the pinentry is told ------------------------------------------------

r = run("cancel", { title: "Bitwarden", description: "Unlock Bitwarden for 100%@x.com", prompt: "Master password:" })
check("SETDESC percent-encodes a %", r.log.includes("SETDESC Unlock Bitwarden for 100%25@x.com"), r.log.join("|"))
check("title and prompt are sent", r.log.includes("SETTITLE Bitwarden") && r.log.includes("SETPROMPT Master password:"), r.log.join("|"))
check("no SETERROR without an error", !r.log.some(l => l.startsWith("SETERROR")), r.log.join("|"))

r = run("cancel", { description: "a\r\nBYE\nGETPIN\nSETERROR forged", error: "bad %0A\nPIN" })
check("a line break in the description cannot start another command",
  r.log.includes("SETDESC a%0D%0ABYE%0AGETPIN%0ASETERROR forged")
    && r.log.filter(l => l === "GETPIN").length === 1
    && r.log.filter(l => l.startsWith("SETERROR")).length === 1, r.log.join("|"))
check("an error is encoded and sent before GETPIN",
  r.log.includes("SETERROR bad %250A%0APIN") && r.log.indexOf("GETPIN") > r.log.findIndex(l => l.startsWith("SETERROR")), r.log.join("|"))
check("the script takes its text from arguments, not from its own source",
  !/forged|100%/.test(Model.pinentryCommand(fake, { description: "forged 100%" })[2]), "")

// --- the descriptions ----------------------------------------------------------

check("the description names the account",
  /you@example\.com/.test(Model.pinentryDescription("unlock", "you@example.com"))
    && /PIN/.test(Model.pinentryDescription("pin", "you@example.com"))
    && /master password/i.test(Model.pinentryDescription("reprompt", "you@example.com")), "")
check("the description copes with no account",
  Model.pinentryDescription("unlock", "").length > 0, "")

// --- the program ----------------------------------------------------------------

eq("pinentry from PATH by default", Model.pinentryProgram(undefined), "pinentry")
eq("a blank override is the default", Model.pinentryProgram("  "), "pinentry")
eq("an override is used as given", Model.pinentryProgram(" /usr/bin/pinentry-gnome3 "), "/usr/bin/pinentry-gnome3")
eq("an override cannot be an option", Model.pinentryProgram("--help"), "pinentry")
eq("an override that is not text is ignored", Model.pinentryProgram({ a: 1 }), "pinentry")
// What the panel concludes from one probe run: only a probe that ran to its
// end and said so makes pinentry missing.
const probe = (program, env) => {
  const argv = Model.pinentryProbeCommand(program)
  const r = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", timeout: 1000, killSignal: "SIGKILL",
    env: Object.assign({}, process.env, env || {}) })
  // As Qt reports it: a signal's number for a kill.
  const code = r.status === null ? require("os").constants.signals[r.signal] : r.status
  return Model.pinentryProbeMissing(code, r.stdout)
}
eq("the probe finds the stand-in", probe(fake), false)
eq("and reports a missing program as missing", probe(path.join(dir, "nope")), true)
{
  // A probe killed before it answers (any program running as you can) is not
  // a missing pinentry: the field would be offered on the strength of it.
  const slow = path.join(dir, "slow-bin")
  fs.mkdirSync(slow)
  fs.writeFileSync(path.join(slow, "bash"), "#!/usr/bin/bash\nsleep 5\nexec /usr/bin/bash \"$@\"\n", { mode: 0o755 })
  eq("a probe killed before it answers, for a missing program, is not 'missing'",
    probe(path.join(dir, "nope"), { PATH: `${slow}:${process.env.PATH}` }), false)
}
check("nor is any other end that is not the probe's own answer",
  [[9, ""], [15, ""], [1, ""], [127, ""], [0, ""], [1, "missing"], [0, "missing\nfound"]]
    .every(([code, out]) => Model.pinentryProbeMissing(code, out) === false), "")

// --- through the vault helper -----------------------------------------------------

const helper = path.join(repoRoot, "vault", "target", "debug", "qs-bitwarden-vault")

// The helper stops its runs when its stdin closes, so each request waits for
// the exit of the one before.
function driveHelper(requests) {
  return new Promise(resolve => {
    const child = spawn(helper, [], { stdio: ["pipe", "pipe", "ignore"],
      env: Object.assign({}, process.env, { FAKE_PINENTRY_ANSWERS: answers }) })
    const replies = {}
    let next = 0
    let buffer = ""
    const send = () => { child.stdin.write(requests[next++] + "\n") }
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
    child.on("close", () => resolve(replies))
    setTimeout(() => child.kill("SIGKILL"), 20000).unref()
    send()
  })
}

async function throughHelper() {
  const request = (id, argv, extra) => JSON.stringify(Object.assign({ type: "exec", v: 1, id, argv, env: {}, inject: {} }, extra))
  fs.writeFileSync(answers, "pin:p%25w%0Ad+\ncancel\n")
  const ask = Model.pinentryCommand(fake, { title: "Bitwarden", prompt: "PIN:" })
  const show = ["bash", "-c", "printf '%s' \"$PW\""]
  const replies = await driveHelper([
    request(1, ask, { capture: "pinentry:pin" }),
    request(2, show, { inject: { PW: "secret:pin" } }),
    request(3, ask, { capture: "pinentry:other" }),
    request(4, show, { inject: { PW: "secret:other" } })
  ])
  check("the helper holds the decoded answer and tells the panel nothing of it",
    replies[1] && replies[1].code === 0 && replies[1].held === true && replies[1].out === "", JSON.stringify(replies[1]))
  eq("a held answer reaches a command by name, decoded", replies[2] && replies[2].out, "p%w\nd+")
  check("a cancel holds nothing",
    replies[3] && replies[3].code === exits.cancelled && replies[3].held === false && replies[3].out === "", JSON.stringify(replies[3]))
  eq("nothing is injected for a cancel", replies[4] && replies[4].out, "")
}

async function main() {
  if (fs.existsSync(helper)) await throughHelper()
  else console.log("pinentry: skipping the helper checks, the helper is not built (cargo build --manifest-path vault/Cargo.toml --locked)")
  fs.rmSync(dir, { recursive: true, force: true })
  done()
}
main()
