#!/usr/bin/env node
// Two places where data the panel did not write reaches the system: the
// session-handoff file path, and a vault item's URI on its way to xdg-open.
//
//   node tests/handoff-urls.test.js

const fs = require("fs")
const path = require("path")
const { execFileSync } = require("child_process")
const os = require("os")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.terminalLoginCommand = terminalLoginCommand
  exports.sessionHandoffReadCommand = sessionHandoffReadCommand
  exports.normalizeOpenableUrl = normalizeOpenableUrl
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- the session handoff file never falls back to a shared directory --------
// The key is written by a terminal and read by the panel. A world-writable
// fallback would let another user pre-create the directory and collect it.

const login = Model.terminalLoginCommand("login")[2]
const unlock = Model.terminalLoginCommand("unlock")[2]
const read = Model.sessionHandoffReadCommand(true)[2]

for (const [label, script] of [["terminal login", login], ["terminal unlock", unlock], ["handoff read", read]]) {
  check(`${label} never falls back to /tmp`, !script.includes("/tmp"), script)
  check(`${label} puts the key under XDG_RUNTIME_DIR`, script.includes("XDG_RUNTIME_DIR"), script)
}

check("the write side refuses to run without a runtime dir, rather than defaulting",
  /XDG_RUNTIME_DIR:\?/.test(login), login)
check("mkdir and chmod are both checked, so a directory that is not ours aborts",
  login.includes('mkdir -p "$d" || exit 1') && login.includes('chmod 700 "$d" || exit 1'), login)
check("the write side refuses a symlinked handoff directory",
  login.includes('[ ! -L "$d" ]'), login)
check("umask is set before the directory is created, not after",
  login.indexOf("umask 077") < login.indexOf("mkdir"), login)
check("the read side exits quietly instead, since it runs on every refresh",
  read.includes('[ -n "$d" ] || exit 0') && !/XDG_RUNTIME_DIR:\?/.test(read), read)
check("the read side never follows a symlinked directory or handoff file",
  read.includes('[ ! -L "$d" ]') && read.includes('[ ! -L "$f" ]'), read)

// Actually run the two scripts to prove the behaviour, with `bw` stubbed.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-handoff-"))
const bin = path.join(tmp, "bin")
fs.mkdirSync(bin)
fs.writeFileSync(path.join(bin, "bw"), "#!/usr/bin/env bash\necho STUBSESSIONKEY\n", { mode: 0o755 })

const runInner = (script, env) => {
  try {
    // stderr is swallowed: the no-runtime-dir case is *meant* to complain there.
    return { out: execFileSync("bash", ["-c", script], { env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(), code: 0 }
  } catch (e) {
    return { out: String(e.stdout || "").trim(), code: e.status }
  }
}

const noRuntime = { PATH: bin + ":" + process.env.PATH, HOME: tmp }
const withRuntime = { ...noRuntime, XDG_RUNTIME_DIR: tmp }

// The inner script is what the terminal runs; pull it out of the quoted wrapper.
const innerLogin = login.match(/omarchy launch terminal -e bash -c '(.*)' \|\| alacritty/)[1].replace(/'\\''/g, "'")

const denied = runInner(innerLogin, noRuntime)
check("with no runtime dir the login script exits non-zero and writes no key",
  denied.code !== 0 && !fs.existsSync(path.join(tmp, "qs-bitwarden-cli", "session-handoff")),
  `exit ${denied.code}`)

const readNoRuntime = runInner(read, noRuntime)
check("with no runtime dir the read is silent and successful",
  readNoRuntime.code === 0 && readNoRuntime.out === "", JSON.stringify(readNoRuntime))

// A pre-existing symlink must not redirect either side to a persistent or
// less-protected directory. XDG_RUNTIME_DIR is private, but refusing the
// redirect also makes a stale/misconfigured runtime fail closed.
const handoffDir = path.join(tmp, "qs-bitwarden-cli")
const redirectedDir = path.join(tmp, "redirected")
fs.mkdirSync(redirectedDir)
fs.symlinkSync(redirectedDir, handoffDir)
const symlinkWrite = runInner(innerLogin.replace(/omarchy-shell[^;]*;/, "true;").replace(/read -p[^;]*;?/, ""), withRuntime)
check("a symlinked handoff directory makes terminal login fail closed",
  symlinkWrite.code !== 0 && !fs.existsSync(path.join(redirectedDir, "session-handoff")),
  `exit ${symlinkWrite.code}`)
fs.writeFileSync(path.join(redirectedDir, "session-handoff"), "REDIRECTED")
const symlinkRead = runInner(read, withRuntime)
check("the panel does not read through a symlinked handoff directory",
  symlinkRead.out === "", JSON.stringify(symlinkRead))
fs.unlinkSync(handoffDir)

// With a runtime dir, the round trip works and the directory is private.
fs.mkdirSync(path.join(tmp, "qs-bitwarden-cli"), { recursive: true, mode: 0o755 })
runInner(innerLogin.replace(/omarchy-shell[^;]*;/, "true;").replace(/read -p[^;]*;?/, ""), withRuntime)
check("the handoff directory ends up private to the user",
  (fs.statSync(handoffDir).mode & 0o777) === 0o700,
  "0" + (fs.statSync(handoffDir).mode & 0o777).toString(8))

const roundTrip = runInner(read, withRuntime)
check("the panel reads the key back", roundTrip.out === "STUBSESSIONKEY", JSON.stringify(roundTrip))
const secondRead = runInner(read, withRuntime)
check("and the key is consumed, so a second read gets nothing",
  secondRead.out === "", JSON.stringify(secondRead))

fs.rmSync(tmp, { recursive: true, force: true })

// --- only web links are handed to xdg-open ----------------------------------
// A vault item's URI is data, and an org-shared item can be written by others.

const opens = (u) => Model.normalizeOpenableUrl(u)

for (const [input, expected] of [
  ["https://example.com", "https://example.com"],
  ["http://example.com/login", "http://example.com/login"],
  ["HTTPS://Example.COM", "HTTPS://Example.COM"],
  ["example.com", "https://example.com"],
  ["example.com:8443/login", "https://example.com:8443/login"],
  ["localhost:3000", "https://localhost:3000"],
  ["192.168.1.10:8006", "https://192.168.1.10:8006"]
]) {
  const r = opens(input)
  check(`${input} opens as ${expected}`, r.ok && r.url === expected, JSON.stringify(r))
}

for (const [input, scheme] of [
  ["file:///etc/passwd", "file"],
  ["ftp://files.example.com", "ftp"],
  ["javascript:alert(1)", "javascript"],
  ["data:text/html,<script>x</script>", "data"],
  ["mailto:someone@example.com", "mailto"],
  ["vnc://10.0.0.1", "vnc"],
  ["custom-app-handler://do-something", "custom-app-handler"]
]) {
  const r = opens(input)
  check(`${input} is refused`, !r.ok && r.scheme === scheme, JSON.stringify(r))
}

check("an empty URI is refused without naming a scheme",
  !opens("").ok && opens("").scheme === "", JSON.stringify(opens("")))
check("whitespace is trimmed rather than https-ified",
  opens("  https://example.com  ").url === "https://example.com", JSON.stringify(opens("  https://example.com  ")))
check("an ambiguous backslash web URL is refused instead of parsed differently by the browser",
  !opens("https://evil.example\\@trusted.example").ok
    && opens("https://evil.example\\@trusted.example").reason === "ambiguous",
  JSON.stringify(opens("https://evil.example\\@trusted.example")))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
