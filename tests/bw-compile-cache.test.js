#!/usr/bin/env node
// Node's compile cache for `bw` (NODE_COMPILE_CACHE): compiled code that Node
// runs inside a process that sees the master password. The directory must be
// the user's own and private before the variable is ever set, the cache must
// change nothing `bw` prints or returns, and it must work beside the two
// NODE_OPTIONS preloads.
//
//   node tests/bw-compile-cache.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const { createSuite, functionBody, loadModule, read, repoRoot } = require("./harness")

const Model = loadModule()
const { check, done } = createSuite("bw-compile-cache")
const svc = read("Service.qml")

// The probe refuses a directory with a shared ancestor, which is what the
// usual temporary directory is. The cases that must pass need a root whose
// whole chain is the user's or root's: the runtime directory, else beside
// this file.
const underTmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-compile-cache-"))
const roots = [process.env.XDG_RUNTIME_DIR, __dirname].filter(d => d && path.isAbsolute(d) && fs.existsSync(d))
const mode = p => fs.lstatSync(p).mode & 0o7777
const run = home => {
  const cmd = Model.bwCompileCacheCommand(home)
  const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: Model.plainProbeEnv(process.env.PATH) })
  return { rc: r.status, line: String(r.stdout || "").replace(/\n$/, ""), dir: Model.bwCompileCacheAccepted(r.status, String(r.stdout || "").replace(/\n$/, "")) }
}
const probe = home => run(home).rc
let tmp = ""
for (const root of roots) {
  const candidate = fs.mkdtempSync(path.join(root, ".qsbw-compile-cache-"))
  fs.chmodSync(candidate, 0o700)
  fs.mkdirSync(path.join(candidate, "trial"), { mode: 0o700 })
  if (probe(path.join(candidate, "trial")) === 0) { tmp = fs.realpathSync(candidate); break }
  fs.rmSync(candidate, { recursive: true, force: true })
}
check("there is somewhere to test whose every ancestor is the user's or root's", tmp !== "", roots.join(" "))
if (tmp === "") { fs.rmSync(underTmp, { recursive: true, force: true }); done() }
process.on("exit", () => {
  fs.rmSync(tmp, { recursive: true, force: true })
  fs.rmSync(underTmp, { recursive: true, force: true })
})
let n = 0
// A fresh cache home, mode 0700 unless told otherwise.
const home = m => {
  const dir = path.join(tmp, "cache-" + (n++))
  fs.mkdirSync(dir)
  fs.chmodSync(dir, m === undefined ? 0o700 : m)
  return dir
}
const cacheOf = base => path.join(base, "qs-bitwarden-cli", "node-compile-cache")

// --- where it is --------------------------------------------------------------

check("the cache home is XDG_CACHE_HOME",
  Model.bwCompileCacheHome("/home/u/.cache", "/home/u") === "/home/u/.cache"
    && Model.bwCompileCacheHome("/var/cache/u/", "/home/u") === "/var/cache/u",
  Model.bwCompileCacheHome("/home/u/.cache", "/home/u"))
check("...else ~/.cache, when it is unset or empty",
  Model.bwCompileCacheHome("", "/home/u/") === "/home/u/.cache"
    && Model.bwCompileCacheHome(undefined, "/home/u") === "/home/u/.cache")
check("an XDG_CACHE_HOME that is set but not a plain absolute path means no cache, not ~/.cache",
  Model.bwCompileCacheHome("cache", "/home/u") === "" && Model.bwCompileCacheHome("/home/u/link/../cache", "/home/u") === ""
    && Model.bwCompileCacheHome("/home/u/..", "/home/u") === "" && Model.bwCompileCacheHome("/home/u/.cache\n", "/home/u") === ""
    && Model.bwCompileCacheHome("/home/u/a\nb", "/home/u") === "" && Model.bwCompileCacheHome("/home/u/a\tb", "/home/u") === "")
check("no usable home means no cache, never a temporary or shared directory",
  Model.bwCompileCacheHome("", "") === "" && Model.bwCompileCacheHome(undefined, "home") === ""
    && Model.bwCompileCacheHome("", "/home/u/../v") === "" && Model.bwCompileCacheHome("", "/home/u\n") === ""
    && !/tmp|XDG_RUNTIME_DIR/.test(functionBody(read("BitwardenModel.js"), "bwCompileCacheHome")))
check("a name with two dots in it is not a `..`",
  Model.bwCompileCacheHome("/home/u/..cache/a..b", "") === "/home/u/..cache/a..b")
check("the variable is Node's", Model.bwCompileCacheEnvVar() === "NODE_COMPILE_CACHE")

// --- the directory check --------------------------------------------------------

{
  const base = home()
  const dir = cacheOf(base)
  const first = run(base)
  check("a missing cache directory is created, it and the plugin's directory mode 0700",
    first.rc === 0 && mode(dir) === 0o700 && mode(path.dirname(dir)) === 0o700, JSON.stringify(first))
  check("the probe prints the directory it checked, and that is what is accepted",
    first.line === dir && first.dir === dir, JSON.stringify(first))
  check("...and accepted again as it is", run(base).dir === dir)
  fs.chmodSync(dir, 0o755)
  check("one Node recreated with the default umask is made private again",
    probe(base) === 0 && mode(dir) === 0o700, mode(dir).toString(8))
  const old = process.umask(0)
  const open = home()
  const made = run(open)
  process.umask(old)
  check("the directories are created 0700 whatever the umask",
    made.rc === 0 && mode(cacheOf(open)) === 0o700 && mode(path.dirname(cacheOf(open))) === 0o700,
    mode(cacheOf(open)).toString(8))
}
{
  const base = path.join(home(), "not-there-yet")
  check("a cache home that does not exist yet is created private, one level deep",
    run(base).dir === cacheOf(base) && mode(base) === 0o700 && mode(cacheOf(base)) === 0o700)
  const deep = path.join(home(), "not", "there")
  check("...and not a path with more than its last part missing",
    probe(deep) !== 0 && !fs.existsSync(path.dirname(deep)))
}
for (const [what, bad] of [["group-writable", 0o770], ["world-writable", 0o707], ["world-writable and sticky", 0o1777]]) {
  const base = home()
  const dir = cacheOf(base)
  fs.mkdirSync(dir, { recursive: true })
  fs.chmodSync(dir, bad)
  check(`a ${what} cache directory is refused and left as it was`,
    probe(base) !== 0 && mode(dir) === bad, mode(dir).toString(8))
  fs.chmodSync(dir, 0o700)
  fs.chmodSync(path.dirname(dir), bad)
  check(`...and so is one inside a ${what} plugin directory`, probe(base) !== 0)
  const shared = home(bad)
  check(`...and one under a ${what} cache home, where nothing is created`,
    probe(shared) !== 0 && !fs.existsSync(path.dirname(cacheOf(shared))))
  // The ancestor chain: a private cache home inside a shared directory.
  const above = home(bad)
  const inside = path.join(above, "private")
  fs.mkdirSync(inside, { mode: 0o700 })
  check(`...and one whose cache home sits inside a ${what} directory`,
    probe(inside) !== 0 && fs.readdirSync(inside).length === 0)
  const missing = path.join(above, "missing")
  check(`...where a missing cache home is not created either`, probe(missing) !== 0 && !fs.existsSync(missing))
}
{
  const inTmp = path.join(underTmp, "cache")
  fs.mkdirSync(inTmp, { mode: 0o700 })
  check("a private directory under the system's temporary directory is refused: /tmp is above it",
    mode(os.tmpdir()) !== 0o1777 || (probe(inTmp) !== 0 && fs.readdirSync(inTmp).length === 0))
}
{
  const base = home()
  const dir = cacheOf(base)
  const elsewhere = path.join(home(), "real")
  fs.mkdirSync(elsewhere, { mode: 0o700 })
  fs.mkdirSync(path.dirname(dir), { mode: 0o700 })
  fs.symlinkSync(elsewhere, dir)
  check("a symlink in the cache directory's place is refused", probe(base) !== 0)
  fs.unlinkSync(dir)
  fs.symlinkSync(path.join(tmp, "dangling"), dir)
  check("...a dangling one too, and nothing is created through it",
    probe(base) !== 0 && !fs.existsSync(path.join(tmp, "dangling")))
}
{
  const base = home()
  const elsewhere = path.join(home(), "real")
  fs.mkdirSync(elsewhere, { mode: 0o700 })
  fs.symlinkSync(elsewhere, path.dirname(cacheOf(base)))
  check("a symlink in the plugin directory's place is refused, and nothing is created through it",
    probe(base) !== 0 && fs.readdirSync(elsewhere).length === 0)
}
{
  // A cache home that is a symlink: what is checked and printed is where it
  // leads, so Node and the check cannot mean different directories.
  const real = home()
  const link = path.join(home(), "link")
  fs.symlinkSync(real, link)
  const viaLink = run(link)
  check("through a symlinked cache home the canonical directory is the one checked and printed",
    viaLink.rc === 0 && viaLink.dir === cacheOf(real) && viaLink.line.indexOf("link") === -1, JSON.stringify(viaLink))
  const shared = home(0o777)
  const privateInShared = path.join(shared, "private")
  fs.mkdirSync(privateInShared, { mode: 0o700 })
  const sneaky = path.join(home(), "link")
  fs.symlinkSync(privateInShared, sneaky)
  check("...and its own ancestors are the ones that count, not the link's",
    probe(sneaky) !== 0 && fs.readdirSync(privateInShared).length === 0)
  const dangling = path.join(home(), "dangling")
  fs.symlinkSync(path.join(tmp, "nowhere"), dangling)
  check("a dangling symlink as the cache home is refused, and nothing is created through it",
    probe(dangling) !== 0 && !fs.existsSync(path.join(tmp, "nowhere")))
}
{
  // The review's two cases: what the shell would check is not what Node opens.
  const base = home()
  fs.mkdirSync(path.join(base, "real", "inner"), { recursive: true, mode: 0o700 })
  fs.symlinkSync(path.join("real", "inner"), path.join(base, "link"))
  check("a path with `..` after a symlink never reaches the probe",
    Model.bwCompileCacheHome(path.join(base, "link") + "/../x", "") === "")
  const newline = path.join(base, "h\n")
  fs.mkdirSync(newline, { mode: 0o700 })
  check("...nor one ending in a newline, and the probe refuses it if it does",
    Model.bwCompileCacheHome(newline, "") === "" && probe(newline) !== 0
      && fs.readdirSync(newline).length === 0 && !fs.existsSync(path.join(base, "h")))
}
{
  const base = home()
  fs.mkdirSync(path.dirname(cacheOf(base)), { mode: 0o700 })
  fs.writeFileSync(cacheOf(base), "")
  check("a file in the cache directory's place is refused", probe(base) !== 0)
}
check("a directory this user does not own is refused",
  process.getuid() === 0 || probe("/usr") !== 0)
check("a relative or empty path is refused", probe("") !== 0 && probe("cache") !== 0)
check("only what the probe printed on success is accepted, and only as the cache directory",
  Model.bwCompileCacheAccepted(0, "/home/u/.cache/qs-bitwarden-cli/node-compile-cache") === "/home/u/.cache/qs-bitwarden-cli/node-compile-cache"
    && Model.bwCompileCacheAccepted(1, "/home/u/.cache/qs-bitwarden-cli/node-compile-cache") === ""
    && Model.bwCompileCacheAccepted(0, "") === "" && Model.bwCompileCacheAccepted(0, "/qs-bitwarden-cli/node-compile-cache") === "/qs-bitwarden-cli/node-compile-cache"
    && Model.bwCompileCacheAccepted(0, "/home/u/.cache") === "" && Model.bwCompileCacheAccepted(0, "qs-bitwarden-cli/node-compile-cache") === ""
    && Model.bwCompileCacheAccepted(0, "/home/u/../v/qs-bitwarden-cli/node-compile-cache") === ""
    && Model.bwCompileCacheAccepted(0, "/home/u/./qs-bitwarden-cli/node-compile-cache") === ""
    && Model.bwCompileCacheAccepted(0, "/home//u/qs-bitwarden-cli/node-compile-cache") === ""
    && Model.bwCompileCacheAccepted(0, "/home/u/qs-bitwarden-cli/node-compile-cache/") === "")
{
  const script = Model.bwCompileCacheCommand("/x")[2]
  check("owner and mode are checked on every directory up to /, and strictly on the two the plugin makes",
    /__ok\(\) \{ \[ -d "\$1" \] && \[ ! -L "\$1" \] \|\| return 1; __s="\$\(stat -c '%u %a' -- "\$1" 2>\/dev\/null\)" \|\| return 1; case "\$\{__s#\* \}" in \*\[0145\]\[0145\]\) ;; \*\) return 1 ;; esac; \[ "\$\{__s%% \*\}" = "\$__u" \] \|\| \{ \[ "\$2" = root \] && \[ "\$\{__s%% \*\}" = 0 \]; \}; \}/.test(script)
      && /while :; do __ok "\$__a" root \|\| return 1; \[ "\$__a" = \/ \] && break/.test(script)
      && /mkdir -m 700 -- "\$__x" \|\| exit 1; __ok "\$__x" \|\| exit 1/.test(script),
    script)
  check("directories are made by mode, never by umask, and no dirname is taken of the path",
    !/umask|dirname|mkdir -p/.test(script) && (script.match(/mkdir -m 700 -- /g) || []).length === 2, script)
  check("the path is an argument, not part of the script",
    Model.bwCompileCacheCommand("/a b/$(x)")[4] === "/a b/$(x)" && !/\/a b/.test(Model.bwCompileCacheCommand("/a b/$(x)")[2]))
  check("the probe runs with PATH and a fixed locale only",
    JSON.stringify(Model.plainProbeEnv("/usr/bin")) === JSON.stringify({ PATH: "/usr/bin", LC_ALL: "C" })
      && Model.plainProbeEnv("").PATH === "/usr/local/bin:/usr/bin:/bin"
      && /id: bwCompileCacheProc\s+command: Model\.bwCompileCacheCommand\(root\.bwCompileCacheHome\)\s+clearEnvironment: true\s+environment: Model\.plainProbeEnv\(Quickshell\.env\("PATH"\) \|\| ""\)\s+stdout: SplitParser \{\s+onRead: function\(line\) \{ root\.bwCompileCacheLine = line \}\s+\}\s+onExited: function\(exitCode\) \{ root\.onBwCompileCacheProbed\(exitCode\) \}/.test(svc))
}

// --- who gets it ----------------------------------------------------------------

check("the directory offered to bw is the one the probe printed, and nothing else sets it",
  /property string bwCompileCacheDir: ""/.test(svc)
    && /bwCompileCacheDir = Model\.bwCompileCacheAccepted\(exitCode, bwCompileCacheLine\)/.test(functionBody(svc, "onBwCompileCacheProbed"))
    && (svc.match(/\bbwCompileCacheDir = /g) || []).length === 1,
  functionBody(svc, "onBwCompileCacheProbed"))
check("the probe runs once at start, on the cache home the shell's own environment gives",
  /root\.probeBwCompileCache\(\)/.test(svc.slice(svc.indexOf("onLiveChanged: {"), svc.indexOf("readonly property var categories")))
    && /bwCompileCacheHome: Model\.bwCompileCacheHome\(\s*Quickshell\.env\("XDG_CACHE_HOME"\) \|\| "", Quickshell\.env\("HOME"\) \|\| ""\)/.test(svc))
check("nothing else names the variable: pinentry, which runs no bw, starts without it and without an inherited one",
  (svc.match(/bwCompileCacheEnvVar\(\)/g) || []).length === 2
    && Model.pinentryEnvironment({})[Model.bwCompileCacheEnvVar()] === null
    && /id: pinentryProbeProc\s+environment: Model\.withoutCompileCache\(\{\}\)/.test(svc)
    && !/COMPILE_CACHE/.test(read("pinentry/omarchy-pinentry")))

// Every other `bw` or `node` the plugin starts takes an inherited value out.
{
  const without = /Model\.withoutCompileCache\(\{\}\)/.source
  check("bw -v, the signed-out slot's bw logout, the SSH export, bw login in a terminal and opening an attachment drop an inherited cache",
    new RegExp("id: bwVersionProc\\s+property string probeId: \"\"\\s+command: Model\\.bwVersionCommand\\(\\)\\s+environment: " + without).test(svc)
      && new RegExp("id: sshExportProc\\s+command: Model\\.sshExportCommand\\(\\)\\s+environment: " + without).test(svc)
      && new RegExp("id: slotRemovalProc\\s+environment: " + without).test(svc)
      && new RegExp("execDetached\\(\\{ command: Model\\.terminalLoginCommand\\(mode, serverUrl, activeSlot\\),\\s+environment: " + without + " \\}\\)").test(svc)
      && new RegExp("var env = " + without + "\\s+env\\[Model\\.openPathEnvVar\\(\\)\\]").test(functionBody(svc, "openSavedAttachment")))
}

// The panel's own environment builders, run as they are written.
function service(state) {
  const v = Object.assign({ Model, bwNodeOptions: "", bwCompileCacheDir: "", bwCompileCacheLine: "",
    accountAppDataEnv: () => ({}) }, state)
  const names = ["bwEnv", "generatorServeEnv", "bwCompileCacheEnvValue", "onBwCompileCacheProbed"]
  Object.assign(v, new Function("scope", "with (scope) {\n" + names.map(nm => functionBody(svc, nm)).join("\n")
    + "\nreturn { " + names.join(", ") + " } }")(v))
  return v
}
// What a child gets: the shell's environment with the builder's on top, a
// null removing the variable, as Quickshell's Process and the vault helper
// (Command::env_remove) both apply it.
const childEnv = (inherited, built) => {
  const env = Object.assign({}, inherited)
  for (const k in built) { if (built[k] === null || built[k] === undefined) delete env[k]; else env[k] = String(built[k]) }
  return env
}

// --- Node, with the preloads ------------------------------------------------------

// A stand-in at the path the preloads look for, as tests/bw-fast-exit.test.js
// builds it: answers, records an exit code, and would idle on a timer.
const pluginDir = path.join(tmp, "plug in\"s")
fs.mkdirSync(pluginDir)
for (const file of ["bw-fast-exit.js", "bw-login-code.js"]) {
  fs.copyFileSync(path.join(repoRoot, file), path.join(pluginDir, file))
}
const cliDir = path.join(tmp, "node_modules", "@bitwarden", "cli", "build")
fs.mkdirSync(cliDir, { recursive: true })
fs.writeFileSync(path.join(cliDir, "dep.js"), "module.exports = function answer() { return \"answer\" }\n")
fs.writeFileSync(path.join(cliDir, "bw.js"),
  "const answer = require(\"./dep.js\")\nprocess.stdout.write(answer() + \" \" + process.argv.slice(2).join(\" \") + \"\\n\")\n"
  + "process.exitCode = 3\nsetTimeout(function () { process.stdout.write(\"late\\n\") }, 30000)\n")
const runBwWith = env => {
  const r = spawnSync(process.execPath, [path.join(cliDir, "bw.js"), "login", "--qsbw-code-from-env"],
    { encoding: "utf8", env, timeout: 20000 })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}
const entriesOf = dir => !fs.existsSync(dir) ? []
  : fs.readdirSync(dir, { recursive: true }).filter(f => fs.statSync(path.join(dir, f)).isFile())
const [major, minor] = process.versions.node.split(".").map(Number)
const supported = major > 22 || (major === 22 && minor >= 1)
const same = (a, b) => a.status === b.status && a.stdout === b.stdout && a.stderr === b.stderr
const options = Model.bwNodeOptions(pluginDir, "")

for (const builder of ["bwEnv", "generatorServeEnv"]) {
  // The shell was started with a cache directory of someone's choosing.
  const inheritedDir = path.join(home(), "inherited")
  const shellEnv = { PATH: process.env.PATH, NODE_OPTIONS: options, QSBW_CODE: "123456", NODE_COMPILE_CACHE: inheritedDir }

  const pending = service({ bwNodeOptions: options })
  check(`${builder}: before the probe has answered the variable is removed, not left to inheritance`,
    Model.bwCompileCacheEnvVar() in pending[builder]() && pending[builder]()[Model.bwCompileCacheEnvVar()] === null,
    JSON.stringify(pending[builder]()))
  const before = runBwWith(childEnv(shellEnv, pending[builder]()))
  check(`${builder}: ...so Node writes nothing into the inherited directory`,
    before.status === 3 && !fs.existsSync(inheritedDir), JSON.stringify(before))

  // A refused probe: a cache home anyone can write to.
  const refusedHome = home(0o777)
  const refused = service({ bwNodeOptions: options })
  const refusal = run(refusedHome)
  refused.bwCompileCacheLine = refusal.line
  refused.onBwCompileCacheProbed(refusal.rc)
  runBwWith(childEnv(shellEnv, refused[builder]()))
  check(`${builder}: a refused probe leaves no cache at all, inherited or its own`,
    refusal.rc !== 0 && refused.bwCompileCacheDir === "" && refused[builder]()[Model.bwCompileCacheEnvVar()] === null
      && !fs.existsSync(inheritedDir) && fs.readdirSync(refusedHome).length === 0)
  const lying = service({ bwNodeOptions: options })
  lying.bwCompileCacheLine = inheritedDir
  lying.onBwCompileCacheProbed(0)
  check(`${builder}: a probe that printed something other than the cache directory is not believed`,
    lying.bwCompileCacheDir === "" && lying[builder]()[Model.bwCompileCacheEnvVar()] === null)

  // An accepted probe: bw gets exactly the directory that was printed.
  const base = home()
  const ok = service({ bwNodeOptions: options })
  const accepted = run(base)
  ok.bwCompileCacheLine = accepted.line
  ok.onBwCompileCacheProbed(accepted.rc)
  check(`${builder}: an accepted probe's directory replaces the inherited one`,
    ok.bwCompileCacheDir === cacheOf(base) && ok[builder]()[Model.bwCompileCacheEnvVar()] === cacheOf(base)
      && ok.bwCompileCacheLine === "", JSON.stringify(ok[builder]()))
  if (builder === "bwEnv") {
    const plain = runBwWith(childEnv({ PATH: process.env.PATH, NODE_OPTIONS: options, QSBW_CODE: "123456" }, {}))
    const cold = runBwWith(childEnv(shellEnv, ok.bwEnv()))
    const written = entriesOf(cacheOf(base)).length
    const warm = runBwWith(childEnv(shellEnv, ok.bwEnv()))
    check("with the cache, bw prints and returns what it did without it, cold and warm",
      plain.status === 3 && plain.stdout === "answer login --code=123456\n" && same(plain, cold) && same(plain, warm),
      JSON.stringify([plain, cold, warm]))
    check("the preloads' early exit still lets Node write the cache, into the accepted directory only",
      !fs.existsSync(inheritedDir) && (!supported || written >= 2), "entries: " + written + " on Node " + process.versions.node)
    check("what is written is private to the user",
      entriesOf(cacheOf(base)).every(f => (mode(path.join(cacheOf(base), f)) & 0o077) === 0))
    // A cache someone damaged costs speed, not the answer.
    for (const f of entriesOf(cacheOf(base))) fs.writeFileSync(path.join(cacheOf(base), f), "not a code cache")
    check("a damaged cache entry is not an error", same(plain, runBwWith(childEnv(shellEnv, ok.bwEnv()))))
    check("bwEnv() still carries the preloads beside it, and what the caller adds",
      ok.bwEnv({ EXTRA: "1" }).NODE_OPTIONS === options && ok.bwEnv({ EXTRA: "1" }).EXTRA === "1")
  } else {
    check("the generator's server still gets no session",
      ok.generatorServeEnv()[Model.sessionEnvVar()] === null)
  }
}
// Positive control for the cases above: left alone, Node does use an inherited directory.
{
  const inheritedDir = path.join(home(), "inherited")
  runBwWith({ PATH: process.env.PATH, NODE_OPTIONS: options, QSBW_CODE: "123456", NODE_COMPILE_CACHE: inheritedDir })
  check("(Node does write to an inherited directory when nothing removes the variable)",
    !supported || entriesOf(inheritedDir).length >= 2)
}

done()
