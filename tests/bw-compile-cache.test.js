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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-compile-cache-"))
fs.chmodSync(tmp, 0o700)
const mode = p => fs.lstatSync(p).mode & 0o7777
const probe = dir => spawnSync(Model.bwCompileCacheCommand(dir)[0], Model.bwCompileCacheCommand(dir).slice(1),
  { encoding: "utf8" }).status
let n = 0
// A fresh cache home, mode 0700 unless told otherwise.
const home = m => {
  const dir = path.join(tmp, "cache-" + (n++))
  fs.mkdirSync(dir)
  fs.chmodSync(dir, m === undefined ? 0o700 : m)
  return dir
}

// --- where it is --------------------------------------------------------------

check("the cache is in the plugin's own directory under XDG_CACHE_HOME",
  Model.bwCompileCacheDir("/home/u/.cache", "/home/u") === "/home/u/.cache/qs-bitwarden-cli/node-compile-cache"
    && Model.bwCompileCacheDir("/var/cache/u/", "/home/u") === "/var/cache/u/qs-bitwarden-cli/node-compile-cache",
  Model.bwCompileCacheDir("/home/u/.cache", "/home/u"))
check("...else under ~/.cache, a relative XDG_CACHE_HOME being no path at all",
  Model.bwCompileCacheDir("", "/home/u/") === "/home/u/.cache/qs-bitwarden-cli/node-compile-cache"
    && Model.bwCompileCacheDir("cache", "/home/u") === "/home/u/.cache/qs-bitwarden-cli/node-compile-cache")
check("no absolute base means no cache, never a temporary or shared directory",
  Model.bwCompileCacheDir("", "") === "" && Model.bwCompileCacheDir(undefined, "home") === ""
    && !/tmp|XDG_RUNTIME_DIR/.test(functionBody(read("BitwardenModel.js"), "bwCompileCacheDir")))
check("the variable is Node's", Model.bwCompileCacheEnvVar() === "NODE_COMPILE_CACHE")

// --- the directory check --------------------------------------------------------

{
  const base = home()
  const dir = Model.bwCompileCacheDir(base, "")
  check("a missing cache directory is created, it and the plugin's directory mode 0700",
    probe(dir) === 0 && mode(dir) === 0o700 && mode(path.dirname(dir)) === 0o700,
    String(probe(dir)))
  check("...and accepted again as it is", probe(dir) === 0)
  fs.chmodSync(dir, 0o755)
  check("one Node recreated with the default umask is made private again",
    probe(dir) === 0 && mode(dir) === 0o700, mode(dir).toString(8))
}
{
  const base = path.join(home(), "not", "there", "yet")
  const dir = Model.bwCompileCacheDir(base, "")
  check("a cache home that does not exist yet is created private",
    probe(dir) === 0 && mode(base) === 0o700 && mode(dir) === 0o700)
}
for (const [what, bad] of [["group-writable", 0o770], ["world-writable", 0o707], ["world-writable and sticky", 0o1777]]) {
  const base = home()
  const dir = Model.bwCompileCacheDir(base, "")
  fs.mkdirSync(dir, { recursive: true })
  fs.chmodSync(dir, bad)
  check(`a ${what} cache directory is refused and left as it was`,
    probe(dir) !== 0 && mode(dir) === bad, mode(dir).toString(8))
  fs.chmodSync(dir, 0o700)
  fs.chmodSync(path.dirname(dir), bad)
  check(`...and so is one inside a ${what} plugin directory`, probe(dir) !== 0)
  const shared = home(bad)
  const inShared = Model.bwCompileCacheDir(shared, "")
  check(`...and one under a ${what} cache home, where nothing is created`,
    probe(inShared) !== 0 && !fs.existsSync(path.dirname(inShared)))
}
{
  const base = home()
  const dir = Model.bwCompileCacheDir(base, "")
  const elsewhere = path.join(home(), "real")
  fs.mkdirSync(elsewhere, { mode: 0o700 })
  fs.mkdirSync(path.dirname(dir), { mode: 0o700 })
  fs.symlinkSync(elsewhere, dir)
  check("a symlink in the cache directory's place is refused", probe(dir) !== 0)
  fs.unlinkSync(dir)
  fs.symlinkSync(path.join(tmp, "dangling"), dir)
  check("...a dangling one too, and nothing is created through it",
    probe(dir) !== 0 && !fs.existsSync(path.join(tmp, "dangling")))
}
{
  const base = home()
  const dir = Model.bwCompileCacheDir(base, "")
  const elsewhere = path.join(home(), "real")
  fs.mkdirSync(elsewhere, { mode: 0o700 })
  fs.symlinkSync(elsewhere, path.dirname(dir))
  check("a symlink in the plugin directory's place is refused, and nothing is created through it",
    probe(dir) !== 0 && fs.readdirSync(elsewhere).length === 0)
}
{
  const base = home()
  const dir = Model.bwCompileCacheDir(base, "")
  fs.mkdirSync(path.dirname(dir), { mode: 0o700 })
  fs.writeFileSync(dir, "")
  check("a file in the cache directory's place is refused", probe(dir) !== 0)
}
check("a directory this user does not own is refused",
  process.getuid() === 0 || probe("/usr/qs-bitwarden-cli/node-compile-cache") !== 0)
check("a relative or empty path is refused",
  probe("") !== 0 && probe("cache/qs-bitwarden-cli/node-compile-cache") !== 0)
{
  const script = Model.bwCompileCacheCommand("/x")[2]
  check("the owner and mode check covers the cache home, the plugin's directory and the cache directory",
    /__own\(\) \{ \[ -d "\$1" \] && \[ -O "\$1" \] \|\| return 1; case "\$\(stat -L -c %a -- "\$1" 2>\/dev\/null\)" in \*\[0145\]\[0145\]\) ;; \*\) return 1 ;; esac; \}/.test(script)
      && /__own "\$__b" \|\| exit 1/.test(script)
      && /for __x in "\$__p" "\$__d"; do if \[ -e "\$__x" \] \|\| \[ -L "\$__x" \]; then \[ ! -L "\$__x" \] && __own "\$__x" \|\| exit 1/.test(script),
    script)
  check("the path is an argument, not part of the script",
    Model.bwCompileCacheCommand("/a b/$(x)")[4] === "/a b/$(x)" && !/\/a b/.test(Model.bwCompileCacheCommand("/a b/$(x)")[2]))
}

// --- who gets it ----------------------------------------------------------------

check("the directory is offered to bw only after the probe accepted it",
  /property string bwCompileCacheDir: ""/.test(svc)
    && /bwCompileCacheDir = exitCode === 0 \? bwCompileCachePath : ""/.test(functionBody(svc, "onBwCompileCacheProbed"))
    && (svc.match(/\bbwCompileCacheDir = /g) || []).length === 1,
  functionBody(svc, "onBwCompileCacheProbed"))
check("the probe runs once at start, on the path the shell's own environment gives",
  /root\.probeBwCompileCache\(\)/.test(svc.slice(svc.indexOf("onLiveChanged: {"), svc.indexOf("readonly property var categories")))
    && /bwCompileCachePath: Model\.bwCompileCacheDir\(\s*Quickshell\.env\("XDG_CACHE_HOME"\) \|\| "", Quickshell\.env\("HOME"\) \|\| ""\)/.test(svc)
    && /id: bwCompileCacheProc\s+command: Model\.bwCompileCacheCommand\(root\.bwCompileCachePath\)\s+onExited: function\(exitCode\) \{ root\.onBwCompileCacheProbed\(exitCode\) \}/.test(svc))
const sets = /if \(bwCompileCacheDir\) env\[Model\.bwCompileCacheEnvVar\(\)\] = bwCompileCacheDir/
check("every bw the vault runs gets it through bwEnv(), beside the preloads",
  sets.test(functionBody(svc, "bwEnv")) && /env\.NODE_OPTIONS\s*=\s*bwNodeOptions/.test(functionBody(svc, "bwEnv")),
  functionBody(svc, "bwEnv"))
check("the generator's `bw serve` gets it too", sets.test(functionBody(svc, "generatorServeEnv")),
  functionBody(svc, "generatorServeEnv"))
check("nothing else names the variable: pinentry, which runs no bw, starts without it",
  (svc.match(/bwCompileCacheEnvVar\(\)/g) || []).length === 2
    && !/COMPILE_CACHE/.test(functionBody(read("BitwardenModel.js"), "pinentryEnvironment"))
    && !/COMPILE_CACHE/.test(read("pinentry/omarchy-pinentry")))

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
const runBw = cacheDir => {
  const env = { PATH: process.env.PATH, NODE_OPTIONS: Model.bwNodeOptions(pluginDir, ""), QSBW_CODE: "123456" }
  if (cacheDir) env.NODE_COMPILE_CACHE = cacheDir
  const r = spawnSync(process.execPath, [path.join(cliDir, "bw.js"), "login", "--qsbw-code-from-env"],
    { encoding: "utf8", env, timeout: 20000 })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}
const [major, minor] = process.versions.node.split(".").map(Number)
const supported = major > 22 || (major === 22 && minor >= 1)
{
  const dir = Model.bwCompileCacheDir(home(), "")
  const accepted = probe(dir) === 0
  const plain = runBw("")
  const cold = runBw(dir)
  const entries = () => fs.readdirSync(dir, { recursive: true }).filter(f => fs.statSync(path.join(dir, f)).isFile())
  const written = entries().length
  const warm = runBw(dir)
  const same = (a, b) => a.status === b.status && a.stdout === b.stdout && a.stderr === b.stderr
  check("with the cache, bw prints and returns what it did without it, cold and warm",
    accepted && plain.status === 3 && plain.stdout === "answer login --code=123456\n" && same(plain, cold) && same(plain, warm),
    JSON.stringify([plain, cold, warm]))
  check("the preloads' early exit still lets Node write the cache",
    !supported || written >= 2, "entries: " + written + " on Node " + process.versions.node)
  check("what is written is private to the user",
    entries().every(f => (mode(path.join(dir, f)) & 0o077) === 0), entries().map(f => mode(path.join(dir, f)).toString(8)).join(" "))
  // A cache someone damaged costs speed, not the answer.
  for (const f of entries()) fs.writeFileSync(path.join(dir, f), "not a code cache")
  check("a damaged cache entry is not an error", same(plain, runBw(dir)))
}

fs.rmSync(tmp, { recursive: true, force: true })
done()
