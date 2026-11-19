#!/usr/bin/env node
// Node's compile cache for `bw` (NODE_COMPILE_CACHE), an opt-in setting
// (`bwCompileCache`, off by default): compiled code that Node runs inside a
// process that sees the master password. With the setting off nothing is
// checked or created and the variable is removed wherever the plugin starts
// `bw` or `node`. With it on, the directory must be the user's own and
// private, contents included, before the variable is ever set; only a `bw`
// that is given no password gets it; the cache must change nothing `bw`
// prints or returns, and it must work beside the two NODE_OPTIONS preloads.
//
//   node tests/bw-compile-cache.test.js
//
// The directory checks need somewhere whose every ancestor is the user's or
// root's and writable by no one else. Whether a directory is one is decided
// here with plain filesystem calls (harness.privateScratchDir()), never by
// the check under test: the check must then accept it, or the suite fails.
// Only where this machine has no such directory at all are those checks
// skipped, loudly, and the rest still run.

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const { createSuite, functionBody, loadModule, privateScratchDir, read, repoRoot } = require("./harness")

const Model = loadModule()
const { check, done } = createSuite("bw-compile-cache")
const svc = read("Service.qml")
const modelSrc = read("BitwardenModel.js")
const VAR = Model.bwCompileCacheEnvVar()

const underTmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-compile-cache-"))
const mode = p => fs.lstatSync(p).mode & 0o7777
const run = home => {
  const cmd = Model.bwCompileCacheCommand(home)
  const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", env: Model.plainProbeEnv(process.env.PATH) })
  const out = String(r.stdout || "")
  return { rc: r.status, out, line: out.replace(/\n$/, ""), dir: Model.bwCompileCacheAccepted(r.status, out) }
}
const probe = home => run(home).rc
// QSBW_TEST_NO_TRUSTED_DIR=1 runs the suite as a machine with none would.
const tmp = process.env.QSBW_TEST_NO_TRUSTED_DIR === "1" ? "" : privateScratchDir(".qsbw-compile-cache-")
process.on("exit", () => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
  fs.rmSync(underTmp, { recursive: true, force: true })
})
const trusted = tmp !== ""
if (!trusted) {
  console.log("bw-compile-cache: SKIPPED the directory checks and the runs through Node: this user can write to no directory"
    + " whose whole ancestor chain is its own or root's and closed to group and others (tried $XDG_RUNTIME_DIR, $RUNNER_TEMP,"
    + " the account's home and " + __dirname + "). The setting, environment and script-text checks still run.")
} else {
  // The fixture is private by this suite's own reading of owners and modes:
  // a check that refuses it is broken, and nothing below may hide that.
  const trial = path.join(tmp, "trial")
  fs.mkdirSync(trial, { mode: 0o700 })
  const r = run(trial)
  const accepted = r.rc === 0 && r.dir === path.join(trial, "qs-bitwarden-cli", "node-compile-cache")
  check("the check accepts a cache home that is private by this suite's own reading of the filesystem (" + tmp + ")",
    accepted, JSON.stringify(r))
  // Everything below builds on that: stop here, with the reason.
  if (!accepted) { done(); process.exit(1) }
}
let n = 0
// A fresh cache home, mode 0700 unless told otherwise.
const home = m => {
  const dir = path.join(tmp, "cache-" + (n++))
  fs.mkdirSync(dir)
  fs.chmodSync(dir, m === undefined ? 0o700 : m)
  return dir
}
const cacheOf = base => path.join(base, "qs-bitwarden-cli", "node-compile-cache")

// --- the setting -----------------------------------------------------------------

{
  const manifest = JSON.parse(read("manifest.json"))
  const entry = Model.SETTINGS_SCHEMA.find(e => e.key === "bwCompileCache")
  const inManifest = manifest.barWidget.schema.find(e => e.key === "bwCompileCache")
  check("bwCompileCache is a General bool, off by default",
    !!entry && entry.group === "general" && entry.type === "bool" && entry.defaultValue === false, JSON.stringify(entry))
  check("...and the manifest says the same, word for word",
    !!inManifest && inManifest.type === "boolean" && inManifest.defaultValue === false
      && inManifest.label === entry.label && inManifest.description === entry.description
      && manifest.barWidget.defaults.bwCompileCache === false, JSON.stringify(inManifest))
  check("only `true` turns it on",
    Model.boolSetting("bwCompileCache", true) === true && Model.boolSetting("bwCompileCache", "true") === false
      && Model.boolSetting("bwCompileCache", 1) === false && Model.boolSetting("bwCompileCache", undefined) === false)
  check("its description says where the cache is, what it holds, what a program running as you can do with it, and that off leaves the directory",
    /~\/\.cache\/qs-bitwarden-cli\/node-compile-cache/.test(entry.description) && /XDG_CACHE_HOME/.test(entry.description)
      && /compiled code, nothing of your vault/.test(entry.description)
      && /program running as you that can write there can run code inside bw/.test(entry.description)
      && /Off by default/.test(entry.description) && /leaves the directory/.test(entry.description)
      && /docs\/uninstall\.md/.test(entry.description), entry.description)
  check("the service reads it through boolSetting, off when unset, and Settings shows it",
    /readonly property bool bwCompileCache: Model\.boolSetting\("bwCompileCache", setting\("bwCompileCache", false\)\)/.test(svc)
      && /case "bwCompileCache": return bwCompileCache/.test(functionBody(svc, "settingValue")))
  check("the README lists it with the other settings",
    /\| `bwCompileCache` \| `boolean` \| `false` \|/.test(read("README.md")))
  check("the row says when the cache is on but not in use, and nothing otherwise",
    Model.bwCompileCacheNote(false, "/h/.cache", "refused") === "" && Model.bwCompileCacheNote(true, "/h/.cache", "accepted") === ""
      && Model.bwCompileCacheNote(true, "/h/.cache", "pending") === ""
      && /^Not in use/.test(Model.bwCompileCacheNote(true, "/h/.cache", "refused"))
      && /XDG_CACHE_HOME/.test(Model.bwCompileCacheNote(true, "", "refused"))
      && /Model\.bwCompileCacheNote\(bwCompileCache, bwCompileCacheHome, bwCompileCacheState\)/.test(functionBody(svc, "settingNote")))
}

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
    && !/tmp|XDG_RUNTIME_DIR/.test(functionBody(modelSrc, "bwCompileCacheHome")))
check("a name with two dots in it is not a `..`",
  Model.bwCompileCacheHome("/home/u/..cache/a..b", "") === "/home/u/..cache/a..b")
check("the variable is Node's", VAR === "NODE_COMPILE_CACHE")

// --- what is accepted of the probe's answer ---------------------------------------

{
  const good = "/home/u/.cache/qs-bitwarden-cli/node-compile-cache"
  const ok = text => Model.bwCompileCacheAccepted(0, text)
  check("only what the probe printed on success is accepted, and only as the cache directory",
    ok(good + "\n") === good && Model.bwCompileCacheAccepted(1, good + "\n") === ""
      && ok("") === "" && ok("\n") === "" && ok("/qs-bitwarden-cli/node-compile-cache\n") === "/qs-bitwarden-cli/node-compile-cache"
      && ok("/home/u/.cache\n") === "" && ok("qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/u/../v/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/u/./qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home//u/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/u/qs-bitwarden-cli/node-compile-cache/\n") === "")
  check("exactly one whole line: not a cut one, not two, nothing after it",
    ok(good) === "" && ok(good + "\n" + good + "\n") === "" && ok("x\n" + good + "\n") === ""
      && ok(good + "\n\n") === "" && ok(good + "\r\n") === "" && ok(undefined) === "" && ok(null) === "")
  check("a path with anything but printable ASCII is not accepted: what Qt decoded may not be the bytes that were checked",
    ok("/home/\ufffd/.cache/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/\u00e9/.cache/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/u\x7f/.cache/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/u\t/.cache/qs-bitwarden-cli/node-compile-cache\n") === ""
      && ok("/home/a b/.cache/qs-bitwarden-cli/node-compile-cache\n") === "/home/a b/.cache/qs-bitwarden-cli/node-compile-cache")
}

// --- the probe's script ------------------------------------------------------------

{
  const script = Model.bwCompileCacheCommand("/x")[2]
  check("owner and mode are checked on every directory up to /, and strictly on the two the plugin makes",
    script.indexOf("__ok() { [ -d \"$1\" ] && [ ! -L \"$1\" ] || return 1; __s=\"$(stat -c '%u %a' -- \"$1\" 2>/dev/null)\" || return 1; "
        + "case \"${__s#* }\" in *[0145][0145]) ;; *) return 1 ;; esac; [ \"${__s%% *}\" = \"$__u\" ] || { [ \"$2\" = root ] && [ \"${__s%% *}\" = 0 ]; }; }; ") !== -1
      && /while :; do __ok "\$__a" root \|\| return 1; \[ "\$__a" = \/ \] && break/.test(script)
      && /for __d in "\$__p" "\$__x"; do __there "\$__d" \|\| mkdir -m 700 -- "\$__d" \|\| exit 1; __ok "\$__d" \|\| exit 1; done; /.test(script),
    script)
  check("directories are made by mode, never by umask, and no dirname is taken of the path",
    !/umask|dirname|mkdir -p/.test(script) && (script.match(/mkdir -m 700 -- /g) || []).length === 2, script)
  check("the path is an argument, not part of the script",
    Model.bwCompileCacheCommand("/a b/$(x)")[4] === "/a b/$(x)" && !/\/a b/.test(Model.bwCompileCacheCommand("/a b/$(x)")[2]))
  check("the path must be printable ASCII, by bytes, and plain: as given, before anything at all, and as resolved, before anything is made under it",
    script.indexOf("exec 2>/dev/null; LC_ALL=C; case \"$1\" in *[!\\ -~]*|*/../*|*/..) exit 1 ;; /*) ;; *) exit 1 ;; esac; ") === 0
      && script.indexOf("case \"$__c\" in *[!\\ -~]*) return 1 ;; /*) ;; *) return 1 ;; esac; ") !== -1
      && script.indexOf("case \"$__c\" in *[!") < script.indexOf("__chain \"${__h%/*}/\" || exit 1")
      && script.indexOf("__chain \"${__h%/*}/\" || exit 1") < script.indexOf("mkdir -m 700"), script)
  const find = "__bad=\"$(timeout 5 find \"$__p\" -mindepth 1 \\( ! \\( -type f -o -type d \\) -o ! -uid \"$__u\" -o -perm /022 \\) -printf x -quit)\" || exit 1; [ -z \"$__bad\" ] || exit 1; fi; "
  check("what is already in the plugin's directory is looked at in bounded finds (one for strangers beside the cache, one for its contents) that follow no symlink and stop at the first offender",
    script.indexOf(find) !== -1 && (script.match(/\bfind\b/g) || []).length === 2 && !/find -L|-follow/.test(script), script)
  check("a refusal changes nothing: what is there is judged before the two directories are made, and modes are set last, once everything has passed",
    script.indexOf("if __there \"$__p\"; then __ok \"$__p\" || exit 1; "
        + "__o=\"$(timeout 5 find \"$__p\" -mindepth 1 -maxdepth 1 ! -name node-compile-cache -printf x -quit)\" || exit 1; [ -z \"$__o\" ] || exit 1; "
        + "if __there \"$__x\"; then __ok \"$__x\" || exit 1; fi; __bad=") !== -1
      && script.indexOf(find) < script.indexOf("for __d in")
      && (script.match(/\bchmod\b/g) || []).length === 1
      && /done; \[ "\$\(realpath -e -- "\$__x" && printf x\)" = "\$__x"\$'\\n'x \] \|\| exit 1; chmod 00700 -- "\$__p" "\$__x" \|\| exit 1; printf '%s\\n' "\$__x"$/.test(script), script)
  check("the probe runs with PATH and a fixed locale only, and its whole output is what is judged",
    JSON.stringify(Model.plainProbeEnv("/usr/bin")) === JSON.stringify({ PATH: "/usr/bin", LC_ALL: "C" })
      && Model.plainProbeEnv("").PATH === "/usr/local/bin:/usr/bin:/bin"
      && /id: bwCompileCacheProc\s+property int probeSeq: 0\s+command: Model\.bwCompileCacheCommand\(root\.bwCompileCacheHome\)\s+clearEnvironment: true\s+environment: Model\.plainProbeEnv\(Quickshell\.env\("PATH"\) \|\| ""\)\s+stdout: StdioCollector \{ id: bwCompileCacheOut; waitForEnd: true \}\s+onExited: function\(exitCode\) \{ root\.onBwCompileCacheProbed\(probeSeq, exitCode, bwCompileCacheOut\.text\) \}/.test(svc))
}

// --- the directory check, on a real filesystem -----------------------------------

if (trusted) {
  {
    const base = home()
    const dir = cacheOf(base)
    const first = run(base)
    check("a missing cache directory is created, it and the plugin's directory mode 0700",
      first.rc === 0 && mode(dir) === 0o700 && mode(path.dirname(dir)) === 0o700, JSON.stringify(first))
    check("the probe prints the directory it checked, and that is what is accepted",
      first.line === dir && first.out === dir + "\n" && first.dir === dir, JSON.stringify(first))
    check("...and accepted again as it is", run(base).dir === dir)
    fs.chmodSync(dir, 0o755)
    check("one Node recreated with the default umask is made private again",
      probe(base) === 0 && mode(dir) === 0o700, mode(dir).toString(8))
    fs.chmodSync(path.dirname(dir), 0o755)
    check("...and so is the plugin's directory above it, which holds nothing else: with it private, whatever is recreated inside is out of others' reach",
      probe(base) === 0 && mode(path.dirname(dir)) === 0o700 && mode(dir) === 0o700, mode(path.dirname(dir)).toString(8))
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
    fs.chmodSync(dir, 0o755)
    fs.chmodSync(path.dirname(dir), bad)
    check(`...and so is one inside a ${what} plugin directory, with neither mode touched`,
      probe(base) !== 0 && mode(path.dirname(dir)) === bad && mode(dir) === 0o755)
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
    // What the shell would check is not what Node opens.
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
    // The path QML reads back: only one it cannot get wrong.
    const accented = path.join(home(), "caf\u00e9")
    fs.mkdirSync(accented, { mode: 0o700 })
    check("a cache home with a non-ASCII character is refused, and nothing is created in it",
      probe(accented) !== 0 && fs.readdirSync(accented).length === 0)
    const missingAccented = path.join(home(), "caf\u00e9-not-there")
    const underAccented = path.join(accented, "not-there")
    check("...and one that does not exist yet is not created, by that name or under a parent with one",
      probe(missingAccented) !== 0 && !fs.existsSync(missingAccented) && probe(underAccented) !== 0 && !fs.existsSync(underAccented))
    const viaAscii = path.join(home(), "plain")
    fs.symlinkSync(accented, viaAscii)
    check("...also when an ASCII symlink leads to it: the canonical path is the one that counts",
      probe(viaAscii) !== 0 && fs.readdirSync(accented).length === 0)
    // A name that is not UTF-8 at all, which Qt would decode to U+FFFD.
    const rawParent = home()
    const raw = Buffer.concat([Buffer.from(rawParent + "/bad"), Buffer.from([0xff, 0xfe])])
    fs.mkdirSync(raw, { mode: 0o700 })
    const link = path.join(home(), "to-raw")
    fs.symlinkSync(raw, link)
    const viaRaw = run(link)
    check("a canonical path that is not valid UTF-8 is refused, where Qt would otherwise hand Node other bytes",
      viaRaw.rc !== 0 && viaRaw.dir === "" && fs.readdirSync(raw).length === 0, JSON.stringify(viaRaw))
    const spaced = path.join(home(), "a b~c")
    fs.mkdirSync(spaced, { mode: 0o700 })
    check("a space or any other printable ASCII character in the path is fine",
      run(spaced).dir === cacheOf(spaced))
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

  // What is already in the cache directory. Node opens entries by name and
  // follows a symlink it finds, so one planted there could lead it to a file
  // someone else can write.
  {
    // As Node lays it out: one directory per Node build, files inside.
    const filled = () => {
      const base = home()
      const version = path.join(cacheOf(base), "v22.0.0-x64-00000000-0")
      fs.mkdirSync(version, { recursive: true, mode: 0o755 })
      fs.chmodSync(path.dirname(cacheOf(base)), 0o700)
      fs.chmodSync(cacheOf(base), 0o700)
      fs.writeFileSync(path.join(version, "aaaa"), "x", { mode: 0o600 })
      return { base, version }
    }
    const clean = filled()
    check("a cache as Node leaves it (a 0755 directory of 0600 files inside the private one) is accepted",
      run(clean.base).dir === cacheOf(clean.base), JSON.stringify(run(clean.base)))
    const outside = path.join(home(), "outside")
    fs.writeFileSync(outside, "code")
    const cases = [
      ["a symlink to a file among the entries", f => fs.symlinkSync(outside, path.join(f.version, "bbbb"))],
      ["a symlink in place of the version directory", f => fs.symlinkSync(path.dirname(outside), path.join(cacheOf(f.base), "v23.0.0-x64-00000000-0"))],
      ["a dangling symlink", f => fs.symlinkSync(path.join(tmp, "nothing-here"), path.join(f.version, "cccc"))],
      ["a symlink at the top of the cache directory", f => fs.symlinkSync(outside, path.join(cacheOf(f.base), "dddd"))],
      ["a group-writable directory inside", f => fs.chmodSync(f.version, 0o775)],
      ["a world-writable directory inside", f => fs.chmodSync(f.version, 0o757)],
      ["a nested world-writable directory", f => { fs.mkdirSync(path.join(f.version, "deep")); fs.chmodSync(path.join(f.version, "deep"), 0o777) }],
      ["a group-writable file inside", f => fs.chmodSync(path.join(f.version, "aaaa"), 0o660)],
      ["a world-writable file inside", f => fs.chmodSync(path.join(f.version, "aaaa"), 0o606)],
      ["a FIFO inside", f => { if (spawnSync("mkfifo", [path.join(f.version, "eeee")]).status !== 0) throw new Error("mkfifo") }]
    ]
    for (const [what, plant] of cases) {
      const f = filled()
      plant(f)
      const before = fs.readdirSync(f.version).sort().join()
      // As Node leaves them after recreating: a refusal must not tighten them.
      fs.chmodSync(cacheOf(f.base), 0o755)
      fs.chmodSync(path.dirname(cacheOf(f.base)), 0o755)
      const r = run(f.base)
      check(`a cache with ${what} is refused, and left as it was, modes included`,
        r.rc !== 0 && r.dir === "" && r.out === "" && fs.readdirSync(f.version).sort().join() === before
          && mode(cacheOf(f.base)) === 0o755 && mode(path.dirname(cacheOf(f.base))) === 0o755, JSON.stringify(r))
    }
    {
      // A plugin directory that is not the cache's alone: XDG_CACHE_HOME set
      // to the data or state home, where the plugin keeps accounts and
      // learned picks under the same name.
      for (const [what, plant] of [["a directory of the plugin's data", d => fs.mkdirSync(path.join(d, "accounts"), { mode: 0o700 })],
        ["a file", d => fs.writeFileSync(path.join(d, "associations.json"), "{}", { mode: 0o600 })],
        ["a hidden file", d => fs.writeFileSync(path.join(d, ".hidden"), "", { mode: 0o600 })]]) {
        for (const withCache of [true, false]) {
          const base = home()
          const dir = path.dirname(cacheOf(base))
          fs.mkdirSync(withCache ? cacheOf(base) : dir, { recursive: true, mode: 0o755 })
          fs.chmodSync(dir, 0o755)
          plant(dir)
          const before = fs.readdirSync(dir).sort().join()
          check(`a plugin directory that also holds ${what} is refused${withCache ? "" : " before a cache directory is made in it"}, and nothing in it is made or has its mode changed`,
            probe(base) !== 0 && mode(dir) === 0o755 && fs.readdirSync(dir).sort().join() === before
              && (!withCache || mode(cacheOf(base)) === 0o755), mode(dir).toString(8) + " " + fs.readdirSync(dir).join())
        }
      }
      const sg = home()
      fs.mkdirSync(cacheOf(sg), { recursive: true })
      fs.chmodSync(path.dirname(cacheOf(sg)), 0o2750)
      fs.chmodSync(cacheOf(sg), 0o2755)
      check("0700 means exactly that: a setgid bit on either directory is cleared by a check that passes",
        probe(sg) === 0 && mode(cacheOf(sg)) === 0o700 && mode(path.dirname(cacheOf(sg))) === 0o700,
        mode(cacheOf(sg)).toString(8) + " " + mode(path.dirname(cacheOf(sg))).toString(8))
      const sgHome = home()
      fs.chmodSync(sgHome, 0o2700)
      check("...and directories made inside a setgid cache home, which inherit the bit, end without it",
        run(sgHome).dir === cacheOf(sgHome) && mode(cacheOf(sgHome)) === 0o700 && mode(path.dirname(cacheOf(sgHome))) === 0o700,
        mode(cacheOf(sgHome)).toString(8))
    }
    {
      const f = filled()
      fs.symlinkSync(outside, path.join(path.dirname(cacheOf(f.base)), "beside"))
      check("a symlink beside the cache directory, in the plugin's directory, is refused too: the whole of that directory is the plugin's",
        probe(f.base) !== 0)
      const fresh = home()
      fs.mkdirSync(path.dirname(cacheOf(fresh)), { mode: 0o700 })
      fs.symlinkSync(outside, path.join(path.dirname(cacheOf(fresh)), "beside"))
      check("...and then the cache directory is not made either", probe(fresh) !== 0 && !fs.existsSync(cacheOf(fresh)))
    }
    // An unreadable directory inside: find fails, and so does the probe.
    const unread = filled()
    fs.mkdirSync(path.join(unread.version, "closed"), { mode: 0o700 })
    fs.chmodSync(path.join(unread.version, "closed"), 0o000)
    check("a directory inside that cannot be read is a refusal, not a pass",
      process.getuid() === 0 || probe(unread.base) !== 0)
    fs.chmodSync(path.join(unread.version, "closed"), 0o700)

    // A cache the size bw's is (about 1,600 files): the look inside must
    // not make the probe slow.
    const big = filled()
    for (let i = 0; i < 1600; i++) fs.writeFileSync(path.join(big.version, "f" + i), "x", { mode: 0o600 })
    const times = []
    for (let i = 0; i < 9; i++) {
      const t0 = process.hrtime.bigint()
      const r = run(big.base)
      times.push(Number(process.hrtime.bigint() - t0) / 1e6)
      if (r.dir !== cacheOf(big.base)) times.push(Infinity)
    }
    times.sort((a, b) => a - b)
    const median = times[Math.floor(times.length / 2)]
    console.log(`bw-compile-cache: probe over a cache of 1,600 files: median ${median.toFixed(1)} ms of ${times.length} runs`)
    // 50 ms is the aim on the machine it was written on (about 20); the
    // bound here leaves room for a loaded CI runner.
    check("the probe over a cache of 1,600 files is accepted and quick", median < 250, median.toFixed(1) + " ms")
    fs.symlinkSync(outside, path.join(big.version, "zzzz-planted"))
    check("...and one symlink among the 1,600 is still found", probe(big.base) !== 0)
  }
}

// --- who gets it ----------------------------------------------------------------

check("the directory offered to bw is the one the probe printed; a new check withdraws it first, and nothing else sets it",
  /property string bwCompileCacheDir: ""/.test(svc)
    && /bwCompileCacheDir = Model\.bwCompileCacheAccepted\(exitCode, output\)/.test(functionBody(svc, "onBwCompileCacheProbed"))
    && /^function probeBwCompileCache\(\) \{\s+bwCompileCacheDir = ""/.test(functionBody(svc, "probeBwCompileCache"))
    && (svc.match(/\bbwCompileCacheDir = /g) || []).length === 2,
  functionBody(svc, "onBwCompileCacheProbed"))
check("the check runs at start, when the setting changes and every time the vault becomes unlocked, before that opening's reads start",
  /root\.probeBwCompileCache\(\)/.test(svc.slice(svc.indexOf("onLiveChanged: {"), svc.indexOf("readonly property var categories")))
    && /\n  onBwCompileCacheChanged: probeBwCompileCache\(\)\n/.test(svc)
    && /onStatusChanged: \{\s+\/\/[^\n]*\n\s+if \(status === "unlocked"\) probeBwCompileCache\(\)\s+promoteUnlockToApproval\(\)\s+maybeStartupLoad\(\)/.test(svc)
    // Those three and no other: the rest are the definition and a comment.
    && (svc.match(/^[^/\n]*\bprobeBwCompileCache\(\)(?! \{)/gm) || []).length === 3
    && /bwCompileCacheHome: Model\.bwCompileCacheHome\(\s*Quickshell\.env\("XDG_CACHE_HOME"\) \|\| "", Quickshell\.env\("HOME"\) \|\| ""\)/.test(svc))
check("that is all the feature keeps: the directory, what the last check came to, and the count that tells answers apart. No clock, no credit from one opening to the next",
  svc.split("\n").filter(l => /^\s*(?:readonly )?property \w+ bwCompileCache\w*:/.test(l)).map(l => l.trim().split(":")[0]).join("; ")
    === "readonly property bool bwCompileCache; readonly property string bwCompileCacheHome; property string bwCompileCacheDir; "
      + "property string bwCompileCacheState; property int bwCompileCacheProbeSeq"
    && !/Date\.now|Timer/.test(["probeBwCompileCache", "startBwCompileCacheProbe", "onBwCompileCacheProbed", "bwCompileCacheEnvValue", "bwEnvAtStart"]
      .map(name => functionBody(svc, name)).join("\n"))
    && !/isUnlocking/.test(svc.slice(svc.indexOf("property string bwCompileCacheDir"), svc.indexOf("function bwEnv(extra)")))
    && !/CheckIsRecent|TRUST_MS/.test(modelSrc))
check("only bwEnv(), the generator's server and the last word at a start name the variable; pinentry, which runs no bw, starts without an inherited one",
  (svc.match(/bwCompileCacheEnvVar\(\)/g) || []).length === 3
    && /var name = Model\.bwCompileCacheEnvVar\(\)\s+if \(env && env\[name\] !== undefined && env\[name\] !== null\) env\[name\] = bwCompileCacheEnvValue\(\)\s+return env/.test(functionBody(svc, "bwEnvAtStart"))
    && /env\[Model\.bwCompileCacheEnvVar\(\)\] = bwCompileCacheEnvValue\(\)/.test(functionBody(svc, "bwEnv"))
    && /env\[Model\.bwCompileCacheEnvVar\(\)\] = bwCompileCacheEnvValue\(\)/.test(functionBody(svc, "generatorServeEnv"))
    && Model.pinentryEnvironment({})[VAR] === null
    && /id: pinentryProbeProc\s+environment: Model\.withoutCompileCache\(\{\}\)/.test(svc)
    && !/COMPILE_CACHE/.test(read("pinentry/omarchy-pinentry")))
check("a bw that is given the master password or a login's credentials never gets the cache: unlock and the process waiting for it, every login, the password check",
  /^function bwSecretEnv\(extra\) \{\s+return Model\.withoutCompileCache\(bwEnv\(extra\)\)\s+\}$/.test(functionBody(svc, "bwSecretEnv"))
    && /^function authEnv\(password, clientId, clientSecret, code\) \{\s+var env = bwSecretEnv\(\)/.test(functionBody(svc, "authEnv"))
    && !/bwEnv\(/.test(functionBody(svc, "authEnv").replace(/bwSecretEnv\(/g, ""))
    && !/bwEnv\(/.test(functionBody(svc, "loginProcessEnv").replace(/bwSecretEnv\(/g, ""))
    && /var deviceEnv = bwSecretEnv\(\)/.test(functionBody(svc, "loginProcessEnv"))
    && /command: Model\.bwVerifyPasswordCommand\(\),\s+env: bwSecretEnv\(env\)/.test(functionBody(svc, "verifyWithBw"))
    && /id: unlockProc\s+vault: root\s+capture: "session"\s+command: Model\.unlockPrewarmCommand\(\)\s+environment: root\.authEnv\("", "", "", ""\)/.test(svc)
    && /id: loginProc\s+vault: root\s+capture: "session"\s+environment: root\.loginProcessEnv\(\)/.test(svc)
    && /id: authPasswordWriterProc\s+vault: root\s+session: false\s+environment: root\.authEnv\(/.test(svc)
    // Nothing else is handed the password variable.
    && (svc.match(/Model\.passwordEnvVar\(\)/g) || []).length === 1 && /Model\.passwordEnvVar\(\)/.test(functionBody(svc, "authEnv")))

// Every other `bw` or `node` the plugin starts takes an inherited value out.
{
  const without = /Model\.withoutCompileCache\(\{\}\)/.source
  check("bw -v, the signed-out slot's bw logout, the SSH export, bw login in a terminal and opening an attachment drop an inherited cache",
    new RegExp("id: bwVersionProc\\s+property string probeId: \"\"\\s+command: Model\\.bwVersionCommand\\(\\)\\s+environment: " + without).test(svc)
      && new RegExp("id: sshExportProc\\s+command: Model\\.sshExportCommand\\(\\)\\s+environment: " + without).test(svc)
      && new RegExp("id: slotRemovalProc\\s+environment: " + without).test(svc)
      && new RegExp("execDetached\\(\\{ command: Model\\.terminalLoginCommand\\(mode, serverUrl, activeSlot\\),\\s+environment: " + without + " \\}\\)").test(svc)
      && new RegExp("var env = " + without + "\\s+env\\[Model\\.openPathEnvVar\\(\\)\\]").test(functionBody(svc, "openSavedAttachment")))
  check("withoutCompileCache() sets the variable to null, which a Process and the vault helper unset, and keeps the rest",
    JSON.stringify(Model.withoutCompileCache({ A: "1" })) === JSON.stringify({ A: "1", NODE_COMPILE_CACHE: null })
      && JSON.stringify(Model.withoutCompileCache()) === JSON.stringify({ NODE_COMPILE_CACHE: null })
      && Model.vaultEnv(Model.withoutCompileCache({}))[VAR] === null)
}

// The inventory: every model function whose script starts `bw` or `node`
// (or the pinentry, a node script), and how the cache variable reaches it.
// A new one that is not listed here fails the suite, so it cannot be added
// without deciding.
{
  const fns = {}
  const re = /^function ([A-Za-z0-9_]+)\([^)]*\) \{\n([\s\S]*?)^\}/gm
  let m
  while ((m = re.exec(modelSrc))) fns[m[1]] = m[2].split("\n").filter(l => !/^\s*\/\//.test(l)).join("\n")
  const starts = body => /(^|[^A-Za-z_.\/-])(bw|node) (-|[a-z"$\\])/.test(body) || /NODE_UNCACHED|var inner = "bw"|\["bw", |bundledPinentry\(/.test(body)
  const found = new Set(Object.keys(fns).filter(name => starts(fns[name])))
  for (let grew = true; grew;) {
    grew = false
    for (const name in fns) {
      if (found.has(name)) continue
      for (const dep of found) {
        if (new RegExp("\\b" + dep + "\\(").test(fns[name])) { found.add(name); grew = true; break }
      }
    }
  }
  // `env`: the expression the process that runs it is given, as a pattern
  // over Service.qml. "cached": bwEnv() (or one built on it), so the
  // accepted directory with the setting on and the variable removed
  // otherwise. "removed": always removed.
  const bwEnvOf = id => new RegExp("id: " + id + "\\b[^}]*?environment: root\\.(?:bwEnv|itemEnv|folderEnv|sendEnv)\\(")
  // "removed" for these: built on bwSecretEnv(), for a bw given a password.
  const secretEnvOf = id => new RegExp("id: " + id + "\\b[^}]*?environment: root\\.(?:loginProcessEnv|authEnv)\\(")
  const builtOnBwEnv = ["itemEnv", "folderEnv", "sendEnv"].every(name => /\bbwEnv\(/.test(functionBody(svc, name)))
    && /root\.bwEnv\(\)/.test(functionBody(svc, "vaultListEnv"))
  const sites = {
    // bw itself, through bwEnv(): the cache when it is on and accepted.
    statusCommand: ["cached", bwEnvOf("statusProc"), /command: Model\.statusCommand\(\),\s+env: bwEnv\(\), session: true/,
      /lockProc\.environment = run\.env/, /lockQueue = lockQueue\.concat\(\[\{ env: bwEnv\(\), key: name/],
    lockCommand: ["cached", /lockProc\.environment = run\.env/, /argv: Model\.lockCommand\(\),\s+env: Model\.vaultEnv\(bwEnv\(\)\)/,
      /var env = bwEnv\(\)\s+env\[Model\.sessionEnvVar\(\)\] = String\(session\)\s+Quickshell\.execDetached\(\{ command: Model\.lockCommand\(\), environment: env \}\)/],
    logoutCommand: ["cached", bwEnvOf("logoutProc")],
    syncCommand: ["cached", bwEnvOf("syncProc")],
    listOrganizationsCommand: ["cached", bwEnvOf("listOrgsProc")],
    listFoldersCommand: ["cached", bwEnvOf("listFoldersProc")],
    listOrgCollectionsCommand: ["cached", bwEnvOf("orgCollectionsProc")],
    listSendsCommand: ["cached", bwEnvOf("listSendsProc")],
    createSendCommand: ["cached", bwEnvOf("createSendProc")],
    deleteSendCommand: ["cached", bwEnvOf("deleteSendProc")],
    createFolderCommand: ["cached", bwEnvOf("createFolderProc")],
    getItemCommand: ["cached", bwEnvOf("getItemProc")],
    getTotpCommand: ["cached", bwEnvOf("getTotpProc")],
    getPasswordCommand: ["cached", bwEnvOf("copyPasswordProc"), bwEnvOf("autoTypeReadProc")],
    deleteItemCommand: ["cached", bwEnvOf("deleteItemProc")],
    generateCommand: ["cached", bwEnvOf("generateProc")],
    generateServeCommand: ["cached", /id: generateServeProc\s+command: Model\.generateServeCommand\(\)\s+environment: root\.generatorServeEnv\(\)/],
    // bw with a `node -e` check beside it in one script: bw as above, the
    // check through NODE_UNCACHED.
    sanitizedListCommand: ["cached", /listProc\.environment = root\.vaultListEnv\(/, bwEnvOf("listProc")],
    createItemCommand: ["cached", bwEnvOf("createItemProc")],
    editItemCommand: ["cached", bwEnvOf("editItemProc")],
    attachmentDownloadCommand: ["cached", bwEnvOf("attachmentProc")],
    // Never the cache, setting on or off. First the ones that are given the
    // master password or a login's credentials.
    unlockPrewarmCommand: ["removed", secretEnvOf("unlockProc")],
    emailLoginPrewarmCommand: ["removed", secretEnvOf("loginProc")],
    deviceVerificationLoginCommand: ["removed", secretEnvOf("loginProc")],
    apiKeyLoginCommand: ["removed", secretEnvOf("loginProc")],
    bwVerifyPasswordCommand: ["removed", /command: Model\.bwVerifyPasswordCommand\(\),\s+env: bwSecretEnv\(env\)/],
    bwVersionCommand: ["removed", /id: bwVersionProc\b[^}]*?environment: Model\.withoutCompileCache\(\{\}\)/],
    accountSlotRemoveCommand: ["removed", /id: slotRemovalProc\s+environment: Model\.withoutCompileCache\(\{\}\)/],
    accountSlotRetireCommand: ["removed", /id: slotRemovalProc\s+environment: Model\.withoutCompileCache\(\{\}\)/],
    terminalLoginCommand: ["removed", /execDetached\(\{ command: Model\.terminalLoginCommand\([^)]*\),\s+environment: Model\.withoutCompileCache\(\{\}\) \}\)/],
    attachmentOpenCommand: ["removed", /var env = Model\.withoutCompileCache\(\{\}\)\s+env\[Model\.openPathEnvVar\(\)\] = String\(path\)\s+Quickshell\.execDetached\(\{ command: Model\.attachmentOpenCommand\(\), environment: env \}\)/],
    sshExportCommand: ["removed", /id: sshExportProc\s+command: Model\.sshExportCommand\(\)\s+environment: Model\.withoutCompileCache\(\{\}\)/],
    pinentryCommand: ["removed", /pinentryProc\.environment = Model\.pinentryEnvironment\(ask\)/],
    pinentryProbeCommand: ["removed", /id: pinentryProbeProc\s+environment: Model\.withoutCompileCache\(\{\}\)/]
  }
  // Pieces of the scripts above, and functions that only mention `bw` or
  // `node` in a message.
  const parts = ["agentBranchScript", "buildCappedCommand", "savePipelineScript", "serverConfigPrefix"]
  const words = ["autoTypeFailureMessage", "bwCompileCacheNote", "parseDependencies", "parsePluginDataRemoval",
    "pinentryMissingNotice"]
  const listed = new Set(Object.keys(sites).concat(parts, words))
  const unlisted = [...found].filter(name => !listed.has(name))
  const gone = [...listed].filter(name => !found.has(name))
  check("every model function that starts bw or node is in the inventory, and the inventory lists nothing else",
    unlisted.length === 0 && gone.length === 0, "not listed: " + unlisted.join(", ") + "; listed but not found: " + gone.join(", "))
  check("the environments built on bwEnv() are", builtOnBwEnv)
  const wrong = []
  for (const name in sites) {
    const [, ...patterns] = sites[name]
    if (!new RegExp("Model\\." + name + "\\(").test(svc)) wrong.push(name + ": not used by the service")
    patterns.forEach((p, i) => { if (!p.test(svc)) wrong.push(name + " #" + i) })
  }
  check("each one runs in the environment the inventory says", wrong.length === 0, wrong.join("; "))
  const uses = name => (svc.match(new RegExp("Model\\." + name + "\\(", "g")) || []).length
  check("...and nowhere else: each command is assigned as many times as the inventory accounts for",
    uses("lockCommand") === 3 && uses("statusCommand") === 3 && uses("getPasswordCommand") === 2
      && uses("emailLoginPrewarmCommand") === 2 && uses("unlockPrewarmCommand") === 2
      && uses("pinentryCommand") === 1 + (svc.match(/\(Model\.pinentryCommand\(\)\)/g) || []).length
      && Object.keys(sites).filter(k => !["lockCommand", "statusCommand", "getPasswordCommand", "emailLoginPrewarmCommand",
        "unlockPrewarmCommand", "pinentryCommand", "generateServeCommand", "attachmentOpenCommand"].includes(k))
        .every(k => uses(k) === 1),
    Object.keys(sites).map(k => k + "=" + uses(k)).join(" "))
  // The other QML files start neither.
  const others = fs.readdirSync(repoRoot).filter(f => f.endsWith(".qml") && f !== "Service.qml")
  const strays = others.filter(f => Object.keys(sites).some(k => new RegExp("Model\\." + k + "\\(").test(read(f).replace(/^\s*\/\/.*$/gm, ""))))
  check("no other QML file starts one of them", strays.length === 0, strays.join())
}

// The `node -e` checks that share a script with bw.
{
  const nodeStarts = modelSrc.split("\n").filter(l => !/^\s*\/\//.test(l) && /(^|[^A-Za-z_.\/-])node -e\b/.test(l))
  check("no script starts a bare `node -e`: each goes through NODE_UNCACHED",
    nodeStarts.length === 0 && (modelSrc.match(/NODE_UNCACHED \+ " -e "/g) || []).length === 6
      && /var NODE_UNCACHED = "env -u " \+ BW_COMPILE_CACHE_ENV \+ " node"/.test(modelSrc), nodeStarts.join("\n"))
  const text = cmd => cmd.join(" ")
  const scripts = [Model.sanitizedListCommand({ agentBranch: true }), Model.createItemCommand({}), Model.editItemCommand("id", 1),
    Model.attachmentDownloadCommand("a", "i", 10), Model.attachmentOpenCommand(), Model.sshExportCommand()]
  check("...so the list, save, attachment and export scripts start node only as `env -u NODE_COMPILE_CACHE node`",
    scripts.every(s => /env -u NODE_COMPILE_CACHE node -e /.test(text(s))
      && !/(^|[^E] )node -e /.test(text(s).replace(/env -u NODE_COMPILE_CACHE node -e /g, ""))),
    scripts.map(s => (text(s).match(/.{0,30}node -e/g) || []).join(" | ")).join("\n"))
  check("the list script's two checks both do (the validator, and the writer that hands SSH keys to the agent)",
    (text(Model.sanitizedListCommand({ agentBranch: true })).match(/env -u NODE_COMPILE_CACHE node -e /g) || []).length === 2
      && /timeout 10 env -u NODE_COMPILE_CACHE node -e /.test(text(Model.sanitizedListCommand({ agentBranch: true }))))
}

// The terminal hand-off: the script that runs inside the terminal.
{
  const cmd = Model.terminalLoginCommand("login", "https://vault.example.com", "default")
  const outer = cmd[2]
  check("the script the terminal runs unsets the variable itself, before any bw",
    (outer.match(/set -u; unset NODE_COMPILE_CACHE; bw\(\) \{ command env -u NODE_COMPILE_CACHE bw "\$@"; \}; /g) || []).length === 2
      && outer.split("bash -c ").slice(1).every(inner => inner.indexOf("unset NODE_COMPILE_CACHE; ") < inner.indexOf("bw ")), outer)
  // Run it: a launcher that, like a terminal started by the session manager,
  // gives the script an environment of its own with the variable set.
  const dir = fs.mkdtempSync(path.join(underTmp, "term-"))
  const bin = path.join(dir, "bin")
  const seen = path.join(dir, "seen")
  fs.mkdirSync(bin)
  fs.mkdirSync(path.join(dir, "run"), { mode: 0o700 })
  fs.writeFileSync(path.join(bin, "bw"),
    "#!/bin/bash\nprintf '%s\\t%s\\n' \"${NODE_COMPILE_CACHE-<unset>}\" \"$*\" >> " + JSON.stringify(seen)
      + "\ncase \"$1\" in login|unlock) printf 'c2Vzc2lvbi1rZXktc2Vzc2lvbi1rZXktc2Vzc2lvbi1rZXk=' ;; esac\nexit 0\n", { mode: 0o755 })
  for (const launcher of ["omarchy", "alacritty"]) {
    // `omarchy launch terminal -e bash -c <script>` / `alacritty -e bash -c <script>`.
    fs.writeFileSync(path.join(bin, launcher),
      "#!/bin/bash\nwhile [ $# -gt 0 ] && [ \"$1\" != -e ]; do shift; done; shift\n"
        + "export NODE_COMPILE_CACHE=/somewhere/else/cache\nexec \"$@\" </dev/null\n", { mode: 0o755 })
  }
  fs.writeFileSync(path.join(bin, "omarchy-shell"), "#!/bin/bash\nexit 0\n", { mode: 0o755 })
  fs.writeFileSync(path.join(bin, "sleep"), "#!/bin/bash\nexit 0\n", { mode: 0o755 })
  for (const [verb, url, expected] of [["login", "https://vault.example.com", ["config server https://vault.example.com", "login --raw"]],
    ["unlock", "", ["unlock --raw"]]]) {
    fs.rmSync(seen, { force: true })
    const c = Model.terminalLoginCommand(verb, url, "default")
    const env = Object.assign({ PATH: bin + ":" + process.env.PATH, HOME: dir, XDG_RUNTIME_DIR: path.join(dir, "run") },
      { NODE_COMPILE_CACHE: "/inherited/by/the/shell" })
    const r = spawnSync(c[0], c.slice(1), { encoding: "utf8", env, timeout: 20000 })
    const lines = fs.existsSync(seen) ? fs.readFileSync(seen, "utf8").split("\n").filter(Boolean) : []
    check(`bw ${verb} in the terminal sees no NODE_COMPILE_CACHE, though the terminal's own environment has one`,
      r.status === 0 && lines.length === expected.length
        && lines.every((l, i) => l === "<unset>\t" + expected[i]), JSON.stringify([r.status, r.stderr, lines]))
  }
  // A startup file named by BASH_ENV, read by the terminal's `bash -c`,
  // that exports the variable and makes it readonly: `unset` cannot remove
  // it, so every bw of the script is started through `env -u`.
  {
    const startup = path.join(dir, "bash-env")
    fs.writeFileSync(startup, "export NODE_COMPILE_CACHE=/from/bash/env\nreadonly NODE_COMPILE_CACHE\n")
    fs.rmSync(seen, { force: true })
    // bw as it is, a Node program: a bash stand-in would read the startup
    // file itself and export the variable again.
    const bashBw = fs.readFileSync(path.join(bin, "bw"))
    fs.writeFileSync(path.join(bin, "bw"), "#!/usr/bin/env node\n"
      + "const c = process.env.NODE_COMPILE_CACHE\n"
      + "require('fs').appendFileSync(" + JSON.stringify(seen) + ", (c === undefined ? '<unset>' : c) + '\\t' + process.argv.slice(2).join(' ') + '\\n')\n"
      + "if (/^(login|unlock)$/.test(process.argv[2])) process.stdout.write('c2Vzc2lvbi1rZXktc2Vzc2lvbi1rZXktc2Vzc2lvbi1rZXk=')\n", { mode: 0o755 })
    const c = Model.terminalLoginCommand("login", "https://vault.example.com", "default")
    const r = spawnSync(c[0], c.slice(1), { encoding: "utf8", timeout: 20000,
      env: { PATH: bin + ":" + process.env.PATH, HOME: dir, XDG_RUNTIME_DIR: path.join(dir, "run"), BASH_ENV: startup } })
    const lines = fs.existsSync(seen) ? fs.readFileSync(seen, "utf8").split("\n").filter(Boolean) : []
    // The same script without the wrapper: the control for this case.
    fs.rmSync(seen, { force: true })
    spawnSync(c[0], [c[1], c[2].replace(/bw\(\) \{[^}]*\}; /g, "")], { encoding: "utf8", timeout: 20000,
      env: { PATH: bin + ":" + process.env.PATH, HOME: dir, XDG_RUNTIME_DIR: path.join(dir, "run"), BASH_ENV: startup } })
    const bare = fs.existsSync(seen) ? fs.readFileSync(seen, "utf8").split("\n").filter(Boolean) : []
    fs.writeFileSync(path.join(bin, "bw"), bashBw, { mode: 0o755 })
    check("(with unset alone, that readonly value does reach bw)",
      bare.length === 2 && bare.every(l => l.split("\t")[0] === "/from/bash/env"), JSON.stringify(bare))
    check("with the variable exported readonly by a BASH_ENV file, where unset fails, bw config and bw login in the terminal still see none",
      r.status === 0 && lines.join("|") === "<unset>\tconfig server https://vault.example.com|<unset>\tlogin --raw",
      JSON.stringify([r.status, lines]))
  }
  // Positive control: the same launcher without the unset and the wrapper
  // does pass it on.
  fs.rmSync(seen, { force: true })
  const c = Model.terminalLoginCommand("unlock", "", "default")
  spawnSync(c[0], [c[1], c[2].replace(/unset NODE_COMPILE_CACHE; bw\(\) \{[^}]*\}; /g, "")], { encoding: "utf8", timeout: 20000,
    env: { PATH: bin + ":" + process.env.PATH, HOME: dir, XDG_RUNTIME_DIR: path.join(dir, "run") } })
  check("(without the unset, that launcher's value does reach bw)",
    fs.existsSync(seen) && fs.readFileSync(seen, "utf8") === "/somewhere/else/cache\tunlock --raw\n",
    fs.existsSync(seen) ? fs.readFileSync(seen, "utf8") : "no bw ran")
}

// --- the panel's own environment builders, run as they are written ----------------

function service(state) {
  const v = Object.assign({ Model, bwNodeOptions: "", started: true, bwCompileCache: true,
    bwCompileCacheHome: "/h/.cache", bwCompileCacheDir: "", bwCompileCacheState: "off",
    bwCompileCacheProbeSeq: 0, status: "locked", warnings: [], later: [],
    // The probe process: `running` set true is a start; its exit is answer().
    bwCompileCacheProc: { running: false, probeSeq: 0, starts: 0 },
    accountAppDataEnv: () => ({}) }, state)
  Object.defineProperty(v.bwCompileCacheProc, "running", {
    get() { return this._running === true },
    set(on) { if (on && !this._running) this.starts++; this._running = on }
  })
  v.console = { warn: text => v.warnings.push(text) }
  v.Qt = { callLater: fn => v.later.push(fn) }
  const names = ["bwEnv", "generatorServeEnv", "bwCompileCacheEnvValue", "onBwCompileCacheProbed",
    "probeBwCompileCache", "startBwCompileCacheProbe", "bwEnvAtStart", "bwSecretEnv", "authEnv"]
  Object.assign(v, new Function("scope", "with (scope) {\n" + names.map(nm => functionBody(svc, nm)).join("\n")
    + "\nreturn { " + names.join(", ") + " } }")(v))
  // The running probe exits with `rc` and `out`.
  v.answer = (rc, out) => {
    const seq = v.bwCompileCacheProc.probeSeq
    v.bwCompileCacheProc.running = false
    v.onBwCompileCacheProbed(seq, rc, out)
    v.later.splice(0).forEach(fn => fn())
  }
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
const GOOD = "/h/.cache/qs-bitwarden-cli/node-compile-cache"

for (const builder of ["bwEnv", "generatorServeEnv"]) {
  const inherited = { PATH: "/usr/bin", NODE_COMPILE_CACHE: "/inherited/cache" }
  const value = v => v[builder]()[VAR]
  const reaches = v => childEnv(inherited, v[builder]()).NODE_COMPILE_CACHE

  // The setting off.
  const off = service({ bwCompileCache: false })
  off.probeBwCompileCache()
  check(`${builder}: with the setting off no probe runs, and an inherited value is removed, not left to inheritance`,
    off.bwCompileCacheProc.starts === 0 && off.bwCompileCacheState === "off"
      && VAR in off[builder]() && value(off) === null && reaches(off) === undefined, JSON.stringify(off[builder]()))
  const offButAccepted = service({ bwCompileCache: false, bwCompileCacheDir: GOOD, bwCompileCacheState: "accepted" })
  check(`${builder}: ...even with a directory accepted earlier still on record: off wins at the moment of use`,
    value(offButAccepted) === null && reaches(offButAccepted) === undefined)

  // On, the probe not yet answered.
  const pending = service({})
  pending.probeBwCompileCache()
  check(`${builder}: on, while the check is running, the variable is removed`,
    pending.bwCompileCacheProc.starts === 1 && pending.bwCompileCacheState === "pending"
      && value(pending) === null && reaches(pending) === undefined)

  // On, refused.
  pending.answer(1, "")
  check(`${builder}: on, a refused check leaves no cache at all, inherited or its own, and says so in the log`,
    pending.bwCompileCacheState === "refused" && pending.bwCompileCacheDir === "" && value(pending) === null
      && reaches(pending) === undefined && pending.warnings.length === 1)
  const lying = service({})
  lying.probeBwCompileCache()
  lying.answer(0, "/inherited/cache\n")
  check(`${builder}: a check that printed something other than the cache directory is not believed`,
    lying.bwCompileCacheDir === "" && lying.bwCompileCacheState === "refused" && value(lying) === null)

  // On, accepted.
  const ok = service({})
  ok.probeBwCompileCache()
  ok.answer(0, GOOD + "\n")
  check(`${builder}: on and accepted, bw gets exactly the directory the check printed, in place of the inherited one`,
    ok.bwCompileCacheState === "accepted" && value(ok) === GOOD && reaches(ok) === GOOD && ok.warnings.length === 0,
    JSON.stringify(ok[builder]()))

  // Checked again: nothing is believed until the new answer.
  ok.probeBwCompileCache()
  check(`${builder}: a new check withdraws the accepted directory until it has answered`,
    ok.bwCompileCacheState === "pending" && ok.bwCompileCacheDir === "" && value(ok) === null && reaches(ok) === undefined
      && ok.bwCompileCacheProc.starts === 2)
  ok.answer(1, "")
  check(`${builder}: ...and if that one refuses (the directory has changed), the cache stays unused`,
    ok.bwCompileCacheState === "refused" && value(ok) === null)

  // Turned off after being accepted.
  const toggled = service({})
  toggled.probeBwCompileCache()
  toggled.answer(0, GOOD + "\n")
  toggled.bwCompileCache = false
  check(`${builder}: turned off, the next bw start has no cache, before any handler has run`,
    value(toggled) === null && reaches(toggled) === undefined)
  toggled.probeBwCompileCache()
  check(`${builder}: ...and the change handler forgets the directory and starts nothing`,
    toggled.bwCompileCacheDir === "" && toggled.bwCompileCacheState === "off" && toggled.bwCompileCacheProc.starts === 1)
}

{
  // Answers that are no longer wanted.
  const v = service({})
  v.probeBwCompileCache()
  v.bwCompileCache = false
  v.probeBwCompileCache()
  v.answer(0, GOOD + "\n")
  check("a check answered after the setting was turned off is dropped",
    v.bwCompileCacheDir === "" && v.bwCompileCacheState === "off" && v.bwEnv()[VAR] === null && v.bwCompileCacheProc.starts === 1)
  v.bwCompileCache = true
  check("...and nothing of it comes back when the setting is turned on again, until a new check passes",
    v.bwEnv()[VAR] === null)

  const again = service({})
  again.probeBwCompileCache()
  again.probeBwCompileCache()
  check("a check asked for while one is running waits for it, and does not start a second process",
    again.bwCompileCacheProc.starts === 1 && again.bwCompileCacheState === "pending")
  again.answer(0, GOOD + "\n")
  check("...the first one's answer is for an earlier question and is not taken; the check runs again",
    again.bwCompileCacheDir === "" && again.bwCompileCacheProc.starts === 2 && again.bwCompileCacheState === "pending")
  again.answer(0, GOOD + "\n")
  check("...and the second one's is", again.bwCompileCacheDir === GOOD && again.bwCompileCacheState === "accepted")

  const offOn = service({})
  offOn.probeBwCompileCache()
  offOn.bwCompileCache = false
  offOn.probeBwCompileCache()
  offOn.bwCompileCache = true
  offOn.probeBwCompileCache()
  offOn.answer(1, "")
  check("off and on again while a check runs: the old answer (a refusal here) is dropped and a new check decides",
    offOn.bwCompileCacheState === "pending" && offOn.bwCompileCacheProc.starts === 2)
  offOn.answer(0, GOOD + "\n")
  check("...and its answer stands", offOn.bwCompileCacheDir === GOOD)

  const noHome = service({ bwCompileCacheHome: "" })
  noHome.probeBwCompileCache()
  check("on with no usable cache home: nothing runs, nothing is used, and the row can say why",
    noHome.bwCompileCacheProc.starts === 0 && noHome.bwCompileCacheState === "refused" && noHome.bwEnv()[VAR] === null
      && /XDG_CACHE_HOME/.test(Model.bwCompileCacheNote(true, "", noHome.bwCompileCacheState)))
  const early = service({ started: false })
  early.probeBwCompileCache()
  check("before the service has started (the setting's first value arriving) nothing runs; the start does it",
    early.bwCompileCacheProc.starts === 0 && early.bwCompileCacheState === "off")

  // A check that answered an earlier question starts the next one later
  // (Qt.callLater). `exit()` is the process ending; `runLater()` the event
  // loop reaching what was put off.
  const deferred = () => {
    const v = service({})
    v.exit = (rc, out) => { const seq = v.bwCompileCacheProc.probeSeq; v.bwCompileCacheProc.running = false; v.onBwCompileCacheProbed(seq, rc, out) }
    v.runLater = () => v.later.splice(0).forEach(fn => fn())
    v.probeBwCompileCache()
    v.probeBwCompileCache()
    v.exit(0, GOOD + "\n")
    return v
  }
  const optedOut = deferred()
  const putOff = optedOut.later.length
  optedOut.bwCompileCache = false
  optedOut.probeBwCompileCache()
  optedOut.runLater()
  check("the setting turned off between a check ending and the next one being started: nothing starts, so nothing is made",
    putOff === 1 && optedOut.bwCompileCacheProc.starts === 1 && optedOut.bwCompileCacheProc.running === false
      && optedOut.bwCompileCacheState === "off" && optedOut.bwCompileCacheDir === "")
  const offNoHandler = deferred()
  offNoHandler.bwCompileCache = false
  offNoHandler.runLater()
  check("...even before the setting's own handler has run", offNoHandler.bwCompileCacheProc.starts === 1)
  const answered = deferred()
  answered.bwCompileCacheState = "refused"
  answered.runLater()
  check("...and nothing starts for a question that is no longer open", answered.bwCompileCacheProc.starts === 1)
  const asked = deferred()
  asked.probeBwCompileCache()
  asked.runLater()
  check("asked again in that moment: what starts answers the newest question, once",
    asked.bwCompileCacheProc.starts === 2 && asked.bwCompileCacheProc.probeSeq === asked.bwCompileCacheProbeSeq && asked.bwCompileCacheProbeSeq === 3)
  asked.runLater()
  asked.exit(0, GOOD + "\n")
  check("...and its answer stands", asked.bwCompileCacheDir === GOOD && asked.bwCompileCacheProc.starts === 2)
  const stale = service({ bwCompileCacheState: "accepted", bwCompileCacheDir: GOOD, bwCompileCacheProbeSeq: 4 })
  stale.onBwCompileCacheProbed(4, 1, "")
  check("an answer arriving when no question is open changes nothing", stale.bwCompileCacheDir === GOOD && stale.bwCompileCacheState === "accepted")

  // The vault opening: the status becoming "unlocked", by whatever way.
  check("every opening is checked for itself, and nothing carries over from a check made before it",
    (() => {
      const v = service({})
      // As onStatusChanged does.
      const to = status => { v.status = status; if (status === "unlocked") v.probeBwCompileCache() }
      v.probeBwCompileCache()
      v.answer(0, GOOD + "\n")
      const beforeOpening = v.bwEnv()[VAR]
      to("unlocked")
      const firstReads = v.bwEnv()[VAR]
      const startsAtOpening = v.bwCompileCacheProc.starts
      v.answer(0, GOOD + "\n")
      const laterReads = v.bwEnv()[VAR]
      to("locked")
      const locked = v.bwCompileCacheProc.starts
      to("unlocked")
      const second = [v.bwCompileCacheProc.starts, v.bwEnv()[VAR]]
      v.answer(1, "")
      return beforeOpening === GOOD && firstReads === null && startsAtOpening === 2 && laterReads === GOOD
        && locked === 2 && second[0] === 3 && second[1] === null && v.bwEnv()[VAR] === null && v.bwCompileCacheState === "refused"
    })())
  const offOpen = service({ bwCompileCache: false, status: "unlocked" })
  offOpen.probeBwCompileCache()
  check("with the setting off an opening starts nothing", offOpen.bwCompileCacheProc.starts === 0 && offOpen.bwCompileCacheState === "off")

  // A bw that is given a password.
  const secret = service({})
  secret.probeBwCompileCache()
  secret.answer(0, GOOD + "\n")
  const auth = secret.authEnv("pw", "", "", "")
  check("accepted and in use, the unlock's and the login's environment still has the variable removed, and an inherited one with it",
    secret.bwEnv()[VAR] === GOOD && VAR in auth && auth[VAR] === null && auth[Model.passwordEnvVar()] === "pw"
      && childEnv({ NODE_COMPILE_CACHE: "/inherited" }, auth).NODE_COMPILE_CACHE === undefined
      && secret.bwSecretEnv({ X: "1" })[VAR] === null && secret.bwSecretEnv({ X: "1" }).X === "1")
  check("...and stays removed at the start: the last word never puts a directory where there was none",
    secret.bwEnvAtStart(auth)[VAR] === null && secret.bwEnvAtStart(secret.bwSecretEnv())[VAR] === null
      && JSON.stringify(secret.bwEnvAtStart({ A: "1" })) === JSON.stringify({ A: "1" }) && secret.bwEnvAtStart(null) === null)
}

// --- an environment built before its bw starts --------------------------------------
// A queued lock or envelope job, a read waiting for the vault helper, a local
// start put off behind the last run's cleanup: each was given its environment
// earlier. Both ways a VaultProcess can start are driven here with the
// service's and VaultProcess.qml's own functions: accepted, captured, the
// setting turned off, started.
{
  const vaultProcess = read("VaultProcess.qml")
  const route = helperActive => {
    const v = service({ vaultHelperState: "pending", vaultHelperActive: false, vaultWaiting: [], vaultRuns: {}, vaultRunSeq: 0,
      vaultLocalSecrets: {}, session: "sess", written: [], vaultHelperProc: { running: true, write: line => v.written.push(line) } })
    const names = ["vaultStart", "flushVaultWaiting", "vaultLocalEnv"]
    Object.assign(v, new Function("scope", "with (scope) {\n" + names.map(nm => functionBody(svc, nm)).join("\n")
      + "\nreturn { " + names.join(", ") + " } }")(v))
    // A VaultProcess: its own runLocally()/launchLocal() over a stand-in Process.
    const local = { running: false, started: [] }
    const proc = { vault: v, running: true, runId: 0, startSeq: 1, stdinText: "", capture: "plain", session: true, inject: {},
      command: ["bw", "list"], environment: {}, local, started() {}, finish() {} }
    Object.assign(proc, new Function("scope", "Qt", "local", "proc",
      "with (scope) { " + functionBody(vaultProcess, "runLocally") + "\n" + functionBody(vaultProcess, "launchLocal")
        + "\nreturn { runLocally: runLocally, launchLocal: launchLocal } }")(proc, v.Qt, local, proc))
    v.probeBwCompileCache()
    v.answer(0, GOOD + "\n")
    // Captured with the cache accepted, and handed to a helper not ready yet.
    proc.environment = v.bwEnv({ EXTRA: "1" })
    v.vaultStart(proc)
    const captured = proc.environment[VAR]
    const waited = v.vaultWaiting.length === 1 && v.written.length === 0
    return { v, proc, local, captured, waited,
      // The helper comes up (or is found missing) and the run is dispatched.
      dispatch() {
        v.vaultHelperState = helperActive ? "active" : "unavailable"
        v.vaultHelperActive = helperActive
        v.flushVaultWaiting()
      },
      sent: () => v.written.map(line => JSON.parse(line).env),
      runLater: () => v.later.splice(0).forEach(fn => fn()) }
  }
  check("both starts ask the service last: the helper dispatch once its environment is put together, the local start as it hands it to the process",
    /else environment\[key\] = proc\.environment\[key\]\s+\}\s+bwEnvAtStart\(environment\)\s+if \(!vaultHelperActive\)/.test(functionBody(svc, "vaultStart"))
      && /local\.environment = vault\.bwEnvAtStart\(env\)\s+local\.command = cmd\s+local\.stdinEnabled = stdinText !== ""\s+local\.running = true/.test(functionBody(vaultProcess, "launchLocal"))
      && (vaultProcess.match(/local\.environment = /g) || []).length === 2
      && !/refreshBwCompileCacheIn/.test(svc))

  const helper = route(true)
  helper.v.bwCompileCache = false
  helper.dispatch()
  check("through the helper: accepted, captured, turned off, dispatched: the helper is told to remove the variable",
    helper.captured === GOOD && helper.waited && helper.sent().length === 1 && helper.sent()[0][VAR] === null && helper.sent()[0].EXTRA === "1",
    JSON.stringify(helper.sent()))
  const helperOn = route(true)
  helperOn.dispatch()
  check("(left on, the same run is given the directory)", helperOn.sent().length === 1 && helperOn.sent()[0][VAR] === GOOD, JSON.stringify(helperOn.sent()))
  const helperRecheck = route(true)
  helperRecheck.v.probeBwCompileCache()
  helperRecheck.dispatch()
  check("through the helper, dispatched while a new check is running: removed", helperRecheck.sent()[0][VAR] === null)

  const here = route(false)
  here.v.bwCompileCache = false
  here.dispatch()
  check("run here instead: accepted, captured, turned off, started: the process gets the variable removed",
    here.captured === GOOD && here.waited && here.local.running === true && here.local.environment[VAR] === null
      && here.local.environment.EXTRA === "1" && here.local.environment[Model.sessionEnvVar()] === "sess", JSON.stringify(here.local.environment))
  const hereOn = route(false)
  hereOn.dispatch()
  check("(left on, the same run is given the directory)", hereOn.local.environment[VAR] === GOOD)
  // The local start itself put off: the previous run's process still busy.
  const late = route(false)
  late.local.running = true
  late.dispatch()
  const heldBack = late.local.environment === undefined && late.v.later.length === 1
  late.v.bwCompileCache = false
  late.local.running = false
  late.runLater()
  check("run here and put off once more behind the previous run: turned off in that moment too, it starts without the cache",
    heldBack && late.local.running === true && late.local.environment[VAR] === null, JSON.stringify(late.local.environment))

  check("the queues hand over what they were given, unchanged: the start is where it is settled",
    /lockProc\.environment = run\.env/.test(functionBody(svc, "runBwLockStep"))
      && /envelopeProc\.environment = Object\.assign\(\{\}, job\.accountEnv \|\| \{\}, job\.env \|\| \{\}\)\s*\n\s*job\.env = null/.test(functionBody(svc, "pumpEnvelopeJobs"))
      && ["lockProc", "envelopeProc", "listProc"].every(id => new RegExp("VaultProcess \\{\\s*id: " + id + "\\b").test(svc)))
  // What is not a VaultProcess reads its environment as a binding when it
  // starts, so there is no earlier copy to go stale.
  const plain = svc.split(/\n  (?=Process \{)/).slice(1).map(block => block.slice(0, block.indexOf("\n  }\n")))
    .filter(block => /environment: root\.(?:bwEnv|generatorServeEnv)\(/.test(block)).map(block => (block.match(/id: (\w+)/) || [])[1])
  check("the one plain Process that may use the cache (the generator's server) takes its environment from a binding",
    plain.join() === "generateServeProc", plain.join())
}

// --- Node, with the preloads ------------------------------------------------------

if (trusted) {
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
  // The service with a real probe behind it.
  const probed = (state, cacheHome) => {
    const v = service(Object.assign({ bwNodeOptions: options, bwCompileCacheHome: cacheHome }, state))
    v.probeBwCompileCache()
    if (v.bwCompileCacheProc.running) { const r = run(cacheHome); v.answer(r.rc, r.out) }
    return v
  }

  for (const builder of ["bwEnv", "generatorServeEnv"]) {
    // The shell was started with a cache directory of someone's choosing.
    const inheritedDir = path.join(home(), "inherited")
    const shellEnv = { PATH: process.env.PATH, NODE_OPTIONS: options, QSBW_CODE: "123456", NODE_COMPILE_CACHE: inheritedDir }

    // Off: a cache home that would pass, and nothing happens in it.
    const offHome = home()
    const off = probed({ bwCompileCache: false }, offHome)
    const offRun = runBwWith(childEnv(shellEnv, off[builder]()))
    check(`${builder}: with the setting off, Node writes nothing anywhere: no directory of the plugin's, none in the inherited one`,
      offRun.status === 3 && !fs.existsSync(inheritedDir) && fs.readdirSync(offHome).length === 0, JSON.stringify(offRun))

    // On, refused: a cache home anyone can write to.
    const refusedHome = home(0o777)
    const refused = probed({}, refusedHome)
    runBwWith(childEnv(shellEnv, refused[builder]()))
    check(`${builder}: on but refused, Node still writes nothing, inherited or its own`,
      refused.bwCompileCacheState === "refused" && !fs.existsSync(inheritedDir) && fs.readdirSync(refusedHome).length === 0)

    // On, accepted: bw gets exactly the directory that was printed.
    const base = home()
    const ok = probed({}, base)
    check(`${builder}: on and accepted by the real check, the directory is the one it made`,
      ok.bwCompileCacheDir === cacheOf(base) && ok[builder]()[VAR] === cacheOf(base), JSON.stringify(ok[builder]()))
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
      check("what Node wrote passes the next check as it is", !supported || run(base).dir === cacheOf(base))
      // A cache someone damaged costs speed, not the answer.
      for (const f of entriesOf(cacheOf(base))) fs.writeFileSync(path.join(cacheOf(base), f), "not a code cache")
      check("a damaged cache entry is not an error", same(plain, runBwWith(childEnv(shellEnv, ok.bwEnv()))))
      check("bwEnv() still carries the preloads beside it, and what the caller adds",
        ok.bwEnv({ EXTRA: "1" }).NODE_OPTIONS === options && ok.bwEnv({ EXTRA: "1" }).EXTRA === "1")

      // The directory removed behind the plugin's back: Node makes it again,
      // by umask; the next check is what looks at it.
      fs.rmSync(cacheOf(base), { recursive: true })
      const old = process.umask(0o002)
      runBwWith(childEnv(shellEnv, ok.bwEnv()))
      process.umask(old)
      if (supported) {
        check("(Node recreates a cache directory that was removed, group-writable under such a umask)",
          fs.existsSync(cacheOf(base)) && (mode(cacheOf(base)) & 0o020) !== 0, mode(cacheOf(base)).toString(8))
        const after = probed({}, base)
        check("...inside the plugin's directory, which stayed private, so no one else could reach it",
          (mode(path.dirname(cacheOf(base))) & 0o077) === 0, mode(path.dirname(cacheOf(base))).toString(8))
        check("...and the next check (the next opening) refuses it as it stands: the cache goes unused until it is put right",
          after.bwCompileCacheState === "refused" && after.bwEnv()[VAR] === null && (mode(cacheOf(base)) & 0o020) !== 0)
      }
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
  // The `node -e` checks: with the variable in the script's environment, as
  // it is beside a cached bw, `env -u` keeps Node from touching the cache.
  {
    const dir = path.join(home(), "for-node-e")
    const script = "process.stdout.write(String(require('module').getCompileCacheDir ? require('module').getCompileCacheDir() : undefined))"
    const viaUncached = spawnSync("bash", ["-c", "printf x | env -u NODE_COMPILE_CACHE node -e \"$1\"", "_", script],
      { encoding: "utf8", env: { PATH: process.env.PATH, NODE_COMPILE_CACHE: dir } })
    check("a `node -e` started the way the scripts start it has no compile cache and makes no directory",
      viaUncached.status === 0 && viaUncached.stdout === "undefined" && !fs.existsSync(dir), JSON.stringify(viaUncached.stdout))
    const bare = spawnSync("bash", ["-c", "printf x | node -e \"$1\"", "_", script],
      { encoding: "utf8", env: { PATH: process.env.PATH, NODE_COMPILE_CACHE: dir } })
    check("(started bare in the same environment, it would have one)",
      !supported || (bare.stdout !== "undefined" && fs.existsSync(dir)), JSON.stringify(bare.stdout))
  }
}

done()
