// Shared helpers for the Node suites: load a `.pragma library` module, read the
// plugin's QML as text, and record and report checks.

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const read = file => fs.readFileSync(path.join(repoRoot, file), "utf8")

// Evaluates a QML JavaScript library and returns every top-level function and
// variable it declares.
function loadModule(file = "BitwardenModel.js") {
  const src = read(file).replace(/^\.pragma library\s*$/m, "")
  const names = new Set()
  for (const m of src.matchAll(/^(?:function\s+(\w+)|(?:var|const|let)\s+(\w+))/gm)) names.add(m[1] || m[2])
  const exports = {}
  new Function("exports", src + "\n" + [...names].map(n => `exports.${n} = ${n}`).join("\n"))(exports)
  return exports
}

// The vault lives in Service.qml and Panel.qml views it as `root.vault.<name>`;
// the SSH screens and field editor take it as `vault` beside their `panel`.
// For Panel.qml this returns the vault followed by the view, with the view's
// vault qualifier folded back, so `root.status` means the vault's status.
// service-host.test.js keeps that fold exact.
function readPluginSource(file) {
  if (file === "Panel.qml") {
    return read("Service.qml") + "\n" + readView().replace(/\broot\.vault\./g, "root.")
  }
  return read(file).replace(/\bvault\./g, "panel.")
}

// The files that make up the per-monitor view that Panel.qml is, as one text
// in drawing order: Panel.qml itself, then what it builds.
const viewFiles = ["Panel.qml"]

function readView() {
  return viewFiles.map(read).join("\n")
}

// The text of `function name(...) { ... }` in src, or "" if absent.
function functionBody(src, name) {
  const start = src.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = src.indexOf("{", start); i < src.length; i++) {
    if (src[i] === "{") depth++
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1)
  }
  return ""
}

// Directories in which a test may build a compile-cache home the plugin's
// check has to accept, judged here with plain filesystem calls and not by
// the check itself: the path is printable ASCII, and it and everything above
// it up to / is a directory of this user's or root's that neither group nor
// others can write to. A check that refuses a directory under one of these
// is wrong, and the suites say so instead of skipping.
function privateChain(dir) {
  try {
    let p = fs.realpathSync(dir)
    if (!/^\/[\x20-\x7e]*$/.test(p)) return false
    const uid = process.getuid()
    for (;;) {
      const st = fs.lstatSync(p)
      if (!st.isDirectory() || (st.uid !== uid && st.uid !== 0) || (st.mode & 0o022) !== 0) return false
      if (p === "/") return true
      p = path.dirname(p)
    }
  } catch (e) {
    return false
  }
}

// A new private directory under the first such place this user can write
// to, "" if there is none: the runtime directory, a CI runner's temporary
// directory, the account's home (from the password database, not $HOME,
// which `runuser` leaves as the caller's), this directory.
function privateScratchDir(prefix) {
  const candidates = [process.env.XDG_RUNTIME_DIR, process.env.RUNNER_TEMP, require("os").userInfo().homedir, __dirname]
  for (const root of candidates) {
    if (!root || !path.isAbsolute(root) || !privateChain(root)) continue
    try {
      const dir = fs.mkdtempSync(path.join(fs.realpathSync(root), prefix))
      fs.chmodSync(dir, 0o700)
      if (privateChain(dir)) return dir
      fs.rmSync(dir, { recursive: true, force: true })
    } catch (e) {}
  }
  return ""
}

function createSuite(name) {
  let pass = 0
  const failures = []
  const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
  const eq = (label, actual, expected) =>
    check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
  const done = () => {
    console.log(`${name}: ${pass} passed, ${failures.length} failed`)
    if (failures.length) {
      console.error("\nFAILURES:\n  " + failures.join("\n  "))
      process.exit(1)
    }
  }
  return { check, eq, done, failures, get pass() { return pass } }
}

module.exports = { repoRoot, read, loadModule, readPluginSource, readView, viewFiles, functionBody, createSuite,
  privateChain, privateScratchDir }
