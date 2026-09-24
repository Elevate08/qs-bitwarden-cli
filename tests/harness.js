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
    return read("Service.qml") + "\n" + read("Panel.qml").replace(/\broot\.vault\./g, "root.")
  }
  return read(file).replace(/\bvault\./g, "panel.")
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

module.exports = { repoRoot, read, loadModule, readPluginSource, functionBody, createSuite }
