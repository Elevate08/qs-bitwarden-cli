#!/usr/bin/env node
// One vault per shell (issue #30). The bar builds this widget once per monitor;
// the vault lives in Service.qml, which the shell loads once and every bar
// copy reaches through `bar.shell.serviceFor()`. A copy that cannot reach it
// hosts a private one. These checks pin the decision and the wiring: a view
// that picks "private" while the shared service is merely late starts a
// second vault, which is the contention the service exists to remove.
//
//   node tests/service-host.test.js

const fs = require("fs")
const path = require("path")
const root = path.join(__dirname, "..")
const read = f => fs.readFileSync(path.join(root, f), "utf8")

const Model = {}
new Function("exports", read("BitwardenModel.js").replace(/^\.pragma library\s*$/m, "") + `
  exports.vaultHostDecision = vaultHostDecision
  exports.vaultHostTimeoutMs = vaultHostTimeoutMs
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- the decision -----------------------------------------------------------

const timeout = Model.vaultHostTimeoutMs()
check("the timeout is long enough for a service published after its views",
  timeout >= 1000 && timeout <= 10000, String(timeout))
check("a found service is used at once",
  Model.vaultHostDecision(true, 0, timeout) === "shared", "expected shared")
check("a found service wins even after the timeout",
  Model.vaultHostDecision(true, timeout * 2, timeout) === "shared", "expected shared")
check("not found yet is a wait, not a private vault",
  Model.vaultHostDecision(false, 0, timeout) === "wait"
    && Model.vaultHostDecision(false, timeout - 1, timeout) === "wait", "expected wait")
check("not found by the timeout falls back to a private vault",
  Model.vaultHostDecision(false, timeout, timeout) === "private", "expected private")
check("a missing or invalid timeout uses the default rather than deciding at once",
  Model.vaultHostDecision(false, 0, undefined) === "wait"
    && Model.vaultHostDecision(false, 0, NaN) === "wait", "expected wait")

// --- the manifest -----------------------------------------------------------

const manifest = JSON.parse(read("manifest.json"))
check("the plugin is still a bar widget",
  manifest.kinds.includes("bar-widget") && manifest.entryPoints.barWidget === "Panel.qml",
  JSON.stringify(manifest.kinds))
check("and declares the service the shell loads once",
  manifest.kinds.includes("service") && manifest.entryPoints.service === "Service.qml"
    && fs.existsSync(path.join(root, "Service.qml")),
  JSON.stringify(manifest.entryPoints))

// --- the view's wiring ------------------------------------------------------

const panel = read("Panel.qml")
const service = read("Service.qml")

check("the view asks the shell for its own plugin's service",
  /var host = root\.bar \? root\.bar\.shell : null[\s\S]{0,120}host\.serviceFor\(root\.moduleName\)/.test(panel),
  "the bar's shell facade must be asked for serviceFor(root.moduleName)")
check("and lets the model decide between shared, private and waiting",
  /Model\.vaultHostDecision\(/.test(panel), "vaultHostDecision not called")
check("the lookup is polled, because nothing notifies a binding when the service appears",
  /id:\s*vaultResolveTimer[\s\S]{0,200}running:\s*root\.vault === null && root\.vaultHost === "pending"/.test(panel),
  "vaultResolveTimer must run until a vault is resolved")
check("a private vault that cannot be created is not retried in a tight loop",
  /if \(!root\.vault\) \{\s*root\.vaultHost = "failed"/.test(panel),
  "a failed createObject must end the polling")
check("a private vault is marked as one",
  /createObject\(null,\s*\{\s*privateHost:\s*true\s*\}\)/.test(panel), "privateHost: true not set")
check("a view attaches once resolved and detaches when destroyed",
  /root\.vault\.attachView\(root\)/.test(panel) && /root\.vault\.detachView\(root\)/.test(panel),
  "attachView/detachView not both called")
check("only a private vault is destroyed with its view",
  /if \(root\.vaultHost === "private"\) root\.vault\.destroy\(\)/.test(panel),
  "the shared vault must outlive the view")
check("settings reach the vault when the bar changes them",
  /onSettingsChanged:\s*if \(root\.vault\) root\.vault\.updateSettings\(root\.settings\)/.test(panel),
  "onSettingsChanged must push to the vault")

// --- the service's view registry --------------------------------------------

check("attaching is idempotent",
  /function attachView\(view\)\s*\{\s*if \(!view \|\| views\.indexOf\(view\) !== -1\) return/.test(service),
  "attachView must ignore a view it already has")
check("an attaching view brings its settings",
  /function attachView[\s\S]{0,200}updateSettings\(view\.settings\)/.test(service),
  "attachView must take the view's settings")
check("detaching an unknown view is a no-op",
  /function detachView\(view\)\s*\{\s*var index = views\.indexOf\(view\)\s*if \(index === -1\) return/.test(service),
  "detachView must ignore a view it does not have")

console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  for (const f of failures) console.log(`\n  FAIL ${f}`)
  process.exit(1)
}
