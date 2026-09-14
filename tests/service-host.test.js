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
  exports.presenterIndex = presenterIndex
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
  /id:\s*vaultResolveTimer[\s\S]{0,200}running:\s*root\.resolvedVault === null && root\.vaultHost === "pending"/.test(panel),
  "vaultResolveTimer must run until a vault is resolved")
check("`vault` is never null: the view's own standby vault stands in until one is resolved",
  /readonly property var vault: resolvedVault !== null \? resolvedVault : localVault/.test(panel)
    && /Service \{\s*id: localVault\s*privateHost: true\s*\}/.test(panel),
  "vault must fall back to the declared localVault")
check("the fallback is that standby vault, not a second one created later",
  /root\.resolvedVault = decision === "shared" \? shared : localVault/.test(panel)
    && !/createObject\(/.test(panel),
  "private must reuse localVault")
check("a view attaches to the vault it resolved and detaches when destroyed",
  /root\.resolvedVault\.attachView\(root\)/.test(panel)
    && /Component\.onDestruction: if \(root\.resolvedVault\) root\.resolvedVault\.detachView\(root\)/.test(panel),
  "attachView/detachView not both called on the resolved vault")
check("settings reach the resolved vault when the bar changes them",
  /onSettingsChanged: if \(root\.resolvedVault\) root\.resolvedVault\.updateSettings\(root\.settings\)/.test(panel),
  "onSettingsChanged must push to the resolved vault")
check("the widget's open, close and toggle forward to the vault, naming the view that asked",
  /function open\(\) \{ root\.vault\.open\(root\) \}/.test(panel)
    && /function close\(\) \{ root\.vault\.close\(\) \}/.test(panel)
    && /function toggle\(\) \{ root\.vault\.toggle\(root\) \}/.test(panel),
  "open/close/toggle wrappers missing")

// --- the service's view registry --------------------------------------------

check("attaching is idempotent",
  /function attachView\(view\)\s*\{\s*if \(!view \|\| views\.indexOf\(view\) !== -1\) return/.test(service),
  "attachView must ignore a view it already has")
check("an attaching view's settings land before the view does, because attaching starts the vault",
  /function attachView[\s\S]{0,260}updateSettings\(view\.settings\)\s*views = views\.concat\(\[view\]\)/.test(service),
  "updateSettings must precede adding the view")
check("detaching an unknown view is a no-op",
  /function detachView\(view\)\s*\{\s*var index = views\.indexOf\(view\)\s*if \(index === -1\) return/.test(service),
  "detachView must ignore a view it does not have")

// --- an unattached vault is inert ----------------------------------------------
//
// Every bar carries a standby Service, and the shared one exists before any bar
// finds it. Neither may do anything until a view attaches, or each monitor
// would run its own vault again.

check("the vault is live only while a view is attached",
  /readonly property bool live: viewCount > 0/.test(service), "live must follow viewCount")
check("startup runs once, on the first attach, instead of at creation",
  /onLiveChanged: \{[\s\S]{0,500}if \(!root\.live \|\| root\.started\) return\s*root\.started = true/.test(service)
    && !/^  Component\.onCompleted:/m.test(service),
  "startup must wait for live")
check("the IPC target is claimed only by a live vault",
  /IpcHandler \{\s*target: "io\.github\.elevate08\.qs-bitwarden-cli"\s*enabled: root\.live/.test(service),
  "IpcHandler must be enabled only while live")
check("nothing starts itself in an unattached vault",
  /running: root\.live && root\.lockOnSuspend/.test(service)
    && /running: root\.live && !root\.statusProbeStarted/.test(service),
  "self-starting processes and timers must be gated on live")
// Every other declarative `running:` must depend on state an inert vault never
// reaches: an unlocked vault, an SSH phase, an open view, a pending prompt.
const inertSafe = /root\.live|root\.status === "unlocked"|root\.opened|root\.sshAgent(Phase|GateOpen)|root\.ssh(GrantsAnnounced|CooldownStatus|Prompt)|root\.secondFactorStartedAt > 0/
const running = [...service.matchAll(/^\s+running: (.+)$/gm)].map(m => m[1])
const unsafe = running.filter(r => !inertSafe.test(r))
check("every declarative running binding is gated on live or on state an inert vault cannot reach",
  running.length >= 10 && unsafe.length === 0, "ungated: " + unsafe.join(" | "))
check("with no view attached, the presenter is a stand-in that does nothing",
  /return index >= 0 \? views\[index\] : nullPresenter/.test(service) && /id: nullPresenter/.test(service),
  "presenter must never be null")
check("the vault's `opened` is whether any view's popout is open",
  /readonly property bool opened: \{[\s\S]{0,160}views\[i\]\.opened === true/.test(service),
  "opened must come from the views")

// --- choosing the presenter -------------------------------------------------

const P = Model.presenterIndex
check("no views, no presenter", P([], "eDP-1") === -1 && P(null, "eDP-1") === -1, "expected -1")
check("a single view presents whatever is focused",
  P([{ opened: false, screen: "eDP-1" }], "DP-1") === 0, "expected 0")
check("an open popout outranks the focused monitor",
  P([{ opened: false, screen: "eDP-1" }, { opened: true, screen: "DP-1" }], "eDP-1") === 1, "expected 1")
check("otherwise the view on the focused monitor presents",
  P([{ opened: false, screen: "eDP-1" }, { opened: false, screen: "DP-1" }], "DP-1") === 1, "expected 1")
check("with no focused monitor reported, the first view presents",
  P([{ opened: false, screen: "eDP-1" }, { opened: false, screen: "DP-1" }], "") === 0, "expected 0")
check("a focused monitor with no bar on it falls back to the first view",
  P([{ opened: false, screen: "eDP-1" }, { opened: false, screen: "DP-1" }], "HDMI-A-1") === 0, "expected 0")
check("only a real true counts as open",
  P([{ opened: "true", screen: "eDP-1" }, { opened: false, screen: "DP-1" }], "DP-1") === 1, "expected 1")

check("the service follows Hyprland's focused monitor",
  /Hyprland\.focusedMonitor/.test(service) && /Model\.presenterIndex\(summaries, focusedScreen\)/.test(service),
  "presenter must be derived from the views and the focused monitor")
check("each view reports the monitor it is on",
  /readonly property string screenName:/.test(panel), "screenName missing from the view")

// --- the split ----------------------------------------------------------------
//
// Service.qml is the vault; Panel.qml draws it. The vault reaches the screen only
// through the presenter contract, and the views reach the vault only through
// `root.vault` (Panel.qml) or `vault` (the components Panel.qml hands it to).
// tests/plugin-source.js relies on the second half to fold those qualifiers back
// for the older source-reading suites, so it is enforced here.

const code = src => src
  .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
  .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
  .replace(/\/\/[^\n]*/g, "")

const serviceCode = code(service)
const panelCode = code(panel)
const vaultMembers = new Set([
  ...[...serviceCode.matchAll(/^  (?:readonly )?property \S+ ([A-Za-z_]\w*)/gm)].map(m => m[1]),
  ...[...serviceCode.matchAll(/^  function ([A-Za-z_]\w*)\s*\(/gm)].map(m => m[1]),
  ...[...serviceCode.matchAll(/^\s+id:\s*([A-Za-z_]\w*)\s*$/gm)].map(m => m[1]),
])
check("the vault has its members", vaultMembers.size > 600, String(vaultMembers.size))

// Names both halves legitimately share: the registry the view talks to, and the
// widget's own members the vault mirrors.
const shared = new Set(["root", "open", "close", "toggle", "opened", "settings", "setting", "shell", "presenter",
  "privateHost", "views", "viewCount", "attachView", "detachView", "updateSettings", "live", "started",
  "focusedScreen", "eachView", "nullPresenter"])

const viewIds = [...panelCode.matchAll(/^\s+id:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/gm)].map(m => m[1])
check("the view declares the controls", viewIds.length > 50, String(viewIds.length))
const leaked = viewIds.filter(id => id !== "root" && new RegExp(`\\b${id}\\b`).test(serviceCode))
check("the vault names no control declared in the view",
  leaked.length === 0, "vault references: " + leaked.join(", "))

const declaredInView = [
  ...[...panelCode.matchAll(/^  (?:readonly )?property \S+ ([A-Za-z_]\w*)/gm)].map(m => m[1]),
  ...[...panelCode.matchAll(/^  function ([A-Za-z_]\w*)\s*\(/gm)].map(m => m[1]),
].filter(n => vaultMembers.has(n) && !shared.has(n))
check("no vault member is still declared in the view",
  declaredInView.length === 0, "declared in Panel.qml: " + declaredInView.join(", "))

const unqualified = [...vaultMembers].filter(n => !shared.has(n)
  && new RegExp(`(?<![\\w.$])(?:root\\.)?${n}\\b(?!\\s*:)`).test(panelCode.replace(/root\.vault\.[A-Za-z_]\w*/g, "")))
check("Panel.qml reaches every vault member through root.vault",
  unqualified.length === 0, "reached another way: " + unqualified.join(", "))

for (const file of ["CustomFieldsEditor.qml", "SshAgentSettings.qml", "SshApprovalPopup.qml",
                    "SshApprovalScreen.qml", "SshUnlockScreen.qml"]) {
  const src = code(read(file))
  const viaPanel = [...src.matchAll(/\bpanel\.([A-Za-z_]\w*)/g)].map(m => m[1])
    .filter(n => vaultMembers.has(n) && !shared.has(n))
  check(`${file} reaches vault members through vault, not panel`,
    /required property var vault/.test(src) && viaPanel.length === 0,
    "through panel: " + [...new Set(viaPanel)].join(", "))
}

// A Connections block listening for a vault member's change signal has to
// target the vault; aimed at the view it silently never fires.
const handlerTargets = []
for (const [file, src, vaultRef] of [["Panel.qml", panel, "root.vault"], ["CustomFieldsEditor.qml", read("CustomFieldsEditor.qml"), null],
    ["SshAgentSettings.qml", read("SshAgentSettings.qml"), null], ["SshApprovalPopup.qml", read("SshApprovalPopup.qml"), null],
    ["SshApprovalScreen.qml", read("SshApprovalScreen.qml"), null], ["SshUnlockScreen.qml", read("SshUnlockScreen.qml"), null]]) {
  for (const m of code(src).matchAll(/Connections \{\s*target: ([\w.]+)([\s\S]*?)\n\s*\}/g)) {
    const listened = [...m[2].matchAll(/function on([A-Z]\w*)Changed\(/g)]
      .map(h => h[1][0].toLowerCase() + h[1].slice(1)).filter(n => vaultMembers.has(n))
    if (listened.length && !/(^|\.)vault$/.test(m[1])) handlerTargets.push(`${file}: ${m[1]} for ${listened.join(", ")}`)
  }
}
check("Connections on a vault member's change signal target the vault",
  handlerTargets.length === 0, handlerTargets.join("; "))

// A statement that opens with `(` or `[` continues the line before it when that
// line has no semicolon -- `var x = a` then `(b).c()` is `a(b).c()`. That is how
// opening the panel came to throw "opened is not a function". Flag any such
// line whose predecessor ends in something that can be called or indexed.
const asiHazards = []
for (const [file, src] of [["Service.qml", service], ["Panel.qml", panel]]) {
  const lines = code(src).split("\n")
  for (let i = 1; i < lines.length; i++) {
    if (!/^\s*[([]/.test(lines[i])) continue
    let j = i - 1
    while (j > 0 && lines[j].trim() === "") j--
    if (/[\w)\]"']\s*$/.test(lines[j]) && !/^\s*(if|for|while|switch|return|else)\b/.test(lines[j]))
      asiHazards.push(`${file}:${i + 1}: ${lines[i].trim()}`)
  }
}
check("no statement begins with ( or [ straight after a line it would continue",
  asiHazards.length === 0, asiHazards.join("\n    "))

// Every vault member a view reaches must exist as a property or function. An
// object id is not reachable from outside its file, and `vault` is untyped, so
// qmllint cannot see either mistake: the search box called
// vault.searchDebounceTimer.restart() and the filter silently never ran.
const vaultApi = new Set([
  ...[...serviceCode.matchAll(/^  (?:readonly )?property \S+ ([A-Za-z_]\w*)/gm)].map(m => m[1]),
  ...[...serviceCode.matchAll(/^  function ([A-Za-z_]\w*)\s*\(/gm)].map(m => m[1]),
  // Item's own members, which the vault inherits
  "visible", "enabled", "parent", "objectName", "destroy",
])
const unreachable = []
for (const [file, src] of [["Panel.qml", panel], ["CustomFieldsEditor.qml", read("CustomFieldsEditor.qml")],
    ["SshAgentSettings.qml", read("SshAgentSettings.qml")], ["SshApprovalPopup.qml", read("SshApprovalPopup.qml")],
    ["SshApprovalScreen.qml", read("SshApprovalScreen.qml")], ["SshUnlockScreen.qml", read("SshUnlockScreen.qml")]]) {
  for (const m of code(src).matchAll(/\bvault\.([A-Za-z_]\w*)/g)) {
    if (!vaultApi.has(m[1])) unreachable.push(`${file}: vault.${m[1]}`)
  }
}
check("views reach only the vault's properties and functions, never an id or a missing name",
  unreachable.length === 0, [...new Set(unreachable)].join(", "))

const contract = new Set([...panelCode.matchAll(/function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)].map(m => m[1]))
const asked = new Set([...serviceCode.matchAll(/\b(?:presenter|view|target)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)]
  .map(m => m[1]))
const missing = [...asked].filter(name => !contract.has(name))
check("every call the vault makes on a view is part of the View contract",
  asked.size > 5 && missing.length === 0, "not defined in Panel.qml: " + missing.join(", "))
const stubbed = new Set([...code(service.slice(service.indexOf("id: nullPresenter"))).slice(0, 900)
  .matchAll(/function\s+([A-Za-z_]\w*)\s*\(/g)].map(m => m[1]))
const unstubbed = [...asked].filter(name => !stubbed.has(name))
check("and the stand-in presenter answers every one of them",
  unstubbed.length === 0, "missing from nullPresenter: " + unstubbed.join(", "))
const asksNames = [...serviceCode.matchAll(/presenter\.(?:focusField|fieldHasFocus)\(""\)/g)].length
check("the vault asks for fields by name, never by control", asksNames > 10, String(asksNames))

console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  for (const f of failures) console.log(`\n  FAIL ${f}`)
  process.exit(1)
}
