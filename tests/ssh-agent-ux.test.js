#!/usr/bin/env node
// The approval prompt's other doors: a desktop notification when the card goes
// unanswered, listing and answering requests from a terminal, and what does
// and does not count as activity for the auto-lock timer.
//
//   node tests/ssh-agent-ux.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")

const Model = loadModule()
const service = readPluginSource("Service.qml")

const { check, eq, done } = createSuite("ssh-agent-ux")

const raw = {
  requestId: 7, keyId: "k", keyName: "Work <key> & co", fingerprint: "SHA256:abc",
  pid: 4242, processPath: "/usr/bin/ssh", operation: "ssh-auth", operationDetail: "git",
  hostKey: "SHA256:host", forwarded: false, grantOffered: true
}
const view = Model.sshAgentPromptView(raw, 120)

// -------------------------------------------------------------------------
// Notification command
// -------------------------------------------------------------------------

const cmd = Model.sshAgentNotifyCommand(view, 100)
eq("uses notify-send", cmd[0], "notify-send")
check("offers Deny", cmd.includes("--action=deny=Deny"))
// Any program running as the user can press a notification action through the
// daemon, so the notification must have nothing that approves.
const actions = cmd.filter(a => /^(--action|-A)/.test(a))
check("offers Deny and the harmless default action, nothing that approves",
  actions.join("|") === "--action=default=Answer on the card|--action=deny=Deny"
  && !/allow|approve/i.test(cmd.slice(0, cmd.indexOf("--")).join(" ")))
// "default" is the key the notification spec gives the action a daemon runs
// when the notification itself is activated. Without it Dunst's middle click
// runs the only action there is.
check("generic activation has its own action, ahead of Deny, so it cannot land on Deny",
  actions.length === 2 && actions[0].indexOf("--action=default=") === 0)
check("waits for the answer", cmd.includes("--wait"))
check("expires with the request", cmd.includes("--expire-time=100000"))
const sep = cmd.indexOf("--")
check("title and body come after a lone --", sep > 0 && cmd.length === sep + 3)
const body = cmd[cmd.length - 1]
check("body names the key, fingerprint and program (no pid, as on the card)",
  body.includes("SHA256:abc") && body.includes("ssh") && !body.includes("4242"))
const tmpView = Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/tmp/x/git" }), 120)
const tmpBody = Model.sshAgentNotifyCommand(tmpView, 100).pop()
check("body shows the full program path, as the card does", tmpBody.split("\n").includes("/tmp/x/git") && body.split("\n").includes("/usr/bin/ssh"))
check("body carries the card's not-verified note",
  tmpView.provenanceNote !== "" && tmpBody.includes(tmpView.provenanceNote) && /not verified/.test(tmpBody))
check("body sends approval to the card", /answer on the Bitwarden card/.test(body))
check("a path is escaped as markup too",
  Model.sshAgentNotifyCommand(Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/tmp/<b>/git" }), 120), 100)
    .pop().includes("/tmp/&lt;b&gt;/git"))
check("body is escaped as markup", body.includes("&lt;key&gt; &amp; co") && !body.includes("<key>"))
check("a bad request id builds nothing", Model.sshAgentNotifyCommand({ requestId: -1 }, 100).length === 0)
check("a forwarded request carries its warning",
  Model.sshAgentNotifyCommand(Model.sshAgentPromptView(Object.assign({}, raw, { forwarded: true }), 120), 50)
    .pop().includes("Forwarded"))
check("expiry never drops below five seconds", Model.sshAgentNotifyCommand(view, -3).includes("--expire-time=5000"))

// -------------------------------------------------------------------------
// Notification decision
// -------------------------------------------------------------------------

eq("a stale or foreign allow decides nothing", Model.sshAgentNotifyDecision(0, "allow\n"), "none")
eq("no elapsed time makes an allow count", Model.sshAgentNotifyDecision(0, "allow\n", 60000), "none")
check("the decision is never an approval",
  ["allow", "allow\n", "Allow once", "approve", "default", "0", "", "deny\nallow"].every(out =>
    [0, 1, 2].every(code => ["deny", "none"].includes(Model.sshAgentNotifyDecision(code, out)))))
eq("the default action (a click on the notification, Dunst's middle click) leaves the request pending",
  Model.sshAgentNotifyDecision(0, "default\n"), "none")
eq("deny action denies", Model.sshAgentNotifyDecision(0, "deny\n"), "deny")
eq("dismiss, expiry or suppression (no output) leaves the request pending", Model.sshAgentNotifyDecision(0, ""), "none")
eq("unknown output leaves the request pending", Model.sshAgentNotifyDecision(0, "0\n"), "none")
eq("a failed notify-send decides nothing", Model.sshAgentNotifyDecision(1, ""), "none")
eq("a failed notify-send that printed deny decides nothing", Model.sshAgentNotifyDecision(1, "deny\n"), "none")
check("the arm delay that only guarded the notification's allow is gone",
  typeof Model.sshAgentNotifyArmMs === "undefined" && !/sshNotifyStartedMs|NOTIFY_ARM/.test(service + readPluginSource("BitwardenModel.js")))
check("the notification waits before appearing", Model.sshAgentNotifyDelayMs() >= 3000)

// -------------------------------------------------------------------------
// Terminal listing
// -------------------------------------------------------------------------

const unlock = { requestId: 9, reason: "list-identities", pid: 5, processPath: "/usr/bin/ssh-add" }
const listed = Model.sshAgentPendingRequests(raw, [Object.assign({}, raw, { requestId: 8 })], unlock, [])
eq("lists signing prompts, queue and unlocks", listed.map(r => r.kind + ":" + r.id).join(","), "sign:7,sign:8,unlock:9")
check("a listing holds only the card's fields",
  Object.keys(listed[0]).sort().join(",") === "destination,fingerprint,forwarded,id,key,kind,operation,pid,program")
eq("nothing pending lists nothing", Model.sshAgentPendingRequests(null, [], null, []).length, 0)

// -------------------------------------------------------------------------
// Wiring in Service.qml
// -------------------------------------------------------------------------

function body_(name) {
  const start = service.indexOf("function " + name + "(")
  if (start < 0) return ""
  const next = service.indexOf("\n  function ", start + 10)
  return service.slice(start, next < 0 ? undefined : next)
}

check("IPC exposes sshPending and sshReply",
  /function sshPending\(\): string/.test(service) && /function sshReply\(id: string, decision: string\): string/.test(service))
check("allowing from a terminal is refused unless opted in",
  /if \(allow && !root\.sshAgentTerminalApproval\) return "disabled"/.test(body_("replySshRequest")))
check("a terminal allow is always once (zero grant window)",
  /sshAgentApproveLine\(id, 0\)/.test(body_("replySshRequest"))
  && /approveSshRequest\(0\)/.test(body_("replySshRequest"))
  && !/approveSshRequest\([1-9a-z]/.test(body_("replySshRequest")))
check("unlock prompts cannot be allowed from a terminal", /return "unlock-only"/.test(body_("replySshRequest")))
check("terminal approval is off by default", /boolSetting\("sshAgentTerminalApproval", setting\("sshAgentTerminalApproval", false\)\)/.test(service))
check("the notification fallback is armed only for signing prompts (showSshApproval)",
  /armSshNotifyFallback\(\)/.test(body_("showSshApproval")) && !/armSshNotifyFallback/.test(body_("onSshAgentMessage")))
check("dismissing the prompt stops the notification", /stopSshNotifyFallback\(\)/.test(body_("dismissSshApproval")))
check("a notification answer applies only to the request it was raised for",
  /root\.sshPrompt\.requestId !== id/.test(body_("onSshNotifyExited")))
// The exit handler alone (body_ runs on into the Timer and Process after it).
const notifyExit = body_("onSshNotifyExited").split("\n  Timer {")[0]
check("a notification answer cannot approve",
  notifyExit !== "" && !/approve/i.test(body_("onSshNotifyExited"))
  && !/approve/i.test(body_("showSshNotification")))
check("only the deny decision denies; anything else leaves the request pending and uncounted",
  /sshAgentNotifyDecision\(exitCode, stdout\) === "deny"\) denyCurrentSshPrompt\(\)/.test(notifyExit)
  && !/sshCooldown|expireSshRequest|dismissSshApproval|advanceSshPrompt|showSshNotification|sshAgentWrite/.test(notifyExit))
check("the setting says the notification cannot approve, in the schema and the manifest",
  [Model.SETTINGS_SCHEMA.find(s => s.key === "sshAgentNotifyFallback").description,
    JSON.parse(readPluginSource("manifest.json")).barWidget.schema.find(s => s.key === "sshAgentNotifyFallback").description]
    .every(d => /Deny button/.test(d) && /Approving is done on the card/.test(d) && !/Allow once/.test(d)))
check("the notify-send exit is wired to the handler, with its exit code and output",
  /id: sshNotifyProc\s+stdout: StdioCollector \{ id: sshNotifyStdout; waitForEnd: true \}\s+onExited: function\(exitCode\) \{ root\.onSshNotifyExited\(exitCode, sshNotifyStdout\.text\) \}/.test(service))
check("the timer shows the notification", /id: sshNotifyTimer[\s\S]{0,80}onTriggered: root\.showSshNotification\(\)/.test(service))

// The real onSshNotifyExited(), run against a stand-in service: what each way
// a notify-send can end does to the request.
function notifyExit_(state, exitCode, stdout) {
  const v = Object.assign({ Model, calls: [], sshNotifyRequestId: 7, sshPrompt: { requestId: 7 },
    denyCurrentSshPrompt() { v.calls.push("deny") },
    approveSshRequest() { v.calls.push("approve") },
    expireSshRequest() { v.calls.push("expire") },
    dismissSshApproval() { v.calls.push("dismiss") },
    showSshNotification() { v.calls.push("show") } }, state)
  v.root = v
  new Function("root", "with (root) {\n" + functionBody(service, "onSshNotifyExited") + "\nreturn onSshNotifyExited }")(v)(exitCode, stdout)
  return v
}
eq("Deny on the request that is up denies it, once", notifyExit_({}, 0, "deny\n").calls.join(), "deny")
for (const [why, code, out] of [["dismissed, expired or suppressed", 0, ""], ["activated (the default action)", 0, "default\n"],
  ["an allow from anywhere", 0, "allow\n"], ["unknown output", 0, "0\n"], ["notify-send failed", 1, ""],
  ["notify-send failed after printing deny", 1, "deny\n"], ["killed", 15, ""]]) {
  eq(`${why}: nothing is called, the request stays`, notifyExit_({}, code, out).calls.join(), "")
}
eq("Deny for a request that has been replaced by another does nothing",
  notifyExit_({ sshNotifyRequestId: 7, sshPrompt: { requestId: 8 } }, 0, "deny\n").calls.join(), "")
eq("Deny after the request was answered (no prompt) does nothing", notifyExit_({ sshPrompt: null }, 0, "deny\n").calls.join(), "")
eq("Deny after the notification's claim was dropped does nothing", notifyExit_({ sshNotifyRequestId: -1 }, 0, "deny\n").calls.join(), "")
eq("the handler gives up its claim whatever happened", notifyExit_({}, 0, "").sshNotifyRequestId, -1)
check("no outcome approves",
  [0, 1, 2, 15].every(code => ["allow", "allow\n", "Allow once", "approve", "default", "deny", "deny\n", "", "0", "1"].every(out =>
    [{}, { sshPrompt: { requestId: 8 } }, { sshPrompt: null }, { sshNotifyRequestId: -1 }].every(state =>
      !notifyExit_(state, code, out).calls.includes("approve")))))

// Every code point the engine's own Unicode data calls default-ignorable is
// written out, so the list in BitwardenModel.js cannot fall behind unnoticed.
{
  const missed = []
  let count = 0
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue
    const c = String.fromCodePoint(cp)
    if (!/\p{Default_Ignorable_Code_Point}/u.test(c)) continue
    count++
    const hex = cp.toString(16)
    const want = "a" + (cp > 0xffff ? "\\u{" + hex + "}" : "\\u" + ("0000" + hex).slice(-4)) + "b"
    if (Model.visibleText("a" + c + "b") !== want) missed.push("U+" + hex.toUpperCase())
  }
  check(`all ${count} Default_Ignorable_Code_Point characters (Unicode ${process.versions.unicode}) are written out`,
    count > 4000 && missed.length === 0, missed.slice(0, 20).join(" "))
  check("the shorthand format controls and musical symbol controls are among them",
    ["\u{1bca0}", "\u{1bca3}", "\u{1d173}", "\u{1d17a}"].every(c =>
      Model.visibleText(c) === "\\u{" + c.codePointAt(0).toString(16) + "}")
    && Model.visibleText("\u{1bc9f}\u{1bca4}\u{1d172}\u{1d17b}") === "\u{1bc9f}\u{1bca4}\u{1d172}\u{1d17b}")
}

// The limits cut between whole characters and never inside a written-out one.
{
  const wellFormed = t => !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(t)
  const wholeEscapes = t => t.replace(/\\u\{[0-9a-f]+\}|\\u[0-9a-f]{4}/g, "").indexOf("\\u") === -1
  const name = t => Model.sshAgentPromptView(Object.assign({}, raw, { keyName: t }), 120).keyName
  const path = t => Model.sshAgentPromptView(Object.assign({}, raw, { processPath: t }), 120).processPath
  const key = "\u{1f511}"

  // The reviewer's cases: 252 units of name whose escapes push a pair across
  // the 256 limit, and 511 units of path whose escape pushes one across 512.
  const name252 = "\u00ad" + "a".repeat(249) + key
  const path511 = "/" + key + "a".repeat(507) + "\u00ad"
  check("a 252-unit key name with an escape does not end in half a surrogate pair",
    name252.length === 252 && wellFormed(name(name252)) && name(name252) === "\\u00ad" + "a".repeat(249), JSON.stringify(name(name252).slice(-4)))
  check("a 511-unit path with an escape does not start with half a surrogate pair",
    path511.length === 511 && wellFormed(path(path511)) && path(path511) === "\u2026" + "a".repeat(505) + "\\u00ad",
    JSON.stringify(path(path511).slice(0, 4)))
  check("a pair that fits exactly is kept whole",
    name("a".repeat(254) + key) === "a".repeat(254) + key && name("a".repeat(255) + key) === "a".repeat(255))

  // An escape straddling the limit is dropped whole, at either end.
  for (const [what, c, shown] of [["\\uXXXX", "\u00ad", "\\u00ad"], ["\\u{XXXXX}", "\u{e0001}", "\\u{e0001}"]]) {
    for (let before = 256 - shown.length - 1; before <= 256; before++) {
      const out = name("a".repeat(before) + c + "zzz")
      if (!(out.length <= 256 && wholeEscapes(out) && wellFormed(out)
        && out === ("a".repeat(before) + shown + "zzz").slice(0, before + shown.length <= 256 ? 256 : before))) {
        check(`key name: ${what} after ${before} characters is kept or dropped whole`, false, JSON.stringify(out.slice(-12)))
      }
    }
    check(`key name: a ${what} escape straddling the limit is never cut`, true)
    for (let after = 511 - shown.length - 1; after <= 512; after++) {
      const out = path("/zzz" + c + "a".repeat(after))
      const whole = "/zzz" + shown + "a".repeat(after)
      const want = whole.length <= 512 ? whole : "\u2026" + (shown.length + after <= 511 ? whole.slice(whole.length - 511) : "a".repeat(after).slice(-511))
      if (out !== want || out.length > 512 || !wholeEscapes(out)) {
        check(`path: ${what} before ${after} characters is kept or dropped whole`, false, JSON.stringify(out.slice(0, 14)))
      }
    }
    check(`path: a ${what} escape straddling the limit is never cut`, true)
  }
  check("limits still bound the escaped text", name("\u00ad".repeat(300)).length <= 256 && name("\u00ad".repeat(300)).length === 252
    && path("\u00ad".repeat(300)).length <= 512 && wholeEscapes(path("\u00ad".repeat(300))))
  check("the notification body is cut the same way",
    wellFormed(Model.sshAgentNotifyCommand(Model.sshAgentPromptView(Object.assign({}, raw, { processPath: path511 }), 120), 100).pop()))
}

// Text the agent has already escaped (it writes a tab as the six characters
// \u0009), and the panel's own escapes bounded a second time: a cut never
// lands inside an escape that is already in the text either.
{
  const wholeEscapes = t => t.replace(/\\u\{[0-9a-fA-F]+\}|\\u[0-9a-fA-F]{4}/g, "").indexOf("\\u") === -1
  const view = fields => Model.sshAgentPromptView(Object.assign({}, raw, fields), 120)
  const tab = "\\u0009"
  check("the reviewer's case: a path cut through an agent-written \\u0009 does not start with its tail",
    view({ processPath: "/" + "a".repeat(3) + tab + "b".repeat(508) }).processPath === "…" + "b".repeat(508)
      && view({ processPath: "/" + tab + "b".repeat(506) }).processPath === "\u2026" + "b".repeat(506)
      && view({ processPath: "/" + tab + "b".repeat(505) }).processPath === "/" + tab + "b".repeat(505))
  const broken = []
  for (const escape of [tab, "\\u{e0001}", "\\u00ad"]) {
    for (let after = 500; after <= 514; after++) {
      const p = view({ processPath: "/dir/" + escape + "b".repeat(after) }).processPath
      if (p.length > 512 || !wholeEscapes(p) || !/^(…|\/dir\/)/.test(p)) broken.push("path " + escape + "+" + after + ": " + p.slice(0, 12))
    }
    for (let before = 244; before <= 258; before++) {
      const text = "k".repeat(before) + escape + "zzz"
      const n = view({ keyName: text }).keyName
      const pn = view({ processPath: "/usr/bin/" + text }).processName
      for (const [what, out] of [["key name", n], ["program name", pn]]) {
        if (out.length > 256 || !wholeEscapes(out) || out !== (before + escape.length <= 256 ? text.slice(0, 256) : "k".repeat(Math.min(before, 256))))
          broken.push(what + " " + before + "+" + escape + ": " + out.slice(-12))
      }
    }
  }
  check("an escape already in the text is kept or dropped whole at either end", broken.length === 0, broken.slice(0, 6).join(" | "))
  // Only what the agent or this file writes is such an escape: lowercase,
  // \uXXXX in the first plane and \u{X...} beyond it, naming a character that
  // is written out. Anything else that looks like one is the text it is.
  const piecesOf = t => { const out = []; Model.eachVisiblePiece(t, 0, p => { out.push(p) }); return out }
  check("the two formatters' escapes are one piece each",
    ["\\u0009", "\\u00ad", "\\u200b", "\\ufeff", "\\u{e0001}", "\\u{1bca0}"].every(e => piecesOf(e).length === 1), "")
  const literal = ["\\u0041", "\\u00AD", "\\u000A", "\\u{1F600}", "\\u{1f600}", "\\u{ad}", "\\u{00e0001}", "\\u{E0001}", "\\ud83d", "\\u{110000}"]
  check("a spelling neither formatter writes is ordinary characters",
    literal.every(e => piecesOf(e).length === e.length && piecesOf(e).join("") === e), literal.filter(e => piecesOf(e).length !== e.length).join(" "))
  check("so a cut may fall inside it, like any text",
    view({ keyName: "k".repeat(253) + "\\u0041" }).keyName === "k".repeat(253) + "\\u0"
      && view({ keyName: "k".repeat(253) + "\\u00ad" }).keyName === "k".repeat(253))
  // The reviewer's other case: the name of a program escaped here, then cut.
  for (let before = 249; before <= 256; before++) {
    const pn = view({ processPath: "/opt/" + "n".repeat(before) + "­tail" }).processName
    if (/\\u?[0-9a-f]{0,3}$/.test(pn) && !/\\u00ad$/.test(pn) || pn.length > 256)
      check(`a program name with a soft hyphen after ${before} characters does not end in a cut escape`, false, pn.slice(-8))
  }
  check("a program name is escaped and cut in one step",
    view({ processPath: "/opt/" + "n".repeat(252) + "­tail" }).processName === "n".repeat(252)
      && view({ processPath: "/opt/" + "n".repeat(250) + "­tail" }).processName === "n".repeat(250) + "\\u00ad"
      && view({ processPath: "/o­pt/ssh" }).processName === "ssh" && view({ processPath: "ssh" }).processName === "ssh"
      && view({ processPath: "/usr/bin/" }).processName === "")
  check("a backslash that starts no escape is still one character",
    view({ keyName: "a\\b\\u12\\u{}\\uzzzz" }).keyName === "a\\b\\u12\\u{}\\uzzzz")
}

// The limits bound the work as well as the result: a long text is not read
// to its end (boundedText stops at the limit, boundedPath reads only the
// tail). Counted on the one RegExp every step goes through.
{
  const re = Model.SSH_AGENT_TOKEN_RE
  let steps = 0
  re.exec = function(text) { steps++; return RegExp.prototype.exec.call(this, text) }
  const count = run => { steps = 0; run(); return steps }
  const long = "x".repeat(64000)
  const mixed = ("/seg­" + "\u{1f511}").repeat(9000) + "/ssh"
  eq("premise: a 64,000-character text", long.length, 64000)
  const text = count(() => Model.boundedText(long, 256))
  const path = count(() => Model.boundedPath(long, 512))
  const name = count(() => Model.processNameFromPath(long))
  // What is not a step of that RegExp: the string methods the name's lookup
  // uses. One lastIndexOf and one slice, and nothing that walks the text here.
  const used = {}
  const methods = ["lastIndexOf", "indexOf", "slice", "substring", "substr", "split", "replace", "match", "charCodeAt", "charAt", "codePointAt"]
  const originals = methods.map(n => String.prototype[n])
  methods.forEach((n, i) => { String.prototype[n] = function() { if (this.length > 1000) used[n] = (used[n] || 0) + 1; return originals[i].apply(this, arguments) } })
  let named
  try { named = Model.processNameFromPath("/usr/bin/" + long) } finally { methods.forEach((n, i) => { String.prototype[n] = originals[i] }) }
  check("a long program name's lookup is one lastIndexOf and one slice of the text, and no walk of it in script",
    named === "x".repeat(256) && JSON.stringify(used) === JSON.stringify({ lastIndexOf: 1, slice: 1 }), JSON.stringify(used))
  const tail = count(() => Model.boundedPath(mixed, 512))
  const viewed = count(() => Model.sshAgentPromptView(Object.assign({}, raw, { keyName: long, processPath: mixed, fingerprint: long, keyId: long }), 120))
  check("boundedText reads no further than its limit", text > 0 && text <= 258, String(text))
  check("boundedPath reads only the end of the path", path > 0 && path <= 512 + 12, String(path))
  check("a long program name is cut the same way", name > 0 && name <= 258, String(name))
  check("with escapes and pairs in it too", tail > 0 && tail <= 512 + 12, String(tail))
  check("a whole prompt of oversized fields stays bounded", viewed > 0 && viewed <= 4 * 258 + 524 + 258, String(viewed))
  delete re.exec
  check("and what they return is what reading it all returns",
    Model.boundedText(long, 256) === "x".repeat(256) && Model.boundedPath(long, 512) === "…" + "x".repeat(511)
      && Model.processNameFromPath(mixed) === "ssh" && Model.boundedPath(mixed, 512).length <= 512
      && Model.boundedPath(mixed, 512).slice(-4) === "/ssh")

  // Against the plain definition (escape everything, then cut between
  // pieces), over texts whose pairs and escapes fall on every edge.
  const pieces = t => { const out = []; Model.eachVisiblePiece(String(t), 0, p => { out.push(p) }); return out }
  const plainText = (t, limit) => { let out = ""; for (const p of pieces(t)) { if (out.length + p.length > limit) break; out += p } return out }
  const plainPath = (t, limit) => {
    const all = pieces(t)
    if (all.join("").length <= limit) return all.join("")
    let kept = ""
    for (let i = all.length - 1; i >= 0; i--) { if (kept.length + all[i].length > limit - 1) break; kept = all[i] + kept }
    return "…" + kept
  }
  const alphabet = ["a", "/", "­", "\u{1f511}", "\u{e0001}", "\\u0009", "\\u{1F600}", "\\", "u", "{", "}", "0", "\ud83d", "\udd11"]
  let seed = 12345
  const next = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n }
  const differ = []
  for (let round = 0; round < 400 && differ.length < 3; round++) {
    let t = ""
    const parts = 20 + next(90)
    for (let i = 0; i < parts; i++) t += alphabet[next(alphabet.length)]
    for (const limit of [8, 31, 64]) {
      if (Model.boundedPath(t, limit) !== plainPath(t, limit)) differ.push("path " + limit + " " + JSON.stringify(t))
      if (Model.boundedText(t, limit) !== plainText(t, limit)) differ.push("text " + limit + " " + JSON.stringify(t))
    }
  }
  check("the bounded scans agree with the plain definition on random texts", differ.length === 0, differ.join(" | ").slice(0, 400))
}

// Characters that draw as nothing are written out wherever the prompt shows them.
const ignorable = ["\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180b", "\u180f", "\u200b", "\u200f",
  "\u202a", "\u202e", "\u2060", "\u2065", "\u206f", "\u3164", "\ufe00", "\ufe0f", "\ufeff", "\uffa0", "\ufff0", "\ufff8",
  "\u{e0000}", "\u{e0001}", "\u{e007f}", "\u{e0100}", "\u{e01ef}", "\u{e0fff}"]
for (const c of ignorable) {
  const hex = c.codePointAt(0).toString(16)
  const shown = c.length === 2 ? "\\u{" + hex + "}" : "\\u" + ("0000" + hex).slice(-4)
  const v = Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/usr/bin/s" + c + "sh", keyName: "k" + c }), 120)
  const shownBody = Model.sshAgentNotifyCommand(v, 100).pop()
  check(`U+${hex.toUpperCase()} is written out on the card and in the notification`,
    v.processPath === "/usr/bin/s" + shown + "sh" && v.processName === "s" + shown + "sh" && v.keyName === "k" + shown
    && shownBody.includes("/usr/bin/s" + shown + "sh") && !shownBody.includes(c), v.processPath)
}
check("a path with a soft hyphen no longer reads as the path without it",
  Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/usr/bin/s\u00adsh" }), 120).processPath !== view.processPath)
check("ordinary text is untouched, accents, CJK, emoji and the next plane-14 neighbour included",
  ["/usr/bin/ssh", "caf\u00e9 \u4e2d\u6587", "\u{1f511} key", "a\ufff9b\ufffdc", "\u{e1000}", "\u{dffff}", "a\u00acb\u00aec"].every(t =>
    Model.sshAgentPromptView(Object.assign({}, raw, { keyName: t }), 120).keyName === t))

check("the notification command carries no secret state",
  !/masterPassword|pinEntry|session/i.test(body_("showSshNotification")))

// -------------------------------------------------------------------------
// The security policy states what these doors give a program running as you
// -------------------------------------------------------------------------

const policy = readPluginSource("SECURITY.md").replace(/\s+/g, " ")
check("SECURITY.md names sshPending and what it lists",
  /`sshPending` lists/.test(policy) && /fingerprint/.test(policy) && /path and pid/.test(policy))
check("SECURITY.md says sshReply can always deny, and that denials start the cooldown",
  /`sshReply <id> deny` denies/.test(policy) && /cooldown/.test(policy))
check("SECURITY.md says allowing from a terminal needs the opt-in",
  /`sshReply <id> allow` is refused unless/.test(policy) && /sshAgentTerminalApproval/.test(policy))
check("SECURITY.md says the notification can only deny",
  /only action on the notification that decides the request is \*\*Deny\*\*/.test(policy)
  && /\*\*Answer on the card\*\*, which some daemons draw as a second button, decides nothing/.test(policy)
  && /Nothing a notification returns approves/.test(policy))
const guide = readPluginSource("docs/ssh-agent.md")
check("the guide counts the notification's actions as the command has them",
  actions.length === 2 && /with two actions: \*\*Deny\*\*, the only one that decides the request, and \*\*Answer on the card\*\*/.test(guide)
  && !/one button/.test(guide) && !/offers only \*\*Deny\*\*/.test(policy))
check("the docs do not promise that different paths always look different",
  /does not make every pair of different paths look different/.test(guide) && !/so two different paths do not look the same/.test(guide)
  && !/full path/.test(guide + readPluginSource("CHANGELOG.md").split("## [Unreleased]")[1].split(/\n## \[/)[0]))
// The two collisions the guide owns up to, as the code has them.
check("a literal backslash spelling and the escaped character do read the same (documented, not changed)",
  Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/tmp/a\\u00adb" }), 120).processPath
    === Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/tmp/a\u00adb" }), 120).processPath)
check("two long paths that differ only in the part cut off read the same (documented)",
  Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/x" + "a".repeat(600) }), 120).processPath
    === Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/y" + "a".repeat(600) }), 120).processPath)
check("SECURITY.md separates what the notification's Deny and sshReply deny can reach",
  /denies the one signing request on the card/.test(policy) && /cannot reach a queued request or an unlock request/.test(policy)
  && /except a queued unlock request's/.test(policy))
// What the policy says about which denials count, against the code.
const reply = functionBody(service, "replySshRequest")
const queuedUnlock = reply.slice(reply.indexOf("var unlockLeft"))
check("a queued unlock denial is the one sshReply deny that does not count toward the cooldown",
  queuedUnlock !== "" && !/sshCooldown/.test(queuedUnlock)
  && (reply.slice(0, reply.indexOf("var unlockLeft")).match(/sshAgentCooldownAfter\(root\.sshCooldown, "denied"/g) || []).length === 2
  && /sshAgentCooldownAfter\(root\.sshCooldown, "denied"/.test(functionBody(service, "denyCurrentSshPrompt")))
check("the request's own deadline counts toward the cooldown, as the docs say",
  /sshAgentCooldownAfter\(root\.sshCooldown, "timeout"/.test(functionBody(service, "expireSshRequest"))
  && Model.sshAgentCooldownAfter(Model.sshAgentCooldownInitial(), "timeout", 1).refusals === 1
  && /two-minute deadline is separate/.test(readPluginSource("docs/ssh-agent.md")))
const ipc = service.slice(service.indexOf("IpcHandler {"))
const ipcNames = (ipc.match(/^    function [A-Za-z]+\(/gm) || []).map(f => f.trim().slice(9, -1))
check("the IPC target has the commands this test knows", ipcNames.length >= 16 && ipcNames.includes("sshReply"))
for (const name of ipcNames) {
  check(`SECURITY.md names the IPC command ${name}`, new RegExp("`" + name + "[ `]").test(policy))
}
check("the docs say a long path is shortened from the left",
  /the path is shortened from the left past the display limit/.test(guide) && /The limit is 512 UTF-16 code units of the text as written out, one of them reserved for the `…`/.test(guide)
  && Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/" + "a".repeat(600) + "/ssh" }), 120).processPath.length === 512
  && Model.sshAgentPromptView(Object.assign({}, raw, { processPath: "/" + "a".repeat(600) + "/ssh" }), 120).processPath[0] === "\u2026")
for (const [name, text] of [["README.md", readPluginSource("README.md")], ["docs/ssh-agent.md", readPluginSource("docs/ssh-agent.md")],
  ["CHANGELOG.md [Unreleased] Added", readPluginSource("CHANGELOG.md").split("## [Unreleased]")[1].split("### Security")[0]]]) {
  check(`${name} does not describe an Allow once notification`, !/Allow once/.test(text))
}

// -------------------------------------------------------------------------
// Idle timer: listing identities is not activity
// -------------------------------------------------------------------------

for (const fn of ["onSshAgentMessage", "showSshApproval", "armSshNotifyFallback", "showSshNotification", "sshPendingJson"]) {
  check(`${fn} does not refresh the auto-lock timer`, body_(fn) !== "" && !/resetAutoLockTimer/.test(body_(fn)))
}
check("approving a signing request counts as activity", /resetAutoLockTimer\(\)/.test(body_("approveSshRequest")))
check("denying does not", !/resetAutoLockTimer/.test(body_("denyCurrentSshPrompt")))

// The helper never reports identity listings except as the unlock prompt above.
const rust = readPluginSource("agent/src/main.rs")
const identitiesArm = rust.slice(rust.indexOf("AgentRequest::Identities =>"), rust.indexOf("AgentRequest::Sign {"))
check("the helper emits only unlock_required for a listing, never an approval or activity message",
  identitiesArm.includes("Output::UnlockRequired") && !identitiesArm.includes("Output::ApprovalRequired"))

done()
