#!/usr/bin/env node
// The approval prompt's other doors: a desktop notification when the card goes
// unanswered, listing and answering requests from a terminal, and what does
// and does not count as activity for the auto-lock timer.
//
//   node tests/ssh-agent-ux.test.js

const { createSuite, loadModule, readPluginSource } = require("./harness")

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
check("offers no action but Deny (nothing that approves)",
  cmd.filter(a => /^(--action|-A)/.test(a)).join("|") === "--action=deny=Deny" && !/allow|approve/i.test(cmd.slice(0, cmd.indexOf("--")).join(" ")))
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
check("the notification command carries no secret state",
  !/masterPassword|pinEntry|session/i.test(body_("showSshNotification")))

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
