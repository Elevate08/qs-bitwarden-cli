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
check("offers Allow once and Deny", cmd.includes("--action=allow=Allow once") && cmd.includes("--action=deny=Deny"))
check("waits for the answer", cmd.includes("--wait"))
check("expires with the request", cmd.includes("--expire-time=100000"))
const sep = cmd.indexOf("--")
check("title and body come after a lone --", sep > 0 && cmd.length === sep + 3)
const body = cmd[cmd.length - 1]
check("body names the key, fingerprint and program (no pid, as on the card)",
  body.includes("SHA256:abc") && body.includes("ssh") && !body.includes("4242"))
check("body is escaped as markup", body.includes("&lt;key&gt; &amp; co") && !body.includes("<key>"))
check("a bad request id builds nothing", Model.sshAgentNotifyCommand({ requestId: -1 }, 100).length === 0)
check("a forwarded request carries its warning",
  Model.sshAgentNotifyCommand(Model.sshAgentPromptView(Object.assign({}, raw, { forwarded: true }), 120), 50)
    .pop().includes("Forwarded"))
check("expiry never drops below five seconds", Model.sshAgentNotifyCommand(view, -3).includes("--expire-time=5000"))

// -------------------------------------------------------------------------
// Notification decision
// -------------------------------------------------------------------------

const arm = Model.sshAgentNotifyArmMs()
eq("allow after the arm delay approves", Model.sshAgentNotifyDecision(0, "allow\n", arm + 1), "allow")
eq("allow inside the arm delay is ignored and re-shown", Model.sshAgentNotifyDecision(0, "allow\n", 100), "early")
eq("deny action denies", Model.sshAgentNotifyDecision(0, "deny\n", 5000), "deny")
eq("dismiss or expiry (no output) denies", Model.sshAgentNotifyDecision(0, "", 5000), "deny")
eq("unknown output denies", Model.sshAgentNotifyDecision(0, "0\n", 5000), "deny")
eq("a failed notify-send decides nothing", Model.sshAgentNotifyDecision(1, "", 5000), "none")
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
