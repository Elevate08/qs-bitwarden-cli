#!/usr/bin/env node
// The approval prompt must say accurately what the companion verified and what
// it did not. Covers its presentation, the deny/approve/grant control lines,
// the denial cooldown, and never prompting over a locked screen.
//
//   node tests/ssh-agent-ui.test.js

const { createSuite, loadModule, read, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const path = require("path")

const Model = loadModule()

const { check, eq, done } = createSuite("ssh-agent-ui")

// -------------------------------------------------------------------------
// The companion's new messages must survive the bounded reader
// -------------------------------------------------------------------------

for (const [type, body] of [
  ["unlock_required", { requestId: 41, reason: "sign", keyName: "Work", fingerprint: "SHA256:x", pid: 12, processPath: "/usr/bin/ssh" }],
  ["approval_required", { requestId: 42, keyId: "k", keyName: "Work", fingerprint: "SHA256:x", pid: 12, processPath: "/usr/bin/ssh", operation: "ssh-sign", forwarded: false, grantOffered: true }],
  ["request_cancelled", { requestId: 42, reason: "withdrawn" }],
  ["grants_changed", { grants: [] }]
]) {
  const parsed = Model.parseAgentEvent(JSON.stringify(Object.assign({ v: 1, type: type }, body)))
  eq(`${type} keeps its type`, parsed.ok && parsed.message.type, type)
}

// -------------------------------------------------------------------------
// Control lines
// -------------------------------------------------------------------------

eq("approve once carries a zero window", Model.sshAgentApproveLine(42, 0),
  JSON.stringify({ v: 1, type: "approve", requestId: 42, grantSeconds: 0 }) + "\n")
eq("approve for a process carries its window", Model.sshAgentApproveLine(42, 120),
  JSON.stringify({ v: 1, type: "approve", requestId: 42, grantSeconds: 120 }) + "\n")
eq("a grant window is clamped to the documented cap", Model.sshAgentApproveLine(42, 99999),
  JSON.stringify({ v: 1, type: "approve", requestId: 42, grantSeconds: 900 }) + "\n")
eq("a negative window approves once instead", Model.sshAgentApproveLine(42, -5),
  JSON.stringify({ v: 1, type: "approve", requestId: 42, grantSeconds: 0 }) + "\n")
eq("deny is a versioned v1 line", Model.sshAgentDenyLine(42),
  JSON.stringify({ v: 1, type: "deny", requestId: 42 }) + "\n")
eq("a dismissed unlock is reported as user-cancelled", Model.sshAgentUnlockCancelledLine(41),
  JSON.stringify({ v: 1, type: "unlock_cancelled", requestId: 41, reason: "user-cancelled" }) + "\n")
// The companion cannot read shell.json, so the panel has to tell it.
eq("unlock-on-demand is sent to the companion", Model.sshAgentOptionsLine(true),
  JSON.stringify({ v: 1, type: "options", unlockOnDemand: true }) + "\n")
eq("anything that is not true is off", Model.sshAgentOptionsLine(undefined),
  JSON.stringify({ v: 1, type: "options", unlockOnDemand: false }) + "\n")

eq("a single grant is revoked by id", Model.sshAgentRevokeGrantLine(9),
  JSON.stringify({ v: 1, type: "revoke_grant", grantId: 9 }) + "\n")
eq("an invalid request id yields no line", Model.sshAgentApproveLine("nope", 0), "")
eq("an invalid grant id yields no line", Model.sshAgentRevokeGrantLine(-1), "")

// -------------------------------------------------------------------------
// What the prompt shows
// -------------------------------------------------------------------------

const request = {
  v: 1, type: "approval_required", requestId: 42, keyId: "item-1",
  keyName: "personal ed25519", fingerprint: "SHA256:9wKk2nQ8xR1vLm4pZc7dYtE0",
  pid: 48213, processPath: "/usr/bin/ssh", operation: "ssh-sign",
  forwarded: false, grantOffered: true
}

const view = Model.sshAgentPromptView(request, 120)
eq("the prompt names the key", view.keyName, "personal ed25519")
eq("the prompt shows the full fingerprint", view.fingerprint, "SHA256:9wKk2nQ8xR1vLm4pZc7dYtE0")
eq("the prompt shows the executable path", view.processPath, "/usr/bin/ssh")
eq("the prompt derives the process name from the path", view.processName, "ssh")
eq("the prompt shows the pid", view.pid, 48213)
eq("the prompt offers a grant", view.grantOffered, true)
check("the grant button states its window", /2m|120/.test(view.grantLabel), view.grantLabel)
check("and so does its short tile label", view.grantShortLabel === "Approve 2m", view.grantShortLabel)
// A grant covers one program, not one process.
// The button has to say so, or it promises a narrower thing than it does.
check("the grant button says what it actually covers",
  /program/i.test(view.grantLabel) && !/this process/i.test(view.grantLabel), view.grantLabel)

// The companion verifies the peer UID and nothing else. Saying so on the
// prompt is the difference between context and a claim of identity.
check("the prompt says process details are not verified",
  /not verified|reported/i.test(view.provenanceNote), view.provenanceNote)
check("the prompt never calls the process trusted or verified",
  !/\b(verified|authenticated|trusted) (process|by)\b/i.test(view.provenanceNote), view.provenanceNote)

// A zero window means grants are off, so the button must not be offered.
const noGrant = Model.sshAgentPromptView(request, 0)
eq("a zero window offers no grant", noGrant.grantOffered, false)
const refusedGrant = Model.sshAgentPromptView(Object.assign({}, request, { grantOffered: false }), 120)
eq("a companion that offers no grant is respected", refusedGrant.grantOffered, false)

// Forwarding is rejected in v1; if one ever arrives it is called out, not
// shown as ordinary context.
const forwarded = Model.sshAgentPromptView(Object.assign({}, request, { forwarded: true }), 120)
check("a forwarded request is flagged", forwarded.forwardedWarning.length > 0, forwarded.forwardedWarning)
eq("a forwarded request offers no grant", forwarded.grantOffered, false)
eq("an ordinary request has no forwarding warning", view.forwardedWarning, "")

// What is being signed. A grant covers one kind of signature, so the prompt
// names the kind the companion classified -- and nothing it did not.
const labelled = (operation, operationDetail) =>
  Model.sshAgentPromptView(Object.assign({}, request, { operation, operationDetail }), 120)
eq("a Git signature is named as one", labelled("sshsig", "git").operationLabel, "Git commit or tag signature")
check("another namespace is shown as-is",
  /"file"/.test(labelled("sshsig", "file").operationLabel), labelled("sshsig", "file").operationLabel)
eq("a login names its user", labelled("ssh-auth", "root").operationLabel, "SSH login as root")
check("unrecognised data says so",
  /unrecognised/i.test(labelled("ssh-sign", "").operationLabel), labelled("ssh-sign", "").operationLabel)
eq("an unknown operation is not passed through", labelled("delete-everything", "x").operation, "")
eq("and gets no label", labelled("delete-everything", "x").operationLabel, "")
// A login names the server its session was bound to; a grant covers only it.
const HOST = "SHA256:LgZpRzWEAbVvBimxTv69/UB88PD8jyOSDqfozr+iNX0"
const loginTo = (hostKey, operation) => Model.sshAgentPromptView(
  Object.assign({}, request, { operation: operation || "ssh-auth", operationDetail: "git", hostKey }), 120)
eq("a login carries its server's host key", loginTo(HOST).hostKey, HOST)
check("and names it in the prompt", loginTo(HOST).destinationLabel.indexOf(HOST) >= 0, loginTo(HOST).destinationLabel)
check("a login with no reported server says so",
  /not reported/i.test(loginTo("").destinationLabel), loginTo("").destinationLabel)
eq("a host key of any other shape is dropped", loginTo("SHA256:x\nforged").hostKey, "")
eq("a Git signature has no server", loginTo(HOST, "sshsig").hostKey, "")
eq("and no destination line", loginTo(HOST, "sshsig").destinationLabel, "")
// On a forwarded connection the remote host can send a bind of its own, so a
// server named only by one is its claim. The helper says which
// (hostKeyClaimed); the prompt, the notification and the terminal listing
// say so instead of showing it as the client's report.
{
  const login = extra => Model.sshAgentPromptView(Object.assign({}, request,
    { operation: "ssh-auth", operationDetail: "git", hostKey: HOST }, extra), 120)
  const plain = "Server host key " + HOST
  const claimedLabel = "Server claimed by the remote host, not verified: " + HOST
  const claimed = login({ forwarded: true, hostKeyClaimed: true })
  eq("a server only the remote host named is marked", claimed.hostKeyClaimed, true)
  eq("and the prompt says whose word it is", claimed.destinationLabel, claimedLabel)
  eq("the fingerprint is still carried", claimed.hostKey, HOST)
  eq("such a login offers no grant", claimed.grantOffered, false)
  check("and keeps the forwarding warning", claimed.forwardedWarning.length > 0)

  const hostbound = login({ forwarded: true, hostKeyClaimed: false })
  eq("a forwarded login whose server the helper vouches for is not marked", hostbound.hostKeyClaimed, false)
  eq("and reads as before", hostbound.destinationLabel, plain)
  eq("a local login is not marked", login({ forwarded: false, hostKeyClaimed: false }).destinationLabel, plain)

  // A helper from before the field cannot say, so a forwarded host key is
  // taken for a claim; only the boolean false is believed.
  eq("a forwarded login from a helper without the field is marked",
    login({ forwarded: true }).destinationLabel, claimedLabel)
  for (const odd of [0, "false"]) {
    eq(`hostKeyClaimed ${JSON.stringify(odd)} on a forwarded login is not a "no"`,
      login({ forwarded: true, hostKeyClaimed: odd }).hostKeyClaimed, true)
    eq(`hostKeyClaimed ${JSON.stringify(odd)} on a local login is not a "yes"`,
      login({ forwarded: false, hostKeyClaimed: odd }).hostKeyClaimed, false)
  }
  eq("a claim is marked even if the helper did not say forwarded",
    login({ forwarded: false, hostKeyClaimed: true }).destinationLabel, claimedLabel)

  // Nothing is claimed where there is no server to show.
  const none = login({ forwarded: true, hostKeyClaimed: true, hostKey: "" })
  eq("no host key, nothing claimed", none.hostKeyClaimed, false)
  check("and the line says none was reported", /not reported/i.test(none.destinationLabel), none.destinationLabel)

  // The notification and the terminal listing carry the same line.
  const body = Model.sshAgentNotifyCommand(claimed, 60).pop()
  check("the notification says the server is claimed", body.split("\n").indexOf(claimedLabel) >= 0, body)
  check("and never the unmarked line", body.indexOf(plain) < 0, body)
  const raw = Object.assign({}, request, { requestId: 5, operation: "ssh-auth", operationDetail: "git",
    hostKey: HOST, forwarded: true, hostKeyClaimed: true })
  const listed = Model.sshAgentPendingRequests(raw, [Object.assign({}, raw, { requestId: 6, hostKeyClaimed: false })],
    Object.assign({}, raw, { requestId: 7 }), [])
  eq("sshPending says a signing request's server is claimed", listed[0].destination, claimedLabel)
  eq("and not one the helper vouches for", listed[1].destination, plain)
  eq("an unlock request's too", listed[2].destination, claimedLabel)

  // The release of a held request matches its unlock prompt only if both
  // say the same about the server.
  const unlock = Object.assign({}, raw, { type: "unlock_required" })
  eq("the same claim is the same request", Model.sshAgentSameRequest(unlock, Object.assign({}, raw, { requestId: 9 })), true)
  eq("a different one is not",
    Model.sshAgentSameRequest(unlock, Object.assign({}, raw, { requestId: 9, hostKeyClaimed: false })), false)

  // From the helper's stdout to the prompt: a line as the rebuilt helper
  // prints it (its field order, the new field included) goes through the
  // supervisor's own parser unchanged, for both kinds of prompt, and the
  // view reads the helper's answer either way.
  {
    let state = Model.sshAgentReduce(Model.sshAgentInitialState(), { kind: "enabled", value: true, nowMs: 1 }).state
    state = Model.sshAgentReduce(state, { kind: "started", nowMs: 2 }).state
    state = Model.sshAgentReduce(state, { kind: "line", nowMs: 3, line: JSON.stringify({ type: "ready", v: 1,
      socketPath: "/run/user/1000/qs-bitwarden-cli/ssh-agent.sock", fifoPath: "/run/user/1000/qs-bitwarden-cli/load.fifo",
      agentVersion: "0.1.0" }) + "\n" }).state
    eq("premise: the supervisor is ready", state.phase, "ready")
    const printed = (type, claimed) => (type === "approval_required"
      ? `{"type":"approval_required","v":1,"requestId":7,"keyId":"item","keyName":"key","fingerprint":"SHA256:x",`
      : `{"type":"unlock_required","v":1,"requestId":7,"reason":"sign","keyName":"key","fingerprint":"SHA256:x",`)
      + `"pid":4242,"processPath":"/usr/bin/ssh","operation":"ssh-auth","operationDetail":"git","hostKey":"${HOST}",`
      + `"hostKeyClaimed":${claimed},"forwarded":true,"grantOffered":false}\n`
    for (const type of ["approval_required", "unlock_required"]) {
      for (const claimed of [true, false]) {
        const step = Model.sshAgentReduce(state, { kind: "line", line: printed(type, claimed), nowMs: 4 })
        const message = step.action.message
        check(`${type} with hostKeyClaimed ${claimed} is accepted as the helper printed it`,
          step.state.phase === "ready" && message && message.type === type && message.hostKeyClaimed === claimed,
          JSON.stringify(step))
      }
    }
  }
  // Nothing between the parser and the view rebuilds the message from a
  // list of fields: the prompt is made from the message as it arrived.
  const service = read("Service.qml")
  check("the card's view is made from the helper's message itself",
    /root\.sshPromptRaw = message/.test(service)
      && /root\.sshPrompt = Model\.sshAgentPromptView\(message, root\.sshAgentApprovalWindowSec\)/.test(service)
      && /root\.sshUnlockRequest = Model\.sshAgentPromptView\(message, 0\)/.test(service))

  // The card draws a claimed server as a warning.
  const screen = read("SshApprovalScreen.qml")
  check("the card colours a claimed server as urgent",
    /text: vault\.sshPrompt \? vault\.sshPrompt\.destinationLabel : ""\s+color: screen\.vault\.sshPrompt && screen\.vault\.sshPrompt\.hostKeyClaimed === true\s+\? screen\.panel\.urgent : screen\.panel\.dim/.test(screen))
}
eq("a login grant shows its server",
  Model.sshAgentGrantViews([{ grantId: 12, keyName: "k", fingerprint: "SHA256:z", pid: 7,
    processPath: "/usr/bin/ssh", operation: "ssh-auth", operationDetail: "git", hostKey: HOST,
    expiresInSec: 60 }], 1_000)[0].hostKey, HOST)

check("an absurd login name is bounded",
  labelled("ssh-auth", "u".repeat(5000)).operationLabel.length <= 300,
  String(labelled("ssh-auth", "u".repeat(5000)).operationLabel.length))

// A vault item's name is attacker-controllable by whoever shares the
// collection it came from, and the process path comes from outside too.
const hostile = Model.sshAgentPromptView(Object.assign({}, request, {
  keyName: "<img src=x onerror=alert(1)>",
  processPath: "/usr/bin/<b>ssh</b>"
}), 120)
// The kit and the plugin's own Text elements draw plain text (plainLabel
// passes values through; rich-text.test.js holds every Text to PlainText),
// so the markup is shown as the characters it is, never rendered.
const approvalScreenSrc = read("SshApprovalScreen.qml")
const keyNameText = approvalScreenSrc.slice(approvalScreenSrc.lastIndexOf("Text {", approvalScreenSrc.indexOf("sshPrompt.keyName")),
  approvalScreenSrc.indexOf("sshPrompt.keyName"))
check("a markup key name is drawn as plain text, never rendered",
  Model.plainLabel(hostile.keyName) === hostile.keyName && /textFormat:\s*Text\.PlainText/.test(keyNameText),
  keyNameText)
check("a hostile name is not silently dropped",
  hostile.keyName.length > 0, hostile.keyName)

const huge = Model.sshAgentPromptView(Object.assign({}, request, {
  keyName: "n".repeat(5000), processPath: "/" + "p".repeat(5000)
}), 120)
check("an absurd key name is bounded", huge.keyName.length <= 256, String(huge.keyName.length))
check("an absurd path is bounded", huge.processPath.length <= 512, String(huge.processPath.length))

// Text that draws as nothing, or as something else, is written out. A path may
// hold a newline, so a directory can end in a line that looks like the
// requesting program.
const spoofed = Model.sshAgentPromptView(Object.assign({}, request, {
  processPath: "/home/u/x\n/usr/bin/ssh-keygen",
  keyName: "prod\u202egnihtemos\u200b key\u0085",
  operation: "sshsig", operationDetail: "git\u2066"
}), 120)
eq("a newline in a path is shown, not drawn", spoofed.processPath, "/home/u/x\\u000a/usr/bin/ssh-keygen")
eq("the name beside it is the real executable", spoofed.processName, "ssh-keygen")
eq("a direction override and zero-width space in a key name are shown",
  spoofed.keyName, "prod\\u202egnihtemos\\u200b key\\u0085")
check("the signature namespace is escaped too", spoofed.operationLabel.indexOf("\u2066") < 0
  && spoofed.operationLabel.indexOf("\\u2066") >= 0, spoofed.operationLabel)
const everyInvisible = Model.sshAgentPromptView(Object.assign({}, request, {
  keyName: "\u0000\u001f\u007f\u009f\u200b\u200f\u2028\u202a\u202e\u2066\u2069\ufeff"
}), 120)
check("no control, bidi or zero-width character reaches the prompt",
  !/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/.test(everyInvisible.keyName),
  JSON.stringify(everyInvisible.keyName))

// A long path loses its beginning, never the executable.
const longPath = "/" + "d".repeat(600) + "/bin/ssh-keygen"
const longView = Model.sshAgentPromptView(Object.assign({}, request, { processPath: longPath }), 120)
check("a long path keeps its end", longView.processPath.length === 512
  && longView.processPath.charAt(0) === "\u2026" && longView.processPath.endsWith("/bin/ssh-keygen"),
  longView.processPath.slice(-30))
eq("the name is taken from the whole path", longView.processName, "ssh-keygen")
const hiddenInGrant = Model.sshAgentGrantViews([
  { grantId: 1, keyName: "k\n", fingerprint: "SHA256:x", pid: 1, processPath: "/a\n/b/ssh", expiresInSec: 5 }])
check("a grant's path and key name are escaped",
  hiddenInGrant[0].processPath === "/a\\u000a/b/ssh" && hiddenInGrant[0].keyName === "k\\u000a",
  JSON.stringify(hiddenInGrant[0]))

// The panel's countdown has to agree with the companion's deadline, or it
// counts down to a moment nothing happens at.
const agentSrc = fs.readFileSync(path.join(repoRoot, "agent", "src", "approvals.rs"), "utf8")
const agentDeadline = /pub const REQUEST_LIFETIME_MS: u64 = ([0-9_]+);/.exec(agentSrc)
check("the panel and the companion agree on it",
  agentDeadline && Number(agentDeadline[1].replace(/_/g, "")) === Model.sshAgentRequestDeadlineMs(),
  agentDeadline ? agentDeadline[1] : "REQUEST_LIFETIME_MS not found")

// -------------------------------------------------------------------------
// Grants
// -------------------------------------------------------------------------

const grants = Model.sshAgentGrantViews([
  { grantId: 9, keyName: "personal ed25519", fingerprint: "SHA256:x", pid: 48213, processPath: "/usr/bin/ssh", expiresInSec: 95 },
  { grantId: 10, keyName: "work rsa", fingerprint: "SHA256:y", pid: 5, processPath: "/usr/bin/git", expiresInSec: 0 }
])
eq("every grant is listed", grants.length, 2)
eq("a grant keeps its id", grants[0].grantId, 9)
eq("a grant names its process", grants[0].processName, "ssh")
check("a grant states its remaining time", /1m 35s|95/.test(grants[0].remainingLabel), grants[0].remainingLabel)
check("an expiring grant says so", grants[1].remainingLabel.length > 0, grants[1].remainingLabel)
eq("a malformed grant list yields nothing", Model.sshAgentGrantViews(null).length, 0)
const scoped = Model.sshAgentGrantViews([
  { grantId: 11, keyName: "work", fingerprint: "SHA256:z", pid: 7, processPath: "/usr/bin/ssh-keygen",
    operation: "sshsig", operationDetail: "git", expiresInSec: 60 }
], 1_000)
eq("a grant says what kind of signature it covers", scoped[0].operationLabel, "Git commit or tag signature")
eq("and still says so as it counts down",
  Model.sshAgentGrantsAt(scoped, 31_000)[0].operationLabel, "Git commit or tag signature")

// A grant is announced once, so its remaining time must be re-derived each
// tick or it never counts down.
const announced = Model.sshAgentGrantViews(
  [{ grantId: 9, keyName: "personal ed25519", fingerprint: "SHA256:x", pid: 48213, processPath: "/usr/bin/ssh", expiresInSec: 120 }],
  10_000)
eq("an announced grant records when it expires", announced[0].expiresAtMs, 130_000)
const halfway = Model.sshAgentGrantsAt(announced, 70_000)
eq("the remaining time follows the clock", halfway[0].remainingSec, 60)
check("and the label follows it", /1m/.test(halfway[0].remainingLabel), halfway[0].remainingLabel)
eq("a lapsed grant leaves the list without waiting to be told",
  Model.sshAgentGrantsAt(announced, 130_001).length, 0)
eq("a grant on its last second is still listed",
  Model.sshAgentGrantsAt(announced, 129_500).length, 1)
eq("an unstamped view survives re-derivation rather than vanishing",
  Model.sshAgentGrantsAt([{ grantId: 9, remainingLabel: "2m left" }], 70_000).length, 1)
eq("and so does every view before the first tick",
  Model.sshAgentGrantsAt(announced, 0).length, 1)
eq("a malformed set re-derives to nothing", Model.sshAgentGrantsAt(null, 1).length, 0)

// The development-helper warning says why it matters and whether the shipped
// helper was rejected or just absent.
const rejected = Model.sshAgentDevelopmentHelperWarning({ source: "development", checksum: "mismatch" })
check("a rejected shipped helper is named as the reason", /checksum/i.test(rejected), rejected)
const absent = Model.sshAgentDevelopmentHelperWarning({ source: "development", checksum: "unchecked" })
check("an absent one is not blamed on a checksum", !/checksum/i.test(absent), absent)
for (const [label, text] of [["rejected", rejected], ["absent", absent]]) {
  check(`the ${label} warning says what is serving keys`, /locally built/i.test(text), text)
  check(`the ${label} warning says what it lacks`, /provenance|digest/i.test(text), text)
  check(`the ${label} warning says how to fix it`, /reinstall/i.test(text), text)
  check(`the ${label} warning does not answer a user with a build command`,
    !/build-agent|cargo/.test(text), text)
}
check("a missing helper record does not throw",
  typeof Model.sshAgentDevelopmentHelperWarning(null) === "string", "threw or returned non-string")

// -------------------------------------------------------------------------
// Never prompt over a locked screen
// -------------------------------------------------------------------------

eq("an ordinary desktop prompts", Model.sshAgentShouldPrompt({ screenLocked: false }), true)
eq("a locked screen never prompts", Model.sshAgentShouldPrompt({ screenLocked: true }), false)
eq("an unknown screen state does not prompt", Model.sshAgentShouldPrompt(null), false)

// -------------------------------------------------------------------------
// Denial cooldown
// -------------------------------------------------------------------------

let cool = Model.sshAgentCooldownInitial()
eq("nothing is on cooldown to begin with", Model.sshAgentCooldownActive(cool, 0), false)

cool = Model.sshAgentCooldownAfter(cool, "denied", 1000)
eq("one denial does not start a cooldown", Model.sshAgentCooldownActive(cool, 1000), false)
cool = Model.sshAgentCooldownAfter(cool, "denied", 2000)
eq("two consecutive denials start one", Model.sshAgentCooldownActive(cool, 2000), true)
eq("the cooldown ends on its own", Model.sshAgentCooldownActive(cool, 2000 + 10 * 60 * 1000), false)

// Approving clears the history: the user is engaging, not being pestered.
let mixed = Model.sshAgentCooldownInitial()
mixed = Model.sshAgentCooldownAfter(mixed, "denied", 0)
mixed = Model.sshAgentCooldownAfter(mixed, "approved", 100)
mixed = Model.sshAgentCooldownAfter(mixed, "denied", 200)
eq("an approval resets the denial run", Model.sshAgentCooldownActive(mixed, 200), false)

// No prompt can appear during a cooldown, so only an explicit resume ends it
// early.
let stuck = Model.sshAgentCooldownInitial()
stuck = Model.sshAgentCooldownAfter(stuck, "denied", 0)
stuck = Model.sshAgentCooldownAfter(stuck, "denied", 100)
stuck = Model.sshAgentCooldownAfter(stuck, "resumed", 200)
eq("an explicit resume ends it at once", Model.sshAgentCooldownActive(stuck, 200), false)
eq("and clears the run behind it, so one later denial does not re-arm it",
  Model.sshAgentCooldownActive(Model.sshAgentCooldownAfter(stuck, "denied", 300), 300), false)

// Nothing the requesting process does may end a cooldown, or prolong one: the
// suppressed path answers the client itself and records no outcome, so only
// prompts a person actually saw ever feed the run.
let unattended = Model.sshAgentCooldownInitial()
unattended = Model.sshAgentCooldownAfter(unattended, "denied", 0)
unattended = Model.sshAgentCooldownAfter(unattended, "denied", 100)
eq("an unanswered request leaves the window where it was",
  Model.sshAgentCooldownAfter(unattended, "withdrawn", 200).untilMs, unattended.untilMs)

// A cooldown that fails signatures silently is worse than the pestering it
// prevents: SSH just stops working for five minutes with no explanation
// anywhere. It has to say so, and say when it lifts.
let cooled = Model.sshAgentCooldownInitial()
const quiet = Model.sshAgentCooldownStatus(cooled, 0)
eq("nothing is reported while no cooldown is running", quiet.active, false)

cooled = Model.sshAgentCooldownAfter(cooled, "denied", 0)
cooled = Model.sshAgentCooldownAfter(cooled, "denied", 0)
const cooling = Model.sshAgentCooldownStatus(cooled, 0)
eq("an active cooldown is reported", cooling.active, true)
check("it says SSH requests are being refused",
  /refus|declin/i.test(cooling.message), cooling.message)
check("it says when it lifts", /\d/.test(cooling.message), cooling.message)
eq("it reports the remaining time", cooling.remainingSec, 300)
check("the remaining time counts down",
  Model.sshAgentCooldownStatus(cooled, 60000).remainingSec === 240,
  String(Model.sshAgentCooldownStatus(cooled, 60000).remainingSec))
eq("it clears itself when the window passes",
  Model.sshAgentCooldownStatus(cooled, 5 * 60 * 1000).active, false)

// Unlocking runs one `bw list items`, which takes seconds on a real vault.
// The request that triggered the unlock is held across it, so without a
// loading state the user unlocks and then watches nothing happen.
const note = Model.sshAgentLoadingNote()
check("the loading note says keys are on the way", /load/i.test(note), note)

// -------------------------------------------------------------------------
// The panel wiring
// -------------------------------------------------------------------------

// Every file with SSH markup, so "must NOT appear" checks cannot pass on
// content that merely moved.
const sshUiFiles = [
  "Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml",
  "SshApprovalPopup.qml", "SshUnlockScreen.qml", "UnlockForm.qml",
  "SshCaption.qml", "SshSectionHeader.qml"
]
const panelSrc = sshUiFiles
  .map(file => fs.existsSync(path.join(repoRoot, file)) ? readPluginSource(file) : "")
  .join("\n")
const approvalSrc = readPluginSource("SshApprovalScreen.qml")
const settingsSrc = readPluginSource("SshAgentSettings.qml")
const popupSrc = fs.existsSync(path.join(repoRoot, "SshApprovalPopup.qml"))
  ? readPluginSource("SshApprovalPopup.qml") : ""
const unlockSrc = ["SshUnlockScreen.qml", "UnlockForm.qml"]
  .filter(file => fs.existsSync(path.join(repoRoot, file)))
  .map(readPluginSource)
  .join("\n")
const unlockFormSrc = fs.existsSync(path.join(repoRoot, "UnlockForm.qml"))
  ? read("UnlockForm.qml") : ""
const sshUnlockOnly = fs.existsSync(path.join(repoRoot, "SshUnlockScreen.qml"))
  ? read("SshUnlockScreen.qml") : ""

check("an approval_required message raises the prompt",
  /message\.type === "approval_required"[\s\S]{0,600}?showSshApproval\(message\)/.test(panelSrc),
  "approval_required never raises the prompt")
// Opening the panel sends it to the item list, so a prompt must open it before
// claiming the screen (else: live state, blank screen).
check("the legacy panel is opened before its approval screen is claimed",
  /function showSshApproval\(message\)[\s\S]{0,300}?if \(startSshPromptClock\(\)\) return[\s\S]{0,600}?if \(!root\.opened\) root\.open\(\)\s*root\.currentScreen = "sshApproval"\s*\}/.test(panelSrc),
  "the screen is claimed before opening, so opening resets it")
// Pinned on ordering, not character distance.
const openedBody = panelSrc.slice(panelSrc.indexOf("function onPanelOpened()"),
  panelSrc.indexOf("function onPanelClosed") > 0
    ? panelSrc.indexOf("function onPanelClosed")
    : panelSrc.indexOf("function onPanelOpened()") + 2000)
check("opening the panel does not discard a live request",
  /if \(sshPrompt\)[\s\S]{0,160}?currentScreen = "sshApproval"[\s\S]{0,40}?return/.test(openedBody)
    && openedBody.indexOf("sshPrompt") < openedBody.indexOf('status === "unlocked"'),
  "onPanelOpened resets away from a live prompt")

// Screen visibility binds to activeScreen, which a live request wins, so no
// currentScreen assignment can hide it.
check("a live prompt outranks navigation state",
  /readonly property string activeScreen: sshPrompt !== null && !sshAgentApprovalPopup \? "sshApproval" : currentScreen/.test(panelSrc),
  "no activeScreen; a stray currentScreen assignment can hide the prompt")
check("no screen visibility still binds to currentScreen directly",
  panelSrc.split("\n").filter(l => l.trim().startsWith("visible:") && l.includes("root.currentScreen")).length === 0,
  panelSrc.split("\n").filter(l => l.trim().startsWith("visible:") && l.includes("root.currentScreen")).join(" | "))

// A prompt that opened the panel closes it when answered; one the user opened
// stays.
check("answering a prompt that opened the panel closes it again",
  /function dismissSshApproval\(\)[\s\S]{0,900}?openedForThis && root\.opened\) root\.close\(\)/.test(panelSrc),
  "the panel stays open after an answer it opened itself for")
check("whether the panel was already open is captured before opening it",
  /function showSshApproval\(message\)[\s\S]{0,900}?sshPromptOpenedPanel = !root\.opened/.test(panelSrc),
  "nothing records whether the request opened the panel")
check("a panel the user already had open is restored, not closed",
  /function dismissSshApproval\(\)[\s\S]{0,900}?screenBeforeSshApproval/.test(panelSrc),
  "answering does not restore the previous screen")

check("a withdrawn request takes its prompt down",
  /message\.type === "request_cancelled"[\s\S]{0,1500}?dismissSshApproval\(\)/.test(panelSrc),
  "request_cancelled is ignored")
// The approval decision depends on the key identity and the requesting
// program, both known before the vault read finishes. Waiting for the read
// and only then asking is delay with nothing behind it.
check("unlocking promotes the held request straight to an approval",
  /function promoteUnlockToApproval\(\)[\s\S]{0,600}?showSshApproval\(raw\)/.test(panelSrc),
  "unlocking never promotes the held request")
check("the promotion happens as soon as the vault unlocks",
  /onStatusChanged:[\s\S]{0,200}?promoteUnlockToApproval\(\)/.test(panelSrc),
  "nothing promotes on unlock")
// The panel root reaches the screens as `root` and the extracted files as
// `panel`, so the object is matched either way -- a check pinned to one of
// them starts passing or failing on which file the markup sits in.
check("the approval prompt says keys are still loading",
  /visible: (?:root|panel)\.sshAgentLoadActive[\s\S]{0,200}?sshAgentLoadingNote\(\)/.test(panelSrc),
  "the prompt does not say the keys are still on their way")

check("the setting reaches the companion on handshake and on change",
  /onSshAgentUnlockOnDemandChanged: sendSshAgentOptions\(\)/.test(panelSrc)
    && /if \(sshAgentGateOpen\) sendSshAgentOptions\(\)/.test(panelSrc),
  "unlock-on-demand never reaches the companion")
check("an identity listing is not promoted into an approval",
  /reason === "list-identities"/.test(panelSrc),
  "a listing would be turned into a signature approval")

check("grants are tracked from the companion",
  /message\.type === "grants_changed"/.test(panelSrc), "grants_changed is ignored")

check("the card's approve and deny answer the request that is shown",
  /function approveSshRequest\(grantSeconds\)[\s\S]{0,500}?sshAgentWrite\(Model\.sshAgentApproveLine\(sshPrompt\.requestId, grantSeconds\)\)/.test(panelSrc)
    && /function denySshRequest\(\)[\s\S]{0,500}?if \(sshPrompt\) \{\s*sshAgentWrite\(Model\.sshAgentDenyLine\(sshPrompt\.requestId\)\)\s*root\.sshCooldown = Model\.sshAgentCooldownAfter\(root\.sshCooldown, "denied"/.test(panelSrc),
  "approve or deny on the card does not reach the companion")
check("grants can be revoked individually and together",
  /sshAgentRevokeGrantLine\(/.test(panelSrc) && /sshAgentRevokeGrantsLine\(/.test(panelSrc),
  "grant revocation is not wired")

check("a locked screen or a running cooldown suppresses the prompt",
  /function sshAgentMayPrompt\(\)[\s\S]{0,200}?if \(!Model\.sshAgentShouldPrompt\([^\n]*\) return false\s+return !Model\.sshAgentCooldownActive\(root\.sshCooldown, Date\.now\(\)\)/.test(panelSrc),
  "the screen-lock rule or the cooldown is not applied")

check("a request the cooldown refuses does not feed the cooldown",
  /!sshAgentMayPrompt\(\)\)\s*\{\s*sshAgentWrite\(Model\.sshAgentDenyLine\(message\.requestId\)\)\s*return/.test(panelSrc),
  "a suppressed request records an outcome, so a busy process can hold the cooldown open")
// SSH_AUTH_SOCK is fixed at login, so the notice reads the routing file, not
// the environment.
const routed = { state: "matches" }
eq("a deleted fragment is caught even while this session still points here",
  Model.sshAgentRoutingNotice({ state: "absent" }, routed).urgent, true)
check("and it says the next login is what breaks",
  /next login/.test(Model.sshAgentRoutingNotice({ state: "absent" }, routed).text),
  Model.sshAgentRoutingNotice({ state: "absent" }, routed).text)
eq("a managed fragment in a routed session says nothing",
  Model.sshAgentRoutingNotice({ state: "managed" }, routed).text, "")
check("a managed fragment in an unrouted session explains the wait",
  /next login/.test(Model.sshAgentRoutingNotice({ state: "managed" }, { state: "elsewhere" }).text),
  "a freshly written fragment does not explain why nothing changed yet")
eq("and that is information, not a fault",
  Model.sshAgentRoutingNotice({ state: "managed" }, { state: "elsewhere" }).urgent, false)
for (const quiet of ["unknown", "no-home"]) {
  eq(`a ${quiet} fragment leaves the routing section to explain itself`,
    Model.sshAgentRoutingNotice({ state: quiet }, routed).text, "")
}
eq("a missing record says nothing rather than throwing",
  Model.sshAgentRoutingNotice(null, null).text, "")

check("re-enabling the agent restores the routing file it removed on disable",
  /uwsmRestorePending = true[\s\S]{0,1200}?function applyUwsmRestore\(\)[\s\S]{0,600}?beginUwsmSetup\(\)/.test(panelSrc),
  "disabling removes the routing file and enabling never puts it back")
check("but never over a file it did not write, or another session's agent",
  /uwsmFragment\.state !== "absent" \|\| sshRouting\.state === "elsewhere"[\s\S]{0,40}?return/.test(panelSrc),
  "the restore overrules a foreign routing file or an existing agent")

// `omarchy plugin remove` has no uninstall hook, so the last moment this code
// can run is while the plugin is still installed. What it misses becomes a
// command the user has to type from the README.
const wipe = Model.pluginDataRemoveCommand().join(" ")
for (const [what, needle] of [
  ["the keyring entries", "secret-tool clear service qs-bitwarden-cli"],
  ["the learned suggestions", "XDG_STATE_HOME"],
  ["the exported public keys", "XDG_DATA_HOME"]
]) check(`removal clears ${what}`, wipe.indexOf(needle) >= 0, wipe)
check("and never logs the vault out on its own",
  wipe.indexOf("bw logout") < 0 && wipe.indexOf("bw ") < 0, wipe)
check("nor touches the shell's own settings file",
  wipe.indexOf("shell.json") < 0, wipe)

const wiped = Model.parsePluginDataRemoval(0, "removed keyring state data")
eq("a full removal reports success", wiped.ok, true)
check("and names what went", /keyring|suggestions|public keys/.test(wiped.message), wiped.message)
check("and says the vault survived it", /vault/i.test(wiped.message), wiped.message)
eq("nothing to remove is still a success",
  Model.parsePluginDataRemoval(0, "removed").ok, true)
check("and says so plainly",
  /nothing/i.test(Model.parsePluginDataRemoval(0, "removed").message),
  Model.parsePluginDataRemoval(0, "removed").message)
eq("a missing HOME is a failure, not a silent no-op",
  Model.parsePluginDataRemoval(3, "").ok, false)
eq("and so is any other non-zero exit", Model.parsePluginDataRemoval(1, "").ok, false)

check("removing plugin data is confirmed before it happens",
  /pluginDataConfirmPending = true[\s\S]{0,200}?return/.test(panelSrc),
  "the first click wipes stored data with no confirmation")
check("and a cleared keyring is not still believed to hold a password",
  /parsePluginDataRemoval[\s\S]{0,400}?fingerprintStored = false/.test(panelSrc),
  "the panel still thinks a deleted master password is stored")

// A pid is noise on a prompt: it is gone by the time anyone could look it up,
// and it is deliberately not part of what a grant matches on -- so showing it
// implies a scope the approval does not have.
for (const [what, src] of [["the approval prompt", approvalSrc], ["the settings screen", settingsSrc]])
  check(`${what} does not show a pid`, !/\bpid\b/.test(src), `${what} still renders a pid`)
check("the unlock prompt does not either", !/sshUnlockRequest\.pid/.test(panelSrc),
  "the unlock prompt still renders a pid")

check("a development helper is called out wherever the user is",
  /sshAgentHelper\.source === "development"[\s\S]{0,900}?sshAgentDevelopmentHelperWarning\(/.test(panelSrc),
  "nothing warns that an unverified helper is serving keys")
check("the diagnostics say which helper is running and whether it was verified",
  /helperSource: root\.sshAgentHelper\.source[\s\S]{0,200}?helperChecksum: root\.sshAgentHelper\.checksum/.test(panelSrc),
  "sshAgentStatus cannot tell a shipped helper from a local build")
check("a running cooldown can be ended from the panel",
  /function resumeSshSigning\(\)[\s\S]{0,300}?sshAgentCooldownAfter\(root\.sshCooldown, "resumed"/.test(panelSrc),
  "nothing ends the cooldown early, so it cannot be escaped")
check("and the control that does it sits on the banner explaining the outage",
  /sshCooldownStatus\.active[\s\S]{0,1600}?resumeSshSigning\(\)/.test(panelSrc),
  "the resume control is not on the cooldown banner")
check("escape denies rather than silently dismissing",
  /function handleEscape\(\)[\s\S]{0,200}?if \(currentScreen === "sshApproval" \|\| sshUnlockRequest\) \{\s*denySshRequest\(\)/.test(panelSrc),
  "escape does not deny")

// -------------------------------------------------------------------------
// Opt-in centered approval surface
// -------------------------------------------------------------------------

check("the panel reads the centered popup setting",
  /readonly property bool sshAgentApprovalPopup:[^\n]*boolSetting\("sshAgentApprovalPopup"/.test(panelSrc),
  "sshAgentApprovalPopup never reaches Panel.qml")
check("the popup is an overlay layer surface centered independently of the bar",
  /PanelWindow\s*\{/.test(popupSrc)
    && /anchors\s*\{\s*top:\s*true\s*bottom:\s*true\s*left:\s*true\s*right:\s*true/.test(popupSrc)
    && /WlrLayer\.Overlay/.test(popupSrc)
    && /ExclusionMode\.Ignore/.test(popupSrc)
    && /namespace:\s*"qs-bitwarden-ssh-approval"/.test(popupSrc),
  "the popup is not a full-screen, non-exclusive overlay layer surface")
check("the popup follows the panel's monitor",
  /screen:[^\n]*anchorItem\.QsWindow\.window\.screen/.test(popupSrc),
  "the popup has no screen affinity")
check("the popup exists only for opted-in pending SSH work",
  /sshAgentApprovalPopup\s*&&\s*\(panel\.sshPrompt !== null \|\| panel\.sshUnlockRequest !== null\)/.test(popupSrc),
  "the popup is not gated by both the setting and a pending request")
check("popup mode claims the request without opening the panel",
  /function startSshPromptClock\(\)[\s\S]{0,300}?if \(!root\.sshAgentApprovalPopup\) return false[\s\S]{0,80}?return true/.test(panelSrc),
  "startSshPromptClock does not stop at the popup")
check("popup mode leaves the anchored panel closed for unlock requests",
  /message\.type === "unlock_required"[\s\S]{0,900}?if \(startSshPromptClock\(\)\) return[\s\S]{0,200}?root\.open\(\)/.test(panelSrc),
  "unlock_required always opens the panel")
check("changing presentation mode cannot strand a live request off-screen",
  /onSshAgentApprovalPopupChanged:[\s\S]{0,900}?sshPrompt \|\| root\.sshUnlockRequest[\s\S]{0,900}?root\.open\(\)/.test(panelSrc),
  "turning popup mode off during a request leaves no visible approval surface")
check("the popup moves from unlock to approval without changing windows",
  /SshUnlockScreen\s*\{/.test(popupSrc) && /SshApprovalScreen\s*\{/.test(popupSrc),
  "unlock and approval are not hosted by one popup")
check("the popup unlock screen names who is asking and for what",
  /is needed by " \+ request\.processName/.test(sshUnlockOnly)
    && /is asking which SSH keys are available/.test(sshUnlockOnly),
  "the popup does not say what raised it")
check("the popup can submit every configured unlock method",
  /unlockVault\(/.test(unlockSrc)
    && /submitPinUnlock\(/.test(unlockSrc)
    && /startFingerprintUnlock\(/.test(unlockSrc),
  "password, PIN, or fingerprint is missing from the popup")
const fieldsOfferedExpr = (unlockFormSrc.match(/property bool fieldsOffered:([^\n]*)/) || [])[1] || ""
check("unlock fields are offered while locked or still checking, and not once unlocked",
  /status === "locked"/.test(fieldsOfferedExpr)
    && /status === "checking"/.test(fieldsOfferedExpr)
    && !/unlocked/.test(fieldsOfferedExpr)
    && (unlockFormSrc.match(/visible:\s*form\.fieldsOffered/g) || []).length >= 2,
  fieldsOfferedExpr || "fieldsOffered is missing from UnlockForm.qml")
check("the SSH popup offers unlock fields only once the vault is known to be locked",
  /UnlockForm \{[\s\S]{0,600}?fieldsOffered:\s*screen\.vault\.status === "locked"\s*\n/.test(sshUnlockOnly),
  "before bw status answers, a password has no unlock process to reach and a PIN result is dropped")
check("the SSH popup focuses the fields when they appear",
  /UnlockForm \{[\s\S]{0,800}?onFieldsOfferedChanged:\s*if \(fieldsOffered\) screen\.focusDefault\(\)/.test(sshUnlockOnly),
  "a popup open when status resolves leaves the new field unfocused")
check("UnlockForm resets the eye when it hides, whichever screen hides it",
  /onVisibleChanged:\s*\{[\s\S]{0,200}?resetReveal\(\)/.test(unlockFormSrc),
  "visible is effective visibility, so the form's own handler covers an ancestor hiding")

// --- one unlock method at a time --------------------------------------------
//
// The first available of fingerprint, PIN, master password; an unavailable
// method (e.g. PIN cleared after too many attempts) drops out by itself.
check("the offered method is the first one that is actually set up",
  /method:\s*chosen[\s\S]{0,400}?methodAvailable\("fingerprint"\)\s*\?\s*"fingerprint"[\s\S]{0,120}?methodAvailable\("pin"\)\s*\?\s*"pin"\s*:\s*"password"/.test(unlockFormSrc),
  "fingerprint, then PIN, then master password")
check("each method draws on its own, so only one is on screen",
  ['fingerprint', 'pin', 'password']
    .every((name) => new RegExp(`visible: form\\.fieldsOffered && form\\.method === "${name}"`).test(unlockFormSrc)),
  unlockFormSrc)
check("one Unlock Vault button submits whichever typed method is offered",
  /visible: form\.fieldsOffered && form\.method !== "fingerprint"[\s\S]{0,400}?text: form\.busy \?[\s\S]{0,200}?"Unlock Vault"[\s\S]{0,400}?onClicked: form\.submitCurrentMethod\(\)/.test(unlockFormSrc)
    && /function submitCurrentMethod\(\)[\s\S]{0,300}?submitPinUnlock\(\)[\s\S]{0,120}?unlockVault\(\)/.test(unlockFormSrc),
  "the PIN and the master password must be submitted the same way")
check("a failed fingerprint keeps its reason on whichever screen follows",
  /visible: form\.vault\.fingerprintError !== ""/.test(unlockFormSrc)
    && !/fingerprintError[\s\S]{0,120}?form\.method/.test(unlockFormSrc),
  "an unreadable finger is when the user moves to the PIN or password")
check("the fingerprint prompt and glyph belong to the fingerprint screen only",
  /visible: form\.method === "fingerprint" && form\.vault\.fingerprintMessage !== ""/.test(unlockFormSrc)
    && /text: form\.method === "fido" \? "\u{f07f5}" : \(form\.fingerprintBusy \? "\u{f0237}" : "\u{f030b}"\)/u.test(unlockFormSrc)
    && /text: form\.method === "fido"[\s\S]{0,400}?color: Color\.accent/.test(unlockFormSrc),
  "a PIN or password screen has no reader to touch; the header glyph stays accent on every method")
check("the fingerprint button says what the vault is doing once the finger is read",
  /form\.method === "fingerprint"[\s\S]{0,400}?text: form\.vault\.isUnlocking\s*\n?\s*\?\s*"Unlocking\.\.\."[\s\S]{0,200}?fingerprintScanning \? "Waiting for fingerprint\.\.\." : "Unlock with Fingerprint"/.test(unlockFormSrc),
  "a read finger ends the scan and starts the unlock; the button must not re-invite a touch")
check("fingerprint offers no field and no separate submit",
  !/form\.method === "fingerprint"[\s\S]{0,400}?TextField/.test(unlockFormSrc),
  "fingerprint asks for a finger, nothing else")
check("every available method is offered at once, one column each",
  /availableMethods: \["fido", "fingerprint", "pin", "password"\]\s*\.filter\(function\(name\) \{ return methodAvailable\(name\) \}\)/.test(unlockFormSrc)
    && /Repeater \{\s*model: form\.availableMethods/.test(unlockFormSrc)
    && /selected: form\.method === modelData/.test(unlockFormSrc)
    && /onClicked: form\.useMethod\(modelData\)/.test(unlockFormSrc)
    && !/nextMethod/.test(unlockFormSrc),
  "the methods must sit side by side, not behind a cycling button")
check("the row is only drawn when there is a choice",
  /visible: form\.fieldsOffered && form\.availableMethods\.length > 1/.test(unlockFormSrc),
  "one method needs no picker")
check("a method turned off in settings is not offered",
  /if \(name === "fido"\) return form\.vault\.fidoReady/.test(unlockFormSrc)
    && /if \(name === "fingerprint"\) return form\.vault\.fingerprintReady/.test(unlockFormSrc)
    && /if \(name === "pin"\) return form\.vault\.pinReady/.test(unlockFormSrc),
  "availability must follow the ready flags, which include the setting")
check("a rejected PIN keeps its reason after the PIN method is gone",
  /visible: form\.fieldsOffered && form\.method !== "pin" && form\.vault\.pinUnlockError !== ""/.test(unlockFormSrc)
    && !/form\.vault\.pinError/.test(unlockFormSrc),
  "an exhausted PIN clears itself, so the reason has to outlive it -- but a setup-form error is not that reason")
check("a hand-picked method lasts only as long as the screen",
  /onVisibleChanged:\s*\{[\s\S]{0,500}?if \(!form\.vault\.pinentryActive\) form\.chosen = ""/.test(unlockFormSrc),
  "a reopened lock screen starts at the leading method again; hiding for pinentry is not a close")
check("dismissing the popup re-points every view's secret fields at the vault",
  /function clearSshPopupUnlockState\(\)[\s\S]{0,900}?syncLoginFieldsToState\(\)/.test(panelSrc),
  "the popup clears masterPassword and pinEntry; the fields must follow them")
check("popup unlock buttons opt into focus; the panel lock screen does not",
  /property bool buttonsFocusable:\s*false/.test(unlockFormSrc)
    && /focusable:\s*form\.buttonsFocusable/.test(unlockFormSrc)
    && /buttonsFocusable:\s*true/.test(sshUnlockOnly)
    && !/UnlockForm \{[\s\S]{0,120}buttonsFocusable:\s*true/.test(
      panelSrc.slice(panelSrc.indexOf("id: unlockForm"), panelSrc.indexOf("id: unlockForm") + 200)
    ),
  "sharing the form must not Tab-focus fingerprint/Unlock on the bar lock screen")
check("background click and Escape explicitly deny the pending request",
  /MouseArea[\s\S]{0,500}?onClicked:\s*popup\.panel\.denySshRequest\(\)/.test(popupSrc)
    && /Qt\.Key_Escape[\s\S]{0,160}?denySshRequest\(\)/.test(popupSrc),
  "the modal can disappear without answering the helper")
check("approval defaults keyboard focus to Deny",
  /id:\s*denyButton/.test(approvalSrc)
    && /function focusDefault\(\)[\s\S]{0,120}?denyButton\.forceActiveFocus\(\)/.test(approvalSrc),
  "an approval can receive accidental affirmative focus")
check("hidden panel fields cannot steal focus from the popup",
  /function focusAppropriateField\(\)[\s\S]{0,120}?if \(sshApprovalPopupOpen\) return/.test(panelSrc),
  "status and unlock handlers can focus an input in the closed panel")
check("approval actions opt into keyboard focus",
  (approvalSrc.match(/focusable:\s*true/g) || []).length >= 2,
  "approval buttons cannot be reached by Tab")
check("popup unlock is accepted while the anchored panel is closed",
  /readonly property bool sshAuthSurfaceActive:\s*opened \|\| sshApprovalPopupOpen/.test(panelSrc)
    && /function prepareUnlock\(\)[\s\S]{0,180}?!sshAuthSurfaceActive/.test(panelSrc),
  "unlock handlers still require root.opened")
check("closing the transient popup clears authentication state",
  /function clearSshPopupUnlockState\(\)[\s\S]{0,700}?masterPassword = ""/.test(panelSrc)
    && /function dismissSshApproval\(\)[\s\S]{0,900}?clearSshPopupUnlockState\(\)/.test(panelSrc),
  "password/PIN state can survive a dismissed popup")

// -------------------------------------------------------------------------
// Concurrent request queueing
// -------------------------------------------------------------------------

let q = []
q = Model.sshAgentEnqueuePrompt(q, { requestId: 1, keyName: "key1" }, 4)
q = Model.sshAgentEnqueuePrompt(q, { requestId: 2, keyName: "key2" }, 4)
eq("enqueues second item", q.length, 2)
q = Model.sshAgentEnqueuePrompt(q, { requestId: 2, keyName: "key2" }, 4)
eq("ignores duplicate requestId", q.length, 2)
q = Model.sshAgentEnqueuePrompt(q, { requestId: 3 }, 4)
q = Model.sshAgentEnqueuePrompt(q, { requestId: 4 }, 4)
q = Model.sshAgentEnqueuePrompt(q, { requestId: 5 }, 4)
eq("respects queue capacity cap", q.length, 4)

eq("pending count includes active and queued", Model.sshAgentPendingCount({ requestId: 0 }, q), 5)
eq("pending count with no active", Model.sshAgentPendingCount(null, q), 4)

let deq = Model.sshAgentDequeuePrompt(q)
eq("dequeues first item", deq.next.requestId, 1)
eq("remaining queue length is decremented", deq.remaining.length, 3)

let emptyDeq = Model.sshAgentDequeuePrompt([])
eq("empty dequeue next is null", emptyDeq.next, null)

let removed = Model.sshAgentRemovePrompt(q, 3)
eq("removes targeted requestId", removed.length, 3)
eq("requestId 3 is absent", removed.some(x => x.requestId === 3), false)

check("multiple concurrent approval requests are queued",
  /root\.sshPromptQueue = Model\.sshAgentEnqueuePrompt\(root\.sshPromptQueue, message, 4\)/.test(panelSrc),
  "concurrent approvals are not queued")
check("multiple concurrent unlock requests are queued",
  /root\.sshUnlockQueue = Model\.sshAgentEnqueuePrompt\(root\.sshUnlockQueue, message, 4\)/.test(panelSrc),
  "concurrent unlocks are not queued")
check("advancing an approval dequeues the next prompt",
  /function advanceSshPrompt\(\)[\s\S]{0,400}?Model\.sshAgentDequeuePrompt\(root\.sshPromptQueue\)/.test(panelSrc),
  "advanceSshPrompt does not dequeue from sshPromptQueue")
check("advancing an unlock dequeues the next unlock request",
  /function advanceSshUnlock\(\)[\s\S]{0,400}?Model\.sshAgentDequeuePrompt\(root\.sshUnlockQueue\)/.test(panelSrc),
  "advanceSshUnlock does not dequeue from sshUnlockQueue")
check("deny all rejects active and queued requests",
  /function denyAllSshRequests\(\)[\s\S]{0,900}?sshPromptQueue[\s\S]{0,600}?sshUnlockQueue[\s\S]{0,600}?dismissSshApproval\(\)/.test(panelSrc),
  "denyAllSshRequests is missing or does not clear queues")
check("approval screen displays 1 of N when multiple requests are queued",
  /text:\s*"1 of "\s*\+\s*panel\.sshPendingCount/.test(approvalSrc),
  "approval screen does not display queue counter")
// The helper answers queued requests a new grant covers and withdraws their
// prompts as "granted": answered, so it must never count toward the cooldown.
check("a prompt withdrawn because a grant answered it costs no cooldown",
  /message\.reason === "granted"\) \{\s*\/\/[^\n]*\n\s*\} else if \(message\.reason === "released"\)/.test(panelSrc)
    && /\} else \{\s*root\.sshCooldown = Model\.sshAgentCooldownAfter\(root\.sshCooldown, "timeout"/.test(panelSrc),
  "a granted withdrawal would be counted as an unanswered prompt")
// Every decision sits in one row of tiles; Deny stays first and focused.
check("the approval decisions share one row, Deny first",
  /Row \{\s*id: decisionRow[\s\S]*?ChoiceTile \{\s*id: denyButton[\s\S]*?label: "Deny all[\s\S]*?label: "Approve once"[\s\S]*?grantShortLabel/.test(approvalSrc)
    && !/^\s*Button \{/m.test(approvalSrc), "")
check("approval screen provides a Deny all button when multiple requests exist",
  /label:\s*"Deny all \("\s*\+\s*panel\.sshPendingCount\s*\+\s*"\)"/.test(approvalSrc)
    && /onClicked: panel\.denyAllSshRequests\(\)/.test(approvalSrc),
  "approval screen is missing Deny all button")
check("popup accepts Shift+Escape to deny all requests",
  /event\.modifiers\s*&\s*Qt\.ShiftModifier[\s\S]{0,120}?popup\.panel\.denyAllSshRequests\(\)/.test(popupSrc),
  "popup does not handle Shift+Escape for deny all")

done()
