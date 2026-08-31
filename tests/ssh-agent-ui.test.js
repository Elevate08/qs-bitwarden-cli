#!/usr/bin/env node
// The approval prompt is the one place a user is asked to authorise a
// signature, so what it shows has to be accurate about what the companion
// actually verified -- and what it did not. These tests cover the prompt's
// presentation, the deny/approve/grant control lines, the denial cooldown
// that stops a same-UID process reopening the panel forever, and the rule
// that no prompt is ever raised over a locked screen.
//
//   node tests/ssh-agent-ui.test.js

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseAgentEvent = parseAgentEvent
  exports.sshAgentApproveLine = sshAgentApproveLine
  exports.sshAgentDenyLine = sshAgentDenyLine
  exports.sshAgentUnlockCancelledLine = sshAgentUnlockCancelledLine
  exports.sshAgentRevokeGrantLine = sshAgentRevokeGrantLine
  exports.sshAgentRevokeGrantsLine = sshAgentRevokeGrantsLine
  exports.sshAgentPromptView = sshAgentPromptView
  exports.sshAgentGrantViews = sshAgentGrantViews
  exports.sshAgentGrantsAt = sshAgentGrantsAt
  exports.sshAgentDevelopmentHelperWarning = sshAgentDevelopmentHelperWarning
  exports.sshAgentShouldPrompt = sshAgentShouldPrompt
  exports.sshAgentCooldownInitial = sshAgentCooldownInitial
  exports.sshAgentCooldownAfter = sshAgentCooldownAfter
  exports.sshAgentCooldownActive = sshAgentCooldownActive
  exports.sshAgentCooldownStatus = sshAgentCooldownStatus
  exports.sshAgentLoadingNote = sshAgentLoadingNote
  exports.sshAgentOptionsLine = sshAgentOptionsLine
  exports.sshAgentRequestDeadlineMs = sshAgentRequestDeadlineMs
  exports.plainLabel = plainLabel
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

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
  eq(`${type} parses`, parsed.ok, true)
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
eq("and its default off state is sent too", Model.sshAgentOptionsLine(false),
  JSON.stringify({ v: 1, type: "options", unlockOnDemand: false }) + "\n")
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
// A grant covers one program, not one process (docs/decisions/0002-grant-scope.md).
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

// A vault item's name is attacker-controllable by whoever shares the
// collection it came from, and the process path comes from outside too.
const hostile = Model.sshAgentPromptView(Object.assign({}, request, {
  keyName: "<img src=x onerror=alert(1)>",
  processPath: "/usr/bin/<b>ssh</b>"
}), 120)
check("a markup key name cannot reach a rich-text control",
  Model.plainLabel(hostile.keyName).indexOf("<img") < 0, Model.plainLabel(hostile.keyName))
check("a hostile name is not silently dropped",
  hostile.keyName.length > 0, hostile.keyName)

const huge = Model.sshAgentPromptView(Object.assign({}, request, {
  keyName: "n".repeat(5000), processPath: "/" + "p".repeat(5000)
}), 120)
check("an absurd key name is bounded", huge.keyName.length <= 256, String(huge.keyName.length))
check("an absurd path is bounded", huge.processPath.length <= 512, String(huge.processPath.length))

// The panel's countdown has to agree with the companion's deadline, or it
// counts down to a moment nothing happens at. See
// docs/decisions/0003-request-deadline.md for the figure.
eq("the request deadline matches the companion's", Model.sshAgentRequestDeadlineMs(), 120000)
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
check("no grant view carries key material",
  grants.every(g => JSON.stringify(g).indexOf("PRIVATE") < 0), "leaked")
eq("a malformed grant list yields nothing", Model.sshAgentGrantViews(null).length, 0)

// A grant is announced once and then nothing is said until it changes, so the
// remaining time has to be re-derived rather than remembered. Without this the
// settings screen showed "1m 59s left" for the whole two minutes and then the
// row disappeared, having never counted down.
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

// A development helper is a state you can sit in for days without noticing,
// signing with a binary that has no recorded digest and no provenance. The
// warning has to say why that matters, and distinguish a shipped helper that
// was rejected from one that was simply never there.
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

// A timeout is a denial for this purpose: the user saw it and did nothing.
let timedOut = Model.sshAgentCooldownInitial()
timedOut = Model.sshAgentCooldownAfter(timedOut, "timeout", 0)
timedOut = Model.sshAgentCooldownAfter(timedOut, "timeout", 100)
eq("two timeouts also start a cooldown", Model.sshAgentCooldownActive(timedOut, 100), true)

// Approving clears the history: the user is engaging, not being pestered.
let mixed = Model.sshAgentCooldownInitial()
mixed = Model.sshAgentCooldownAfter(mixed, "denied", 0)
mixed = Model.sshAgentCooldownAfter(mixed, "approved", 100)
mixed = Model.sshAgentCooldownAfter(mixed, "denied", 200)
eq("an approval resets the denial run", Model.sshAgentCooldownActive(mixed, 200), false)

// An approval cannot end a cooldown that is already running -- the cooldown is
// precisely what stops the prompt an approval would answer. Only an explicit
// resume ends it early; otherwise a user who dismissed two prompts waits out
// the full five minutes with nothing they can do about it.
let stuck = Model.sshAgentCooldownInitial()
stuck = Model.sshAgentCooldownAfter(stuck, "denied", 0)
stuck = Model.sshAgentCooldownAfter(stuck, "denied", 100)
eq("two denials leave a cooldown running", Model.sshAgentCooldownActive(stuck, 100), true)
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
eq("and the cooldown lapses on its own",
  Model.sshAgentCooldownActive(unattended, 100 + 5 * 60 * 1000), false)

// A cooldown that fails signatures silently is worse than the pestering it
// prevents: SSH just stops working for five minutes with no explanation
// anywhere. It has to say so, and say when it lifts.
let cooled = Model.sshAgentCooldownInitial()
const quiet = Model.sshAgentCooldownStatus(cooled, 0)
eq("nothing is reported while no cooldown is running", quiet.active, false)
eq("a quiet cooldown has no message", quiet.message, "")

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
check("the status never names a key or a process",
  cooling.message.indexOf("ssh-") < 0 && cooling.message.indexOf("/usr/") < 0, cooling.message)

// Unlocking runs one `bw list items`, which takes seconds on a real vault.
// The request that triggered the unlock is held across it, so without a
// loading state the user unlocks and then watches nothing happen.
const waiting = Model.sshAgentPromptView(Object.assign({}, request, { type: "unlock_required" }), 120)
check("a held request can say it is still loading",
  typeof Model.sshAgentLoadingNote === "function", "no loading note is available")
if (typeof Model.sshAgentLoadingNote === "function") {
  const note = Model.sshAgentLoadingNote()
  check("the loading note says keys are on the way", /load/i.test(note), note)
  check("the loading note does not promise it is instant",
    !/instant|immediat/i.test(note), note)
}

// -------------------------------------------------------------------------
// The panel wiring
// -------------------------------------------------------------------------

// Every file the SSH markup lives in: the settings sections and the approval
// screen have their own, and Panel.qml keeps the rest. Reading only the first
// would leave every "this must NOT appear" check below passing on content that
// had simply moved.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml"]
  .map(file => fs.readFileSync(path.join(repoRoot, file), "utf8"))
  .join("\n")

// plainLabel() wraps its argument in a span when the text contains markup
// characters, which a PlainText control then renders literally. The field is
// matched with whatever object it hangs off, because the settings sections
// reach the panel as `panel` and the screens as `root`: pinning the prefix
// would let these checks pass on content that had only moved between files.
for (const field of [
  "sshAgentVersion",
  "modelData.keyName",
  "modelData.processName",
  "sshUnlockRequest.keyName",
  "sshUnlockRequest.processName",
  "sshPrompt.keyName",
  "sshPrompt.processName",
  "sshPrompt.processPath",
  "sshRouting.owner"
]) {
  const wrapped = new RegExp(
    "plainLabel\\(\\s*(?:root|panel|section\\.panel)?\\.?"
      + field.replace(/\./g, "\\.") + "\\s*\\)")
  check("SSH PlainText labels do not receive rich-text wrappers for " + field,
    !wrapped.test(panelSrc), field)
}

check("there is a dedicated approval screen",
  /currentScreen === "sshApproval"/.test(panelSrc), "no sshApproval screen")
check("an approval_required message raises the prompt",
  /message\.type === "approval_required"[\s\S]{0,600}?showSshApproval\(message\)/.test(panelSrc),
  "approval_required never raises the prompt")
// Opening the panel sends an unlocked one to the item list, so a prompt that
// claimed the screen first would be silently undone -- live state, blank
// screen. Both halves of that ordering are pinned here because the failure is
// invisible: everything reports healthy while nothing is drawn.
check("the panel is opened before the approval screen is claimed",
  /function showSshApproval\(message\)[\s\S]{0,900}?root\.open\(\)[\s\S]{0,200}?currentScreen = "sshApproval"/.test(panelSrc),
  "the screen is claimed before opening, so opening resets it")
// Pinned on the ordering rather than on a character distance: what matters is
// that a live prompt claims the screen and returns before the branch that
// would send an unlocked panel to the item list, not how much housekeeping
// happens above it.
const openedBody = panelSrc.slice(panelSrc.indexOf("function onPanelOpened()"),
  panelSrc.indexOf("function onPanelClosed") > 0
    ? panelSrc.indexOf("function onPanelClosed")
    : panelSrc.indexOf("function onPanelOpened()") + 2000)
check("opening the panel does not discard a live request",
  /if \(sshPrompt\)[\s\S]{0,160}?currentScreen = "sshApproval"[\s\S]{0,40}?return/.test(openedBody)
    && openedBody.indexOf("sshPrompt") < openedBody.indexOf('status === "unlocked"'),
  "onPanelOpened resets away from a live prompt")
check("a withdrawn prompt counts toward the cooldown",
  /message\.reason !== "released"[\s\S]{0,200}?sshAgentCooldownAfter\(root\.sshCooldown, "timeout"/.test(panelSrc),
  "an unanswered prompt never feeds the cooldown")

// The panel resets currentScreen in several of its own flows -- opening the
// panel, finishing an unlock -- each of which silently dropped a live prompt
// before. Screen visibility binds to activeScreen, which a live request wins,
// so no later assignment can hide a question a client is blocked on.
check("a live prompt outranks navigation state",
  /readonly property string activeScreen: sshPrompt !== null \? "sshApproval" : currentScreen/.test(panelSrc),
  "no activeScreen; a stray currentScreen assignment can hide the prompt")
check("no screen visibility still binds to currentScreen directly",
  panelSrc.split("\n").filter(l => l.trim().startsWith("visible:") && l.includes("root.currentScreen")).length === 0,
  panelSrc.split("\n").filter(l => l.trim().startsWith("visible:") && l.includes("root.currentScreen")).join(" | "))

check("raising the prompt switches to the approval screen",
  /function showSshApproval\(message\)[\s\S]{0,1200}?currentScreen = "sshApproval"/.test(panelSrc),
  "the prompt never opens the approval screen")
check("a request that cannot prompt is denied rather than left hanging",
  /message\.type === "approval_required"[\s\S]{0,400}?sshAgentMayPrompt\(\)[\s\S]{0,200}?sshAgentDenyLine/.test(panelSrc),
  "a suppressed request is not answered")
// A prompt that opened the panel on the user's behalf should hand the desktop
// back when it is answered -- approved or denied alike. A panel the user had
// already opened is theirs, so answering returns them to the screen they were
// on rather than closing it under them.
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
  /message\.type === "request_cancelled"[\s\S]{0,900}?dismissSshApproval\(\)/.test(panelSrc),
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

check("the held request stays on screen while keys load",
  /sshAgentLoadingNote\(\)/.test(panelSrc), "nothing tells the user keys are loading")
check("the loading state is driven by the load actually being in flight",
  /sshUnlockRequest[\s\S]{0,600}?sshAgentLoadActive|sshAgentLoadActive[\s\S]{0,600}?sshUnlockRequest/.test(panelSrc),
  "the loading state is not tied to a real load")

check("the setting reaches the companion on handshake and on change",
  /onSshAgentUnlockOnDemandChanged: sendSshAgentOptions\(\)/.test(panelSrc)
    && /if \(sshAgentGateOpen\) sendSshAgentOptions\(\)/.test(panelSrc),
  "unlock-on-demand never reaches the companion")
check("an identity listing is not promoted into an approval",
  /reason === "list-identities"/.test(panelSrc),
  "a listing would be turned into a signature approval")

check("an unlock request is shown with its context",
  /message\.type === "unlock_required"/.test(panelSrc), "unlock_required is ignored")
check("grants are tracked from the companion",
  /message\.type === "grants_changed"/.test(panelSrc), "grants_changed is ignored")

check("denying is wired to the deny line",
  /sshAgentDenyLine\(/.test(panelSrc), "nothing sends deny")
check("approving once is wired",
  /sshAgentApproveLine\(/.test(panelSrc), "nothing sends approve")
check("grants can be revoked individually and together",
  /sshAgentRevokeGrantLine\(/.test(panelSrc) && /sshAgentRevokeGrantsLine\(/.test(panelSrc),
  "grant revocation is not wired")

check("a locked screen suppresses the prompt",
  /sshAgentShouldPrompt\(/.test(panelSrc), "the screen-lock rule is not applied")
check("the cooldown is surfaced in the panel rather than failing silently",
  /sshAgentCooldownStatus\(/.test(panelSrc), "the cooldown is never shown to the user")
check("entering the cooldown is announced once, not on every refusal",
  /sshCooldownAnnounced/.test(panelSrc), "nothing announces the cooldown")

check("a request the cooldown refuses does not feed the cooldown",
  /!sshAgentMayPrompt\(\)\)\s*\{\s*sshAgentWrite\(Model\.sshAgentDenyLine\(message\.requestId\)\)\s*return/.test(panelSrc),
  "a suppressed request records an outcome, so a busy process can hold the cooldown open")
check("a development helper is called out wherever the user is",
  /sshAgentHelper\.source === "development"[\s\S]{0,900}?sshAgentDevelopmentHelperWarning\(/.test(panelSrc),
  "nothing warns that an unverified helper is serving keys")
check("the diagnostics say which helper is running and whether it was verified",
  /helperSource: root\.sshAgentHelper\.source[\s\S]{0,200}?helperChecksum: root\.sshAgentHelper\.checksum/.test(panelSrc),
  "sshAgentStatus cannot tell a shipped helper from a local build")
check("and why inspection rejected one, which errorCode never carries",
  /helperState: root\.sshAgentHelper\.state/.test(panelSrc),
  "sshAgentStatus reports an error state without naming it")
check("a running cooldown can be ended from the panel",
  /function resumeSshSigning\(\)[\s\S]{0,300}?sshAgentCooldownAfter\(root\.sshCooldown, "resumed"/.test(panelSrc),
  "nothing ends the cooldown early, so it cannot be escaped")
check("and the control that does it sits on the banner explaining the outage",
  /sshCooldownStatus\.active[\s\S]{0,1600}?resumeSshSigning\(\)/.test(panelSrc),
  "the resume control is not on the cooldown banner")
check("repeated denials enter the cooldown",
  /sshAgentCooldownAfter\(/.test(panelSrc) && /sshAgentCooldownActive\(/.test(panelSrc),
  "the cooldown is not applied")
check("escape denies rather than silently dismissing",
  /sshApproval[\s\S]{0,900}?denySshRequest\(/.test(panelSrc), "escape does not deny")
check("the key name is rendered literally by a PlainText control",
  /Text\s*\{[\s\S]{0,180}?textFormat:\s*Text\.PlainText[\s\S]{0,180}?(?:root|panel)\.sshPrompt\.keyName(?![A-Za-z0-9_])/
    .test(panelSrc),
  "the key name is not pinned to plain text")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`ssh-agent-ui: ${pass} passed`)
