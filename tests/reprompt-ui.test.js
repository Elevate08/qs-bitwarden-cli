#!/usr/bin/env node
// Bitwarden's master password re-prompt, on the view's side: every action the
// panel takes that shows, copies or edits a protected secret goes through the
// vault's withReprompt(), flagged items say so with a lock, and the question
// itself (RepromptConfirm.qml) is masked, submits on Enter and cancels on
// Escape. The vault side (the check itself) is the service's.
//
//   node tests/reprompt-ui.test.js

const { createSuite, read, readView, functionBody } = require("./harness")

const { check, done } = createSuite("reprompt-ui")

const view = readView()
const confirm = read("RepromptConfirm.qml")

// Comments and strings out, so a mention in prose cannot pass or fail a check.
const code = src => src
  .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
  .replace(/\/\/[^\n]*/g, "")
const viewCode = code(view)

// --- the one way through ------------------------------------------------------

check("protected actions go to the vault's withReprompt()",
  /function protect\(item, action\) \{\s*root\.vault\.withReprompt\(item, action\)\s*\}/.test(view),
  functionBody(view, "protect"))

// Calls that act on a secret, and where each may appear. Everything else
// reaching them would bypass the question.
const allowed = {
  "copyToClipboard": ["copyDetailSecret"],
  "toggleFieldReveal": ["toggleProtectedReveal"],
  "startEditItem": ["editDetailItem"],
  "handleSmartEnter": ["smartEnter"],
}
for (const [call, owners] of Object.entries(allowed)) {
  const outside = viewCode.split(new RegExp(`(?=function (?:${owners.join("|")})\\()`))
    .map((part, i) => i === 0 ? part : part.slice(functionBody(part, owners.find(o => part.startsWith(`function ${o}(`))).length))
    .join("")
  const stray = [...outside.matchAll(new RegExp(`root\\.vault\\.${call}\\(([^\\n]*)`, "g"))].map(m => m[1])
  // Copying a username, an address or a plain custom field asks nothing.
  const secret = stray.filter(args => call !== "copyToClipboard"
    || !/^(?:root\.vault\.detailItem \? root\.vault\.detailItem\.username|root\.vault\.detailItem\.username|root\.vault\.detailIdentity\.(?:email|username)|root\.vault\.detailIdentity \? root\.vault\.detailIdentity\.(?:username|company|email|phone)|root\.vault\.detailIdentityName|root\.vault\.detailIdentityAddress|root\.vault\.detailCard \? root\.vault\.detailCard\.(?:cardholderName|brand)|root\.vault\.detailCardExpiry|value, name\)|\"\"|"")/.test(args.trim()))
  check(`${call}() on a secret is reached only through ${owners.join(", ")}`,
    secret.length === 0, secret.join("\n    "))
}

check("the TOTP copies on the list and in the follow-up banner ask first",
  !/root\.vault\.copyTotpCode\((?:itemData|root\.vault\.totpFollowupItem)\)(?![^\n]*\})/.test(view)
    && /root\.protect\(itemData, function\(\) \{ root\.vault\.copyTotpCode\(itemData\) \}\)/.test(view)
    && /root\.protect\(item, function\(\) \{ root\.vault\.copyTotpCode\(item\) \}\)/.test(view),
  "a TOTP copy bypasses the re-prompt")
check("attachments are saved only after asking",
  !/onClicked: root\.vault\.(?:saveAllAttachments|queueAttachment)\(/.test(view)
    && /root\.protect\(root\.vault\.detailItem, function\(\) \{ root\.vault\.saveAllAttachments\(\) \}\)/.test(view)
    && /root\.protect\(root\.vault\.detailItem, function\(\) \{ root\.vault\.queueAttachment\(attachment\) \}\)/.test(view),
  "an attachment of a flagged item is written to disk without the question")
check("Enter on the list and in the search box copies through smartEnter()",
  /root\.smartEnter\(root\.vault\.getSelectedItem\(\)\)/.test(view)
    && (view.match(/root\.smartEnter\(/g) || []).length >= 3,
  "Enter still copies a password without the question")
check("smartEnter() asks only when Enter would copy a password",
  /function smartEnter\(item\)[\s\S]{0,300}?isLoginItem\(item\)[\s\S]{0,200}?root\.protect\(item, function\(\) \{ root\.vault\.handleSmartEnter\(item\) \}\)[\s\S]{0,80}?else \{\s*root\.vault\.handleSmartEnter\(item\)/.test(view),
  functionBody(view, "smartEnter"))
check("the detail keys copy, reveal and edit through the protected helpers",
  /lower === "y" \|\| lower === "p"\) \{\s*root\.copyPrimarySecret\(\)/.test(view)
    && /lower === "m"\) \{\s*if \(root\.vault\.liveTotp\) root\.copyDetailSecret\(/.test(view)
    && /lower === "e"\) \{\s*root\.editDetailItem\(\)/.test(view)
    && /lower === "v"\) \{[^\n]*\n[^\n]*root\.toggleProtectedReveal\(root\.vault\.primaryRevealKey\)/.test(view),
  "a detail shortcut bypasses the re-prompt")

// --- what a flagged item shows ------------------------------------------------

check("a flagged row carries a lock",
  /visible: root\.asksMasterPassword\(itemData\)\s*text: "\\u\{F033E\}"/.test(view),
  "no lock glyph on re-prompt rows")
check("and so does its detail header",
  /visible: root\.asksMasterPassword\(root\.vault\.detailItem\)\s*text: "\\u\{F033E\}"/.test(view),
  "no lock glyph on a re-prompt item's detail")
check("the flag is Bitwarden's reprompt value 1",
  /function asksMasterPassword\(item\) \{\s*return !!item && Number\(item\.reprompt\) === 1/.test(view),
  functionBody(view, "asksMasterPassword"))
check("a flagged item's TOTP code and notes stay hidden until revealed",
  /asksMasterPassword\(root\.vault\.detailItem\) && !root\.vault\.isFieldRevealed\("totp"\)/.test(view)
    && /asksMasterPassword\(root\.vault\.detailItem\) && !root\.vault\.isFieldRevealed\("notes"\)/.test(view)
    && /root\.toggleProtectedReveal\("totp"\)/.test(view) && /root\.toggleProtectedReveal\("notes"\)/.test(view),
  "a flagged item's code or notes are drawn in the clear")

// --- the question -------------------------------------------------------------

check("the question shows while the vault holds an action",
  /readonly property bool shown: vault\.repromptPending === true/.test(confirm)
    && /visible: shown/.test(confirm), "")
check("its field is masked and kept from input methods",
  /password: true/.test(confirm)
    && /inputMethodHints: Qt\.ImhSensitiveData \| Qt\.ImhNoPredictiveText/.test(confirm), "")
check("Enter submits the typed password and the field is emptied",
  /onAccepted: confirm\.submit\(\)/.test(confirm)
    && /function submit\(\)[\s\S]{0,200}?passwordField\.text = ""[\s\S]{0,80}?vault\.submitReprompt\(typed\)/.test(confirm), "")
check("Escape cancels in the field itself, before the panel would leave the screen",
  /Keys\.onEscapePressed: function\(event\) \{\s*event\.accepted = true\s*confirm\.cancel\(\)/.test(confirm)
    && /function cancel\(\)[\s\S]{0,80}?vault\.cancelReprompt\(\)/.test(confirm), "")
check("nothing underneath can be clicked while it asks",
  /MouseArea \{\s*anchors\.fill: parent\s*acceptedButtons: Qt\.AllButtons/.test(confirm), "")
check("the panel draws it and holds its own key dispatch meanwhile",
  /RepromptConfirm \{\s*id: repromptConfirm/.test(view)
    && /blocked: repromptConfirm\.shown/.test(view)
    && /if \(repromptConfirm\.shown\) \{\s*if \(event\.key === Qt\.Key_Escape\) \{\s*repromptConfirm\.cancel\(\)/.test(view),
  "typing the master password would run panel shortcuts")

done()
