#!/usr/bin/env node
// Transient status and error messages float over the panel instead of joining
// its content column. Their arrival must never change the height used by
// KeyboardPanel, which is what made every screen jump down and back up.
//
//   node tests/status-notice.test.js

const fs = require("fs")
const path = require("path")

const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const noticeSrc = fs.existsSync(path.join(__dirname, "..", "StatusNotice.qml"))
  ? fs.readFileSync(path.join(__dirname, "..", "StatusNotice.qml"), "utf8")
  : ""
let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

const noticeAt = panelSrc.indexOf("id: statusNotice")
const noticeUse = noticeAt === -1 ? "" : panelSrc.slice(noticeAt, noticeAt + 2000)

check("the status notice is a sibling overlay rather than a mainColumn child",
  /^      StatusNotice \{\n        id: statusNotice/m.test(panelSrc),
  "expected statusNotice at PanelKeyCatcher child indentation")
check("the overlay is pinned inside the bottom of the panel",
  /anchors\.bottom:\s*parent\.bottom/.test(noticeSrc)
    && /anchors\.horizontalCenter:\s*parent\.horizontalCenter/.test(noticeSrc)
    && /z:\s*[1-9][0-9]*/.test(noticeSrc),
  noticeSrc)
check("the overlay never participates in panel height measurement",
  /contentHeight:\s*panel\.fittedContentHeight\(mainColumn\.implicitHeight/.test(panelSrc)
    && !/implicitHeight:\s*statusNotice/.test(panelSrc),
  "KeyboardPanel must continue to measure only mainColumn")

check("errors take priority over transient status text",
  /showsError:\s*root\.errorMessage\s*!==\s*""/.test(noticeSrc)
    && /text:\s*root\.showsError\s*\?\s*root\.errorMessage\s*:\s*root\.statusMessage/.test(noticeSrc),
  noticeSrc)
check("status text still yields to the sequential TOTP action",
  /showsStatus:[^\n]*root\.statusMessage\s*!==\s*""[^\n]*!root\.statusSuppressed/.test(noticeSrc)
    && /statusSuppressed:\s*root\.totpFollowupActive/.test(noticeUse),
  noticeSrc + "\n" + noticeUse)
check("long messages wrap within the panel",
  /wrapMode:\s*Text\.Wrap/.test(noticeSrc), noticeSrc)
check("errors can be dismissed without hiding ordinary status updates",
  /visible:\s*root\.showsError/.test(noticeSrc)
    && /onClicked:\s*root\.errorDismissed\(\)/.test(noticeSrc)
    && /onErrorDismissed:[\s\S]{0,400}root\.errorMessage = ""/.test(noticeUse),
  noticeSrc + "\n" + noticeUse)

// An error the user can act on carries the action. A refused save is the case:
// the list is already back to what the vault holds, so the button is the way
// back to what was typed.
check("an error can offer a recovery alongside the dismiss",
  /property string actionLabel: ""/.test(noticeSrc)
    && /signal actionRequested\(\)/.test(noticeSrc)
    && /visible: root\.showsError && root\.actionLabel !== ""/.test(noticeSrc),
  noticeSrc)
check("the recovery is offered only when there is one",
  /actionLabel: root\.failedSave \? "Reopen " \+ root\.failedSave\.name : ""/.test(noticeUse),
  noticeUse)
check("dismissing the message discards the recovery with it",
  /root\.failedSave = null\s*\n\s*root\.errorMessage = ""/.test(noticeUse),
  "a Reopen button behind an invisible message is a button for nothing")
check("dynamic notices expose alert semantics to assistive technology",
  /Accessible\.role:\s*Accessible\.AlertMessage/.test(noticeSrc)
    && /Accessible\.ignored:\s*!root\.shown/.test(noticeSrc)
    && /Accessible\.name:/.test(noticeSrc),
  noticeSrc)

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
