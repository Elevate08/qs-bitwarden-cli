#!/usr/bin/env node
// Wheel scrolling across the panel.
//
// Qt moves a Flickable by the platform's wheel-scroll-lines, a figure tuned for
// a full-screen document. In a panel a few hundred pixels tall that is a crawl,
// so the rate is set here instead -- and set in one place, because two views
// scrolling at different speeds is worse than both being slow.
//
//   node tests/scrolling.test.js

const fs = require("fs")
const path = require("path")

const read = f => fs.existsSync(path.join(__dirname, "..", f))
  ? fs.readFileSync(path.join(__dirname, "..", f), "utf8") : ""

const panelSrc = read("Panel.qml")
const wheelSrc = read("WheelScroll.qml")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

check("WheelScroll exists", wheelSrc !== "", "WheelScroll.qml is missing")

// --- the component ------------------------------------------------------------

check("it is one component rather than a handler pasted into every view",
  /required property Flickable view/.test(wheelSrc) && /property real step/.test(wheelSrc),
  "expected a reusable component taking the view it drives")

check("it accepts the event so the slower built-in handling does not also run",
  /event\.accepted = true/.test(wheelSrc),
  "an unaccepted wheel event would be handled twice, at two different rates")

check("it cannot scroll past either end",
  /Math\.max\(0, Math\.min\(limit, next\)\)/.test(wheelSrc),
  "expected the new position to be clamped to the content")

check("the limit accounts for the visible height, not just the content",
  /contentHeight - root\.view\.height/.test(wheelSrc),
  "scrolling would run past the bottom by one screen")

check("a wheel event carrying no vertical movement changes nothing",
  /if \(notches === 0\) return/.test(wheelSrc),
  "a horizontal wheel or a stray event must not move the view")

// --- every view uses it --------------------------------------------------------

// Each scrolling view in the panel. The list is spelled out so a view added
// later without tuned scrolling shows up as a failure rather than as an
// inconsistency somebody notices months later.
const scrollViews = [
  "sendFlick", "fpFlick", "genFlick", "pinFlick", "setupFlick", "settingsFlick",
  "itemsListView", "filterOptionsList", "detailFlickable", "editFlickable",
  "folderPickList", "orgPickList", "collectionList",
]

for (const view of scrollViews) {
  check(`${view} scrolls at the panel's rate`,
    new RegExp(`WheelScroll \\{ view: ${view} \\}`).test(panelSrc),
    `${view} still scrolls at the platform default`)
}

check("every scrolling view is accounted for",
  (panelSrc.match(/WheelScroll \{/g) || []).length === scrollViews.length,
  `${(panelSrc.match(/WheelScroll \{/g) || []).length} handlers for ${scrollViews.length} views`)

check("and every one of them has a scrollbar, so the list is the same list",
  (panelSrc.match(/ScrollBar\.vertical:/g) || []).length === scrollViews.length,
  "a view with a scrollbar but no wheel tuning would scroll at a different rate")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
