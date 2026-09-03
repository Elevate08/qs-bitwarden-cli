#!/usr/bin/env node
// The settings screen's structure: what is pinned, what scrolls, and the
// invariants the folding depends on.
//
//   node tests/settings-screen.test.js

const fs = require("fs")
const path = require("path")

const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

// The settings screen, from its wrapper Column to the end of the Flickable.
const screenAt = panelSrc.indexOf("id: settingsScreen")
const flickAt = panelSrc.indexOf("id: settingsFlick")
const colAt = panelSrc.indexOf("id: settingsCol")
const screen = screenAt < 0 ? "" : panelSrc.slice(screenAt, panelSrc.indexOf("SCREEN 1", screenAt))

check("the settings screen has a wrapper outside the scroll area", screenAt >= 0,
  "expected a settingsScreen Column")

// --- what must not scroll away -----------------------------------------------

check("the way out is pinned, not scrolled",
  screenAt < flickAt && screen.indexOf('text: "Back (Esc)"') < screen.indexOf("id: settingsFlick"),
  "the Back button must sit above the Flickable, not inside settingsCol")

check("the pinned section indicator is also above the scroll area",
  screen.indexOf("id: stickySection") >= 0
    && screen.indexOf("id: stickySection") < screen.indexOf("id: settingsFlick"),
  "stickySection must be outside the Flickable")

check("the scrolling column no longer draws its own Back button",
  panelSrc.slice(colAt).indexOf('text: "Back (Esc)"') < 0
    || panelSrc.slice(colAt).indexOf('text: "Back (Esc)"') > panelSrc.slice(colAt).indexOf("SCREEN 1"),
  "settingsCol still contains a Back button")

// The section name goes left, the way out goes right.
check("the section indicator anchors left and the exit anchors right",
  /id: stickySection[\s\S]{0,200}anchors\.left: parent\.left/.test(screen)
    && /anchors\.right: parent\.right[\s\S]{0,600}text: "Back \(Esc\)"/.test(screen),
  "expected section on the left, Back on the right")

// --- the pinned indicator tracks the scroll ----------------------------------

check("the indicator is recomputed as the view scrolls",
  /onContentYChanged: root\.updateSettingsSticky\(\)/.test(panelSrc),
  "scrolling must update which section the bar names")

check("and when folding changes what is in the list",
  /onContentHeightChanged: Qt\.callLater\(root\.updateSettingsSticky\)/.test(panelSrc),
  "a fold changes contentHeight and must re-run the check after layout")

check("the indicator is held rather than bound",
  /property var settingsStickyEntry: null/.test(panelSrc),
  "it depends on delegate geometry, which a binding cannot read without fighting layout")

check("it names the last heading at or above the top of the viewport",
  /if \(row\.y <= settingsViewportTop\(\) \+ 1\) found = entries\[i\]\s*\n\s*else break/.test(panelSrc),
  "expected a scan that stops at the first heading below the fold")

check("above the first heading it still names a section rather than nothing",
  /if \(!found\) \{[\s\S]{0,220}kind === "group"[\s\S]{0,80}break/.test(panelSrc),
  "an empty bar at the top of the screen is the one position every user starts from")

// --- folding from the bar ----------------------------------------------------

check("the pinned section folds the section it names",
  /function toggleStickySettingsGroup\(\)[\s\S]{0,400}toggleSettingsGroup\(group\)/.test(panelSrc),
  "clicking the pinned heading must fold that group")

check("folding from the bar leaves the view on that heading",
  /Qt\.callLater\(function\(\) \{ root\.scrollSettingsToGroup\(group\) \}\)/.test(panelSrc),
  "the rows under the cursor have just gone; the view must land somewhere deliberate")

check("the scroll-to runs after layout, not against stale geometry",
  /\/\/ The rows this just added or removed have not been laid out yet/.test(panelSrc),
  "expected the reason recorded next to the callLater")

check("the stale entry object is refreshed when the fold changes the model",
  /collapsedGroups = Model\.toggleCollapsedGroup[\s\S]{0,260}Qt\.callLater\(updateSettingsSticky\)/.test(panelSrc),
  "the bar holds an entry object that the toggle rebuilds")

check("opening the screen computes the indicator once",
  /currentScreen = "settings"\s*\n\s*Qt\.callLater\(updateSettingsSticky\)/.test(panelSrc),
  "the bar must be right before the user's first scroll")

// --- geometry access is funnelled ---------------------------------------------

check("view geometry is reached through named helpers, not ids scattered about",
  /function settingsViewportTop\(\)/.test(panelSrc)
    && /function settingsRepeaterItem\(i\)/.test(panelSrc),
  "expected settingsViewportTop and settingsRepeaterItem")

check("both helpers survive being called before the view exists",
  /return settingsFlick \? settingsFlick\.contentY : 0/.test(panelSrc)
    && /return settingsRepeater \? settingsRepeater\.itemAt\(i\) : null/.test(panelSrc),
  "openSettings runs before the screen is built")

// --- the danger zone ----------------------------------------------------------

check("destructive actions are separated from maintenance ones",
  /text: "MAINTENANCE"/.test(panelSrc) && /text: "DANGER ZONE"/.test(panelSrc),
  "expected both headings")

check("the danger heading is drawn in the urgent colour",
  /text: "DANGER ZONE"[\s\S]{0,120}foreground: Color\.urgent/.test(panelSrc),
  "a destructive section should not look like every other heading")

check("the danger zone is set off by a separator",
  /PanelSeparator \{ width: parent\.width \}\s*\n\s*\n?\s*PanelSectionHeader \{[\s\S]{0,120}DANGER ZONE/.test(panelSrc),
  "expected a rule above the destructive section")

check("Remove Plugin Data sits under the danger heading, not beside Dependencies",
  panelSrc.indexOf('text: "DANGER ZONE"') < panelSrc.indexOf('text: "Remove Plugin Data"')
    && panelSrc.indexOf('text: "Dependencies"') < panelSrc.indexOf('text: "DANGER ZONE"'),
  "ordering puts the destructive button in the wrong section")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
