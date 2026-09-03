#!/usr/bin/env node
// The settings screen's structure -- what is pinned, what scrolls, how its
// sections are drawn -- and the one invariant that is panel-wide rather than
// settings-only: every scrolling view keeps its content clear of its own
// scrollbar.
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
    && screen.indexOf("anchors.right: parent.right") < screen.indexOf('text: "Back (Esc)"')
    && screen.indexOf("anchors.right: parent.right") > screen.indexOf("id: stickySection"),
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

// The bar names the section the view is inside, including at rest -- an empty
// bar on the one position everybody starts from is worse than a redundant one.
// Duplication is prevented at the other end instead: the in-list heading of
// the section the bar names is drawn transparent.
check("the bar names a section from the top of the list, before any scrolling",
  /if \(row\.y > top \+ 1\) break/.test(panelSrc),
  "a heading at the top edge is the section the view is in")

check("the in-list heading yields to the bar rather than drawing alongside it",
  /opacity: \(root\.settingsStickyEntry\s*\n?\s*&& root\.settingsStickyEntry\.group === modelData\.group\) \? 0 : 1/.test(panelSrc),
  "the pinned section's own heading must not be drawn twice")

check("it yields by going transparent, not by being removed",
  /\/\/ Transparent\s*\n\s*\/\/ rather than hidden|rather than hidden: removing it would shorten the content/.test(panelSrc)
    && !/visible: !\(root\.settingsStickyEntry/.test(panelSrc),
  "removing it would shorten the content and jump the view at the top edge")

check("and only while part of that section is still on screen",
  /if \(top < settingsSectionEnd\(i\)\)/.test(panelSrc),
  "past the end of a section the bar must let go of it")

check("a section's extent is the next heading, or the last row for the final one",
  /function settingsSectionEnd\(index\)/.test(panelSrc)
    && /if \(next\) return next\.y/.test(panelSrc)
    && /if \(last\) return last\.y \+ last\.height/.test(panelSrc),
  "expected both the between-headings and the final-section cases")

// The trailing maintenance and danger-zone blocks are not foldable sections.
// Leaving the last group pinned through them would offer to fold something the
// user had scrolled past and could no longer see.
check("the bar empties rather than naming a section that is no longer in view",
  /var found = null/.test(panelSrc)
    && !/if \(!found\) \{/.test(panelSrc),
  "there must be no fallback that forces a section into an empty bar")

// --- the sections are not foldable ------------------------------------------
//
// They were, for a few commits. Three groups of three, seven and four rows do
// not need folding, and a fold is one more state to be in and one more thing
// to leave shut by accident. These assertions exist so it does not creep back
// halfway -- a chevron with nothing behind it, or a heading that swallows a
// click.

check("no collapse state is kept",
  !/collapsedGroups/.test(panelSrc), "settings sections are not foldable")

check("headings are not controls",
  !/toggleSettingsGroup|toggleStickySettingsGroup/.test(panelSrc),
  "a heading that folds nothing must not accept a click")

check("the pinned indicator carries no chevron or count",
  !/settingsStickyEntry\.collapsed|settingsStickyEntry\.count/.test(panelSrc),
  "the bar names the section and nothing more")

// A heading is in the list so the indicator has geometry to read, but it is
// not something the cursor can act on -- stopping there and doing nothing on
// Enter is worse than stepping over it.
check("the keyboard cursor steps over headings",
  /while \(i >= 0 && i < n && settingsEntries\[i\] && settingsEntries\[i\]\.kind === "group"\) i \+= step/.test(panelSrc),
  "expected the cursor to skip group rows")

check("the screen opens on a setting, not on a heading",
  /settingsIndex = firstSettingIndex\(\)/.test(panelSrc),
  "the first row in the list is a heading")

check("activation and adjustment have no group case left",
  !/e\.kind === "group"/.test(panelSrc),
  "the cursor can no longer land on a heading, so neither needs to handle one")

// --- geometry access is funnelled ---------------------------------------------

check("view geometry is reached through named helpers, not ids scattered about",
  /function settingsViewportTop\(\)/.test(panelSrc)
    && /function settingsRepeaterItem\(i\)/.test(panelSrc),
  "expected settingsViewportTop and settingsRepeaterItem")

check("both helpers survive being called before the view exists",
  /return settingsFlick \? settingsFlick\.contentY : 0/.test(panelSrc)
    && /return settingsRepeater \? settingsRepeater\.itemAt\(i\) : null/.test(panelSrc),
  "openSettings runs before the screen is built")

// --- every scrollbar gets a lane of its own ----------------------------------
//
// These bars are overlays. Left alone each one draws on top of whatever is at
// the right edge of its view -- toggles, number fields, copy buttons, the ends
// of elided text. Every scrolling view subtracts one shared gutter, so no bar
// covers a control and the right-hand edges line up across screens.

check("the gutter is measured from a real scrollbar, not guessed",
  /settingsScrollBar \? settingsScrollBar\.implicitWidth : 0/.test(panelSrc),
  "a theme with a wider bar would put it back over the controls")

check("the gutter has a floor for a null bar and for the frames before layout",
  /Math\.max\(settingsScrollBar[\s\S]{0,120}Style\.space\(10\)\)/.test(panelSrc),
  "expected a minimum gutter")

// Every scrolling view in the panel, by the id its content width is bound to.
const scrollViews = [
  "sendFlick", "fpFlick", "genFlick", "pinFlick", "setupFlick", "settingsFlick",
  "filterOptionsList", "detailFlickable", "editFlickable",
  "folderPickList", "orgPickList", "collectionList",
]
for (const view of scrollViews) {
  check(`${view} keeps its content clear of the scrollbar`,
    new RegExp(`width: ${view}\\.width - root\\.scrollGutter`).test(panelSrc),
    `${view} content runs under its own scrollbar`)
}

// The vault list is a ListView, so its delegate takes the width directly
// rather than through a content column.
check("the vault list's rows keep clear of the scrollbar too",
  /width: ListView\.view\.width - root\.scrollGutter/.test(panelSrc),
  "the item rows run under the bar")

check("every scrolling view is accounted for",
  (panelSrc.match(/ScrollBar\.vertical:/g) || []).length === scrollViews.length + 1,
  `${(panelSrc.match(/ScrollBar\.vertical:/g) || []).length} scrollbars for ${scrollViews.length} views plus the list`)

check("the pinned settings row is inset to match its rows",
  /anchors\.rightMargin: root\.scrollGutter/.test(panelSrc),
  "Back would otherwise overhang every control beneath it")

// Heading rows carry no description and no zeroLabel, and QML evaluates the
// bindings of invisible items, so these ran for every heading in the list.
check("bindings that also run for heading rows tolerate the missing fields",
  /\(modelData\.description \|\| ""\)/.test(panelSrc)
    && /\(modelData\.zeroLabel \|\| ""\)/.test(panelSrc),
  "undefined reaching a QString property is a warning on every frame")

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
