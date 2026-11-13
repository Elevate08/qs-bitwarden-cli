#!/usr/bin/env node
// Password history: the model's entries (newest first, secrets withheld for a
// helper-held item), the detail shape, and the panel wiring (key, sub-screen,
// the one clipboard path).
//
//   node tests/password-history.test.js

const { createSuite, loadModule, read, readPluginSource, functionBody } = require("./harness")

const Model = loadModule()
const { check, eq, done } = createSuite("password-history")

const stored = [
  { password: "old-a", lastUsedDate: "2023-01-01T00:00:00.000Z" },
  { password: "old-c", lastUsedDate: "2025-03-01T12:00:00.000Z" },
  { password: "old-b", lastUsedDate: "2024-06-15T00:00:00.000Z" }
]

// --- entries ---------------------------------------------------------------

const entries = Model.passwordHistoryEntries(stored, false)
eq("entries come newest first", entries.map(e => e.password).join(","), "old-c,old-b,old-a")
eq("an entry keeps its position in the stored list", entries.map(e => e.index).join(","), "1,2,0")
eq("an entry keeps its date", entries[0].date, "2025-03-01T12:00:00.000Z")
eq("no history is an empty list", Model.passwordHistoryEntries(undefined, false).length, 0)
eq("junk is an empty list", Model.passwordHistoryEntries("x", false).length, 0)
eq("an entry with no password is left out",
  Model.passwordHistoryEntries([{ password: "", lastUsedDate: "2024-01-01T00:00:00Z" }, null, { password: "p" }], false).length, 1)
const undated = Model.passwordHistoryEntries([{ password: "x" }, { password: "y", lastUsedDate: "2020-01-01T00:00:00Z" }], false)
eq("an undated entry sorts after dated ones", undated.map(e => e.password).join(","), "y,x")

const withheld = Model.passwordHistoryEntries(["2023-01-01T00:00:00.000Z", "2025-03-01T12:00:00.000Z"], true)
eq("a helper-held history is dated newest first", withheld.map(e => e.index).join(","), "1,0")
check("a helper-held history carries no password",
  withheld.every(e => e.password === Model.WITHHELD), JSON.stringify(withheld))

check("a date is formatted", /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(Model.formatHistoryDate("2025-03-01T12:00:00.000Z")),
  Model.formatHistoryDate("2025-03-01T12:00:00.000Z"))
eq("a bad date is named so", Model.formatHistoryDate("nope"), "Unknown date")
eq("a missing date is named so", Model.formatHistoryDate(""), "Unknown date")

// --- detail shapes -----------------------------------------------------------

const login = { id: "1", type: 1, name: "Bank", login: { username: "me", password: "now" }, passwordHistory: stored }
const detail = Model.itemDetailFromObject(login)
eq("a loaded login's detail has its history", detail.passwordHistory.length, 3)
eq("the detail reads an old password by the helper's key", Model.detailSecretValue(detail, "passwordHistory:1"), "old-c")
eq("an unknown position reads nothing", Model.detailSecretValue(detail, "passwordHistory:9"), null)
eq("a login without history has none", Model.itemDetailFromObject({ id: "2", type: 1, name: "n", login: {} }).passwordHistory.length, 0)
eq("a note has none", Model.itemDetailFromObject({ id: "3", type: 2, name: "n", passwordHistory: stored }).passwordHistory.length, 0)

const held = JSON.parse(JSON.stringify(login))
delete held.passwordHistory
delete held.login.password
held.qsbwHeld = { password: true, totp: false, notes: false, passwordHistory: stored.map(e => e.lastUsedDate) }
const row = Model.parseItems([held])[0]
eq("a row keeps the dates the helper reports", row.historyDates.length, 3)
const pub = Model.publicItemDetail(row)
eq("the public detail counts the history", pub.passwordHistory.length, 3)
check("the public detail holds no old password", !JSON.stringify(pub).includes("old-"), JSON.stringify(pub))
eq("the public detail reads no old password", Model.detailSecretValue(pub, "passwordHistory:0"), Model.WITHHELD)

const plainRow = Model.parseItems([{ id: "p", type: 1, name: "n", login: {}, qsbwHeld: { password: false } }])[0]
eq("an old helper's row has no history", Model.publicItemDetail(plainRow).passwordHistory.length, 0)

// --- the panel ---------------------------------------------------------------

const service = read("Service.qml")
const panel = readPluginSource("Panel.qml")
const panelOnly = read("Panel.qml")

// --- the action palette --------------------------------------------------------

const withHistory = Model.itemDetailFromObject(login)
const actionsOf = (item, screen) => Model.itemActions(item, { screen }).filter(a => a.id === "passwordHistory")
eq("the palette offers the history on the detail screen, keyed h",
  JSON.stringify(actionsOf(withHistory, "detail")), JSON.stringify([{ id: "passwordHistory", label: "Password history", key: "h" }]))
eq("the palette does not offer it from the list", actionsOf(withHistory, "main").length, 0)
eq("the palette does not offer it without history",
  actionsOf(Model.itemDetailFromObject({ id: "2", type: 1, name: "n", login: {} }), "detail").length, 0)
eq("the palette offers it for a helper-held login", actionsOf(pub, "detail").length, 1)

check("h opens the history from the detail",
  /else if \(lower === "h"\) \{\s*root\.vault\.openHistory\(\)/.test(functionBody(panelOnly, "runDetailShortcut")), "h is not wired")
check("h is not bound twice on the detail screen",
  panelOnly.split('lower === "h"').length - 1 === 1,
  "the detail key handler binds h more than once")
check("b and q leave the history", /currentScreen === "history"\) \{\s*if \(lower === "b" \|\| lower === "q"\) root\.vault\.closeHistory/.test(panelOnly), "")
check("Esc leaves the history for the detail",
  /currentScreen === "history"\) \{\s*closeHistory\(\)/.test(functionBody(service, "handleEscape")), "")
check("the detail has the link with a count",
  /"Password history \(" \+ root\.vault\.detailHistoryCount \+ "\)"/.test(panelOnly), "")
check("the history copies through the detail's one clipboard path",
  /root\.copyDetailSecret\(historyEntry\.revealKey, "Previous password"\)/.test(panelOnly), "")
check("the history reveals through the protected reveal",
  /root\.toggleProtectedReveal\(historyEntry\.revealKey\)/.test(panelOnly), "")
check("an old password is drawn masked", /Model\.maskString\(historyEntry\.modelData\.password/.test(panelOnly), "")
check("the helper read still works from the history screen",
  /currentScreen !== "detail" && root\.currentScreen !== "history"/.test(service), "")
check("leaving the history masks its passwords again",
  /Back from the edit form or the password history[\s\S]*?withholdDetailSecrets\(\)/.test(service),
  "going back to the detail must drop every revealed value")
check("the history stays part of the item for the re-prompt grant",
  /screen === "detail" \|\| screen === "history" \|\| screen === "edit"/.test(service), "")
check("a history entry is never logged", !/console\.(log|warn|error)[^\n]*(passwordHistory|history)/i.test(service + panelOnly), "")

done()
