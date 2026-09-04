#!/usr/bin/env node
// Tests for folder parsing, filtering and payload assignment.
//
//   node tests/folders.test.js

const fs = require("fs")
const path = require("path")
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseFolders = parseFolders
  exports.folderName = folderName
  exports.filterItems = filterItems
  exports.parseItems = parseItems
  exports.parseItemDetail = parseItemDetail
  exports.buildCreatePayload = buildCreatePayload
  exports.buildEditPayload = buildEditPayload
  exports.listFoldersCommand = listFoldersCommand
  exports.createFolderCommand = createFolderCommand
  exports.folderPayload = folderPayload
  exports.folderEnvVar = folderEnvVar
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- parsing ---
const folders = Model.parseFolders(JSON.stringify([
  { id: "b", name: "Work", object: "folder" },
  { id: null, name: "No Folder", object: "folder" },
  { id: "a", name: "apps", object: "folder" },
]))
check("folders are sorted case-insensitively",
  folders.map(f => f.name).join(",") === "apps,Work", folders.map(f => f.name).join(","))
check("bw's null-id 'No Folder' entry is dropped (the panel has its own control)",
  folders.length === 2 && folders.every(f => f.id), JSON.stringify(folders))
check("malformed folder JSON yields an empty list",
  Model.parseFolders("{{").length === 0 && Model.parseFolders("").length === 0, "expected []")
check("folderName resolves a known id", Model.folderName(folders, "b") === "Work", Model.folderName(folders, "b"))
check("folderName is empty for an unknown or absent id",
  Model.folderName(folders, "zzz") === "" && Model.folderName(folders, null) === "", "expected empty")

// --- items carry folderId ---
const items = Model.parseItems(JSON.stringify([
  { id: "1", name: "In folder", type: 1, folderId: "a", login: {} },
  { id: "2", name: "Unfiled", type: 1, folderId: null, login: {} },
  { id: "3", name: "Other folder", type: 1, folderId: "b", login: {} },
]))
check("parseItems exposes folderId",
  items.find(i => i.id === "1").folderId === "a" && items.find(i => i.id === "2").folderId === null,
  JSON.stringify(items.map(i => [i.id, i.folderId])))
check("parseItemDetail exposes folderId",
  Model.parseItemDetail(JSON.stringify({ id: "1", name: "x", type: 1, folderId: "a", login: {} })).folderId === "a",
  "expected 'a'")

// --- filtering ---
const ids = f => Model.filterItems(items, "", "all", "all", f).map(i => i.id).sort().join(",")
check('folder "all" returns everything', ids("all") === "1,2,3", ids("all"))
check('folder "none" returns only unfiled items', ids("none") === "2", ids("none"))
check("a folder id returns only that folder", ids("a") === "1", ids("a"))
// Existing callers pass four arguments; folders must not break them.
check("omitting the folder argument behaves as 'all'",
  Model.filterItems(items, "", "all", "all").map(i => i.id).sort().join(",") === "1,2,3",
  "regression: existing four-arg calls changed behaviour")
check("folder filter composes with search",
  Model.filterItems(items, "unfiled", "all", "all", "none").map(i => i.id).join(",") === "2",
  "expected only item 2")

// --- payloads ---
check("create assigns the chosen folder",
  Model.buildCreatePayload(1, "n", "u", "p", "", "", "", false, null, "a").folderId === "a", "expected 'a'")
for (const v of ["", null, "all", "none", undefined]) {
  check(`create maps ${JSON.stringify(v)} to no folder`,
    Model.buildCreatePayload(1, "n", "u", "p", "", "", "", false, null, v).folderId === null,
    JSON.stringify(Model.buildCreatePayload(1, "n", "u", "p", "", "", "", false, null, v).folderId))
}
// Editing must be able to clear an assignment, not only set one.
const existing = { rawObject: { id: "1", name: "x", type: 1, folderId: "a", login: {} } }
check("edit can move an item to another folder",
  Model.buildEditPayload(existing, "x", "", "", "", "", "", false, null, "b").folderId === "b", "expected 'b'")
check("edit can clear an existing folder assignment",
  Model.buildEditPayload(existing, "x", "", "", "", "", "", false, null, "").folderId === null, "expected null")

// --- commands ---
// The session goes in BW_SESSION, never argv -- /proc/<pid>/cmdline is
// world-readable and the token unlocks the vault.
check("list folders carries no session on the command line and caps output",
  Model.listFoldersCommand().join(" ").includes("bw list folders")
    && Model.listFoldersCommand().join(" ").includes("head -c")
    && !Model.listFoldersCommand().join(" ").includes("--session"),
  Model.listFoldersCommand().join(" "))
const folderName = "it's \"private\""
check("folder names are serialized for the private environment payload",
  JSON.parse(Model.folderPayload(folderName)).name === folderName,
  Model.folderPayload(folderName))
check("folder names never enter the command line",
  Model.createFolderCommand().join(" ").includes('"$' + Model.folderEnvVar() + '"')
    && !Model.createFolderCommand().join(" ").includes(folderName),
  Model.createFolderCommand().join(" "))
check("the folder writer receives its payload through the private environment binding",
  /function folderEnv\(\)[\s\S]{0,180}Model\.folderEnvVar\(\)[\s\S]{0,180}Model\.folderPayload\(newFolderName\)/.test(panelSrc)
    && /id:\s*createFolderProc[\s\S]{0,100}environment:\s*root\.folderEnv\(\)/.test(panelSrc),
  "createFolderProc is not bound to folderEnv()")

// --- the collapsed filter buttons ---
// Each button names its own keyboard shortcut in its tooltip, and the key that
// actually opens the drawer lives in runShortcut(). Two places, so they can
// disagree -- and a tooltip promising a key that does nothing is worse than no
// tooltip. Pin them to each other.
const filterButtons = [...panelSrc.matchAll(
  /VaultFilterButton\s*\{[\s\S]*?group:\s*"([a-z]+)"[\s\S]*?shortcut:\s*"([a-z])"/g)]
  .map(m => ({ group: m[1], shortcut: m[2] }))
check("all three vault filter buttons are declared",
  filterButtons.length === 3, JSON.stringify(filterButtons))
for (const { group, shortcut } of filterButtons) {
  const dispatch = new RegExp(`case "${shortcut}":\\s*toggleFilterGroup\\("${group}"\\)`)
  check(`the "${shortcut}" in the ${group} filter tooltip is the key that opens it`,
    dispatch.test(panelSrc), `no runShortcut case pairing "${shortcut}" with "${group}"`)
}
// The label is the vault value alone now, so the group name survives only in
// the tooltip -- which is the one place still telling you what you are looking at.
check("each filter button still names its group somewhere the user can reach",
  /tooltipText: Model\.plainLabel\(name \+ " filter \(" \+ shortcut \+ "\): " \+ value\)/.test(panelSrc),
  "the filter tooltip no longer carries the group name and value")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
