#!/usr/bin/env node
// Tests for organization collections on the item form.
//
// Field names were read from a real `bw list org-collections` response
// (id / organizationId / name / externalId / object) and from the item
// template, which carries collectionIds.
//
//   node tests/collections.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.listOrgCollectionsCommand = listOrgCollectionsCommand
  exports.parseCollections = parseCollections
  exports.collectionName = collectionName
  exports.buildCreatePayload = buildCreatePayload
  exports.buildEditPayload = buildEditPayload
  exports.validateItemForm = validateItemForm
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- command ---
check("collections are listed per organization",
  Model.listOrgCollectionsCommand("o1").join(" ") === "bw list org-collections --organizationid o1",
  Model.listOrgCollectionsCommand("o1").join(" "))
check("the session is not on the command line",
  !Model.listOrgCollectionsCommand("o1").join(" ").includes("--session"), "expected no --session")

// --- parsing ---
const cols = Model.parseCollections(JSON.stringify([
  { object: "org-collection", id: "c2", organizationId: "o1", name: "Ops", externalId: null },
  { object: "org-collection", id: "c1", organizationId: "o1", name: "admin", externalId: null },
  { object: "org-collection", name: "no id at all" },
]))
check("collections sort case-insensitively", cols.map(c => c.name).join(",") === "admin,Ops", cols.map(c => c.name).join(","))
check("an entry without an id is dropped", cols.length === 2, JSON.stringify(cols))
check("organizationId is carried through", cols[0].organizationId === "o1", JSON.stringify(cols[0]))
check("malformed JSON yields an empty list",
  Model.parseCollections("{{").length === 0 && Model.parseCollections("").length === 0, "expected []")
check("collectionName resolves a known id", Model.collectionName(cols, "c2") === "Ops", Model.collectionName(cols, "c2"))
check("collectionName is empty for an unknown id", Model.collectionName(cols, "zz") === "", "expected empty")

// --- payloads ---
// A personal item has no collections; sending the key at all would be wrong.
check("a personal item carries no collectionIds",
  !("collectionIds" in Model.buildCreatePayload(1, "n", "", "", "", "", "", false, null, null, ["c1"])),
  "expected the key to be absent")
check("an org item carries the chosen collections",
  JSON.stringify(Model.buildCreatePayload(1, "n", "", "", "", "", "", false, "o1", null, ["c1", "c2"]).collectionIds)
    === JSON.stringify(["c1", "c2"]), "expected both ids")
// Callers that predate collections pass ten arguments; they must not start
// sending an empty array, which is not the same as sending nothing.
check("an org item with no collections omits the key rather than sending []",
  !("collectionIds" in Model.buildCreatePayload(1, "n", "", "", "", "", "", false, "o1", null)),
  "expected the key to be absent")

const existing = { rawObject: { id: "1", type: 1, organizationId: "o1", collectionIds: ["keep"], login: {} } }
check("editing keeps existing collections when none are supplied",
  JSON.stringify(Model.buildEditPayload(existing, "n", "", "", "", "", "", false, "o1", null).collectionIds)
    === JSON.stringify(["keep"]), "expected the existing ids to survive")
check("editing replaces collections when new ones are supplied",
  JSON.stringify(Model.buildEditPayload(existing, "n", "", "", "", "", "", false, "o1", null, ["c9"]).collectionIds)
    === JSON.stringify(["c9"]), "expected the new ids")
check("moving an item to a personal vault drops its collections",
  !("collectionIds" in Model.buildEditPayload(existing, "n", "", "", "", "", "", false, null, null, [])),
  "expected the key to be removed")

// --- validation ---
// Bitwarden rejects an org item with no collection, so say so before the CLI does.
check("an org item with no collection is refused",
  Model.validateItemForm("n", "o1", []) !== "", Model.validateItemForm("n", "o1", []))
check("an org item with a collection is accepted",
  Model.validateItemForm("n", "o1", ["c1"]) === "", Model.validateItemForm("n", "o1", ["c1"]))
check("a personal item needs no collection",
  Model.validateItemForm("n", null, []) === "" && Model.validateItemForm("n", "personal", []) === "",
  "expected personal items to pass")
check("a blank title is still refused first",
  Model.validateItemForm("   ", "o1", ["c1"]).includes("title"), Model.validateItemForm("   ", "o1", ["c1"]))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
