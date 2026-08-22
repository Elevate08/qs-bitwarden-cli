#!/usr/bin/env node
// The item detail view is built from what `bw list items` already returned
// rather than from a second `bw get item`. That is only correct if the two
// produce the same detail, so that equivalence is the property under test.
//
//   node tests/items.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseItems = parseItems
  exports.parseItemDetail = parseItemDetail
  exports.itemDetailFromObject = itemDetailFromObject
  exports.itemTypeGlyph = itemTypeGlyph
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// Shaped like a real `bw list items` entry, which carries the complete cipher
// -- this is what makes the second CLI call unnecessary.
const login = {
  object: "item", id: "11111111-1111-1111-1111-111111111111",
  organizationId: null, folderId: "f1", type: 1, name: "GitHub",
  notes: "recovery codes in the safe", favorite: true,
  login: {
    username: "octocat", password: "s3cr3t-p4ss", totp: "JBSWY3DPEHPK3PXP",
    uris: [{ match: null, uri: "https://github.com/login" }]
  },
  fields: [{ name: "recovery", value: "abcd-efgh", type: 1 }]
}

const card = {
  object: "item", id: "22222222-2222-2222-2222-222222222222",
  type: 3, name: "Visa", notes: "", favorite: false,
  card: { cardholderName: "A Person", brand: "Visa", number: "4111111111111111",
          expMonth: "04", expYear: "2030", code: "123" }
}

const identity = {
  object: "item", id: "33333333-3333-3333-3333-333333333333",
  type: 4, name: "Home", notes: "", favorite: false,
  identity: { title: "Mr", firstName: "A", lastName: "Person", email: "a@example.com",
              phone: "555", address1: "1 Road", city: "Town", state: "ST",
              postalCode: "00000", country: "US" }
}

// --- the equivalence the optimisation rests on ------------------------------

for (const raw of [login, card, identity]) {
  const viaGetItem = Model.parseItemDetail(JSON.stringify(raw))
  const viaList = Model.itemDetailFromObject(raw)
  check(`${raw.name}: the list-built detail matches the get-item-built detail`,
    JSON.stringify(viaList) === JSON.stringify(viaGetItem),
    `\n      list: ${JSON.stringify(viaList)}\n      get:  ${JSON.stringify(viaGetItem)}`)
}

// --- parseItems keeps what the detail view needs ----------------------------

const listed = Model.parseItems(JSON.stringify([login, card, identity]))
check("every listed item carries its raw object", listed.every(i => i.rawObject), "missing rawObject")

const listedLogin = listed.find(i => i.id === login.id)
const detail = Model.itemDetailFromObject(listedLogin.rawObject)
check("the password survives the round trip through the list",
  detail.password === "s3cr3t-p4ss", detail.password)
check("so does the TOTP key", detail.totpKey === "JBSWY3DPEHPK3PXP", detail.totpKey)
check("so do custom fields, which the list view itself never shows",
  detail.fields.length === 1 && detail.fields[0].name === "recovery"
    && detail.fields[0].value === "abcd-efgh", JSON.stringify(detail.fields))
check("so do notes", detail.notes === "recovery codes in the safe", detail.notes)
check("so do URIs", detail.uris[0] === "https://github.com/login", JSON.stringify(detail.uris))

const listedCard = listed.find(i => i.id === card.id)
const cardDetail = Model.itemDetailFromObject(listedCard.rawObject)
check("card numbers and codes survive too",
  cardDetail.card.number === "4111111111111111" && cardDetail.card.code === "123",
  JSON.stringify(cardDetail.card))

const listedIdentity = listed.find(i => i.id === identity.id)
const identityDetail = Model.itemDetailFromObject(listedIdentity.rawObject)
check("identity fields survive too",
  identityDetail.identity.email === "a@example.com" && identityDetail.identity.postalCode === "00000",
  JSON.stringify(identityDetail.identity))

// --- the fallback path still has to behave ----------------------------------

check("a missing raw object yields null rather than a broken detail",
  Model.itemDetailFromObject(null) === null, String(Model.itemDetailFromObject(null)))
check("so does a non-object", Model.itemDetailFromObject("nope") === null,
  String(Model.itemDetailFromObject("nope")))
check("unparseable JSON still yields null from the string form",
  Model.parseItemDetail("{not json") === null, String(Model.parseItemDetail("{not json")))

// --- the type glyphs -------------------------------------------------------
//
// Pinned by codepoint, because a wrong one is invisible in review: the glyph
// renders as a small picture in the editor and the name is nowhere in the
// source. Two of these were wrong for exactly that reason -- Secure Note drew
// md-fan (a ceiling fan) and Card drew md-close_octagon_outline (a stop sign),
// both under comments claiming otherwise. The values below are the same ones
// the type filter chips in Panel.qml use, which is the point: a row and the
// chip that selects it should not disagree.

const glyphs = [
  [1, 0xF030B, "md-key_variant", "Login"],
  [2, 0xF0219, "md-file_document", "Secure Note"],
  [3, 0xF0FEF, "md-credit_card", "Card"],
  [4, 0x0F007, "fa-user", "Identity"]
]
for (const [typeCode, cp, name, label] of glyphs) {
  const got = Model.itemTypeGlyph(typeCode)
  check(`${label} draws ${name}`, got.codePointAt(0) === cp,
    `U+${got.codePointAt(0).toString(16).toUpperCase()}`)
  check(`${label} is one glyph, not a sequence`, [...got].length === 1, JSON.stringify(got))
}
// itemTypeName() already answers "login" for anything it does not recognise,
// so a cipher type Bitwarden adds later renders as a login rather than as
// nothing. That also means itemTypeGlyph's own `default:` shield can never be
// reached -- pinned here so the next reader does not go looking for it.
check("an unrecognised type is drawn as a login, not as the unreachable shield",
  Model.itemTypeGlyph(99).codePointAt(0) === 0xF030B,
  Model.itemTypeGlyph(99).codePointAt(0).toString(16))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
