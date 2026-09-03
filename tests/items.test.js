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
  exports.parseSanitizedItems = parseSanitizedItems
  exports.filterItems = filterItems
  exports.buildCreatePayload = buildCreatePayload
  exports.buildEditPayload = buildEditPayload
  exports.matchesQuery = matchesQuery
  exports.identityFullName = identityFullName
  exports.getItemCommand = getItemCommand
  exports.editItemCommand = editItemCommand
  exports.deleteItemCommand = deleteItemCommand
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
  identity: { title: "Mr", firstName: "A", middleName: "Q", lastName: "Person",
              username: "aperson", company: "Acme", email: "a@example.com",
              phone: "555", ssn: "000-00-0000", passportNumber: "P123",
              licenseNumber: "L456", address1: "1 Road", address2: "Flat 2",
              address3: "", city: "Town", state: "ST",
              postalCode: "00000", country: "US" }
}

const sshPublic = { id: "ssh-1", name: "Work SSH", type: 5, organizationId: "org-1",
  folderId: "folder-1", favorite: true, reprompt: 1,
  sshKey: { publicKey: "ssh-ed25519 AAAATEST", fingerprint: "SHA256:public" } }
const sanitized = Model.parseSanitizedItems(JSON.stringify({ items: [login], sshKeys: [sshPublic] }))
check("sanitized envelope adds a public SSH item", sanitized.length === 2
  && sanitized.some(i => i.typeCode === 5 && i.publicKey === "ssh-ed25519 AAAATEST"), JSON.stringify(sanitized))
const ssh = sanitized.find(i => i.typeCode === 5)
check("SSH search and favorite filtering use the combined list",
  Model.filterItems(sanitized, "AAAATEST", "all", "all", "all").length === 1
    && Model.filterItems(sanitized, "", "favorite", "all", "all").some(i => i.id === "ssh-1"), JSON.stringify(sanitized))
check("SSH detail is public-only", ssh && Model.itemDetailFromObject(ssh.rawObject).password === ""
  && Model.itemDetailFromObject(ssh.rawObject).publicKey === "ssh-ed25519 AAAATEST", JSON.stringify(ssh))
check("generic write and private-read commands reject SSH", Model.buildCreatePayload(5, "x") === null
  && Model.buildEditPayload(ssh, "x") === null && Model.getItemCommand("ssh-1", 5).length === 0
  && Model.editItemCommand("ssh-1", 5).length === 0 && Model.deleteItemCommand("ssh-1", 5).length === 0, "guard missing")

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

// --- cards and identities are first-class, not decoration --------------------
//
// The model parsed both of these long before anything drew them, so these
// assertions guard the half that was always right as much as the half that
// was added: what the list shows, what search can find, and above all what
// survives an edit.

check("an identity carries the fields Bitwarden actually returns",
  identityDetail.identity.middleName === "Q" && identityDetail.identity.company === "Acme"
    && identityDetail.identity.passportNumber === "P123"
    && identityDetail.identity.address2 === "Flat 2",
  JSON.stringify(identityDetail.identity))

check("a full name closes the gaps rather than padding them",
  Model.identityFullName({ title: "", firstName: "", middleName: "", lastName: "Person" }) === "Person",
  JSON.stringify(Model.identityFullName({ lastName: "Person" })))

check("a card row is subtitled with its brand and last four",
  listedCard.subtitle === "Visa •••• 1111", listedCard.subtitle)
check("an identity row is subtitled with its name, not left blank",
  listedIdentity.subtitle === "Mr A Q Person", listedIdentity.subtitle)

// Anything the list is willing to show, the search box has to be able to find.
check("a card is found by its brand", Model.matchesQuery(listedCard, "visa"), listedCard.subtitle)
check("a card is found by its last four", Model.matchesQuery(listedCard, "1111"), listedCard.subtitle)
check("a card is not found by the middle of its number",
  !Model.matchesQuery(listedCard, "111111111"), "a stored-card-number lookup is not this box's job")
check("an identity is found by name", Model.matchesQuery(listedIdentity, "person"), listedIdentity.subtitle)
check("an identity is found by email", Model.matchesQuery(listedIdentity, "a@example.com"), listedIdentity.subtitle)

// --- payloads ---------------------------------------------------------------

const createdCard = Model.buildCreatePayload(3, "New", "", "", "", "", "", false, null, null, null,
  { cardholderName: "B Person", brand: "MC", number: "5555444433332222", expMonth: "01", expYear: "2031", code: "999" })
check("creating a card emits a card object and no login",
  createdCard.type === 3 && createdCard.card.number === "5555444433332222"
    && createdCard.card.code === "999" && createdCard.login === undefined,
  JSON.stringify(createdCard))

const createdIdentity = Model.buildCreatePayload(4, "New", "", "", "", "", "", false, null, null, null,
  { firstName: "Ada", lastName: "Lovelace", email: "ada@example.com" })
check("creating an identity emits an identity object",
  createdIdentity.type === 4 && createdIdentity.identity.firstName === "Ada"
    && createdIdentity.identity.email === "ada@example.com"
    && createdIdentity.identity.ssn === "",
  JSON.stringify(createdIdentity))

// The regression that matters most here. The form can rename a card without
// ever showing its number, and the writers set every key they know -- so an
// edit that passes no type fields must leave the sub-object entirely alone,
// not blank it. This is what the `&& typeFields` guard in buildEditPayload is
// for, and it is worth an assertion because nothing about the call site looks
// dangerous.
const renamedCard = Model.buildEditPayload({ typeCode: 3, rawObject: card },
  "Renamed", "", "", "", "", "", false, null, null, null)
check("renaming a card leaves its number, expiry and code untouched",
  renamedCard.name === "Renamed" && renamedCard.card.number === "4111111111111111"
    && renamedCard.card.code === "123" && renamedCard.card.expYear === "2030",
  JSON.stringify(renamedCard.card))

const renamedIdentity = Model.buildEditPayload({ typeCode: 4, rawObject: identity },
  "Renamed", "", "", "", "", "", false, null, null, null)
check("renaming an identity leaves its fields untouched",
  renamedIdentity.identity.email === "a@example.com" && renamedIdentity.identity.ssn === "000-00-0000",
  JSON.stringify(renamedIdentity.identity))

const editedCard = Model.buildEditPayload({ typeCode: 3, rawObject: card },
  "Visa", "", "", "", "", "", false, null, null, null,
  { cardholderName: "A Person", brand: "Visa", number: "4111111111111112", expMonth: "05", expYear: "2031", code: "321" })
check("an edit that does carry card fields writes them",
  editedCard.card.number === "4111111111111112" && editedCard.card.code === "321"
    && editedCard.card.expMonth === "05",
  JSON.stringify(editedCard.card))

check("editing a card never turns it into a login",
  editedCard.type === 3 && editedCard.login === undefined, JSON.stringify(Object.keys(editedCard)))

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

// A key icon on the password controls, not a refresh icon. Pinned by button
// rather than by count, because what broke this was a bulk glyph replacement
// that meant to touch one new button and silently rewrote every other use of
// the same codepoint. A count alone would have moved with it.
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const KEY = String.fromCodePoint(0xF0306)
const passwordButtons = [
  ['tooltipText: "Password generator (g)"', "the generator button"],
  ['tooltipText: "Copy password (Enter / y)"', "copy password on an item row"],
  ['tooltipText: "Copy password (y / Enter)"', "copy password in the detail view"],
  ['selected: root.genOpts.type === "password"', "the generator's Password type"],
]
for (const [anchor, label] of passwordButtons) {
  const at = panelSrc.indexOf(anchor)
  const before = at < 0 ? "" : panelSrc.slice(Math.max(0, at - 200), at)
  const icon = before.lastIndexOf("iconText:")
  check(`${label} wears the key glyph`,
    at >= 0 && icon >= 0 && before.slice(icon).includes(KEY),
    at < 0 ? `anchor missing: ${anchor}` : JSON.stringify(before.slice(icon).trim()))
}
check("the Generate... button wears it too",
  /text: "Generate\.\.\."[\s\S]{0,80}iconText: "\u{F0306}"/u.test(panelSrc),
  "the field-level generator shortcut")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
