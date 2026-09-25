#!/usr/bin/env node
// The detail view is built from `bw list items` data rather than `bw get item`,
// which is only right if both give the same detail.
//
//   node tests/items.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")
const path = require("path")
const Model = loadModule()

const { check, done } = createSuite("items")

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
  fields: [
    { name: "recovery", value: "abcd-efgh", type: 1 },
    { name: "Account name", value: null, type: 3, linkedId: 100 }
  ]
}

const secureNote = {
  object: "item", id: "44444444-4444-4444-4444-444444444444",
  type: 2, name: "Operations", notes: "Runbook", favorite: false,
  secureNote: { type: 0 },
  fields: [
    { name: "Region", value: "eu-west", type: 0 },
    { name: "API key", value: "not-a-real-secret", type: 1 },
    { name: "Enabled", value: false, type: 2 }
  ]
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

for (const raw of [login, secureNote, card, identity]) {
  const viaGetItem = Model.parseItemDetail(JSON.stringify(raw))
  const viaList = Model.itemDetailFromObject(raw)
  check(`${raw.name}: the list-built detail matches the get-item-built detail`,
    JSON.stringify(viaList) === JSON.stringify(viaGetItem),
    `\n      list: ${JSON.stringify(viaList)}\n      get:  ${JSON.stringify(viaGetItem)}`)
}

// --- parseItems keeps what the detail view needs ----------------------------

const listed = Model.parseItems(JSON.stringify([login, secureNote, card, identity]))
check("every listed item carries its raw object", listed.every(i => i.rawObject), "missing rawObject")

const listedLogin = listed.find(i => i.id === login.id)
const detail = Model.itemDetailFromObject(listedLogin.rawObject)
check("the password survives the round trip through the list",
  detail.password === "s3cr3t-p4ss", detail.password)
check("so does the TOTP key", detail.totpKey === "JBSWY3DPEHPK3PXP", detail.totpKey)
check("so do custom fields, which the list view itself never shows",
  detail.fields.length === 2 && detail.fields[0].name === "recovery"
    && detail.fields[0].value === "abcd-efgh", JSON.stringify(detail.fields))
check("linked custom fields resolve their native value and retain their target id",
  detail.fields[1].value === "octocat" && detail.fields[1].linkedId === 100,
  JSON.stringify(detail.fields[1]))
check("linked secrets stay sensitive in the detail model",
  Model.itemDetailFromObject({ type: 1, name: "linked", login: { password: "secret" },
    fields: [{ name: "Password alias", type: 3, linkedId: 101 }] }).fields[0].sensitive === true,
  JSON.stringify(detail.fields))
check("the detail says whether there is a password, as the list row does",
  detail.hasPassword === true
    && Model.itemDetailFromObject({ type: 1, name: "no password", login: { username: "u" } }).hasPassword === false
    && Model.itemDetailFromObject({ type: 5, name: "key", sshKey: {} }).hasPassword === false,
  "hasPassword must be a boolean on every detail")
check("so do notes", detail.notes === "recovery codes in the safe", detail.notes)
check("so do URIs", detail.uris[0] === "https://github.com/login", JSON.stringify(detail.uris))

const listedSecureNote = listed.find(i => i.id === secureNote.id)
const secureNoteDetail = Model.itemDetailFromObject(listedSecureNote.rawObject)
check("secure-note custom fields survive into the detail model",
  secureNoteDetail.fields.length === 3
    && secureNoteDetail.fields[0].name === "Region"
    && secureNoteDetail.fields[1].type === 1,
  JSON.stringify(secureNoteDetail.fields))
check("an explicit false boolean custom field is not erased as empty",
  secureNoteDetail.fields[2].value === "false",
  JSON.stringify(secureNoteDetail.fields[2]))

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
//
// What the list shows, what search finds, and what survives an edit.

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

// A rename passes no type fields and must leave the card untouched (the
// `&& typeFields` guard in buildEditPayload), not blank it.
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

const createdNoteWithFields = Model.buildCreatePayload(2, "Runbook", "", "", "", "", "", false,
  null, null, null, null, [
    { name: "Region", value: "eu-west", type: 0, revealed: true },
    { name: "API key", value: "secret", type: 1, revealed: true },
    { name: "Enabled", value: false, type: 2, revealed: true }
  ])
check("creating a note writes all editable custom-field types",
  createdNoteWithFields.fields.length === 3
    && createdNoteWithFields.fields[0].value === "eu-west"
    && createdNoteWithFields.fields[1].type === 1
    && createdNoteWithFields.fields[2].value === "false",
  JSON.stringify(createdNoteWithFields.fields))
check("form-only reveal state never enters cipher JSON",
  createdNoteWithFields.fields.every(field => !("revealed" in field)),
  JSON.stringify(createdNoteWithFields.fields))

const editedNoteFields = Model.buildEditPayload({ typeCode: 2, rawObject: secureNote },
  "Operations", "", "", "", "", "Runbook", false, null, null, null, null,
  [{ name: "Environment", value: "production", type: 0 }])
check("an edit can add, change, and remove custom fields authoritatively",
  editedNoteFields.fields.length === 1
    && editedNoteFields.fields[0].name === "Environment"
    && editedNoteFields.fields[0].value === "production",
  JSON.stringify(editedNoteFields.fields))

const unchangedNoteFields = Model.buildEditPayload({ typeCode: 2, rawObject: secureNote },
  "Operations renamed", "", "", "", "", "Runbook", false, null, null, null, null)
check("callers that omit custom-field state preserve the original array",
  JSON.stringify(unchangedNoteFields.fields) === JSON.stringify(secureNote.fields),
  JSON.stringify(unchangedNoteFields.fields))

const linkedCard = Model.buildCreatePayload(3, "Card", "", "", "", "", "", false,
  null, null, null, { number: "4111111111111111" },
  [{ name: "Payment number", value: "must-not-be-copied", type: 3, linkedId: 305 }])
check("linked fields store an id rather than duplicating the native secret",
  linkedCard.fields[0].linkedId === 305 && linkedCard.fields[0].value === null,
  JSON.stringify(linkedCard.fields[0]))

check("a blank custom-field label blocks the save with a useful row number",
  Model.validateItemForm("Runbook", null, [], [{ name: "Region" }, { name: "   " }])
    === "Custom field 2 needs a label",
  Model.validateItemForm("Runbook", null, [], [{ name: "Region" }, { name: "   " }]))

// --- the encoder swap --------------------------------------------------------
//
// coreutils base64 replaced `bw encode` (~2.7 s of CLI startup per save): the
// output must be identical and the payload must still stay out of argv.

const { execFileSync } = require("child_process")
const encodeSamples = [
  '{"name":"Test","type":3}',
  '{"name":"unicode \u00e9\u00e5\u4e2d","notes":"line1\nline2"}',
  '{"name":"' + "x".repeat(500) + '"}',
  '{"password":"p@ss w/ spaces & $pecial \'quotes\'"}',
]
for (const sample of encodeSamples) {
  const ours = execFileSync("bash", ["-c", 'printf "%s" "$P" | base64 -w0'],
    { env: { ...process.env, P: sample } }).toString()
  const node = Buffer.from(sample, "utf8").toString("base64")
  check(`base64 -w0 matches a reference encoder for ${sample.slice(0, 28)}...`,
    ours === node, `${ours}\n    !=\n    ${node}`)
}

check("base64 -w0 emits a single line, as the CLI's stdin requires",
  !execFileSync("bash", ["-c", 'printf "%s" "$P" | base64 -w0'],
    { env: { ...process.env, P: '{"name":"' + "y".repeat(400) + '"}' } }).toString().includes("\n"),
  "a wrapped encoding would reach `bw` as several lines")

for (const [label, cmd] of [
  ["create item", Model.createItemCommand({ name: "x" })[2]],
  ["edit item", Model.editItemCommand("id-1", 1)[2]],
]) {
  check(`${label} pipes the payload from the environment through base64`,
    /printf '%s' "\$QSBW_ITEM" \| base64 -w0 \|/.test(cmd), cmd)
  check(`${label} still keeps the payload out of argv`,
    !cmd.includes("password") && !cmd.includes("cardholderName"), cmd)
}

// --- splicing a save into the list ------------------------------------------
//
// The list is updated from the save's own response instead of a full reload;
// these cover the ways that can go wrong.

const envelope = (...objs) => JSON.stringify({
  sshCapability: "unconfirmed", items: objs, sshKeys: []
})

const listed3 = Model.parseItems(JSON.stringify([login, card, identity]))

// An edit replaces in place and does not duplicate.
const renamed = { ...card, name: "Amex" }
const afterEdit = Model.spliceSavedItem(listed3, envelope(renamed))
check("editing an item replaces it rather than adding a second copy",
  afterEdit.length === listed3.length
    && afterEdit.filter(i => i.id === card.id).length === 1,
  JSON.stringify(afterEdit.map(i => i.name)))
check("the replacement carries the saved values",
  afterEdit.find(i => i.id === card.id).name === "Amex",
  JSON.stringify(afterEdit.find(i => i.id === card.id)))

// A create appends and sorts, rather than landing at the end of the list.
const created = { object: "item", id: "44444444-4444-4444-4444-444444444444",
  type: 1, name: "AAA First", favorite: false, login: { username: "a" } }
const afterCreate = Model.spliceSavedItem(listed3, envelope(created))
check("creating an item adds it", afterCreate.length === listed3.length + 1,
  String(afterCreate.length))
// The login fixture is a favourite, so it sorts above everything; the new
// item is expected at the head of the non-favourites, not of the whole list.
check("a created item lands in sort order, not at the end",
  afterCreate.filter(i => !i.favorite)[0].name === "AAA First",
  JSON.stringify(afterCreate.map(i => `${i.name}:${i.favorite}`)))

// Favourites sort above everything, so toggling one has to move the row.
const favourited = { ...card, favorite: true }
const afterFav = Model.spliceSavedItem(listed3, envelope(favourited))
check("favouriting an item moves it into the favourites block",
  afterFav.filter(i => i.favorite).some(i => i.id === card.id)
    && afterFav.findIndex(i => i.id === card.id) < afterFav.findIndex(i => !i.favorite),
  JSON.stringify(afterFav.map(i => `${i.name}:${i.favorite}`)))

// A rename has to re-sort too, or the row stays where its old name put it.
const renamedFirst = { ...login, name: "AAA Renamed" }
const afterRename = Model.spliceSavedItem(listed3, envelope(renamedFirst))
check("renaming an item re-sorts it",
  afterRename.filter(i => i.favorite)[0].name === "AAA Renamed",
  JSON.stringify(afterRename.map(i => `${i.name}:${i.favorite}`)))

// The spliced row must be a list row, not a raw cipher: the list draws
// subtitles and copy buttons off these fields.
const splicedCard = afterEdit.find(i => i.id === card.id)
check("a spliced row is parsed into list shape, not left as a raw cipher",
  splicedCard.typeCode === 3 && splicedCard.subtitle === "Visa •••• 1111"
    && splicedCard.hasPassword === false,
  JSON.stringify(splicedCard))

// --- everything that must fall back to a full reload -------------------------

check("an unrecognised envelope refuses to splice",
  Model.spliceSavedItem(listed3, '{"not":"an envelope"}') === null, "expected null")
check("malformed JSON refuses to splice",
  Model.spliceSavedItem(listed3, "{oops") === null, "expected null")
check("an envelope carrying more than one item refuses to splice",
  Model.spliceSavedItem(listed3, envelope(renamed, created)) === null, "expected null")
check("an empty envelope refuses to splice",
  Model.spliceSavedItem(listed3, envelope()) === null, "expected null")
check("an item with no id refuses to splice",
  Model.spliceSavedItem(listed3, envelope({ ...card, id: "" })) === null, "expected null")

check("the saved-but-unsanitized marker is a fixed sentinel the panel can test",
  typeof Model.savedUnsanitizedMarker() === "string"
    && Model.savedUnsanitizedMarker().length > 0
    && Model.spliceSavedItem(listed3, Model.savedUnsanitizedMarker()) === null,
  Model.savedUnsanitizedMarker())

// The save pipeline must sanitize its response the same way the list does,
// because a save returns a complete decrypted cipher just as `bw list` does.
const createCmd = Model.createItemCommand({ name: "x" })[2]
check("a save runs its response through the strict JSON validator",
  createCmd.includes("TextDecoder") && createCmd.includes("Array.isArray"), createCmd.slice(0, 200))
check("a save runs its response through the allowlisting filter",
  createCmd.includes("ordinary item carries an SSH key subtree")
    && createCmd.includes("sshCapability"), createCmd.slice(0, 200))
check("a failed save is never reported as a success",
  /if \[ "\$__rc" -ne 0 \]; then exit "\$__rc"; fi/.test(createCmd), createCmd)

// --- saving without making the user wait -------------------------------------
//
// The form closes when the save starts and the list shows the item as
// saving until the vault answers.

const draftCard = { type: 3, name: "Draft Visa", notes: "", favorite: false,
  card: { brand: "Visa", number: "4111111111111111", code: "999",
          expMonth: "01", expYear: "2031", cardholderName: "A Person" } }

const provisional = Model.pendingItemId(12345)
const optimistic = Model.optimisticItem(draftCard, provisional)

check("an optimistic row is built through the same parser as a real one",
  optimistic.typeCode === 3 && optimistic.subtitle === "Visa •••• 1111"
    && optimistic.hasPassword === false,
  JSON.stringify(optimistic))
check("and is marked as still saving", optimistic.pending === true, JSON.stringify(optimistic))
check("a provisional id is recognisable as one",
  Model.isPendingItemId(optimistic.id), optimistic.id)
check("a real vault id is not mistaken for a provisional one",
  !Model.isPendingItemId(card.id), card.id)

// The response carries the id the server assigned, which is not the one the
// row went in under.
const createdEnvelope = JSON.stringify({
  sshCapability: "unconfirmed",
  items: [{ ...draftCard, object: "item", id: "55555555-5555-5555-5555-555555555555" }],
  sshKeys: []
})
const withOptimistic = Model.replaceItemById(listed3, provisional, optimistic)
check("the optimistic row goes into the list", withOptimistic.length === listed3.length + 1,
  String(withOptimistic.length))

const settled = Model.spliceSavedItem(withOptimistic, createdEnvelope, provisional)
check("the saved item replaces the provisional row rather than joining it",
  settled.length === withOptimistic.length
    && settled.filter(i => Model.isPendingItemId(i.id)).length === 0,
  JSON.stringify(settled.map(i => i.id)))
check("and lands under the id the server assigned",
  settled.some(i => i.id === "55555555-5555-5555-5555-555555555555"),
  JSON.stringify(settled.map(i => i.id)))
check("the settled row is no longer marked as saving",
  !settled.find(i => i.id === "55555555-5555-5555-5555-555555555555").pending,
  "a row that has landed must not keep spinning")

// A refused save must not leave the panel showing something the vault rejected.
check("a failed create takes its provisional row back out",
  Model.replaceItemById(withOptimistic, provisional, null).length === listed3.length,
  "a create that failed must leave no row behind")

const editOptimistic = Model.optimisticItem(
  { ...card, name: "Renamed while saving" }, card.id)
const duringEdit = Model.replaceItemById(listed3, card.id, editOptimistic)
check("an optimistic edit replaces in place rather than duplicating",
  duringEdit.length === listed3.length, String(duringEdit.length))
check("a failed edit puts the previous row back",
  (() => {
    const before = Model.findItemById(listed3, card.id)
    const after = Model.replaceItemById(duringEdit, card.id, before)
    const restored = Model.findItemById(after, card.id)
    return after.length === listed3.length && restored.name === "Visa" && !restored.pending
  })(), "the list must return to what the vault actually holds")

check("finding an item by id returns null rather than throwing when absent",
  Model.findItemById(listed3, "nope") === null, "expected null")

// --- the fallback path still has to behave ----------------------------------

check("a missing raw object yields null rather than a broken detail",
  Model.itemDetailFromObject(null) === null, String(Model.itemDetailFromObject(null)))
check("so does a non-object", Model.itemDetailFromObject("nope") === null,
  String(Model.itemDetailFromObject("nope")))
check("unparseable JSON still yields null from the string form",
  Model.parseItemDetail("{not json") === null, String(Model.parseItemDetail("{not json")))

// --- the type glyphs -------------------------------------------------------
//
// Pinned by codepoint (a wrong glyph is invisible in review), and the same as
// the type filter chips in Panel.qml.

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
// itemTypeName() maps unknown types to "login", so itemTypeGlyph's default
// shield is unreachable.
check("an unrecognised type is drawn as a login, not as the unreachable shield",
  Model.itemTypeGlyph(99).codePointAt(0) === 0xF030B,
  Model.itemTypeGlyph(99).codePointAt(0).toString(16))

// --- saving an item changes only what the form changed -----------------------
// Saving used to trim the password (a login with edge spaces stopped working),
// trim a note's trailing newlines, replace every website with the first one and
// reset its match rule to the default (which widens browser-extension
// autofill). An unchanged edit, done the way the panel does it
// (Service.startEditItem() fills the form from the list row and the detail,
// saveItemForm() builds the payload), must write back exactly what is stored.
{
  const assert = require("assert")
  const stored = {
    object: "item", id: "11111111-2222-3333-4444-555555555555", type: 1, name: "Bank",
    notes: "line1\n\n  indented\n\n", favorite: false, organizationId: null, folderId: null,
    reprompt: 0, collectionIds: [],
    login: {
      username: "me", password: "  hunter2 \t", totp: null,
      uris: [
        { match: 3, uri: "https://secure.bank.example/login" },
        { match: 1, uri: "https://bank-app.example" },
        { match: null, uri: "androidapp://example.bank" },
        { match: 4, uri: "^https://(www\\.)?bank\\.example/.*$" }
      ]
    }
  }
  const row = Model.parseItems([JSON.parse(JSON.stringify(stored))])[0]
  const detail = Model.itemDetailFromObject(JSON.parse(JSON.stringify(stored)))
  // startEditItem(): the form fields as the panel fills them.
  const formPassword = detail.password
  const formUri = Model.loginUriEntries(row.rawObject.login)[0].uri
  const payload = Model.buildEditPayload(detail, row.name, row.username, formPassword, row.totpKey,
    formUri, row.notes, row.favorite, "", "", [], null, undefined)
  const expected = JSON.parse(JSON.stringify(stored))
  delete expected.collectionIds // a personal item carries none, as before
  let same = true
  try { assert.deepStrictEqual(payload, expected) } catch (e) { same = false }
  check("an unchanged edit writes the item back byte for byte", same,
    JSON.stringify(payload))
  check("an unchanged edit keeps the password's edge spaces",
    payload.login.password === "  hunter2 \t", JSON.stringify(payload.login.password))
  check("an unchanged edit keeps a note's trailing newlines",
    payload.notes === stored.notes, JSON.stringify(payload.notes))
  check("an unchanged edit keeps every website with its match rule",
    JSON.stringify(payload.login.uris) === JSON.stringify(stored.login.uris),
    JSON.stringify(payload.login.uris))

  // A rename is an unchanged edit apart from the name.
  const renamed = Model.buildEditPayload(detail, "Bank (joint)", row.username, formPassword,
    row.totpKey, formUri, row.notes, row.favorite, "", "", [], null, undefined)
  check("a rename changes the name and nothing else",
    renamed.name === "Bank (joint)" && renamed.login.password === stored.login.password
      && renamed.notes === stored.notes
      && JSON.stringify(renamed.login.uris) === JSON.stringify(stored.login.uris),
    JSON.stringify(renamed))

  // The one website field edits the first website only.
  const moved = Model.buildEditPayload(detail, row.name, row.username, formPassword, row.totpKey,
    "https://login.bank.example", row.notes, row.favorite, "", "", [], null, undefined)
  check("changing the first website keeps its match rule and the other websites",
    JSON.stringify(moved.login.uris) === JSON.stringify([{ match: 3, uri: "https://login.bank.example" }]
      .concat(stored.login.uris.slice(1))),
    JSON.stringify(moved.login.uris))
  const cleared = Model.buildEditPayload(detail, row.name, row.username, formPassword, row.totpKey,
    "", row.notes, row.favorite, "", "", [], null, undefined)
  check("clearing the website field drops only the first website",
    JSON.stringify(cleared.login.uris) === JSON.stringify(stored.login.uris.slice(1)),
    JSON.stringify(cleared.login.uris))

  // A changed password is written as typed, edge spaces included.
  const repassed = Model.buildEditPayload(detail, row.name, row.username, "  new pass  ", row.totpKey,
    formUri, row.notes, row.favorite, "", "", [], null, undefined)
  check("a changed password is saved as typed, never trimmed",
    repassed.login.password === "  new pass  ", JSON.stringify(repassed.login.password))

  // A stored null behind an empty box stays null.
  const bare = { id: "b", type: 1, name: "Bare", notes: null, login: { username: null, password: null, totp: null, uris: null } }
  const bareRow = Model.parseItems([bare])[0]
  const bareSaved = Model.buildEditPayload(Model.itemDetailFromObject(bare), bareRow.name, bareRow.username,
    "", bareRow.totpKey, "", bareRow.notes, false, "", "", [], null, undefined)
  check("empty boxes over stored nulls leave the nulls alone",
    bareSaved.notes === null && bareSaved.login.username === null && bareSaved.login.password === null
      && bareSaved.login.totp === null && bareSaved.login.uris === null,
    JSON.stringify(bareSaved))

  // Every website is exposed with its rule, for a form that edits them all.
  check("items and details carry every website with its match rule",
    JSON.stringify(row.uriEntries.map(e => [e.uri, e.match]))
      === JSON.stringify(stored.login.uris.map(u => [u.uri, u.match]))
      && JSON.stringify(detail.uriEntries) === JSON.stringify(row.uriEntries),
    JSON.stringify(row.uriEntries))
  const listEdited = Model.buildEditPayload(detail, row.name, row.username, formPassword, row.totpKey,
    formUri, row.notes, row.favorite, "", "", [], null, undefined,
    [row.uriEntries[1], { uri: " https://new.bank.example ", match: 2, sourceIndex: null },
     Object.assign({}, row.uriEntries[0], { match: 0 })])
  check("a whole-list edit writes the list as shown, rules included",
    JSON.stringify(listEdited.login.uris) === JSON.stringify([
      { match: 1, uri: "https://bank-app.example" },
      { match: 2, uri: "https://new.bank.example" },
      { match: 0, uri: "https://secure.bank.example/login" }]),
    JSON.stringify(listEdited.login.uris))
  const listUnchanged = Model.buildEditPayload(detail, row.name, row.username, formPassword, row.totpKey,
    formUri, row.notes, row.favorite, "", "", [], null, undefined, row.uriEntries)
  check("a whole-list edit that changed nothing writes the stored list back",
    JSON.stringify(listUnchanged.login.uris) === JSON.stringify(stored.login.uris),
    JSON.stringify(listUnchanged.login.uris))

  // The panel wires it: every website loaded at edit, the list passed only
  // when a view edited it as a list.
  const service = readPluginSource("Panel.qml")
  const start = functionBody(service, "startEditItem")
  const save = functionBody(service, "saveItemForm")
  check("the edit form loads every website of the item",
    /formUriEntries\s*=\s*Model\.loginUriEntries\(/.test(start), start)
  check("the save passes the website list only when a view edited it",
    /formUriEntriesEdited\s*\?\s*formUriEntries\s*:\s*undefined/.test(save)
      && /buildEditPayload\([^\n]*formCustomFields, uriEntries\)/.test(save), save)
}

// --- a masked value does not give away its length ------------------------------
// The mask used to repeat one dot per character (up to 16), which showed how
// long a hidden password, card code or PIN was.
check("every hidden value is masked to the same length",
  ["a", "1234", "hunter2", "x".repeat(40)].every(v => Model.maskString(v) === "••••••••"),
  ["a", "1234", "hunter2"].map(v => Model.maskString(v)).join(" | "))
check("nothing to hide masks to nothing", Model.maskString("") === "" && Model.maskString(null) === "", "")

// A key icon on the password controls, pinned per button (a bulk glyph
// replacement once changed them all).
const panelSrc = readPluginSource("Panel.qml")
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

done()
