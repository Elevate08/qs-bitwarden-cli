#!/usr/bin/env node
// With the vault helper, opening any item draws its detail from the list row
// and holds no secret: each value is asked of the helper when it is revealed
// or copied, held only while revealed, and the whole item is fetched only for
// an edit and dropped when the edit ends. The functions run against a
// stand-in vault with a scripted helper (detail-vault.js).
//
//   node tests/detail-on-demand.test.js

const { createSuite } = require("./harness")
const { Model, src, body, makeVault, answer, confirm } = require("./detail-vault")

const { check, eq, done } = createSuite("detail-on-demand")

// What the helper hands the list.
const login = {
  id: "n1", type: 1, name: "Mail", reprompt: 0,
  login: { username: "me", uris: [{ uri: "https://mail.example" }] },
  fields: [{ name: "pin", type: 1 }, { name: "label", value: "plain", type: 0 }, { name: "linked pw", type: 3, linkedId: 101 }],
  attachments: [{ id: "a1", fileName: "scan.pdf", size: "10" }],
  qsbwHeld: { password: true, totp: true, notes: true, cardCode: false, ssn: false, passportNumber: false, licenseNumber: false }
}
const card = {
  id: "c1", type: 3, name: "Visa", reprompt: 0,
  card: { brand: "Visa", number: "1111", cardholderName: "Me", expMonth: "04", expYear: "2030" },
  qsbwHeld: { password: false, totp: false, notes: false, cardCode: true, ssn: false, passportNumber: false, licenseNumber: false }
}
const person = {
  id: "i1", type: 4, name: "Me", reprompt: 0,
  identity: { firstName: "Ada", lastName: "L", email: "ada@example.com", phone: "555", address1: "1 Road", city: "Town" },
  qsbwHeld: { password: false, totp: false, notes: false, cardCode: false, ssn: true, passportNumber: false, licenseNumber: true }
}
const list = () => Model.parseItems([login, card, person])
const row = (v, id) => v.items.find(i => i.id === id)
const MARKERS = ["hunter2", "JBSWY3DPEHPK3PXP", "recovery words", "4111111111111111", "987", "123-45-6789", "L-0042", "4242"]
const full = {
  id: "n1", type: 1, name: "Mail", notes: "recovery words",
  login: { username: "me", password: "hunter2", totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://mail.example" }] },
  fields: [{ name: "pin", value: "4242", type: 1 }, { name: "label", value: "plain", type: 0 }, { name: "linked pw", type: 3, linkedId: 101 }],
  attachments: [{ id: "a1", fileName: "scan.pdf", size: "10" }]
}

// What the shell's state holds, as text: every property but the functions and
// the libraries.
const shellState = v => JSON.stringify(v, (key, value) =>
  typeof value === "function" || key === "Model" || key === "Totp" || key === "root" || key === "queries" || key === "answers" || key === "edits"
    ? undefined : value)
// Forget the questions asked so far, to read the next ones from the start.
const fresh = v => { v.queries.length = 0; v.answers.length = 0 }
const leaks = v => MARKERS.filter(m => shellState(v).includes(m))

// --- the public detail ------------------------------------------------------------------

{
  const v = makeVault(list())
  v.openDetail(row(v, "n1"))
  check("opening a login sends no item query", !v.queries.some(q => q.kind === "item"), JSON.stringify(v.queries))
  check("it shows the public detail: username, website, attachments, visible and hidden field rows",
    v.currentScreen === "detail" && !v.isLoading && v.detailItem.secretsWithheld && v.detailItem.username === "me"
      && v.detailItem.uris[0] === "https://mail.example" && v.detailItem.attachments[0].fileName === "scan.pdf"
      && v.detailItem.fields.length === 3 && v.detailItem.fields[1].value === "plain"
      && v.detailItem.fields[0].sensitive && v.detailItem.fields[0].value !== "" && v.detailItem.fields[2].sensitive,
    JSON.stringify(v.detailItem))
  check("it says which secrets exist", v.detailItem.hasPassword && v.detailItem.hasTotp && v.detailItem.hasNotes,
    JSON.stringify(v.detailItem))
  check("and holds none", v.detailPassword === "" && v.detailItem.notes === "" && v.detailItem.totpKey === "" && leaks(v).length === 0, leaks(v).join())
  check("only the TOTP code is asked for, and by item id",
    v.queries.length === 1 && v.queries[0].kind === "totp" && v.queries[0].args.id === "n1" && Object.keys(v.queries[0].args).join() === "id",
    JSON.stringify(v.queries))
  answer(v, 0, true, { code: "123456", period: 30 })
  eq("the helper's code is shown", v.liveTotp, "123456")
  check("with no key anywhere in the shell", leaks(v).length === 0, shellState(v))
  v.applyTotpCode("n1", "654321")
  eq("a refreshed code replaces it", v.liveTotp, "654321")
  eq("the shell has no key to compute a code from", v.localTotp("n1"), "")
}

{
  const v = makeVault(list())
  v.openDetail(row(v, "c1"))
  const d = v.detailItem
  check("a card shows brand, holder and expiry, and a masked number and code",
    d.card.brand === "Visa" && d.card.cardholderName === "Me" && d.card.expMonth === "04" && d.card.expYear === "2030"
      && d.card.number !== "" && d.card.number !== "1111" && d.card.code !== "", JSON.stringify(d.card))
  check("no query was sent", v.queries.length === 0, JSON.stringify(v.queries))
  v.openDetail(row(v, "i1"))
  const id = v.detailItem.identity
  check("an identity shows name, email, phone and address, and masks only the numbers it has",
    id.firstName === "Ada" && id.email === "ada@example.com" && id.phone === "555" && id.address1 === "1 Road"
      && id.ssn !== "" && id.licenseNumber !== "" && id.passportNumber === "", JSON.stringify(id))
  check("opening them sent no query", v.queries.length === 0, JSON.stringify(v.queries))
}

// --- reveal ------------------------------------------------------------------------------

{
  const v = makeVault(list())
  v.openDetail(row(v, "n1"))
  fresh(v)
  v.toggleFieldReveal("password")
  check("revealing the password asks the helper for that field only",
    v.queries.length === 1 && v.queries[0].kind === "field" && v.queries[0].args.id === "n1" && v.queries[0].args.field === "password"
      && !v.repromptPending, JSON.stringify(v.queries))
  check("nothing is shown until it answers", !v.isFieldRevealed("password") && leaks(v).length === 0, "")
  answer(v, 0, true, "hunter2")
  check("then it shows, and the notes and the rest stay out",
    v.shownSecret("password", "") === "hunter2" && leaks(v).join() === "hunter2" && v.detailItem.notes === "", leaks(v).join())
  v.toggleFieldReveal("password")
  check("hiding it drops the value", !v.isFieldRevealed("password") && leaks(v).length === 0, shellState(v))
  check("and sends nothing", v.queries.length === 1, JSON.stringify(v.queries))

  // A failed fetch.
  v.toggleFieldReveal("notes")
  answer(v, 1, false, null)
  check("a refused fetch reveals nothing and says so", !v.isFieldRevealed("notes") && /could not read/i.test(v.errorMessage), v.errorMessage)
  v.toggleFieldReveal("notes")
  answer(v, 2, true, "recovery words")
  eq("the notes are shown only when revealed", v.shownSecret("notes", ""), "recovery words")
}

{
  const v = makeVault(list())
  v.openDetail(row(v, "n1"))
  fresh(v)
  v.toggleFieldReveal("customField:0")
  eq("a hidden custom field is asked for by its place in the item", v.queries[0].args.field, "customField:0")
  v.toggleFieldReveal("customField:2")
  eq("so is a linked secret", v.queries[1].args.field, "customField:2")
  answer(v, 0, true, "4242")
  answer(v, 1, true, "hunter2")
  check("each is held under its own key", v.shownSecret("customField:0", "") === "4242" && v.shownSecret("customField:2", "") === "hunter2"
    && !v.isFieldRevealed("customField:1"), JSON.stringify(v.revealedFields))
  v.toggleFieldReveal("customField:0")
  check("hiding one leaves the other", !v.isFieldRevealed("customField:0") && v.isFieldRevealed("customField:2"), JSON.stringify(v.revealedFields))
}

{
  // Card number, code and identity numbers: one field each.
  const v = makeVault(list())
  v.openDetail(row(v, "c1"))
  v.toggleFieldReveal("cardCode")
  eq("the card code is asked for as cardCode", v.queries[0].args.field, "cardCode")
  answer(v, 0, true, "987")
  eq("and shown", v.shownSecret("cardCode", "x"), "987")
  eq("the number stays masked", v.shownSecret("cardNumber", v.detailItem.card.number), v.detailItem.card.number)
  v.openDetail(row(v, "i1"))
  check("opening another item drops the revealed value", !v.isFieldRevealed("cardCode") && leaks(v).length === 0, shellState(v))
  v.toggleFieldReveal("ssn")
  v.toggleFieldReveal("licenseNumber")
  eq("identity numbers are asked for by the helper's names", v.queries.slice(-2).map(q => q.args.field).join(), "ssn,licenseNumber")
}

// --- hide, close, leave, lock -------------------------------------------------------------

{
  const reveal = v => {
    v.openDetail(row(v, "n1"))
    fresh(v)
    v.toggleFieldReveal("password")
    v.toggleFieldReveal("notes")
    answer(v, 0, true, "hunter2")
    answer(v, 1, true, "recovery words")
  }
  const cases = [
    ["closing the item (leaving to the list)", v => v.goTo("main")],
    ["closing the panel", v => v.clearRepromptGrant()],
    ["opening another item", v => v.openDetail(row(v, "c1"))],
    ["a lock", v => { v.vaultEpoch++; v.detailItem = null; v.clearRepromptGrant() }]
  ]
  for (const [label, act] of cases) {
    const v = makeVault(list())
    reveal(v)
    check(`${label} drops every revealed value`, leaks(v).join() === "hunter2,recovery words", leaks(v).join())
    act(v)
    check(`${label} drops every revealed value, afterwards`, leaks(v).length === 0 && Object.keys(v.revealedFields).length === 0, shellState(v))
  }
  const v = makeVault(list())
  reveal(v)
  v.openDetail(row(v, "n1"))
  check("reopening the same item shows nothing revealed", Object.keys(v.revealedFields).length === 0 && leaks(v).length === 0, shellState(v))
  check("the answer of a reveal that was in flight is dropped",
    (() => {
      const w = makeVault(list())
      w.openDetail(row(w, "n1"))
      w.toggleFieldReveal("password")
      w.goTo("main")
      answer(w, w.answers.length - 1, true, "hunter2")
      return !w.isFieldRevealed("password") && leaks(w).length === 0
    })(), "")
  check("and so is one that arrives after a lock",
    (() => {
      const w = makeVault(list())
      w.openDetail(row(w, "n1"))
      w.toggleFieldReveal("password")
      w.vaultEpoch++
      answer(w, w.answers.length - 1, true, "hunter2")
      return leaks(w).length === 0
    })(), "")
}

// --- copy ---------------------------------------------------------------------------------

{
  const v = makeVault(list())
  v.openDetail(row(v, "c1"))
  fresh(v)
  v.copyDetailField("cardCode", "Security code")
  check("a copy asks the helper to copy, naming the field and the clear time",
    v.queries.length === 1 && v.queries[0].kind === "copyField"
      && JSON.stringify(v.queries[0].args) === JSON.stringify({ id: "c1", field: "cardCode", clearSec: 30 }), JSON.stringify(v.queries))
  answer(v, 0, true, true)
  check("the value never reaches a shell property or the shell's own clipboard call",
    v.copied.length === 0 && leaks(v).length === 0 && v.flashes.join() === "Security code copied!" && Object.keys(v.revealedFields).length === 0,
    shellState(v))
  v.copyDetailField("cardNumber", "Card number")
  answer(v, 1, false, null)
  check("a failed copy says so", /could not read/i.test(v.errorMessage) && v.flashes.length === 1, v.errorMessage)
}

check("every detail copy button names its field, and none reads a value in the shell",
  !/copyToClipboard\(\s*(root\.)?(vault\.)?(detailPassword|detailItem\.notes|detailCard\.(number|code)|detailIdentity\.(ssn|passportNumber|licenseNumber))/.test(src), "")

// --- edit ---------------------------------------------------------------------------------

{
  const v = makeVault(list())
  v.openDetail(row(v, "n1"))
  fresh(v)
  v.currentScreen = "detail"
  v.startEditItem(v.detailItem)
  check("an edit fetches the whole item", v.queries.length === 1 && v.queries[0].kind === "item" && v.queries[0].args.id === "n1", JSON.stringify(v.queries))
  answer(v, 0, true, JSON.stringify(full))
  check("and opens the form from it", v.edits.length === 1 && v.edits[0].password === "hunter2" && v.edits[0].notes === "recovery words"
    && v.edits[0].rawObject.fields[0].value === "4242", JSON.stringify(v.edits))
  v.goTo("edit")
  check("while the form is open the whole item is held", !v.detailItem.secretsWithheld && leaks(v).includes("hunter2"), "")
  v.goTo("detail")
  check("cancelling (back to the detail) drops it", v.detailItem.secretsWithheld && v.detailPassword === "" && leaks(v).length === 0, shellState(v))
  check("and the TOTP code still shows, from the helper", v.queries.length === 1, JSON.stringify(v.queries))
  check("the edit form is reset when its screen is left", v.formResets >= 1, "")
}

{
  const v = makeVault(list())
  v.openDetail(row(v, "n1"))
  v.currentScreen = "detail"
  v.startEditItem(v.detailItem)
  answer(v, v.answers.length - 1, true, JSON.stringify(full))
  v.goTo("edit")
  v.goTo("main")
  check("saving or leaving to the list drops the whole item too", v.detailItem.secretsWithheld && leaks(v).length === 0, shellState(v))
  const w = makeVault(list())
  w.openDetail(row(w, "n1"))
  w.currentScreen = "detail"
  w.startEditItem(w.detailItem)
  answer(w, w.answers.length - 1, true, JSON.stringify(full))
  w.goTo("edit")
  w.generatorReturnScreen = "edit"
  w.formResets = 0
  w.goTo("generator")
  check("a trip to the generator keeps the form and the item", w.formResets === 0 && !w.detailItem.secretsWithheld, "")
  w.generatorReturnScreen = "main"
  w.goTo("main")
  check("and ending it from there drops both", w.formResets === 1 && w.detailItem.secretsWithheld && leaks(w).length === 0, shellState(w))
}

// --- the TOTP key ---------------------------------------------------------------------------

check("the TOTP code is computed by the helper: no query carries a key, and the list has none",
  /vaultQuery\("totp", \{ id: requested \}/.test(body("fetchTotp")) && row(makeVault(list()), "n1").totpKey === "", body("fetchTotp"))
check("the detail from a helper row has no key to compute a code from",
  makeVault(list()).localTotp("n1") === "", "")

// --- without the helper -------------------------------------------------------------------------

{
  const v = makeVault(Model.parseItems([full]), true)
  v.openDetail(v.items[0])
  check("the detail is built from the list as before, with no query",
    v.queries.length === 0 && v.detailPassword === "hunter2" && v.detailItem.notes === "recovery words" && !v.detailItem.secretsWithheld,
    JSON.stringify(v.detailItem))
  v.toggleFieldReveal("notes")
  eq("a reveal reads the detail", v.shownSecret("notes", ""), "recovery words")
  v.toggleFieldReveal("customField:0")
  eq("a hidden field is read from the detail by its index", v.shownSecret("customField:0", ""), "4242")
  v.copyDetailField("password", "Password")
  check("a copy uses the shell's own clipboard, as before", v.copied.length === 1 && v.copied[0][0] === "hunter2" && v.queries.length === 0, JSON.stringify(v.copied))
  v.goTo("main")
  check("leaving drops what was revealed, and the detail keeps working", Object.keys(v.revealedFields).length === 0 && v.detailPassword === "hunter2", "")
}

done()
