#!/usr/bin/env node
// A re-prompt item's secrets reach the shell only after the master password:
// opening it draws the detail from the list's stripped row, and each value is
// asked of the helper once an action on it has passed the prompt (the whole
// item only for an edit). The functions run here against a stand-in vault
// with a scripted helper (detail-vault.js); detail-on-demand.test.js covers
// items without the flag.
//
//   node tests/reprompt-detail.test.js

const { createSuite } = require("./harness")
const { Model, src, body, makeVault: makeStandIn, answer, confirm } = require("./detail-vault")
const { check, eq, done } = createSuite("reprompt-detail")

// What the helper hands the list: secrets gone, `qsbwHeld` saying which there were.
const full = {
  id: "g1", type: 1, name: "Bank", reprompt: 1, notes: "recovery words",
  login: { username: "me", password: "hunter2", totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://bank.example" }] },
  fields: [{ name: "pin", value: "4242", type: 1 }, { name: "label", value: "plain", type: 0 }],
  attachments: [{ id: "a1", fileName: "scan.pdf", size: "10" }]
}
const stripped = {
  id: "g1", type: 1, name: "Bank", reprompt: 1,
  login: { username: "me", uris: [{ uri: "https://bank.example" }] },
  fields: [{ name: "pin", type: 1 }, { name: "label", value: "plain", type: 0 }],
  attachments: [{ id: "a1", fileName: "scan.pdf", size: "10" }],
  qsbwHeld: { password: true, totp: true, notes: true }
}
const plainStripped = { id: "n1", type: 1, name: "Mail", reprompt: 0,
  login: { username: "me" }, qsbwHeld: { password: true, totp: false, notes: false } }
const listed = Model.parseItems([stripped, plainStripped])
const row = id => listed.find(i => i.id === id)
const SECRETS = ["hunter2", "JBSWY3DPEHPK3PXP", "recovery words", "4242"]

// --- the public detail ------------------------------------------------------------------

const pub = Model.publicItemDetail(row("g1"))
check("the public detail holds none of the secrets", !SECRETS.some(s => JSON.stringify(pub).includes(s)), JSON.stringify(pub))
check("it says which secrets exist, so the rows and buttons are drawn",
  pub.hasPassword && pub.hasTotp && pub.hasNotes && pub.password === "" && pub.notes === "" && pub.totpKey === "",
  JSON.stringify(pub))
check("it keeps the plain fields and marks itself withheld",
  pub.name === "Bank" && pub.username === "me" && pub.reprompt === 1 && pub.uris[0] === "https://bank.example"
    && pub.hasAttachments && pub.attachments[0].id === "a1" && pub.secretsWithheld === true && pub.rawObject === null,
  JSON.stringify(pub))
check("a hidden custom field shows as a row without its value; a plain one keeps it",
  pub.fields.length === 2 && pub.fields[0].sensitive && pub.fields[0].value !== "" && pub.fields[0].value !== "4242"
    && pub.fields[1].value === "plain", JSON.stringify(pub.fields))
const fullDetail = Model.itemDetailFromObject(full)
const again = Model.publicItemDetail(fullDetail)
check("the public view of a loaded detail drops its secrets too",
  !SECRETS.some(s => JSON.stringify(again).includes(s)) && again.hasPassword && again.hasTotp && again.hasNotes
    && again.secretsWithheld === true && again.fields[1].value === "plain", JSON.stringify(again))
check("a loaded detail is not marked withheld", !fullDetail.secretsWithheld && fullDetail.hasNotes === true, "")
const cardRaw = { id: "c1", type: 3, name: "Card", reprompt: 1,
  card: { brand: "Visa", number: "4111111111111111", code: "123", cardholderName: "Me" } }
const cardPub = Model.publicItemDetail(Model.itemDetailFromObject(cardRaw))
check("a card's number and code are not in its public view",
  !/4111111111111111|123/.test(JSON.stringify(cardPub)) && cardPub.card.number !== "" && cardPub.card.code !== "",
  JSON.stringify(cardPub.card))

// --- the shell's side, run against a stand-in vault ------------------------------------------

const makeVault = items => makeStandIn(items || listed)
const answerItem = (v, i, raw) => answer(v, i, true, JSON.stringify(raw))

{
  const v = makeVault()
  v.openDetail(row("g1"))
  check("opening a protected item sends no query and no TOTP request", v.queries.length === 0, JSON.stringify(v.queries))
  check("it draws the public detail and holds no secret",
    v.detailItem && v.detailItem.secretsWithheld && v.detailPassword === "" && v.liveTotp === ""
      && v.currentScreen === "detail" && !v.isLoading && v.detailItem.hasPassword && v.detailItem.hasTotp,
    JSON.stringify(v.detailItem))

  // Reveal the password: prompt, then the one field.
  v.toggleFieldReveal("password")
  check("a reveal asks first and fetches nothing yet", v.repromptPending && v.queries.length === 0, "")
  confirm(v)
  check("once confirmed only that field is requested from the helper",
    v.queries.length === 1 && v.queries[0].kind === "field" && v.queries[0].args.id === "g1"
      && v.queries[0].args.field === "password" && !v.isFieldRevealed("password"),
    JSON.stringify(v.queries))
  answer(v, 0, true, "hunter2")
  check("the value is shown while revealed, and the detail stays public",
    v.isFieldRevealed("password") && v.shownSecret("password", "") === "hunter2"
      && v.detailItem.secretsWithheld && v.detailPassword === "" && v.detailItem.notes === "",
    JSON.stringify(v.detailItem))
  check("revealing the password asks for no TOTP code", v.queries.length === 1, JSON.stringify(v.queries))

  // Clearing the grant takes the secrets out again.
  v.clearRepromptGrant()
  check("clearing the grant empties the revealed values and keeps the public view",
    v.detailItem.secretsWithheld && v.detailPassword === "" && v.liveTotp === "" && !v.isFieldRevealed("password")
      && !SECRETS.some(s => JSON.stringify(v.revealedFields).includes(s)), JSON.stringify(v.revealedFields))
  v.toggleFieldReveal("password")
  check("and the next reveal asks again", v.repromptPending, "")
}

{
  // The code of a flagged item: fetched on its eye, dropped when hidden.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.toggleFieldReveal("totp")
  confirm(v)
  check("the code is asked of the helper (no key, no item) after the prompt",
    v.queries.length === 1 && v.queries[0].kind === "totp" && v.queries[0].args.id === "g1" && v.isFieldRevealed("totp"),
    JSON.stringify(v.queries))
  answer(v, 0, true, { code: "123456", period: 30 })
  eq("it shows", v.liveTotp, "123456")
  v.toggleFieldReveal("totp")
  check("hiding it drops the code, with no prompt", v.liveTotp === "" && !v.isFieldRevealed("totp") && !v.repromptPending, v.liveTotp)
  v.applyTotpCode("g1", "654321")
  eq("a late answer does not refill a hidden code", v.liveTotp, "")
}

{
  // A copy goes through the helper, and the value never comes here.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.copyDetailField("notes", "Notes")
  confirm(v)
  check("a copy after the prompt asks the helper to copy that one field",
    v.queries.length === 1 && v.queries[0].kind === "copyField" && v.queries[0].args.field === "notes"
      && v.queries[0].args.clearSec === 30, JSON.stringify(v.queries))
  answer(v, 0, true, true)
  check("the shell holds no value and says it copied",
    v.copied.length === 0 && v.flashes.join() === "Notes copied!" && v.revealedFields.notes === undefined, JSON.stringify(v.flashes))
}

{
  // Stale answers.
  const stale = (label, change) => {
    const v = makeVault()
    v.openDetail(row("g1"))
    v.toggleFieldReveal("password")
    confirm(v)
    change(v)
    answer(v, 0, true, "hunter2")
    check(label, !v.isFieldRevealed("password") && !SECRETS.some(s => JSON.stringify(v.revealedFields).includes(s)),
      JSON.stringify(v.revealedFields))
  }
  stale("an answer after another item was opened is dropped", v => v.openDetail(row("n1")))
  stale("an answer after the detail was closed is dropped", v => { v.currentScreen = "main"; v.clearRepromptGrant() })
  stale("an answer after the grant was cleared is dropped", v => v.clearRepromptGrant())
  stale("an answer after a lock is dropped", v => { v.vaultEpoch++; v.detailItem = null; v.clearRepromptGrant() })
}

{
  // Reopening the confirmed item keeps the confirmation, not the values.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.toggleFieldReveal("password")
  confirm(v)
  answer(v, 0, true, "hunter2")
  v.openDetail(row("g1"))
  check("reopening the confirmed item shows nothing revealed", !v.isFieldRevealed("password") && v.detailItem.secretsWithheld,
    JSON.stringify(v.revealedFields))
  check("and the code of a flagged item is still not fetched", v.queries.length === 1, JSON.stringify(v.queries))
}

{
  // Fallback: the list holds the raw item.
  const v = makeVault(Model.parseItems([full]))
  v.vaultHelperActive = false
  v.openDetail(v.items[0])
  check("without the helper the detail is built from the list as before",
    v.queries.length === 0 && v.detailPassword === "hunter2" && !v.detailItem.secretsWithheld, JSON.stringify(v.detailItem))
  v.clearRepromptGrant()
  check("and clearing the grant leaves it working", v.detailPassword === "hunter2", "")
  v.toggleFieldReveal("password")
  confirm(v)
  check("a reveal reads the detail, with no helper query", v.shownSecret("password", "") === "hunter2" && v.queries.length === 0, "")
}

{
  // Edit runs on the fetched item.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.startEditItem(v.detailItem)
  confirm(v)
  check("an edit waits for the fetch", v.edits.length === 0 && v.queries.length === 1 && v.queries[0].kind === "item", JSON.stringify(v.queries))
  answerItem(v, 0, full)
  check("then opens the form from the whole item",
    v.edits.length === 1 && v.edits[0].password === "hunter2" && v.edits[0].rawObject.login.password === "hunter2",
    JSON.stringify(v.edits))
  v.clearRepromptGrant()
  check("clearing the grant puts the public view back", v.detailItem.secretsWithheld && v.detailPassword === "", JSON.stringify(v.detailItem))
  v.saveItemForm()
  check("a form kept past the grant cannot be saved from the public view",
    v.pendingSave === null && /open the item again/i.test(v.errorMessage), v.errorMessage)
}

check("a copy of a TOTP code goes through the prompt, not a fetch of the item",
  /withReprompt\(item, function\(\) \{ root\.copyTotpCodeNow\(item\) \}\)/.test(body("copyDetailTotp")), body("copyDetailTotp"))

// --- wiring in the source ------------------------------------------------------------------

check("a late TOTP answer does not refill a hidden code",
  /totpWanted\(detailItem\)/.test(body("applyTotpCode")), body("applyTotpCode"))
const timer = src.slice(src.indexOf("id: totpCountdownTimer"), src.indexOf("id: totpCountdownTimer") + 700)
check("the countdown does not refetch a hidden TOTP", /root\.totpWanted\(root\.detailItem\)/.test(timer), timer)
const screen = src.slice(src.indexOf("onCurrentScreenChanged:"), src.indexOf("onCurrentScreenChanged:") + 1400)
check("leaving the item clears the grant and with it the secrets", /if \(!inItem\) \{\s*clearRepromptGrant\(\)/.test(screen), screen)
check("every secret copy on the detail screen names its field, not a value",
  !/copyDetailSecret\(\s*(function|root\.|detailPassword|liveTotp|detailCard|detailIdentity|detailItem\.notes|value)/.test(src),
  "copyDetailSecret was passed a value or a reader")
check("the TOTP button and key use the vault's own copy",
  /copyDetailTotp\(\)/.test(src.slice(src.indexOf("id: copyTotpBtn"), src.indexOf("id: copyTotpBtn") + 500)), "")

done()
