#!/usr/bin/env node
// A re-prompt item's secrets reach the shell only after the master password:
// opening it draws the detail from the list's stripped row, and the helper is
// asked for the whole item once an action on it has passed the prompt. The
// functions run here against a stand-in vault with a scripted helper.
//
//   node tests/reprompt-detail.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")

const Model = loadModule()
const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)
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

const names = ["itemNeedsReprompt", "repromptSatisfied", "withReprompt", "submitReprompt", "cancelReprompt",
  "clearRepromptGrant", "withholdDetailSecrets", "withRevealedDetail", "loadFullDetail", "openDetail",
  "onDetailFinished", "toggleFieldReveal", "setFieldRevealed", "isFieldRevealed", "startEditItem",
  "copyDetailTotp", "applyTotpCode", "saveItemForm"]
function makeVault(items) {
  const v = {
    Model,
    items: items || listed, vaultHelperActive: true, status: "unlocked", vaultEpoch: 3, currentScreen: "main",
    repromptPending: false, repromptItemId: "", repromptItemName: "", repromptError: "", repromptBusy: false,
    repromptCallback: null, repromptEpoch: -1, repromptVerifiedId: "", repromptActionId: "",
    detailItem: null, detailPassword: "", liveTotp: "", revealedFields: {}, errorMessage: "", isLoading: false,
    showDeleteConfirm: false, attachmentQueue: [], attachmentSaved: {}, detailRequestedId: "",
    totpFollowupActive: false, totpFollowupItem: null, totpFollowupCode: "", totpCopyItemId: "",
    pendingSave: null, formIsEditing: true, formItemId: "g1",
    queries: [], totps: [], answers: [], copied: [], edits: [], verify: null,
    closeFilterGroup() {}, learnFromPick() {}, beginVaultRead() {}, vaultReadIsStale() { return false },
    fetchTotp(id) { v.totps.push(id) },
    copyToClipboard(value, label) { v.copied.push([value, label]) },
    startEditItemNow(item) { v.edits.push(item) },
    verifyMasterPassword(pw, done) { v.verify = done },
    // The helper answers when the test says so.
    vaultQuery(kind, args, cb) { v.queries.push({ kind, args }); v.answers.push(cb) }
  }
  v.root = v
  const make = new Function("root", "with (root) {\n" + names.map(body).join("\n")
    + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")
  Object.assign(v, make(v))
  return v
}
const answerItem = (v, i, raw) => v.answers[i](true, JSON.stringify(raw))
const confirm = v => { v.submitReprompt("pw"); v.verify(true) }

{
  const v = makeVault()
  v.openDetail(row("g1"))
  check("opening a protected item sends no item or TOTP query",
    v.queries.length === 0 && v.totps.length === 0, JSON.stringify(v.queries))
  check("it draws the public detail and holds no secret",
    v.detailItem && v.detailItem.secretsWithheld && v.detailPassword === "" && v.liveTotp === ""
      && v.currentScreen === "detail" && !v.isLoading && v.detailItem.hasPassword && v.detailItem.hasTotp,
    JSON.stringify(v.detailItem))

  // Reveal the password: prompt, then fetch, then the action.
  v.toggleFieldReveal("password")
  check("a reveal asks first and fetches nothing yet", v.repromptPending && v.queries.length === 0, "")
  confirm(v)
  check("once confirmed the item is requested from the helper",
    v.queries.length === 1 && v.queries[0].kind === "item" && v.queries[0].args.id === "g1" && !v.isFieldRevealed("password"),
    JSON.stringify(v.queries))
  answerItem(v, 0, full)
  check("the fetched item replaces the public view and the reveal runs",
    !v.detailItem.secretsWithheld && v.detailPassword === "hunter2" && v.isFieldRevealed("password")
      && v.detailItem.notes === "recovery words", JSON.stringify(v.detailItem))
  check("its TOTP is asked for once the item is loaded", v.totps.join() === "g1", v.totps.join())

  // Clearing the grant takes the secrets out again.
  v.liveTotp = "123456"
  v.clearRepromptGrant()
  check("clearing the grant empties the secrets and restores the public view",
    v.detailItem.secretsWithheld && v.detailPassword === "" && v.liveTotp === "" && !v.isFieldRevealed("password")
      && !SECRETS.some(s => JSON.stringify(v.detailItem).includes(s)), JSON.stringify(v.detailItem))
  v.toggleFieldReveal("password")
  check("and the next reveal asks again", v.repromptPending, "")
}

{
  // A copy waits for the fetched value.
  const v = makeVault()
  v.openDetail(row("g1"))
  let value = ""
  v.withRevealedDetail(v.detailItem, () => { value = v.detailPassword })
  confirm(v)
  check("the action has not run before the item arrives", value === "" && v.queries.length === 1, value)
  answerItem(v, 0, full)
  eq("it runs with the fetched value", value, "hunter2")
  let second = ""
  v.withRevealedDetail(v.detailItem, () => { second = v.detailPassword })
  check("a loaded item runs further actions at once, with no second fetch", second === "hunter2" && v.queries.length === 1, "")
}

{
  // Stale answers.
  const stale = (label, change) => {
    const v = makeVault()
    v.openDetail(row("g1"))
    let ran = 0
    v.withRevealedDetail(v.detailItem, () => ran++)
    confirm(v)
    change(v)
    answerItem(v, 0, full)
    check(label, ran === 0 && v.detailPassword === "" && !SECRETS.some(s => JSON.stringify(v.detailItem || "").includes(s)),
      JSON.stringify([ran, v.detailPassword, v.detailItem]))
  }
  stale("an answer after another item was opened is dropped", v => v.openDetail(row("n1")))
  stale("an answer after the detail was closed is dropped", v => { v.currentScreen = "main"; v.clearRepromptGrant() })
  stale("an answer after the grant was cleared is dropped", v => v.clearRepromptGrant())
  stale("an answer after a lock is dropped", v => { v.vaultEpoch++; v.detailItem = null; v.clearRepromptGrant() })
}

{
  // Not protected: one step, as before.
  const v = makeVault()
  v.openDetail(row("n1"))
  check("an unprotected item still loads in one step",
    v.queries.length === 1 && v.queries[0].kind === "item" && v.queries[0].args.id === "n1" && v.isLoading, JSON.stringify(v.queries))
  answerItem(v, 0, { id: "n1", type: 1, name: "Mail", reprompt: 0, login: { username: "me", password: "pw" } })
  check("and shows its password at once", v.detailPassword === "pw" && !v.detailItem.secretsWithheld, "")
  let ran = 0
  v.withRevealedDetail(v.detailItem, () => ran++)
  check("its actions run without a prompt", ran === 1 && !v.repromptPending && v.queries.length === 1, "")
  v.clearRepromptGrant()
  check("clearing a grant leaves it alone", v.detailPassword === "pw", "")
}

{
  // Reopening the confirmed item loads it whole.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.withRevealedDetail(v.detailItem, () => {})
  confirm(v)
  answerItem(v, 0, full)
  v.openDetail(row("g1"))
  check("reopening the confirmed item loads it in one step", v.queries.length === 2 && v.queries[1].kind === "item", JSON.stringify(v.queries))
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
}

{
  // Edit runs on the fetched item.
  const v = makeVault()
  v.openDetail(row("g1"))
  v.startEditItem(v.detailItem)
  confirm(v)
  check("an edit waits for the fetch", v.edits.length === 0 && v.queries.length === 1, "")
  answerItem(v, 0, full)
  check("then opens the form from the whole item",
    v.edits.length === 1 && v.edits[0].password === "hunter2" && v.edits[0].rawObject.login.password === "hunter2",
    JSON.stringify(v.edits))
  v.clearRepromptGrant()
  v.saveItemForm()
  check("a form kept past the grant cannot be saved from the public view",
    v.pendingSave === null && /open the item again/i.test(v.errorMessage), v.errorMessage)
}

check("a copy of a TOTP code goes through the fetch",
  /withRevealedDetail\(item, function\(\) \{ root\.copyTotpCodeNow\(item\) \}\)/.test(body("copyDetailTotp")), body("copyDetailTotp"))

// --- wiring in the source ------------------------------------------------------------------

check("a late TOTP answer does not refill a withheld detail",
  /!detailItem\.secretsWithheld/.test(body("applyTotpCode")), body("applyTotpCode"))
const timer = src.slice(src.indexOf("id: totpCountdownTimer"), src.indexOf("id: totpCountdownTimer") + 700)
check("the countdown does not refetch a withheld TOTP", /!root\.detailItem\.secretsWithheld/.test(timer), timer)
const screen = src.slice(src.indexOf("onCurrentScreenChanged:"), src.indexOf("onCurrentScreenChanged:") + 1400)
check("leaving the item clears the grant and with it the secrets", /if \(!inItem\) clearRepromptGrant\(\)/.test(screen), screen)
check("every secret copy on the detail screen reads its value after the fetch",
  !/copyDetailSecret\(\s*(root\.)?(detailPassword|liveTotp|detailCard|detailIdentity|detailItem\.notes|value)/.test(src),
  "copyDetailSecret was passed a value read before the prompt")
check("the TOTP button and key use the vault's own copy",
  /copyDetailTotp\(\)/.test(src.slice(src.indexOf("id: copyTotpBtn"), src.indexOf("id: copyTotpBtn") + 500)), "")

done()
