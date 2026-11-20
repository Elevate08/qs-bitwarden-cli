#!/usr/bin/env node
// The master-password re-prompt across a reload of the list. A sync can turn
// an item's re-prompt on while its detail is open, and the vault helper
// replaces its items before the panel has the new list. So: the list that is
// accepted is checked against the open detail (gone: back to the list; asks
// now and did not: what was revealed is dropped and the detail is opened
// again, behind the prompt). An item whose flag did not change, or whose
// re-prompt was confirmed, behaves as it did.
//
// The service's functions run against the stand-in of detail-vault.js.
//
//   node tests/reprompt-reload.test.js

const { createSuite, read } = require("./harness")
const { Model, makeVault: makeStandIn, answer, confirm } = require("./detail-vault")
const { check, eq, done } = createSuite("reprompt-reload")

// Rows as the helper hands them over: no secret, `qsbwHeld` saying which exist.
const stripped = (id, name, reprompt, totp) => ({ id, type: 1, name, reprompt,
  login: { username: "me", uris: [{ uri: "https://" + name.toLowerCase() + ".example" }] },
  qsbwHeld: { password: true, totp: Boolean(totp), notes: false } })
const VAULT = [stripped("n1", "Mail", 0, true), stripped("g1", "Bank", 1, false), stripped("p1", "Plain", 0, false)]
const envelope = rows => JSON.stringify({ sshCapability: "unconfirmed", sshKeys: [], items: rows })
const withFlag = (id, reprompt) => VAULT.map(r => r.id === id ? Object.assign({}, r, { reprompt }) : r)

function makeVault(fallback) {
  const v = makeStandIn(Model.parseItems(VAULT), fallback)
  // QML runs onCurrentScreenChanged whenever the screen changes; so does this.
  let screen = v.currentScreen
  Object.defineProperty(v, "currentScreen", {
    get() { return screen },
    set(next) { if (next === screen) return; screen = next; v.goTo(next) }
  })
  v.row = id => Model.findItemById(v.items, id)
  // A list read: running from start() until land(), which is what the
  // exit handler does with a good answer.
  v.start = () => { v.listProc.command = Model.sanitizedListCommand({ agentBranch: false }); v.listProc.running = true }
  v.land = rows => { v.listProc.running = false; v.readEpochs.items = v.vaultEpoch; v.onListFinished(envelope(rows)) }
  v.reload = rows => { v.start(); v.land(rows) }
  v.kinds = () => v.queries.map(q => q.kind).join()
  return v
}

// --- (a) the accepted list against the open detail -----------------------------------------
{
  const v = makeVault()
  v.openDetail(v.row("n1"))
  v.toggleFieldReveal("password")
  answer(v, v.answers.length - 1, true, "hunter2")
  check("premise: an ordinary item reveals without a prompt, and its code is fetched on opening",
    v.isFieldRevealed("password") && !v.repromptPending && v.kinds() === "totp,field", v.kinds())
  answer(v, 0, true, { code: "123456", period: 30 })
  eq("premise: the code shows", v.liveTotp, "123456")
  const asked = v.queries.length
  v.reload(withFlag("n1", 1))
  check("a reload that turns the re-prompt on drops what was revealed and the code",
    !v.isFieldRevealed("password") && JSON.stringify(v.revealedFields) === "{}" && v.liveTotp === "" && v.detailPassword === "",
    JSON.stringify(v.revealedFields) + v.liveTotp)
  check("the detail stays open, now the flagged item's public view",
    v.currentScreen === "detail" && v.detailItem && v.detailItem.id === "n1" && v.detailItem.reprompt === 1
      && v.detailItem.secretsWithheld === true, JSON.stringify(v.detailItem))
  check("reopening it asks the helper nothing: no code for an item that now asks first",
    v.queries.length === asked && !v.repromptPending && v.repromptVerifiedId === "", v.kinds())
  v.copyDetailField("password", "Password")
  check("the next copy asks for the master password first", v.repromptPending && v.repromptItemId === "n1" && v.queries.length === asked, v.kinds())
  confirm(v)
  check("and reads only once it is confirmed", v.queries.length === asked + 1 && v.queries[asked].kind === "copyField", v.kinds())
  v.toggleFieldReveal("totp")
  check("its code is then fetched on its eye, under that confirmation", v.queries.length === asked + 2 && v.queries[asked + 1].kind === "totp", v.kinds())
}
{
  // A value asked for before the read started, answered after the list turned the flag on.
  const v = makeVault()
  v.openDetail(v.row("p1"))
  v.toggleFieldReveal("password")
  v.startEditItem(v.detailItem)
  check("premise: both were asked of the helper", v.kinds() === "field,item", v.kinds())
  v.reload(withFlag("p1", 1))
  answer(v, 0, true, "hunter2")
  answer(v, 1, true, JSON.stringify({ id: "p1", type: 1, name: "Plain", reprompt: 1, login: { password: "hunter2" } }))
  check("a late answer is not shown on, or loaded into, an item that asks now",
    !v.isFieldRevealed("password") && v.detailItem.secretsWithheld === true && v.edits.length === 0 && v.detailPassword === "",
    JSON.stringify(v.revealedFields))
}
{
  // The flag did not change: nothing about the open detail does.
  const v = makeVault()
  v.openDetail(v.row("p1"))
  v.toggleFieldReveal("password"); answer(v, 0, true, "hunter2")
  const detail = v.detailItem
  v.reload(VAULT)
  check("an item whose flag did not change keeps its detail and what is revealed",
    v.detailItem === detail && v.shownSecret("password", "") === "hunter2" && v.currentScreen === "detail" && v.flashes.length === 0,
    JSON.stringify(v.revealedFields))
  v.copyDetailField("password", "Password")
  check("and copies as before, with no prompt", !v.repromptPending && v.queries[v.queries.length - 1].kind === "copyField", v.kinds())

  // A flagged item whose re-prompt was confirmed keeps the confirmation.
  const g = makeVault()
  g.openDetail(g.row("g1"))
  g.toggleFieldReveal("password"); confirm(g); answer(g, 0, true, "hunter2")
  const flagged = g.detailItem
  g.reload(VAULT)
  check("a confirmed re-prompt survives a reload that leaves the flag on",
    g.detailItem === flagged && g.repromptVerifiedId === "g1" && g.shownSecret("password", "") === "hunter2", g.repromptVerifiedId)
  g.copyDetailField("password", "Password")
  check("so the next action needs no second prompt", !g.repromptPending && g.queries.length === 2, g.kinds())

  // Turned off: nothing to take away.
  const o = makeVault()
  o.openDetail(o.row("g1"))
  const before = o.detailItem
  o.reload(withFlag("g1", 0))
  check("a reload that turns the re-prompt off leaves the open detail as it is", o.detailItem === before && o.currentScreen === "detail")
}
{
  // The item is gone from the vault.
  const v = makeVault()
  v.openDetail(v.row("p1"))
  v.toggleFieldReveal("password"); answer(v, 0, true, "hunter2")
  v.reload(VAULT.filter(r => r.id !== "p1"))
  check("an item the reload no longer lists goes back to the list, with nothing revealed left",
    v.currentScreen === "main" && JSON.stringify(v.revealedFields) === "{}" && v.detailPassword === ""
      && v.flashes.indexOf("That item is no longer in the vault") !== -1, v.currentScreen)
  eq("and its detail is not kept behind the list", v.detailItem, null)
  // Its code, asked for before the list, answers after.
  const t = makeVault()
  t.openDetail(t.row("n1"))
  t.reload(VAULT.filter(r => r.id !== "n1"))
  answer(t, 0, true, { code: "123456", period: 30 })
  eq("a code answering after its item is gone is not kept", t.liveTotp, "")
  const e = makeVault()
  e.openDetail(e.row("n1"))
  e.currentScreen = "main"                       // left with Escape: the detail object stays behind
  answer(e, 0, true, { code: "123456", period: 30 })
  check("nor is one answering after its detail was left", e.liveTotp === "" && e.detailItem !== null, e.liveTotp)
  const h = makeVault()
  h.openDetail(h.row("p1")); h.currentScreen = "history"
  h.reload(VAULT.filter(r => r.id !== "p1"))
  eq("from its password history too", h.currentScreen, "main")
  const m = makeVault()
  m.openDetail(m.row("p1")); m.currentScreen = "main"
  m.reload(VAULT.filter(r => r.id !== "p1"))
  check("a detail no longer on screen is not acted on", m.currentScreen === "main" && m.flashes.length === 0)
}
{
  // The edit form of the open item holds the whole item.
  const v = makeVault()
  v.openDetail(v.row("p1")); v.formIsEditing = true; v.formItemId = "p1"; v.currentScreen = "edit"
  const resets = v.formResets
  v.reload(withFlag("p1", 1))
  check("an edit form open on an item that asks now is closed, back to its gated detail",
    v.currentScreen === "detail" && v.formResets > resets && v.detailItem.secretsWithheld === true && v.detailItem.reprompt === 1,
    v.currentScreen)
  const g = makeVault()
  g.openDetail(g.row("p1")); g.formIsEditing = true; g.formItemId = "p1"; g.currentScreen = "edit"
  g.reload(VAULT.filter(r => r.id !== "p1"))
  check("an item gone under its edit form closes the form too: back to the list, nothing of it kept",
    g.currentScreen === "main" && g.detailItem === null && g.formResets > 0
      && g.flashes.indexOf("That item is no longer in the vault") !== -1, g.currentScreen)
  // A new-item form, with an older detail still in memory behind it.
  const n = makeVault()
  n.openDetail(n.row("p1")); n.formIsEditing = false; n.formItemId = ""; n.currentScreen = "edit"
  n.reload(withFlag("p1", 1))
  eq("a new-item form is not closed for the item last looked at", n.currentScreen, "edit")
}
{
  // An SSH approval shown in the panel covers the detail.
  const v = makeVault()
  v.openDetail(v.row("p1"))
  v.toggleFieldReveal("password"); answer(v, 0, true, "hunter2")
  v.screenBeforeSshApproval = "detail"; v.currentScreen = "sshApproval"
  v.reload(withFlag("p1", 1))
  check("under an SSH approval nothing revealed is left and the approval keeps the screen",
    JSON.stringify(v.revealedFields) === "{}" && v.detailPassword === "" && v.currentScreen === "sshApproval", JSON.stringify(v.revealedFields))
  eq("which then returns to the list, not to the old detail", v.screenBeforeSshApproval, "main")
  eq("and the old detail is not kept under it", v.detailItem, null)
  const f = makeVault()
  f.openDetail(f.row("p1")); f.formIsEditing = true; f.formItemId = "p1"; f.currentScreen = "edit"
  f.screenBeforeSshApproval = "edit"; f.currentScreen = "sshApproval"
  const resets = f.formResets
  f.reload(withFlag("p1", 1))
  check("an edit form under the approval is emptied at once, not when the approval is answered",
    f.formResets > resets && f.screenBeforeSshApproval === "main" && f.detailItem === null && f.currentScreen === "sshApproval", String(f.formResets))
}
{
  // Accounts and Settings cover the detail too, and a list accepted under
  // them is not checked against it: returning to it is.
  for (const [cover, saved, close] of [["accounts", "screenBeforeAccounts", "closeAccounts"], ["settings", "screenBeforeSettings", "closeSettings"]]) {
    const v = makeVault()
    v.openDetail(v.row("p1"))
    v.toggleFieldReveal("password"); answer(v, 0, true, "hunter2")
    v[saved] = "detail"; v.currentScreen = cover
    v.reload(withFlag("p1", 1))
    check(`premise: under ${cover} the old detail is still what is held`, v.detailItem.reprompt === 0 && v.currentScreen === cover)
    v[close]()
    check(`returning from ${cover} re-gates a detail that asks now`,
      v.currentScreen === "detail" && v.detailItem.reprompt === 1 && v.detailItem.secretsWithheld === true
        && JSON.stringify(v.revealedFields) === "{}", JSON.stringify(v.detailItem))
    const asked = v.queries.length
    v.copyDetailField("password", "Password")
    check(`and a copy there asks first (${cover})`, v.repromptPending && v.queries.length === asked, v.kinds())
    const g = makeVault()
    g.openDetail(g.row("p1"))
    g[saved] = "detail"; g.currentScreen = cover
    g.reload(VAULT.filter(r => r.id !== "p1"))
    g[close]()
    check(`returning from ${cover} to an item that is gone lands on the list`,
      g.currentScreen === "main" && g.detailItem === null, g.currentScreen)
  }
}
{
  // The gate goes by the row the list has now, whatever object it is handed.
  const v = makeVault()
  const old = v.row("p1")                        // a row still drawn from before the refresh (a search waiting for the helper)
  v.reload(withFlag("p1", 1))
  let ran = 0
  v.withReprompt(old, () => { ran++ })
  check("a row from before the refresh asks, by the flag the list has now", ran === 0 && v.repromptPending && v.repromptItemId === "p1")
  v.cancelReprompt()
  check("and is not satisfied for a helper's late answer either", v.repromptSatisfied(old) === false && v.repromptSatisfied(v.row("p1")) === false)
  v.withReprompt({ id: Model.pendingItemId(9), name: "New", reprompt: 0 }, () => { ran++ })
  eq("an item in no list (one being created) goes by its own flag: no prompt", ran, 1)
  v.withReprompt({ id: Model.pendingItemId(9), name: "New", reprompt: 1 }, () => { ran++ })
  check("or a prompt, if that is what it says", ran === 1 && v.repromptPending)
  v.cancelReprompt()
  v.withReprompt(v.row("n1"), () => { ran++ })
  eq("an unflagged row runs at once, as ever", ran, 2)
}
{
  // "Reopen" after a refused save: the draft holds the password and TOTP key.
  const draft = id => ({ isEditing: true, itemId: id, name: "Plain", password: "hunter2", totp: "SEED" })
  const refused = (id, rows) => {
    const v = makeVault()
    v.failedSave = { name: "Plain", form: draft(id) }
    v.errorMessage = "Could not save Plain. refused"
    if (rows) v.reload(rows)
    v.reopenFailedSave()
    return v
  }
  const same = refused("p1", null)
  check("a refused edit reopens with its draft", same.restored.length === 1 && same.restored[0].password === "hunter2"
    && same.failedSave === null && same.errorMessage === "", same.errorMessage)
  const gone = refused("p1", VAULT.filter(r => r.id !== "p1"))
  check("not for an item a later list no longer has: the draft is discarded",
    gone.restored.length === 0 && gone.failedSave === null && gone.flashes.indexOf("That item is no longer in the vault") !== -1, String(gone.restored.length))
  const asks = refused("p1", withFlag("p1", 1))
  check("and behind the prompt for one a later list protects",
    asks.restored.length === 0 && asks.repromptPending && asks.repromptItemId === "p1" && asks.failedSave !== null, String(asks.restored.length))
  confirm(asks)
  check("which reopens it once confirmed", asks.restored.length === 1 && asks.failedSave === null)
  const created = makeVault()
  created.failedSave = { name: "New", form: { isEditing: false, itemId: "", name: "New", password: "pw" } }
  created.reopenFailedSave()
  eq("a refused create has no item to check: its draft reopens", created.restored.length, 1)
}
{
  // The TOTP follow-up to a password copy, across a reload.
  const followed = id => {
    const v = makeVault()
    v.totpFollowupItem = v.row(id); v.totpFollowupActive = true; v.totpFollowupCode = "123456"; v.totpCopyItemId = id
    return v
  }
  const v = followed("n1")
  v.reload(VAULT)
  check("a reload that changes nothing keeps the follow-up", v.totpFollowupActive && v.totpFollowupItem !== null && v.totpCopyItemId === "n1")
  v.reload(withFlag("n1", 1))
  check("one that turns the item's re-prompt on ends it: no code held, no copy on its way",
    v.totpFollowupItem === null && v.totpFollowupActive === false && v.totpFollowupCode === "" && v.totpCopyItemId === "", v.totpCopyItemId)
  const g = followed("n1")
  g.reload(VAULT.filter(r => r.id !== "n1"))
  check("so does one that no longer has the item", g.totpFollowupItem === null && g.totpCopyItemId === "")
  const p = followed("g1")                       // armed after its prompt
  p.reload(VAULT)
  check("a follow-up armed for an item that asked then is kept", p.totpFollowupActive && p.totpFollowupItem !== null)
}
{
  // A new item's detail, still on its provisional row: followCreatedItem()'s business.
  const v = makeVault()
  const provisional = Model.pendingItemId(5)
  v.currentScreen = "detail"; v.detailItem = { id: provisional, name: "New", pending: true }
  v.reload(VAULT)
  check("a detail on a provisional row is left for its save", v.currentScreen === "detail" && v.detailItem.id === provisional)
}

// --- (b) what the accepted list leaves alone, and what it re-gates ----------------------------
{
  // The list lands with the flag unchanged: the open item is as it was.
  const v = makeVault()
  v.openDetail(v.row("n1"))
  answer(v, 0, true, { code: "123456", period: 30 })
  const asked = v.queries.length
  v.reload(VAULT)
  check("an accepted list fetches the open item's code afresh, from the vault the helper has now",
    v.queries.length === asked + 1 && v.queries[asked].kind === "totp" && v.totpWanted(v.detailItem), v.kinds())
  eq("the code on screen stays until that answer", v.liveTotp, "123456")
  v.copyDetailField("password", "Password")
  check("and a copy goes through, with no prompt",
    v.queries.length === asked + 2 && v.queries[asked + 1].kind === "copyField" && !v.repromptPending && v.errorMessage === "", v.kinds())
}
{
  // An item opened while a list read runs has its code asked for as ever;
  // the list that says it asks first takes the code down.
  const v = makeVault()
  v.start()
  v.openDetail(v.row("n1"))
  check("an item opened during a list read is not held back", v.detailItem.id === "n1" && v.kinds() === "totp", v.kinds())
  v.land(withFlag("n1", 1))
  check("the list that protects it re-gates it: no code wanted, none on screen",
    v.detailItem.reprompt === 1 && v.totpWanted(v.detailItem) === false && v.liveTotp === "", v.kinds())
  answer(v, 0, true, { code: "654321", period: 30 })
  eq("and the code asked for before the list, answering late, is not shown", v.liveTotp, "")
}
{
  // A copy while the read runs is not refused; once the list is in, it asks.
  const v = makeVault()
  v.openDetail(v.row("p1"))
  v.start()
  v.copyDetailField("password", "Password")
  check("a copy during a list read goes to the helper as ever", v.kinds() === "copyField" && v.errorMessage === "", v.kinds() + " | " + v.errorMessage)
  v.land(withFlag("p1", 1))
  v.copyDetailField("password", "Password")
  check("after the list it asks for the master password", v.repromptPending && v.kinds() === "copyField", v.kinds())
}
{
  // A flagged item: its prompt, or its confirmation, stands across a reload.
  const v = makeVault()
  v.openDetail(v.row("g1"))
  v.toggleFieldReveal("password"); confirm(v); answer(v, 0, true, "hunter2")
  v.reload(VAULT)
  v.copyDetailField("password", "Password")
  check("a confirmed re-prompt item copies as ever", v.queries.length === 2 && v.queries[1].kind === "copyField" && v.errorMessage === "", v.errorMessage)
  const u = makeVault()
  u.openDetail(u.row("g1"))
  u.reload(VAULT)
  u.copyDetailField("password", "Password")
  check("an unconfirmed one asks for the master password as ever", u.repromptPending && u.queries.length === 0 && u.errorMessage === "", u.errorMessage)
}

// --- (c) an auto-type armed before the reload ------------------------------------------------
{
  // Armed from the list (no detail open), with no prompt.
  const v = makeVault()
  const arm = id => { v.autoTypeItemId = id; v.autoTypeArmEpoch = v.vaultEpoch; v.autoTypeArmReprompt = false }
  arm("p1")
  v.reload(VAULT)
  check("a reload that changes nothing keeps the arm", v.autoTypeArmed() && v.autoTypeItemId === "p1")
  v.reload(withFlag("n1", 1))
  check("as does one that protects another item", v.autoTypeArmed())
  v.reload(withFlag("p1", 1))
  check("a reload that turns the armed item's re-prompt on disarms it, with no detail open",
    !v.autoTypeArmed() && v.autoTypeItemId === "" && v.detailItem === null, v.autoTypeItemId)
  v.autoTypeItemId = "g1"; v.autoTypeArmEpoch = v.vaultEpoch; v.autoTypeArmReprompt = true
  v.reload(VAULT)
  check("an item that asked when it was armed stays armed", v.autoTypeArmed() && v.autoTypeItemId === "g1")
}

// --- wiring -----------------------------------------------------------------------------------
const service = read("Service.qml")
check("the code's refresh timer goes through totpWanted()",
  /root\.detailItem\.hasTotp\s*&& root\.totpWanted\(root\.detailItem\)\) \{\s*root\.fetchTotp\(root\.detailItem\.id\)/.test(service))

done()
