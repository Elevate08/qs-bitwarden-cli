#!/usr/bin/env node
// The action palette (Ctrl+K): the commands an item supports as a pure list,
// the box's filter, and the panel's wiring (same handlers as the letters).
//
//   node tests/action-palette.test.js

const { createSuite, functionBody, loadModule, read } = require("./harness")
const Model = loadModule()

const { check, done } = createSuite("action-palette")

const ids = (item, ctx) => Model.itemActions(item, ctx).map(a => a.id)
const keyOf = (item, ctx, id) => (Model.itemActions(item, ctx).find(a => a.id === id) || {}).key
const LIST = { screen: "main" }
const DETAIL = { screen: "detail" }

const login = { typeCode: 1, type: "login", username: "me", hasPassword: true, hasTotp: true,
  uris: ["https://example.com/login"], hasAttachments: true, hasNotes: true, fields: [] }

// --- list context: the letters runShortcut() has ---------------------------------

check("list login: password, username, TOTP, website, details",
  JSON.stringify(Model.itemActions(login, LIST).map(a => [a.id, a.key])) ===
  JSON.stringify([["copyPassword", "p"], ["copyUsername", "u"], ["copyTotp", "m"], ["openWebsite", "w"], ["openDetail", "e"]]))
check("list: nothing the item lacks",
  JSON.stringify(ids({ typeCode: 1, type: "login", hasPassword: false, uris: [] }, LIST)) === JSON.stringify(["openDetail"]))
check("list: a non-web link is not offered as a website",
  !ids(Object.assign({}, login, { uris: ["ssh://host"] }), LIST).includes("openWebsite"))
check("list: card offers only details", JSON.stringify(ids({ typeCode: 3, card: { number: "4" } }, LIST)) === JSON.stringify(["openDetail"]))
check("null item gives none", Model.itemActions(null, LIST).length === 0)

// --- detail context -------------------------------------------------------------

const d = ids(login, DETAIL)
check("detail login has its full set", ["copyPassword", "copyUsername", "copyTotp", "openWebsite", "reveal", "saveAttachments", "copyNotes", "edit", "delete"].every(i => d.includes(i)))
check("detail letters", keyOf(login, DETAIL, "reveal") === "v" && keyOf(login, DETAIL, "saveAttachments") === "a"
  && keyOf(login, DETAIL, "edit") === "e" && keyOf(login, DETAIL, "delete") === "x" && keyOf(login, DETAIL, "copyTotp") === "m")
check("detail website has no letter (the detail has no w)", keyOf(login, DETAIL, "openWebsite") === "")
check("Edit and Delete come last", d.slice(-2).join() === "edit,delete")
check("reveal flips to hide", Model.itemActions(login, { screen: "detail", revealed: true }).find(a => a.id === "reveal").label === "Hide password")

const card = { typeCode: 3, type: "card", hasPassword: false, card: { number: "4111", code: "123", brand: "Visa", cardholderName: "A B", expMonth: "1", expYear: "30" } }
check("card actions", JSON.stringify(Model.itemActions(card, DETAIL).map(a => a.key)) === JSON.stringify(["n", "k", "v", "", "", "", "e", "x"]))
check("card: number and code letters", keyOf(card, DETAIL, "copyCardNumber") === "n" && keyOf(card, DETAIL, "copyCardCode") === "k")
check("card without a code omits it", !ids(Object.assign({}, card, { card: { number: "4111", code: "" } }), DETAIL).includes("copyCardCode"))
check("card reveal names the number", Model.itemActions(card, DETAIL).find(a => a.id === "reveal").label === "Reveal card number")

const ident = { typeCode: 4, type: "identity", hasPassword: false, identity: { firstName: "Ann", lastName: "Lee", username: "ann", email: "a@b.c", phone: "1", company: "X", ssn: "9", passportNumber: "", licenseNumber: "", city: "Town" } }
const di = ids(ident, DETAIL)
check("identity fields", ["copyUsername", "copyEmail", "copyIdentityName", "copyCompany", "copyPhone", "copySsn", "copyAddress"].every(i => di.includes(i)))
check("identity omits empty numbers", !di.includes("copyPassport") && !di.includes("copyLicense"))
check("identity letters u and c", keyOf(ident, DETAIL, "copyUsername") === "u" && keyOf(ident, DETAIL, "copyEmail") === "c")
check("identity has no reveal", !di.includes("reveal"))

const withFields = Object.assign({}, login, { fields: [
  { name: "PIN", value: "•", sensitive: true, index: 0 },
  { name: "Site", value: "x", sensitive: false, index: 2 },
  { name: "Empty", value: "", sensitive: false, index: 3 }] })
const df = Model.itemActions(withFields, DETAIL).filter(a => a.id.indexOf("customField:") === 0)
check("custom fields by their own index, empty plain ones skipped",
  JSON.stringify(df.map(a => [a.id, a.label])) === JSON.stringify([["customField:0", "Copy field: PIN"], ["customField:2", "Copy field: Site"]]))

const ssh = { typeCode: 5, type: "sshKey", publicKey: "ssh-ed25519 AAA" }
check("ssh key is read-only", JSON.stringify(ids(ssh, DETAIL)) === "[]")

// --- filtering --------------------------------------------------------------------

const all = Model.itemActions(login, DETAIL)
check("empty query keeps all", Model.filterActions(all, "").length === all.length)
check("matches any case", Model.filterActions(all, "COPY pass").map(a => a.id).join() === "copyPassword")
check("every word must match", Model.filterActions(all, "copy zzz").length === 0)
check("label-start matches lead", Model.filterActions(all, "e")[0].label.toLowerCase().indexOf("e") === 0)
check("query does not mutate input", all.length === Model.itemActions(login, DETAIL).length)

// --- wiring ---------------------------------------------------------------------------

const panel = read("Panel.qml")
const interceptor = panel.slice(panel.indexOf("id: shortcutInterceptor"), panel.indexOf("id: keyCatcher"))
check("Ctrl+K handled in the interceptor", /Key_K[\s\S]{0,300}openActionPalette/.test(interceptor))
check("Ctrl+K handled in the search box", /id: searchField[\s\S]*?Key_K[\s\S]{0,300}openActionPalette/.test(panel))
check("catcher blocked while the palette is open", /blocked: repromptConfirm\.shown[\s\S]{0,900}\|\| actionPalette\.shown/.test(panel))
check("palette builds from the model", panel.includes("Model.itemActions(") && panel.includes("Model.filterActions("))
const fnBody = name => {
  const start = panel.indexOf("  function " + name + "(")
  return start < 0 ? "" : panel.slice(start, panel.indexOf("\n  }\n", start))
}
const runPalette = fnBody("runPaletteAction")
const paletteItem = fnBody("paletteItem")
const listBranch = runPalette.slice(runPalette.indexOf('if (screen !== "detail")'), runPalette.indexOf('action.id === "delete"'))
check("detail letters run through the existing handler", runPalette.includes("root.runDetailShortcut(action.key)"))
check("list actions run through the letters' own gated handlers, on the palette's item",
  ["root.vault.copyPassword(item)", "root.vault.copyUsername(item)", "root.vault.copyTotpCode(item)",
    "root.vault.openUrl(item.uris[0])", "root.vault.openDetail(item)"].every(call => listBranch.includes(call)))
check("list actions keep the letters' guards (TOTP only where there is one, a website only with a link)",
  /if \(item\.hasTotp\) root\.vault\.copyTotpCode\(item\)/.test(listBranch)
  && /if \(item\.uris && item\.uris\.length > 0\) root\.vault\.openUrl/.test(listBranch))
check("every list action the model offers has a case",
  Model.itemActions(login, LIST).every(a => listBranch.includes('case "' + a.id + '":')))
// The re-prompt lives in copyPassword()/copyTotpCode(); the *Now variants skip it.
check("the palette never calls an ungated copy", !/Now\(/.test(runPalette))

// --- bound to the item it was opened for, by id --------------------------------------

const openFor = panel.slice(panel.indexOf("function openFor()"), panel.indexOf("// Back to where it was opened."))
const runAt = panel.slice(panel.indexOf("function runAt(index)"), panel.indexOf("// Closed when the vault locks"))
check("the palette remembers the id of the item it was opened for",
  /property string itemId: ""/.test(panel) && /actionPalette\.itemId = String\(item\.id \|\| ""\)/.test(openFor))
check("the id is read before the palette closes and handed to the action",
  /var itemId = actionPalette\.itemId[\s\S]*actionPalette\.close\(\)[\s\S]*root\.runPaletteAction\(action, screen, itemId\)/.test(runAt))
check("closing forgets the id", /actionPalette\.itemId = ""/.test(panel.slice(panel.indexOf("// Back to where it was opened."), panel.indexOf("function move(delta)"))))
check("an action resolves its item by id first and does nothing without it",
  /^  function runPaletteAction\(action, screen, itemId\) \{\n    var item = root\.paletteItem\(screen, itemId\)\n    if \(!item\) return\n/.test(runPalette))
check("no palette action re-reads the selected row", !/runShortcut|getSelectedItem|selectedIndex|filteredItems/.test(runPalette + paletteItem))
check("the item is looked up by id among the vault's items",
  /String\(list\[i\]\.id\) === itemId/.test(paletteItem) && /root\.vault\.items/.test(paletteItem)
  && /if \(itemId === ""\) return null/.test(paletteItem))
check("on the detail screen the open item must still be the palette's",
  /String\(detail\.id\) !== itemId\) return null/.test(paletteItem))
check("delete asks only for the palette's own item", /if \(item\.typeCode !== 5\) root\.vault\.showDeleteConfirm = true/.test(runPalette)
  && !/root\.vault\.detailItem/.test(runPalette))

// --- the real paletteItem() and runPaletteAction(), run against a stand-in panel ------
// Both use nothing of QML but root and root.vault. The vault's re-prompt test
// is Service.qml's own.

const serviceSrc = read("Service.qml")
function makePanel(items, detailItem) {
  const calls = []
  const rec = name => (...args) => { calls.push([name, ...args]) }
  const vault = {
    items, detailItem: detailItem || null, selectedIndex: 0, showDeleteConfirm: false,
    detailCard: null, detailIdentity: null,
    copyPassword: rec("copyPassword"), copyUsername: rec("copyUsername"), copyTotpCode: rec("copyTotpCode"),
    openUrl: rec("openUrl"), openDetail: rec("openDetail"), copyToClipboard: rec("copyToClipboard"),
    // What the palette must never fall back to.
    runShortcut: rec("runShortcut"),
    getSelectedItem() { calls.push(["getSelectedItem"]); return vault.items[vault.selectedIndex] || null }
  }
  vault.itemNeedsReprompt = new Function(functionBody(serviceSrc, "itemNeedsReprompt") + "\nreturn itemNeedsReprompt")()
  const root = { vault, calls, runDetailShortcut: rec("runDetailShortcut"), copyDetailSecret: rec("copyDetailSecret") }
  Object.assign(root, new Function("root", functionBody(panel, "paletteItem") + "\n" + functionBody(panel, "runPaletteAction")
    + "\nreturn { paletteItem: paletteItem, runPaletteAction: runPaletteAction }")(root))
  return root
}

const A = { id: "a" }, B = { id: "b" }
const lookup = (vault, screen, id) => {
  const p = makePanel(vault.items, vault.detailItem)
  return p.paletteItem(screen, id)
}
check("finds the item wherever a sync moved it", lookup({ items: [B, A] }, "main", "a") === A)
check("an item a sync removed resolves to nothing", lookup({ items: [B] }, "main", "a") === null)
check("an empty id resolves to nothing", lookup({ items: [{ id: "" }, A] }, "main", "") === null)
check("detail: the open item resolves while the vault still has it", lookup({ detailItem: A, items: [B, { id: "a" }] }, "detail", "a") === A)
check("detail: another item in its place resolves to nothing",
  lookup({ detailItem: B, items: [A, B] }, "detail", "a") === null
  && lookup({ detailItem: null, items: [A] }, "detail", "a") === null)
check("detail: an open item a sync removed from the vault resolves to nothing",
  lookup({ detailItem: A, items: [B] }, "detail", "a") === null && lookup({ detailItem: A, items: [] }, "detail", "a") === null)
check("detail: a re-prompt a sync turned on, which the open copy does not have, resolves to nothing",
  lookup({ detailItem: { id: "a", reprompt: 0 }, items: [{ id: "a", reprompt: 1 }] }, "detail", "a") === null
  && lookup({ detailItem: { id: "a" }, items: [{ id: "a", reprompt: 1 }] }, "detail", "a") === null)
check("detail: a re-prompt turned off since resolves to nothing too (the copy is stale either way)",
  lookup({ detailItem: { id: "a", reprompt: 1 }, items: [{ id: "a", reprompt: 0 }] }, "detail", "a") === null)
const guarded = { id: "a", reprompt: 1 }
check("detail: agreeing re-prompt flags resolve to the open item",
  lookup({ detailItem: guarded, items: [{ id: "a", reprompt: 1 }] }, "detail", "a") === guarded)

// The list: the palette was opened on row 0 (the login); by the time the action
// runs a sync has put another item there and moved the login down.
const other = Object.assign({}, login, { id: "other", name: "Other", username: "them", uris: ["https://other.example/"] })
const listActions = Model.itemActions(Object.assign({ id: "a" }, login), LIST)
const expectCall = { copyPassword: "copyPassword", copyUsername: "copyUsername", copyTotp: "copyTotpCode",
  openWebsite: "openUrl", openDetail: "openDetail" }
check("the list offers the five actions the dispatch test covers",
  listActions.map(a => a.id).sort().join() === Object.keys(expectCall).sort().join())
for (const action of listActions) {
  const fresh = Object.assign({ id: "a" }, login)
  const p = makePanel([other, { id: "x" }, fresh])
  p.vault.selectedIndex = 0
  p.runPaletteAction(action, "main", "a")
  const want = action.id === "openWebsite" ? fresh.uris[0] : fresh
  check(`list ${action.id}: runs ${expectCall[action.id]} once, on the palette's item, not the selected row`,
    p.calls.length === 1 && p.calls[0][0] === expectCall[action.id] && p.calls[0][1] === want && p.calls[0].length === 2,
    JSON.stringify(p.calls.map(c => c[0])))
  const gone = makePanel([other, { id: "x" }])
  gone.runPaletteAction(action, "main", "a")
  check(`list ${action.id}: does nothing once the item is gone`, gone.calls.length === 0, JSON.stringify(gone.calls.map(c => c[0])))
}
{
  const p = makePanel([Object.assign({ id: "a" }, login, { hasTotp: false, uris: [] })])
  p.runPaletteAction({ id: "copyTotp", key: "m" }, "main", "a")
  p.runPaletteAction({ id: "openWebsite", key: "w" }, "main", "a")
  check("list: a TOTP or website the item no longer has is not acted on", p.calls.length === 0)
  p.runPaletteAction({ id: "noSuchAction", key: "p" }, "main", "a")
  check("list: an unknown action runs nothing (no fall back to its letter)", p.calls.length === 0)
}

// The detail screen: letters go to runDetailShortcut, the rest by id, and all
// of it only while the open item is still the vault's.
{
  const open = Object.assign({ id: "a" }, login)
  const live = makePanel([other, Object.assign({ id: "a" }, login)], open)
  live.runPaletteAction({ id: "copyPassword", key: "p" }, "detail", "a")
  live.runPaletteAction({ id: "openWebsite", key: "" }, "detail", "a")
  live.runPaletteAction({ id: "copyNotes", key: "" }, "detail", "a")
  live.runPaletteAction({ id: "delete", key: "x" }, "detail", "a")
  check("detail: letter, website, notes and delete reach their handlers",
    JSON.stringify(live.calls) === JSON.stringify([["runDetailShortcut", "p"], ["openUrl", open.uris[0]], ["copyDetailSecret", "notes", "Notes"]])
    && live.vault.showDeleteConfirm === true, JSON.stringify(live.calls))

  for (const [why, items, detail] of [
    ["a sync removed the item", [other], open],
    ["another item is open", [other, Object.assign({ id: "a" }, login)], other],
    ["the vault now asks for the master password and the open copy does not", [Object.assign({ id: "a", reprompt: 1 }, login)], open]]) {
    const p = makePanel(items, detail)
    for (const action of Model.itemActions(open, DETAIL)) p.runPaletteAction(action, "detail", "a")
    check(`detail: no action runs when ${why}`, p.calls.length === 0 && p.vault.showDeleteConfirm === false,
      JSON.stringify(p.calls.map(c => c[0])))
  }
}
check("onTextKey uses runDetailShortcut", /onTextKey[\s\S]*?root\.runDetailShortcut\(lower\)/.test(panel))
// --- a new item's detail, opened while its save runs ---------------------------------
// The real onSaveItemFinished(), followCreatedItem() and openDetail(), on the
// detail stand-in (detail-vault.js): the open detail moves from the
// provisional row to the saved item as a click on its row would, so the
// palette (bound by id) has an item to act on, a re-prompt item asks before
// anything is read, and an ordinary one reads on demand.
const { makeVault: makeDetailVault, answer: answerHelper, confirm: confirmReprompt } = require("./detail-vault")
const draft = { type: 1, name: "New login", notes: "", favorite: false, login: { username: "me", password: "pw", uris: [] } }
const provisionalId = Model.pendingItemId(777)
const provisionalRow = Model.optimisticItem(draft, provisionalId)
const existingRow = Model.parseItems([{ id: "11111111-1111-1111-1111-111111111111", type: 1, name: "Old", reprompt: 0,
  login: { username: "old" }, qsbwHeld: { password: true, totp: false, notes: false } }])[0]
const savedId = "55555555-5555-5555-5555-555555555555"
// What the helper hands back for the saved item: no secret, flags for what it holds.
const savedEnvelope = (id, extra) => JSON.stringify({ sshCapability: "unconfirmed", sshKeys: [], items: [Object.assign(
  { object: "item", id, type: 1, name: "New login", reprompt: 0, login: { username: "me", uris: [] },
    qsbwHeld: { password: true, totp: false, notes: false } }, extra || {})] })
// A vault with the provisional row listed and its save running; `open`: the id of the detail on screen.
function saving(open, screen) {
  const v = makeDetailVault(Model.replaceItemById([existingRow], provisionalId, provisionalRow))
  v.picks = []
  v.learnFromPick = item => { v.picks.push(item.id) }
  v.pendingSave = { id: provisionalId, isCreate: true, name: "New login", previous: null, form: {} }
  v.readEpochs.itemSave = v.vaultEpoch
  if (open === provisionalId) { v.currentScreen = "detail"; v.detailItem = Object.assign({}, provisionalRow) }
  else if (open) v.openDetail(Model.findItemById(v.items, open), true)
  if (screen) v.currentScreen = screen
  v.queries.length = 0; v.answers.length = 0
  return v
}
{
  const v = saving(provisionalId)
  // Before the save lands the palette acts on the provisional row's detail.
  const before = makePanel(v.items, v.detailItem)
  before.runPaletteAction({ id: "copyUsername", key: "u" }, "detail", provisionalId)
  check("new item: the palette works in the provisional detail", before.calls.length === 1)
  v.onSaveItemFinished(0, savedEnvelope(savedId), "")
  check("new item: the open detail follows the save to the saved item, the row now listed under its id",
    v.currentScreen === "detail" && v.detailItem && v.detailItem.id === savedId && !v.detailItem.pending
      && v.detailItem.secretsWithheld === true && !Model.findItemById(v.items, provisionalId)
      && Model.findItemById(v.items, savedId) !== null, JSON.stringify(v.detailItem && v.detailItem.id))
  check("new item: opened as a browse, so it is not learned as a pick, and nothing secret is asked for by opening",
    v.picks.length === 0 && v.queries.length === 0 && v.detailPassword === "", JSON.stringify(v.queries))
  v.toggleFieldReveal("password")
  check("new item: its password is then read on demand, under the saved id",
    v.queries.length === 1 && v.queries[0].kind === "field" && v.queries[0].args.id === savedId && !v.repromptPending,
    JSON.stringify(v.queries))
  answerHelper(v, 0, true, "pw")
  check("new item: and shows", v.shownSecret("password", "") === "pw")
  const after = makePanel(v.items, v.detailItem)
  after.runPaletteAction({ id: "copyUsername", key: "u" }, "detail", String(v.detailItem.id))
  check("new item: a palette opened on the saved detail acts", after.calls.length === 1 && after.calls[0][0] === "runDetailShortcut")
  after.runPaletteAction({ id: "copyUsername", key: "u" }, "detail", provisionalId)
  check("new item: a palette still holding the provisional id does nothing", after.calls.length === 1)
}
{
  // The saved item has a TOTP key: the handoff fetches the code as opening a row does.
  const v = saving(provisionalId)
  v.onSaveItemFinished(0, savedEnvelope(savedId, { qsbwHeld: { password: true, totp: true, notes: false } }), "")
  check("new item with a TOTP key: its code is asked of the helper through the handoff",
    v.detailItem.id === savedId && v.queries.length === 1 && v.queries[0].kind === "totp" && v.queries[0].args.id === savedId,
    JSON.stringify(v.queries))
}
{
  // The saved item asks for the master password (an organization's policy, a
  // clone of a flagged item): the handoff must not hand its secrets over.
  const v = saving(provisionalId)
  v.onSaveItemFinished(0, savedEnvelope(savedId, { reprompt: 1, qsbwHeld: { password: true, totp: true, notes: false } }), "")
  check("new re-prompt item: the handoff opens its public view and asks the helper nothing, not even the code",
    v.detailItem.id === savedId && v.detailItem.reprompt === 1 && v.detailItem.secretsWithheld === true
      && v.queries.length === 0 && v.liveTotp === "" && !v.repromptPending, JSON.stringify(v.queries))
  v.copyDetailField("password", "Password")
  check("new re-prompt item: a copy asks for the master password first", v.repromptPending && v.repromptItemId === savedId && v.queries.length === 0)
  confirmReprompt(v)
  check("new re-prompt item: and reads once it is confirmed", v.queries.length === 1 && v.queries[0].kind === "copyField"
    && v.queries[0].args.id === savedId, JSON.stringify(v.queries))
}
{
  const v = saving(existingRow.id)
  const detail = v.detailItem
  v.onSaveItemFinished(0, savedEnvelope(savedId), "")
  check("new item: a detail open on another item is left alone", v.detailItem === detail && v.detailItem.id === existingRow.id && v.queries.length === 0)
  const m = saving(provisionalId, "main")
  m.onSaveItemFinished(0, savedEnvelope(savedId), "")
  check("new item: nothing is opened when the detail is not on screen", m.currentScreen === "main" && m.detailItem.id === provisionalId)
  const f = saving(provisionalId)
  f.onSaveItemFinished(1, "", "refused")
  check("new item: a refused save opens nothing", f.detailItem.id === provisionalId && !Model.findItemById(f.items, provisionalId)
    && f.failedSave !== null && f.queries.length === 0)
}
{
  // An edit keeps its id: the saved row replaces the old one and the detail is not reopened.
  const v = makeDetailVault([existingRow])
  v.openDetail(existingRow, true)
  const detail = v.detailItem
  v.pendingSave = { id: existingRow.id, isCreate: false, name: "Old", previous: existingRow, form: {} }
  v.readEpochs.itemSave = v.vaultEpoch
  v.onSaveItemFinished(0, savedEnvelope(existingRow.id), "")
  check("an edit does not reopen the detail, and its id still resolves",
    v.detailItem === detail && v.items.length === 1 && v.items[0].id === existingRow.id
    && makePanel(v.items, v.detailItem).paletteItem("detail", existingRow.id) === v.detailItem)
}
const paletteConn = panel.slice(panel.indexOf("// Closed when the vault locks"), panel.indexOf("color: Color.menu.scrim"))
// The block is instantiated and driven through the vault's signals in
// tests/qml/tst_palette_follows_detail.qml (qmltestrunner); a handler that is
// right does nothing on a block that listens to something else, so what it
// listens to is pinned here too, for a run without Qt.
check("the palette's Connections block listens to the vault",
  /^Closed when the vault locks[^\n]*\n\s*Connections \{\s*target: root\.vault\s*function onStatusChanged\(\)/.test(paletteConn.slice(3)), paletteConn.slice(0, 200))
check("an open detail palette closes when the detail's item changes under it",
  /function onDetailItemChanged\(\) \{\s+if \(!actionPalette\.shown \|\| actionPalette\.fromScreen !== "detail"\) return\s+var detail = root\.vault\.detailItem\s+if \(!detail \|\| String\(detail\.id\) !== actionPalette\.itemId\) actionPalette\.close\(\)/.test(paletteConn))
check("and a QML test drives that block through the vault's own signals",
  /paletteConnections\(\)/.test(read("tests/qml/tst_palette_follows_detail.qml"))
    && /root\.vault\.detailItem = \{ id: "b" \}/.test(read("tests/qml/tst_palette_follows_detail.qml")))
{
  // That handler, run: same id stays open, another id or none closes.
  const run = (palette, detailItem) => {
    let closed = 0
    new Function("actionPalette", "root", functionBody(paletteConn, "onDetailItemChanged") + "\nonDetailItemChanged()")(
      Object.assign({ close() { closed++ } }, palette), { vault: { detailItem } })
    return closed
  }
  const open = { shown: true, fromScreen: "detail", itemId: "a" }
  check("palette: a reload of the same item keeps it open", run(open, { id: "a" }) === 0)
  check("palette: another item, or none, closes it", run(open, { id: "b" }) === 1 && run(open, null) === 1)
  check("palette: a list palette ignores the detail changing", run({ shown: true, fromScreen: "main", itemId: "a" }, { id: "b" }) === 0
    && run({ shown: false, fromScreen: "detail", itemId: "a" }, { id: "b" }) === 0)
}

check("README documents Ctrl+K", (read("README.md").match(/<kbd>Ctrl<\/kbd>\+<kbd>K<\/kbd>/g) || []).length >= 2)
check("CHANGELOG mentions the palette", /action palette/i.test(read("CHANGELOG.md").split("## [Unreleased]")[1].split(/\n## \[/)[0]))

done()
