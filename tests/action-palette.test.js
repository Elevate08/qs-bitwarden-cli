#!/usr/bin/env node
// The action palette (Ctrl+K): the commands an item supports as a pure list,
// the box's filter, and the panel's wiring (same handlers as the letters).
//
//   node tests/action-palette.test.js

const { createSuite, loadModule, read } = require("./harness")
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
check("letters run through the existing handlers", panel.includes("runDetailShortcut(action.key)") && panel.includes("root.vault.runShortcut(action.key)"))
check("onTextKey uses runDetailShortcut", /onTextKey[\s\S]*?root\.runDetailShortcut\(lower\)/.test(panel))
check("README documents Ctrl+K", (read("README.md").match(/<kbd>Ctrl<\/kbd>\+<kbd>K<\/kbd>/g) || []).length >= 2)
check("CHANGELOG mentions the palette", /action palette/i.test(read("CHANGELOG.md").split("## [Unreleased]")[1].split(/\n## \[/)[0]))

done()
