// A stand-in for Service.qml's detail-screen state, shared by
// reprompt-detail.test.js and detail-on-demand.test.js: the real functions
// run against plain properties and a scripted helper (`vaultQuery` records
// each question and answers when the test says so).

const { functionBody, loadModule, readPluginSource } = require("./harness")

const Model = loadModule()
const Totp = loadModule("TotpModel.js")
const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)

// The body of a QML handler such as `onCurrentScreenChanged: { ... }`.
function handlerBody(source, name) {
  const start = source.indexOf(`${name}: {`)
  if (start === -1) return ""
  let depth = 0
  for (let i = source.indexOf("{", start); i < source.length; i++) {
    if (source[i] === "{") depth++
    else if (source[i] === "}" && --depth === 0) return source.slice(source.indexOf("{", start) + 1, i)
  }
  return ""
}

const names = ["itemNeedsReprompt", "repromptSatisfied", "withReprompt", "submitReprompt", "cancelReprompt",
  "clearRepromptGrant", "withholdDetailSecrets", "withRevealedDetail", "loadFullDetail", "openDetail",
  "onDetailFinished", "toggleFieldReveal", "setFieldRevealed", "isFieldRevealed", "shownSecret", "revealField",
  "totpWanted", "helperRow", "readDetailSecret", "copyDetailField", "copyDetailFieldNow", "startEditItem",
  "copyDetailTotp", "copyTotpCodeNow", "applyTotpCode", "fetchTotp", "localTotp", "saveItemForm"]

// `items`: the list (rows from Model.parseItems). `fallback`: no helper.
function makeVault(items, fallback) {
  const v = {
    Model, Totp,
    items, vaultHelperActive: !fallback, status: "unlocked", vaultEpoch: 3, currentScreen: "main",
    session: "HELD-BY-QS-BITWARDEN-VAULT-HELPER-SESSION", clearClipboardSec: 30, generatorReturnScreen: "main",
    repromptPending: false, repromptItemId: "", repromptItemName: "", repromptError: "", repromptBusy: false,
    repromptCallback: null, repromptEpoch: -1, repromptVerifiedId: "", repromptActionId: "",
    detailItem: null, detailPassword: "", liveTotp: "", revealedFields: {}, errorMessage: "", isLoading: false,
    showDeleteConfirm: false, attachmentQueue: [], attachmentSaved: {},
    totpFollowupActive: false, totpFollowupItem: null, totpFollowupCode: "", totpCopyItemId: "",
    totpRequestItemId: "", totpQueuedItemId: "", totpQueuedEpoch: -1, totpRestartPending: false,
    getTotpProc: { running: false },
    pendingSave: null, formIsEditing: true, formItemId: "g1",
    queries: [], answers: [], copied: [], edits: [], flashes: [], formResets: 0, verify: null,
    closeFilterGroup() {}, learnFromPick() {}, beginVaultRead() {}, vaultReadIsStale() { return false },
    resetAutoLockTimer() {}, flashNotification(text) { v.flashes.push(text) },
    startTotpFetch(id) { v.queries.push({ kind: "bw get totp", args: { id } }) },
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
  // What the panel does when the screen changes (Service.qml's handler).
  const handler = new Function("root", "with (root) {\n" + handlerBody(src, "onCurrentScreenChanged")
    .replace(/if \(currentScreen !== "generator"\) stopGeneratorServe\(\)/, "")
    .replace(/if \(currentScreen !== "pin"\) abandonPinSetup\(\)/, "")
    .replace(/if \(currentScreen !== "fingerprint"\) abandonFingerprintSetup\(\)/, "")
    .replace(/if \(currentScreen !== "fido"\) fidoUnlocker\.abandonSetup\(\)/, "")
    .replace(/restoreScreenFocus\(\)/, "")
    + "\n}")
  v.resetItemForm = () => { v.formResets++ }
  v.goTo = screen => { v.currentScreen = screen; handler(v) }
  return v
}

const answer = (v, i, ok, value) => v.answers[i](ok, value)
const confirm = v => { v.submitReprompt("pw"); v.verify(true) }

module.exports = { Model, Totp, src, body, handlerBody, makeVault, answer, confirm }
