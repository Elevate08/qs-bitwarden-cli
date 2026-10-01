#!/usr/bin/env node
// Master password re-prompt: an item with `reprompt` 1 asks for the master
// password before anything secret of it is revealed, copied or edited. The
// gate's own functions are run here against a stand-in vault (the state
// they read and write, and a scripted password check); the wiring is
// checked in the source.
//
//   node tests/reprompt.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")

const Model = loadModule()
const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)
const { check, eq, done } = createSuite("reprompt")

// --- the flag reaches items and details --------------------------------------------

const raw = [
  { id: "p1", type: 1, name: "Bank", reprompt: 1, login: { username: "me", password: "pw" } },
  { id: "p0", type: 1, name: "Mail", reprompt: 0, login: { username: "me", password: "pw" } },
  { id: "px", type: 1, name: "Odd", reprompt: "yes", login: { username: "me", password: "pw" } }
]
const listed = Model.parseItems(raw)
check("list items carry reprompt as a number",
  listed.find(i => i.id === "p1").reprompt === 1 && listed.find(i => i.id === "p0").reprompt === 0
    && listed.find(i => i.id === "px").reprompt === 0, JSON.stringify(listed.map(i => [i.id, i.reprompt])))
check("details carry it too",
  Model.itemDetailFromObject(raw[0]).reprompt === 1 && Model.itemDetailFromObject(raw[1]).reprompt === 0, "")
const sanitized = Model.readSanitizedVault(JSON.stringify({ items: [raw[0]], sshKeys: [
  { id: "k1", name: "Key", type: 5, reprompt: 1, publicKey: "ssh-ed25519 AAAA", fingerprint: "SHA256:x" }] }))
check("so do SSH key rows and their details",
  sanitized.items.find(i => i.id === "k1").reprompt === 1
    && Model.itemDetailFromObject(sanitized.items.find(i => i.id === "k1").rawObject).reprompt === 1, "")

// --- the gate, run against a stand-in vault ------------------------------------------

const names = ["itemNeedsReprompt", "repromptSatisfied", "withReprompt", "submitReprompt", "cancelReprompt",
  "clearRepromptGrant", "withholdDetailSecrets"]
function makeVault() {
  const v = {
    repromptPending: false, repromptItemId: "", repromptItemName: "", repromptError: "", repromptBusy: false,
    repromptCallback: null, repromptEpoch: -1, repromptVerifiedId: "", repromptActionId: "",
    detailItem: null, status: "unlocked", vaultEpoch: 7, vaultHelperActive: false,
    checks: [], answer: null,
    // The password check answers when the test says so.
    verifyMasterPassword(pw, done) { v.checks.push(pw); v.answer = done }
  }
  v.root = v
  const make = new Function("root", "with (root) {\n" + names.map(body).join("\n")
    + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")
  Object.assign(v, make(v))
  return v
}

const bank = { id: "p1", name: "Bank", reprompt: 1 }
const mail = { id: "p0", name: "Mail", reprompt: 0 }

{
  const v = makeVault()
  let ran = 0
  v.withReprompt(mail, () => ran++)
  eq("an item without re-prompt runs at once", ran, 1)
  v.withReprompt(bank, () => ran++)
  check("a re-prompt item waits for the master password",
    ran === 1 && v.repromptPending && v.repromptItemName === "Bank" && v.repromptItemId === "p1", "")
  v.submitReprompt("")
  check("an empty answer is refused without a check", v.checks.length === 0 && v.repromptError !== "", v.repromptError)
  v.submitReprompt("wrong")
  check("the answer is checked", v.checks.join() === "wrong" && v.repromptBusy, "")
  v.submitReprompt("again")
  check("a second answer while one is being checked is ignored", v.checks.length === 1, v.checks.join())
  v.answer(false)
  check("a wrong password keeps the prompt up and says so",
    ran === 1 && v.repromptPending && !v.repromptBusy && /not your master password/.test(v.repromptError), v.repromptError)
  v.submitReprompt("right")
  v.answer(true)
  check("the right one runs the action and closes the prompt", ran === 2 && !v.repromptPending && v.repromptError === "", "")
  check("with no detail open, nothing is remembered", v.repromptVerifiedId === "", v.repromptVerifiedId)
  v.withReprompt(bank, () => ran++)
  check("so the next action on it asks again", ran === 2 && v.repromptPending, "")
  v.cancelReprompt()
  check("cancelling drops the waiting action", !v.repromptPending && v.repromptCallback === null, "")
}

{
  const v = makeVault()
  let ran = 0
  v.detailItem = { id: "p1", reprompt: 1 }
  v.withReprompt(bank, () => ran++)
  v.submitReprompt("right")
  v.answer(true)
  check("confirmed with its detail open, the item is remembered", ran === 1 && v.repromptVerifiedId === "p1", "")
  v.withReprompt(bank, () => ran++)
  check("and further actions on it run at once while the detail stays open", ran === 2 && !v.repromptPending, "")
  v.detailItem = { id: "other", reprompt: 1 }
  v.withReprompt(bank, () => ran++)
  check("not once another item is open", ran === 2 && v.repromptPending, "")
  v.clearRepromptGrant()
  check("clearing forgets the confirmation and a waiting prompt", v.repromptVerifiedId === "" && !v.repromptPending, "")
}

{
  const v = makeVault()
  let ran = 0
  v.withReprompt(bank, () => {
    ran++
    // A gated function called from the confirmed action does not ask again.
    v.withReprompt(bank, () => ran++)
  })
  v.submitReprompt("right")
  v.answer(true)
  check("an action confirmed once is not asked for again by what it calls", ran === 2 && !v.repromptPending, "")
  check("that pass ends with the action", v.repromptActionId === "", v.repromptActionId)
}

{
  const v = makeVault()
  let ran = 0
  v.withReprompt(bank, () => ran++)
  v.submitReprompt("right")
  v.vaultEpoch = 8 // locked meanwhile
  v.answer(true)
  check("an answer landing after a lock runs nothing", ran === 0, "")
  const w = makeVault()
  w.status = "locked"
  w.withReprompt(bank, () => ran++)
  check("a locked vault asks nothing and runs nothing", ran === 0 && !w.repromptPending, "")
}

// --- what is gated, and when the confirmation is forgotten -----------------------------

for (const [fn, now] of [["copyPassword", "copyPasswordNow"], ["copyTotpCode", "copyTotpCodeNow"],
                         ["deleteCurrentItem", "deleteCurrentItemNow"],
                         ["handleSmartEnter", "smartCopy"]]) {
  check(`${fn} goes through the re-prompt`,
    new RegExp(`withReprompt\\([^,]+, function\\(\\) \\{[^}]*${now}\\(`).test(body(fn)), body(fn))
}
check("editing goes through it, on the whole item",
  /withRevealedDetail\(item, function\(\) \{[^]*?startEditItemNow\(/.test(body("startEditItem")), body("startEditItem"))
check("revealing a field goes through it; hiding one does not",
  /if \(!revealedFields\[key\] && detailItem\) \{\s*withRevealedDetail\(detailItem/.test(body("toggleFieldReveal")),
  body("toggleFieldReveal"))
check("the TOTP that follows Enter's copy is not asked for again",
  /totpFollowupActive && totpFollowupItem && totpFollowupItem\.id === item\.id\) \{\s*copyTotpCodeNow\(item\)/.test(body("copyTotpCode"))
    && /root\.copyTotpCodeNow\(root\.totpFollowupItem\)/.test(src.slice(src.indexOf("id: autoTotpTimer"), src.indexOf("id: autoTotpTimer") + 500)),
  body("copyTotpCode"))
check("a lock forgets it", /clearRepromptGrant\(\)/.test(body("dropVaultSecrets")), body("dropVaultSecrets"))
check("closing the panel forgets it",
  /clearRepromptGrant\(\)/.test(src.slice(src.indexOf("onOpenedChanged:"), src.indexOf("onOpenedChanged:") + 200)), "")
const screen = src.slice(src.indexOf("onCurrentScreenChanged:"), src.indexOf("onCurrentScreenChanged:") + 1400)
check("leaving the item (detail, its edit form, a generator trip from it) forgets it",
  /if \(!inItem\) clearRepromptGrant\(\)/.test(screen) && /if \(repromptPending\) cancelReprompt\(\)/.test(screen), screen)
check("opening another item forgets it",
  /String\(item\.id\) !== repromptVerifiedId\) clearRepromptGrant\(\)/.test(body("openDetail")), body("openDetail"))
check("Escape dismisses a waiting prompt first",
  /if \(repromptPending\) \{\s*cancelReprompt\(\)/.test(body("handleEscape")), body("handleEscape"))

// --- the check itself ------------------------------------------------------------------

const verify = body("verifyMasterPassword")
check("the stored copy answers first, silently, with the password in the environment",
  /Model\.unlockEnvelopeCheckCommand\(envelopeTool\(\), envelopeAccount\(\)\)/.test(verify)
    && /env\[Model\.keyringSecretEnvVar\(\)\] = pw/.test(verify) && !/secretOutput/.test(verify), verify)
check("a stale stored copy is not trusted, and anything but a match goes to bw",
  /!envelopeSummary\.stale/.test(verify) && /if \(code === 0\) \{ done\(true\); return \}\s*root\.verifyWithBw\(pw/.test(verify),
  verify)
const check0 = Model.unlockEnvelopeCheckCommand("/opt/tool", { id: "u", server: "https://s", slot: "default" })
check("the check's command holds no secret and prints nothing",
  check0[2].includes('"$QSBW_SECRET"') && /\s>\/dev\/null$/.test(check0[2]), check0[2])
check("bw's own check keeps the password out of argv",
  /--passwordenv QSBW_SECRET/.test(Model.bwVerifyPasswordCommand()[2]), Model.bwVerifyPasswordCommand()[2])

done()
