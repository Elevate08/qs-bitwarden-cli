#!/usr/bin/env node
// Tests for Bitwarden Send payloads, parsing and command construction.
// Field names come from a real `bw send --fullObject` response.
//
//   node tests/sends.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.buildSendPayload = buildSendPayload
  exports.parseSends = parseSends
  exports.sendExpiryLabel = sendExpiryLabel
  exports.sendAccessLabel = sendAccessLabel
  exports.createSendCommand = createSendCommand
  exports.listSendsCommand = listSendsCommand
  exports.deleteSendCommand = deleteSendCommand
  exports.createItemCommand = createItemCommand
  exports.editItemCommand = editItemCommand
  exports.sessionEnvVar = sessionEnvVar
  exports.statusCommand = statusCommand
  exports.listCommand = listCommand
  exports.syncCommand = syncCommand
  exports.getItemCommand = getItemCommand
  exports.getTotpCommand = getTotpCommand
  exports.lockCommand = lockCommand
  exports.deleteItemCommand = deleteItemCommand
  exports.createFolderCommand = createFolderCommand
  exports.listFoldersCommand = listFoldersCommand
  exports.listOrganizationsCommand = listOrganizationsCommand
  exports.deleteFolderCommand = deleteFolderCommand
  exports.terminalLoginCommand = terminalLoginCommand
  exports.sessionHandoffReadCommand = sessionHandoffReadCommand
  exports.extractSessionToken = extractSessionToken
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- the security property that motivated the env-based commands ------------
// argv is world-readable via /proc on a default Linux box, so no secret may
// ever appear in a command line.
const sendCmd = Model.createSendCommand("SESSIONTOKEN")[2]
check("send create reads its payload from the environment",
  sendCmd.includes('"$QSBW_SEND"') && sendCmd.includes("bw encode"), sendCmd)
check("send create carries no payload in argv",
  !sendCmd.includes("password") && !sendCmd.includes("text"), sendCmd)

const itemCmd = Model.createItemCommand({ organizationId: null }, "SESSIONTOKEN")[2]
check("item create reads its payload from the environment",
  itemCmd.includes('"$QSBW_ITEM"'), itemCmd)
const editCmd = Model.editItemCommand("id-1", "SESSIONTOKEN")[2]
check("item edit reads its payload from the environment",
  editCmd.includes('"$QSBW_ITEM"') && editCmd.includes("'id-1'"), editCmd)

// --- payload ---------------------------------------------------------------
const p = Model.buildSendPayload("Name", "secret", true, 3, 5, "pw", "note")
check("payload sets the text and its hidden flag",
  p.text.text === "secret" && p.text.hidden === true, JSON.stringify(p.text))
check("deletionDate is days in the future, as an ISO string",
  Math.abs(Date.parse(p.deletionDate) - (Date.now() + 3 * 86400000)) < 60000, p.deletionDate)
check("maxAccessCount of 0 means unlimited, sent as null",
  Model.buildSendPayload("n", "t", false, 7, 0, "", "").maxAccessCount === null, "expected null")
check("an empty password is sent as null, not an empty string",
  Model.buildSendPayload("n", "t", false, 7, 0, "", "").password === null, "expected null")
check("a blank name falls back rather than creating an unnamed Send",
  Model.buildSendPayload("   ", "t", false, 7, 0, "", "").name === "Untitled Send",
  Model.buildSendPayload("   ", "t", false, 7, 0, "", "").name)
for (const [days, lo, hi] of [[0, 1, 31], [999, 1, 31], [-5, 1, 31]]) {
  const got = (Date.parse(Model.buildSendPayload("n", "t", false, days, 0, "", "").deletionDate) - Date.now()) / 86400000
  check(`deleteInDays=${days} clamps into [${lo}, ${hi}]`, got > lo - 1 && got < hi + 1, `got ~${got.toFixed(1)} days`)
}

// --- parsing (shape taken from a real response) -----------------------------
const listed = Model.parseSends(JSON.stringify([
  { id: "b", name: "Later", type: 0, accessUrl: "u2", accessCount: 1, maxAccessCount: 3,
    deletionDate: "2026-09-01T00:00:00Z", passwordSet: false, text: { text: "x", hidden: false } },
  { id: "a", name: "Sooner", type: 1, accessUrl: "u1", accessCount: 0, maxAccessCount: null,
    deletionDate: "2026-08-22T00:00:00Z", passwordSet: true, file: { fileName: "f.pdf" } },
]))
check("sends are ordered by how soon they vanish",
  listed.map(s => s.id).join(",") === "a,b", listed.map(s => s.id).join(","))
check("type 1 is recognised as a file Send",
  listed[0].isFile === true && listed[0].fileName === "f.pdf", JSON.stringify(listed[0]))
check("passwordSet is carried through as a boolean, and no password is exposed",
  listed[0].passwordSet === true && !("password" in listed[0]), JSON.stringify(listed[0]))
check("malformed JSON yields an empty list",
  Model.parseSends("{{").length === 0 && Model.parseSends("").length === 0, "expected []")

// --- labels -----------------------------------------------------------------
const at = t => Date.parse(t)
const mk = d => ({ deletionDate: d })
check("a past deletion date reads as expired",
  Model.sendExpiryLabel(mk("2026-08-20T00:00:00Z"), at("2026-08-21T00:00:00Z")) === "expired", "expected expired")
check("hours are used under a day",
  Model.sendExpiryLabel(mk("2026-08-21T05:00:00Z"), at("2026-08-21T00:00:00Z")) === "in 5 hours", "expected 'in 5 hours'")
check("singular day is not pluralised",
  Model.sendExpiryLabel(mk("2026-08-22T00:00:00Z"), at("2026-08-21T00:00:00Z")) === "in 1 day", "expected 'in 1 day'")
check("a missing deletion date yields no label",
  Model.sendExpiryLabel({}, Date.now()) === "", "expected empty")
check("unlimited access omits the maximum",
  Model.sendAccessLabel({ accessCount: 2, maxAccessCount: null }) === "2 views", "expected '2 views'")
check("a capped Send shows the maximum",
  Model.sendAccessLabel({ accessCount: 2, maxAccessCount: 5 }) === "2 of 5 views", "expected '2 of 5 views'")


// --- no bw command may carry the session token in argv ----------------------
// /proc/<pid>/cmdline is world-readable on a default Linux install, and the
// token grants full access to the unlocked vault. It goes in BW_SESSION.
check("the session env var is BW_SESSION, which bw reads natively",
  Model.sessionEnvVar() === "BW_SESSION", Model.sessionEnvVar())

const builders = [
  ["statusCommand", () => Model.statusCommand()],
  ["listCommand", () => Model.listCommand()],
  ["listFoldersCommand", () => Model.listFoldersCommand()],
  ["listOrganizationsCommand", () => Model.listOrganizationsCommand()],
  ["listSendsCommand", () => Model.listSendsCommand()],
  ["syncCommand", () => Model.syncCommand()],
  ["lockCommand", () => Model.lockCommand()],
  ["getItemCommand", () => Model.getItemCommand("id")],
  ["getTotpCommand", () => Model.getTotpCommand("id")],
  ["deleteItemCommand", () => Model.deleteItemCommand("id")],
  ["deleteFolderCommand", () => Model.deleteFolderCommand("id")],
  ["deleteSendCommand", () => Model.deleteSendCommand("id")],
  ["createFolderCommand", () => Model.createFolderCommand("f")],
  ["createItemCommand", () => Model.createItemCommand({ organizationId: null })],
  ["editItemCommand", () => Model.editItemCommand("id")],
  ["createSendCommand", () => Model.createSendCommand()],
]
for (const [name, build] of builders) {
  const argv = build().join(" ")
  check(`${name} passes no --session flag`, !argv.includes("--session"), argv)
}


// --- terminal login handoff -------------------------------------------------
const login = Model.terminalLoginCommand("login")[2]
const unlock = Model.terminalLoginCommand("unlock")[2]
check("terminal login runs in a terminal", login.includes("omarchy launch terminal"), login.slice(0, 80))
check("it falls back to a second terminal if the first is unavailable",
  login.includes("alacritty"), login.slice(0, 80))
// --raw prints only the session key on stdout while prompts stay on stderr,
// which is what lets the key be captured without breaking the interactive login.
check("it captures the key with --raw", login.includes("--raw"), login.slice(0, 120))
// The panel already knows which state it is in, so the terminal does not spend
// a `bw status` round trip (~3.3s here) working it out before prompting.
check("login mode runs bw login", login.includes("bw login --raw") && !login.includes("bw unlock"), login.slice(0, 200))
check("unlock mode runs bw unlock", unlock.includes("bw unlock --raw") && !unlock.includes("bw login"), unlock.slice(0, 200))
check("neither mode probes with bw status",
  !login.includes("bw status") && !unlock.includes("bw status"), "expected no status probe")
check("an unknown mode falls back to login",
  Model.terminalLoginCommand("")[2].includes("bw login --raw"), "expected login")
// Only the method name crosses the IPC boundary; the key never does.
check("a successful login reopens the panel",
  login.includes("omarchy-shell io.github.elevate08.qs-bitwarden-cli open"), login.slice(0, 300))
check("the session key is not passed over IPC",
  !login.includes("open $f") && !login.includes("open \"$f\""), login.slice(0, 300))
// The inner script appears twice -- once for the terminal, once for the
// alacritty fallback -- so count pauses against failure branches rather than
// assuming a single occurrence.
check("the user is only made to press a key when the login failed",
  login.split("read -p").length === login.split("Not completed").length,
  `${login.split("read -p").length - 1} pauses vs ${login.split("Not completed").length - 1} failure branches`)
check("a successful login closes the terminal on its own",
  login.includes("Returning to the Bitwarden panel") && login.includes("sleep 1"),
  "expected the success branch to close itself")
// The key is a secret at rest: tmpfs, user-only, gone when the session ends.
check("the handoff lives in XDG_RUNTIME_DIR, not on disk",
  login.includes("XDG_RUNTIME_DIR"), login.slice(0, 120))
check("the handoff is created with a restrictive umask",
  login.includes("umask 077") && login.includes("chmod 700"), login.slice(0, 200))
check("an incomplete login leaves nothing behind",
  login.includes('rm -f'), login.slice(0, 300))

const read = Model.sessionHandoffReadCommand()[2]
check("the handoff is read once and removed with a byte limit",
  read.includes("head -c") && read.includes("rm -f"), read)
check("an absent or empty handoff yields nothing",
  read.includes("-s "), read)

// The panel parses whatever the file holds through the same extractor it uses
// for unlock output, so a stray newline or an `export BW_SESSION=` line is fine.
check("a bare key is extracted intact",
  Model.extractSessionToken("abcdefghijklmnopqrstuvwxyz0123456789==") === "abcdefghijklmnopqrstuvwxyz0123456789==",
  Model.extractSessionToken("abcdefghijklmnopqrstuvwxyz0123456789=="))
check("an export line is unwrapped",
  Model.extractSessionToken('export BW_SESSION="tok3n-value-that-is-long-enough=="') === "tok3n-value-that-is-long-enough==",
  Model.extractSessionToken('export BW_SESSION="tok3n-value-that-is-long-enough=="'))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
