#!/usr/bin/env node
// Verifies that all data streams read by the long-lived shell process
// are capped on the producer side to prevent unbounded buffering.

const fs = require("fs")
const path = require("path")
const os = require("os")
const { execFileSync, spawnSync } = require("child_process")

const Model = {}
const code = fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "")

new Function("exports", code + `
  exports.listCommand = listCommand
  exports.getItemCommand = getItemCommand
  exports.listSendsCommand = listSendsCommand
  exports.listFoldersCommand = listFoldersCommand
  exports.listOrganizationsCommand = listOrganizationsCommand
  exports.listOrgCollectionsCommand = listOrgCollectionsCommand
  exports.getTotpCommand = getTotpCommand
  exports.statusCommand = statusCommand
  exports.unlockCommand = unlockCommand
  exports.generateCommand = generateCommand
  exports.generateServeRequestCommand = generateServeRequestCommand
  exports.createSendCommand = createSendCommand
  exports.createFileSendCommand = createFileSendCommand
  exports.createItemCommand = createItemCommand
  exports.editItemCommand = editItemCommand
  exports.deleteItemCommand = deleteItemCommand
  exports.createFolderCommand = createFolderCommand
  exports.deleteFolderCommand = deleteFolderCommand
  exports.attachmentDownloadCommand = attachmentDownloadCommand
  exports.sessionHandoffReadCommand = sessionHandoffReadCommand
  exports.associationsReadCommand = associationsReadCommand
  exports.keyringLookupCommand = keyringLookupCommand
  exports.keyringLookupMasterPasswordCommand = keyringLookupMasterPasswordCommand
  exports.pinUnlockCommand = pinUnlockCommand
  exports.dependencyCheckCommand = dependencyCheckCommand
  exports.buildCappedCommand = buildCappedCommand
  exports.buildCommand = buildCommand
  exports.syncCommand = syncCommand
  exports.deleteSendCommand = deleteSendCommand
  exports.settingWriteCommand = settingWriteCommand
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => {
  if (ok) {
    pass++
  } else {
    failures.push(`${label}\n    ${detail}`)
  }
}

const flat = (cmd) => (Array.isArray(cmd) ? cmd.join(" ") : String(cmd))

// 1. Vault item list stream is capped
const listCmd = Model.listCommand()
check("listCommand produces bash pipeline with head -c byte cap",
  flat(listCmd).includes("bw list items") && flat(listCmd).includes("head -c 16777216"),
  flat(listCmd))
check("listCommand caps diagnostic stderr stream",
  flat(listCmd).includes("exec 2> >(head -c 8192 >&2)"),
  flat(listCmd))

// 2. Vault item detail stream is capped
const getItemCmd = Model.getItemCommand("12345-abc")
check("getItemCommand caps item detail output to 4MB",
  flat(getItemCmd).includes("bw get item -- 12345-abc") && flat(getItemCmd).includes("head -c 4194304"),
  flat(getItemCmd))
check("getItemCommand caps stderr stream",
  flat(getItemCmd).includes("exec 2> >(head -c 8192 >&2)"),
  flat(getItemCmd))

// 3. Bitwarden send list stream is capped
const sendsCmd = Model.listSendsCommand()
check("listSendsCommand caps send list output to 8MB",
  flat(sendsCmd).includes("bw send list") && flat(sendsCmd).includes("head -c 8388608"),
  flat(sendsCmd))

// 4. Folder list stream is capped
const foldersCmd = Model.listFoldersCommand()
check("listFoldersCommand caps folder list output to 2MB",
  flat(foldersCmd).includes("bw list folders") && flat(foldersCmd).includes("head -c 2097152"),
  flat(foldersCmd))

// 5. Organization list stream is capped
const orgsCmd = Model.listOrganizationsCommand()
check("listOrganizationsCommand caps org list output to 2MB",
  flat(orgsCmd).includes("bw list organizations") && flat(orgsCmd).includes("head -c 2097152"),
  flat(orgsCmd))

// 6. Organization collections stream is capped
const orgColsCmd = Model.listOrgCollectionsCommand("org-99")
check("listOrgCollectionsCommand caps collections output to 2MB",
  flat(orgColsCmd).includes("bw list org-collections --organizationid org-99") && flat(orgColsCmd).includes("head -c 2097152"),
  flat(orgColsCmd))

// 7. Status and unlock streams are capped
const statusCmd = Model.statusCommand()
check("statusCommand caps status json output to 64KB",
  flat(statusCmd).includes("bw status") && flat(statusCmd).includes("head -c 65536"),
  flat(statusCmd))

const unlockCmd = Model.unlockCommand()
check("unlockCommand caps session token output to 4KB",
  flat(unlockCmd).includes("bw unlock") && flat(unlockCmd).includes("head -c 4096"),
  flat(unlockCmd))

// 8. TOTP code stream is capped
const totpCmd = Model.getTotpCommand("item-55")
check("getTotpCommand caps totp output to 4KB",
  flat(totpCmd).includes("bw get totp --raw -- item-55") && flat(totpCmd).includes("head -c 4096"),
  flat(totpCmd))

// 9. Session handoff file reader is size-bounded
const handoffCmd = Model.sessionHandoffReadCommand(true)
check("sessionHandoffReadCommand bounds file reading with head -c 4096",
  flat(handoffCmd).includes("head -c 4096") && !flat(handoffCmd).includes("cat \"$f\""),
  flat(handoffCmd))

// 10. Associations file reader is size-bounded
const assocCmd = Model.associationsReadCommand()
check("associationsReadCommand bounds file reading with head -c 1048576",
  flat(assocCmd).includes("head -c 1048576") && !flat(assocCmd).includes("cat \"$ASSOC_FILE\""),
  flat(assocCmd))

// 11. Keyring lookups and PIN unlock are size-bounded
const keyringCmd = Model.keyringLookupCommand()
check("keyringLookupCommand bounds secret-tool output to 4KB",
  flat(keyringCmd).includes("head -c 4096") && flat(keyringCmd).includes("head -c 128"),
  flat(keyringCmd))

const pinCmd = Model.pinUnlockCommand()
check("pinUnlockCommand bounds both ciphertext lookup and decrypted password",
  flat(pinCmd).includes("head -c 8192") && flat(pinCmd).includes("head -c 4096"),
  flat(pinCmd))

// 12. Password generator output is capped
const genPassCmd = Model.generateCommand({ length: 32 })
check("generateCommand caps password output to 4KB",
  flat(genPassCmd).includes("bw generate") && flat(genPassCmd).includes("head -c 4096"),
  flat(genPassCmd))

// 12b. Generator serve request stream is capped on the producer side
const serveReqCmd = Model.generateServeRequestCommand({ length: 24 })
check("generateServeRequestCommand bounds loopback response stream with head -c 65536",
  flat(serveReqCmd).includes("curl -s -S") && flat(serveReqCmd).includes("head -c 65536"),
  flat(serveReqCmd))

// 13. Create/Edit/Delete commands are capped
const createFolderCmd = Model.createFolderCommand("test")
check("createFolderCommand caps stderr and response",
  flat(createFolderCmd).includes("exec 2> >(head -c 8192 >&2)") && flat(createFolderCmd).includes("head -c 65536"),
  flat(createFolderCmd))

const createItemCmd = Model.createItemCommand({ organizationId: "org-1" })
check("createItemCommand caps stderr and response",
  flat(createItemCmd).includes("exec 2> >(head -c 8192 >&2)") && flat(createItemCmd).includes("head -c 65536"),
  flat(createItemCmd))

const editItemCmd = Model.editItemCommand("item-1")
check("editItemCommand caps stderr and response",
  flat(editItemCmd).includes("exec 2> >(head -c 8192 >&2)") && flat(editItemCmd).includes("head -c 65536"),
  flat(editItemCmd))

const deleteItemCmd = Model.deleteItemCommand("item-1")
check("deleteItemCommand caps stderr and response",
  flat(deleteItemCmd).includes("exec 2> >(head -c 8192 >&2)") && flat(deleteItemCmd).includes("head -c 65536"),
  flat(deleteItemCmd))

// 14. Live execution check: verify head -c truncation behaviour on huge stream
const hugeScript = "yes 'unbounded streaming line' | head -c 1024"
const hugeOut = execFileSync("bash", ["-c", hugeScript], { encoding: "utf8" })
check("head -c strictly bounds incoming stream to exact byte count",
  Buffer.byteLength(hugeOut, "utf8") === 1024,
  `Expected 1024 bytes, got ${Buffer.byteLength(hugeOut, "utf8")}`)

// 15. Live execution check: verify stderr bounding does not corrupt stdout
const stderrScript = "exec 2> >(head -c 100 >&2); echo 'stdout data'; (echo 'short stderr error' >&2)"
const proc = execFileSync("bash", ["-c", stderrScript], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
check("capped stderr does not leak into stdout",
  proc.trim() === "stdout data",
  `stdout was: ${JSON.stringify(proc)}`)

// 16. A cap must not swallow the producer's exit status. `head -c` closes the
// pipe and exits 0, so without `pipefail` every failing bw command would reach
// the panel as a success and the UI would report "Item deleted" for a delete
// that never happened.
const cappedBuilders = [
  ["listCommand", Model.listCommand()],
  ["getItemCommand", Model.getItemCommand("x")],
  ["deleteItemCommand", Model.deleteItemCommand("x")],
  ["deleteSendCommand", Model.deleteSendCommand("x")],
  ["syncCommand", Model.syncCommand()],
  ["createItemCommand", Model.createItemCommand({})],
  ["editItemCommand", Model.editItemCommand("x")],
  ["createSendCommand", Model.createSendCommand()],
  ["createFolderCommand", Model.createFolderCommand("x")],
  ["settingWriteCommand", Model.settingWriteCommand("autoLockMinutes", 5, "int")],
]
for (const [name, cmd] of cappedBuilders) {
  check(`${name} restores the producer's exit status with pipefail`,
    flat(cmd).includes("set -o pipefail"), flat(cmd))
  check(`${name} does not report truncation (SIGPIPE 141) as a failure`,
    flat(cmd).includes('case "$__rc" in 141) __rc=0 ;; esac'), flat(cmd))
}

// 17. Live execution check, with a stub `bw`: a failing command must exit
// non-zero through the cap, and a stream large enough to hit the cap must not
// be mistaken for a failure.
const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-stream-"))
fs.writeFileSync(path.join(stubDir, "bw"), [
  "#!/bin/bash",
  'case "$*" in',
  '  *boom*) echo "error: bad request" >&2; exit 1 ;;',
  "  *big*) yes '{\"x\":\"aaaaaaaaaaaaaaaaaaaa\"}' ;;",
  "  *) echo '{\"ok\":true}' ;;",
  "esac",
  "",
].join("\n"))
fs.chmodSync(path.join(stubDir, "bw"), 0o755)
const stubEnv = Object.assign({}, process.env, { PATH: stubDir + path.delimiter + process.env.PATH })

const runScript = (script) => {
  const r = spawnSync("bash", ["-c", script], {
    env: stubEnv, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  })
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" }
}

const failRun = runScript(Model.deleteItemCommand("boom")[2])
check("a failing bw command exits non-zero through the cap",
  failRun.code === 1, `exit ${failRun.code}, stderr ${JSON.stringify(failRun.stderr)}`)
check("a failing bw command still delivers its stderr to the panel",
  failRun.stderr.includes("bad request"), JSON.stringify(failRun.stderr))

const okRun = runScript(Model.deleteItemCommand("fine")[2])
check("a succeeding bw command exits zero through the cap",
  okRun.code === 0, `exit ${okRun.code}`)

// `bw big` never stops printing: only the cap ends it, and the SIGPIPE that
// follows must not be reported as a failed vault read.
const truncRun = runScript(Model.getItemCommand("big")[2])
check("hitting the cap is not reported as a failure",
  truncRun.code === 0, `exit ${truncRun.code}`)
check("hitting the cap truncates at exactly the limit",
  Buffer.byteLength(truncRun.stdout, "utf8") === 4 * 1024 * 1024,
  `got ${Buffer.byteLength(truncRun.stdout, "utf8")} bytes`)

fs.rmSync(stubDir, { recursive: true, force: true })

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
