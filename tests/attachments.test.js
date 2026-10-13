#!/usr/bin/env node
// Attachment metadata comes with `bw list items`; only the bytes are fetched,
// on demand. Checks that the metadata survives both parse paths and that a
// vault file name cannot escape the download directory.
//
//   node tests/attachments.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")
const fs = require("fs")
const path = require("path")
const panelSrc = readPluginSource("Panel.qml")
const bodyOf = name => functionBody(panelSrc, name)
const Model = loadModule()

const { check, done } = createSuite("attachments")

const withFiles = {
  object: "item", id: "11111111-1111-1111-1111-111111111111",
  organizationId: null, folderId: null, type: 2, name: "Recovery Codes",
  notes: "", favorite: false, secureNote: { type: 0 },
  attachments: [
    { object: "attachment", id: "a1", fileName: "codes.txt", size: "412", sizeName: "412 B" },
    { object: "attachment", id: "a2", fileName: "key.pem", size: "3204", sizeName: "3.13 KB" }
  ]
}

const withoutFiles = {
  object: "item", id: "22222222-2222-2222-2222-222222222222",
  type: 1, name: "GitHub", notes: "", favorite: false,
  login: { username: "octocat", password: "s3cr3t", uris: [] }
}

// --- the metadata survives every path an item can arrive by ------------------

const detail = Model.itemDetailFromObject(withFiles)
check("the detail view sees both attachments",
  detail.hasAttachments && detail.attachments.length === 2,
  JSON.stringify(detail.attachments))
check("with the name and size bw reported",
  detail.attachments[0].fileName === "codes.txt" && detail.attachments[0].sizeName === "412 B",
  JSON.stringify(detail.attachments[0]))

check("the list-built detail matches the get-item-built detail",
  JSON.stringify(Model.itemDetailFromObject(withFiles))
    === JSON.stringify(Model.parseItemDetail(JSON.stringify(withFiles))),
  JSON.stringify(Model.itemDetailFromObject(withFiles).attachments))

const listed = Model.parseItems(JSON.stringify([withFiles, withoutFiles]))
const listedWith = listed.find(i => i.id === withFiles.id)
const listedWithout = listed.find(i => i.id === withoutFiles.id)
check("the list row knows the item has files, which is what draws the paperclip",
  listedWith.hasAttachments === true, String(listedWith.hasAttachments))
check("and knows when it has none",
  listedWithout.hasAttachments === false && listedWithout.attachments.length === 0,
  JSON.stringify(listedWithout.attachments))
check("opening a listed item still yields its attachments without a second call",
  Model.itemDetailFromObject(listedWith.rawObject).attachments.length === 2,
  JSON.stringify(Model.itemDetailFromObject(listedWith.rawObject).attachments))

// --- malformed metadata is dropped, never rendered ---------------------------

check("a missing attachments array is an empty list, not a crash",
  Model.parseAttachments(undefined).length === 0, "threw or returned non-empty")
check("a non-array is too", Model.parseAttachments("nope").length === 0, "non-empty")
check("an entry with no id is dropped -- there is nothing to fetch it by",
  Model.parseAttachments([{ fileName: "orphan.txt" }]).length === 0, "kept")
check("an entry with no file name still gets a label",
  Model.parseAttachments([{ id: "x" }])[0].fileName === "attachment",
  Model.parseAttachments([{ id: "x" }])[0].fileName)

// --- the size fallback, for entries that arrive without sizeName -------------

const sized = Model.parseAttachments([{ id: "x", fileName: "f", size: "2048" }])
check("a byte count with no sizeName is formatted", sized[0].sizeName === "2 KB", sized[0].sizeName)
for (const [bytes, want] of [[0, "0 B"], [512, "512 B"], [1024, "1 KB"],
                             [1536, "1.5 KB"], [1048576, "1 MB"], [5242880, "5 MB"]]) {
  check(`${bytes} bytes reads as ${want}`, Model.formatAttachmentSize(bytes) === want,
    Model.formatAttachmentSize(bytes))
}
check("a missing size yields no size text rather than NaN",
  Model.formatAttachmentSize(undefined) === "", Model.formatAttachmentSize(undefined))
check("so does junk", Model.formatAttachmentSize("banana") === "", Model.formatAttachmentSize("banana"))

// --- a vault file name cannot escape the download directory ------------------
//
// The name is decrypted vault content, and the path is built from it.

const traversals = [
  "../../.bashrc",
  "/etc/passwd",
  "..\\..\\windows\\system32\\evil.dll",
  "sub/dir/../../../../root/.ssh/authorized_keys",
  "....//....//etc/shadow"
]
for (const raw of traversals) {
  const safe = Model.safeAttachmentFileName(raw)
  check(`"${raw}" cannot traverse`,
    safe.indexOf("/") === -1 && safe.indexOf("\\") === -1 && safe !== ".." && safe !== ".",
    safe)
  check(`"${raw}" cannot start a path or a flag`,
    safe[0] !== "." && safe[0] !== "-" && safe[0] !== "/", safe)
}

check("a NUL is neutralised", Model.safeAttachmentFileName("a\u0000b").indexOf("\u0000") === -1,
  JSON.stringify(Model.safeAttachmentFileName("a\u0000b")))
check("so is a newline, which no shell quoting would have caught on its own",
  Model.safeAttachmentFileName("a\nrm -rf ~\n").indexOf("\n") === -1,
  JSON.stringify(Model.safeAttachmentFileName("a\nrm -rf ~\n")))
check("an empty name still yields something openable",
  Model.safeAttachmentFileName("") === "attachment", Model.safeAttachmentFileName(""))
check("a name of nothing but dots does too",
  Model.safeAttachmentFileName("...") === "attachment", Model.safeAttachmentFileName("..."))
check("an ordinary name is left alone",
  Model.safeAttachmentFileName("Scan 2026-08-21.pdf") === "Scan 2026-08-21.pdf",
  Model.safeAttachmentFileName("Scan 2026-08-21.pdf"))
check("spaces and unicode survive",
  Model.safeAttachmentFileName("résumé final.pdf") === "résumé final.pdf",
  Model.safeAttachmentFileName("résumé final.pdf"))

const long = Model.safeAttachmentFileName("x".repeat(400) + ".pdf")
check("an absurdly long name is truncated but keeps its extension",
  long.length <= 128 && long.slice(-4) === ".pdf", `${long.length} ${long.slice(-8)}`)

// --- the download command ----------------------------------------------------

const cmd = Model.attachmentDownloadCommand("a1", "item-id")
check("it runs through bash, because the download directory is resolved at run time",
  cmd[0] === "bash" && cmd[1] === "-c", JSON.stringify(cmd.slice(0, 2)))

const script = cmd[2]
check("the attachment id and item id are quoted, never interpolated bare",
  script.indexOf("bw get attachment --itemid 'item-id'") !== -1
    && script.indexOf("-- 'a1'") !== -1, script)
check("the decrypted file name never reaches argv, which /proc shows every local user",
  Model.attachmentDownloadCommand.length === 3 && !/codes|name=/.test(cmd.join("\n")), script)
check("it travels in the environment, already sanitised",
  Model.attachmentDownloadEnv("../../codes.txt")[Model.attachmentNameEnvVar()] === "codes.txt"
    && Model.attachmentNameEnvVar() === "QSBW_ATTACHMENT_NAME",
  JSON.stringify(Model.attachmentDownloadEnv("../../codes.txt")))
check("the panel hands the download its name only through the environment",
  /attachmentDownloadCommand\(job\.id, job\.itemId, job\.size\)/.test(bodyOf("pumpAttachmentQueue"))
    && /attachmentBusyName = String\(job\.fileName/.test(bodyOf("pumpAttachmentQueue"))
    && /environment: root\.bwEnv\(Model\.attachmentDownloadEnv\(root\.attachmentBusyName\)\)/.test(panelSrc),
  bodyOf("pumpAttachmentQueue"))
check("it prints where the file landed, which is how the panel learns the path",
  /printf %s "\$out"/.test(script), script)
check("it claims the name with link(), which is the existence test and the creation at once",
  script.indexOf("fs.linkSync(tmp, c)") !== -1 && !/\bln -- /.test(script), script)
check("it no longer decides the name with a test a symlink can answer for",
  script.indexOf('while [ -e "$out" ]') === -1, script)
check("the bytes are staged in a private directory before they are placed",
  script.indexOf('mktemp -d -- "$dir/.qsbw-XXXXXXXX"') !== -1
    && script.indexOf('--output "$tmp"') !== -1, script)
check("the staging directory is removed however the script leaves",
  script.indexOf(`trap 'rm -rf -- "$work"' EXIT`) !== -1, script)
check("a decrypted attachment is not left readable by anyone else",
  script.split("\n").indexOf("umask 077") !== -1, script)
check("locking and panel dismissal cancel an attachment that is still decrypting",
  /cancelAttachmentDownloads\(\)/.test(bodyOf("dropVaultState"))
    && /cancelAttachmentDownloads\(\)/.test(bodyOf("close"))
    && /if\s*\(attachmentProc\.running\)\s*attachmentProc\.running\s*=\s*false/.test(bodyOf("cancelAttachmentDownloads"))
    && /invalidateEpochOperation\("attachment"\)/.test(bodyOf("cancelAttachmentDownloads")),
  bodyOf("close") + "\n" + bodyOf("dropVaultState") + "\n" + bodyOf("cancelAttachmentDownloads"))
check("cancellation reaches the complete attachment process group",
  script.includes("set -m") && script.includes('kill -TERM -- "-$__auth_job"'), script)

// --- the ceilings ------------------------------------------------------------
check("the transfer is bounded in bytes by RLIMIT_FSIZE",
  /ulimit -f \d+/.test(script), script)
check("the transfer is bounded in time",
  /timeout \d+s bw get attachment/.test(script)
    && !script.includes("command -v timeout"), script)
check("the disk is not filled to the last byte",
  script.indexOf("df -Pk") !== -1, script)
check("an unknown declared size reserves room for the full bounded transfer",
  script.indexOf('[ "$avail" -lt 589824 ]') !== -1, script)
check("the size the vault declares buys an early refusal",
  script.indexOf('if [ "$want" -gt "$max" ]') !== -1, script)
check("the size on disk is checked even where the kernel limit was not applied",
  script.indexOf('wc -c < "$tmp"') !== -1, script)

const withSize = Model.attachmentDownloadCommand("a1", "item-id", "4096")
check("the declared size reaches the script", withSize[2].indexOf("want=4096") !== -1, withSize[2])
check("a missing or nonsense declared size is treated as unknown, not as a refusal",
  Model.attachmentDownloadCommand("a1", "i")[2].indexOf("want=0") !== -1
    && Model.attachmentDownloadCommand("a1", "i", "nope")[2].indexOf("want=0") !== -1,
  Model.attachmentDownloadCommand("a1", "i", "nope")[2])
check("the no-hardlink fallback still refuses to replace a raced destination",
  script.indexOf('fs.openSync(c, "wx")') !== -1 && !/\bmv -n/.test(script), script)
check("it refuses to treat $HOME as the download directory",
  script.indexOf("\"$dir\" = \"$HOME\"") !== -1, script)
check("it stops at the first failure rather than printing a path for a file it did not write",
  /set -e/.test(script), script.split("\n")[0])

// Hostile ids stay quoted; a hostile name reaches the environment defanged.
const hostile = Model.attachmentDownloadCommand("a'1", "i'd")
check("a quote in the attachment id cannot break out of its quoting",
  hostile[2].indexOf("bw get attachment --itemid 'i'\\''d'") !== -1
    && hostile[2].indexOf("-- 'a'\\''1'") !== -1, hostile[2])
check("a traversing name is sanitised before it reaches the environment",
  Model.attachmentDownloadEnv("../../.bashrc")[Model.attachmentNameEnvVar()] === "bashrc",
  JSON.stringify(Model.attachmentDownloadEnv("../../.bashrc")))

// --- path helpers the detail view uses ---------------------------------------

check("parentDirectory finds the folder to reveal",
  Model.parentDirectory("/home/u/Downloads/f.pdf") === "/home/u/Downloads",
  Model.parentDirectory("/home/u/Downloads/f.pdf"))
check("a root-level file reveals /", Model.parentDirectory("/f.pdf") === "/",
  Model.parentDirectory("/f.pdf"))
check("a bare name has no folder to reveal", Model.parentDirectory("f.pdf") === "",
  Model.parentDirectory("f.pdf"))
check("baseName names the saved file for the flash message",
  Model.baseName("/home/u/Downloads/f.pdf") === "f.pdf",
  Model.baseName("/home/u/Downloads/f.pdf"))

// --- the shape QML hands back ------------------------------------------------
//
// A cipher stored in a QML `var` comes back with array-like objects for which
// Array.isArray() is false (the detail view once found no attachments this
// way). Node gives real arrays, so fake the conversion.

const qmlish = (arr) => {
  // Array-like, deliberately not an Array -- what Qt hands back.
  const o = { length: arr.length }
  arr.forEach((v, i) => { o[i] = v && typeof v === "object" ? qmlish_obj(v) : v })
  return o
}
const qmlish_obj = (obj) => {
  if (Array.isArray(obj)) return qmlish(obj)
  const out = {}
  for (const k of Object.keys(obj)) {
    const v = obj[k]
    out[k] = (v && typeof v === "object") ? qmlish_obj(v) : v
  }
  return out
}

const roundTripped = qmlish_obj(withFiles)
check("the round-tripped attachments really are not an Array, or this test proves nothing",
  !Array.isArray(roundTripped.attachments) && roundTripped.attachments.length === 2,
  `${Array.isArray(roundTripped.attachments)} len=${roundTripped.attachments.length}`)

const rtDetail = Model.itemDetailFromObject(roundTripped)
check("attachments survive the QML round trip",
  rtDetail.hasAttachments && rtDetail.attachments.length === 2,
  JSON.stringify(rtDetail.attachments))
check("with their names intact",
  rtDetail.attachments.length > 0 && rtDetail.attachments[0].fileName === "codes.txt",
  JSON.stringify(rtDetail.attachments))

// The same conversion silently emptied these two long before attachments
// existed: the detail view's WEBSITE section and its custom fields.
const login = {
  object: "item", id: "33333333-3333-3333-3333-333333333333", type: 1,
  name: "GitHub", notes: "", favorite: false,
  login: { username: "octocat", password: "p", uris: [{ match: null, uri: "https://github.com" }] },
  fields: [{ name: "recovery", value: "abcd", type: 1 }]
}
const rtLogin = Model.itemDetailFromObject(qmlish_obj(login))
check("URIs survive it too -- the WEBSITE section was empty for every login",
  rtLogin.uris.length === 1 && rtLogin.uris[0] === "https://github.com",
  JSON.stringify(rtLogin.uris))
check("and so do custom fields",
  rtLogin.fields.length === 1 && rtLogin.fields[0].name === "recovery",
  JSON.stringify(rtLogin.fields))

// The same for the per-keystroke readers: URL search and site matching.
const rtListItem = Model.parseItems(JSON.stringify([login])).map(qmlish_obj)
check("searching by URL still finds the item after the round trip",
  Model.filterItems(rtListItem, "github.com", "all", "all", "all").length === 1,
  `matched ${Model.filterItems(rtListItem, "github.com", "all", "all", "all").length} items`)
check("and the site's own domain still identifies it",
  Model.itemDomains(rtListItem[0]).length === 1
    && Model.itemDomains(rtListItem[0])[0].baseDomain === "github.com",
  JSON.stringify(Model.itemDomains(rtListItem[0])))
check("so the focused tab still suggests it",
  Model.findContextualMatches(rtListItem,
    { class: "chromium", title: "Pulls - github.com - Chromium", mapped: true })
    .matches.length === 1,
  "expected the item back on a domain match")

// The list parser held the same ceiling as the detail parser everywhere except
// here, where the URI array is real and was copied out entry for entry. A
// single item is free to carry as many as the byte cap allows.
const floodUris = []
for (let i = 0; i < 5000; i++) floodUris.push({ uri: "https://example" + i + ".com" })
check("a flooded URI list is held to the ceiling on the list path too",
  Model.parseItems(JSON.stringify([{ id: "i", type: 1, login: { uris: floodUris } }]))[0].uris.length === 4096,
  String(Model.parseItems(JSON.stringify([{ id: "i", type: 1, login: { uris: floodUris } }]))[0].uris.length))

// toList must not mistake a string, or anything else with a length, for a list.
check("a string is not a list of characters",
  Model.parseAttachments("nope").length === 0, "treated a string as a list")
check("an object with a junk length is not a list",
  Model.parseAttachments({ length: -1 }).length === 0
    && Model.parseAttachments({ length: 1.5 }).length === 0
    && Model.parseAttachments({ length: "2" }).length === 0, "accepted a junk length")

// A duck-typed length is the server's claim ({"length": 2e8} is 40 bytes), so
// it is a ceiling, not an instruction.
const manyUris = { length: 5000 }
for (let i = 0; i < 5000; i++) manyUris[i] = { uri: "https://example" + i + ".com" }
check("a list longer than any real item stops at the ceiling",
  Model.itemDetailFromObject({ id: "i", type: 1, login: { uris: manyUris } }).uris.length === 4096,
  String(Model.itemDetailFromObject({ id: "i", type: 1, login: { uris: manyUris } }).uris.length))

const manyReal = []
for (let i = 0; i < 5000; i++) manyReal.push({ id: "a" + i, fileName: "f" + i, size: "1" })
check("and a real array is held to the same ceiling",
  Model.parseAttachments(manyReal).length === 4096, String(Model.parseAttachments(manyReal).length))

// Run in a child with a small heap: with the ceiling this finishes instantly,
// and without it the parse takes the whole process down with it -- which, in
// the panel, is the shell.
const lengthLie = `
  const M = require(${JSON.stringify(path.join(__dirname, "harness.js"))}).loadModule()
  M.parseItems(JSON.stringify([{
    object: "item", id: "x", type: 1, name: "n",
    attachments: { length: 200000000 },
    login: { uris: { length: 200000000 } },
    fields: { length: 200000000 }
  }]))
`
let survived = true
try {
  require("child_process").execFileSync(process.execPath,
    ["--max-old-space-size=256", "-e", lengthLie],
    { stdio: ["ignore", "pipe", "pipe"], timeout: 30000 })
} catch (e) {
  survived = false
}
check("a declared length of two hundred million does not take the shell process with it",
  survived, "the parse exhausted the heap")

// --- and the script actually run ---------------------------------------------
//
// Run for real against a stub `bw` and a throwaway HOME: traversal ends inside
// the download dir, and collisions never overwrite.

const os = require("os")
const { execFileSync } = require("child_process")

const home = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-attachments-"))
const bin = path.join(home, "bin")
fs.mkdirSync(bin)
fs.writeFileSync(path.join(bin, "bw"), `#!/usr/bin/env bash
# Stands in for the CLI: writes whatever --output names, or fails on demand.
out=""
while [ $# -gt 0 ]; do if [ "$1" = "--output" ]; then out="$2"; fi; shift; done
if [ -n "$QSBW_TEST_FAIL" ]; then echo "Not found." >&2; exit 1; fi
# What another local user sees mid-transfer: every process's argv.
if [ -n "$QSBW_TEST_SCAN" ]; then
  for f in /proc/[0-9]*/cmdline; do
    if tr '\\0' ' ' < "$f" 2>/dev/null | grep -qF -- "$QSBW_TEST_SCAN"; then echo "argv leak: $f" >&2; exit 1; fi
  done
fi
printf 'bytes\\n' > "$out"
echo "Saved $out"
`)
fs.chmodSync(path.join(bin, "bw"), 0o755)

// The claim and open steps run `node`, which CI installs outside /usr/bin.
const nodeDir = path.dirname(process.execPath)
const env = { PATH: bin + ":" + nodeDir + ":/usr/bin:/bin", HOME: home }
const run = (fileName, extra, declaredSize) => {
  const cmd = Model.attachmentDownloadCommand("att-id", "item-id", declaredSize)
  return execFileSync(cmd[0], cmd.slice(1), {
    env: Object.assign({}, env, Model.attachmentDownloadEnv(fileName), extra || {}),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  })
}

const downloads = path.join(home, "Downloads")
const firstSave = run("codes.txt")
check("the file lands in the download directory",
  firstSave === path.join(downloads, "codes.txt"), firstSave)
check("a second file of the same name does not overwrite the first",
  run("codes.txt") === path.join(downloads, "codes (1).txt"), "overwrote")
check("and a third keeps counting",
  run("codes.txt") === path.join(downloads, "codes (2).txt"), "overwrote")
check("a name with no extension still gets a free slot",
  run("notes") === path.join(downloads, "notes")
    && run("notes") === path.join(downloads, "notes (1)"), "collided")
check("a quote in the file name is data, not syntax",
  run("it's here.txt") === path.join(downloads, "it's here.txt"), "broke out")

// Random, so nothing else on the machine carries it in argv.
const transferScan = "scan-" + require("crypto").randomBytes(8).toString("hex")
check("the name is in no process's argv while the transfer runs",
  run(transferScan + ".txt", { QSBW_TEST_SCAN: transferScan }) === path.join(downloads, transferScan + ".txt"),
  "leaked")

// Filesystems without hard links: link() fails, so an O_EXCL placeholder
// claims the name and rename() fills it.
const noLink = path.join(home, "no-link.js")
fs.writeFileSync(noLink, `require("fs").linkSync = function () {
  const e = new Error("EPERM"); e.code = "EPERM"; throw e }
`)
const noLinkEnv = { NODE_OPTIONS: "--require " + noLink }
check("without hard links the file still lands under its own name",
  run("vfat.txt", noLinkEnv) === path.join(downloads, "vfat.txt")
    && fs.readFileSync(path.join(downloads, "vfat.txt"), "utf8") === "bytes\n", "fallback failed")
check("and without hard links an existing file is not replaced",
  run("vfat.txt", noLinkEnv) === path.join(downloads, "vfat (1).txt")
    && fs.readFileSync(path.join(downloads, "vfat.txt"), "utf8") === "bytes\n", "replaced")
fs.symlinkSync(path.join(home, "target-of-dangling"), path.join(downloads, "dangling.txt"))
check("and a dangling symlink at the name is skipped, not followed",
  run("dangling.txt", noLinkEnv) === path.join(downloads, "dangling (1).txt")
    && !fs.existsSync(path.join(home, "target-of-dangling")), "followed")
// The claim step reads the name from the environment too: nothing in any
// argv while it runs either.
const scan = path.join(home, "scan.js")
fs.writeFileSync(scan, `const fs = require("fs")
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d)) continue
  let argv = ""
  try { argv = fs.readFileSync("/proc/" + d + "/cmdline", "latin1") } catch (e) { continue }
  if (argv.indexOf(process.env.QSBW_TEST_SCAN) !== -1) { process.stderr.write("argv leak\\n"); process.exit(1) }
}
`)
const claimScan = "scan-" + require("crypto").randomBytes(8).toString("hex")
check("the name is in no process's argv while it is claimed",
  run(claimScan + ".txt", { QSBW_TEST_SCAN: claimScan, NODE_OPTIONS: "--require " + scan })
    === path.join(downloads, claimScan + ".txt"), "leaked")

// Something replaces the name between the O_EXCL create and the copy.
const raced = path.join(home, "raced.js")
fs.writeFileSync(raced, `const fs = require("fs")
fs.linkSync = function () { const e = new Error("EPERM"); e.code = "EPERM"; throw e }
const open = fs.openSync
fs.openSync = function (p, flags) {
  const fd = open.apply(fs, arguments)
  if (flags === "wx") { fs.unlinkSync(p); fs.writeFileSync(p, "theirs\\n") }
  return fd
}
if (process.env.QSBW_TEST_WRITE_FAIL) fs.write = fs.writev = function () {
  const e = new Error("ENOSPC"); e.code = "ENOSPC"; arguments[arguments.length - 1](e) }
`)
const racedEnv = { NODE_OPTIONS: "--require " + raced }
run("raced.txt", racedEnv)
check("without hard links a raced replacement is never overwritten",
  fs.readFileSync(path.join(downloads, "raced.txt"), "utf8") === "theirs\n",
  fs.readFileSync(path.join(downloads, "raced.txt"), "utf8"))
let copyFailed = null
try { run("raced-fail.txt", Object.assign({ QSBW_TEST_WRITE_FAIL: "1" }, racedEnv)) } catch (e) { copyFailed = e }
check("and a failed copy does not delete or empty the replacement",
  copyFailed !== null && fs.readFileSync(path.join(downloads, "raced-fail.txt"), "utf8") === "theirs\n",
  copyFailed ? fs.readFileSync(path.join(downloads, "raced-fail.txt"), "utf8") : "succeeded")

// A failed or cancelled copy never unlinks by name (that name may by then be
// another file): it empties its own descriptor and says what it left.
const isEmptyFile = p => fs.existsSync(p) && fs.lstatSync(p).isFile() && fs.statSync(p).size === 0
const noLinkFaults = path.join(home, "no-link-faults.js")
fs.writeFileSync(noLinkFaults, fs.readFileSync(noLink, "utf8") + `const fs = require("fs")
const read = fs.read, write = fs.write
let reads = 0
// The second read fails, after the first chunk was written.
if (process.env.QSBW_TEST_READ_FAIL) fs.read = function () {
  if (++reads === 2) { const e = new Error("EIO"); e.code = "EIO"; return arguments[arguments.length - 1](e) }
  return read.apply(fs, arguments)
}
if (process.env.QSBW_TEST_TRUNCATE_FAIL) fs.ftruncateSync = function () {
  const e = new Error("EIO"); e.code = "EIO"; throw e }
// The lock's SIGTERM arrives while a write is in flight, which then lands.
if (process.env.QSBW_TEST_CANCEL) fs.write = function () {
  const args = arguments
  process.kill(process.pid, "SIGTERM")
  setTimeout(() => write.apply(fs, args), 50)
}
`)
const noLinkFaultsEnv = { NODE_OPTIONS: "--require " + noLinkFaults }
let partial = null
try { run("partial.txt", Object.assign({ QSBW_TEST_READ_FAIL: "1" }, noLinkFaultsEnv)) } catch (e) { partial = e }
check("a copy that fails partway leaves an empty file, not decrypted bytes, and says so",
  partial !== null && isEmptyFile(path.join(downloads, "partial.txt"))
    && String(partial.stderr).indexOf("an empty partial.txt was left there") !== -1,
  partial ? String(partial.stderr) : "succeeded")

let unemptied = null
try {
  run("unemptied.txt", Object.assign({ QSBW_TEST_READ_FAIL: "1", QSBW_TEST_TRUNCATE_FAIL: "1" }, noLinkFaultsEnv))
} catch (e) { unemptied = e }
check("and when it cannot even empty it, it says part of the attachment may remain",
  unemptied !== null && String(unemptied.stderr).indexOf("unemptied.txt there may still hold part of the attachment") !== -1
    && String(unemptied.stderr).indexOf("an empty") === -1,
  unemptied ? String(unemptied.stderr) : "succeeded")

let cancelled = null
try { run("cancelled.txt", Object.assign({ QSBW_TEST_CANCEL: "1" }, noLinkFaultsEnv)) } catch (e) { cancelled = e }
check("a copy cancelled mid-write is emptied after that write lands, not before",
  cancelled !== null && isEmptyFile(path.join(downloads, "cancelled.txt")),
  cancelled ? String(fs.statSync(path.join(downloads, "cancelled.txt")).size) : "succeeded")

// The same signal landing right after the O_EXCL create, before the copy.
const cancelAtClaim = path.join(home, "cancel-at-claim.js")
fs.writeFileSync(cancelAtClaim, fs.readFileSync(noLink, "utf8") + `const fs = require("fs")
const open = fs.openSync
fs.openSync = function (p, flags) {
  const fd = open.apply(fs, arguments)
  if (flags === "wx") process.kill(process.pid, "SIGTERM")
  return fd
}
`)
let cancelledAtClaim = null
try { run("cancelled-at-claim.txt", { NODE_OPTIONS: "--require " + cancelAtClaim }) } catch (e) { cancelledAtClaim = e }
check("a cancel that lands as the name is claimed leaves at most an empty file",
  cancelledAtClaim !== null && isEmptyFile(path.join(downloads, "cancelled-at-claim.txt")),
  cancelledAtClaim ? "not empty" : "succeeded")

check("no staging directory is left behind",
  fs.readdirSync(downloads).every(n => !n.startsWith(".qsbw-")), fs.readdirSync(downloads).join(" "))

let unnamed = null
try {
  const cmd = Model.attachmentDownloadCommand("att-id", "item-id")
  execFileSync(cmd[0], cmd.slice(1), { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })
} catch (e) { unnamed = e }
check("a run with no name in its environment fails instead of inventing a path",
  unnamed !== null && String(unnamed.stderr).indexOf("Invalid attachment name.") !== -1,
  unnamed ? String(unnamed.stderr) : "succeeded")

const traversed = run("../../.bashrc")
check("a traversing name cannot write outside the download directory",
  path.dirname(traversed) === downloads && !fs.existsSync(path.join(home, ".bashrc")),
  traversed)

let failed = null
try { run("codes.txt", { QSBW_TEST_FAIL: "1" }) } catch (e) { failed = e }
check("a failing bw exits non-zero rather than reporting a path for a file it never wrote",
  failed !== null && String(failed.stdout || "") === "", String(failed && failed.stdout))

// --- the size the server declares ---------------------------------------------
//
// The declared size reaches the script unquoted, and JS prints huge numbers as
// "1e+30", which `[ ]` errors on (skipping the checks inside `if`). Checked by
// running the script.

for (const absurd of ["1e21", "1e30", "1e40", "999999999999999999999999"]) {
  let refused = null
  try { run(`huge-${absurd}.bin`, {}, absurd) } catch (e) { refused = e }
  check(`a declared size of ${absurd} is refused instead of skipping both ceilings`,
    refused !== null && String(refused.stderr || "").indexOf("download limit") !== -1,
    refused ? String(refused.stderr) : "the download went ahead")
  check(`and nothing lands in the download folder for ${absurd}`,
    !fs.existsSync(path.join(downloads, `huge-${absurd}.bin`)), "a file was written")
  check(`and no raw bash error is what the panel would show for ${absurd}`,
    refused !== null && String(refused.stderr || "").indexOf("integer expected") === -1,
    refused ? String(refused.stderr) : "")
}

check("a size within the limit still downloads",
  run("sized.txt", {}, "4096") === path.join(downloads, "sized.txt"), "refused a legitimate size")

// Whatever the server says, nothing exponential may be written into the script.
for (const absurd of ["1e21", "1e30", "1e40", String(Number.MAX_SAFE_INTEGER * 512)]) {
  const generated = Model.attachmentDownloadCommand("a", "i", absurd)[2]
  check(`every number in the script stays a plain integer for ${absurd}`,
    !/[0-9]e[+-][0-9]/.test(generated), generated.split("\n").filter(l => /e[+-][0-9]/.test(l)).join(" | "))
}

// --- Open hands the opener a neutral link -------------------------------------
//
// The opener and the app it starts keep their argv for the app's lifetime.

const runtimeDir = path.join(home, "runtime")
fs.mkdirSync(runtimeDir, { mode: 0o700 })
const opened = path.join(home, "opened.json")
// Stands in for gio and xdg-open: records how it was called and whether any
// process's argv held the scanned-for name meanwhile.
const recorder = (skipArgs) => `#!/usr/bin/env bash
leak=""
if [ -n "\${QSBW_TEST_SCAN:-}" ]; then
  for f in /proc/[0-9]*/cmdline; do
    if tr '\\0' ' ' < "$f" 2>/dev/null | grep -qF -- "$QSBW_TEST_SCAN"; then leak="$f"; fi
  done
fi
node -e 'require("fs").writeFileSync(process.argv[1], JSON.stringify({ tool: process.argv[3], argv: process.argv.slice(4 + ${skipArgs}), env: process.env.${Model.openPathEnvVar()} || null, leak: process.argv[2] }))' "${opened}" "$leak" "$(basename "$0")" "$@"
`
fs.writeFileSync(path.join(bin, "xdg-open"), recorder(0))
fs.chmodSync(path.join(bin, "xdg-open"), 0o755)
fs.writeFileSync(path.join(bin, "gio"), recorder(1))   // `gio open LINK`
fs.chmodSync(path.join(bin, "gio"), 0o755)
// A PATH with no gio at all, for the xdg-open fallback.
const noGioBin = path.join(home, "bin-no-gio")
fs.mkdirSync(noGioBin)
fs.copyFileSync(path.join(bin, "xdg-open"), path.join(noGioBin, "xdg-open"))
fs.chmodSync(path.join(noGioBin, "xdg-open"), 0o755)
for (const tool of ["bash", "node", "env", "mkdir", "chmod", "basename", "tr", "grep"]) {
  const found = execFileSync("bash", ["-c", 'command -v "$1"', "_", tool], { encoding: "utf8" }).trim()
  fs.symlinkSync(found, path.join(noGioBin, tool))
}

const openScan = "scan-" + require("crypto").randomBytes(8).toString("hex")
const openTarget = path.join(downloads, openScan + ".pdf")
fs.writeFileSync(openTarget, "%PDF-1.4\n")
const openCmd = Model.attachmentOpenCommand()
check("the open command carries no path", openCmd.join("\n").indexOf("Downloads") === -1, openCmd.join(" "))
check("the panel opens a saved attachment only through the environment",
  /environment: env/.test(bodyOf("openSavedAttachment")) && /Model\.attachmentOpenCommand\(\)/.test(bodyOf("openSavedAttachment"))
    && !/"xdg-open", path/.test(bodyOf("openSavedAttachment")),
  bodyOf("openSavedAttachment"))
const openWith = (target, extra) => {
  const e = {}
  e[Model.openPathEnvVar()] = target
  fs.rmSync(opened, { force: true })
  execFileSync(openCmd[0], openCmd.slice(1), {
    env: Object.assign({}, env, { XDG_RUNTIME_DIR: runtimeDir }, e, extra || {}), encoding: "utf8"
  })
  return JSON.parse(fs.readFileSync(opened, "utf8"))
}
const got = openWith(openTarget, { QSBW_TEST_SCAN: openScan })
const link = got.argv[0] || ""
check("gio, when there is one, gets a neutral link that keeps the extension",
  got.tool === "gio" && got.argv.length === 1 && path.basename(link) === "attachment.pdf"
    && fs.lstatSync(link).isSymbolicLink() && fs.readlinkSync(link) === openTarget,
  JSON.stringify(got))
check("and the name is in no process's argv while the opener runs", got.leak === "", got.leak)
check("the opener does not inherit the path in its environment", got.env === null, String(got.env))
const fallback = openWith(openTarget, { PATH: noGioBin })
check("without gio, xdg-open gets the same kind of link",
  fallback.tool === "xdg-open" && fallback.argv.length === 1 && path.basename(fallback.argv[0]) === "attachment.pdf"
    && fs.readlinkSync(fallback.argv[0]) === openTarget && fallback.env === null,
  JSON.stringify(fallback))
const openDir = path.join(runtimeDir, "qs-bitwarden-cli", "open")
check("the links live in private directories",
  (fs.statSync(openDir).mode & 0o777) === 0o700 && (fs.statSync(path.dirname(link)).mode & 0o777) === 0o700,
  (fs.statSync(openDir).mode & 0o777).toString(8))
check("each open gets its own link", openWith(openTarget).argv[0] !== link, "reused")
check("an extension that could carry the name is dropped",
  path.basename(openWith(path.join(downloads, "notes.project-falcon-budget")).argv[0]) === "attachment",
  "kept")
let relative = null
try { openWith("relative.pdf") } catch (e) { relative = e }
check("only an absolute path is linked", relative !== null, "linked")

// The real gio, launching a handler registered for PDFs in a private XDG
// tree: the handler gets the link, and nothing in the chain held the name.
const realGio = ["/usr/bin/gio", "/bin/gio"].find(p => fs.existsSync(p))
if (realGio) {
  const xdg = path.join(home, "xdg")
  fs.mkdirSync(path.join(xdg, "data", "applications"), { recursive: true })
  fs.mkdirSync(path.join(xdg, "config"), { recursive: true })
  fs.writeFileSync(path.join(xdg, "data", "applications", "qsbw-test.desktop"),
    `[Desktop Entry]\nType=Application\nName=qsbw test\nExec=${path.join(noGioBin, "xdg-open")} %f\nMimeType=application/pdf;\n`)
  fs.writeFileSync(path.join(xdg, "config", "mimeapps.list"), "[Default Applications]\napplication/pdf=qsbw-test.desktop\n")
  fs.rmSync(opened, { force: true })
  const e = {}
  e[Model.openPathEnvVar()] = openTarget
  execFileSync(openCmd[0], openCmd.slice(1), {
    env: Object.assign({}, env, e, {
      PATH: path.dirname(realGio) + ":" + nodeDir + ":/usr/bin:/bin", XDG_RUNTIME_DIR: runtimeDir, QSBW_TEST_SCAN: openScan,
      XDG_DATA_HOME: path.join(xdg, "data"), XDG_DATA_DIRS: path.join(xdg, "data") + ":/usr/share",
      XDG_CONFIG_HOME: path.join(xdg, "config")
    }), encoding: "utf8"
  })
  const until = Date.now() + 10000
  while (!fs.existsSync(opened) && Date.now() < until) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50)
  const real = fs.existsSync(opened) ? JSON.parse(fs.readFileSync(opened, "utf8")) : null
  check("through the real gio, the app is handed the neutral link",
    real !== null && real.argv.length === 1 && path.basename(real.argv[0]) === "attachment.pdf",
    JSON.stringify(real))
  check("and nothing in the real launch chain held the name in argv", real !== null && real.leak === "",
    real ? real.leak : "no launch")
}

fs.rmSync(home, { recursive: true, force: true })

// --- a server-chosen id cannot become an option to bw ------------------------
//
// `--` stops a server-chosen id like `--help` being read as an option.

const optionish = "--help"
const guarded = [
  ["getItemCommand", Model.getItemCommand(optionish), "bw get item -- --help"],
  ["getTotpCommand", Model.getTotpCommand(optionish), "bw get totp --raw -- --help"],
  ["deleteItemCommand", Model.deleteItemCommand(optionish), "bw delete item -- --help"],
  ["deleteSendCommand", Model.deleteSendCommand(optionish), "bw send delete -- --help"],
]
for (const [name, cmd, want] of guarded) {
  check(`${name} ends the options before the id`, cmd[2].indexOf(want) !== -1, cmd[2])
}
check("editItemCommand ends the options before the id",
  Model.editItemCommand(optionish)[2].indexOf("bw edit item -- '--help'") !== -1,
  Model.editItemCommand(optionish)[2])
check("the attachment id goes last, after our own flags and the separator",
  Model.attachmentDownloadCommand(optionish, "i")[2]
    .indexOf(`--output "$tmp" -- '--help'`) !== -1,
  Model.attachmentDownloadCommand(optionish, "i")[2])

done()
