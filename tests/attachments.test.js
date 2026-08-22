#!/usr/bin/env node
// Attachment metadata rides along with `bw list items`, so the panel lists an
// item's files without a second CLI call; only the bytes are fetched, and only
// on demand. Two things are worth pinning down here: that the metadata really
// does survive both parse paths, and that a file name out of the vault -- which
// is attacker-controlled text about to become part of a path we create --
// cannot escape the download directory.
//
//   node tests/attachments.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseItems = parseItems
  exports.parseItemDetail = parseItemDetail
  exports.itemDetailFromObject = itemDetailFromObject
  exports.parseAttachments = parseAttachments
  exports.formatAttachmentSize = formatAttachmentSize
  exports.safeAttachmentFileName = safeAttachmentFileName
  exports.attachmentDownloadCommand = attachmentDownloadCommand
  exports.parentDirectory = parentDirectory
  exports.baseName = baseName
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

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
// This is the one that matters: the name is decrypted vault content, and the
// download path is built from it.

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

const cmd = Model.attachmentDownloadCommand("a1", "item-id", "codes.txt")
check("it runs through bash, because the download directory is resolved at run time",
  cmd[0] === "bash" && cmd[1] === "-c", JSON.stringify(cmd.slice(0, 2)))

const script = cmd[2]
check("the attachment id and item id are quoted, never interpolated bare",
  script.indexOf("bw get attachment 'a1' --itemid 'item-id'") !== -1, script)
check("the file name is quoted too", script.indexOf("name='codes.txt'") !== -1, script)
check("it prints where the file landed, which is how the panel learns the path",
  /printf %s "\$out"/.test(script), script)
check("it claims the name with link(), which is the existence test and the creation at once",
  script.indexOf('ln -- "$tmp" "$cand"') !== -1, script)
check("it no longer decides the name with a test a symlink can answer for",
  script.indexOf('while [ -e "$out" ]') === -1, script)
check("the bytes are staged in a private directory before they are placed",
  script.indexOf('mktemp -d -- "$dir/.qsbw-XXXXXXXX"') !== -1
    && script.indexOf('--output "$tmp"') !== -1, script)
check("the staging directory is removed however the script leaves",
  script.indexOf(`trap 'rm -rf -- "$work"' EXIT`) !== -1, script)
check("a decrypted attachment is not left readable by anyone else",
  script.split("\n").indexOf("umask 077") !== -1, script)

// --- the ceilings ------------------------------------------------------------
check("the transfer is bounded in bytes by RLIMIT_FSIZE",
  /ulimit -f \d+/.test(script), script)
check("the transfer is bounded in time",
  /timeout \d+/.test(script), script)
check("the disk is not filled to the last byte",
  script.indexOf("df -Pk") !== -1, script)
check("the size the vault declares buys an early refusal",
  script.indexOf('if [ "$want" -gt "$max" ]') !== -1, script)
check("the size on disk is checked even where the kernel limit was not applied",
  script.indexOf('wc -c < "$tmp"') !== -1, script)

const withSize = Model.attachmentDownloadCommand("a1", "item-id", "codes.txt", "4096")
check("the declared size reaches the script", withSize[2].indexOf("want=4096") !== -1, withSize[2])
check("a missing or nonsense declared size is treated as unknown, not as a refusal",
  Model.attachmentDownloadCommand("a1", "i", "f.txt")[2].indexOf("want=0") !== -1
    && Model.attachmentDownloadCommand("a1", "i", "f.txt", "nope")[2].indexOf("want=0") !== -1,
  Model.attachmentDownloadCommand("a1", "i", "f.txt", "nope")[2])
check("it refuses to treat $HOME as the download directory",
  script.indexOf("\"$dir\" = \"$HOME\"") !== -1, script)
check("it stops at the first failure rather than printing a path for a file it did not write",
  script.split("\n")[0] === "set -e", script.split("\n")[0])

// A hostile name reaches the script already defanged, and quoted on top.
const hostile = Model.attachmentDownloadCommand("a'1", "i'd", "../../.bashrc")
check("a quote in the attachment id cannot break out of its quoting",
  hostile[2].indexOf("bw get attachment 'a'\\''1' --itemid 'i'\\''d'") !== -1, hostile[2])
check("a traversing name is sanitised before it is ever quoted",
  hostile[2].indexOf("name='.bashrc'") === -1 && hostile[2].indexOf("name='bashrc'") !== -1,
  hostile[2].split("\n")[1])

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
// This is the one that would have caught the bug that shipped. A cipher parsed
// from `bw` JSON holds real arrays, and every check in the model said
// Array.isArray(). But the parsed cipher is stored in a QML `var` property and
// read back through a ListView delegate, and Qt converts the nested arrays on
// that trip into array-like objects: typeof "object", correct .length,
// indexing works, Array.isArray() false. So the detail view built from that
// object found no attachments on an item the list had just drawn a paperclip
// on -- and no error anywhere, because an empty list is a valid answer.
//
// Node always gives real arrays, which is exactly why the first round of tests
// passed while the panel was broken. So fake the conversion here.

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

// toList must not mistake a string, or anything else with a length, for a list.
check("a string is not a list of characters",
  Model.parseAttachments("nope").length === 0, "treated a string as a list")
check("an object with a junk length is not a list",
  Model.parseAttachments({ length: -1 }).length === 0
    && Model.parseAttachments({ length: 1.5 }).length === 0
    && Model.parseAttachments({ length: "2" }).length === 0, "accepted a junk length")

// --- and the script actually run ---------------------------------------------
//
// String-matching the script only says what we wrote. What matters is what
// bash does with it, so it is run for real here against a stub `bw` and a
// throwaway HOME: the traversal has to end up inside the download directory,
// and a name collision must never overwrite what is already there.

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
printf 'bytes\\n' > "$out"
echo "Saved $out"
`)
fs.chmodSync(path.join(bin, "bw"), 0o755)

const env = { PATH: bin + ":/usr/bin:/bin", HOME: home }
const run = (fileName, extra) => {
  const cmd = Model.attachmentDownloadCommand("att-id", "item-id", fileName)
  return execFileSync(cmd[0], cmd.slice(1), {
    env: Object.assign({}, env, extra || {}),
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

const traversed = run("../../.bashrc")
check("a traversing name cannot write outside the download directory",
  path.dirname(traversed) === downloads && !fs.existsSync(path.join(home, ".bashrc")),
  traversed)

let failed = null
try { run("codes.txt", { QSBW_TEST_FAIL: "1" }) } catch (e) { failed = e }
check("a failing bw exits non-zero rather than reporting a path for a file it never wrote",
  failed !== null && String(failed.stdout || "") === "", String(failed && failed.stdout))

fs.rmSync(home, { recursive: true, force: true })

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
