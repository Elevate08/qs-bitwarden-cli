#!/usr/bin/env node
// `bw list items` returns every decrypted cipher field. Before QML sees that
// stream, supported ordinary items must be allowlisted and SSH keys reduced to
// public metadata. These tests execute the real shell/jq pipeline with a fake
// `bw`, so they cover the process boundary rather than a second JS sanitizer.
//
//   node tests/ssh-items.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.sanitizedListCommand = sanitizedListCommand
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

const PRIVATE_MARKER = "SSH_PRIVATE_MARKER_must_not_reach_QML"
const UNKNOWN_MARKER = "UNKNOWN_TYPE_MARKER_must_not_reach_QML"
const STDERR_MARKER = "BW_STDERR_MARKER_must_not_reach_QML"
const FILTER_STDERR_MARKER = "JQ_STDERR_MARKER_must_not_reach_QML"
const MAX_ITEMS_BYTES = 16 * 1024 * 1024
const MAX_STDERR_BYTES = 8192
const SAFE_DIAGNOSTIC = "Could not safely read vault items.\n"

const fixture = [
  { object: "item", id: "login-1", type: 1, name: "Login", favorite: true,
    login: { username: "me", password: "ordinary-login-secret" } },
  { object: "item", id: "note-1", type: 2, name: "Note", secureNote: { type: 0 } },
  { object: "item", id: "card-1", type: 3, name: "Card", card: { number: "4111111111111111" } },
  { object: "item", id: "identity-1", type: 4, name: "Identity", identity: { email: "me@example.com" } },
  { object: "item", id: "ssh-1", type: 5, name: "Work SSH", organizationId: "org-1",
    folderId: "folder-1", favorite: false, reprompt: 1, notes: "not public",
    sshKey: { privateKey: PRIVATE_MARKER, publicKey: "ssh-ed25519 AAAATEST",
      fingerprint: "SHA256:public-fingerprint", extra: "not public either" } },
  { object: "item", id: "bank-1", type: 6, name: "Bank",
    bankAccount: { accountNumber: UNKNOWN_MARKER } },
  { object: "item", id: "licence-1", type: 7, name: "Licence", notes: UNKNOWN_MARKER },
  { object: "item", id: "passport-1", type: 8, name: "Passport", fields: [{ value: UNKNOWN_MARKER }] }
]

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-ssh-items-"))
const fixturePath = path.join(tempDir, "items.json")
const bwPath = path.join(tempDir, "bw")
fs.writeFileSync(bwPath, [
  "#!/bin/bash",
  "if [ \"$1\" = \"--version\" ] || [ \"$1\" = \"-v\" ]; then",
  "  printf '%s\\n' \"${QSBW_BW_VERSION:-2025.1.2}\"",
  "  exit 0",
  "fi",
  "if [ -n \"${QSBW_BW_INVOCATIONS:-}\" ]; then printf x >> \"$QSBW_BW_INVOCATIONS\"; fi",
  "if [ -n \"${QSBW_BW_STDERR:-}\" ]; then printf '%s' \"$QSBW_BW_STDERR\" >&2; fi",
  "cat -- \"$QSBW_FIXTURE\"",
  "exit \"${QSBW_BW_EXIT:-0}\"",
  ""
].join("\n"), { mode: 0o755 })

const command = Model.sanitizedListCommand()
const commandText = command.join(" ")
const testEnv = Object.assign({}, process.env, {
  PATH: tempDir + path.delimiter + process.env.PATH,
  QSBW_FIXTURE: fixturePath
})

function categoryIds() {
  const block = panelSrc.match(/readonly property var categories: \[([\s\S]*?)\n  \]/)
  return block ? Array.from(block[1].matchAll(/\{\s*id:\s*"([^"]+)"/g), m => m[1]) : []
}

function visibleFilterRows() {
  const match = panelSrc.match(/readonly property int filterVisibleRows:\s*(\d+)/)
  return match ? Number(match[1]) : 0
}

function typeDrawerShowsAllRows() {
  return /readonly property int currentFilterVisibleRows:[\s\S]*openFilterGroup === "types"[\s\S]*currentFilterOptions\.length/.test(panelSrc)
    && /Math\.min\(currentFilterVisibleRows,\s*currentFilterOptions\.length\)/.test(panelSrc)
}

function runFixture(contents, envOverrides) {
  fs.writeFileSync(fixturePath, contents)
  return spawnSync(command[0], command.slice(1), {
    env: Object.assign({}, testEnv, envOverrides || {}),
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024
  })
}

try {
  const ids = categoryIds()
  const sshIndex = ids.indexOf("sshKey")
  const visibleRows = visibleFilterRows()
  check("type filters are ordered by Bitwarden type id with synthetic filters at the edges",
    ids.join(",") === "all,login,secureNote,card,identity,sshKey,favorite",
    JSON.stringify({ categoryIds: ids }))
  check("the SSH type filter is visible without scrolling",
    sshIndex >= 0 && (sshIndex < visibleRows || typeDrawerShowsAllRows()),
    JSON.stringify({ visibleRows, typeDrawerShowsAllRows: typeDrawerShowsAllRows(), categoryIds: ids }))
  check("the SSH type filter is offered only when the CLI supports SSH keys",
    /readonly property bool sshUiAvailable: Model\.sshUiAvailable\(dependencies, depsChecked\)/.test(panelSrc)
      && /readonly property var visibleCategories[\s\S]{0,200}category\.id !== "sshKey"/.test(panelSrc)
      && /group === "types"[\s\S]{0,200}visibleCategories\.length/.test(panelSrc)
      && !/group === "types"[\s\S]{0,200}categories\[i\]/.test(panelSrc),
    "the types filter drawer does not follow the CLI-gated category list")
  check("an unconfirmed SSH capability reads differently from an empty vault",
    /function emptyListMessage\(\)[\s\S]{0,400}sshCapability\.state === "unconfirmed"[\s\S]{0,120}sshCapability\.message/.test(panelSrc)
      && /text: root\.isLoading && root\.items\.length === 0[\s\S]{0,120}root\.emptyListMessage\(\)/.test(panelSrc),
    "the empty list cannot distinguish an unconfirmed server from an empty vault")

  check("search help says SSH public fields are searchable",
    /placeholderText:\s*"[^"]*(public keys|fingerprints)[^"]*"/i.test(panelSrc),
    "search placeholder does not mention public keys or fingerprints")
  check("the detail delete shortcut is guarded for read-only SSH items",
    /lower === "x"[\s\S]{0,120}detailItem[\s\S]{0,120}typeCode !== 5[\s\S]{0,120}showDeleteConfirm = true/.test(panelSrc),
    "detail shortcut x can open delete confirmation for SSH")

  check("the sanitizer is a bounded bash pipeline",
    command[0] === "bash" && command[1] === "-c"
      && commandText.includes("node -e")
      && commandText.includes("jq -c")
      && commandText.includes("BW_NOINTERACTION=true")
      && (commandText.match(/head -c 16777217/g) || []).length === 2,
    commandText)
  check("the static command carries no fixture secret",
    !commandText.includes(PRIVATE_MARKER) && !commandText.includes(UNKNOWN_MARKER), commandText)

  const valid = runFixture(JSON.stringify(fixture))
  check("a valid vault read succeeds", valid.status === 0,
    `exit=${valid.status} stderr=${JSON.stringify(valid.stderr)}`)

  let parsed = null
  try { parsed = JSON.parse(valid.stdout) } catch (e) {}
  check("the sanitizer emits one items/sshKeys document",
    parsed && Array.isArray(parsed.items) && Array.isArray(parsed.sshKeys), valid.stdout.slice(0, 500))
  check("types 1-4 remain intact",
    parsed && JSON.stringify(parsed.items) === JSON.stringify(fixture.slice(0, 4)),
    parsed ? JSON.stringify(parsed.items) : "no parsed output")
  check("only type 5 receives a public projection",
    parsed && JSON.stringify(parsed.sshKeys) === JSON.stringify([{
      id: "ssh-1", name: "Work SSH", type: 5, organizationId: "org-1",
      folderId: "folder-1", favorite: false, reprompt: 1,
      publicKey: "ssh-ed25519 AAAATEST", fingerprint: "SHA256:public-fingerprint"
    }]), parsed ? JSON.stringify(parsed.sshKeys) : "no parsed output")
  check("seeing a type-5 item confirms SSH capability in the sanitized envelope",
    parsed && parsed.sshCapability === "confirmed",
    parsed ? JSON.stringify(parsed) : "no parsed output")
  const keyFingerprint = runFixture(JSON.stringify([{
    object: "item", id: "ssh-keyfp", type: "5", name: "CLI SSH",
    publicKey: "ssh-rsa AAAATEST2", keyFingerprint: "SHA256:key-fingerprint",
    sshKey: { privateKey: PRIVATE_MARKER }
  }]))
  let keyFingerprintParsed = null
  try { keyFingerprintParsed = JSON.parse(keyFingerprint.stdout) } catch (e) {}
  check("the sanitizer accepts the installed CLI keyFingerprint schema",
    keyFingerprint.status === 0
      && keyFingerprintParsed
      && JSON.stringify(keyFingerprintParsed.sshKeys) === JSON.stringify([{
        id: "ssh-keyfp", name: "CLI SSH", type: 5, organizationId: null,
        folderId: null, favorite: false, reprompt: 0,
        publicKey: "ssh-rsa AAAATEST2", fingerprint: "SHA256:key-fingerprint"
      }])
      && !keyFingerprint.stdout.includes(PRIVATE_MARKER),
    `exit=${keyFingerprint.status} stdout=${JSON.stringify(keyFingerprint.stdout)}`)
  const noType5 = runFixture(JSON.stringify(fixture.slice(0, 4)))
  let noType5Parsed = null
  try { noType5Parsed = JSON.parse(noType5.stdout) } catch (e) {}
  check("a read with no type-5 items keeps ordinary items but marks SSH capability unconfirmed",
    noType5.status === 0
      && noType5Parsed
      && JSON.stringify(noType5Parsed.items) === JSON.stringify(fixture.slice(0, 4))
      && Array.isArray(noType5Parsed.sshKeys)
      && noType5Parsed.sshKeys.length === 0
      && noType5Parsed.sshCapability === "unconfirmed",
    `exit=${noType5.status} stdout=${JSON.stringify(noType5.stdout)}`)
  check("zero type-5 keys stay unconfirmed even on official Bitwarden cloud",
    noType5.status === 0
      && noType5Parsed
      && noType5Parsed.sshCapability === "unconfirmed",
    `exit=${noType5.status} stdout=${JSON.stringify(noType5.stdout)}`)
  check("private and unknown-type markers never reach stdout",
    !valid.stdout.includes(PRIVATE_MARKER) && !valid.stdout.includes(UNKNOWN_MARKER), valid.stdout)

  const crossTyped = runFixture(JSON.stringify([{
    object: "item", id: "login-with-ssh", type: 1, name: "Forged",
    login: { username: "still-intact", password: "ordinary-login-secret" },
    sshKey: { privateKey: PRIVATE_MARKER, publicKey: "not-an-SSH-item" }
  }]))
  check("a cross-typed ordinary item fails instead of being mutated or leaking SSH data",
    crossTyped.status === 1
      && crossTyped.stdout === ""
      && crossTyped.stderr === SAFE_DIAGNOSTIC
      && !crossTyped.stderr.includes(PRIVATE_MARKER),
    `exit=${crossTyped.status} stdout=${JSON.stringify(crossTyped.stdout)} stderr=${JSON.stringify(crossTyped.stderr)}`)

  const unboundedReprompt = runFixture(
    '[{"type":5,"id":"ssh-large-reprompt","reprompt":1e9999,"sshKey":{}}]')
  let unboundedRepromptParsed = null
  try { unboundedRepromptParsed = JSON.parse(unboundedReprompt.stdout) } catch (e) {}
  check("SSH reprompt is normalized to the finite Bitwarden enum",
    unboundedReprompt.status === 0
      && unboundedRepromptParsed
      && unboundedRepromptParsed.sshKeys[0].reprompt === 0
      && Number.isFinite(unboundedRepromptParsed.sshKeys[0].reprompt),
    `exit=${unboundedReprompt.status} stdout=${JSON.stringify(unboundedReprompt.stdout)}`)

  for (const [label, contents] of [
    ["malformed JSON", "[{not-json"],
    ["a non-array root", JSON.stringify({ items: fixture })],
    ["multiple JSON documents", "[]\n[]\n"]
  ]) {
    const result = runFixture(contents)
    check(`${label} fails closed`, result.status !== 0 && result.stdout === "",
      `exit=${result.status} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`)
  }

  const malformedSecret = runFixture(
    `[{"type":5,"sshKey":{"privateKey":"${PRIVATE_MARKER}"}`)
  check("parse diagnostics do not echo malformed private material",
    malformedSecret.status !== 0
      && !malformedSecret.stdout.includes(PRIVATE_MARKER)
      && !malformedSecret.stderr.includes(PRIVATE_MARKER),
    `stdout=${JSON.stringify(malformedSecret.stdout)} stderr=${JSON.stringify(malformedSecret.stderr)}`)

  for (const [label, contents] of [
    ["a leading-zero number", '[{"type":1,"value":01}]'],
    ["a NaN value", '[{"type":1,"value":NaN}]'],
    ["an Infinity value", '[{"type":1,"value":Infinity}]']
  ]) {
    const result = runFixture(contents)
    check(`${label} is rejected as non-JSON`, result.status !== 0 && result.stdout === "",
      `exit=${result.status} stdout=${JSON.stringify(result.stdout)} stderr=${JSON.stringify(result.stderr)}`)
  }

  const failedProducer = runFixture("[]", {
    QSBW_BW_EXIT: "9",
    QSBW_BW_STDERR: STDERR_MARKER.repeat(
      Math.ceil((MAX_STDERR_BYTES + 100) / Buffer.byteLength(STDERR_MARKER)))
  })
  const failedProducerStdout = failedProducer.stdout || ""
  const failedProducerStderr = failedProducer.stderr || ""
  check("a failed bw read exposes only a bounded static diagnostic",
    failedProducer.status === 1
      && failedProducerStdout === ""
      && !failedProducerStderr.includes(STDERR_MARKER)
      && failedProducerStderr === SAFE_DIAGNOSTIC
      && Buffer.byteLength(failedProducerStderr) <= MAX_STDERR_BYTES,
    `exit=${failedProducer.status} error=${failedProducer.error || "none"} stdout=${JSON.stringify(failedProducerStdout)} stderr=${JSON.stringify(failedProducerStderr.slice(0, 200))}`)
  const malformedOlderCli = runFixture("[]", {
    QSBW_BW_VERSION: "2026.7.0",
    QSBW_BW_EXIT: "1",
    QSBW_BW_STDERR: "TypeError: Cannot read properties of null (reading 'keyFingerprint')"
  })
  check("bw list failures stay on the exact bounded safe diagnostic with no raw CLI output",
    malformedOlderCli.status === 1
      && malformedOlderCli.stdout === ""
      && malformedOlderCli.stderr === SAFE_DIAGNOSTIC
      && !malformedOlderCli.stderr.includes("2026.8.0")
      && !malformedOlderCli.stderr.includes("keyFingerprint")
      && !malformedOlderCli.stderr.includes("TypeError"),
    `exit=${malformedOlderCli.status} stdout=${JSON.stringify(malformedOlderCli.stdout)} stderr=${JSON.stringify(malformedOlderCli.stderr)}`)

  const fakeJqDir = path.join(tempDir, "failed-filter")
  fs.mkdirSync(fakeJqDir)
  fs.writeFileSync(path.join(fakeJqDir, "jq"),
    `#!/bin/bash\nprintf '%s' '${FILTER_STDERR_MARKER}' >&2\nexit 7\n`, { mode: 0o755 })
  const failedFilter = runFixture("[]", {
    PATH: fakeJqDir + path.delimiter + testEnv.PATH
  })
  check("a failed jq filter exposes no raw diagnostic or partial output",
    failedFilter.status === 1
      && failedFilter.stdout === ""
      && !failedFilter.stderr.includes(FILTER_STDERR_MARKER)
      && failedFilter.stderr === SAFE_DIAGNOSTIC
      && Buffer.byteLength(failedFilter.stderr) <= MAX_STDERR_BYTES,
    `exit=${failedFilter.status} stdout=${JSON.stringify(failedFilter.stdout)} stderr=${JSON.stringify(failedFilter.stderr)}`)

  const invocationPath = path.join(tempDir, "bw-invocations")
  const invokedOnce = runFixture("[]", { QSBW_BW_INVOCATIONS: invocationPath })
  const invocationCount = fs.existsSync(invocationPath)
    ? fs.readFileSync(invocationPath, "utf8").length : 0
  check("one sanitized read invokes bw exactly once",
    invokedOnce.status === 0 && invocationCount === 1,
    `exit=${invokedOnce.status} invocations=${invocationCount}`)

  // The prefix is valid JSON. Only the extra whitespace crosses the raw cap,
  // proving upstream truncation is rejected even when jq could parse the bytes
  // that made it through.
  const oversizedInput = "[]" + " ".repeat(MAX_ITEMS_BYTES)
  const inputLimited = runFixture(oversizedInput)
  check("raw input beyond 16 MiB fails closed",
    inputLimited.status !== 0 && inputLimited.stdout === "",
    `exit=${inputLimited.status} stdout-bytes=${Buffer.byteLength(inputLimited.stdout)}`)

  // jq replaces this invalid four-byte sequence with a three-byte U+FFFD.
  // The raw stream is one byte over the cap, but a post-decoding measurement
  // sees exactly the limit and would incorrectly accept it.
  const invalidPrefix = Buffer.from('[{"type":6,"value":"')
  const invalidUtf8 = Buffer.from([0xf4, 0x90, 0x80, 0x80])
  const invalidSuffix = Buffer.from('"}]')
  const invalidPadding = Buffer.alloc(
    MAX_ITEMS_BYTES + 1 - invalidPrefix.length - invalidUtf8.length - invalidSuffix.length,
    0x61)
  const decodingBypass = runFixture(
    Buffer.concat([invalidPrefix, invalidPadding, invalidUtf8, invalidSuffix]))
  check("invalid UTF-8 cannot shrink an oversized raw input past the cap",
    decodingBypass.status !== 0 && decodingBypass.stdout === "",
    `exit=${decodingBypass.status} stdout=${JSON.stringify(decodingBypass.stdout)}`)

  // The input fits just under its cap, but the {items,sshKeys} envelope pushes
  // the sanitized document over the QML-facing ceiling.
  const largeItem = { object: "item", id: "large", type: 1, name: "Large", notes: "" }
  const emptyBytes = Buffer.byteLength(JSON.stringify([largeItem]))
  largeItem.notes = "x".repeat(MAX_ITEMS_BYTES - emptyBytes - 8)
  const nearLimitInput = JSON.stringify([largeItem])
  check("the output-overflow fixture itself stays below the raw cap",
    Buffer.byteLength(nearLimitInput) < MAX_ITEMS_BYTES,
    String(Buffer.byteLength(nearLimitInput)))
  const outputLimited = runFixture(nearLimitInput)
  check("sanitized output beyond 16 MiB fails without partial stdout",
    outputLimited.status !== 0 && outputLimited.stdout === "",
    `exit=${outputLimited.status} stdout-bytes=${Buffer.byteLength(outputLimited.stdout)}`)
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true })
}

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
