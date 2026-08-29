#!/usr/bin/env node
// Tests for three boundaries that had drifted or were never drawn.
//
//   node tests/hardening.test.js
//
//  1. Every bw invocation that takes a server-chosen id ends its options with
//     `--`. Quoting an id defends against the shell, not against bw's own
//     option parser -- a quoted `--help` is still `--help` by the time bw
//     sees it.
//  2. The custom-server field is where the master password is about to be
//     sent, so it may not name a plaintext http host off this machine.
//  3. The learned-suggestion store is account data with no expiry of its own,
//     so logging out has to remove it.

const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync } = require("child_process")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.getPasswordCommand = getPasswordCommand
  exports.getTotpCommand = getTotpCommand
  exports.validateServerUrl = validateServerUrl
  exports.associationsEnvVar = associationsEnvVar
  exports.associationsReadCommand = associationsReadCommand
  exports.associationsWriteCommand = associationsWriteCommand
  exports.associationsClearCommand = associationsClearCommand
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// -------------------------------------------------------------------------
// 1. `--` before a server-chosen id
// -------------------------------------------------------------------------

const HOSTILE_ID = "--help"

for (const [label, build, verb] of [
  ["password", Model.getPasswordCommand, "get password"],
  ["totp", Model.getTotpCommand, "get totp"],
]) {
  const script = build("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").join(" ")

  check(`copy ${label}: ends bw's options with --`,
    script.includes(`bw ${verb} --raw -- `),
    script)

  check(`fetch ${label}: preserves the id as one shell word`,
    script.includes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
    script)

  check(`fetch ${label}: bounds the secret before it reaches QML`,
    script.includes("head -c"),
    script)

  // The whole point of `--`: an id shaped like a flag stays an id.
  const hostile = build(HOSTILE_ID).join(" ")
  check(`fetch ${label}: a flag-shaped id lands after --`,
    hostile.includes(`bw ${verb} --raw -- --help`),
    hostile)
}

// -------------------------------------------------------------------------
// 2. Custom server URL
// -------------------------------------------------------------------------

const ACCEPTED = [
  ["", "empty means the official server"],
  ["https://vault.example.com", "plain https"],
  ["https://vault.example.com:8443/path", "https with port and path"],
  ["HTTPS://VAULT.EXAMPLE.COM", "scheme is case-insensitive"],
  ["http://localhost:8080", "http to localhost"],
  ["http://127.0.0.1", "http to 127.0.0.1"],
  ["http://127.1.2.3:9000", "http anywhere in 127/8"],
  ["http://[::1]:8000", "http to ::1"],
  ["  https://vault.example.com  ", "surrounding whitespace"],
]

for (const [url, why] of ACCEPTED) {
  const problem = Model.validateServerUrl(url)
  check(`server URL accepts ${why}`, problem === "", `${JSON.stringify(url)} -> ${problem}`)
}

const REFUSED = [
  ["http://vault.example.com", "plaintext http off this machine"],
  ["http://192.168.1.10", "http to a LAN address is still on a wire"],
  ["ftp://vault.example.com", "a scheme bw does not speak"],
  ["file:///etc/passwd", "a scheme that is not a server at all"],
  ["vault.example.com", "no scheme at all"],
  ["https://", "no host"],
  // Anchored, so a host that merely starts or ends with a loopback name is not
  // mistaken for one.
  ["http://localhost.evil.com", "a host that only begins with localhost"],
  ["http://127.0.0.1.evil.com", "a host that only begins with 127.0.0.1"],
  ["http://evil.com/localhost", "loopback appearing in the path"],
  // Userinfo is stripped before the host is judged, so it cannot smuggle a
  // loopback name in front of the real destination.
  ["http://localhost@evil.com", "loopback smuggled into userinfo"],
  // WHATWG URL parsers treat a backslash like a slash for http(s). Without an
  // explicit refusal, our lightweight host parser sees localhost after the @
  // while Bitwarden's Node runtime connects to evil.example before the slash.
  ["http://evil.example\\@localhost", "a loopback host smuggled after a backslash"],
  ["https://evil.example\\@vault.example.com", "an ambiguous HTTPS backslash destination"],
]

for (const [url, why] of REFUSED) {
  const problem = Model.validateServerUrl(url)
  check(`server URL refuses ${why}`, problem !== "", JSON.stringify(url))
}

check("server URL refusal names the host it refused",
  Model.validateServerUrl("http://vault.example.com").includes("vault.example.com"),
  Model.validateServerUrl("http://vault.example.com"))

check("server URL refusal for userinfo names the real host, not the userinfo",
  Model.validateServerUrl("http://localhost@evil.com").includes("evil.com"),
  Model.validateServerUrl("http://localhost@evil.com"))

// -------------------------------------------------------------------------
// 3. Logging out removes the learned-suggestion store
// -------------------------------------------------------------------------

const clear = Model.associationsClearCommand().join(" ")

check("clearing associations removes the store file",
  /\brm -f --/.test(clear) && clear.includes("associations.json"),
  clear)

check("clearing associations resolves the same path the writer uses",
  clear.includes("${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli")
    && clear.includes("associations.json"),
  clear)

// A missing file is the ordinary case on an account that never learned
// anything, and it must not be reported as a failed logout.
check("clearing associations succeeds when there is nothing to remove",
  /exit 0\s*$/.test(clear),
  clear)

const assocTmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-assoc-"))
const assocDir = path.join(assocTmp, "qs-bitwarden-cli")
const assocFile = path.join(assocDir, "associations.json")
const assocEnv = value => Object.assign({}, process.env, {
  XDG_STATE_HOME: assocTmp,
  [Model.associationsEnvVar()]: value,
})
const writeAssociations = value => execFileSync(
  Model.associationsWriteCommand()[0], Model.associationsWriteCommand().slice(1),
  { env: assocEnv(value), encoding: "utf8" })

try {
  fs.mkdirSync(assocDir, { recursive: true })
  fs.writeFileSync(assocFile, "old", { mode: 0o644 })
  writeAssociations('{"version":1,"keys":{}}')
  check("association replacement narrows an existing public file to mode 600",
    (fs.statSync(assocFile).mode & 0o777) === 0o600,
    "0" + (fs.statSync(assocFile).mode & 0o777).toString(8))

  const redirect = path.join(assocTmp, "must-not-change")
  fs.writeFileSync(redirect, "sentinel")
  fs.unlinkSync(assocFile)
  fs.symlinkSync(redirect, assocFile)
  writeAssociations('{"version":1,"keys":{"safe":[]}}')
  check("association writes replace a symlink instead of following it",
    !fs.lstatSync(assocFile).isSymbolicLink()
      && fs.readFileSync(redirect, "utf8") === "sentinel"
      && fs.readFileSync(assocFile, "utf8").includes('"safe"'),
    `target=${fs.readFileSync(redirect, "utf8")}`)
  check("atomic association writes leave no temporary files behind",
    fs.readdirSync(assocDir).join(",") === "associations.json",
    fs.readdirSync(assocDir).join(","))

  fs.unlinkSync(assocFile)
  fs.writeFileSync(redirect, '{"private":"redirected"}')
  fs.symlinkSync(redirect, assocFile)
  const readThroughLink = execFileSync(
    Model.associationsReadCommand()[0], Model.associationsReadCommand().slice(1),
    { env: assocEnv(""), encoding: "utf8" })
  check("association reads refuse a symlinked store",
    readThroughLink.trim() === "{}", JSON.stringify(readThroughLink))
} finally {
  fs.rmSync(assocTmp, { recursive: true, force: true })
}

// The panel is three QML files now -- the SSH settings sections and the
// approval screen have their own. A check that reads only the largest one
// silently narrows as markup moves out of it.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml"]
  .map(file => fs.readFileSync(path.join(__dirname, "..", file), "utf8"))
  .join("\n")
const bodyOf = name => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}
const forget = bodyOf("forgetStoredCredentials")
const assocWriter = panelSrc.slice(panelSrc.indexOf("id: associationsWriteProc"),
  panelSrc.indexOf("id: associationsClearProc"))
check("logout waits for an active association writer before clearing",
  /associationsWriteProc\.running[\s\S]*associationsClearPending\s*=\s*true/.test(forget), forget)
check("the association writer exit services a queued logout clear",
  /associationsClearPending[\s\S]*associationsClearProc\.running\s*=\s*true/.test(assocWriter), assocWriter)
check("association updates made during a write are persisted by a follow-up write",
  /associationsWriteProc\.running[\s\S]*associationsWritePending\s*=\s*true/.test(bodyOf("saveAssociations"))
    && /associationsWritePending[\s\S]*associationsWriteProc\.running\s*=\s*true/.test(assocWriter),
  bodyOf("saveAssociations") + "\n" + assocWriter)
check("logout discards a queued association write before clearing account metadata",
  /associationsWritePending\s*=\s*false/.test(forget), forget)

const copyToClipboard = bodyOf("copyToClipboard")
check("the long-lived clipboard owner does not inherit the copied secret variable",
  /env -u QSBW_CLIP wl-copy --sensitive/.test(copyToClipboard), copyToClipboard)
check("locking clears any credential already on the clipboard",
  /clearClipboard\(\)/.test(bodyOf("lockVault")), bodyOf("lockVault"))
check("a password missing from the in-memory item uses a managed generation-stamped fetch",
  /requestPasswordCopy\(item\.id,\s*item\.typeCode\)/.test(bodyOf("copyPassword"))
    && /beginVaultRead\("passwordCopy"\)/.test(bodyOf("requestPasswordCopy"))
    && /Model\.getPasswordCommand\(itemId,\s*typeCode\)/.test(bodyOf("requestPasswordCopy"))
    && /vaultReadIsStale\("passwordCopy"\)/.test(bodyOf("onPasswordCopyFinished")),
  bodyOf("copyPassword") + "\n" + bodyOf("requestPasswordCopy") + "\n" + bodyOf("onPasswordCopyFinished"))
check("TOTP copy reuses the managed TOTP reader instead of a detached bw process",
  /fetchTotp\(item\.id,\s*true\)/.test(bodyOf("copyTotpCode"))
    && !/execDetached/.test(bodyOf("copyTotpCode")), bodyOf("copyTotpCode"))

// -------------------------------------------------------------------------

if (failures.length) {
  console.error(`\n${failures.length} failure(s):\n`)
  for (const f of failures) console.error(`  ${f}\n`)
  process.exit(1)
}
console.log(`hardening.test.js: ${pass} checks passed`)
