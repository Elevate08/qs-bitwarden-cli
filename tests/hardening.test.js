#!/usr/bin/env node
// Three boundaries:
//
//   node tests/hardening.test.js
//
//  1. `--` before every server-chosen id (quoting does not stop bw reading a
//     quoted `--help` as an option).
//  2. The custom server may not be plaintext http off this machine.
//  3. Logout removes the learned-suggestion store.

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync } = require("child_process")

const Model = loadModule()

const { check, done } = createSuite("hardening")

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
const assocEnv = () => Object.assign({}, process.env, { XDG_STATE_HOME: assocTmp })
// The store arrives on stdin, as the panel writes it.
const writeAssociations = value => execFileSync(
  Model.associationsWriteCommand()[0], Model.associationsWriteCommand().slice(1),
  { env: assocEnv(), encoding: "utf8", input: value })

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
    { env: assocEnv(), encoding: "utf8" })
  check("association reads refuse a symlinked store",
    readThroughLink.trim() === "{}", JSON.stringify(readThroughLink))
  fs.unlinkSync(assocFile)

  // Linux caps one environment string at 128 KiB (MAX_ARG_STRLEN), and the
  // store used to travel in one, so past that size learning silently stopped
  // being saved. Grow a real store past it and write it the panel's way.
  let big = Model.emptyAssociations()
  for (let n = 0; Model.serializeAssociations(big).length <= 200 * 1024; n++) {
    const ctx = { detectedDomain: { baseDomain: `site${n}.example`, isIp: false }, isBrowser: true,
      isTerminal: false, clsSquashed: "firefox", titleTokens: [] }
    big = Model.recordAssociation(big, ctx, "0e6f1c9a-1d2b-4c3d-9e8f-" + String(100000000000 + n), "2026-09-24T00:00:00Z")
  }
  const bigJson = Model.serializeAssociations(big)
  writeAssociations(bigJson)
  check("a store past the 128 KiB environment limit is saved in full",
    bigJson.length > 128 * 1024 && fs.readFileSync(assocFile, "utf8") === bigJson,
    `${bigJson.length} bytes written, ${fs.statSync(assocFile).size} on disk`)
  check("the writer's argv and environment never carry the store",
    !Model.associationsWriteCommand().join(" ").includes("QSBW_ASSOC"), Model.associationsWriteCommand()[2])
  let refused = false
  try { writeAssociations("x".repeat(Model.MAX_ASSOC_BYTES + 1)) } catch (e) { refused = true }
  check("a store over the read cap is refused rather than written truncated",
    refused && fs.readFileSync(assocFile, "utf8") === bigJson
      && fs.readdirSync(assocDir).join(",") === "associations.json",
    fs.readdirSync(assocDir).join(","))
} finally {
  fs.rmSync(assocTmp, { recursive: true, force: true })
}

// The panel is three QML files now -- the SSH settings sections and the
// approval screen have their own. A check that reads only the largest one
// silently narrows as markup moves out of it.
const panelSrc = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml"]
  .map(readPluginSource)
  .join("\n")
const bodyOf = name => functionBody(panelSrc, name)
const forget = bodyOf("forgetStoredCredentials")
const assocWriter = panelSrc.slice(panelSrc.indexOf("id: associationsWriteProc"),
  panelSrc.indexOf("id: associationsClearProc"))
check("logout waits for an active association writer before clearing",
  /associationsWriteProc\.running[\s\S]*associationsClearPending\s*=\s*true/.test(forget), forget)
check("the association writer exit services a queued logout clear",
  /associationsClearPending[\s\S]*associationsClearProc\.running\s*=\s*true/.test(assocWriter), assocWriter)
check("association updates made during a write are persisted by a follow-up write",
  /associationsWriteProc\.running[\s\S]*associationsWritePending\s*=\s*true/.test(bodyOf("saveAssociations"))
    && /associationsWritePending[\s\S]*Qt\.callLater\(root\.startAssociationsWrite\)/.test(assocWriter),
  bodyOf("saveAssociations") + "\n" + assocWriter)
check("the store is written to the writer's stdin, which is then closed",
  /stdinEnabled\s*=\s*true[\s\S]*running\s*=\s*true[\s\S]*\.write\(pendingAssociationsJson\)[\s\S]*stdinEnabled\s*=\s*false/
    .test(bodyOf("startAssociationsWrite")) && !/environment:/.test(assocWriter),
  bodyOf("startAssociationsWrite") + "\n" + assocWriter)
check("logout discards a queued association write before clearing account metadata",
  /associationsWritePending\s*=\s*false/.test(forget), forget)

const copyToClipboard = bodyOf("copyToClipboard")
check("copies go through the model's copy command, detached, with the value in the environment",
  /Quickshell\.execDetached\(\{[\s\S]*command:\s*Model\.clipboardCopyCommand\(clearClipboardSec\)[\s\S]*environment:\s*env/.test(copyToClipboard)
    && /env\[Model\.clipboardEnvVar\(\)\]\s*=\s*String\(text\)/.test(copyToClipboard),
  copyToClipboard)
// The clear used to be a timer in the shell, lost on every shell restart,
// and a lock ran `wl-copy --clear` whatever was on the clipboard by then.
check("no shell-side timer owns the clipboard clear",
  !/clipboardClearTimer/.test(panelSrc), "clipboardClearTimer is back")
check("locking clears a credential still on the clipboard",
  /clearClipboard\(\)/.test(bodyOf("lockVault")), bodyOf("lockVault"))
check("clearing asks for the sensitive-only clear, never a bare wl-copy --clear",
  /Model\.clipboardClearSensitiveCommand\(\)/.test(bodyOf("clearClipboard"))
    && !/"--clear"/.test(bodyOf("clearClipboard")),
  bodyOf("clearClipboard"))

// The copy and the clear, run against stand-in wl-copy and wl-paste: nothing
// here touches the real clipboard. The stand-ins record their argv and
// environment and what they were given.
{
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-clip-"))
  try {
    const log = path.join(work, "log")
    fs.writeFileSync(path.join(work, "wl-copy"), `#!/bin/bash
{ printf 'argv:'; printf ' %s' "$@"; printf '\\n'
  printf 'env-has-clip:%s\\n' "\${QSBW_CLIP+yes}"
  for p in $$ $PPID; do printf 'cmdline %s:' "$p"; tr '\\0' ' ' < /proc/$p/cmdline; printf '\\n'; done
  case " $* " in *" --clear "*) : ;; *) printf 'stdin:'; cat; printf '\\n' ;; esac
} >> "${log}"
case " $* " in *" --foreground "*) exec sleep 30 ;; esac
`, { mode: 0o755 })
    fs.writeFileSync(path.join(work, "wl-paste"), `#!/bin/bash
printf '%s\\n' "\${QSBW_TEST_TYPES:-text/plain}" | tr ',' '\\n'
`, { mode: 0o755 })
    const SECRET = "  pa ss\\nword$(x)  "
    const run = (cmd, env, timeoutMs) => {
      try {
        execFileSync(cmd[0], cmd.slice(1), {
          env: Object.assign({}, process.env, { PATH: `${work}:${process.env.PATH}` }, env),
          encoding: "utf8", timeout: timeoutMs || 10000
        })
        return 0
      } catch (e) { return e.status === null ? "killed" : e.status }
    }

    // A timed copy: the stand-in stays in the foreground until `timeout`
    // ends it after one second.
    const started = Date.now()
    const rc = run(Model.clipboardCopyCommand(1), { [Model.clipboardEnvVar()]: SECRET })
    const took = Date.now() - started
    const record = fs.readFileSync(log, "utf8")
    check("a timed copy keeps wl-copy in the foreground under timeout",
      /argv: --foreground --sensitive/.test(record) && Model.clipboardCopyCommand(30)[2].includes("timeout 30s wl-copy --foreground --sensitive"),
      record)
    check("the timed copy ends itself, which is what clears it",
      rc === 124 && took >= 900 && took < 8000, `rc=${rc} after ${took}ms`)
    check("wl-copy receives the value exactly, edge spaces and all",
      record.includes("stdin:" + SECRET + "\n"), record)
    check("wl-copy does not inherit the value's variable",
      /env-has-clip:\n/.test(record), record)
    check("the value is in no argv along the way",
      !record.split("\n").filter(l => l.startsWith("cmdline")).some(l => l.includes("pa ss")),
      record)

    // With the clear off, the plain background copy.
    fs.writeFileSync(log, "")
    check("clearing disabled copies without a deadline",
      run(Model.clipboardCopyCommand(0), { [Model.clipboardEnvVar()]: "x" }) === 0
        && /argv: --sensitive\n/.test(fs.readFileSync(log, "utf8"))
        && !Model.clipboardCopyCommand(0)[2].includes("timeout"),
      fs.readFileSync(log, "utf8"))

    // The lock-time clear takes only a copy marked sensitive.
    fs.writeFileSync(log, "")
    run(Model.clipboardClearSensitiveCommand(), { QSBW_TEST_TYPES: "text/plain,UTF8_STRING" })
    check("a lock leaves the user's own later copy alone",
      !fs.readFileSync(log, "utf8").includes("--clear"), fs.readFileSync(log, "utf8"))
    run(Model.clipboardClearSensitiveCommand(), { QSBW_TEST_TYPES: "text/plain,x-kde-passwordManagerHint" })
    check("a lock clears a sensitive copy still on the clipboard",
      fs.readFileSync(log, "utf8").includes("argv: --clear"), fs.readFileSync(log, "utf8"))
  } finally {
    fs.rmSync(work, { recursive: true, force: true })
  }
}
check("a password missing from the in-memory item uses a managed generation-stamped fetch",
  /requestPasswordCopy\(item\.id,\s*item\.typeCode\)/.test(bodyOf("copyPasswordNow"))
    && /beginVaultRead\("passwordCopy"\)/.test(bodyOf("requestPasswordCopy"))
    && /Model\.getPasswordCommand\(itemId,\s*typeCode\)/.test(bodyOf("requestPasswordCopy"))
    && /vaultReadIsStale\("passwordCopy"\)/.test(bodyOf("onPasswordCopyFinished")),
  bodyOf("copyPasswordNow") + "\n" + bodyOf("requestPasswordCopy") + "\n" + bodyOf("onPasswordCopyFinished"))
check("TOTP copy reuses the managed TOTP reader instead of a detached bw process",
  /fetchTotp\(item\.id,\s*true\)/.test(bodyOf("copyTotpCodeNow"))
    && !/execDetached/.test(bodyOf("copyTotpCode") + bodyOf("copyTotpCodeNow")), bodyOf("copyTotpCodeNow"))

// -------------------------------------------------------------------------
// Every secret entry field keeps its text from input methods, even while the
// eye button shows it: predictive text and IME would otherwise see (and learn)
// a revealed password.

const qmlFiles = fs.readdirSync(path.join(__dirname, "..")).filter(f => f.endsWith(".qml"))
let secretFields = 0
for (const file of qmlFiles) {
  const lines = fs.readFileSync(path.join(__dirname, "..", file), "utf8").split("\n")
  lines.forEach((line, i) => {
    const m = line.match(/^(\s*)password:\s/)
    if (!m) return
    secretFields++
    // The rest of the enclosing object: until a line closing it.
    let end = i
    while (end < lines.length && !new RegExp("^" + m[1].slice(0, -2) + "\\}").test(lines[end])) end++
    const body = lines.slice(Math.max(0, i - 15), end).join("\n")
    check(`${file}:${i + 1} secret field hides itself from input methods`,
      /inputMethodHints:[^\n]*\n?[^\n]*Qt\.ImhSensitiveData/.test(body)
        && /Qt\.ImhNoPredictiveText/.test(body), lines[i])
  })
}
check("the secret-field scan found the fields", secretFields >= 10, String(secretFields))

// -------------------------------------------------------------------------

done()
