#!/usr/bin/env node
// One `bw list items` read feeds both the panel and the companion. These tests
// run the real shell pipeline against a fake `bw` and a real FIFO, because the
// properties that matter are process-boundary properties: what reaches QML's
// stdout, what reaches the FIFO, and -- above all -- that the optional agent
// branch can never take the ordinary item list down with it.
//
//   node tests/ssh-agent-pipeline.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync, execFileSync } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.sanitizedListCommand = sanitizedListCommand
  exports.sshAgentFifoPath = sshAgentFifoPath
  exports.loadIdEnvVar = loadIdEnvVar
  exports.isValidLoadId = isValidLoadId
  exports.loadIdCommand = loadIdCommand
  exports.sshAgentLoadBeginLine = sshAgentLoadBeginLine
  exports.sshAgentLoadEndLine = sshAgentLoadEndLine
  exports.sshAgentVaultLockedLine = sshAgentVaultLockedLine
  exports.sshAgentLoggedOutLine = sshAgentLoggedOutLine
  exports.sshAgentHelloLine = sshAgentHelloLine
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

const PRIVATE_MARKER = "SSH_PRIVATE_MARKER_must_not_reach_QML"
const REPROMPT_MARKER = "REPROMPT_PRIVATE_MARKER_must_not_reach_the_agent"
const LOAD_ID = "0123456789abcdef0123456789abcdef"

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-pipeline-"))
const fixturePath = path.join(tempDir, "items.json")
const runtimeDir = path.join(tempDir, "run")
fs.mkdirSync(runtimeDir, { mode: 0o700 })
fs.mkdirSync(path.join(runtimeDir, "qs-bitwarden-cli"), { mode: 0o700 })
const fifoPath = Model.sshAgentFifoPath(runtimeDir)

fs.writeFileSync(path.join(tempDir, "bw"), [
  "#!/usr/bin/env bash",
  'if [ "$1" = "--version" ]; then printf "%s\\n" "${QSBW_BW_VERSION:-2026.2.0}"; exit 0; fi',
  'cat -- "$QSBW_FIXTURE"',
  'exit "${QSBW_BW_EXIT:-0}"',
  ""
].join("\n"), { mode: 0o755 })

const baseEnv = () => Object.assign({}, process.env, {
  PATH: tempDir + path.delimiter + process.env.PATH,
  QSBW_FIXTURE: fixturePath,
  XDG_RUNTIME_DIR: runtimeDir
})

const privatePem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + PRIVATE_MARKER + "\n-----END OPENSSH PRIVATE KEY-----"
const repromptPem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + REPROMPT_MARKER + "\n-----END OPENSSH PRIVATE KEY-----"

const fixture = [
  { object: "item", id: "login-1", type: 1, name: "Login", login: { username: "u", password: "p" } },
  { object: "item", id: "ssh-1", type: 5, name: "Work", favorite: true, reprompt: 0,
    sshKey: { privateKey: privatePem, publicKey: "ssh-ed25519 AAAAWORK", fingerprint: "SHA256:work" } },
  { object: "item", id: "ssh-2", type: 5, name: "Guarded", reprompt: 1,
    sshKey: { privateKey: repromptPem, publicKey: "ssh-ed25519 AAAAGUARD", fingerprint: "SHA256:guard" } },
  { object: "item", id: "bank-1", type: 6, name: "Bank", bankAccount: { number: "UNKNOWN_TYPE_MARKER" } }
]

// A real reader on the FIFO, held open the way the companion holds it (O_RDWR),
// so the writer never blocks on open and never sees the reader disappear.
function withFifoReader(fn) {
  try { fs.unlinkSync(fifoPath) } catch (e) {}
  execFileSync("mkfifo", ["-m", "600", fifoPath])
  const fd = fs.openSync(fifoPath, fs.constants.O_RDWR | fs.constants.O_NONBLOCK)
  try {
    const result = fn()
    // Drain whatever the branch wrote, without blocking when it wrote nothing.
    let out = Buffer.alloc(0)
    const buf = Buffer.alloc(1 << 20)
    for (;;) {
      let n = 0
      try { n = fs.readSync(fd, buf, 0, buf.length, null) } catch (e) { break }
      if (n <= 0) break
      out = Buffer.concat([out, buf.slice(0, n)])
    }
    return { result, fifo: out.toString("utf8") }
  } finally {
    fs.closeSync(fd)
    try { fs.unlinkSync(fifoPath) } catch (e) {}
  }
}

function runPipeline(opts, envOverrides, contents) {
  fs.writeFileSync(fixturePath, contents === undefined ? JSON.stringify(fixture) : contents)
  const command = Model.sanitizedListCommand(opts)
  return spawnSync(command[0], command.slice(1), {
    env: Object.assign(baseEnv(), envOverrides || {}),
    encoding: "utf8", maxBuffer: 20 * 1024 * 1024
  })
}

// -------------------------------------------------------------------------
// The load nonce
// -------------------------------------------------------------------------

eq("the load id env var is named", Model.loadIdEnvVar(), "QSBW_LOAD_ID")
eq("a 128-bit lowercase hex nonce is valid", Model.isValidLoadId(LOAD_ID), true)
eq("a short nonce is refused", Model.isValidLoadId("abc"), false)
eq("an uppercase nonce is refused", Model.isValidLoadId(LOAD_ID.toUpperCase()), false)
eq("a non-hex nonce is refused", Model.isValidLoadId("z".repeat(32)), false)
eq("an empty nonce is refused", Model.isValidLoadId(""), false)
eq("a non-string nonce is refused", Model.isValidLoadId(null), false)

const nonceRun = spawnSync("bash", Model.loadIdCommand().slice(1), { encoding: "utf8" })
const generated = String(nonceRun.stdout || "").trim()
eq("the generator produces a usable nonce", Model.isValidLoadId(generated), true)
const second = String(spawnSync("bash", Model.loadIdCommand().slice(1), { encoding: "utf8" }).stdout || "").trim()
check("two nonces differ", generated !== second, generated + " == " + second)

// The nonce is what stops another same-UID process writing its own key set
// into an open FIFO window. /proc/<pid>/cmdline is world-readable, so it must
// never be an argument.
const agentCommandText = Model.sanitizedListCommand({ agentBranch: true, runtimeDir: runtimeDir }).join(" ")
// The fstat below is the check that decides; this one only keeps a dead
// companion from costing a full decrypt-and-filter pass whose output has
// nowhere to go.
check("a missing FIFO skips the filter rather than running it for nobody",
  /if \[ -p "\$__qsbw_fifo" \]; then/.test(agentCommandText),
  agentCommandText.slice(0, 500))
check("the FIFO is opened without following a swapped symlink",
  agentCommandText.indexOf("O_NOFOLLOW") >= 0, agentCommandText.slice(0, 500))
check("the opened descriptor, not the pathname, is checked as a FIFO",
  agentCommandText.indexOf("fstatSync") >= 0 && agentCommandText.indexOf("S_IFIFO") >= 0,
  agentCommandText.slice(0, 500))
check("the nonce is read from the environment, never passed in argv",
  agentCommandText.indexOf(Model.loadIdEnvVar()) >= 0 && agentCommandText.indexOf(LOAD_ID) < 0,
  "nonce appears literally in the command")

// -------------------------------------------------------------------------
// Disabled mode has no private branch at all
// -------------------------------------------------------------------------

const plainText = Model.sanitizedListCommand().join(" ")
check("the default command has no tee branch", plainText.indexOf("tee") < 0, plainText.slice(0, 400))
check("the default command never names the key FIFO",
  plainText.indexOf("ssh-keys.fifo") < 0, plainText.slice(0, 400))
check("an explicitly disabled branch is identical to the default",
  Model.sanitizedListCommand({ agentBranch: false, runtimeDir: runtimeDir }).join(" ")
    === Model.sanitizedListCommand().join(" "), "disabled form differs from the default")

const disabledRun = withFifoReader(() =>
  runPipeline({ agentBranch: false, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: LOAD_ID }))
eq("the disabled pipeline succeeds", disabledRun.result.status, 0)
eq("the disabled pipeline writes nothing to the FIFO", disabledRun.fifo, "")

// -------------------------------------------------------------------------
// Enabled mode: one read, two consumers
// -------------------------------------------------------------------------

const enabled = withFifoReader(() =>
  runPipeline({ agentBranch: true, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: LOAD_ID }))

eq("the fan-out pipeline succeeds", enabled.result.status, 0)

const panelOut = JSON.parse(enabled.result.stdout)
check("QML still receives the ordinary items", panelOut.items.length === 1 && panelOut.items[0].id === "login-1",
  JSON.stringify(panelOut.items))
eq("QML still receives both public SSH keys", panelOut.sshKeys.length, 2)
check("no private key marker reaches QML", enabled.result.stdout.indexOf(PRIVATE_MARKER) < 0, "leaked")
check("no re-prompt private marker reaches QML", enabled.result.stdout.indexOf(REPROMPT_MARKER) < 0, "leaked")
check("no unknown cipher type reaches QML", enabled.result.stdout.indexOf("UNKNOWN_TYPE_MARKER") < 0, "leaked")

const payload = JSON.parse(enabled.fifo)
eq("the FIFO payload carries the matching nonce", payload.loadId, LOAD_ID)
eq("the FIFO payload carries only eligible keys", payload.items.length, 1)
eq("the eligible key is the non-reprompt one", payload.items[0].itemId, "ssh-1")
eq("the eligible key carries its private material", payload.items[0].privateKey, privatePem)
eq("the eligible key carries its public blob", payload.items[0].publicKey, "ssh-ed25519 AAAAWORK")
eq("the eligible key carries its fingerprint", payload.items[0].fingerprint, "SHA256:work")
eq("the eligible key is not marked re-prompt", payload.items[0].requiresReprompt, false)

// Re-prompt private keys never leave the jq stage, so the companion is never
// asked to hold one -- its own skip rule is the second line, not the first.
check("no re-prompt private key reaches the FIFO", enabled.fifo.indexOf(REPROMPT_MARKER) < 0, "leaked")
check("no ordinary item reaches the FIFO", enabled.fifo.indexOf("login-1") < 0, "leaked")
check("no unknown cipher type reaches the FIFO", enabled.fifo.indexOf("UNKNOWN_TYPE_MARKER") < 0, "leaked")

// The companion decodes with serde `deny_unknown_fields`, so the projection
// has to be exactly the agreed shape or every load fails closed.
eq("the envelope has exactly loadId and items",
  Object.keys(payload).sort().join(","), "items,loadId")
eq("each item has exactly the agreed fields",
  Object.keys(payload.items[0]).sort().join(","),
  "fingerprint,itemId,name,privateKey,publicKey,requiresReprompt")

// -------------------------------------------------------------------------
// The optional branch can never break the ordinary list
// -------------------------------------------------------------------------

// No FIFO at all: the helper never started, or cleaned up on the way out.
{
  try { fs.unlinkSync(fifoPath) } catch (e) {}
  const run = runPipeline({ agentBranch: true, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: LOAD_ID })
  eq("a missing FIFO still loads the item list", run.status, 0)
  check("a missing FIFO still produces the full envelope",
    JSON.parse(run.stdout).sshKeys.length === 2, run.stdout.slice(0, 200))
  check("a missing FIFO is not created as a regular file", !fs.existsSync(fifoPath),
    "the branch created something at the FIFO path")
}

// A regular file squatting on the FIFO path is never written through.
{
  fs.writeFileSync(fifoPath, "not a fifo\n")
  const run = runPipeline({ agentBranch: true, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: LOAD_ID })
  eq("a squatted FIFO path still loads the item list", run.status, 0)
  eq("the squatting file is untouched", fs.readFileSync(fifoPath, "utf8"), "not a fifo\n")
  check("no private key was written to the squatting file",
    fs.readFileSync(fifoPath, "utf8").indexOf(PRIVATE_MARKER) < 0, "leaked")
  fs.unlinkSync(fifoPath)
}

// A FIFO nobody drains. The branch opens O_RDWR so it never blocks on open,
// and the payload here fits the pipe buffer, so the list is unaffected.
{
  execFileSync("mkfifo", ["-m", "600", fifoPath])
  const run = runPipeline({ agentBranch: true, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: LOAD_ID })
  eq("an undrained FIFO still loads the item list", run.status, 0)
  check("an undrained FIFO still produces the full envelope",
    JSON.parse(run.stdout).sshKeys.length === 2, run.stdout.slice(0, 200))
  fs.unlinkSync(fifoPath)
}

// A missing nonce must not produce a payload the companion would accept.
{
  const run = withFifoReader(() =>
    runPipeline({ agentBranch: true, runtimeDir: runtimeDir }, { [Model.loadIdEnvVar()]: "" }))
  eq("a missing nonce still loads the item list", run.result.status, 0)
  check("a missing nonce never yields a usable payload",
    run.fifo === "" || !Model.isValidLoadId((JSON.parse(run.fifo || "{}").loadId) || ""),
    run.fifo.slice(0, 200))
}

// -------------------------------------------------------------------------
// Whole-pipeline failures publish no partial private set
// -------------------------------------------------------------------------

// Input the filters reject: the branch cannot even construct a payload, so
// nothing usable reaches the FIFO in the first place.
for (const [label, contents] of [
  ["malformed JSON", "{ this is not json"],
  ["a truncated array", '[{"object":"item","id":"a","type":1,'],
  ["a non-array document", '{"items":[]}']
]) {
  const run = withFifoReader(() =>
    runPipeline({ agentBranch: true, runtimeDir: runtimeDir },
      { [Model.loadIdEnvVar()]: LOAD_ID }, contents))
  check(`${label} fails the whole read`, run.result.status !== 0, `status ${run.result.status}`)
  check(`${label} produces no item list`, run.result.stdout.trim() === "", run.result.stdout.slice(0, 200))
  check(`${label} publishes no private key`, run.fifo.indexOf(PRIVATE_MARKER) < 0, "leaked")
  check(`${label} publishes no complete payload`, (() => {
    if (run.fifo.trim() === "") return true
    try { JSON.parse(run.fifo); return false } catch (e) { return true }
  })(), run.fifo.slice(0, 200))
}

// A `bw` that streams a complete, valid document and *then* exits nonzero is
// a different shape of failure: the branch has already forwarded well-formed
// bytes by the time the exit status exists, and no in-stream check could have
// known. The FIFO is deliberately not the boundary here -- `key_load_end` is.
// The companion holds every candidate unpublished until that line arrives, and
// discards it on `failed`, so what matters is that the panel reports failure.
{
  const run = withFifoReader(() =>
    runPipeline({ agentBranch: true, runtimeDir: runtimeDir },
      { [Model.loadIdEnvVar()]: LOAD_ID, QSBW_BW_EXIT: "1" }, JSON.stringify(fixture)))
  check("a failing bw fails the whole read", run.result.status !== 0, `status ${run.result.status}`)
  check("a failing bw produces no item list", run.result.stdout.trim() === "", run.result.stdout.slice(0, 200))
  eq("a failed read is framed as a failed load", Model.sshAgentLoadEndLine(7, false),
    JSON.stringify({ v: 1, type: "key_load_end", epoch: 7, status: "failed" }) + "\n")
  const panelSrc = fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8")
  check("the panel closes every load window with the read's real outcome",
    /endSshAgentLoad\(exitCode === 0\)/.test(panelSrc), "the exit handler does not close the load window")
  check("the panel closes the window on paths that abandon a load",
    /endSshAgentLoad\(false\)/.test(panelSrc), "no path reports a failed load")
  check("closing the window writes the versioned key_load_end line",
    /sshAgentProc\.write\(Model\.sshAgentLoadEndLine\(/.test(panelSrc),
    "key_load_end is never sent to the helper")
  // The cancel itself lives in the lock transition (see
  // tests/ssh-agent-lifecycle.test.js); what matters here is that locking
  // goes through it rather than leaving a fan-out read running.
  check("a lock abandons the in-flight load",
    /function lockVault\(\)[\s\S]{0,600}?applySshAgentLifecycle\("lock"\)/.test(panelSrc)
      && /function applySshAgentLifecycle\(event\)[\s\S]{0,900}?action\.cancelLoad\) cancelSshAgentLoad\(\)/.test(panelSrc),
    "locking does not cancel the in-flight load")
  check("a failed fan-out read is retried once without the branch",
    /listRetriedWithoutAgent = true[\s\S]{0,200}?startVaultListRead\(true\)/.test(panelSrc),
    "no retry without the agent branch")
}

// An ordinary item carrying an SSH subtree still rejects the whole read, with
// the agent branch present as well as without it.
{
  const crossed = [{ object: "item", id: "x", type: 1, name: "Crossed",
    login: { username: "u" }, sshKey: { privateKey: privatePem } }]
  const run = withFifoReader(() =>
    runPipeline({ agentBranch: true, runtimeDir: runtimeDir },
      { [Model.loadIdEnvVar()]: LOAD_ID }, JSON.stringify(crossed)))
  check("a cross-typed item rejects the whole read", run.result.status !== 0, `status ${run.result.status}`)
  check("a cross-typed item leaks no private key to QML",
    run.result.stdout.indexOf(PRIVATE_MARKER) < 0, "leaked")
  check("a cross-typed item leaks no private key to the FIFO",
    run.fifo.indexOf(PRIVATE_MARKER) < 0, "leaked")
}

// -------------------------------------------------------------------------
// Lock has to be able to stop the whole group
// -------------------------------------------------------------------------

check("the fan-out pipeline runs under process-group supervision",
  agentCommandText.indexOf("set -m") >= 0 && agentCommandText.indexOf("kill -TERM") >= 0,
  agentCommandText.slice(0, 300))

// -------------------------------------------------------------------------
// Control lines that frame a load
// -------------------------------------------------------------------------

eq("key_load_begin is a versioned v1 line", Model.sshAgentLoadBeginLine(7, LOAD_ID),
  JSON.stringify({ v: 1, type: "key_load_begin", epoch: 7, loadId: LOAD_ID }) + "\n")
eq("key_load_end reports success", Model.sshAgentLoadEndLine(7, true),
  JSON.stringify({ v: 1, type: "key_load_end", epoch: 7, status: "ok" }) + "\n")
eq("key_load_end reports failure", Model.sshAgentLoadEndLine(7, false),
  JSON.stringify({ v: 1, type: "key_load_end", epoch: 7, status: "failed" }) + "\n")
eq("vault_locked is a versioned v1 line", Model.sshAgentVaultLockedLine(7),
  JSON.stringify({ v: 1, type: "vault_locked", epoch: 7 }) + "\n")
eq("vault_logged_out is a versioned v1 line", Model.sshAgentLoggedOutLine(),
  JSON.stringify({ v: 1, type: "vault_logged_out" }) + "\n")
eq("an invalid nonce yields no begin line", Model.sshAgentLoadBeginLine(7, "nope"), "")

// No control line may ever carry key material or a session token.
for (const line of [Model.sshAgentLoadBeginLine(7, LOAD_ID), Model.sshAgentLoadEndLine(7, true),
                    Model.sshAgentVaultLockedLine(7), Model.sshAgentLoggedOutLine()]) {
  check("no control line carries private material",
    line.indexOf(PRIVATE_MARKER) < 0 && line.indexOf("BW_SESSION") < 0 && line.indexOf("privateKey") < 0, line)
}

// -------------------------------------------------------------------------
// The whole data plane, end to end
// -------------------------------------------------------------------------
//
// Everything above tests one boundary at a time. This runs the real thing:
// the real pipeline writes to the real companion's FIFO, the companion
// validates and publishes, and the real OpenSSH client lists the key back.
// It is the only test that would catch the projection and the decoder
// disagreeing about a field name, because both sides are real here.
const helperBin = path.join(repoRoot, "agent", "target", "debug", "qs-bitwarden-ssh-agent")

function endToEnd(done) {
  if (!fs.existsSync(helperBin) || !fs.existsSync("/usr/bin/ssh-keygen")) {
    failures.push("the end-to-end check needs the built helper and /usr/bin/ssh-keygen\n    "
      + "build it with: cargo build --manifest-path agent/Cargo.toml --locked")
    return done()
  }

  const e2eDir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-e2e-"))
  const e2eRuntime = path.join(e2eDir, "run")
  fs.mkdirSync(e2eRuntime, { mode: 0o700 })
  const e2eLoadId = "aaaabbbbccccddddeeeeffff00001111"

  // A disposable key that exists only for the life of this test.
  const keyPath = path.join(e2eDir, "id_ed25519")
  execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e", "-f", keyPath])
  const priv = fs.readFileSync(keyPath, "utf8")
  const pub = fs.readFileSync(keyPath + ".pub", "utf8").trim()
  const fingerprint = execFileSync("/usr/bin/ssh-keygen", ["-lf", keyPath + ".pub"],
    { encoding: "utf8" }).split(" ")[1]

  const e2eFixture = path.join(e2eDir, "items.json")
  fs.writeFileSync(e2eFixture, JSON.stringify([
    { object: "item", id: "login-1", type: 1, name: "Login", login: { username: "u" } },
    { object: "item", id: "ssh-1", type: 5, name: "Disposable", reprompt: 0,
      sshKey: { privateKey: priv, publicKey: pub, fingerprint: fingerprint } }
  ]))
  fs.writeFileSync(path.join(e2eDir, "bw"), [
    "#!/usr/bin/env bash",
    'if [ "$1" = "--version" ]; then echo 2026.2.0; exit 0; fi',
    'cat -- "$QSBW_FIXTURE"', ""
  ].join("\n"), { mode: 0o755 })

  const { spawn } = require("child_process")
  const helper = spawn(helperBin, [], { env: { XDG_RUNTIME_DIR: e2eRuntime }, stdio: ["pipe", "pipe", "pipe"] })
  let buffered = ""
  let socketPath = ""
  let settled = false
  const finish = () => {
    if (settled) return
    settled = true
    clearTimeout(guard)
    try { helper.kill("SIGKILL") } catch (e) {}
    try { fs.rmSync(e2eDir, { recursive: true, force: true }) } catch (e) {}
    done()
  }
  const guard = setTimeout(() => {
    failures.push("the end-to-end load timed out\n    the companion never reported keys_loaded")
    finish()
  }, 30000)

  helper.stdin.write(Model.sshAgentHelloLine())
  helper.stdout.on("data", chunk => {
    buffered += chunk.toString("utf8")
    let nl
    while ((nl = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, nl)
      buffered = buffered.slice(nl + 1)
      let message
      try { message = JSON.parse(line) } catch (e) {
        failures.push("the companion emitted an unparseable line\n    " + line)
        return finish()
      }

      if (message.type === "ready") {
        socketPath = message.socketPath
        // Arm the window before anything can write to the FIFO.
        helper.stdin.write(Model.sshAgentLoadBeginLine(1, e2eLoadId))
        const command = Model.sanitizedListCommand({ agentBranch: true })
        const run = spawnSync(command[0], command.slice(1), {
          env: { PATH: e2eDir + path.delimiter + process.env.PATH, QSBW_FIXTURE: e2eFixture,
                 XDG_RUNTIME_DIR: e2eRuntime, [Model.loadIdEnvVar()]: e2eLoadId },
          encoding: "utf8", maxBuffer: 20 * 1024 * 1024
        })
        eq("the end-to-end pipeline succeeds", run.status, 0)
        check("the end-to-end read still renders the panel envelope",
          run.status === 0 && JSON.parse(run.stdout).sshKeys.length === 1, String(run.stdout).slice(0, 200))
        check("no private key reaches QML in the end-to-end read",
          String(run.stdout).indexOf("PRIVATE KEY") < 0, "leaked")
        if (run.status !== 0) return finish()
        helper.stdin.write(Model.sshAgentLoadEndLine(1, true))
      }

      if (message.type === "keys_loaded") {
        eq("the companion published exactly the eligible key", message.keyCount, 1)
        eq("the companion published it for the load's epoch", message.epoch, 1)
        const listed = spawnSync("/usr/bin/ssh-add", ["-L"], {
          env: { SSH_AUTH_SOCK: socketPath, PATH: "/usr/bin", HOME: os.homedir() }, encoding: "utf8"
        })
        eq("a real OpenSSH client lists the loaded identity", listed.status, 0)
        eq("the agent offers exactly the key the vault held",
          String(listed.stdout).trim().split(" ").slice(0, 2).join(" "),
          pub.split(" ").slice(0, 2).join(" "))
        return finish()
      }
    }
  })
  helper.on("error", () => {
    failures.push("the companion could not be started\n    " + helperBin)
    finish()
  })
  helper.on("exit", code => {
    if (settled) return
    failures.push("the companion exited before publishing\n    exit " + code)
    finish()
  })
}

endToEnd(() => {
  try { fs.rmSync(tempDir, { recursive: true, force: true }) } catch (e) {}
  if (failures.length) {
    console.error(`\n${failures.length} failed, ${pass} passed\n`)
    failures.forEach(f => console.error(`  FAIL ${f}`))
    process.exit(1)
  }
  console.log(`ssh-agent-pipeline: ${pass} passed`)
})
