#!/usr/bin/env node
// The vault helper (vault/, docs/vault-helper.md): the panel's side of the
// protocol, what the shell may still hold, and the real helper binary driven
// the way the panel drives it. The helper's own Rust tests cover the rest.
//
// Needs the helper built at vault/target/debug/ (cargo build --manifest-path
// vault/Cargo.toml --locked) for the binary checks.
//
//   node tests/vault-helper.test.js

const { createSuite, loadModule, readPluginSource, functionBody, repoRoot, read } = require("./harness")
const path = require("path")
const fs = require("fs")
const { spawn } = require("child_process")

const { check, eq, done } = createSuite("vault-helper")
const Model = loadModule()
const Totp = loadModule("TotpModel.js")
const service = readPluginSource("Service.qml")
const body = name => functionBody(service, name)

// --- the protocol, panel side ---------------------------------------------------

const line = JSON.parse(Model.vaultExecLine(4, ["bw", "status"], { A: 1, B: null }, { BW_SESSION: "session" }, "session", "in"))
eq("an exec request carries the run, strings only in env",
  JSON.stringify(line),
  JSON.stringify({ type: "exec", v: 1, id: 4, argv: ["bw", "status"], env: { A: "1", B: null },
    inject: { BW_SESSION: "session" }, capture: "session", stdin: "in" }))
eq("a reply line parses, anything else is null",
  [Model.parseVaultHelperLine('{"type":"ready"}').type, Model.parseVaultHelperLine("nope"), Model.parseVaultHelperLine("3")].join(),
  "ready,,")
const ref = Model.heldSecretRef("pw7")
check("a held password is a reference by name, never a real value",
  Model.heldSecretName(ref) === "pw7" && Model.heldSecretName("pw7") === "" && ref.indexOf("\u0000") === 0, ref)
check("the held-session placeholder is shaped like a key, so parsing is unchanged",
  Model.extractSessionToken("export BW_SESSION=\"" + Model.vaultHeldSession() + "\"") === Model.vaultHeldSession(), "")
check("the fallback banner says what is lost",
  /Crash protection is off/.test(Model.vaultHelperWarning("")) && /core dump/.test(Model.vaultHelperWarning("x")), "")

// --- what the shell may still hold ---------------------------------------------------

check("bwEnv() carries no session: a VaultProcess adds it",
  !/sessionEnvVar/.test(body("bwEnv")), body("bwEnv"))
// Every process whose environment is a `bw` one must be a VaultProcess.
const bwEnvFns = /root\.(bwEnv|authEnv|itemEnv|folderEnv|sendEnv|loginProcessEnv)\(/
const plainProcesses = service.split(/\n  (?=Process \{|VaultProcess \{)/)
  .filter(block => block.indexOf("Process {") === 0)
  .map(block => block.slice(0, block.indexOf("\n  }\n") + 1))
const leaking = plainProcesses.filter(block => bwEnvFns.test(block)).map(block => (/id: (\w+)/.exec(block) || [])[1])
eq("no plain Process runs with a bw environment", leaking.join(), "")
for (const id of ["envelopeProc", "lockProc", "listProc", "unlockProc", "loginProc", "keyringStoreProc",
                  "sessionHandoffProc", "keyringLookupProc", "authPasswordWriterProc", "pinUnlockProc", "keyringLookupMasterProc"]) {
  check(`${id} is a VaultProcess`, new RegExp(`VaultProcess \\{\\s*id: ${id}\\b`).test(service), id)
}
check("the list read keeps its items in the helper",
  /VaultProcess \{\s*id: listProc\s*vault: root\s*capture: "vault"/.test(service), "")
check("saves update the helper's copy of the item",
  /id: createItemProc\s*vault: root\s*capture: "vaultMerge"/.test(service) && /id: editItemProc\s*vault: root\s*capture: "vaultMerge"/.test(service), "")
check("the keyring store gets the session from the helper",
  /id: keyringStoreProc[\s\S]{0,300}inject: root\.injectSession\(Model\.keyringSecretEnvVar\(\)\)/.test(service)
    && !/secretEnv\(root\.session\)/.test(service), "")
check("an unknown plugin directory ends in the fallback, so queued runs are flushed rather than left waiting",
  /sshAgentPluginDir === ""\) \{\s*useVaultFallback\(/.test(body("inspectVaultHelper"))
    && /vaultHelperState = "fallback"[\s\S]*flushVaultWaiting\(\)/.test(body("useVaultFallback")), body("inspectVaultHelper"))
check("a lock drops the helper's key and items",
  /forgetVault\(\)/.test(body("dropVaultState")), body("dropVaultState"))
check("each queued lock keeps its own copy of the key until it has run",
  /holdSession\(name\)/.test(body("requestBwLock")) && /"secret:" \+ run\.key/.test(body("runBwLockStep"))
    && /forgetVaultSecret\(lockRun\.key\)/.test(body("finishBwLock")), body("requestBwLock"))
check("a deleted item is dropped from the helper once the delete succeeded, even if the panel moved on",
  /exitCode === 0 && removal\) forgetVaultItem\(removal\.id\)[\s\S]*?vaultReadIsStale\("itemDelete"\)/.test(body("onDeleteItemFinished"))
    && /vaultHelperLine\("forgetItem", \{ id: id \}\)/.test(body("forgetVaultItem")), body("onDeleteItemFinished"))
check("quick unlock's master password stays in the helper",
  /holdOutput: true/.test(body("submitPinUnlock")) && /holdOutput: true/.test(body("openEnvelopeForFingerprint"))
    && /envelopeProc\.outputHeld \? Model\.heldSecretRef\(job\.heldName\)/.test(body("onEnvelopeJobExited")), "")
check("a held reference in an environment travels by name",
  /Model\.heldSecretName\(proc\.environment\[key\]\)[\s\S]{0,80}inject\[key\] = "secret:" \+ held/.test(body("vaultStart")), body("vaultStart"))
check("a password copy goes from the helper to wl-copy",
  /vaultQuery\("copyPassword"/.test(body("copyPasswordNow")), body("copyPasswordNow"))
check("the detail view asks the helper for the one item",
  /vaultQuery\("item", \{ id: id \}/.test(body("openDetail")), body("openDetail"))
check("TOTP comes from the helper, bw only for keys it does not mirror",
  /vaultQuery\("totp"/.test(body("fetchTotp")) && /root\.fetchTotp\(requested, false, true\)/.test(body("fetchTotp")), "")
check("search asks the helper, and an answer for old text is dropped",
  /vaultQuery\("search"/.test(body("askHelperSearch")) && /root\.searchAskedQuery !== query\) return/.test(body("askHelperSearch")), "")
check("a helper that stops locks a vault it held the key for",
  /session === heldSessionMarker[\s\S]{0,400}lockVault\(\)/.test(body("onVaultHelperExited")), body("onVaultHelperExited"))
// A lock of its own here once skipped the SSH agent, which kept signing with
// the vault's keys behind a panel that said it was locked.
check("that lock is the ordinary one, not a copy of it",
  !/status = "locked"/.test(body("onVaultHelperExited")), body("onVaultHelperExited"))
check("the SSH agent is locked even when the panel was not yet unlocked",
  /session === heldSessionMarker[\s\S]{0,600}\} else \{\s*applySshAgentLifecycle\("lock"\)\s*dropVaultState\(\)/
    .test(body("onVaultHelperExited")), body("onVaultHelperExited"))
// A `bw status` failing with the helper used to land first and read as a
// sign-out, putting up the login screen instead of the unlock.
{
  const exited = body("onVaultHelperExited")
  check("the vault is locked before the helper's runs fail",
    exited.indexOf("lockVault()") > 0 && exited.indexOf("lockVault()") < exited.indexOf("runs[id].finish("), exited)
}
check("a run stopped after the helper died is not written to it",
  /if \(proc\.runId > 0\) \{[\s\S]{0,120}if \(vaultHelperActive\) vaultHelperProc\.write/.test(body("vaultKill")), body("vaultKill"))
check("a helper that cannot be used at start falls back, and says so",
  /useVaultFallback\(vaultHelper\.message\)/.test(body("onVaultHelperInspected")), "")
check("the panel shows the fallback banner",
  /visible: root\.vaultHelperWarning !== ""/.test(readPluginSource("Panel.qml")), "")

// A stripped list item is no base for detail or edit.
const [held] = Model.parseItems([{ id: "a", type: 1, name: "n", login: { username: "u" }, qsbwHeld: { password: true, totp: true, notes: true } }])
check("an item from the helper says what it has without holding it",
  held.hasPassword && held.hasTotp && held.hasNotes && held.password === "" && held.totpKey === ""
    && held.rawObject === null && held.secretsHeld, JSON.stringify(held))

// --- a helper that keeps stopping (GHSA-6qjw-gmvg-7hvw #2) -----------------------

{
  const exited = body("onVaultHelperExited")
  check("a helper that keeps stopping leaves the vault locked rather than in the shell",
    /stopVaultHelper\(\)/.test(exited) && !/useVaultFallback/.test(exited), exited)
  const stop = body("stopVaultHelper")
  check("stopped is its own state, with a banner and no fallback",
    /vaultHelperState = "stopped"/.test(stop) && /vaultHelperWarning = /.test(stop)
      && !/useVaultFallback|runLocally/.test(stop), stop)
  const start = body("vaultStart")
  check("runs wait while the helper is stopped instead of running in the shell",
    /vaultHelperState === "stopped"/.test(start.split("runLocally")[0]), start)
  const retry = body("retryVaultHelper")
  check("trying again starts the helper with a fresh count",
    /vaultHelperState !== "stopped"\) return/.test(retry) && /vaultHelperRestarts = 0/.test(retry)
      && /startVaultHelper\(\)/.test(retry), retry)
  check("the count clears once the helper has stayed up a minute",
    /vaultHelperSettledMs: 60000/.test(service)
      && /id: vaultHelperSettleTimer[\s\S]{0,200}vaultHelperRestarts = 0/.test(service)
      && /vaultHelperSettleTimer\.restart\(\)/.test(body("onVaultHelperLine"))
      && /vaultHelperSettleTimer\.stop\(\)/.test(exited), "")
}

// --- the real helper -------------------------------------------------------------

const binary = path.join(repoRoot, "vault/target/debug/qs-bitwarden-vault")
if (!fs.existsSync(binary)) {
  check("the helper is built for the binary checks", false,
    "build it with: cargo build --manifest-path vault/Cargo.toml --locked")
  done()
} else {
  const inspection = require("child_process").execFileSync(...(c => [c[0], c.slice(1)])(Model.vaultHelperInspectCommand(repoRoot))).toString()
  const parsed = Model.parseVaultHelperInspection(inspection)
  eq("the panel's inspection accepts the built helper", parsed.state + "/" + parsed.protocol, "ok/1")

  const child = spawn(binary, [], { stdio: ["pipe", "pipe", "inherit"] })
  let buffer = ""
  const waiting = []
  const replies = []
  child.stdout.on("data", chunk => {
    buffer += chunk
    let at
    while ((at = buffer.indexOf("\n")) >= 0) {
      replies.push(JSON.parse(buffer.slice(0, at)))
      buffer = buffer.slice(at + 1)
      for (const w of waiting.splice(0)) w()
    }
  })
  const reply = match => new Promise(resolve => {
    const look = () => {
      const i = replies.findIndex(match)
      if (i >= 0) resolve(replies.splice(i, 1)[0])
      else waiting.push(look)
    }
    look()
  })
  const send = text => child.stdin.write(text)

  ;(async () => {
    send(Model.vaultHelperLine("hello", {}))
    eq("the helper answers the panel's hello", (await reply(m => m.type === "ready")).protocol, 1)

    // TOTP: the helper's codes match TotpModel.js, quirks included.
    const keys = [
      "JBSWY3DPEHPK3PXP", "jbsw y3dp ehpk 3pxp====", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8",
      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&period=60", "steam://JBSWY3DPEHPK3PXP",
      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512", "otpauth://totp/Issuer:me%40x?secret=JBSWY3DP&issuer=Issuer"
    ]
    const items = keys.map((key, i) => ({ id: "t" + i, type: 1, name: "t" + i, login: { totp: key } }))
    const list = JSON.stringify({ items, sshKeys: [] })
    send(Model.vaultExecLine(1, ["sh", "-c", "cat"], {}, {}, "vault", list))
    await reply(m => m.type === "exit" && m.id === 1)
    let q = 100
    for (let i = 0; i < keys.length; i++) {
      q += 1
      const before = Date.now()
      send(Model.vaultHelperLine("totp", { q, id: "t" + i }))
      const answer = await reply(m => m.type === "result" && m.q === q)
      const local = Totp.generate(keys[i], before)
      const after = Totp.generate(keys[i], Date.now())
      const helperCode = answer.ok ? answer.value.code : null
      check(`TOTP matches TotpModel.js for ${keys[i].slice(0, 40)}`,
        (local === null && helperCode === null) || (local && (helperCode === local.code || helperCode === (after && after.code))),
        `helper ${helperCode}, js ${local && local.code}`)
    }

    // Search in the helper covers notes; the list the panel gets has none.
    const vault = JSON.stringify({ items: [{ id: "n", type: 2, name: "Note", notes: "the recovery words" }], sshKeys: [] })
    send(Model.vaultExecLine(2, ["sh", "-c", "cat"], {}, {}, "vault", vault))
    const read = await reply(m => m.type === "exit" && m.id === 2)
    check("the list the panel gets has no notes", !/recovery/.test(read.out) && /"qsbwHeld"/.test(read.out), read.out)
    send(Model.vaultHelperLine("search", { q: 200, query: "Recovery" }))
    eq("the helper's search finds note text", JSON.stringify((await reply(m => m.q === 200)).value), '["n"]')

    send(Model.vaultHelperLine("forgetItem", { id: "n" }))
    send(Model.vaultHelperLine("item", { q: 201, id: "n" }))
    check("a forgotten item is no longer served by the helper", (await reply(m => m.q === 201)).ok === false, "")
    send(Model.vaultHelperLine("search", { q: 202, query: "Recovery" }))
    eq("nor found by its search", JSON.stringify((await reply(m => m.q === 202)).value), "[]")

    child.stdin.end()
    child.on("exit", () => done())
  })().catch(error => {
    check("the helper round trip", false, String(error && error.stack || error))
    child.kill()
    done()
  })
}
