#!/usr/bin/env node
// Several accounts side by side: each keeps its own bw data directory, keyring
// entries and quick-unlock envelope, and signing one out or switching away
// leaves the others' untouched. The keyring and envelope pipelines run for
// real against a file-backed `secret-tool` (as in unlock-envelope.test.js),
// and `bw` is a stand-in that records which data directory it was given.
//
// Needs: argon2, jq, and unlock-key/target/debug/qs-bitwarden-unlock-key.
//
//   node tests/multi-account.test.js

const { createSuite, loadModule, readPluginSource, functionBody, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const Model = loadModule()
const { check, eq, done } = createSuite("multi-account")

const which = name => spawnSync("bash", ["-c", `command -v ${name}`], { encoding: "utf8" }).stdout.trim()
const realTool = path.join(repoRoot, "unlock-key", "target", "debug", "qs-bitwarden-unlock-key")
const argon2 = which("argon2")
const missing = [["argon2", argon2], ["jq", which("jq")], ["the unlock tool", fs.existsSync(realTool) ? realTool : ""]]
  .filter(([, found]) => !found).map(([name]) => name)
if (missing.length) {
  console.error(`multi-account: cannot run without ${missing.join(", ")}`)
  process.exit(1)
}

const SLOT_A = Model.DEFAULT_ACCOUNT_SLOT
const SLOT_B = "0123456789abcdef"
const SLOT_C = "fedcba9876543210"

// -------------------------------------------------------------------------
// Slots and names
// -------------------------------------------------------------------------

check("the default slot and 16 hex digits are slots", Model.isAccountSlot("default") && Model.isAccountSlot(SLOT_B), "")
for (const bad of ["", "DEFAULT", "0123456789ABCDEF", "0123456789abcde", "../../etc", "0123456789abcdef0", "a b"]) {
  check(`"${bad}" is not a slot`, !Model.isAccountSlot(bad), bad)
}
eq("anything that is not a slot means the default one", Model.accountSlot("../x"), "default")
eq("the default slot keeps the legacy keyring names", Model.keyringEntryName("unlock_envelope", "default"), "unlock_envelope")
eq("so does a caller that passes no slot", Model.keyringEntryName("session"), "session")
eq("another slot's names are suffixed", Model.keyringEntryName("unlock_envelope", SLOT_B), "unlock_envelope@" + SLOT_B)

eq("the default slot uses bw's own directory", Model.accountAppDataDir("default", "/x", "/home/u"), "")
eq("another slot lives under XDG_DATA_HOME",
  Model.accountAppDataDir(SLOT_B, "/data", "/home/u"), "/data/qs-bitwarden-cli/accounts/" + SLOT_B)
eq("or ~/.local/share without it",
  Model.accountAppDataDir(SLOT_B, "", "/home/u/"), "/home/u/.local/share/qs-bitwarden-cli/accounts/" + SLOT_B)
eq("a relative XDG_DATA_HOME is ignored, as the spec says",
  Model.accountAppDataDir(SLOT_B, "rel", "/home/u"), "/home/u/.local/share/qs-bitwarden-cli/accounts/" + SLOT_B)
eq("and with no home at all there is no directory", Model.accountAppDataDir(SLOT_B, "", ""), "")

const fresh = Model.newAccountSlot([SLOT_B])
check("a new slot is a slot", Model.isAccountSlot(fresh) && fresh !== "default", fresh)

// -------------------------------------------------------------------------
// The registry
// -------------------------------------------------------------------------

let reg = Model.parseAccountRegistry("")
eq("no file is an empty registry on the default slot", Model.serializeAccountRegistry(reg),
  JSON.stringify({ version: 1, active: "default", accounts: [] }))
eq("a new account goes to the default slot while it is free", Model.slotForNewAccount(reg), "default")

let noted = Model.registryNoteAccount(reg, SLOT_A, { userId: "u-a", email: "a@example.com", server: "https://vault.bitwarden.com" }, 100)
reg = noted.registry
eq("the first account is recorded", reg.accounts.length, 1)
const nextSlot = Model.slotForNewAccount(reg)
check("once taken, a new account gets a fresh slot", Model.isAccountSlot(nextSlot) && nextSlot !== "default", nextSlot)

reg = Model.registryNoteAccount(reg, SLOT_B, { userId: "u-b", email: "b@example.eu", server: "https://vault.bitwarden.eu" }, 200).registry
eq("a second account is recorded beside it", reg.accounts.length, 2)
eq("and becomes active", reg.active, SLOT_B)
eq("the most recent other account is next after the active one", Model.registryNextAccount(reg, SLOT_B), SLOT_A)

const rows = Model.accountRows(reg, SLOT_B)
eq("rows are sorted by email", rows.map(r => r.email).join(","), "a@example.com,b@example.eu")
eq("a US-server account shows no server", rows[0].label, "a@example.com")
eq("an EU one says so", rows[1].label, "b@example.eu (EU)")
check("only the active row is marked", !rows[0].active && rows[1].active, JSON.stringify(rows))

noted = Model.registryNoteAccount(reg, SLOT_C, { userId: "u-a", email: "a@example.com", server: "https://vault.bitwarden.com" }, 300)
eq("signing the same account in again retires its older slot", noted.retired.join(","), SLOT_A)
eq("which leaves one entry for it", noted.registry.accounts.filter(a => a.userId === "u-a").length, 1)
const sameUserOtherServer = Model.registryNoteAccount(reg, SLOT_C,
  { userId: "u-a", email: "a@example.com", server: "https://selfhosted.example" }, 300)
eq("the same user id on another server is another account", sameUserOtherServer.retired.length, 0)

const removed = Model.registryRemoveAccount(reg, SLOT_B)
eq("removing an account keeps the others", removed.accounts.map(a => a.slot).join(","), SLOT_A)
eq("the registry itself is not changed in place", reg.accounts.length, 2)

const roundTrip = Model.parseAccountRegistry(Model.serializeAccountRegistry(reg))
eq("the registry round-trips", Model.serializeAccountRegistry(roundTrip), Model.serializeAccountRegistry(reg))
const hostile = Model.parseAccountRegistry(JSON.stringify({ version: 1, active: "../../x", accounts: [
  { slot: "../../etc", email: "x" }, { slot: SLOT_B, email: "b\u001b[31m@x", userId: 5 }, { slot: SLOT_B, email: "dup" }] }))
eq("a malformed slot and a duplicate are dropped", hostile.accounts.length, 1)
eq("control characters are stripped", hostile.accounts[0].email, "b[31m@x")
eq("a malformed active slot means the default", hostile.active, "default")
eq("another version is not trusted", Model.parseAccountRegistry('{"version":2,"accounts":[{"slot":"default"}]}').accounts.length, 0)

let full = Model.emptyAccountRegistry()
for (let i = 0; i < Model.maxAccounts(); i++) {
  full = Model.registryNoteAccount(full, i === 0 ? "default" : Model.newAccountSlot(full.accounts.map(a => a.slot)),
    { userId: "u" + i, email: i + "@x", server: "" }, i).registry
}
check("the list is capped", Model.registryNoteAccount(full, SLOT_C, { userId: "new", email: "n@x" }, 1).full === true, "")

// -------------------------------------------------------------------------
// Commands name their slot
// -------------------------------------------------------------------------

const script = cmd => cmd[cmd.length - 1]
check("a slot's session entry is its own",
  script(Model.keyringStoreCommand(SLOT_B)).includes("'session@" + SLOT_B + "'")
    && script(Model.keyringLookupCommand(SLOT_B)).includes("'session@" + SLOT_B + "'"), script(Model.keyringStoreCommand(SLOT_B)))
check("the default slot's session entry is unchanged",
  /account 'session'( |;|$)/.test(script(Model.keyringStoreCommand("default"))), script(Model.keyringStoreCommand("default")))
check("logout clears only its own slot",
  script(Model.keyringClearAllCommand(SLOT_B)).includes("unlock_envelope@" + SLOT_B)
    && !/'unlock_envelope'/.test(script(Model.keyringClearAllCommand(SLOT_B))), script(Model.keyringClearAllCommand(SLOT_B)))
check("the envelope builders use the account's slot",
  script(Model.unlockEnvelopeOpenCommand("/t", { id: "u", server: "s", slot: SLOT_B }, { kind: "fingerprint" })).includes("unlock_envelope@" + SLOT_B)
    && script(Model.unlockEnvelopeInspectCommand("/t", SLOT_B)).includes("unlock_envelope@" + SLOT_B), "")
eq("an account with a malformed slot is refused",
  Model.unlockEnvelopeOpenCommand("/t", { id: "u", server: "s", slot: "../x" }, { kind: "fingerprint" }).join(" "), "bash -c exit 2")
check("learned suggestions are per account",
  script(Model.associationsReadCommand(SLOT_B)).includes("associations@" + SLOT_B + ".json")
    && script(Model.associationsReadCommand("default")).includes("/associations.json"), "")
check("a terminal login for another slot exports its directory",
  script(Model.terminalLoginCommand("login", "", SLOT_B)).includes("BITWARDENCLI_APPDATA_DIR") , "")
check("a terminal login for the default slot does not",
  !script(Model.terminalLoginCommand("login", "", "default")).includes("export BITWARDENCLI_APPDATA_DIR"), "")

// -------------------------------------------------------------------------
// Real pipelines: two accounts' envelopes and sessions in one keyring
// -------------------------------------------------------------------------

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-accounts-"))
try {
  const bin = path.join(dir, "bin")
  const store = path.join(dir, "store")
  const dataHome = path.join(dir, "data")
  const bwLog = path.join(dir, "bw.log")
  fs.mkdirSync(bin)
  fs.mkdirSync(store)
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 })
  // One file per `account` attribute, as in unlock-envelope.test.js.
  write("secret-tool", `
cmd="$1"; shift
account=""; while [ $# -gt 0 ]; do case "$1" in account) account="$2"; shift 2;; *) shift;; esac; done
f="$STORE_DIR/$account"
case "$cmd" in
  lookup) [ -f "$f" ] || exit 1; cat "$f"; echo ;;
  store) cat > "$f.tmp" && mv "$f.tmp" "$f" ;;
  clear) rm -f "$f" ;;
  search) [ -f "$f" ] && cat "$f"; exit 0 ;;
  *) exit 2 ;;
esac`)
  write("systemd-creds", `
mode=""; name=""
for a in "$@"; do case "$a" in encrypt|decrypt) mode="$a";; --name=*) name="\${a#--name=}";; esac; done
if [ "$mode" = encrypt ]; then { printf 'SEALED:%s:' "$name"; base64 -w0; } | base64 -w0
else input="$(cat | base64 -d 2>/dev/null)" || exit 1
  case "$input" in "SEALED:$name:"*) printf '%s' "\${input#SEALED:$name:}" | base64 -d ;; *) exit 1 ;; esac; fi`)
  // Records the data directory it ran in; `status` answers from a file there.
  write("bw", `
printf '%s %s\\n' "\${BITWARDENCLI_APPDATA_DIR:-<own>}" "$*" >> "$BW_LOG"
if [ "$1" = status ]; then d="\${BITWARDENCLI_APPDATA_DIR:-$HOME/own}"; cat "$d/status.json" 2>/dev/null || echo '{"status":"unauthenticated"}'; fi
exit 0`)

  const baseEnv = {
    PATH: `${bin}:/usr/bin:/bin`, HOME: dir, XDG_DATA_HOME: dataHome,
    XDG_STATE_HOME: path.join(dir, "state"), STORE_DIR: store, BW_LOG: bwLog
  }
  const run = (cmd, extra) => {
    const r = spawnSync(cmd[0], cmd.slice(1), { env: Object.assign({}, baseEnv, extra || {}), encoding: "utf8", timeout: 120000 })
    return { code: r.status, out: r.stdout, err: r.stderr }
  }
  const entries = () => fs.readdirSync(store).sort()
  const SECRET = Model.keyringSecretEnvVar()
  const PIN = Model.pinEnvVar()
  const tool = realTool
  const A = { id: "user-a", server: "https://vault.bitwarden.com", slot: SLOT_A }
  const B = { id: "user-b", server: "https://vault.bitwarden.eu", slot: SLOT_B }
  const PW_A = "password of account A"
  const PW_B = "password of 'account' B $x"

  eq("account A's envelope is created", run(Model.unlockEnvelopeCreateCommand(tool, A), { [SECRET]: PW_A }).code, 0)
  eq("account B's envelope is created beside it", run(Model.unlockEnvelopeCreateCommand(tool, B), { [SECRET]: PW_B }).code, 0)
  eq("both are in the keyring under their own names", entries().join(","), "unlock_envelope,unlock_envelope@" + SLOT_B)
  eq("A gets a PIN", run(Model.unlockEnvelopeUpdateCommand(tool, A, { kind: "add-pin" }), { [SECRET]: PW_A, [PIN]: "111111" }).code, 0)
  eq("B gets another", run(Model.unlockEnvelopeUpdateCommand(tool, B, { kind: "add-pin" }), { [SECRET]: PW_B, [PIN]: "222222" }).code, 0)
  eq("B gets fingerprint too", run(Model.unlockEnvelopeUpdateCommand(tool, B, { kind: "add-fingerprint" }), { [SECRET]: PW_B }).code, 0)

  const open = (acct, via, env) => run(Model.unlockEnvelopeOpenCommand(tool, acct, via), env)
  eq("A's PIN opens A", open(A, { kind: "pin" }, { [PIN]: "111111" }).out, PW_A)
  eq("B's PIN opens B", open(B, { kind: "pin" }, { [PIN]: "222222" }).out, PW_B)
  eq("A's PIN does not open B", open(B, { kind: "pin" }, { [PIN]: "111111" }).code, 3)
  eq("fingerprint opens B", open(B, { kind: "fingerprint" }).out, PW_B)
  eq("but A never had it", open(A, { kind: "fingerprint" }).code, 7)
  eq("B's envelope refuses A's account", open({ id: A.id, server: A.server, slot: SLOT_B }, { kind: "pin" }, { [PIN]: "222222" }).code, 6)

  const inspect = slot => JSON.parse(run(Model.unlockEnvelopeInspectCommand(tool, slot)).out)
  check("each account's summary is its own",
    inspect(SLOT_A).account.id === "user-a" && inspect(SLOT_B).account.id === "user-b"
      && inspect(SLOT_A).fingerprint === false && inspect(SLOT_B).fingerprint === true, "")

  // Sessions: the boot-stamped entry, per slot.
  eq("A's session is stored", run(Model.keyringStoreCommand(SLOT_A), { [SECRET]: "session-a" }).code, 0)
  eq("B's session is stored", run(Model.keyringStoreCommand(SLOT_B), { [SECRET]: "session-b" }).code, 0)
  eq("A's lookup finds A's session", run(Model.keyringLookupCommand(SLOT_A)).out, "session-a")
  eq("B's finds B's", run(Model.keyringLookupCommand(SLOT_B)).out, "session-b")
  run(Model.keyringClearCommand(SLOT_B))
  eq("locking B leaves A's session", run(Model.keyringLookupCommand(SLOT_A)).out, "session-a")

  // Logging B out clears B, and only B.
  eq("B's logout sweep succeeds", run(Model.keyringClearAllCommand(SLOT_B)).code, 0)
  eq("only A's entries remain", entries().join(","), "session,unlock_envelope")
  eq("and A still unlocks with its PIN", open(A, { kind: "pin" }, { [PIN]: "111111" }).out, PW_A)

  // bw runs in the slot's directory.
  const slotDir = path.join(dataHome, "qs-bitwarden-cli", "accounts", SLOT_B)
  fs.writeFileSync(bwLog, "")
  const login = run(["bash", "-c", Model.appDataDirPrelude() + "bw status"], { BITWARDENCLI_APPDATA_DIR: slotDir })
  eq("the login prelude creates the slot's directory", login.code, 0)
  eq("private to the user", (fs.statSync(slotDir).mode & 0o777).toString(8), "700")
  eq("and bw runs in it", fs.readFileSync(bwLog, "utf8").trim(), slotDir + " status")
  const decoy = path.join(dir, "elsewhere")
  fs.mkdirSync(decoy)
  const linked = path.join(dataHome, "qs-bitwarden-cli", "accounts", SLOT_C)
  fs.symlinkSync(decoy, linked)
  check("a symlink in a slot's place is refused",
    run(["bash", "-c", Model.appDataDirPrelude() + "bw status"], { BITWARDENCLI_APPDATA_DIR: linked }).code !== 0, "")
  fs.unlinkSync(linked)

  // The registry file.
  const json = Model.serializeAccountRegistry(reg)
  eq("the registry is written", run(Model.accountRegistryWriteCommand(), { [Model.accountsEnvVar()]: json }).code, 0)
  eq("and read back", run(Model.accountRegistryReadCommand()).out, json)
  const regFile = path.join(dataHome, "qs-bitwarden-cli", "accounts", "registry.json")
  eq("readable only by the user", (fs.statSync(regFile).mode & 0o777).toString(8), "600")

  // Removing a slot signs it out and deletes its directory; never bw's own.
  fs.writeFileSync(bwLog, "")
  eq("removing B succeeds", run(Model.accountSlotRemoveCommand(SLOT_B)).code, 0)
  check("B's directory is gone", !fs.existsSync(slotDir), slotDir)
  check("after bw logout ran in it", fs.readFileSync(bwLog, "utf8").includes(slotDir + " logout"), fs.readFileSync(bwLog, "utf8"))
  const own = path.join(dir, "own")
  fs.mkdirSync(own)
  fs.writeFileSync(bwLog, "")
  run(Model.accountSlotRemoveCommand("default"))
  check("the default slot is signed out in bw's own directory", fs.readFileSync(bwLog, "utf8").trim() === "<own> logout", "")
  check("and nothing of it is deleted", fs.existsSync(own) && fs.existsSync(regFile), "")

  // Retiring a slot (replaced by a new sign-in) also clears its keyring.
  run(Model.unlockEnvelopeCreateCommand(tool, B), { [SECRET]: PW_B })
  eq("retiring B succeeds", run(Model.accountSlotRetireCommand(SLOT_B)).code, 0)
  eq("its envelope went with it, A's did not", entries().join(","), "session,unlock_envelope")
} finally {
  fs.rmSync(dir, { recursive: true, force: true })
}

// -------------------------------------------------------------------------
// The vault: one account active, the others left alone
// -------------------------------------------------------------------------

const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)

check("every bw process runs in the active account's directory",
  /var env = accountAppDataEnv\(\)/.test(body("bwEnv")) && /var env = accountAppDataEnv\(\)/.test(body("generatorServeEnv")), body("bwEnv"))
check("a slot without a home is pointed nowhere rather than at bw's own directory",
  /accountAppDataDir \|\| "\/dev\/null\//.test(body("accountAppDataEnv")), body("accountAppDataEnv"))
check("no keyring process uses a slot-less command",
  !/Model\.keyring\w+Command\(\)/.test(src) && !/Model\.associations\w+Command\(\)/.test(src),
  (src.match(/Model\.(keyring|associations)\w+Command\(\)/g) || []).join(", "))
check("the FIDO2 legacy entry is the active account's",
  !/Model\.keyring\w+Command\(\)/.test(fs.readFileSync(path.join(repoRoot, "FidoUnlock.qml"), "utf8")), "")
check("the status probe waits for the account list", /if \(!accountsLoaded\)/.test(body("refreshStatus")), body("refreshStatus"))
check("the envelope waits for it too", /!accountsLoaded/.test(body("envelopeReadinessChanged")), body("envelopeReadinessChanged"))
check("an envelope answer for an account no longer active is dropped",
  /job\.slot = activeSlot/.test(body("queueEnvelopeJob")) && /job\.slot === activeSlot/.test(body("onEnvelopeJobExited")), "")

const leave = body("leaveActiveAccount")
check("leaving an account tells the SSH agent it changed", /applySshAgentLifecycle\("account-change"\)/.test(leave), leave)
check("locks it in bw and drops its session from the keyring",
  /lockProc\.running = true/.test(leave) && /requestSessionCredentialClear\(\)/.test(leave), leave)
check("drops the open vault and the envelope state", /dropVaultState\(\)/.test(leave) && /dropEnvelopeState\(\)/.test(leave), leave)
check("but never clears the keyring or signs out",
  !/requestAllCredentialClear|logoutProc|forgetStoredCredentials|removeQuickUnlockMethod/.test(leave), leave)
check("switching leaves the current account first", /leaveActiveAccount\(\)/.test(body("switchAccount")), body("switchAccount"))
check("only to an account the panel knows", /registryHasAccount\(accountRegistry, slot\)/.test(body("switchAccount")), "")
check("adding an account leaves the current one too", /leaveActiveAccount\(\)/.test(body("beginAddAccount")), "")
check("an abandoned add is cleaned up", /retireAccountSlot\(abandoned, true\)/.test(body("switchAccount")), "")

const finish = body("finishLogoutIfReady")
check("logging out moves to the next account", /moveOffRemovedAccount\(activeSlot\)/.test(finish), finish)
check("and removes only the one logged out",
  /registryRemoveAccount\(accountRegistry, removed\)/.test(body("moveOffRemovedAccount")), body("moveOffRemovedAccount"))
check("a sole account's logout still turns the PIN setting off, another's does not",
  (src.match(/if \(pinUnlock && !otherAccountsExist\(\)\) writeSetting\("pinUnlock", false, "bool"\)/g) || []).length === 2
    && !/if \(pinUnlock\) writeSetting\("pinUnlock", false/.test(src), "")
check("bw status records the account in its slot", /noteActiveAccount\(st\)/.test(body("onStatusFinished")), "")
check("a status probe stopped by a switch restarts",
  /restartStaleStatusProbe\(\)/.test(body("onStatusFinished")) && /statusCheckQueued = true/.test(body("runStatusCheck")), "")
// Found driving a real shell: a lock scrubs the status chain's processes, so
// the probe a switch starts right after found them busy and never ran.
check("a probe that finds the lock's scrub in its way runs once the scrub is done",
  ["statusProc", "sessionHandoffProc", "keyringLookupProc"].every(id =>
    new RegExp(`finishScrubRun\\(${id}\\)\\) \\{\\s*root\\.onStatusProbeProcessFreed\\(\\)`).test(src))
    && /isScrubCommand\(sessionHandoffProc\.command\)/.test(body("refreshStatus"))
    && /isScrubCommand\(statusProc\.command\)/.test(body("runStatusCheck")), "")
// Found by tests/e2e: a logout right after a sign-in deferred its sweep behind
// the envelope write, and the writer's exit handler still saw it running.
check("a logout sweep deferred behind a writer is retried until it runs",
  /credentialClearRetry\.restart\(\)/.test(body("requestAllCredentialClear"))
    && /id: credentialClearRetry[\s\S]{0,200}root\.requestAllCredentialClear\(\)/.test(src), body("requestAllCredentialClear"))
// Races between a switch and keyring work still running for the account left.
check("a session clear names the account it is for, and queues behind a running one",
  /var target = Model\.isAccountSlot\(slot\) \? slot : activeSlot/.test(body("requestSessionCredentialClear"))
    && /keyringClearProc\.command = Model\.keyringClearCommand\(target\)/.test(body("requestSessionCredentialClear"))
    && /sessionClearSlots\.concat\(\[target\]\)/.test(body("requestSessionCredentialClear")), body("requestSessionCredentialClear"))
check("a suggestions write owed to the account being left is dropped",
  /associationsWritePending = false/.test(leave), leave)
check("and a write is never re-run with nothing to write",
  /associationsWritePending && root\.pendingAssociationsJson !== ""/.test(src), "")
check("a suggestions read that finds its process busy is asked again",
  /associationsReloadPending = true/.test(body("loadAssociations"))
    && /root\.associationsReloadPending\) root\.loadAssociations\(\)/.test(src), body("loadAssociations"))
check("legacy checks drop an answer for an account no longer active",
  /pinCheckSlot !== activeSlot/.test(body("onPinConfiguredChecked"))
    && /masterCheckSlot !== activeSlot/.test(body("onFingerprintStoredChecked"))
    && /hasSlot !== vault\.activeSlot/.test(fs.readFileSync(path.join(repoRoot, "FidoUnlock.qml"), "utf8")), "")
check("the probes of the account being left are stopped before the lock borrows them",
  leave.indexOf("statusRefreshPending = true") !== -1 && leave.indexOf("statusRefreshPending = true") < leave.indexOf("dropVaultState()"), leave)

const panel = fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8")
check("the panel has an account list", /activeScreen === "accounts"/.test(panel) && /root\.vault\.switchAccount\(modelData\.slot\)/.test(panel), "")
check("the lock screen offers switching and logging out separately",
  /root\.vault\.openAccounts\(\) : root\.vault\.beginAddAccount\(\)/.test(panel) && /text: "Log Out"/.test(panel), "")
check("an add can be cancelled from the login screen", /root\.vault\.cancelAddAccount\(\)/.test(panel), "")
check("the IPC can list and switch accounts",
  /function accounts\(\): string/.test(src) && /function switchAccount\(email: string\): string/.test(src), "")

done()
