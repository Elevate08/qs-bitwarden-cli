#!/usr/bin/env node
// The quick-unlock envelope's keyring commands, run for real: the actual
// shell pipelines, the real `argon2`, `jq` and qs-bitwarden-unlock-key, and a
// file-backed `secret-tool` so nothing touches this machine's keyring.
//
// `systemd-creds` is a stand-in by default -- CI's runner predates `--user` --
// and the whole suite runs a second time against the real one wherever
// `systemd-creds --user` works.
//
// Every tool the pipelines start logs its argv, and the suite ends by checking
// that no password, PIN, hmac-secret or derived key ever appeared there:
// /proc/<pid>/cmdline is readable by every local user.
//
// Needs: argon2, jq, and unlock-key/target/debug/qs-bitwarden-unlock-key
// (`cargo build` in unlock-key/).
//
//   node tests/unlock-envelope.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const Model = {}
new Function("exports", fs.readFileSync(path.join(repoRoot, "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.inspect = unlockEnvelopeInspectCommand
  exports.open = unlockEnvelopeOpenCommand
  exports.create = unlockEnvelopeCreateCommand
  exports.update = unlockEnvelopeUpdateCommand
  exports.clear = unlockEnvelopeClearCommand
  exports.has = unlockEnvelopeHasCommand
  exports.exits = envelopeExitCodes
  exports.secretEnv = keyringSecretEnvVar
  exports.pinEnv = pinEnvVar
  exports.newSecretEnv = envelopeNewSecretEnvVar
  exports.fidoEnv = envelopeFidoHmacEnvVar
  exports.account = keyringEnvelopeAccount
  exports.clearAll = keyringClearAllCommand
  exports.migrate = legacyFingerprintMigrationCommand
  exports.migratePin = legacyPinMigrationCommand
  exports.migrationExits = legacyMigrationExitCodes
  exports.bwVerify = bwVerifyPasswordCommand
  exports.prereqs = quickUnlockPrereqCommand
  exports.parsePrereqs = parseQuickUnlockPrereqs
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

const realTool = path.join(repoRoot, "unlock-key", "target", "debug", "qs-bitwarden-unlock-key")
const which = name => spawnSync("bash", ["-c", `command -v ${name}`], { encoding: "utf8" }).stdout.trim()
const argon2 = which("argon2")
const missing = [["argon2", argon2], ["jq", which("jq")], ["the unlock tool", fs.existsSync(realTool) ? realTool : ""]]
  .filter(([, found]) => !found).map(([name]) => name)
if (missing.length) {
  console.error(`unlock-envelope: cannot run without ${missing.join(", ")}`)
  process.exit(1)
}

// -------------------------------------------------------------------------
// Fixtures
// -------------------------------------------------------------------------

const E = Model.exits()
const SECRET = Model.secretEnv()
const PIN = Model.pinEnv()
const NEW_SECRET = Model.newSecretEnv()
const HMAC = Model.fidoEnv()
const ACCOUNT = { id: "user-1234", server: "https://vault.bitwarden.com" }

// Awkward on purpose: quotes, a dollar, a backslash and a trailing newline
// all have to survive the shell and come back byte for byte.
const PASSWORD = "correct 'horse' \"battery\" $staple \\ \n"
const NEW_PASSWORD = "a new master password"
const PIN_VALUE = "482913"
const HMAC_VALUE = Buffer.alloc(32, 7).toString("base64")
const CRED = Buffer.from("credential-id-from-pam-u2f").toString("base64")
const FIDO_SALT = Buffer.alloc(32, 9).toString("base64")

function fakeBin(dir, realCreds) {
  const bin = path.join(dir, "bin")
  fs.mkdirSync(bin)
  const log = `printf '%s\\0' "$(basename "$0")" "$@" >> "$ARGV_LOG"; printf '\\n' >> "$ARGV_LOG"`
  const write = (name, body) => fs.writeFileSync(path.join(bin, name), `#!/bin/bash\n${log}\n${body}\n`, { mode: 0o755 })

  // A keyring that is a directory: one file per `account` attribute.
  write("secret-tool", `
cmd="$1"; shift
account=""; while [ $# -gt 0 ]; do case "$1" in account) account="$2"; shift 2;; *) shift;; esac; done
f="$STORE_DIR/$account"
case "$cmd" in
  lookup) [ -f "$f" ] || exit 1; cat "$f"; echo ;;
  store) [ -z "\${FAIL_STORE:-}" ] || exit 1; cat > "$f.tmp" && mv "$f.tmp" "$f" ;;
  clear) rm -f "$f" ;;
  search) [ -f "$f" ] && cat "$f"; exit 0 ;;
  *) exit 2 ;;
esac`)

  write("argon2", `exec ${JSON.stringify(argon2)} "$@"`)
  // Every other external command the pipelines run is logged too, so a secret
  // handed to `env`, `jq` or `cmp` is caught as surely as one handed to the
  // tools above. Builtins (printf, read, [) create no process and no argv.
  for (const name of ["env", "jq", "cmp", "head", "base64", "cat", "tr", "od", "mv", "rm"]) {
    const real = which(name)
    if (real) write(name, `exec ${JSON.stringify(real)} "$@"`)
  }
  write("unlock-tool", `exec ${JSON.stringify(realTool)} "$@"`)

  if (realCreds) {
    write("systemd-creds", `exec /usr/bin/systemd-creds "$@"`)
  } else {
    // Reversible, name-bound, and able to corrupt its output on request.
    write("systemd-creds", `
mode=""; name=""
for a in "$@"; do case "$a" in encrypt|decrypt) mode="$a";; --name=*) name="\${a#--name=}";; esac; done
if [ "$mode" = encrypt ]; then
  { printf 'SEALED:%s:' "$name"; base64 -w0; } | base64 -w0
  [ -z "\${CORRUPT_SEAL:-}" ] || printf 'garbage'
else
  input="$(cat | base64 -d 2>/dev/null)" || exit 1
  case "$input" in "SEALED:$name:"*) printf '%s' "\${input#SEALED:$name:}" | base64 -d ;; *) exit 1 ;; esac
fi`)
  }
  return bin
}

function suite(realCreds) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-envelope-"))
  const tag = realCreds ? "[real systemd-creds] " : ""
  try {
    const bin = fakeBin(dir, realCreds)
    const store = path.join(dir, "store")
    fs.mkdirSync(store)
    const argvLog = path.join(dir, "argv.log")
    const tool = path.join(bin, "unlock-tool")
    const stored = () => {
      const f = path.join(store, Model.account())
      return fs.existsSync(f) ? fs.readFileSync(f, "utf8") : null
    }

    const run = (cmd, secrets, extra) => {
      const env = Object.assign({
        PATH: `${bin}:/usr/bin:/bin`,
        HOME: process.env.HOME || dir,
        STORE_DIR: store,
        ARGV_LOG: argvLog
      }, realCreds ? {
        XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || "",
        DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS || ""
      } : {}, secrets || {}, extra || {})
      const r = spawnSync(cmd[0], cmd.slice(1), { env, encoding: "buffer", timeout: 120000 })
      return { code: r.status, out: r.stdout.toString("utf8"), err: r.stderr.toString("utf8") }
    }
    const summary = () => {
      const r = run(Model.inspect(tool))
      return r.code === 0 ? JSON.parse(r.out) : { code: r.code }
    }
    const open = (via, secrets) => run(Model.open(tool, ACCOUNT, via), secrets)

    // --- nothing stored yet ---
    eq(tag + "no envelope: inspect says absent", run(Model.inspect(tool)).code, E.absent)
    eq(tag + "no envelope: opening says absent",
      open({ kind: "master" }, { [SECRET]: PASSWORD }).code, E.absent)

    // --- the first accepted password ---
    const created = run(Model.create(tool, ACCOUNT), { [SECRET]: PASSWORD })
    eq(tag + "a first password is stored", created.code, 0)
    check(tag + "the keyring holds no readable password",
      stored() !== null && !stored().includes("horse") && !stored().includes("staple"),
      String(stored()).slice(0, 80))
    let s = summary()
    eq(tag + "the summary names the account", s.account && s.account.id, ACCOUNT.id)
    check(tag + "only the master wrap exists", s.master && !s.pin && s.fingerprint === false
      && Array.isArray(s.fido) && s.fido.length === 0, JSON.stringify(s))
    eq(tag + "new wraps use 256 MiB", s.master && s.master.m, 262144)

    // --- the master password as a check ---
    const opened = open({ kind: "master" }, { [SECRET]: PASSWORD })
    eq(tag + "the right password opens it", opened.code, 0)
    eq(tag + "and yields the password byte for byte", opened.out, PASSWORD)
    eq(tag + "a wrong password is refused as a wrong key",
      open({ kind: "master" }, { [SECRET]: "not it" }).code, 3)
    eq(tag + "another account is refused",
      run(Model.open(tool, { id: "user-9999", server: ACCOUNT.server }, { kind: "master" }),
        { [SECRET]: PASSWORD }).code, 6)

    // --- adding methods needs the master password, and stores nothing typed ---
    let before = stored()
    eq(tag + "a wrong master password cannot add a PIN",
      run(Model.update(tool, ACCOUNT, { kind: "add-pin" }), { [SECRET]: "wrong", [PIN]: PIN_VALUE }).code, 3)
    eq(tag + "and nothing was written", stored(), before)

    eq(tag + "the right one adds a PIN",
      run(Model.update(tool, ACCOUNT, { kind: "add-pin" }), { [SECRET]: PASSWORD, [PIN]: PIN_VALUE }).code, 0)
    eq(tag + "the PIN opens it", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, PASSWORD)
    eq(tag + "a wrong PIN is a wrong key", open({ kind: "pin" }, { [PIN]: "000000" }).code, 3)

    eq(tag + "fingerprint is added",
      run(Model.update(tool, ACCOUNT, { kind: "add-fingerprint" }), { [SECRET]: PASSWORD }).code, 0)
    eq(tag + "fingerprint opens it", open({ kind: "fingerprint" }).out, PASSWORD)

    eq(tag + "a FIDO2 credential is added",
      run(Model.update(tool, ACCOUNT, { kind: "add-fido", cred: CRED, rp: "pam://host", salt: FIDO_SALT }),
        { [SECRET]: PASSWORD, [HMAC]: HMAC_VALUE }).code, 0)
    eq(tag + "its hmac-secret opens it", open({ kind: "fido", cred: CRED }, { [HMAC]: HMAC_VALUE }).out, PASSWORD)
    eq(tag + "another hmac-secret is a wrong key",
      open({ kind: "fido", cred: CRED }, { [HMAC]: Buffer.alloc(32, 1).toString("base64") }).code, 3)
    s = summary()
    check(tag + "the summary carries what fido2-assert needs",
      s.fido && s.fido[0] && s.fido[0].cred === CRED && s.fido[0].salt === FIDO_SALT && s.fido[0].rp === "pam://host",
      JSON.stringify(s.fido))

    // --- failed writes leave the old envelope ---
    before = stored()
    eq(tag + "a keyring that refuses the store is reported",
      run(Model.update(tool, ACCOUNT, { kind: "mark-stale" }), {}, { FAIL_STORE: "1" }).code, E.store)
    eq(tag + "and the old envelope is still there", stored(), before)
    if (!realCreds) {
      eq(tag + "a new envelope that does not re-open is never stored",
        run(Model.update(tool, ACCOUNT, { kind: "mark-stale" }), {}, { CORRUPT_SEAL: "1" }).code, E.verify)
      eq(tag + "and the old envelope is still there", stored(), before)
    }

    // --- a password changed elsewhere ---
    eq(tag + "marking stale", run(Model.update(tool, ACCOUNT, { kind: "mark-stale" })).code, 0)
    eq(tag + "is recorded", summary().stale, true)
    eq(tag + "a PIN unlock rotates to the new password",
      run(Model.update(tool, ACCOUNT, { kind: "rotate", auth: { kind: "pin" } }),
        { [PIN]: PIN_VALUE, [NEW_SECRET]: NEW_PASSWORD }).code, 0)
    eq(tag + "the new password opens the master wrap",
      open({ kind: "master" }, { [SECRET]: NEW_PASSWORD }).out, NEW_PASSWORD)
    eq(tag + "the old one no longer does", open({ kind: "master" }, { [SECRET]: PASSWORD }).code, 3)
    eq(tag + "the PIN still works, now for the new password", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, NEW_PASSWORD)
    eq(tag + "so does the key", open({ kind: "fido", cred: CRED }, { [HMAC]: HMAC_VALUE }).out, NEW_PASSWORD)
    eq(tag + "and the stale mark is gone", summary().stale, false)
    eq(tag + "rotating through fingerprint needs no secret",
      run(Model.update(tool, ACCOUNT, { kind: "rotate", auth: { kind: "fingerprint" } }),
        { [NEW_SECRET]: PASSWORD }).code, 0)
    eq(tag + "and lands the password given", open({ kind: "fingerprint" }).out, PASSWORD)

    // --- disabling ---
    for (const op of [{ kind: "remove", method: "pin" }, { kind: "remove", method: "fingerprint" },
      { kind: "remove", method: "fido", cred: CRED }]) {
      eq(tag + `removing ${op.method} needs no secret`, run(Model.update(tool, ACCOUNT, op)).code, 0)
    }
    eq(tag + "a removed PIN is missing, not wrong", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).code, 7)
    s = summary()
    check(tag + "only the master wrap is left", s.master && !s.pin && !s.fingerprint && s.fido.length === 0,
      JSON.stringify(s))
    eq(tag + "and it still opens", open({ kind: "master" }, { [SECRET]: PASSWORD }).out, PASSWORD)

    // --- migrating fingerprint unlock's plaintext entry ---
    const legacy = path.join(store, "master_password")
    const M = Model.migrationExits()
    eq(tag + "no legacy entry: nothing to migrate", run(Model.migrate(tool, ACCOUNT)).code, M.none)

    // An envelope whose password is not the legacy one: one of them is stale,
    // so neither is touched.
    fs.writeFileSync(legacy, "an older password")
    before = stored()
    eq(tag + "a legacy password the envelope refuses is left alone",
      run(Model.migrate(tool, ACCOUNT)).code, M.mismatch)
    check(tag + "both entries are still there", fs.existsSync(legacy) && stored() === before, "")

    // The ordinary case: the legacy password is the envelope's.
    fs.writeFileSync(legacy, PASSWORD.replace(/\n+$/, ""))
    run(Model.clear())
    const migrated = run(Model.migrate(tool, ACCOUNT))
    eq(tag + "a legacy entry with no envelope migrates", migrated.code, 0)
    eq(tag + "the plaintext entry is gone", fs.existsSync(legacy), false)
    eq(tag + "the envelope now opens through fingerprint",
      open({ kind: "fingerprint" }).out, PASSWORD.replace(/\n+$/, ""))
    check(tag + "and holds no readable password", !stored().includes("horse"), "")

    // --- migrating a PIN blob, at the PIN unlock that decrypted it ---
    const blob = path.join(store, "pin_blob")
    const plain = PASSWORD.replace(/\n+$/, "")
    fs.writeFileSync(blob, "legacy-ciphertext")
    eq(tag + "no password in hand: nothing to migrate",
      run(Model.migratePin(tool, ACCOUNT), { [PIN]: PIN_VALUE }).code, M.none)
    before = stored()
    eq(tag + "a password the envelope refuses leaves the blob alone",
      run(Model.migratePin(tool, ACCOUNT), { [SECRET]: "an older password", [PIN]: PIN_VALUE }).code, M.mismatch)
    check(tag + "both are still there", fs.existsSync(blob) && stored() === before, "")
    eq(tag + "the password bw accepted migrates the blob",
      run(Model.migratePin(tool, ACCOUNT), { [SECRET]: plain, [PIN]: PIN_VALUE }).code, 0)
    eq(tag + "the blob is gone", fs.existsSync(blob), false)
    eq(tag + "the same PIN now opens the envelope", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, plain)
    eq(tag + "and fingerprint still does", open({ kind: "fingerprint" }).out, plain)

    // --- presence, and clearing ---
    eq(tag + "presence is reported without the secret", run(Model.has()).out.trim(), "yes")
    run(Model.clear())
    eq(tag + "clearing removes it", stored(), null)
    eq(tag + "and presence says so", run(Model.has()).out.trim(), "no")

    // --- nothing secret in any argv ---
    const argv = fs.readFileSync(argvLog, "utf8")
    const secrets = { "the password": "horse", "the new password": NEW_PASSWORD, "the PIN": PIN_VALUE,
      "the hmac-secret": HMAC_VALUE }
    for (const [what, value] of Object.entries(secrets)) {
      check(tag + `${what} never appeared in an argv`, !argv.includes(value), "found in the argv log")
    }
    check(tag + "no derived key appeared in an argv either",
      !/[0-9a-f]{64}/.test(argv), (argv.match(/[0-9a-f]{64}/) || [""])[0])
    check(tag + "the argv log actually recorded the tools",
      ["secret-tool", "argon2", "unlock-tool", "systemd-creds", "jq", "cmp", "head"]
        .every(name => argv.includes(name + "\0")),
      argv.slice(0, 120))
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

suite(false)

const realCreds = spawnSync("bash", ["-c", "printf x | systemd-creds --user encrypt --name=qsbw-probe - - >/dev/null 2>&1"])
if (realCreds.status === 0) {
  suite(true)
} else {
  console.log("unlock-envelope: systemd-creds --user unavailable here; the real-seal pass was skipped")
}

// -------------------------------------------------------------------------
// The prerequisite probe, and bw's check of a typed password
// -------------------------------------------------------------------------

{
  const probe = Model.prereqs()
  const r = spawnSync(probe[0], probe.slice(1), { encoding: "utf8" })
  const parsed = Model.parsePrereqs(r.stdout)
  eq("argon2 is found here", parsed.argon2, true)
  eq("the probe agrees with the real-seal pass about systemd-creds", parsed.creds, realCreds.status === 0)
  check("a missing systemd-creds is explained",
    /systemd-creds --user/.test(Model.parsePrereqs("argon2=1\ncreds=0\n").message), "")
  check("a missing argon2 is explained",
    /argon2/.test(Model.parsePrereqs("argon2=0\ncreds=1\n").message), "")
  eq("both present is ready", Model.parsePrereqs("argon2=1\ncreds=1\n").ready, true)
}
check("bw checks a typed password from the environment, never argv",
  /bw unlock --passwordenv QSBW_SECRET --raw/.test(Model.bwVerify()[2]), Model.bwVerify()[2])

// -------------------------------------------------------------------------
// Builders refuse what should never reach them
// -------------------------------------------------------------------------

const refused = cmd => cmd.length === 3 && cmd[2] === "exit 2"
check("a relative tool path is refused", refused(Model.inspect("unlock-tool")), JSON.stringify(Model.inspect("x")))
check("a missing account is refused", refused(Model.create("/t", null)), "")
check("an empty account id is refused", refused(Model.create("/t", { id: "", server: "s" })), "")
check("a control character in the server is refused", refused(Model.create("/t", { id: "a", server: "s\n" })), "")
check("a FIDO2 credential that is not base64 is refused",
  refused(Model.open("/t", ACCOUNT, { kind: "fido", cred: "a'b" })), "")
check("an unknown method is refused", refused(Model.open("/t", ACCOUNT, { kind: "face" })), "")
check("removing the master wrap is not an operation",
  refused(Model.update("/t", ACCOUNT, { kind: "remove", method: "master" })), "")
check("logout clears the envelope with everything else",
  Model.clearAll()[2].includes("'unlock_envelope'"), "keyringClearAllCommand does not name it")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`unlock-envelope: ${pass} passed`)
