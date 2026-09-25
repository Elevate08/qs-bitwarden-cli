#!/usr/bin/env node
// The envelope's keyring commands, run for real: the actual pipelines, real
// `argon2`, `jq` and qs-bitwarden-unlock-key, and a file-backed `secret-tool`.
// `systemd-creds` is a stand-in (CI lacks `--user`), and the suite reruns
// against the real one where it works. Every tool logs its argv, and no
// secret may appear there.
//
// Needs: argon2, jq, and unlock-key/target/debug/qs-bitwarden-unlock-key.
//
//   node tests/unlock-envelope.test.js

const { createSuite, loadModule, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const Model = loadModule()

const { check, eq, done } = createSuite("unlock-envelope")

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

const E = Model.envelopeExitCodes()
const SECRET = Model.keyringSecretEnvVar()
const PIN = Model.pinEnvVar()
const NEW_SECRET = Model.envelopeNewSecretEnvVar()
const HMAC = Model.FIDO_HMAC_ENV
const ACCOUNT = { id: "user-1234", server: "https://vault.bitwarden.com" }

// Awkward on purpose: quotes, a dollar, a backslash and a trailing newline
// all have to survive the shell and come back byte for byte.
const PASSWORD = "correct 'horse' \"battery\" $staple \\ \n"
const NEW_PASSWORD = "a new master password"
const PIN_VALUE = "482913"
const HMAC_VALUE = Buffer.alloc(32, 7).toString("base64")
const CRED = Buffer.from("credential-id-from-pam-u2f").toString("base64")
const FIDO_SALT = Buffer.alloc(32, 9).toString("base64")
// Credentials as the pam-u2f authfile records them, on a stand-in key.
const FIDO_CRED_A = Buffer.alloc(64, 0xa1).toString("base64")
const FIDO_CRED_B = Buffer.alloc(64, 0xb2).toString("base64")
const FIDO_CRED_ELSEWHERE = Buffer.alloc(64, 0xc3).toString("base64")

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

  // Holds FAKE_FIDO_CREDS, answers only when touched (not FAKE_FIDO_FAIL), and
  // derives a deterministic hmac-secret per credential and salt; logs each.
  write("fido2-assert", `
hmac=0; for a in "$@"; do [ "$a" = -h ] && hmac=1; done
[ -z "\${FAKE_FIDO_FAIL:-}" ] || exit 1
IFS= read -r cdh; IFS= read -r rp; IFS= read -r cred; salt=""; [ $hmac = 1 ] && IFS= read -r salt
case ",$FAKE_FIDO_CREDS," in *",$cred,"*) ;; *) exit 1 ;; esac
printf '%s\n%s\nauthdata\nsignature\n' "$cdh" "$rp"
if [ $hmac = 1 ]; then
  secret="$(printf '%s|%s|%s' fake-device-key "$cred" "$salt" | openssl dgst -sha256 -binary | base64 -w0)"
  printf '%s\n' "$secret" >> "$HMAC_LOG"
  printf '%s\n' "$secret"
fi`)

  if (realCreds) {
    write("systemd-creds", `exec /usr/bin/systemd-creds "$@"`)
  } else {
    // Reversible, name-bound, and able to corrupt its output on request.
    write("systemd-creds", `
mode=""; name=""
for a in "$@"; do case "$a" in encrypt|decrypt) mode="$a";; --name=*) name="\${a#--name=}";; esac; done
if [ "$mode" = encrypt ]; then
  [ -z "\${FAIL_SEAL:-}" ] || { printf 'partial'; exit 1; }
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
    const hmacLog = path.join(dir, "hmac.log")
    const tool = path.join(bin, "unlock-tool")
    const stored = () => {
      const f = path.join(store, Model.KEYRING_ENVELOPE)
      return fs.existsSync(f) ? fs.readFileSync(f, "utf8") : null
    }

    const run = (cmd, secrets, extra) => {
      const env = Object.assign({
        PATH: `${bin}:/usr/bin:/bin`,
        HOME: process.env.HOME || dir,
        STORE_DIR: store,
        ARGV_LOG: argvLog,
        HMAC_LOG: hmacLog,
        FAKE_FIDO_CREDS: [FIDO_CRED_A, FIDO_CRED_B].join(",")
      }, realCreds ? {
        XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR || "",
        DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS || ""
      } : {}, secrets || {}, extra || {})
      const r = spawnSync(cmd[0], cmd.slice(1), { env, encoding: "buffer", timeout: 120000 })
      return { code: r.status, out: r.stdout.toString("utf8"), err: r.stderr.toString("utf8") }
    }
    const summary = () => {
      const r = run(Model.unlockEnvelopeInspectCommand(tool))
      return r.code === 0 ? JSON.parse(r.out) : { code: r.code }
    }
    const open = (via, secrets) => run(Model.unlockEnvelopeOpenCommand(tool, ACCOUNT, via), secrets)

    // --- nothing stored yet ---
    eq(tag + "no envelope: inspect says absent", run(Model.unlockEnvelopeInspectCommand(tool)).code, E.absent)
    eq(tag + "no envelope: opening says absent",
      open({ kind: "master" }, { [SECRET]: PASSWORD }).code, E.absent)

    // --- the first accepted password ---
    const created = run(Model.unlockEnvelopeCreateCommand(tool, ACCOUNT), { [SECRET]: PASSWORD })
    eq(tag + "a first password is stored", created.code, 0)
    check(tag + "the keyring holds no readable password",
      stored() !== null && !stored().includes("horse") && !stored().includes("staple"),
      String(stored()).slice(0, 80))
    // gnome-keyring writes a secret verbatim into a passwordless keyring's
    // text file, and a line break there makes the whole file unreadable.
    check(tag + "the keyring holds the sealed envelope on one line",
      stored() !== null && !/[\r\n]/.test(stored()), "the stored secret has a line break")
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
      run(Model.unlockEnvelopeOpenCommand(tool, { id: "user-9999", server: ACCOUNT.server }, { kind: "master" }),
        { [SECRET]: PASSWORD }).code, 6)

    // --- adding methods needs the master password, and stores nothing typed ---
    let before = stored()
    eq(tag + "a wrong master password cannot add a PIN",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "add-pin" }), { [SECRET]: "wrong", [PIN]: PIN_VALUE }).code, 3)
    eq(tag + "and nothing was written", stored(), before)

    eq(tag + "the right one adds a PIN",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "add-pin" }), { [SECRET]: PASSWORD, [PIN]: PIN_VALUE }).code, 0)
    eq(tag + "the PIN opens it", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, PASSWORD)
    eq(tag + "a wrong PIN is a wrong key", open({ kind: "pin" }, { [PIN]: "000000" }).code, 3)
    check(tag + "adding a method rewrites it on one line",
      !/[\r\n]/.test(stored()), "the stored secret has a line break")

    eq(tag + "fingerprint is added",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "add-fingerprint" }), { [SECRET]: PASSWORD }).code, 0)
    eq(tag + "fingerprint opens it", open({ kind: "fingerprint" }).out, PASSWORD)

    eq(tag + "a FIDO2 credential is added",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "add-fido", cred: CRED, rp: "pam://host", salt: FIDO_SALT }),
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
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "mark-stale" }), {}, { FAIL_STORE: "1" }).code, E.store)
    eq(tag + "and the old envelope is still there", stored(), before)
    if (!realCreds) {
      eq(tag + "a new envelope that does not re-open is never stored",
        run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "mark-stale" }), {}, { CORRUPT_SEAL: "1" }).code, E.verify)
      eq(tag + "and the old envelope is still there", stored(), before)
      eq(tag + "a seal that fails is reported as its own exit, not the join's",
        run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "mark-stale" }), {}, { FAIL_SEAL: "1" }).code, 1)
      eq(tag + "and the old envelope is still there", stored(), before)
    }

    // --- a password changed elsewhere ---
    eq(tag + "marking stale", run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "mark-stale" })).code, 0)
    eq(tag + "is recorded", summary().stale, true)
    eq(tag + "a PIN unlock rotates to the new password",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "rotate", auth: { kind: "pin" } }),
        { [PIN]: PIN_VALUE, [NEW_SECRET]: NEW_PASSWORD }).code, 0)
    eq(tag + "the new password opens the master wrap",
      open({ kind: "master" }, { [SECRET]: NEW_PASSWORD }).out, NEW_PASSWORD)
    eq(tag + "the old one no longer does", open({ kind: "master" }, { [SECRET]: PASSWORD }).code, 3)
    eq(tag + "the PIN still works, now for the new password", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, NEW_PASSWORD)
    eq(tag + "so does the key", open({ kind: "fido", cred: CRED }, { [HMAC]: HMAC_VALUE }).out, NEW_PASSWORD)
    eq(tag + "and the stale mark is gone", summary().stale, false)
    check(tag + "rotating rewrites it on one line",
      !/[\r\n]/.test(stored()), "the stored secret has a line break")
    eq(tag + "rotating through fingerprint needs no secret",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "rotate", auth: { kind: "fingerprint" } }),
        { [NEW_SECRET]: PASSWORD }).code, 0)
    eq(tag + "and lands the password given", open({ kind: "fingerprint" }).out, PASSWORD)

    // --- disabling ---
    for (const op of [{ kind: "remove", method: "pin" }, { kind: "remove", method: "fingerprint" },
      { kind: "remove", method: "fido", cred: CRED }]) {
      eq(tag + `removing ${op.method} needs no secret`, run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, op)).code, 0)
    }
    eq(tag + "a removed PIN is missing, not wrong", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).code, 7)
    s = summary()
    check(tag + "only the master wrap is left", s.master && !s.pin && !s.fingerprint && s.fido.length === 0,
      JSON.stringify(s))
    eq(tag + "and it still opens", open({ kind: "master" }, { [SECRET]: PASSWORD }).out, PASSWORD)

    // --- migrating fingerprint unlock's plaintext entry ---
    const legacy = path.join(store, "master_password")
    const M = Model.legacyMigrationExitCodes()
    eq(tag + "no legacy entry: nothing to migrate", run(Model.legacyFingerprintMigrationCommand(tool, ACCOUNT)).code, M.none)

    // An envelope whose password is not the legacy one: one of them is stale,
    // so neither is touched.
    fs.writeFileSync(legacy, "an older password")
    before = stored()
    eq(tag + "a legacy password the envelope refuses is left alone",
      run(Model.legacyFingerprintMigrationCommand(tool, ACCOUNT)).code, M.mismatch)
    check(tag + "both entries are still there", fs.existsSync(legacy) && stored() === before, "")

    // The ordinary case: the legacy password is the envelope's.
    fs.writeFileSync(legacy, PASSWORD.replace(/\n+$/, ""))
    run(Model.keyringClearEntryCommand(Model.KEYRING_ENVELOPE))
    const migrated = run(Model.legacyFingerprintMigrationCommand(tool, ACCOUNT))
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
      run(Model.legacyPinMigrationCommand(tool, ACCOUNT), { [PIN]: PIN_VALUE }).code, M.none)
    before = stored()
    eq(tag + "a password the envelope refuses leaves the blob alone",
      run(Model.legacyPinMigrationCommand(tool, ACCOUNT), { [SECRET]: "an older password", [PIN]: PIN_VALUE }).code, M.mismatch)
    check(tag + "both are still there", fs.existsSync(blob) && stored() === before, "")
    eq(tag + "the password bw accepted migrates the blob",
      run(Model.legacyPinMigrationCommand(tool, ACCOUNT), { [SECRET]: plain, [PIN]: PIN_VALUE }).code, 0)
    eq(tag + "the blob is gone", fs.existsSync(blob), false)
    eq(tag + "the same PIN now opens the envelope", open({ kind: "pin" }, { [PIN]: PIN_VALUE }).out, plain)
    eq(tag + "and fingerprint still does", open({ kind: "fingerprint" }).out, plain)

    // --- FIDO2 through hmac-secret ---
    const F = Model.fidoExitCodes()
    const onKey = (cred) => ({ device: "/dev/hidraw9", cred, rp: "pam://tuxframe" })
    const wrapOf = (cred) => (summary().fido || []).find(w => w.cred === cred)
    eq(tag + "enrolling needs the right master password (the touch comes first)",
      run(Model.fidoEnrollCommand(tool, ACCOUNT, onKey(FIDO_CRED_A)), { [SECRET]: "wrong" }).code, 3)
    eq(tag + "no touch, no wrap", run(Model.fidoEnrollCommand(tool, ACCOUNT, onKey(FIDO_CRED_A)),
      { [SECRET]: plain }, { FAKE_FIDO_FAIL: "1" }).code, F.assert)
    eq(tag + "a credential on no plugged-in key cannot enroll",
      run(Model.fidoEnrollCommand(tool, ACCOUNT, onKey(FIDO_CRED_ELSEWHERE)), { [SECRET]: plain }).code, F.assert)
    eq(tag + "one touch and the password enroll a key",
      run(Model.fidoEnrollCommand(tool, ACCOUNT, onKey(FIDO_CRED_A)), { [SECRET]: plain }).code, 0)
    const wrapA = wrapOf(FIDO_CRED_A)
    check(tag + "its wrap records the relying party and a fresh 32-byte salt",
      wrapA && wrapA.rp === "pam://tuxframe" && Buffer.from(wrapA.salt, "base64").length === 32,
      JSON.stringify(wrapA))
    const unlockA = run(Model.fidoUnlockCommand(tool, ACCOUNT, Object.assign(onKey(FIDO_CRED_A), { salt: wrapA.salt })))
    eq(tag + "one touch unlocks through it", unlockA.code, 0)
    eq(tag + "and the password is the only output", unlockA.out, plain)
    eq(tag + "no touch, no password",
      run(Model.fidoUnlockCommand(tool, ACCOUNT, Object.assign(onKey(FIDO_CRED_A), { salt: wrapA.salt })),
        {}, { FAKE_FIDO_FAIL: "1" }).code, F.assert)
    eq(tag + "another salt yields another secret, which opens nothing",
      run(Model.fidoUnlockCommand(tool, ACCOUNT, Object.assign(onKey(FIDO_CRED_A), { salt: FIDO_SALT }))).code, 3)

    // The first touch after upgrading: no wrap for this credential yet, but
    // the old plaintext entry is there. The same touch migrates it.
    const legacyFido = path.join(store, "fido_password")
    fs.writeFileSync(legacyFido, plain)
    const migratedFido = run(Model.fidoLegacyUnlockCommand(tool, ACCOUNT, onKey(FIDO_CRED_B)))
    eq(tag + "the legacy entry unlocks and migrates in one touch", migratedFido.code, 0)
    eq(tag + "yielding the password", migratedFido.out, plain)
    eq(tag + "the plaintext entry is gone", fs.existsSync(legacyFido), false)
    const wrapB = wrapOf(FIDO_CRED_B)
    eq(tag + "the key now has its own wrap",
      run(Model.fidoUnlockCommand(tool, ACCOUNT, Object.assign(onKey(FIDO_CRED_B), { salt: wrapB && wrapB.salt }))).out, plain)
    // A legacy password the envelope refuses: it still unlocks (bw decides),
    // exit 40 says the migration did not happen, and the entry stays.
    fs.writeFileSync(legacyFido, "an older password")
    before = stored()
    const stale = run(Model.fidoLegacyUnlockCommand(tool, ACCOUNT, onKey(FIDO_CRED_A)))
    eq(tag + "a legacy password the envelope refuses still comes back", stale.code, F.legacyUsed)
    eq(tag + "as itself", stale.out, "an older password")
    check(tag + "and nothing was written or removed", fs.existsSync(legacyFido) && stored() === before, "")
    fs.rmSync(legacyFido)
    eq(tag + "removing one key's wrap leaves the other working",
      run(Model.unlockEnvelopeUpdateCommand(tool, ACCOUNT, { kind: "remove", method: "fido", cred: FIDO_CRED_A })).code, 0)
    eq(tag + "B still unlocks",
      run(Model.fidoUnlockCommand(tool, ACCOUNT, Object.assign(onKey(FIDO_CRED_B), { salt: wrapB.salt }))).out, plain)
    const handedOut = fs.existsSync(hmacLog) ? fs.readFileSync(hmacLog, "utf8").trim().split("\n") : []
    check(tag + "the stand-in key handed out secrets", handedOut.length >= 5, String(handedOut.length))

    // --- an envelope stored across several lines, before __seal() joined them ---
    {
      const SLOT = "0123456789abcdef"
      const slotFile = path.join(store, Model.keyringEntryName(Model.KEYRING_ENVELOPE, SLOT))
      const good = stored()
      const before = open({ kind: "fingerprint" }).out
      const wrapped = good.match(/.{1,79}/g).join("\n")
      fs.writeFileSync(path.join(store, Model.KEYRING_ENVELOPE), wrapped)
      // Split, but not an envelope: it must be left as it is.
      const junk = Buffer.alloc(200, 5).toString("base64").match(/.{1,79}/g).join("\n")
      fs.writeFileSync(slotFile, junk)
      // No keyring file here: the file step skips, and never reaches the real one.
      const noFiles = { XDG_DATA_HOME: path.join(dir, "data") }
      const repair = () => run(Model.keyringRepairCommand(repoRoot, [SLOT]), {}, noFiles)
      let r = repair()
      const parsed = Model.parseKeyringRepair(r.out)
      eq(tag + "the startup repair runs", r.code, 0)
      eq(tag + "it stores a split envelope again", parsed.rejoined, 1)
      eq(tag + "on one line, the same sealed bytes", stored(), good)
      check(tag + "and it opens to the same password", before !== "" && open({ kind: "fingerprint" }).out === before, "")
      check(tag + "a split secret that does not decrypt is reported",
        parsed.rejoinFailed.length === 1 && parsed.rejoinFailed[0] === "unlock_envelope@" + SLOT, JSON.stringify(parsed))
      eq(tag + "and left as it was", fs.readFileSync(slotFile, "utf8"), junk)
      eq(tag + "a missing keyring file is skipped", parsed.file, "skipped")
      check(tag + "and nothing secret is printed", !r.out.includes(good.slice(0, 40)), "")
      fs.rmSync(slotFile)
      r = repair()
      check(tag + "a second start has nothing to do",
        r.code === 0 && Model.parseKeyringRepair(r.out).rejoined === 0 && stored() === good, r.out)
    }

    // --- presence, and clearing ---
    eq(tag + "presence is reported without the secret", run(Model.keyringHasEntryCommand(Model.KEYRING_ENVELOPE)).out.trim(), "yes")
    run(Model.keyringClearEntryCommand(Model.KEYRING_ENVELOPE))
    eq(tag + "clearing removes it", stored(), null)
    eq(tag + "and presence says so", run(Model.keyringHasEntryCommand(Model.KEYRING_ENVELOPE)).out.trim(), "no")

    // --- nothing secret in any argv ---
    const argv = fs.readFileSync(argvLog, "utf8")
    const secrets = { "the password": "horse", "the new password": NEW_PASSWORD, "the PIN": PIN_VALUE,
      "the hmac-secret": HMAC_VALUE }
    for (const [what, value] of Object.entries(secrets)) {
      check(tag + `${what} never appeared in an argv`, !argv.includes(value), "found in the argv log")
    }
    const keySecrets = fs.existsSync(hmacLog) ? fs.readFileSync(hmacLog, "utf8").trim().split("\n").filter(Boolean) : []
    check(tag + "no secret a key handed out ever appeared in an argv",
      keySecrets.length > 0 && keySecrets.every(k => !argv.includes(k)), "found in the argv log")
    check(tag + "no derived key appeared in an argv either",
      !/[0-9a-f]{64}/.test(argv), (argv.match(/[0-9a-f]{64}/) || [""])[0])
    check(tag + "the argv log actually recorded the tools",
      ["secret-tool", "argon2", "unlock-tool", "systemd-creds", "jq", "cmp", "head", "fido2-assert"]
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
  const probe = Model.quickUnlockPrereqCommand()
  const r = spawnSync(probe[0], probe.slice(1), { encoding: "utf8" })
  const parsed = Model.parseQuickUnlockPrereqs(r.stdout)
  eq("argon2 is found here", parsed.argon2, true)
  eq("the probe agrees with the real-seal pass about systemd-creds", parsed.creds, realCreds.status === 0)
  check("a missing systemd-creds is explained",
    /systemd-creds --user/.test(Model.parseQuickUnlockPrereqs("argon2=1\ncreds=0\n").message), "")
  check("a missing argon2 is explained",
    /argon2/.test(Model.parseQuickUnlockPrereqs("argon2=0\ncreds=1\n").message), "")
  eq("both present is ready", Model.parseQuickUnlockPrereqs("argon2=1\ncreds=1\n").ready, true)
}
check("bw checks a typed password from the environment, never argv",
  /bw unlock --passwordenv QSBW_SECRET --raw/.test(Model.bwVerifyPasswordCommand()[2]), Model.bwVerifyPasswordCommand()[2])

// -------------------------------------------------------------------------
// Builders refuse what should never reach them
// -------------------------------------------------------------------------

const refused = cmd => cmd.length === 3 && cmd[2] === "exit 2"
check("a relative tool path is refused", refused(Model.unlockEnvelopeInspectCommand("unlock-tool")), JSON.stringify(Model.unlockEnvelopeInspectCommand("x")))
check("a missing account is refused", refused(Model.unlockEnvelopeCreateCommand("/t", null)), "")
check("an empty account id is refused", refused(Model.unlockEnvelopeCreateCommand("/t", { id: "", server: "s" })), "")
check("a control character in the server is refused", refused(Model.unlockEnvelopeCreateCommand("/t", { id: "a", server: "s\n" })), "")
check("a FIDO2 credential that is not base64 is refused",
  refused(Model.unlockEnvelopeOpenCommand("/t", ACCOUNT, { kind: "fido", cred: "a'b" })), "")
check("an unknown method is refused", refused(Model.unlockEnvelopeOpenCommand("/t", ACCOUNT, { kind: "face" })), "")
check("removing the master wrap is not an operation",
  refused(Model.unlockEnvelopeUpdateCommand("/t", ACCOUNT, { kind: "remove", method: "master" })), "")
check("the startup repair refuses a relative plugin directory",
  refused(Model.keyringRepairCommand("plugin", [])), "")
check("and looks only at well-formed slots, once each",
  (() => { const c = Model.keyringRepairCommand("/p", ["default", "0123456789abcdef", "0123456789abcdef", "../x"])[2]
    return c.includes("'unlock_envelope' 'unlock_envelope@0123456789abcdef';") && !c.includes("../x") })(), "")
{
  const p = Model.parseKeyringRepair("rejoined=2\nrejoin_failed=unlock_envelope\nfile=repaired\n")
  check("the repair's report is read", p.rejoined === 2 && p.rejoinFailed[0] === "unlock_envelope" && p.file === "repaired",
    JSON.stringify(p))
  eq("a script that died counts as failed", Model.parseKeyringRepair("rejoined=0\n").file, "failed")
  eq("an unknown status too", Model.parseKeyringRepair("file=maybe\n").file, "failed")
}
check("logout clears the envelope with everything else",
  Model.keyringClearAllCommand()[2].includes("'unlock_envelope'"), "keyringClearAllCommand does not name it")

done()
