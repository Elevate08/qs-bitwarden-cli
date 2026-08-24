#!/usr/bin/env node
// Tests for the commands that unlock the vault: unlock, email login, API key
// login. The property under test is the one that matters most here -- none of
// them may put a credential in an argv, because /proc/<pid>/cmdline is
// world-readable on a default Linux install and these are the credentials that
// open everything else.
//
//   node tests/auth.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync, spawnSync } = require("child_process")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.unlockPrewarmCommand = unlockPrewarmCommand
  exports.emailLoginPrewarmCommand = emailLoginPrewarmCommand
  exports.apiKeyLoginCommand = apiKeyLoginCommand
  exports.passwordEnvVar = passwordEnvVar
  exports.clientIdEnvVar = clientIdEnvVar
  exports.clientSecretEnvVar = clientSecretEnvVar
  exports.twoFactorCodeEnvVar = twoFactorCodeEnvVar
  exports.noInteractionEnvVar = noInteractionEnvVar
  exports.sessionEnvVar = sessionEnvVar
  exports.extractSessionToken = extractSessionToken
  exports.isSessionToken = isSessionToken
  exports.keyringClearAllCommand = keyringClearAllCommand
  exports.keyringStoreMasterPasswordCommand = keyringStoreMasterPasswordCommand
  exports.keyringLookupMasterPasswordCommand = keyringLookupMasterPasswordCommand
  exports.pinStoreCommand = pinStoreCommand
  exports.keyringSecretEnvVar = keyringSecretEnvVar
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// Distinctive enough that a substring search cannot miss them.
const MASTER = "correct-horse-battery-staple"
const CLIENT_ID = "user.11111111-2222-3333-4444-555555555555"
const CLIENT_SECRET = "sEcReTcLiEnTsTrInG"
const CODE = "249213"
const SERVER = "https://vault.example.com"

// Everything a builder could conceivably interpolate, flattened to one string.
const flat = (cmd) => cmd.join(" ")

// --- no credential may reach any argv ---------------------------------------

const unlock = Model.unlockPrewarmCommand()
check("unlock takes no password argument at all",
  Model.unlockPrewarmCommand.length === 0, `arity ${Model.unlockPrewarmCommand.length}`)
check("unlock reads the submitted password from its private FIFO",
  flat(unlock).includes("--passwordfile") && !flat(unlock).includes("--passwordenv"), flat(unlock))
check("unlock caps output and diagnostic stderr on the producer side",
  flat(unlock).includes("head -c") && flat(unlock).includes("exec 2>"), flat(unlock))

// The builders are called the way Panel.qml calls them: with what shapes the
// command, never with the secret itself.
const emailPlain = Model.emailLoginPrewarmCommand("john@example.com", false, "")
const emailFull = Model.emailLoginPrewarmCommand("john@example.com", true, SERVER)
const apiKey = Model.apiKeyLoginCommand("")
const apiKeyServer = Model.apiKeyLoginCommand(SERVER)

const everyCommand = [
  ["unlock", unlock],
  ["email login", emailPlain],
  ["email login with a 2FA code and a custom server", emailFull],
  ["api key login", apiKey],
  ["api key login with a custom server", apiKeyServer]
]

for (const [label, cmd] of everyCommand) {
  const text = flat(cmd)
  check(`${label} carries no master password in argv`, !text.includes(MASTER), text)
  check(`${label} carries no client secret in argv`, !text.includes(CLIENT_SECRET), text)
  check(`${label} carries no client id in argv`, !text.includes(CLIENT_ID), text)
  // An inline `VAR=value bw ...` prefix is exactly how the secrets used to
  // leak: the assignment lands in the wrapping shell's own command line.
  check(`${label} assigns no credential inline in the script`,
    !/\b(BW_PASSWORD|BW_CLIENTID|BW_CLIENTSECRET)=/.test(text), text)
}

// The builders cannot leak what they are never given, so also assert they no
// longer accept a secret -- a caller passing one would be silently ignored.
check("emailLoginPrewarmCommand takes (email, hasCode, serverUrl), not a password",
  Model.emailLoginPrewarmCommand.length === 3, `arity ${Model.emailLoginPrewarmCommand.length}`)
check("apiKeyLoginCommand takes only a server URL",
  Model.apiKeyLoginCommand.length === 1, `arity ${Model.apiKeyLoginCommand.length}`)

// A stray password argument must not find its way into the command anyway.
const emailWithStrayArgs = Model.emailLoginPrewarmCommand("john@example.com", MASTER, SERVER)
check("a password passed where hasCode belongs is never interpolated",
  !flat(emailWithStrayArgs).includes(MASTER), flat(emailWithStrayArgs))

// --- the env vars the commands rely on --------------------------------------

check("the password env var is BW_PASSWORD, which bw reads via --passwordenv",
  Model.passwordEnvVar() === "BW_PASSWORD", Model.passwordEnvVar())
check("the API key env vars are the ones bw reads natively",
  Model.clientIdEnvVar() === "BW_CLIENTID" && Model.clientSecretEnvVar() === "BW_CLIENTSECRET",
  Model.clientIdEnvVar() + " / " + Model.clientSecretEnvVar())
check("interaction is disabled through the environment, not the command line",
  Model.noInteractionEnvVar() === "BW_NOINTERACTION"
    && !everyCommand.some(([, c]) => flat(c).includes("BW_NOINTERACTION=")),
  Model.noInteractionEnvVar())

// --- the two-step code, the one exception, is still kept out of the shell ----
// bw has no environment option for --code, so the value reaches bw's argv. It
// must at least be expanded by the shell from the environment rather than
// written into the script, which outlives the login process.

check("a 2FA code is expanded from the environment, never inlined",
  flat(emailFull).includes('--code "$' + Model.twoFactorCodeEnvVar() + '"')
    && !flat(emailFull).includes(CODE), flat(emailFull))
check("no --code flag at all when no code was entered",
  !flat(emailPlain).includes("--code"), flat(emailPlain))

// --- the rest of the command shape still has to be right --------------------

check("email login passes the email address, which is not a secret",
  flat(emailPlain).includes("bw login 'john@example.com'"), flat(emailPlain))
check("a custom server is configured before logging in",
  emailFull[2].includes("bw config server '" + SERVER + "'")
    && emailFull[2].includes("&& bw login"), flat(emailFull))
check("no server config step when the default server is used",
  !flat(emailPlain).includes("bw config server"), flat(emailPlain))
check("api key login authenticates and then unlocks, since --apikey does not unlock",
  flat(apiKey).includes("bw login --apikey")
    && flat(apiKey).includes("bw unlock --passwordenv " + Model.passwordEnvVar()), flat(apiKey))
check("api key login honours a custom server too",
  flat(apiKeyServer).includes("bw config server '" + SERVER + "'"), flat(apiKeyServer))

// Single quotes in a server URL or email must not break out of the script.
const injected = Model.emailLoginPrewarmCommand("a'; touch /tmp/pwned; '@b.c", false,
  "https://x'; touch /tmp/pwned; '.com")
check("shell metacharacters in the email and server URL stay quoted",
  !flat(injected).includes("; touch /tmp/pwned; ")
    || flat(injected).includes("'\\''"), flat(injected))

// --- what counts as a session key -------------------------------------------
// The handoff file and bw's own stdout both feed extractSessionToken, and
// whatever it returns is written to the keyring and treated as an unlocked
// vault. Anything not shaped like a key must come back empty instead.

const REAL_KEY = "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk9PQ=="

check("a raw key is returned as-is",
  Model.extractSessionToken(REAL_KEY) === REAL_KEY, Model.extractSessionToken(REAL_KEY))
check("an export line is unwrapped",
  Model.extractSessionToken('export BW_SESSION="' + REAL_KEY + '"') === REAL_KEY,
  Model.extractSessionToken('export BW_SESSION="' + REAL_KEY + '"'))
check("a key sharing the stream with other output is still found",
  Model.extractSessionToken("Your vault is now unlocked!\n\n" + REAL_KEY) === REAL_KEY,
  Model.extractSessionToken("Your vault is now unlocked!\n\n" + REAL_KEY))

// Each of these used to be returned verbatim and stored as a session.
const notKeys = [
  ["an error message", "You are not logged in."],
  ["a single word of prose", "Failed"],
  ["an empty file", ""],
  ["whitespace", "   \n  "],
  ["a short string of key-ish characters", "abc123=="],
  ["a path someone left in the handoff file", "/home/user/notes.txt"],
  ["a sentence with no spaces but wrong characters", "unlock.failed:invalid.master.password!"]
]
for (const [label, input] of notKeys) {
  check(`${label} is not treated as a session key`,
    Model.extractSessionToken(input) === "", JSON.stringify(Model.extractSessionToken(input)))
}

check("a BW_SESSION line carrying junk is rejected rather than unwrapped",
  Model.extractSessionToken('BW_SESSION="not a key"') === "",
  Model.extractSessionToken('BW_SESSION="not a key"'))

// --- logging out has to take the keyring with it ----------------------------
//
// Two of the three entries this plugin writes are the master password: once in
// the clear for fingerprint unlock, once encrypted under a short PIN. Both go
// to the default collection, which is a file on disk that PAM unlocks at every
// login, so both survive a reboot on purpose. Logging out used to leave the
// PIN blob there forever, and to clear the fingerprint copy only when the
// panel's own `fingerprintStored` flag happened to be true -- a flag that goes
// false when a reader is unplugged, when fprintd is uninstalled, and for the
// first moments of every shell start. Run against a stand-in secret-tool so
// what is checked is that the entries are gone, not that a string looks right.

const keyringStub = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-logout-"))
fs.writeFileSync(path.join(keyringStub, "secret-tool"), `#!/usr/bin/env bash
set -uo pipefail
cmd="\${1:-}"; shift || true
account=""
unlock=false
while [ $# -gt 0 ]; do
  case "$1" in
    account) account="\${2:-}"; shift 2 ;;
    --unlock) unlock=true; shift ;;
    *) shift ;;
  esac
done
f="$STUB/entry-$account"
unlocked="$STUB/unlocked-$account"
case "$cmd" in
  store)  rm -f -- "$unlocked"; cat > "$f"; exit 0 ;;
  lookup) [ -s "$f" ] || exit 1; cat "$f"; printf '\n'; exit 0 ;;
  search)
    if [ "\${FAIL_SEARCH_ACCOUNT:-}" = "$account" ] \
        || { [ "\${FAIL_SEARCH_WHEN_MISSING_ACCOUNT:-}" = "$account" ] && [ ! -e "$f" ]; }; then
      printf '%s\n' 'keyring search unavailable' >&2
      exit 3
    fi
    [ -e "$f" ] || exit 0
    if $unlock && [ "\${LOCK_ACCOUNT:-}" = "$account" ] \
        && [ "\${DENY_UNLOCK_ACCOUNT:-}" != "$account" ]; then
      : > "$unlocked"
    fi
    printf '[stub-item]\nlabel = stub\n'
    if [ "\${LOCK_ACCOUNT:-}" != "$account" ] || [ -e "$unlocked" ]; then
      printf 'secret = '; cat "$f"; printf '\n'
    fi
    exit 0
    ;;
  clear)
    if [ "\${FAIL_CLEAR_ACCOUNT:-}" = "$account" ]; then
      printf '%s\n' 'keyring service unavailable' >&2
      exit 2
    fi
    [ -e "$f" ] || exit 1
    [ "\${LOCK_ACCOUNT:-}" != "$account" ] || [ -e "$unlocked" ] || exit 1
    rm -f -- "$f" "$unlocked"
    exit 0
    ;;
esac
exit 1
`)
fs.chmodSync(path.join(keyringStub, "secret-tool"), 0o755)

const keyringRun = (command, extraEnv) => execFileSync(command[0], command.slice(1), {
  env: Object.assign({}, process.env,
    { PATH: `${keyringStub}:${process.env.PATH}`, STUB: keyringStub }, extraEnv || {}),
  encoding: "utf8"
})
const keyringEntries = () => fs.readdirSync(keyringStub)
  .filter(f => f.startsWith("entry-")).map(f => f.slice("entry-".length)).sort()

// secret-tool terminates lookup output with a newline. The lookup wrapper must
// remove that transport delimiter without trimming spaces that are actually
// part of the master password.
const SPACED_MASTER = "  exact master password  "
keyringRun(Model.keyringStoreMasterPasswordCommand(), {
  [Model.keyringSecretEnvVar()]: SPACED_MASTER
})
check("fingerprint keyring lookup preserves leading and trailing password spaces",
  keyringRun(Model.keyringLookupMasterPasswordCommand()) === SPACED_MASTER,
  JSON.stringify(keyringRun(Model.keyringLookupMasterPasswordCommand())))

// The three accounts as the panel actually writes them, rather than a list
// copied into the test: a fourth secret added later must not slip past this.
keyringRun(["bash", "-c", "printf '%s' \"$QSBW_SECRET\" | secret-tool store --label=x"
  + " service 'qs-bitwarden-cli' account 'session'"], { QSBW_SECRET: "boot-id " + REAL_KEY })
keyringRun(Model.keyringStoreMasterPasswordCommand(), { [Model.keyringSecretEnvVar()]: MASTER })
keyringRun(Model.pinStoreCommand(), { [Model.keyringSecretEnvVar()]: MASTER, QSBW_PIN: "123456" })
check("the fixture leaves all three secrets in the keyring",
  keyringEntries().join(",") === "master_password,pin_blob,session", keyringEntries().join(","))

keyringRun(Model.keyringClearAllCommand())
check("logging out clears every secret the plugin ever stored",
  keyringEntries().length === 0, keyringEntries().join(","))

// Nothing stored is the ordinary case -- the user never enabled either
// feature -- and it must not read as a failure the panel then reports.
check("clearing an empty keyring succeeds",
  keyringRun(Model.keyringClearAllCommand()) === "", "expected silence and exit 0")
check("no secret reaches the clear command's argv",
  !Model.keyringClearAllCommand().join(" ").includes(MASTER),
  Model.keyringClearAllCommand().join(" "))

keyringRun(["bash", "-c", "printf '%s' \"$QSBW_SECRET\" | secret-tool store --label=x"
  + " service 'qs-bitwarden-cli' account 'session'"], { QSBW_SECRET: "stale session" })
const failedClear = spawnSync(Model.keyringClearAllCommand()[0], Model.keyringClearAllCommand().slice(1), {
  env: Object.assign({}, process.env,
    { PATH: `${keyringStub}:${process.env.PATH}`, STUB: keyringStub, FAIL_CLEAR_ACCOUNT: "session" }),
  encoding: "utf8"
})
check("a real keyring deletion failure propagates out of the clear-all command",
  failedClear.status !== 0 && keyringEntries().includes("session"),
  `status ${failedClear.status}; entries ${keyringEntries().join(",")}`)
keyringRun(Model.keyringClearAllCommand())

keyringRun(["bash", "-c", "printf '%s' \"$QSBW_SECRET\" | secret-tool store --label=x"
  + " service 'qs-bitwarden-cli' account 'session'"], { QSBW_SECRET: "locked session" })
const lockedClear = spawnSync(Model.keyringClearAllCommand()[0], Model.keyringClearAllCommand().slice(1), {
  env: Object.assign({}, process.env,
    { PATH: `${keyringStub}:${process.env.PATH}`, STUB: keyringStub,
      LOCK_ACCOUNT: "session", DENY_UNLOCK_ACCOUNT: "session" }),
  encoding: "utf8"
})
check("a matching credential in a locked collection cannot be mistaken for absence",
  lockedClear.status !== 0 && keyringEntries().includes("session"),
  `status ${lockedClear.status}; entries ${keyringEntries().join(",")}`)
keyringRun(Model.keyringClearAllCommand())

keyringRun(["bash", "-c", "printf '%s' \"$QSBW_SECRET\" | secret-tool store --label=x"
  + " service 'qs-bitwarden-cli' account 'session'"], { QSBW_SECRET: "unlockable session" })
keyringRun(Model.keyringClearAllCommand(), { LOCK_ACCOUNT: "session" })
check("clear-all unlocks and removes a matching credential from a locked collection",
  !keyringEntries().includes("session"), keyringEntries().join(","))

const failedSearch = spawnSync(Model.keyringClearAllCommand()[0], Model.keyringClearAllCommand().slice(1), {
  env: Object.assign({}, process.env,
    { PATH: `${keyringStub}:${process.env.PATH}`, STUB: keyringStub, FAIL_SEARCH_ACCOUNT: "session" }),
  encoding: "utf8"
})
check("a pre-clear keyring search failure blocks logout cleanup",
  failedSearch.status !== 0, `status ${failedSearch.status}`)

keyringRun(["bash", "-c", "printf '%s' \"$QSBW_SECRET\" | secret-tool store --label=x"
  + " service 'qs-bitwarden-cli' account 'session'"], { QSBW_SECRET: "post-search session" })
const failedPostSearch = spawnSync(Model.keyringClearAllCommand()[0], Model.keyringClearAllCommand().slice(1), {
  env: Object.assign({}, process.env,
    { PATH: `${keyringStub}:${process.env.PATH}`, STUB: keyringStub,
      FAIL_SEARCH_WHEN_MISSING_ACCOUNT: "session" }),
  encoding: "utf8"
})
check("a post-clear verification failure cannot be reported as successful cleanup",
  failedPostSearch.status !== 0 && !keyringEntries().includes("session"),
  `status ${failedPostSearch.status}; entries ${keyringEntries().join(",")}`)

fs.rmSync(keyringStub, { recursive: true, force: true })

// The command is only half of it: the panel has to run it, and run it without
// first asking a flag for permission. Both gates below were the bug.
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const bodyOf = (name) => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}

const logout = bodyOf("logoutAccount")
const forget = bodyOf("forgetStoredCredentials")
const credentialStores = bodyOf("credentialStoresRunning")
const allCredentialClear = bodyOf("requestAllCredentialClear")
const loginEnv = bodyOf("loginProcessEnv")
const unlockSuccess = bodyOf("onUnlockSuccess")
const pinResult = bodyOf("onPinUnlockResult")
const fingerprintResult = bodyOf("onFingerprintPasswordRetrieved")

check("API credentials are not materialized in the process environment before submission",
  /if\s*\(\s*!loginSubmitted\s*\)\s*return\s+authEnv\(\s*""\s*,\s*""\s*,\s*""\s*,\s*""\s*\)/.test(loginEnv)
    && loginEnv.indexOf("!loginSubmitted") < loginEnv.indexOf("loginClientSecret"),
  loginEnv)
for (const prop of ["loginClientId", "loginClientSecret", "login2faCode"]) {
  check(`successful authentication clears ${prop}`,
    new RegExp(`\\b${prop}\\s*=\\s*""`).test(unlockSuccess), unlockSuccess)
}
check("PIN unlock preserves significant master-password whitespace",
  pinResult !== "" && !/String\(password[^\n]+\)\.trim\(\)/.test(pinResult), pinResult)
check("fingerprint unlock preserves significant master-password whitespace",
  fingerprintResult !== "" && !/String\(raw[^\n]+\)\.trim\(\)/.test(fingerprintResult), fingerprintResult)

check("logging out forgets the stored credentials",
  /forgetStoredCredentials\(\)/.test(logout), logout)
check("the clear-all command is what it runs",
  /requestAllCredentialClear\(\)/.test(forget)
    && /keyringClearAllProc\.running\s*=\s*true/.test(bodyOf("requestAllCredentialClear")), forget)
check("it does not ask fingerprintStored or pinConfigured for permission first",
  forget !== "" && !/\bif\s*\(\s*(fingerprintStored|pinConfigured)\b/.test(forget), forget)
check("the panel declares a process for the clear-all command",
  /id:\s*keyringClearAllProc[\s\S]{0,120}Model\.keyringClearAllCommand\(\)/.test(panelSrc),
  "expected a keyringClearAllProc bound to Model.keyringClearAllCommand()")

check("logout keeps new authentication blocked until CLI and keyring cleanup both finish",
  /logoutPending\s*=\s*true/.test(logout)
    && /logoutCliDone\s*=\s*false/.test(logout)
    && /logoutCredentialsDone\s*=\s*false/.test(logout)
    && /logoutPending/.test(bodyOf("submitLogin"))
    && /logoutPending/.test(bodyOf("prepareEmailLogin"))
    && /logoutPending/.test(bodyOf("launchTerminalLogin")),
  logout + "\n" + bodyOf("submitLogin") + "\n" + bodyOf("prepareEmailLogin")
    + "\n" + bodyOf("launchTerminalLogin"))
check("logout completion is acknowledged by both asynchronous processes",
  /onLogoutCredentialsFinished\(exitCode\)/.test(panelSrc.slice(panelSrc.indexOf("id: keyringClearAllProc"),
    panelSrc.indexOf("id: keyringClearAllProc") + 420))
    && /onLogoutCliFinished\(exitCode\)/.test(panelSrc.slice(panelSrc.indexOf("id: logoutProc"),
      panelSrc.indexOf("id: logoutProc") + 240)),
  "logout cleanup processes are not serialized")
check("failed keyring cleanup keeps authentication blocked until an explicit retry succeeds",
  /logoutCredentialsExitCode\s*=\s*exitCode/.test(bodyOf("onLogoutCredentialsFinished"))
    && /if\s*\(logoutCredentialsExitCode\s*!==\s*0\)[\s\S]*return/.test(bodyOf("finishLogoutIfReady"))
    && /requestAllCredentialClear\(\)/.test(bodyOf("retryLogoutCleanup"))
    && /logoutCleanupFailed\s*\?\s*root\.retryLogoutCleanup\(\)/.test(panelSrc),
  bodyOf("onLogoutCredentialsFinished") + "\n" + bodyOf("finishLogoutIfReady")
    + "\n" + bodyOf("retryLogoutCleanup"))
check("logout's final keyring sweep waits for every credential writer",
  ["keyringStoreProc", "pinStoreProc", "keyringStoreMasterProc"].every(id =>
    new RegExp(`\\b${id}\\.running`).test(credentialStores))
    && /credentialStoresRunning\(\)[\s\S]*allCredentialsClearPending\s*=\s*true[\s\S]*return/.test(allCredentialClear),
  credentialStores + "\n" + allCredentialClear)
for (const id of ["keyringStoreProc", "pinStoreProc", "keyringStoreMasterProc"]) {
  const start = panelSrc.indexOf(`id: ${id}`)
  const processBlock = panelSrc.slice(start, start + 520)
  check(`${id} resumes the deferred logout sweep after its write exits`,
    /logoutPending[\s\S]*allCredentialsClearPending[\s\S]*requestAllCredentialClear/.test(processBlock),
    processBlock)
}

// Turning fingerprint unlock off is the other place a flag used to decide
// whether the master password stayed behind.
const fpOff = panelSrc.slice(panelSrc.indexOf("onFingerprintUnlockChanged:"),
  panelSrc.indexOf("onFingerprintUnlockChanged:") + 700)
check("disabling fingerprint unlock clears the keyring unconditionally",
  /forgetFingerprintUnlock\(\)/.test(fpOff) && !/if\s*\(fingerprintStored\)\s*forgetFingerprintUnlock/.test(fpOff),
  fpOff)

check("locking erases the remembered session whatever the setting now says",
  /requestSessionCredentialClear\(\)/.test(bodyOf("lockVault"))
    && /keyringClearProc\.running\s*=\s*true/.test(bodyOf("requestSessionCredentialClear"))
    && !/if\s*\(rememberSession\)\s*\{\s*\n\s*requestSessionCredentialClear/.test(bodyOf("lockVault")),
  bodyOf("lockVault"))

// --- and nothing the vault gave us outlives the lock ------------------------
// Every one of these is a secret that used to sit in the panel object until
// the shell exited: a generated password, a form left mid-compose, the payload
// JSON on its way to bw, the master password typed into a setup form.
const dropped = bodyOf("dropVaultSecrets")
check("locking drops the vault secrets",
  /dropVaultState\(\)/.test(bodyOf("lockVault")) && /dropVaultSecrets\(\)/.test(bodyOf("dropVaultState")),
  bodyOf("lockVault") + "\n" + bodyOf("dropVaultState"))
for (const prop of ["detailPassword", "liveTotp", "totpFollowupCode", "genValue",
                    "formPassword", "formTotp", "itemPayloadJson", "sendPayloadJson",
                    "sendFormText", "sendFormPassword", "loginPassword", "loginClientSecret",
                    "pinEntry", "pinSetupPin", "pinSetupMaster", "fpSetupMaster",
                    "masterToStore"]) {
  check(`locking clears ${prop}`,
    new RegExp(`\\b${prop}\\s*=\\s*""`).test(dropped), dropped)
}
check("the item payload is dropped once bw has taken it, as the Send one is",
  /itemPayloadJson\s*=\s*""/.test(bodyOf("onSaveItemFinished")), bodyOf("onSaveItemFinished"))

// Cancel and Escape leave a setup form the same way, so the clearing sits on
// the screen change rather than on each of the ways out.
const screenChanged = panelSrc.slice(panelSrc.indexOf("onCurrentScreenChanged:"),
  panelSrc.indexOf("onCurrentScreenChanged:") + 1200)
check("leaving the PIN form drops the master password it asked for",
  /currentScreen !== "pin"[\s\S]{0,80}abandonPinSetup\(\)/.test(screenChanged)
    && /pinSetupMaster\s*=\s*""/.test(bodyOf("abandonPinSetup")), screenChanged)
check("leaving the fingerprint form drops the master password it asked for",
  /currentScreen !== "fingerprint"[\s\S]{0,80}abandonFingerprintSetup\(\)/.test(screenChanged)
    && /fpSetupMaster\s*=\s*""/.test(bodyOf("abandonFingerprintSetup")), screenChanged)

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
