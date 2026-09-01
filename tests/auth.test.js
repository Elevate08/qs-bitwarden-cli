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
  exports.loginServerUrlFor = typeof loginServerUrlFor === "function" ? loginServerUrlFor : null
  exports.passwordEnvVar = passwordEnvVar
  exports.clientIdEnvVar = clientIdEnvVar
  exports.clientSecretEnvVar = clientSecretEnvVar
  exports.twoFactorCodeEnvVar = twoFactorCodeEnvVar
  exports.loginNeedsSecondFactor = typeof loginNeedsSecondFactor === "function" ? loginNeedsSecondFactor : null
  exports.loginNeedsDeviceVerification = typeof loginNeedsDeviceVerification === "function" ? loginNeedsDeviceVerification : null
  exports.loginNeedsMethodChoice = typeof loginNeedsMethodChoice === "function" ? loginNeedsMethodChoice : null
  exports.deviceVerificationLoginCommand = typeof deviceVerificationLoginCommand === "function" ? deviceVerificationLoginCommand : null
  exports.loginPromptRanOutOfInput = typeof loginPromptRanOutOfInput === "function" ? loginPromptRanOutOfInput : null
  exports.sanitizeInteractiveStderr = typeof sanitizeInteractiveStderr === "function" ? sanitizeInteractiveStderr : null
  exports.deviceCodeEnvVar = typeof deviceCodeEnvVar === "function" ? deviceCodeEnvVar : null
  exports.secondFactorWindowOpen = typeof secondFactorWindowOpen === "function" ? secondFactorWindowOpen : null
  exports.loginDiagnostic = typeof loginDiagnostic === "function" ? loginDiagnostic : null
  exports.loginHasNoUsableProvider = typeof loginHasNoUsableProvider === "function" ? loginHasNoUsableProvider : null
  exports.twoFactorMethods = typeof twoFactorMethods === "function" ? twoFactorMethods : null
  exports.isTwoFactorMethod = typeof isTwoFactorMethod === "function" ? isTwoFactorMethod : null
  exports.twoFactorMethodLabel = typeof twoFactorMethodLabel === "function" ? twoFactorMethodLabel : null
  exports.rememberedTwoFactorMethodFor = typeof rememberedTwoFactorMethodFor === "function" ? rememberedTwoFactorMethodFor : null
  exports.rememberTwoFactorMethodIn = typeof rememberTwoFactorMethodIn === "function" ? rememberTwoFactorMethodIn : null
  exports.forgetTwoFactorMethodIn = typeof forgetTwoFactorMethodIn === "function" ? forgetTwoFactorMethodIn : null
  exports.settingWriteCommand = typeof settingWriteCommand === "function" ? settingWriteCommand : null
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

// Fixes #6. Cloud regions are distinct Bitwarden environments, while a
// self-hosted installation still needs to retain the free-form server path.
check("the login server selector maps US, EU and custom without conflating them",
  Model.loginServerUrlFor
    && Model.loginServerUrlFor("us", SERVER) === "https://vault.bitwarden.com"
    && Model.loginServerUrlFor("eu", SERVER) === "https://vault.bitwarden.eu"
    && Model.loginServerUrlFor("custom", `  ${SERVER}  `) === SERVER,
  "US and EU must use their official vault URLs, and custom the entered URL")
check("an invalid login server selection falls back to the safe US default",
  Model.loginServerUrlFor
    && Model.loginServerUrlFor("", SERVER) === "https://vault.bitwarden.com"
    && Model.loginServerUrlFor("other", SERVER) === "https://vault.bitwarden.com",
  "unknown region values must not turn a stale custom URL into a destination")

check("only explicit Bitwarden second-factor challenges reveal the follow-up prompt",
  Model.loginNeedsSecondFactor
    && Model.loginNeedsSecondFactor("", "Two factor required.")
    && Model.loginNeedsSecondFactor("", "Two-step token is invalid. Try again.")
    && Model.loginNeedsSecondFactor("", "Verification code required")
    && !Model.loginNeedsSecondFactor("", "Response status code does not indicate success: 401")
    && !Model.loginNeedsSecondFactor("", "invalid_grant"),
  "generic status codes or invalid_grant must not be treated as MFA")
check("Bitwarden CLI 2026.2.0's standalone required-code error reveals the follow-up prompt",
  Model.loginNeedsSecondFactor && Model.loginNeedsSecondFactor("", "Code is required."),
  "Code is required. must be treated as a login verification challenge")

// Fixes #4. bw says "Code is required." to two different challenges. One of
// them, new-device verification, has no --code flag and no non-interactive
// answer at all, so treating it as a rejected two-step code asks the user for
// the same code forever. The attempt that already carried one is what tells
// them apart.
check("a required-code challenge answering an attempt that carried a code is device verification",
  Model.loginNeedsDeviceVerification
    && Model.loginNeedsDeviceVerification("", "Code is required.", true),
  "a second Code is required. after --code cannot be a rejected two-step code")
check("the same message on the first attempt is still an ordinary second-factor prompt",
  Model.loginNeedsDeviceVerification
    && !Model.loginNeedsDeviceVerification("", "Code is required.", false)
    && Model.loginNeedsSecondFactor("", "Code is required."),
  "the two challenges are indistinguishable until a code has been sent")
check("a genuinely rejected two-step code is not mistaken for device verification",
  Model.loginNeedsDeviceVerification
    && !Model.loginNeedsDeviceVerification("", "Two-step token is invalid. Try again.", true)
    && !Model.loginNeedsDeviceVerification("", "Login failed. No provider selected.", true)
    && !Model.loginNeedsDeviceVerification("", "Username or password is incorrect. Try again.", true),
  "only the bare required-code sentence means the code was never read")

// --- the two-step method question -------------------------------------------
//
// bw picks the provider itself when an account has exactly one, and asks when
// it has more. It asks by failing, because the menu it would otherwise draw
// needs a terminal. Answering by guessing is what produces a failed login, so
// the panel treats the message as the question it is.
check("bw's provider question is recognised as a question, not a credential failure",
  Model.loginNeedsMethodChoice
    && Model.loginNeedsMethodChoice("", "Login failed. No provider selected.")
    && !Model.loginNeedsMethodChoice("", "Code is required.")
    && !Model.loginNeedsMethodChoice("", "Username or password is incorrect. Try again."),
  "only No provider selected. means bw wants --method")
check("an account whose methods this client cannot perform is a separate dead end",
  Model.loginHasNoUsableProvider
    && Model.loginHasNoUsableProvider("", "Login failed. No providers available for this client.")
    && !Model.loginHasNoUsableProvider("", "Login failed. No provider selected.")
    && !Model.loginNeedsMethodChoice("", "Login failed. No providers available for this client."),
  "the two provider messages must not be confused for one another")

// getSupportedProviders() gates Duo and Organization Duo behind supportsDuo()
// and WebAuthn behind supportsWebAuthn(), both of which the CLI's platform
// layer hardcodes to false. So these three are not a shortlist -- they are
// every provider bw can act on, which is what makes a fixed picker complete.
check("the method picker offers every provider bw can use and nothing it cannot",
  Model.twoFactorMethods
    && Model.twoFactorMethods().map((m) => m.method).join(",") === "0,3,1"
    && Model.twoFactorMethods().every((m) => m.label && m.hint),
  JSON.stringify(Model.twoFactorMethods && Model.twoFactorMethods()))
check("the picker's table is copied, so a caller cannot edit the set of methods",
  (() => {
    const first = Model.twoFactorMethods()
    first[0].method = 99
    return Model.twoFactorMethods()[0].method === 0
  })(),
  "twoFactorMethods() must not hand out its own entries")
check("only a listed method may reach the command line",
  Model.isTwoFactorMethod(0) && Model.isTwoFactorMethod(1) && Model.isTwoFactorMethod(3)
    && !Model.isTwoFactorMethod(2) && !Model.isTwoFactorMethod(7)
    && !Model.isTwoFactorMethod(-1) && !Model.isTwoFactorMethod("0")
    && !Model.isTwoFactorMethod(null) && !Model.isTwoFactorMethod(undefined),
  "membership of the table, not shape, is the test")

// shell.json is not validated by whatever writes it, and this value goes
// straight back into an argv.
const R = Model.rememberedTwoFactorMethodFor
const STORE = { "a@example.com": 0, "b@example.com": 1 }
check("a remembered method is validated on the way back out of shell.json",
  R && R(STORE, "a@example.com") === 0
    && R({ "a@example.com": "3" }, "a@example.com") === 3
    && R({ "a@example.com": 2 }, "a@example.com") === -1
    && R({ "a@example.com": 9 }, "a@example.com") === -1
    && R({ "a@example.com": "; rm -rf /" }, "a@example.com") === -1
    && R({ "a@example.com": null }, "a@example.com") === -1
    // Number() reads all of these as 0, which is Authenticator. An unset entry
    // must not come back as a confident answer.
    && R({ "a@example.com": "" }, "a@example.com") === -1
    && R({ "a@example.com": false }, "a@example.com") === -1
    && R({ "a@example.com": true }, "a@example.com") === -1
    && R({ "a@example.com": [1] }, "a@example.com") === -1
    && R({ "a@example.com": {} }, "a@example.com") === -1,
  "anything not in the table reads as not remembered")

// The bug this replaced: one method for the whole machine, so a second vault
// was sent the first vault's method and had to be talked out of it.
check("each account keeps its own method",
  R(STORE, "a@example.com") === 0 && R(STORE, "b@example.com") === 1
    && R(STORE, "c@example.com") === -1,
  JSON.stringify(STORE))
check("the login address is matched the way Bitwarden treats it",
  R(STORE, "  A@Example.COM  ") === 0
    && Model.rememberTwoFactorMethodIn({}, "  A@Example.COM ", 1)["a@example.com"] === 1,
  "case and whitespace must not make an account remember itself twice")
check("no account, no memory",
  R(STORE, "") === -1 && R(STORE, null) === -1 && R(null, "a@example.com") === -1
    && R("not an object", "a@example.com") === -1,
  "an absent or unreadable store is not an answer")

// Rebuilt rather than mutated, so a hand-edit cannot survive into what is
// written back.
const grown = Model.rememberTwoFactorMethodIn(
  { "a@example.com": 0, "junk@example.com": 99, "b@example.com": 1 }, "c@example.com", 3)
check("remembering one account leaves the others alone and drops what it cannot read",
  grown["a@example.com"] === 0 && grown["b@example.com"] === 1
    && grown["c@example.com"] === 3 && !("junk@example.com" in grown),
  JSON.stringify(grown))
check("an existing account is updated rather than duplicated",
  (() => {
    const out = Model.rememberTwoFactorMethodIn(STORE, "a@example.com", 1)
    return out["a@example.com"] === 1 && Object.keys(out).length === 2
  })(),
  "re-answering must replace, not append")
check("the store is bounded, because a config file is not a history",
  (() => {
    let store = {}
    for (let i = 0; i < 30; i++) {
      store = Model.rememberTwoFactorMethodIn(store, `u${i}@example.com`, 0)
    }
    return Object.keys(store).length <= 10 && store["u29@example.com"] === 0
  })(),
  "the newest answer must always survive the cap")
check("forgetting one account forgets only that one",
  (() => {
    const out = Model.forgetTwoFactorMethodIn(STORE, "a@example.com")
    return !("a@example.com" in out) && out["b@example.com"] === 1
  })(),
  "a stale method for one vault must not clear another's")
// `flat` is declared further down; this block runs before it.
const jsonWrite = Model.settingWriteCommand("twoFactorMethods", { "a@example.com": 1 }, "json").join(" ")
check("a per-account map reaches shell.json as JSON, not as a number",
  jsonWrite.includes('{"a@example.com":1}') && jsonWrite.includes("--json"), jsonWrite)
check("an integer setting is still written as an integer",
  Model.settingWriteCommand("autoLockMinutes", 15, "int").join(" ").includes("'15'"),
  Model.settingWriteCommand("autoLockMinutes", 15, "int").join(" "))

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
check("emailLoginPrewarmCommand takes (email, hasCode, serverUrl, method), not a password",
  Model.emailLoginPrewarmCommand.length === 4, `arity ${Model.emailLoginPrewarmCommand.length}`)
check("apiKeyLoginCommand takes only a server URL",
  Model.apiKeyLoginCommand.length === 1, `arity ${Model.apiKeyLoginCommand.length}`)

// A stray password argument must not find its way into the command anyway.
const emailWithStrayArgs = Model.emailLoginPrewarmCommand("john@example.com", MASTER, SERVER)
check("a password passed where hasCode belongs is never interpolated",
  !flat(emailWithStrayArgs).includes(MASTER), flat(emailWithStrayArgs))

// --- --method, the one argument that is a bare integer ----------------------
//
// bw wants a number here, so it is neither quoted nor carried in the
// environment like everything else. What keeps that safe is that the only
// values which reach it are the ones already in the table.
const emailMethod = Model.emailLoginPrewarmCommand("john@example.com", true, "", 0)
const emailNoMethod = Model.emailLoginPrewarmCommand("john@example.com", true, "", -1)
check("a chosen method is passed to bw as a bare integer",
  / --method 0 /.test(flat(emailMethod) + " "), flat(emailMethod))
check("the method is sent before the code, as bw's own option order has it",
  flat(emailMethod).indexOf("--method") < flat(emailMethod).indexOf("--code"),
  flat(emailMethod))
check("no method at all is sent when none was chosen, so bw picks for itself",
  !flat(emailNoMethod).includes("--method")
    && !flat(Model.emailLoginPrewarmCommand("john@example.com", true, "")).includes("--method"),
  flat(emailNoMethod))
check("a method outside the table never reaches the command line",
  [2, 7, 99, -5, "0", "0; rm -rf /", null, undefined, {}, [0]].every(
    (m) => !flat(Model.emailLoginPrewarmCommand("john@example.com", true, "", m)).includes("--method")),
  "only table members may be interpolated")
check("the email login stage that carries a method carries no code with it",
  !flat(Model.emailLoginPrewarmCommand("john@example.com", false, "", 1)).includes("--code")
    && flat(Model.emailLoginPrewarmCommand("john@example.com", false, "", 1)).includes("--method 1"),
  "choosing Email must be able to ask bw to send the mail")

// --- the one login that runs with bw's prompts enabled ----------------------
//
// New-device verification is the only challenge bw accepts from no flag: the
// token comes from an inquirer prompt on stdin. So this command answers it on
// stdin, and everything below is about that being safe rather than merely
// working.
const deviceCmd = Model.deviceVerificationLoginCommand("john@example.com", "", 0)
const deviceFlat = flat(deviceCmd)
check("the device code is piped to bw's stdin, read from the environment",
  Model.deviceCodeEnvVar() === "QSBW_DEVICE_CODE"
    && deviceFlat.includes('printf \'%s\\n\' "$' + Model.deviceCodeEnvVar() + '" |'),
  deviceFlat)
check("the device code reaches no argv at all, not even bw's",
  !deviceFlat.includes("--code") && !/--\w+ \d{6}/.test(deviceFlat), deviceFlat)
check("the master password still travels by FIFO on this path too",
  deviceFlat.includes('--passwordfile "$__auth_fifo"')
    && !deviceFlat.includes("--passwordenv"), deviceFlat)
check("the interactive login is bounded, so a prompt that never comes cannot hold it",
  /timeout \d+s bw login/.test(deviceFlat), deviceFlat)
check("a chosen two-step method still travels with it",
  deviceFlat.includes("--method 0")
    && !flat(Model.deviceVerificationLoginCommand("john@example.com", "", -1)).includes("--method"),
  deviceFlat)
check("this command does not disable interaction, which is the whole point",
  !deviceFlat.includes("BW_NOINTERACTION"), deviceFlat)

// The flag being dropped was there so bw fails fast instead of blocking on a
// prompt nobody can see. A pipe keeps that: inquirer 8.2.6 throws
// ERR_USE_AFTER_CLOSE at EOF rather than waiting, which is what the fallback
// to a terminal login keys off.
check("an unexpected prompt is recognised as a reason to fall back, not an error to show",
  Model.loginPromptRanOutOfInput
    && Model.loginPromptRanOutOfInput("", "Error [ERR_USE_AFTER_CLOSE]: readline was closed")
    && !Model.loginPromptRanOutOfInput("", "Username or password is incorrect. Try again."),
  "inquirer's own failure is a fallback signal")

// An interactive bw echoes every keystroke back to stderr with the cursor
// movement to match, so the captured stream holds the code itself.
const noisy = "\u001b[2K\u001b[G? Enter OTP sent to login email: 913744\u001b[39D"
  + "\u001b[39C\r\nInvalid verification code. Try again.\u001b[?25h"
// Deliberately not on a prompt line: the prompt rule must not be what removes
// it, or redaction is untested.
const echoedElsewhere = "Verification failed for code 913744.\r\nTry again."
check("the echoed device code never survives into a message shown to the user",
  Model.sanitizeInteractiveStderr
    && !Model.sanitizeInteractiveStderr(noisy, "913744").includes("913744")
    && !Model.sanitizeInteractiveStderr(echoedElsewhere, "913744").includes("913744")
    && Model.sanitizeInteractiveStderr(echoedElsewhere, "913744") === "Try again.",
  JSON.stringify(Model.sanitizeInteractiveStderr && Model.sanitizeInteractiveStderr(echoedElsewhere, "913744")))
check("what bw actually had to say survives the sanitiser",
  Model.sanitizeInteractiveStderr(noisy, "913744") === "Invalid verification code. Try again.",
  JSON.stringify(Model.sanitizeInteractiveStderr(noisy, "913744")))
check("the sanitiser drops escape sequences and inquirer's own prompt lines",
  !/\u001b/.test(Model.sanitizeInteractiveStderr(noisy, "913744"))
    && !Model.sanitizeInteractiveStderr(noisy, "913744").includes("Enter OTP"),
  JSON.stringify(Model.sanitizeInteractiveStderr(noisy, "913744")))
check("a stack trace cannot flood the panel's error banner",
  Model.sanitizeInteractiveStderr("x".repeat(9000), "").length <= 300,
  String(Model.sanitizeInteractiveStderr("x".repeat(9000), "").length))

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
const submitLogin = bodyOf("submitLogin")
const loginOutput = bodyOf("onLoginOutput")
const abandonAuth = bodyOf("abandonAuthSecrets")
const resetSecondFactor = bodyOf("resetEmailLoginSecondFactor")
const prepareEmailLogin = bodyOf("prepareEmailLogin")
const chooseMethod = bodyOf("chooseTwoFactorMethod")
const loginSignature = bodyOf("emailLoginSignature")
const rememberMethod = bodyOf("rememberTwoFactorMethod")
const writerExited = bodyOf("onAuthPasswordWriterExited")
const resumeDeferred = bodyOf("resumeDeferredLogin")
const clearCollector = bodyOf("clearProcessCollectorSoon")
const loginExited = panelSrc.slice(panelSrc.indexOf("id: loginProc"),
  panelSrc.indexOf("id: authPasswordWriterProc"))
const focusField = bodyOf("focusAppropriateField")
const statusFinished = bodyOf("onStatusFinished")
const pendingSecondFactor = bodyOf("pendingSecondFactorLogin")
const suspendPending = bodyOf("suspendPendingLogin")
const panelOpened = bodyOf("onPanelOpened")
const syncFields = bodyOf("syncLoginFieldsToState")
const submitDevice = bodyOf("submitDeviceVerification")
const startDevice = bodyOf("startDeviceVerificationLogin")
const loginFieldFocus = bodyOf("loginFieldHasFocus")
const resolvedLoginServer = bodyOf("resolvedLoginServerUrl")
const terminalLoginUi = panelSrc.slice(panelSrc.indexOf("// METHOD B: API Key"),
  panelSrc.indexOf("// SCREEN 2: LOCKED VIEW"))
const emailLoginUi = panelSrc.slice(panelSrc.indexOf("// METHOD A: Email & Password"),
  panelSrc.indexOf("// METHOD B: API Key"))

check("the login screen offers US, EU and Custom server choices to both login methods",
  /text:\s*"US"[\s\S]{0,500}text:\s*"EU"[\s\S]{0,500}text:\s*"Custom"/.test(panelSrc)
    && panelSrc.indexOf('text: "US"') < panelSrc.indexOf("// METHOD A: Email & Password"),
  "the shared region selector must appear before the method-specific forms")
check("the custom URL field appears only for the Custom server choice",
  /id:\s*serverUrlField[\s\S]{0,160}visible:\s*root\.loginServerRegion\s*===\s*"custom"/.test(panelSrc),
  "selecting US or EU must not expose a misleading self-hosted URL field")
check("all login paths resolve their server choice through the same mapping",
  /Model\.loginServerUrlFor\(loginServerRegion,\s*loginServerUrl\)/.test(resolvedLoginServer)
    && (panelSrc.match(/resolvedLoginServerUrl\(\)/g) || []).length >= 4,
  resolvedLoginServer || "resolvedLoginServerUrl() is missing")

// Email/password login is deliberately two-stage. Asking every user for a
// second factor up front makes an optional challenge look mandatory and
// collects a code before Bitwarden has said it needs one.
check("the email login initially hides the second-factor prompt",
  /Column\s*\{\s*visible:\s*root\.show2faField[\s\S]{0,420}TWO-STEP VERIFICATION CODE/.test(emailLoginUi),
  emailLoginUi)
check("each login stage replaces the controls before it instead of overflowing below them",
  (emailLoginUi.match(/visible:\s*root\.loginCredentialsStage/g) || []).length >= 2
    && /visible:\s*root\.loginMethod\s*!==\s*"email"\s*\|\|\s*root\.loginCredentialsStage/.test(panelSrc)
    && /loginCredentialsStage:\s*!show2faField\s*&&\s*!show2faMethodPicker/.test(panelSrc)
    && /visible:\s*root\.show2faMethodPicker/.test(emailLoginUi)
    && /visible:\s*root\.show2faField/.test(emailLoginUi),
  emailLoginUi)
check("only deliberate credential edits can return MFA login to the first stage",
  /id:\s*emailField[\s\S]{0,700}onTextEdited:[\s\S]{0,300}resetEmailLoginSecondFactor\(\)/.test(emailLoginUi)
    && /id:\s*loginPassField[\s\S]{0,900}onTextEdited:\s*\{[\s\S]{0,180}if\s*\(root\.show2faField\)[\s\S]{0,180}resetEmailLoginSecondFactor\(\)/.test(emailLoginUi)
    && /id:\s*loginPassField[\s\S]{0,500}onTextChanged:\s*root\.loginPassword\s*=\s*text/.test(emailLoginUi),
  emailLoginUi)
check("Enter on the password submits the first stage, then advances to the revealed code field",
  /id:\s*loginPassField[\s\S]{0,1200}onAccepted:\s*root\.show2faField\s*\?\s*code2faField\.forceActiveFocus\(\)\s*:\s*root\.submitLogin\(\)/.test(emailLoginUi),
  emailLoginUi)
check("the second stage cannot resubmit without a verification code",
  /show2faField[\s\S]{0,180}login2faCode[\s\S]{0,220}code2faField\.forceActiveFocus\(\)[\s\S]{0,80}return/.test(submitLogin),
  submitLogin)
check("a Bitwarden second-factor challenge reveals and focuses the code field",
  /show2faField\s*=\s*true/.test(loginOutput)
    && /code2faField\.forceActiveFocus\(\)/.test(loginOutput),
  loginOutput)
check("restarting email login clears both the second-factor stage and its code",
  /show2faField\s*=\s*false/.test(resetSecondFactor)
    && /login2faCode\s*=\s*""/.test(resetSecondFactor)
    && /loginDeviceVerification\s*=\s*false/.test(resetSecondFactor),
  resetSecondFactor)

// Fixes #4. The device-verification branch has to be reached first: the
// second-factor test below it matches the same message, so testing in the
// other order would re-prompt for a code bw is never going to read.
check("device verification is decided before the second-factor prompt is raised",
  /loginNeedsDeviceVerification/.test(loginOutput)
    && loginOutput.indexOf("loginNeedsDeviceVerification")
       < loginOutput.indexOf("loginNeedsSecondFactor"),
  loginOutput)
check("the device-verification branch stops asking for a code and does not focus the field",
  /loginNeedsDeviceVerification[\s\S]{0,400}resetEmailLoginSecondFactor\(\)[\s\S]{0,120}loginDeviceVerification\s*=\s*true[\s\S]{0,600}return/.test(loginOutput)
    && loginOutput.indexOf("code2faField.forceActiveFocus")
       > loginOutput.indexOf("loginNeedsSecondFactor"),
  loginOutput)
check("every email login attempt records whether it carried a code",
  (submitLogin.match(/loginAttemptHadCode\s*=/g) || []).length >= 2
    && /loginAttemptHadCode\s*=\s*String\(login2faCode[\s\S]{0,200}emailLoginPrewarmCommand\(\s*\n?\s*email,\s*loginAttemptHadCode/.test(prepareEmailLogin),
  prepareEmailLogin + "\n---\n" + submitLogin)
// --- a code is never sent without the method it belongs to -------------------
//
// bw only puts the two-step token on the wire when a provider came with it
// (TokenRequest.toIdentityToken requires provider != null). Without --method
// the code-carrying request is therefore a bare password grant, and for an
// email provider the server answers that challenge by issuing a fresh code --
// invalidating the one being submitted. Measured against bw 2026.2.0: the same
// command succeeds with --method and fails without it.
check("a code is not collected until the method it belongs to is known",
  /!Model\.isTwoFactorMethod\(login2faMethod\)[\s\S]{0,400}show2faMethodPicker = true[\s\S]{0,300}return/.test(loginOutput),
  loginOutput)
check("the method question is asked before the code field, not after",
  loginOutput.indexOf("second-factor-needs-method")
    < loginOutput.indexOf("secondFactorWasVisible"),
  loginOutput)
check("a known method goes straight to the code field",
  /var secondFactorWasVisible = show2faField/.test(loginOutput)
    && /show2faField = true/.test(loginOutput),
  loginOutput)
check("every command that carries a code also carries a method",
  (() => {
    const withCode = Model.emailLoginPrewarmCommand("a@b.c", true, "", 1).join(" ")
    const noMethod = Model.emailLoginPrewarmCommand("a@b.c", true, "", -1).join(" ")
    // The builder still honours -1; it is the panel that must never reach it
    // with a code. Assert the builder pairs them when asked to.
    return withCode.includes("--method 1") && withCode.includes("--code")
      && !noMethod.includes("--method")
  })(),
  "the pairing is the panel's to enforce, and the builder must support it")

// --- a status check must never cancel the login it raced ---------------------
//
// `bw status` takes seconds and answers about the world as it was when it
// started. Landing mid-login it says "unauthenticated", truthfully for that
// moment, and the unauthenticated branch calls cancelAuthPrewarm() -- which
// SIGTERMs the login the user just submitted. It also clears isLoading on the
// way past, so the button dropped out of "Verifying..." with nothing shown.
check("a status result that raced a submitted login is ignored",
  /if \(authAttemptInFlight\(\)\)[\s\S]{0,240}return/.test(statusFinished)
    && statusFinished.indexOf("authAttemptInFlight")
       < statusFinished.indexOf("isLoading = false"),
  statusFinished)
check("the guard covers both kinds of submitted authentication",
  /loginSubmitted \|\| unlockSubmitted/.test(bodyOf("authAttemptInFlight")),
  bodyOf("authAttemptInFlight"))
check("the guard sits ahead of every branch that cancels or drops state",
  statusFinished.indexOf("authAttemptInFlight")
    < statusFinished.indexOf("cancelAuthPrewarm"),
  statusFinished)

// --- a cleared property must never leave a filled-in field ------------------
//
// Typing into a TextField assigns to its own `text`, which breaks the binding
// back to the property behind it. Clearing the property then leaves the field
// showing what was typed, while every submit reads the property -- so the panel
// sent a login with no code at all while the user looked at a filled-in code
// field, bw answered "Code is required.", and retyping the code repaired the
// property so the next click worked. That was the double Verify.
check("clearing a login field's property clears the field with it",
  ["code2faField", "deviceCodeField", "loginPassField",
   "apiClientIdField", "apiClientSecretField"]
    .every((f) => new RegExp(`${f}\\.text =`).test(syncFields)),
  syncFields)
check("the fields are synced from the state, never the other way round",
  /code2faField\.text = login2faCode/.test(syncFields)
    && !/login2faCode = code2faField/.test(syncFields),
  syncFields)
check("every path that clears login state syncs the fields it is behind",
  ["suspendPendingLogin", "resetEmailLoginSecondFactor", "abandonAuthSecrets"]
    .every((fn) => /syncLoginFieldsToState\(\)/.test(bodyOf(fn))),
  "a clear that skips the sync reintroduces the desync")
check("locking and succeeding sync the fields too, so a later login opens clean",
  (panelSrc.match(/syncLoginFieldsToState\(\)/g) || []).length >= 6, panelSrc)

// --- a login must never end without saying anything -------------------------
//
// bw exiting cleanly with no session used to be handed to the unlock path,
// which refuses it on the login screen and then fails silently two seconds
// later in a FIFO writer. The button went to "Verifying..." and back, and
// nothing was ever shown.
check("a clean exit with no session reports instead of falling through to unlock",
  /logLogin\("clean-exit-no-session"[\s\S]{0,200}errorMessage = "Bitwarden reported no error/.test(loginOutput)
    && !/unlockVaultWithPassword\(loginPassword\)/.test(loginOutput),
  loginOutput)
check("every branch of the login result says which one it was",
  (loginOutput.match(/logLogin\("/g) || []).length >= 9, loginOutput)

// The diagnostic is the shape of an attempt, never its content: a session
// token is counted rather than printed.
check("the diagnostic counts the session rather than printing it",
  Model.loginDiagnostic
    && Model.loginDiagnostic("a-real-looking-session-token==", "", 0, "success")
         .includes("stdout=30b")
    && !Model.loginDiagnostic("a-real-looking-session-token==", "", 0, "success")
         .includes("a-real-looking-session-token"),
  Model.loginDiagnostic && Model.loginDiagnostic("a-real-looking-session-token==", "", 0, "success"))
check("the diagnostic carries what bw said, escape sequences and all removed",
  Model.loginDiagnostic("", "\u001b[2KTwo-step token is invalid.", 1, "bw-error")
    .includes("Two-step token is invalid.")
    && !/\u001b/.test(Model.loginDiagnostic("", "\u001b[2Kx", 1, "bw-error")),
  Model.loginDiagnostic("", "\u001b[2KTwo-step token is invalid.", 1, "bw-error"))
check("the diagnostic is bounded, so a stack trace cannot fill the log",
  Model.loginDiagnostic("", "x".repeat(9000), 1, "bw-error").length < 300,
  String(Model.loginDiagnostic("", "x".repeat(9000), 1, "bw-error").length))

// --- a submit must never be swallowed by the buffer scrub -------------------
//
// The scrub is started from the login process's own exit handler and takes the
// process for a moment. A submit arriving in that moment ends up waiting on the
// scrub's exit rather than the login's, and the exit handler returned early for
// a scrub -- so the deferred submit was dropped and the click did nothing. The
// next click worked because by then nothing held the process. That was having
// to press Verify twice.
check("a scrub's exit still dispatches whatever submit was waiting on it",
  /finishScrubRun\(loginProc\)\)\s*\{[\s\S]{0,120}resumeDeferredLogin\(false\)[\s\S]{0,40}return/.test(loginExited),
  loginExited)
check("the ordinary exit dispatches through the same path",
  /!root\.loginSubmitted\)\s*\{[\s\S]{0,420}root\.resumeDeferredLogin\(true\)/.test(loginExited),
  loginExited)
check("a scrub cannot schedule another scrub",
  /mayScrub\)\s*\{?\s*\n?\s*clearProcessCollectorSoon/.test(resumeDeferred)
    && /resumeDeferredLogin\(false\)/.test(loginExited),
  resumeDeferred)
check("every deferred kind is dispatched, not just the submit",
  /deviceVerificationPending/.test(resumeDeferred)
    && /loginSubmitAfterPrewarmStop/.test(resumeDeferred)
    && /loginPrepareAfterPrewarmStop/.test(resumeDeferred),
  resumeDeferred)
check("a scrub is not started over a submit that is already waiting",
  /proc === loginProc[\s\S]{0,220}loginSubmitAfterPrewarmStop[\s\S]{0,160}return/.test(clearCollector),
  clearCollector)

// --- a login waiting on an emailed code must survive the panel closing ------
//
// A code that arrives by email cannot be read without leaving the panel, and
// closing used to call abandonAuthSecrets() -- so the password and the stage
// were gone by the time the user came back with the code. Email two-step and
// new-device verification were both unreachable by construction.
const MIN = 60 * 1000
check("a pending login survives the panel closing, for a bounded time",
  Model.secondFactorWindowOpen
    && Model.secondFactorWindowOpen(1000, 1000)
    && Model.secondFactorWindowOpen(1000, 1000 + 4 * MIN)
    && !Model.secondFactorWindowOpen(1000, 1000 + 6 * MIN),
  "the window has to be open long enough to read an email and no longer")
check("no window is open when no login was pending",
  !Model.secondFactorWindowOpen(0, Date.now())
    && !Model.secondFactorWindowOpen(null, Date.now())
    && !Model.secondFactorWindowOpen("", Date.now()),
  "0 means nothing is pending, not that everything is")
check("a clock stepped backwards closes the window rather than reopening it",
  !Model.secondFactorWindowOpen(5000, 1000),
  "negative elapsed time is evidence the clock moved, not that the login is recent")

check("only a login stopped on a challenge is kept, and only with a password to submit",
  /show2faField && !showDeviceCodeField && !show2faMethodPicker[\s\S]{0,60}return false/.test(pendingSecondFactor)
    && /!String\(loginPassword \|\| ""\)[\s\S]{0,40}return false/.test(pendingSecondFactor)
    && /status !== "unauthenticated"[\s\S]{0,60}return false/.test(pendingSecondFactor)
    && /Model\.secondFactorWindowOpen\(secondFactorStartedAt/.test(pendingSecondFactor),
  pendingSecondFactor)
check("both ways of closing the panel keep a pending login instead of wiping it",
  (panelSrc.match(/if \(pendingSecondFactorLogin\(\)\) suspendPendingLogin\(\)\s*\n\s*else abandonAuthSecrets\(\)/g) || []).length === 2,
  "close() and onOpenedChanged both call abandonAuthSecrets unconditionally otherwise")
check("a half-typed code is dropped, since it is not the code about to be read",
  /login2faCode = ""/.test(suspendPending) && /loginDeviceCode = ""/.test(suspendPending)
    && !/loginPassword/.test(suspendPending),
  suspendPending)
check("reopening past the window starts over rather than resuming",
  /!Model\.secondFactorWindowOpen\(secondFactorStartedAt[\s\S]{0,80}abandonAuthSecrets\(\)/.test(panelOpened),
  panelOpened)
check("reopening inside the window lands on the field that is waiting",
  /showDeviceCodeField\) deviceCodeField\.forceActiveFocus\(\)/.test(focusField)
    && /show2faField\) code2faField\.forceActiveFocus\(\)/.test(focusField),
  focusField)
check("the window expires on its own, even while the panel is not on screen",
  /running:\s*root\.secondFactorStartedAt > 0[\s\S]{0,300}abandonAuthSecrets\(\)/.test(panelSrc),
  "a closed panel still has to forget on time")
check("every stage that waits on a code starts the clock",
  (panelSrc.match(/markSecondFactorStage\(\)/g) || []).length >= 5, panelSrc)
check("locking, logging out and succeeding all end the pending window",
  (panelSrc.match(/secondFactorStartedAt = 0/g) || []).length >= 3, panelSrc)

// --- an unsynced vault is not an empty vault --------------------------------
//
// `bw login` calls fullSync() without allowThrowOnError, so a sync that throws
// is swallowed: login exits 0 and prints a working session onto a local vault
// with no ciphers in it. The item list is then empty and correct, and looks
// exactly like a vault with nothing in it.
check("an unlocked vault that has never synced is repaired rather than rendered empty",
  /!st\.lastSync && session && !initialSyncAttempted && !isSyncing[\s\S]{0,160}syncVault\(\)/.test(statusFinished),
  statusFinished)
check("the repair is attempted once, so a failing sync cannot loop against the status refresh",
  /initialSyncAttempted = true[\s\S]{0,60}syncVault\(\)/.test(statusFinished)
    && statusFinished.indexOf("initialSyncAttempted = true")
       < statusFinished.indexOf("syncVault()"),
  statusFinished)
check("a new session gets a fresh attempt at the repair",
  /initialSyncAttempted = false/.test(bodyOf("dropVaultState"))
    && /initialSyncAttempted = false/.test(unlockSuccess),
  bodyOf("dropVaultState"))
check("bw's status already reports lastSync, so nothing new has to be parsed for it",
  /lastSync:\s*String\(st\.lastSync/.test(
    fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")),
  "parseStatus must expose lastSync")

// --- new-device verification, in the panel ----------------------------------
check("a confirmed device challenge collects the code in the panel, not in a terminal",
  /loginNeedsDeviceVerification[\s\S]{0,400}showDeviceCodeField\s*=\s*true/.test(loginOutput)
    && /deviceCodeField\.forceActiveFocus/.test(loginOutput),
  loginOutput)

// The interactive login's output is a prompt session, not one of bw's one-line
// refusals. Letting the ordinary detectors read it would send a device
// challenge back round as a two-step prompt.
check("the interactive attempt's result is read before any other detector",
  /if \(wasDeviceAttempt && !\(exitCode === 0 && out\.length > 10\)\)/.test(loginOutput)
    && loginOutput.includes("sanitizeInteractiveStderr")
    && loginOutput.indexOf("sanitizeInteractiveStderr")
       < loginOutput.indexOf("Model.loginNeedsDeviceVerification"),
  loginOutput)
check("the interactive flag is consumed once, so the next attempt is read normally",
  /deviceVerificationAttempt\s*=\s*false/.test(loginOutput)
    && /var wasDeviceAttempt = deviceVerificationAttempt/.test(loginOutput),
  loginOutput)
check("a timeout or an unanswerable prompt falls back to the terminal login",
  /exitCode === 124 \|\| Model\.loginPromptRanOutOfInput\(out, err\)[\s\S]{0,200}showDeviceCodeField\s*=\s*false/.test(loginOutput),
  loginOutput)
check("a rejected code keeps the field so it can be retried",
  /showDeviceCodeField\s*=\s*true[\s\S]{0,300}deviceCodeField\.forceActiveFocus/.test(loginOutput),
  loginOutput)
check("the failing code is dropped before its stderr is turned into a message",
  loginOutput.indexOf("sanitizeInteractiveStderr(err, loginDeviceCode)")
    < loginOutput.indexOf('loginDeviceCode = ""'),
  loginOutput)

check("the interactive login carries no code of its own into the ordinary detectors",
  /loginAttemptHadCode\s*=\s*false/.test(startDevice), startDevice)
check("the interactive flag is set before the process that reads it starts",
  startDevice.includes("deviceVerificationAttempt = true")
    && startDevice.includes("loginProc.running = true")
    && startDevice.indexOf("deviceVerificationAttempt = true")
       < startDevice.indexOf("loginProc.running = true"),
  startDevice)
check("the password is delivered to the interactive login the same way as any other",
  /writeAuthPassword\("login", loginPassword\)/.test(startDevice), startDevice)
check("a prewarmed ordinary login is stopped before the interactive one starts",
  /loginProc\.running[\s\S]{0,200}deviceVerificationPending\s*=\s*true[\s\S]{0,200}return/.test(submitDevice)
    && /deviceVerificationPending[\s\S]{0,120}startDeviceVerificationLogin/.test(panelSrc),
  submitDevice)
check("the device stage refuses to submit an empty code",
  /if \(!code\)[\s\S]{0,160}return/.test(submitDevice), submitDevice)

// authEnv() sets BW_NOINTERACTION unconditionally, so this path must not use
// it -- that is the whole difference between this login and every other.
check("only the interactive login runs without BW_NOINTERACTION",
  /deviceVerificationAttempt[\s\S]{0,260}deviceCodeEnvVar\(\)[\s\S]{0,80}return deviceEnv/.test(loginEnv)
    && !/deviceVerificationAttempt[\s\S]{0,200}authEnv\(/.test(loginEnv),
  loginEnv)
check("the device stage has its own submit and its own way out",
  /visible:\s*root\.showDeviceCodeField/.test(emailLoginUi)
    && /submitDeviceVerification\(\)/.test(emailLoginUi)
    && /Use Terminal Instead[\s\S]{0,300}launchTerminalLogin\(\)/.test(emailLoginUi),
  emailLoginUi)
check("the shared submit button stays out of the stages that do not use it",
  /visible:\s*!root\.show2faMethodPicker\s*&&\s*!root\.showDeviceCodeField/.test(emailLoginUi),
  emailLoginUi)

// --- focus must never be taken off a field being typed into ------------------
//
// A logout sets the status itself, then confirms it with `bw status` seconds
// later. That confirmation used to re-focus the login screen while the master
// password was being typed, moving the rest of it into the unmasked email
// field -- which the next submit would have sent as an email address.
check("a login screen that already has the cursor keeps it",
  /loginFieldHasFocus\(\)[\s\S]{0,40}return/.test(focusField)
    && /unlockFieldHasFocus\(\)[\s\S]{0,40}return/.test(focusField)
    && /!searchField\.activeFocus/.test(focusField),
  focusField)
check("the guard covers every field on the login screen, not just the visible stage",
  ["emailField", "loginPassField", "code2faField", "serverUrlField",
   "apiClientIdField", "apiClientSecretField", "apiMasterField"]
    .every((f) => new RegExp(`\\b${f}\\.activeFocus`).test(loginFieldFocus)),
  loginFieldFocus)
check("every field the guard names exists on the login screen",
  ["serverUrlField", "apiClientIdField", "apiClientSecretField", "apiMasterField"]
    .every((f) => new RegExp(`id:\\s*${f}\\b`).test(panelSrc)),
  "the guard must not silently reference a field that was never given an id")
check("closing the panel releases the cursor, so reopening is not read as typing",
  /abandonAuthSecrets\(\)[\s\S]{0,220}keyCatcher\.forceActiveFocus\(\)/.test(panelSrc),
  panelSrc.slice(panelSrc.indexOf("onOpenedChanged"), panelSrc.indexOf("onOpenedChanged") + 500))

// --- the two-step method question, in the panel -----------------------------
check("bw's provider question is answered by asking, before anything is guessed",
  /loginNeedsMethodChoice/.test(loginOutput)
    && loginOutput.indexOf("loginNeedsMethodChoice")
       < loginOutput.indexOf("loginNeedsSecondFactor")
    && /show2faMethodPicker\s*=\s*true/.test(loginOutput),
  loginOutput)
check("the dead-end provider message is told apart from the answerable one",
  /loginHasNoUsableProvider/.test(loginOutput)
    && loginOutput.indexOf("loginHasNoUsableProvider")
       < loginOutput.indexOf("loginNeedsMethodChoice"),
  loginOutput)

// shell.json holds one method for whichever account logged in last, so a
// remembered method that this account rejects is dropped and retried without,
// where one the user just chose is reported back to them.
check("a rejected method that was only remembered is dropped and retried untargeted",
  /!login2faMethodConfirmed[\s\S]{0,260}forgetTwoFactorMethod\(\)[\s\S]{0,200}login2faMethod\s*=\s*-1[\s\S]{0,200}submitLogin[\s\S]{0,60}return/.test(loginOutput),
  loginOutput)
check("a rejected method the user chose is reported as not configured, not retried",
  /login2faMethodConfirmed\s*\n?\s*\?\s*Model\.twoFactorMethodLabel\(loginAttemptMethod\)/.test(loginOutput)
    && /does not have/.test(loginOutput),
  loginOutput)

// The pick is sent on its own first. For Email that is what makes Bitwarden
// send the mail at all -- bw only posts the two-factor email when no token
// came with the request -- and for the others it validates the pick before
// anything is typed.
check("choosing a method submits it without a code",
  /login2faMethod\s*=\s*method/.test(chooseMethod)
    && /login2faMethodConfirmed\s*=\s*true/.test(chooseMethod)
    && /login2faCode\s*=\s*""/.test(chooseMethod)
    && chooseMethod.indexOf('login2faCode = ""') < chooseMethod.indexOf("submitLogin()"),
  chooseMethod)
check("only a method from the table can be chosen",
  /Model\.isTwoFactorMethod\(method\)[\s\S]{0,40}return/.test(chooseMethod), chooseMethod)

// A prewarmed process was started with whatever method was set at the time.
// Reusing it after the method changed would send the old one.
check("a changed method restarts the prewarmed login instead of reusing it",
  /login2faMethod/.test(loginSignature), loginSignature)
check("every email login attempt records the method it sent",
  (submitLogin.match(/loginAttemptMethod\s*=/g) || []).length >= 2
    && /loginAttemptMethod\s*=\s*login2faMethod/.test(prepareEmailLogin),
  prepareEmailLogin + "\n---\n" + submitLogin)

check("a method is remembered only once it has actually worked",
  /rememberTwoFactorMethod\(login2faMethod\)/.test(loginOutput)
    && loginOutput.indexOf("rememberTwoFactorMethod") > loginOutput.indexOf("exitCode === 0")
    && /Model\.isTwoFactorMethod\(method\)[\s\S]{0,40}return/.test(rememberMethod),
  loginOutput + "\n---\n" + rememberMethod)
check("the remembered method is written without the settings screen's flash",
  /writeSettingQuietly\("twoFactorMethods", next, "json"\)/.test(rememberMethod)
    && !/settingsFlash/.test(bodyOf("writeSettingQuietly")),
  rememberMethod)
check("the method is remembered against the account that just used it",
  /rememberTwoFactorMethodIn\(twoFactorMethodStore, loginEmail, method\)/.test(rememberMethod)
    && /rememberedTwoFactorMethodFor\(twoFactorMethodStore, loginEmail\)/.test(panelSrc),
  rememberMethod)
check("a stale method is forgotten only for the account that rejected it",
  /forgetTwoFactorMethodIn\(twoFactorMethodStore, loginEmail\)/.test(bodyOf("forgetTwoFactorMethod")),
  bodyOf("forgetTwoFactorMethod"))

// Unlock has always re-armed itself when the password could not be handed to
// bw; login left the button for the user to press again.
check("a failed password delivery retries the login once instead of asking for another click",
  /!loginPasswordRetryUsed[\s\S]{0,120}loginPasswordRetryUsed = true[\s\S]{0,220}Qt\.callLater\([\s\S]{0,80}submitLogin\)[\s\S]{0,40}return/.test(writerExited)
    && /errorMessage = "Could not deliver/.test(writerExited),
  writerExited)
check("the retry follows the login that was actually running",
  /retryDevice \? submitDeviceVerification : submitLogin/.test(writerExited), writerExited)
check("a delivered password restores the retry, so the next login gets its own",
  /exitCode === 0\)? \{[\s\S]{0,80}loginPasswordRetryUsed = false/.test(writerExited), writerExited)

check("the picker offers the model's methods rather than a list of its own",
  /visible:\s*root\.show2faMethodPicker[\s\S]{0,1400}Repeater\s*\{\s*\n\s*model:\s*Model\.twoFactorMethods\(\)/.test(emailLoginUi)
    && /chooseTwoFactorMethod\(modelData\.method\)/.test(emailLoginUi),
  emailLoginUi)
check("the code stage names the method it is collecting for and can go back to the question",
  /root\.login2faMethodLabel/.test(emailLoginUi)
    && /Change method[\s\S]{0,300}reopenTwoFactorMethodPicker\(\)/.test(emailLoginUi),
  emailLoginUi)

check("the terminal login stops being an aside once only it can finish the login",
  /root\.loginDeviceVerification[\s\S]{0,600}launchTerminalLogin\(\)/.test(terminalLoginUi)
    && /selected:\s*root\.loginDeviceVerification/.test(terminalLoginUi),
  terminalLoginUi)
check("abandoning credentials returns the next login to its first stage",
  /show2faField\s*=\s*false/.test(abandonAuth), abandonAuth)

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
