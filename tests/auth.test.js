#!/usr/bin/env node
// Tests for the commands that unlock the vault: unlock, email login, API key
// login. The property under test is the one that matters most here -- none of
// them may put a credential in an argv, because /proc/<pid>/cmdline is
// world-readable on a default Linux install and these are the credentials that
// open everything else.
//
//   node tests/auth.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.unlockCommand = unlockCommand
  exports.emailLoginCommand = emailLoginCommand
  exports.apiKeyLoginCommand = apiKeyLoginCommand
  exports.passwordEnvVar = passwordEnvVar
  exports.clientIdEnvVar = clientIdEnvVar
  exports.clientSecretEnvVar = clientSecretEnvVar
  exports.twoFactorCodeEnvVar = twoFactorCodeEnvVar
  exports.noInteractionEnvVar = noInteractionEnvVar
  exports.sessionEnvVar = sessionEnvVar
  exports.extractSessionToken = extractSessionToken
  exports.isSessionToken = isSessionToken
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

const unlock = Model.unlockCommand()
check("unlock takes no password argument at all",
  Model.unlockCommand.length === 0, `arity ${Model.unlockCommand.length}`)
check("unlock names the password env var rather than carrying a password",
  flat(unlock).includes("--passwordenv " + Model.passwordEnvVar()), flat(unlock))
check("unlock caps output and diagnostic stderr on the producer side",
  flat(unlock).includes("head -c") && flat(unlock).includes("exec 2>"), flat(unlock))

// The builders are called the way Panel.qml calls them: with what shapes the
// command, never with the secret itself.
const emailPlain = Model.emailLoginCommand("john@example.com", false, "")
const emailFull = Model.emailLoginCommand("john@example.com", true, SERVER)
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
check("emailLoginCommand takes (email, hasCode, serverUrl), not a password",
  Model.emailLoginCommand.length === 3, `arity ${Model.emailLoginCommand.length}`)
check("apiKeyLoginCommand takes only a server URL",
  Model.apiKeyLoginCommand.length === 1, `arity ${Model.apiKeyLoginCommand.length}`)

// A stray password argument must not find its way into the command anyway.
const emailWithStrayArgs = Model.emailLoginCommand("john@example.com", MASTER, SERVER)
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
const injected = Model.emailLoginCommand("a'; touch /tmp/pwned; '@b.c", false,
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

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
