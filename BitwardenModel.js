// BitwardenModel.js — Helper module for Bitwarden plugin.
// Pure JavaScript: CLI command constructors, output parsers, filtering, and CRUD builders.

.pragma library

const KEYRING_SERVICE = "qs-bitwarden-cli"
const KEYRING_ACCOUNT = "session"
const KEYRING_MASTER = "master_password"

// `secret-tool store` reads its secret from stdin until EOF, and Quickshell's
// Process.write() cannot close stdin -- writing a value alone leaves the process
// hanging forever and nothing is ever stored. So the secret is handed over in
// the environment (readable only by this user, same exposure as the BW_PASSWORD
// env var already used for `bw unlock`) and piped in by a shell that supplies
// the EOF. Never pass secrets in argv: that is world-readable in /proc.
const KEYRING_SECRET_ENV = "QSBW_SECRET"
const KEYRING_PIN = "pin_blob"
const PIN_ENV = "QSBW_PIN"

// PBKDF2 rounds for PIN unlock. Matches Bitwarden's own default and measures
// at ~300ms here -- unnoticeable once, punishing a few million times over.
const PIN_ITERATIONS = 600000

// Two thresholds, because the arithmetic is unforgiving and the choice is
// still the user's. Six digits is what we ask for: 10^6 candidates against
// 600k PBKDF2 rounds is a real cost to an attacker holding the ciphertext.
// Four is 10,000 candidates -- minutes of offline work -- so it is allowed but
// called out in red rather than quietly accepted.
const PIN_MIN_LENGTH = 4
const PIN_RECOMMENDED_LENGTH = 6

function keyringSecretEnvVar() {
  return KEYRING_SECRET_ENV
}

function keyringAttributes(account) {
  return " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(account)
}

function keyringStoreScript(label, account) {
  return "printf '%s' \"$" + KEYRING_SECRET_ENV + "\" | secret-tool store --label=" + shellQuote(label)
    + keyringAttributes(account)
}

function keyringLookupEntryCommand(account) {
  // secret-tool prints a newline after the stored value. Strip only that
  // transport delimiter: QML's String.trim() would also corrupt legitimate
  // leading or trailing spaces in a master password or client secret.
  var script = "stored=$(secret-tool lookup" + keyringAttributes(account)
    + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES + "); "
    + "__lookup_rc=$?; [ \"$__lookup_rc\" -eq 0 ] || exit \"$__lookup_rc\"; "
    + "printf '%s' \"$stored\""
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearEntryCommand(account) {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", account]
}

function keyringHasEntryCommand(account) {
  var script = "if secret-tool lookup" + keyringAttributes(account)
    + " >/dev/null 2>&1; then echo yes; else echo no; fi"
  return ["bash", "-c", script]
}

function shellQuote(value) {
  return "'" + String(value || "").replace(/'/g, "'\\''") + "'"
}

// The session token is never put on a command line. /proc/<pid>/cmdline is
// world-readable on a default Linux install, and the token grants full access
// to the unlocked vault. It travels in BW_SESSION instead, which bw reads
// natively; see sessionEnvVar() and the callers that set it.
const SESSION_ENV = "BW_SESSION"

// The same reasoning applies to the credentials that unlock the vault in the
// first place, and bw reads all three of these natively: BW_PASSWORD via
// --passwordenv, BW_CLIENTID and BW_CLIENTSECRET on `login --apikey`. So the
// master password and API key reach bw without appearing in any argv -- not
// bw's, and not the wrapping shell's. The builders below interpolate nothing
// secret into the script text; see authEnv() in Panel.qml for the values.
const PASSWORD_ENV = "BW_PASSWORD"
const CLIENT_ID_ENV = "BW_CLIENTID"
const CLIENT_SECRET_ENV = "BW_CLIENTSECRET"

// The one credential that cannot follow that rule: bw offers no environment
// option for the two-step code, so --code is the only way in and the code does
// land in bw's own argv. Carrying it in the environment still keeps it out of
// the wrapping shell's argv, which lives for the whole login chain rather than
// just the login process. A six-digit code is single-use and expires in
// seconds, which is why this residue is acceptable where a password would not
// be.
const TWOFACTOR_CODE_ENV = "QSBW_CODE"

// bw prompts on a tty it does not have here, so every auth command runs with
// interaction disabled and fails fast instead of hanging. The one exception is
// deviceVerificationLoginCommand(), which keeps the same guarantee by other
// means -- see the comment there.
const NOINTERACTION_ENV = "BW_NOINTERACTION"
// Bitwarden's SSH documentation names 2025.1.2 as the first supported
// release. Keep the ordinary vault usable on older CLI builds, but do not
// advertise SSH support from them.
const SSH_CLI_MIN_VERSION = "2025.1.2"
// Bitwarden CLI releases before this one throw on SSH key items whose
// decrypted public fields are absent, and the throw takes the whole
// `bw list items` read with it. The panel cannot repair that, but it can name
// the release that fixes it instead of leaving the user with a bare failure.
const SSH_MALFORMED_ITEM_FIX_VERSION = "2026.8.0"

// The new-device verification code. Like the two-step code it is single-use
// and short-lived, and unlike it, it never reaches an argv at all: it is read
// out of the environment by a printf inside the command and piped to bw.
const DEVICE_CODE_ENV = "QSBW_DEVICE_CODE"

function sessionEnvVar() {
  return SESSION_ENV
}

function passwordEnvVar() {
  return PASSWORD_ENV
}

function clientIdEnvVar() {
  return CLIENT_ID_ENV
}

function clientSecretEnvVar() {
  return CLIENT_SECRET_ENV
}

function twoFactorCodeEnvVar() {
  return TWOFACTOR_CODE_ENV
}

function noInteractionEnvVar() {
  return NOINTERACTION_ENV
}

function sshCliMinVersion() {
  return SSH_CLI_MIN_VERSION
}

function deviceCodeEnvVar() {
  return DEVICE_CODE_ENV
}

// Limits on stdout and stderr streams collected into the shell's memory space.
// Producer-side caps (via `head -c`) prevent unbounded buffering in QML StdioCollector.
var MAX_ITEMS_BYTES = 16 * 1024 * 1024       // 16 MB: large vault item list
var MAX_DETAIL_BYTES = 4 * 1024 * 1024      // 4 MB: single item with custom fields & notes
var MAX_SENDS_BYTES = 8 * 1024 * 1024       // 8 MB: send list
var MAX_COLLECTIONS_BYTES = 2 * 1024 * 1024 // 2 MB: org collections
var MAX_FOLDERS_BYTES = 2 * 1024 * 1024     // 2 MB: folder list
var MAX_ORGS_BYTES = 2 * 1024 * 1024        // 2 MB: organizations list
var MAX_STATUS_BYTES = 64 * 1024            // 64 KB: status json
var MAX_TOKEN_BYTES = 4096                  // 4 KB: session token / password / TOTP
var MAX_HANDOFF_BYTES = 4096                // 4 KB: session handoff file
var MAX_ASSOC_BYTES = 1024 * 1024           // 1 MB: learned associations file
var MAX_STDERR_BYTES = 8192                 // 8 KB: diagnostic stderr output
var MAX_MISC_BYTES = 64 * 1024              // 64 KB: create/edit/delete responses

// Attachment bytes go to disk rather than into the shell's memory, so the
// ceilings that matter there are the size of the file itself, how long the
// transfer may run, and leaving the disk with room to spare afterwards.
var MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024        // 512 MB: Bitwarden's own per-file ceiling
var ATTACHMENT_TIMEOUT_SECS = 900                   // 15 min: a stalled transfer must not hold the queue
var ATTACHMENT_FREE_SLACK_BYTES = 64 * 1024 * 1024  // 64 MB: never fill the disk to the last byte

// `head -c` closes the pipe the moment the cap is reached, so a capped pipeline
// exits with head's status -- success -- and every bw failure behind it would be
// reported to the panel as a success. `pipefail` puts the producer's status back.
// The one status it must not forward is 141: that is the SIGPIPE the cap itself
// delivers when it truncates an oversized but otherwise healthy stream, which is
// the limit doing its job rather than the command failing.
function cappedScript(script, maxStderrBytes) {
  var out = ""
  if (maxStderrBytes) {
    out += "exec 2> >(head -c " + Number(maxStderrBytes) + " >&2); "
  }
  out += "set -o pipefail; " + script
  // `case` rather than `[ ... ] && ...`, which reports failure on no match and
  // would trip `set -e` in the scripts that use it.
  out += "\n__rc=$?\ncase \"$__rc\" in 141) __rc=0 ;; esac\nexit \"$__rc\""
  return out
}

// Every id below is the server's to choose, and quoting it defends against the
// shell rather than against bw's own option parser -- `bw get item --help`
// prints help rather than looking anything up. `--` ends the options, so an id
// shaped like a flag is read as the id it is. Flags that belong to us go before
// it, since everything after it is a positional.
function buildCappedCommand(args, maxStdoutBytes, maxStderrBytes) {
  var inner = "bw"
  if (args && args.length > 0) {
    for (var i = 0; i < args.length; i++) {
      var arg = String(args[i])
      if (/^[a-zA-Z0-9_\-\.\/]+$/.test(arg)) {
        inner += " " + arg
      } else {
        inner += " " + shellQuote(arg)
      }
    }
  }
  if (maxStdoutBytes) {
    inner += " | head -c " + Number(maxStdoutBytes)
  }
  return ["bash", "-c", cappedScript(inner, maxStderrBytes)]
}

// A bw session key is base64: 88 characters for the 64 bytes bw mints. Only
// something shaped like one is accepted, and anything else yields "" rather
// than the raw input.
//
// The old last-resort `return s` meant any non-empty text became a "session":
// a bw error message, or whatever happened to be sitting in the handoff file,
// would be written to the keyring and the panel would declare itself unlocked
// on the strength of it. Both callers already treat "" as failure.
var SESSION_TOKEN_RE = /^[A-Za-z0-9+/=_-]{32,}$/

function isSessionToken(value) {
  return SESSION_TOKEN_RE.test(String(value || "").trim())
}

function extractSessionToken(raw) {
  var s = String(raw || "").trim()

  // `export BW_SESSION="..."`, which is what bw prints without --raw.
  var match = s.match(/BW_SESSION="?([^"\n\r]+)"?/)
  if (match && match[1] && isSessionToken(match[1])) {
    return match[1].trim()
  }

  // --raw prints the key alone, but stray output can share the stream.
  var lines = s.split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (isSessionToken(line)) {
      return line
    }
  }
  return ""
}

// -------------------------------------------------------------------------
// Vault generation
// -------------------------------------------------------------------------
//
// Nothing cancels a `bw` that is already running. By the time the panel locks
// the vault, a `bw list items` started a second earlier is long past the point
// where the session mattered: it will finish, print the whole vault, and the
// completion handler will put it back into a panel that has just thrown it
// away. The list carries each login's password in its raw object, so the
// contents of a vault the user had just locked went on living in the shell for
// the rest of the desktop session -- and a logout followed by a login to a
// second account showed the first account's items until the new list landed,
// close enough to copy from.
//
// So every reader records the vault generation it started under, and the
// generation moves on whenever the vault changes hands: locked, logged out of,
// unlocked again. A result from a previous generation is discarded rather than
// rendered. Exit status is no help here -- the command genuinely succeeded;
// the vault it succeeded against is the thing that is gone.
function vaultReadIsStale(startedEpoch, currentEpoch, hasSession) {
  if (!hasSession) return true
  return Number(startedEpoch) !== Number(currentEpoch)
}

// -------------------------------------------------------------------------
// Collector scrubbing
// -------------------------------------------------------------------------
//
// Refusing a stale answer is not the same as forgetting it. A StdioCollector
// keeps whatever its process last printed for as long as that process is not
// started again -- `text` is read-only, there is no clear(), and nothing in
// Quickshell drops the buffer when the panel stops reading it. So every secret
// that has ever come back through a pipe is still in the shell process after
// the vault locks: the session key from the handoff file and from the keyring,
// the master password from the PIN and fingerprint lookups, both halves of a
// login or unlock, the whole item list with each login's password in its raw
// object, an item detail, a live TOTP. dropVaultSecrets() empties the QML
// properties those values were copied into and leaves the originals sitting
// behind them, which for a shell that lives as long as the desktop session is
// the residue it exists to prevent.
//
// The buffer IS replaced when the process next starts, so the way to empty one
// is to run something through it that prints nothing. That command doubles as
// the marker for the run: a handler that finds it on its own process knows the
// empty string it just received is a scrub rather than an answer, so nothing
// needs a flag whose lifetime someone has to get right.
var SCRUB_COMMAND = ["bash", "-c", ""]

function scrubCommand() {
  return SCRUB_COMMAND.slice()
}

function isScrubCommand(cmd) {
  if (!cmd || Number(cmd.length) !== SCRUB_COMMAND.length) return false
  for (var i = 0; i < SCRUB_COMMAND.length; i++) {
    if (String(cmd[i]) !== SCRUB_COMMAND[i]) return false
  }
  return true
}

// How often the panel comes back for a process that was still running when the
// vault locked. Its buffer cannot be scrubbed while it is being written. There
// is deliberately no retry limit: a process that exits late can otherwise
// leave its final output resident until an unrelated future run that may never
// happen.
var SCRUB_RETRY_MS = 1000

function scrubRetryMs() { return SCRUB_RETRY_MS }

// One pass over the scrub queue. Returns what to do with each process and what
// is left to come back for, so the walk itself can be tested without a running
// shell: `start` is scrubbed now, `waiting` is asked again next tick, and
// anything in neither is done and drops out of the queue.
//
// A process that is running is left alone -- stomping its command mid-flight
// would abandon a read the panel is still waiting on -- and one already
// carrying the scrub command has been scrubbed and needs nothing further.
function scrubPass(procs) {
  var start = []
  var waiting = []
  for (var i = 0; i < (procs || []).length; i++) {
    var p = procs[i]
    if (!p) continue
    if (p.running) { waiting.push(p); continue }
    if (isScrubCommand(p.command)) continue
    start.push(p)
    waiting.push(p)
  }
  return { start: start, waiting: waiting }
}

// Record completion before a handler is allowed to reuse the Process. The
// command property describes the newest run, so inspecting it on the next
// timer tick cannot prove that an earlier scrub finished.
function finishScrub(procs, finished) {
  var remaining = []
  for (var i = 0; i < (procs || []).length; i++) {
    if (procs[i] && procs[i] !== finished) remaining.push(procs[i])
  }
  return remaining
}

// -------------------------------------------------------------------------
// CLI Commands
// -------------------------------------------------------------------------

function statusCommand() {
  return buildCappedCommand(["status"], MAX_STATUS_BYTES)
}

// -------------------------------------------------------------------------
// Authentication prewarming
// -------------------------------------------------------------------------
//
// Starting the bw process is a substantial part of unlock/login latency. A
// password FIFO lets bw complete that bootstrap while the user is still
// typing: bw opens the FIFO through --passwordfile and waits there, then the
// panel writes the password only after explicit submission.
//
// The FIFOs live in XDG_RUNTIME_DIR (private tmpfs owned by this login), never
// in /tmp or the plugin directory. Each command removes its FIFO on every exit
// path. There is deliberately one fixed FIFO per auth flow: the panel owns one
// Process for each and never runs two attempts of the same kind concurrently.
var RUNTIME_SUBDIR = "qs-bitwarden-cli"

function authPasswordFifoName(channel) {
  if (channel === "unlock") return "unlock-password.fifo"
  if (channel === "login") return "login-password.fifo"
  return ""
}

function supervisedProcessPrelude(cleanupCommand) {
  var script = "__auth_job=''; "
  script += "__auth_cleanup() { trap - EXIT HUP INT TERM; "
  script += "if [ -n \"${__auth_job:-}\" ]; then "
  script += "kill -TERM -- \"-$__auth_job\" 2>/dev/null || true; "
  script += "wait \"$__auth_job\" 2>/dev/null || true; fi; "
  if (cleanupCommand) script += cleanupCommand + "; "
  script += "}; "
  script += "trap '__auth_cleanup' EXIT; "
  script += "trap '__auth_cleanup; exit 143' HUP INT TERM; "
  return script
}

function authFifoPrelude(channel) {
  var fifoName = authPasswordFifoName(channel)
  if (!fifoName) return ""

  // Check an existing directory before using it so a symlink cannot redirect
  // the FIFO outside the per-login runtime directory. XDG_RUNTIME_DIR itself is
  // supplied and protected by the login manager; absence is a hard failure.
  var script = "test -n \"${XDG_RUNTIME_DIR:-}\" || exit 1; "
  script += "__auth_dir=\"$XDG_RUNTIME_DIR/" + RUNTIME_SUBDIR + "\"; "
  script += "if [ -e \"$__auth_dir\" ]; then "
  script += "[ -d \"$__auth_dir\" ] && [ ! -L \"$__auth_dir\" ] || exit 1; "
  script += "else (umask 077 && mkdir -- \"$__auth_dir\") || exit 1; fi; "
  script += "chmod 700 -- \"$__auth_dir\" || exit 1; "
  script += "__auth_fifo=\"$__auth_dir/" + fifoName + "\"; "
  script += "rm -f -- \"$__auth_fifo\"; "
  script += "mkfifo -m 600 -- \"$__auth_fifo\" || exit 1; "
  // QProcess terminates only this wrapper. Run bw and its output cap as a
  // separate process group so a cancelled panel can stop the FIFO-blocked
  // child immediately instead of leaving it orphaned behind the shell.
  script += supervisedProcessPrelude("rm -f -- \"$__auth_fifo\"")
  return script
}

function supervisedProcessCommand(command) {
  var script = supervisedProcessPrelude("")
  script += supervisedProcessRun(command)
  return ["bash", "-c", script]
}

function supervisedProcessRun(command) {
  // Disarm the EXIT cleanup after a normal wait. Otherwise the trap sends a
  // redundant signal to a process-group ID that has already been reaped and
  // could, in the tiny gap before shell exit, have been reused.
  var script = "set -m; (" + cappedScript(command, MAX_STDERR_BYTES) + ") & "
  script += "__auth_job=$!; wait \"$__auth_job\"; __auth_rc=$?; "
  script += "__auth_job=''; exit \"$__auth_rc\""
  return script
}

function supervisedAuthCommand(channel, command) {
  var script = authFifoPrelude(channel)
  // `set -m` gives the background subshell its own process group. The wrapper
  // then waits with bash's interruptible `wait` builtin, allowing the signal
  // traps above to run immediately even while bw is blocked opening the FIFO.
  script += supervisedProcessRun(command)
  return ["bash", "-c", script]
}

function unlockPrewarmCommand() {
  var command = "bw unlock --passwordfile \"$__auth_fifo\" --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("unlock", command)
}

// The two-step methods bw is able to use, in the order bw itself lists them.
// This is the whole set, not a selection from it: getSupportedProviders()
// offers Duo and Organization Duo only if supportsDuo() and WebAuthn only if
// supportsWebAuthn(), and the CLI's platform layer returns false for both, so
// whatever an account has configured, the providers bw can act on are always a
// subset of these three. A picker over them is therefore complete, which
// matters because bw exposes no way to ask which ones an account actually has:
// it keeps that list in a "memory" StateDefinition that dies with the process,
// `bw serve` has no login route, and no flag reports it.
var TWO_FACTOR_METHODS = [
  { method: 0, label: "Authenticator app",
    hint: "The rotating 6-digit code from your authenticator." },
  { method: 3, label: "YubiKey OTP",
    hint: "Touch the key to type its one-time password." },
  { method: 1, label: "Email",
    hint: "Bitwarden sends a code to your login address when you choose this." }
]

function twoFactorMethods() {
  var out = []
  for (var i = 0; i < TWO_FACTOR_METHODS.length; i++) {
    var entry = {}
    for (var k in TWO_FACTOR_METHODS[i]) entry[k] = TWO_FACTOR_METHODS[i][k]
    out.push(entry)
  }
  return out
}

// --method is the one part of the login command that is neither quoted nor
// carried in the environment, because bw wants a bare integer. Nothing outside
// this table may reach it, so membership -- not shape -- is the test.
function isTwoFactorMethod(method) {
  for (var i = 0; i < TWO_FACTOR_METHODS.length; i++) {
    if (TWO_FACTOR_METHODS[i].method === method) return true
  }
  return false
}

function twoFactorMethodLabel(method) {
  for (var i = 0; i < TWO_FACTOR_METHODS.length; i++) {
    if (TWO_FACTOR_METHODS[i].method === method) return TWO_FACTOR_METHODS[i].label
  }
  return ""
}

// Two-step methods belong to an account, not to a machine. A single remembered
// method was wrong for anyone with more than one vault: signing into the second
// account sent the first account's method, which that account rejects, and the
// stale-method recovery then spent a round trip discovering it. Keyed by email,
// each account answers the question once and keeps its own answer.
var MAX_REMEMBERED_ACCOUNTS = 10

// Bitwarden treats the login address case-insensitively, so the key has to as
// well or the same account remembers itself twice.
function twoFactorAccountKey(email) {
  return String(email || "").trim().toLowerCase()
}

// shell.json is not validated by anything that writes it, and a remembered
// method is read straight back into an argv, so it is checked against the table
// on the way in as well as on the way out. Anything else is "not remembered",
// which costs one picker rather than a malformed command.
function rememberedTwoFactorMethodFor(store, email) {
  var key = twoFactorAccountKey(email)
  if (!key || !store || typeof store !== "object") return -1
  var raw = store[key]
  // The same reason intSetting() does not lean on Number() alone: it reads
  // null, "" and false as 0, and 0 is Authenticator, so an absent entry would
  // come back as a confident answer.
  var m = (typeof raw === "number" || (typeof raw === "string" && String(raw).trim() !== ""))
    ? Math.floor(Number(raw))
    : NaN
  return isFinite(m) && isTwoFactorMethod(m) ? m : -1
}

// Rebuilt rather than mutated, so whatever else is in that key -- a hand-edit,
// an entry from a newer version, an unreadable value -- cannot survive into
// what gets written back. Bounded, because this is a config file and not a
// history: past the cap the oldest surviving entries are simply not copied,
// which costs their accounts one picker each.
function rememberTwoFactorMethodIn(store, email, method) {
  var key = twoFactorAccountKey(email)
  if (!key || !isTwoFactorMethod(method)) return null
  var next = {}
  var kept = 0
  if (store && typeof store === "object") {
    for (var k in store) {
      var other = twoFactorAccountKey(k)
      if (!other || other === key) continue
      var existing = rememberedTwoFactorMethodFor(store, k)
      if (existing < 0) continue
      if (kept >= MAX_REMEMBERED_ACCOUNTS - 1) continue
      next[other] = existing
      kept++
    }
  }
  next[key] = method
  return next
}

function forgetTwoFactorMethodIn(store, email) {
  var key = twoFactorAccountKey(email)
  if (!key || !store || typeof store !== "object") return null
  var next = {}
  for (var k in store) {
    var other = twoFactorAccountKey(k)
    if (!other || other === key) continue
    var existing = rememberedTwoFactorMethodFor(store, k)
    if (existing >= 0) next[other] = existing
  }
  return next
}

function emailLoginPrewarmCommand(email, hasCode, serverUrl, method) {
  var command = ""

  if (serverUrl && serverUrl.trim()) {
    command += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  command += "bw login " + shellQuote(email) + " --passwordfile \"$__auth_fifo\""
  if (isTwoFactorMethod(method)) command += " --method " + String(method)
  if (hasCode) command += " --code \"$" + TWOFACTOR_CODE_ENV + "\""
  command += " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("login", command)
}

// bw 2026.2.0 answers two different challenges with this one bare sentence,
// and which one it is decides whether this panel can answer it at all. See
// loginNeedsDeviceVerification().
// How long the one interactive login may run. It is answering a prompt with a
// code the user has already typed, so it is a couple of server round trips --
// not a person thinking. The bound exists so a login that reaches no prompt at
// all cannot sit holding the master password until the panel is closed.
var DEVICE_VERIFICATION_TIMEOUT_S = 60

// The only login that runs with bw's prompts enabled.
//
// New-device verification is the one challenge bw accepts from no flag. Its
// token comes from an inquirer prompt and from nothing else, so stdin is the
// only way to answer it, and a login that cannot answer it cannot finish here
// at all.
//
// Piping rather than opening a pty is what keeps BW_NOINTERACTION's guarantee
// after taking BW_NOINTERACTION away. That flag was there so bw fails fast
// instead of blocking on a prompt nobody can see, and a pipe ends: measured
// against the inquirer 8.2.6 that bw bundles, a prompt with nothing left to
// read throws ERR_USE_AFTER_CLOSE and the process exits, and a second prompt
// after the single line supplied here does the same. So an unexpected prompt
// still ends the login rather than hanging it, which is the property that
// mattered. `timeout` covers the remainder: a bw that never prompts at all.
//
// The code itself is read from the environment by printf, so unlike --code it
// reaches no argv, not even bw's.
function deviceVerificationLoginCommand(email, serverUrl, method) {
  var command = ""

  if (serverUrl && serverUrl.trim()) {
    command += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  command += "printf '%s\\n' \"$" + DEVICE_CODE_ENV + "\" | "
  command += "timeout " + DEVICE_VERIFICATION_TIMEOUT_S + "s bw login " + shellQuote(email)
    + " --passwordfile \"$__auth_fifo\""
  if (isTwoFactorMethod(method)) command += " --method " + String(method)
  command += " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("login", command)
}

// inquirer's own failure when it is asked for input that is not coming. It
// means bw reached a prompt this login did not expect, which is a reason to
// hand the login to a terminal rather than anything to show the user.
function loginPromptRanOutOfInput(stdoutText, stderrText) {
  var combined = String(stderrText || "") + "\n" + String(stdoutText || "")
  return /ERR_USE_AFTER_CLOSE|readline was closed/.test(combined)
}

// An interactive bw draws its prompt on stderr and echoes every keystroke back
// with the cursor movement to match, so the captured stream holds the code and
// a great deal of noise. None of that is an error message. Strip the escape
// sequences, drop the lines inquirer drew, and redact the code itself, so what
// is left is whatever bw actually had to say.
function sanitizeInteractiveStderr(raw, secret) {
  var text = String(raw || "")
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "")
    .replace(/\r/g, "\n")
  var code = String(secret || "").trim()
  var parts = text.split("\n")
  var kept = []
  for (var i = 0; i < parts.length; i++) {
    var line = parts[i].trim()
    if (!line) continue
    if (line.charAt(0) === "?") continue
    if (code && line.indexOf(code) !== -1) continue
    kept.push(line)
  }
  // A crashing node prints a stack trace, which is not an error message
  // either. Whatever survives is only ever shown as one line of context.
  return kept.join(" ").slice(0, 300)
}

// A failed login is the hardest thing in this plugin to diagnose: it happens on
// someone else's machine, against someone else's account, and the panel shows a
// curated message rather than whatever bw said. This reports the shape of an
// attempt and never its content -- the session token is counted, not printed,
// and stderr goes through the same sanitiser the panel uses before it shows
// anything, with no code to redact because none is passed.
function loginDiagnostic(stdoutText, stderrText, exitCode, branch) {
  return "exit=" + String(exitCode)
    + " stdout=" + String(stdoutText || "").length + "b"
    + " branch=" + String(branch || "?")
    + " stderr=" + JSON.stringify(sanitizeInteractiveStderr(stderrText, "").slice(0, 200))
}

function loginCodeIsRequiredChallenge(stdoutText, stderrText) {
  var combined = (String(stderrText || "") + "\n" + String(stdoutText || "")).toLowerCase()
  return /(?:^|[\r\n])\s*code\s+is\s+required[.!]?\s*(?=$|[\r\n])/.test(combined)
}

function loginNeedsSecondFactor(stdoutText, stderrText) {
  var combined = (String(stderrText || "") + "\n" + String(stdoutText || "")).toLowerCase()
  return /(?:two[ _-]?(?:step|factor)|2fa|verification[ _-]?code)/.test(combined)
    || loginCodeIsRequiredChallenge(stdoutText, stderrText)
}

// New-device verification is the challenge --code cannot answer. bw's login
// command takes a two-step token from --code and reads it only in its
// requiresTwoFactor branch; the requiresDeviceVerification branch that follows
// takes its OTP from an inquirer prompt and nothing else, so BW_NOINTERACTION
// leaves it with an empty token and it returns "Code is required." again. bw
// 2026.2.0 offers no flag for that token -- login accepts --method, --code,
// --sso, --apikey, --passwordenv and --passwordfile, and none of them reach it.
//
// The two challenges are indistinguishable on a first attempt: both come back
// as that same sentence. They separate on the second. A login that carried a
// code and still says the code is required did not have its code rejected --
// a rejected two-step token says so ("Two-step token is invalid") -- it was
// never read. That attempt is the evidence, so the caller passes it in.
function loginNeedsDeviceVerification(stdoutText, stderrText, codeWasSent) {
  if (!codeWasSent) return false
  return loginCodeIsRequiredChallenge(stdoutText, stderrText)
}

// bw's answer when an account has more than one usable provider and nothing
// told it which one to use. It reads like a failure but it is a question: bw
// would have shown a menu here if it had a terminal to show one on, and
// --method is the only answer it accepts. Guessing at it is what produces a
// real failed attempt, so the panel asks instead.
function loginNeedsMethodChoice(stdoutText, stderrText) {
  var combined = (String(stderrText || "") + "\n" + String(stdoutText || "")).toLowerCase()
  return /no\s+provider\s+selected/.test(combined)
}

// The dead end next to it: the account's two-step methods are all ones this
// client cannot perform -- a passkey or Duo, typically. No --method answers
// this and no terminal helps, because it is the CLI that lacks the support,
// so the only way in is an API key.
function loginHasNoUsableProvider(stdoutText, stderrText) {
  var combined = (String(stderrText || "") + "\n" + String(stdoutText || "")).toLowerCase()
  return /no\s+providers\s+available\s+for\s+this\s+client/.test(combined)
}

// The password remains in BW_PASSWORD, inherited only by this short-lived
// writer. The nested shell script is a literal in argv (it contains the
// variable name, not its value), and timeout prevents a dead reader from
// leaving the writer blocked forever between the FIFO check and open.
function authPasswordWriteCommand(channel) {
  var fifoName = authPasswordFifoName(channel)
  if (!fifoName) return []

  var script = "test -n \"${XDG_RUNTIME_DIR:-}\" || exit 1; "
  script += "__auth_dir=\"$XDG_RUNTIME_DIR/" + RUNTIME_SUBDIR + "\"; "
  script += "[ -d \"$__auth_dir\" ] && [ ! -L \"$__auth_dir\" ] || exit 1; "
  script += "__auth_fifo=\"$__auth_dir/" + fifoName + "\"; "
  script += "for __auth_wait in {1..200}; do "
  script += "if [ -p \"$__auth_fifo\" ] && [ ! -L \"$__auth_fifo\" ]; then "
  script += "exec timeout 10s bash -c 'printf \"%s\" \"$" + PASSWORD_ENV + "\" > \"$1\"' _ \"$__auth_fifo\"; "
  script += "fi; sleep 0.01; done; exit 1"
  return ["bash", "-c", script]
}

// `hasCode` rather than the code itself -- only whether the flag is present
// shapes the command; the value comes from the environment.
// The custom-server field is where the master password is about to be sent,
// and `bw config server` takes whatever it is given. Two things it must not be
// allowed to be.
//
// It must not be a scheme bw will not speak. Anything that is not http or
// https is a typo at best, and `bw config server` accepting it quietly means
// the failure surfaces later as an unexplained login error.
//
// It must not be plaintext http to somewhere off this machine. That is the
// master password and every vault secret behind it, in the clear, to whoever
// is on the path -- and the field is a plausible thing to talk someone into
// pasting. Loopback is the exception, because there is no path: a Vaultwarden
// on 127.0.0.1 or an SSH tunnel to one is a normal way to run this.
//
// Returns "" for a URL that is fine to use (including an empty one, which
// means the official server), or the reason it was refused.
var SERVER_SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//
var LOOPBACK_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i
var BITWARDEN_US_SERVER = "https://vault.bitwarden.com"
var BITWARDEN_EU_SERVER = "https://vault.bitwarden.eu"

// Both cloud regions are explicit because bw persists its last configured
// server. An empty US override after an EU login would keep sending the next
// login to EU. Unknown UI state fails closed to US instead of accidentally
// sending credentials to a stale custom URL.
function loginServerUrlFor(region, customUrl) {
  var choice = String(region || "").toLowerCase()
  if (choice === "eu") return BITWARDEN_EU_SERVER
  if (choice === "custom") return String(customUrl || "").trim()
  return BITWARDEN_US_SERVER
}

function validateServerUrl(raw) {
  var url = String(raw || "").trim()
  if (!url) return ""

  // Node's WHATWG URL parser (used by bw) treats backslashes as path
  // separators for http(s), while the small parser below would leave one in
  // the authority. That disagreement can turn
  // `http://evil.example\@localhost` into "localhost" here but evil.example
  // on the wire, bypassing the plaintext-password protection.
  if (url.indexOf("\\") !== -1) return "Server URL must not contain backslashes"

  var m = url.match(SERVER_SCHEME_RE)
  if (!m) return "Server URL must start with https:// (or http:// for localhost)"

  var scheme = m[1].toLowerCase()
  if (scheme !== "http" && scheme !== "https") {
    return "Server URL must be http or https, not " + scheme + ":"
  }

  // Host is everything up to the first /, ? or #, minus any userinfo.
  var rest = url.slice(m[0].length)
  var host = rest.split(/[\/?#]/)[0]
  var at = host.lastIndexOf("@")
  if (at !== -1) host = host.slice(at + 1)
  host = host.replace(/:\d*$/, "")
  if (!host) return "Server URL is missing a host name"

  if (scheme === "http" && !LOOPBACK_HOST_RE.test(host)) {
    return "Refusing to send your master password over plain http to " + host
      + ". Use https:// (http is allowed only for localhost)."
  }

  return ""
}

// `login --apikey` authenticates but does not unlock, so the master password
// is still needed for the second step. Both come from the environment.
function apiKeyLoginCommand(serverUrl) {
  var script = ""

  if (serverUrl && serverUrl.trim()) {
    script += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  script += "bw login --apikey >/dev/null 2>&1 && "
  script += "bw unlock --passwordenv " + PASSWORD_ENV + " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedProcessCommand(script)
}

// -------------------------------------------------------------------------
// Terminal login handoff
// -------------------------------------------------------------------------
//
// `bw login` in a terminal covers what the in-panel form cannot -- SSO, Duo, a
// hardware key -- but it used to leave the panel none the wiser, so a
// successful terminal login was immediately followed by unlocking all over
// again. The terminal now writes its session key to a file the panel reads
// once and deletes.
//
// The key is a secret at rest, so it goes to XDG_RUNTIME_DIR: user-only tmpfs,
// never written to disk, and cleared when the session ends. `--raw` prints only
// the key on stdout while bw's prompts stay on stderr, so redirecting it keeps
// the login interactive.

// No fallback if XDG_RUNTIME_DIR is missing. It is set by pam_systemd at login
// and is a precondition of the systemd user manager that `omarchy launch
// terminal` runs the terminal under, so it cannot realistically be absent --
// and a `${XDG_RUNTIME_DIR:-/tmp}` default would quietly turn that impossible
// case into "write the session key somewhere world-writable", where another
// user could have pre-created the directory. Fail closed instead.
var HANDOFF_BASENAME = "session-handoff"

// `mode` is "login" when logged out and "unlock" when merely locked. The panel
// already knows which, so this does not probe with `bw status` first -- that
// probe measured at ~3.3s, spent before the user was even shown a prompt.
function terminalLoginCommand(mode, serverUrl) {
  var verb = (mode === "unlock") ? "unlock" : "login"
  var configureServer = (verb === "login" && serverUrl && serverUrl.trim())
    ? "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
    : ""
  var inner = "set -u; "
    + "d=\"${XDG_RUNTIME_DIR:?no XDG_RUNTIME_DIR -- refusing to write a session key}/"
    + RUNTIME_SUBDIR + "\"; f=\"$d/" + HANDOFF_BASENAME + "\"; "
    // umask before mkdir, so the directory is born 700 rather than created
    // world-readable and narrowed a moment later. The chmod then covers a
    // directory that already existed, and both are checked: a chmod that
    // fails means the directory is not ours, which is not a place for a key.
    + "umask 077; if [ -e \"$d\" ]; then "
    + "[ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 1; "
    + "else mkdir -p \"$d\" || exit 1; fi; chmod 700 \"$d\" || exit 1; "
    // Remove a stale entry before opening the output path, so a pre-created
    // symlink is unlinked rather than followed by shell redirection.
    + "rm -f -- \"$f\" || exit 1; "
    + configureServer
    + "if bw " + verb + " --raw > \"$f\" && [ -s \"$f\" ]; then "
    // Bring the panel back itself rather than making the user find it again.
    // Only the method name crosses this boundary; the key never does.
    + "omarchy-shell io.github.elevate08.qs-bitwarden-cli open >/dev/null 2>&1 || true; "
    + "echo; echo 'Done. Returning to the Bitwarden panel...'; sleep 1; "
    + "else rm -f \"$f\"; echo; echo 'Not completed -- nothing was handed to the panel.'; "
    + "read -p 'Press enter to close...'; fi"
  var script = "omarchy launch terminal -e bash -c " + shellQuote(inner)
    + " || alacritty -e bash -c " + shellQuote(inner)
  return ["bash", "-c", script]
}

// How long after launching a terminal login the panel will still accept what
// that terminal left behind. Long enough for a real login -- a password, a
// push to a phone, a hardware key tap, and bw's own round trip -- and short
// enough that the window is not simply always open.
var HANDOFF_WINDOW_MS = 10 * 60 * 1000

function handoffWindowMs() {
  return HANDOFF_WINDOW_MS
}

// Whether a handoff written now would still be accepted. `startedAt` is when
// the panel launched the terminal, or 0 if it never did.
// How long a login that is waiting on a second factor survives the panel being
// closed.
//
// It has to survive it at all, because a code that arrives by email cannot be
// read without leaving the panel, and a login that forgets everything the
// moment it loses focus is one that can never be completed by email -- not for
// two-step email codes and not for new-device verification, which is emailed
// too. The panel dropping its state on close is right for every other case and
// wrong for this one.
//
// Shorter than the terminal handoff window, because what is being held over is
// the master password rather than a session key: long enough to open a mail
// client and read six digits, not long enough to be somewhere the password
// lives.
var SECOND_FACTOR_WINDOW_MS = 5 * 60 * 1000

function secondFactorWindowOpen(startedAt, now) {
  var began = Number(startedAt)
  if (!isFinite(began) || began <= 0) return false
  var elapsed = Number(now) - began
  // Measured on the wall clock rather than a monotonic timer, for the reason
  // the auto-lock is: a suspended machine stops CLOCK_MONOTONIC, and a login
  // left pending across a lid close must expire on the time that actually
  // passed. A clock stepped backwards closes the window rather than reopening
  // it, the same way handoffWindowOpen() treats it.
  if (!isFinite(elapsed) || elapsed < 0) return false
  return elapsed <= SECOND_FACTOR_WINDOW_MS
}

function handoffWindowOpen(startedAt, now) {
  var began = Number(startedAt)
  if (!isFinite(began) || began <= 0) return false
  var elapsed = Number(now) - began
  // A clock stepped backwards leaves a negative elapsed time. That is not
  // evidence the login was recent; it is evidence the clock moved, so the
  // window closes rather than reopening for ten minutes.
  if (!isFinite(elapsed) || elapsed < 0) return false
  return elapsed <= HANDOFF_WINDOW_MS
}

// Read-once: the key is consumed by the panel and the file removed, so it does
// not linger for the next process that goes looking.
//
// `expecting` is the whole point of this signature. The read runs on every
// status refresh, and it used to consume whatever was at that path regardless
// of whether the panel had ever asked for a terminal login -- so anything able
// to write the file could hand the panel a session key at a moment of its own
// choosing, and the panel would adopt it and write it to the keyring. The
// runtime directory is 0700, so that is one of this user's own processes
// rather than a stranger, and this was never a privilege boundary. It is a
// window that had no reason to be open: a key is only ever expected in the
// minutes after *we* launched a terminal, so those are the only minutes it is
// read in.
//
// Unexpected is not the same as ignored. The file is removed either way --
// leaving a live session key sitting in the runtime directory because nobody
// was expecting it is the worse of the two outcomes, and a legitimate login
// the user abandoned halfway leaves exactly that.
//
// A missing runtime dir means "nothing was handed over" and exits quietly
// rather than erroring into the shell log the way the write side deliberately
// does.
function sessionHandoffReadCommand(expecting) {
  var script = "d=\"${XDG_RUNTIME_DIR:-}\"; [ -n \"$d\" ] || exit 0; "
    + "d=\"$d/" + RUNTIME_SUBDIR + "\"; "
    + "[ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 0; "
    + "f=\"$d/" + HANDOFF_BASENAME + "\"; "
    + "[ -s \"$f\" ] && [ -f \"$f\" ] && [ ! -L \"$f\" ] || exit 0; "
  if (expecting) {
    script += "head -c " + MAX_HANDOFF_BYTES + " \"$f\"; "
  }
  script += "rm -f \"$f\""
  return ["bash", "-c", script]
}

// -------------------------------------------------------------------------
// Locking on screen lock and on suspend
// -------------------------------------------------------------------------
//
// Auto-lock only ever measured elapsed time, and the two moments a vault most
// obviously stops being attended are not about elapsed time at all: the screen
// locking, and the machine going to sleep. Both used to leave the vault open
// for whatever was left of the countdown. Omarchy already treats the first as
// a "lock your password manager now" event -- `omarchy-system-lock` locks
// 1Password -- so this is the same event, read from the same place.

// The screen-lock half has to be asked rather than waited for. The Omarchy
// lock screen is `WlSessionLock` (ext-session-lock), which is a compositor
// protocol with no bus presence: it never calls `loginctl lock-session`, so
// logind's `LockedHint` stays "no" and its `Lock` signal never fires while the
// screen is locked. The shell's own lock plugin is the only thing that knows,
// and the only way to ask it is its IPC handler.
//
// Only the exact string "true" counts as locked. A shell with the lock plugin
// disabled answers "Target not found." on stdout and exits non-zero, and that
// is "no answer" rather than "unlocked" -- but neither may be read as "locked",
// because a vault that locks itself every few seconds on a machine with no
// lock screen is a vault nobody can use.
function screenLockStateCommand() {
  return ["bash", "-c", "omarchy-shell lock isLocked 2>/dev/null | head -c 16"]
}

function screenIsLocked(raw) {
  return String(raw || "").trim() === "true"
}

// How often to ask. Only ever runs while the setting is on *and* the vault is
// unlocked, so the default configuration pays nothing and a locked vault stops
// paying the moment it locks. The call is an IPC round trip to a socket in the
// runtime directory and measures at ~50ms.
var SCREEN_LOCK_POLL_MS = 3000

function screenLockPollMs() {
  return SCREEN_LOCK_POLL_MS
}

// The suspend half is a real event, so it is waited for rather than polled.
// logind announces `PrepareForSleep(true)` before sleeping and
// `PrepareForSleep(false)` on resume, for every path into suspend -- the lid,
// the menu, `systemctl suspend`, an idle timeout -- which is more than any one
// of those could be watched individually.
//
// The delay inhibitor is what makes the lock mean something. Without one,
// logind announces the sleep and suspends without waiting, so the vault would
// be locked by a panel that is about to be frozen mid-way through doing it --
// and a session key still in the keyring is a session key in the memory image.
// A delay inhibitor makes logind wait, and it costs nothing until a suspend
// actually happens: it is held continuously, and released a second after the
// announcement, which is far inside logind's own InhibitDelayMaxSec (5s by
// default) and long enough for the panel to drop the key and for the keyring
// clear it spawns to finish.
//
// Held *inside* the loop rather than around it, because an inhibitor is only
// released by the process holding it exiting. Announce, wait a beat, exit to
// release, then loop round to take a fresh one for the next suspend.
//
// `gdbus monitor` needs `--dest`, and prints a line about the name having no
// owner rather than exiting if logind is somehow absent, so it keeps waiting
// instead of spinning the loop. sed does the matching, so only the one word
// the panel cares about ever crosses the pipe.
//
// The monitor is killed by pid rather than left to a broken pipe. sed quits on
// the match, but a plain `monitor | sed` would then sit in the pipeline until
// the monitor next wrote something -- and the next thing logind announces
// after a sleep is the resume, which is on the far side of the suspend this is
// supposed to be delaying. The inhibitor would still be held, the loop would
// never come round, and only the very first suspend of the session would ever
// be noticed. Bash sets $! for a process substitution, so the monitor can be
// read from an fd and then killed outright.
var SLEEP_SIGNAL_TOKEN = "sleep"
var WAKE_SIGNAL_TOKEN = "wake"

function sleepSignalToken() { return SLEEP_SIGNAL_TOKEN }
function wakeSignalToken() { return WAKE_SIGNAL_TOKEN }

function sleepMonitorCommand() {
  var monitor = "gdbus monitor --system --dest org.freedesktop.login1"
    + " --object-path /org/freedesktop/login1 2>/dev/null"

  // -u so the match leaves sed the moment it is read, rather than sitting in a
  // block buffer until after the machine has already suspended.
  var match = "sed -une '/PrepareForSleep (true,/{s/.*/" + SLEEP_SIGNAL_TOKEN + "/p;q}'"

  var inner = "exec 3< <(" + monitor + "); g=$!; "
    + match + " <&3; "
    + "kill \"$g\" 2>/dev/null; exec 3<&-; "
    // The beat that makes the inhibitor worth holding: the panel has the token
    // by now, and this is the time it gets to act on it before logind is told
    // we are done.
    + "sleep 1"

  // The loop never exits on its own. Bound to the setting, this process is
  // started and stopped by the panel and by nothing else, so every path that
  // could fail waits before trying again instead of returning and inviting a
  // restart -- a monitor that cannot start must not become a hot loop.
  var script = "while :; do "
    + "command -v gdbus >/dev/null 2>&1 || { sleep 300; continue; }; "
    + "if systemd-inhibit --what=sleep --mode=delay"
    + " --who=" + shellQuote("Bitwarden")
    + " --why=" + shellQuote("Locking the vault before sleep")
    + " bash -c " + shellQuote(inner) + "; then "
    // Resume. Reported once the inhibitor is gone, since nothing waits on it.
    + "echo " + shellQuote(WAKE_SIGNAL_TOKEN) + "; "
    + "else sleep 5; fi; "
    + "done"
  return ["bash", "-c", script]
}

function activeWindowCommand() {
  var script = "hyprctl activewindow -j 2>/dev/null | grep -q '\"class\": \"[^\"]' "
    + "&& (hyprctl activewindow -j 2>/dev/null | head -c 65536) "
    + "|| (hyprctl clients -j 2>/dev/null | head -c 1048576)"
  return ["sh", "-c", script]
}

// -------------------------------------------------------------------------
// Opening an item's URI
// -------------------------------------------------------------------------
//
// A vault item's URI is data, not something the panel wrote, and an item can
// arrive from a shared organization collection that somebody else can edit.
// xdg-open hands whatever scheme it is given to whichever program claims it,
// so `file:///`, `ftp://` or a desktop-registered custom scheme would all be
// launched on a click. Only the web schemes are followed.
//
// A colon followed by digits is a port, not a scheme, so "example.com:8080"
// and "localhost:3000" still work as the bare hosts they are.
var HTTP_URL_RE = /^https?:\/\//i
var URL_SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):(?!\d)/

// Returns { ok: true, url } for something safe to open, or { ok: false,
// scheme } naming what was refused.
function normalizeOpenableUrl(raw) {
  var target = String(raw || "").trim()
  if (!target) return { ok: false, scheme: "" }
  // Browsers parse backslashes as slashes in http(s) authorities. Refuse the
  // ambiguous spelling rather than displaying one apparent host and opening
  // another (for example `https://evil.example\@trusted.example`).
  if (target.indexOf("\\") !== -1) return { ok: false, scheme: "", reason: "ambiguous" }

  if (HTTP_URL_RE.test(target)) return { ok: true, url: target }

  var scheme = target.match(URL_SCHEME_RE)
  if (scheme) return { ok: false, scheme: scheme[1].toLowerCase() }

  // No scheme: a bare host, optionally with a port and path.
  return { ok: true, url: "https://" + target }
}

function logoutCommand() {
  return ["bw", "logout"]
}

function listCommand() {
  return buildCappedCommand(["list", "items"], MAX_ITEMS_BYTES, MAX_STDERR_BYTES)
}

// `bw list items` returns complete decrypted ciphers. In particular, an SSH
// item carries its private key, and cipher types added after this panel was
// written otherwise fall through as ordinary logins. Keep that stream out of
// QML by allowlisting supported types in a short-lived jq process. Types 1-4
// remain complete because their existing edit/detail paths need rawObject. A
// malformed cross-typed ordinary item with an sshKey subtree therefore fails
// the whole read instead of being mutated or allowed to smuggle private-key
// material through that branch. Type 5 is reduced to public metadata, and
// every other type is omitted.
//
// This command is introduced separately from listCommand() so the process
// boundary can be proved before the panel adopts its new output contract.
var SANITIZED_ITEMS_FILTER = [
  "def string_or_empty: if type == \"string\" then . else \"\" end;",
  "def string_or_null: if type == \"string\" then . else null end;",
  "def bool_or_false: if type == \"boolean\" then . else false end;",
  "def reprompt_or_zero: if . == 0 or . == 1 then . else 0 end;",
  "def item_type: try (.type | tonumber) catch null;",
  "def ordinary_type: item_type as $t | ($t == 1 or $t == 2 or $t == 3 or $t == 4);",
  "def ssh_type: item_type == 5;",
  "if type != \"array\" then",
  "  error(\"expected one item array\")",
  "elif any(.[] | objects | select(ordinary_type); has(\"sshKey\")) then",
  "  error(\"ordinary item carries an SSH key subtree\")",
  "else",
  "  {",
  "    sshCapability: (if any(.[] | objects; ssh_type) then \"confirmed\" else \"unconfirmed\" end),",
  "    items: [.[] | objects | select(ordinary_type)],",
  "    sshKeys: [.[] | objects | select(ssh_type) | {",
  "      id: (.id | string_or_empty),",
  "      name: (.name | string_or_empty),",
  "      type: 5,",
  "      organizationId: (.organizationId | string_or_null),",
  "      folderId: (.folderId | string_or_null),",
  "      favorite: (.favorite | bool_or_false),",
  "      reprompt: (.reprompt | reprompt_or_zero),",
  "      publicKey: ((try (.sshKey.publicKey // .publicKey) catch null) | string_or_empty),",
  "      fingerprint: ((try (.sshKey.fingerprint // .sshKey.keyFingerprint // .fingerprint // .keyFingerprint) catch null) | string_or_empty)",
  "    }]",
  "  }",
  "end"
].join("\n")

// The agent branch's projection. It sees the same validated array the panel
// filter sees, and reduces it to the one thing the companion is allowed to
// hold: eligible private keys, framed by the load nonce.
//
// Re-prompt items are dropped here rather than sent and skipped later. The
// companion refuses them too -- that check is authoritative and stays -- but a
// private key that never leaves this stage is one fewer copy in one fewer
// process. Items with no private key are dropped for the same reason: an empty
// PEM is not a key, and forwarding it would only produce a skip on the far side.
//
// The field names and shape are fixed by the companion's decoder, which uses
// serde `deny_unknown_fields`. Anything extra here fails the whole load closed.
var AGENT_KEYS_FILTER = [
  "def string_or_empty: if type == \"string\" then . else \"\" end;",
  "def reprompt_or_zero: if . == 0 or . == 1 then . else 0 end;",
  "def item_type: try (.type | tonumber) catch null;",
  "def ssh_type: item_type == 5;",
  "if type != \"array\" then",
  "  error(\"expected one item array\")",
  "else",
  "  {",
  "    loadId: $loadId,",
  "    items: [.[] | objects | select(ssh_type)",
  "      | select((.reprompt | reprompt_or_zero) == 0)",
  "      | {",
  "        itemId: (.id | string_or_empty),",
  "        name: (.name | string_or_empty),",
  "        privateKey: ((try (.sshKey.privateKey // .privateKey) catch null) | string_or_empty),",
  "        publicKey: ((try (.sshKey.publicKey // .publicKey) catch null) | string_or_empty),",
  "        fingerprint: ((try (.sshKey.fingerprint // .sshKey.keyFingerprint // .fingerprint // .keyFingerprint) catch null) | string_or_empty),",
  "        requiresReprompt: false",
  "      }",
  "      | select(.privateKey != \"\")]",
  "  }",
  "end"
].join("\n")

// jq deliberately accepts several non-JSON extensions and replaces malformed
// UTF-8 before a filter can measure it. Validate and count the bounded raw byte
// stream first with the Node runtime that `bw` itself requires. Nothing is
// written until the entire input is valid strict JSON, so parse failures cannot
// leak a partial vault or an exception containing source material.
var STRICT_JSON_PASSTHROUGH = [
  "const maxBytes = Number(process.argv[1]);",
  "const chunks = [];",
  "let byteLength = 0;",
  "process.stdin.on(\"data\", function (chunk) {",
  "  byteLength += chunk.length;",
  "  chunks.push(chunk);",
  "});",
  "process.stdin.on(\"end\", function () {",
  "  if (byteLength > maxBytes) process.exit(1);",
  "  const raw = Buffer.concat(chunks, byteLength);",
  "  try {",
  "    const decoder = new (require(\"util\").TextDecoder)(\"utf-8\", { fatal: true });",
  "    const parsed = JSON.parse(decoder.decode(raw));",
  "    if (!Array.isArray(parsed)) process.exit(1);",
  "  } catch (error) {",
  "    process.exit(1);",
  "  }",
  "  process.stdout.write(raw);",
  "});"
].join("\n")

var SANITIZED_LIST_ERROR = "Could not safely read vault items."
var SANITIZED_LIST_SSH_FIX_HINT = " Bitwarden CLI before " + SSH_MALFORMED_ITEM_FIX_VERSION
  + " can fail on malformed SSH key items. Upgrading to " + SSH_MALFORMED_ITEM_FIX_VERSION
  + " or newer may fix this."

// The optional `tee` branch. Three rules shape every line of it, because this
// is the one place where an optional feature sits inside the pipeline the
// ordinary item list depends on:
//
//  1. It never blocks the pipeline on opening the FIFO. The writer opens it
//     O_RDWR, which on a FIFO never waits for a peer -- so a companion
//     that died between the panel's readiness check and this read costs
//     nothing instead of hanging the list behind a blocking open.
//  2. It never writes anywhere but the real FIFO descriptor it opened with
//     O_NOFOLLOW. A pathname check followed by a shell redirection would let
//     the last component be swapped between the two operations.
//  3. It always drains its stdin. `tee` writes to this branch; a branch that
//     exited early would leave `tee` with a broken pipe and could take the
//     whole read down. The trailing `cat` guarantees the remainder is consumed
//     however `jq` ended.
//
// `pipefail` cannot see inside a process substitution, so nothing here can
// report success or failure to the panel. That is by design: `key_load_end`
// carries the panel's view of the pipeline, and the companion's own nonce and
// schema validation is what actually decides whether a load is accepted.
function agentBranchScript() {
  var fifoWriter = [
    "const fs = require(\"fs\");",
    "let fd = null;",
    "try {",
    "  const flags = fs.constants.O_RDWR | fs.constants.O_NOFOLLOW;",
    "  const opened = fs.openSync(process.argv[1], flags);",
    "  const stat = fs.fstatSync(opened);",
    "  if ((stat.mode & fs.constants.S_IFMT) === fs.constants.S_IFIFO) fd = opened;",
    "  else fs.closeSync(opened);",
    "} catch (error) {}",
    "process.stdin.on(\"data\", function (chunk) {",
    "  if (fd === null) return;",
    "  try {",
    "    let offset = 0;",
    "    while (offset < chunk.length) offset += fs.writeSync(fd, chunk, offset);",
    "  } catch (error) { try { fs.closeSync(fd); } catch (ignored) {}; fd = null; }",
    "});",
    "process.stdin.on(\"end\", function () { if (fd !== null) fs.closeSync(fd); });"
  ].join("\n")
  var inner = "__qsbw_fifo=\"$XDG_RUNTIME_DIR/" + RUNTIME_SUBDIR + "/ssh-keys.fifo\"; "
    // The pathname test is not the safety check -- the descriptor's own fstat
    // is, below -- but it is free, and without it a companion that died
    // between the panel's readiness check and this read would still cost a
    // full decrypt-and-filter pass over the vault, piping private keys into a
    // writer with nowhere to put them.
    + "if [ -p \"$__qsbw_fifo\" ]; then "
    + "timeout 10 jq -c --arg loadId \"${" + LOAD_ID_ENV + ":-}\" "
    + shellQuote(AGENT_KEYS_FILTER) + " 2>/dev/null | timeout 10 node -e "
    + shellQuote(fifoWriter) + " \"$__qsbw_fifo\" 2>/dev/null || true; "
    + "fi; "
    + "cat >/dev/null 2>&1 || true"
  return "tee >(" + inner + ") | "
}

function sanitizedListCommand(opts) {
  // The validator receives at most one byte beyond the raw ceiling and counts
  // bytes before UTF-8 decoding. The second cap and command substitution keep
  // partial sanitized JSON out of QML-facing stdout. All pipeline diagnostics
  // are suppressed because bw and jq may quote decrypted source material; the
  // only error exposed to QML is the fixed message below. Blaming a failure on
  // the pre-2026.8.0 malformed-SSH-item bug is left to vaultListFailureMessage(),
  // which reads the already-probed CLI version instead of the failure text --
  // nothing here has to look at what the producer printed.
  var agentBranch = Boolean(opts && opts.agentBranch)
  var maxPlusOne = MAX_ITEMS_BYTES + 1
  var script = "export LC_ALL=C BW_NOINTERACTION=true; set -o pipefail; "
  script += "__qsbw_items=$({ bw list items | head -c " + maxPlusOne
    + " | node -e " + shellQuote(STRICT_JSON_PASSTHROUGH) + " " + MAX_ITEMS_BYTES
    // The branch sits after the strict validator, so the companion is only
    // ever offered bytes that already parsed as one strict JSON array.
    + " | " + (agentBranch ? agentBranchScript() : "")
    + "jq -c " + shellQuote(SANITIZED_ITEMS_FILTER)
    + " | head -c " + maxPlusOne + "; } 2>/dev/null)\n"
  script += "__rc=$?\n"
  script += "if [ \"$__rc\" -ne 0 ] || [ \"${#__qsbw_items}\" -gt " + MAX_ITEMS_BYTES + " ]; then\n"
  script += "  printf '%s\\n' " + shellQuote(SANITIZED_LIST_ERROR) + " >&2\n"
  script += "  exit 1\n"
  script += "fi\n"
  script += "printf '%s' \"$__qsbw_items\""
  // Only the fan-out form needs the process-group wrapper: it is the one with
  // a `tee` and a second `jq` that a lock has to be able to reap along with
  // `bw`. The plain form keeps the exact command it has always run.
  return agentBranch ? supervisedProcessCommand(script) : ["bash", "-c", script]
}

function listOrganizationsCommand() {
  return buildCappedCommand(["list", "organizations"], MAX_ORGS_BYTES)
}

function listFoldersCommand() {
  return buildCappedCommand(["list", "folders"], MAX_FOLDERS_BYTES)
}

// An organization's collections. Bitwarden files org-owned items into
// collections rather than folders, and refuses to create one without at least
// one collection, so the form has to offer them.
function listOrgCollectionsCommand(organizationId) {
  return buildCappedCommand(["list", "org-collections", "--organizationid", String(organizationId)], MAX_COLLECTIONS_BYTES)
}

function parseJsonArray(raw) {
  try {
    var parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch (e) {
    return []
  }
}

function compareNames(a, b) {
  return a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
}

function nameById(entries, id) {
  if (!id || !Array.isArray(entries)) return ""
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].id === id) return entries[i].name
  }
  return ""
}

function parseCollections(raw) {
  var arr = parseJsonArray(raw)
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var c = arr[i]
    if (!c || typeof c !== "object" || !c.id) continue
    out.push({
      id: String(c.id),
      name: String(c.name || "Collection"),
      organizationId: c.organizationId ? String(c.organizationId) : ""
    })
  }
  out.sort(compareNames)
  return out
}

function collectionName(collections, id) {
  return nameById(collections, id)
}

var FOLDER_ENV = "QSBW_FOLDER"

function folderEnvVar() {
  return FOLDER_ENV
}

function folderPayload(name) {
  return JSON.stringify({ name: String(name || "").trim() })
}

function createFolderCommand() {
  var script = "printf '%s' \"$" + FOLDER_ENV + "\" | bw encode | bw create folder | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function getItemCommand(id, typeCode) {
  if (Number(typeCode) === 5) return []
  return buildCappedCommand(["get", "item", "--", String(id)], MAX_DETAIL_BYTES, MAX_STDERR_BYTES)
}

function getPasswordCommand(id, typeCode) {
  if (Number(typeCode) === 5) return []
  return buildCappedCommand(["get", "password", "--raw", "--", String(id)], MAX_TOKEN_BYTES, MAX_STDERR_BYTES)
}

function getTotpCommand(id, typeCode) {
  if (Number(typeCode) === 5) return []
  return buildCappedCommand(["get", "totp", "--raw", "--", String(id)], MAX_TOKEN_BYTES)
}

function syncCommand() {
  return buildCappedCommand(["sync"], MAX_MISC_BYTES)
}

function lockCommand() {
  return buildCappedCommand(["lock"], MAX_MISC_BYTES)
}

// -------------------------------------------------------------------------
// CRUD Commands (Create, Edit, Delete)
// -------------------------------------------------------------------------

// The item JSON contains the password, so it travels in the environment. An
// inlined `printf %s '<json>'` would put it in /proc/<pid>/cmdline, which is
// world-readable here (no hidepid).
var ITEM_ENV = "QSBW_ITEM"

function itemEnvVar() {
  return ITEM_ENV
}

function createItemCommand(itemData) {
  var orgArg = (itemData && itemData.organizationId) ? (" --organizationid " + shellQuote(itemData.organizationId)) : ""
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw create item" + orgArg + " | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function editItemCommand(itemId, typeCode) {
  if (Number(typeCode) === 5) return []
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw edit item -- " + shellQuote(itemId) + " | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function deleteItemCommand(itemId, typeCode) {
  if (Number(typeCode) === 5) return []
  return buildCappedCommand(["delete", "item", "--", String(itemId)], MAX_MISC_BYTES, MAX_STDERR_BYTES)
}

// -------------------------------------------------------------------------
// Keyring (libsecret / secret-tool) Commands
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// The remembered session dies with the boot that minted it
// -------------------------------------------------------------------------
//
// A session token used to outlive its machine. The login keyring is a file on
// disk and PAM unlocks it again at the next login, so rebooting with an
// unlocked vault brought the vault back unlocked -- the panel found the token
// waiting and never asked for anything. Locking the screen is not what the
// user did; powering the machine off is, and that has to mean something.
//
// Two independent things stop it now, because one of them depends on the
// secret service and the other does not.
//
// The token goes into libsecret's `session` collection, which the secret
// service holds in memory and destroys when the login session ends, so on a
// well-behaved service there is nothing on disk to come back. Not every
// implementation offers that collection, so the store falls back to the
// default one rather than failing to remember the session at all.
//
// And the token is written behind the kernel's boot id, which is regenerated
// on every boot. A token that did survive -- fallback collection, a keyring
// restored from a backup, a service that ignores the session semantics -- no
// longer matches the running boot and is refused. That check is the guarantee;
// the collection is what keeps the token off the disk in the first place.
//
// Fail closed at every step: a missing boot id, an unreadable keyring or a
// stale entry all report no token, which lands the panel on `bw status` and
// the lock screen. A stale entry is cleared on the way out so it cannot be
// found again.
const KEYRING_SESSION_COLLECTION = "session"
const BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

function bootIdPath() {
  return BOOT_ID_PATH
}

function keyringStoreCommand() {
  var attrs = keyringAttributes(KEYRING_ACCOUNT)
  // The secret still travels in the environment (see keyringStoreScript); only
  // the boot id, which is not a secret, is read inside the script.
  var script = "store() { printf '%s %s' \"$(cat " + shellQuote(BOOT_ID_PATH) + ")\" \"$"
    + KEYRING_SECRET_ENV + "\" | secret-tool store \"$@\" --label="
    + shellQuote("Bitwarden Vault Session") + attrs + "; }; "
    + "store --collection=" + shellQuote(KEYRING_SESSION_COLLECTION) + " 2>/dev/null || store"
  return ["bash", "-c", script]
}

function keyringLookupCommand() {
  var attrs = keyringAttributes(KEYRING_ACCOUNT)
  var script = "boot=$(cat " + shellQuote(BOOT_ID_PATH) + " 2>/dev/null | head -c 128) || exit 0; "
    + "[ -n \"$boot\" ] || exit 0; "
    + "stored=$(secret-tool lookup" + attrs + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES + ") || exit 0; "
    + "case \"$stored\" in "
    + "\"$boot \"?*) printf '%s' \"${stored#* }\" ;; "
    // Anything else is from another boot, or from before the boot id was
    // written at all. Drop it so the next lookup does not have to think.
    + "*) [ -n \"$stored\" ] && secret-tool clear" + attrs + " >/dev/null 2>&1 ;; "
    + "esac; exit 0"
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearCommand() {
  return keyringClearEntryCommand(KEYRING_ACCOUNT)
}

// -------------------------------------------------------------------------
// Fingerprint Unlock
// -------------------------------------------------------------------------
//
// PAM can prove the user is present but cannot produce the Bitwarden master
// password, and `bw unlock` accepts nothing else. So fingerprint unlock keeps
// the master password in the login keyring and uses a successful fingerprint
// verification as the gate on reading it back -- the same trade the Bitwarden
// desktop client makes for its own biometric unlock. Opt-in only.

function keyringStoreMasterPasswordCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden Master Password (fingerprint unlock)", KEYRING_MASTER)]
}

function keyringLookupMasterPasswordCommand() {
  return keyringLookupEntryCommand(KEYRING_MASTER)
}

function keyringClearMasterPasswordCommand() {
  return keyringClearEntryCommand(KEYRING_MASTER)
}

// Presence check that never puts the secret on stdout, so the panel can show
// the right prompt without reading the password until a finger is verified.
function keyringHasMasterPasswordCommand() {
  return keyringHasEntryCommand(KEYRING_MASTER)
}

// -------------------------------------------------------------------------
// PIN Unlock
// -------------------------------------------------------------------------
//
// A PIN cannot produce the master password any more than a fingerprint can, so
// the password is encrypted *with a key derived from the PIN* and only the
// ciphertext is kept. Unlike fingerprint unlock, reading the keyring is then
// not enough on its own -- an attacker also has to break the PIN. A wrong PIN
// fails decryption outright, so correctness needs no separately stored hash
// (and no hash to attack).
//
// Be honest about the limit: a short PIN is a small search space, and the only
// thing standing between a leaked blob and the master password is the KDF cost.
// That is why the iteration count is high and short PINs are refused.

function pinEnvVar() { return PIN_ENV }
function pinMinLength() { return PIN_MIN_LENGTH }
function pinRecommendedLength() { return PIN_RECOMMENDED_LENGTH }

function validatePin(pin, confirm) {
  var p = String(pin || "")
  if (p.length < PIN_MIN_LENGTH) return "PIN must be at least " + PIN_MIN_LENGTH + " digits"
  if (!/^[0-9]+$/.test(p)) return "PIN must contain only digits"
  if (confirm !== undefined && String(confirm || "") !== p) return "PINs do not match"
  return ""
}

// Not an error -- the PIN is accepted -- but short enough to deserve saying so
// in as many words, with the number rather than a vague "weak". Empty for a
// PIN of the recommended length or longer, and empty while still typing so the
// warning does not flash up at every keystroke on the way to six.
function pinWeakWarning(pin) {
  var p = String(pin || "")
  if (p.length < PIN_MIN_LENGTH || p.length >= PIN_RECOMMENDED_LENGTH) return ""
  var combinations = Math.pow(10, p.length).toLocaleString("en-US")
  return "A " + p.length + "-digit PIN is only " + combinations + " combinations. "
    + "If the encrypted blob ever leaks, that is minutes of offline guessing. "
    + "Use " + PIN_RECOMMENDED_LENGTH + " or more."
}

function isPinWeak(pin) {
  return pinWeakWarning(pin) !== ""
}

// Encrypt and store in one process, so the plaintext never travels back
// through QML on the way to the keyring.
function pinStoreCommand() {
  var script = "printf '%s' \"$" + KEYRING_SECRET_ENV + "\""
    + " | openssl enc -aes-256-cbc -pbkdf2 -iter " + PIN_ITERATIONS
    + " -md sha256 -salt -pass env:" + PIN_ENV + " -base64 -A"
    + " | secret-tool store --label=" + shellQuote("Bitwarden Master Password (PIN unlock)")
    + " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(KEYRING_PIN)
  return ["bash", "-c", cappedScript(script)]
}

// Non-zero exit means the PIN was wrong (or the blob is gone). stdout carries
// the master password only on success.
function pinUnlockCommand() {
  var script = "secret-tool lookup" + keyringAttributes(KEYRING_PIN) + " 2>/dev/null | head -c 8192"
    + " | openssl enc -d -aes-256-cbc -pbkdf2 -iter " + PIN_ITERATIONS
    + " -md sha256 -pass env:" + PIN_ENV + " -base64 -A | head -c " + MAX_TOKEN_BYTES
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearPinCommand() {
  return keyringClearEntryCommand(KEYRING_PIN)
}

function keyringHasPinCommand() {
  return keyringHasEntryCommand(KEYRING_PIN)
}

// -------------------------------------------------------------------------
// Everything the keyring holds, gone in one go
// -------------------------------------------------------------------------
//
// Logging out is the moment the plugin should be holding nothing for this
// account. The session token is the least of it: two of the three entries are
// the master password itself -- once in the clear behind fingerprint unlock,
// once encrypted under a four-to-six digit PIN -- and both live in the default
// collection, which is a file on disk that PAM unlocks at every login. Neither
// is any use to an account that is no longer signed in, and both outlive a
// reboot by design, so neither may outlive the logout.
//
// One command that names every account rather than three calls the panel
// decides between, because the deciding was the bug: those decisions were made
// from the panel's own flags, and a flag describes what the settings screen
// last saw rather than what is in the keyring. `fingerprintStored` goes false
// the moment a reader is unplugged or fprintd is uninstalled -- the master
// password does not go anywhere. `secret-tool clear` on an entry that is not
// there returns 1 without printing an error. Worse, `clear` only removes
// unlocked matches, so that result alone cannot distinguish absence from a
// credential hidden in a locked collection. Search first, request unlock of
// every match, clear, then search again. Logout succeeds only when that final
// search proves no matching item remains.
var KEYRING_ALL_ACCOUNTS = [KEYRING_ACCOUNT, KEYRING_MASTER, KEYRING_PIN]

function keyringSearchStateScript(account, resultVar) {
  // Consume the complete search output with wc instead of capturing it: for an
  // unlocked item secret-tool includes the secret in that stream. Only its
  // byte count and the producer exit code are retained by the shell.
  var attrs = keyringAttributes(account)
  return resultVar + "=$(secret-tool search --all" + attrs
    + " 2>/dev/null | wc -c | tr -d '[:space:]'; "
    + "__keyring_pipe=(\"${PIPESTATUS[@]}\"); "
    + "printf ':%s' \"${__keyring_pipe[0]}\"); "
}

function keyringClearAllCommand() {
  var script = "rc=0; "
  for (var i = 0; i < KEYRING_ALL_ACCOUNTS.length; i++) {
    var attrs = keyringAttributes(KEYRING_ALL_ACCOUNTS[i])
    script += keyringSearchStateScript(KEYRING_ALL_ACCOUNTS[i], "__keyring_before")
    script += "__keyring_count=${__keyring_before%%:*}; "
      + "__keyring_search_rc=${__keyring_before##*:}; "
      + "if [ \"$__keyring_search_rc\" -ne 0 ]; then rc=1; "
      + "elif [ \"$__keyring_count\" -gt 0 ]; then "
      + "secret-tool search --all --unlock" + attrs + " >/dev/null 2>&1 || true; "
      + "secret-tool clear" + attrs + " >/dev/null 2>&1 || true; "
    script += keyringSearchStateScript(KEYRING_ALL_ACCOUNTS[i], "__keyring_after")
    script += "__keyring_count=${__keyring_after%%:*}; "
      + "__keyring_search_rc=${__keyring_after##*:}; "
      + "if [ \"$__keyring_search_rc\" -ne 0 ] || [ \"$__keyring_count\" -ne 0 ]; then rc=1; fi; fi; "
  }
  script += "exit \"$rc\""
  return ["bash", "-c", script]
}

// -------------------------------------------------------------------------
// Parsing
// -------------------------------------------------------------------------

function parseStatus(raw) {
  var st = null
  try {
    st = JSON.parse(raw)
  } catch (e) {
    return null
  }
  if (!st || typeof st !== "object") return null
  return {
    authenticated: st.status !== "unauthenticated",
    locked: st.status === "locked",
    unlocked: st.status === "unlocked",
    userEmail: String(st.userEmail || ""),
    userId: String(st.userId || ""),
    lastSync: String(st.lastSync || ""),
    serverUrl: String(st.serverUrl || "")
  }
}

function parseOrganizations(raw) {
  var arr = parseJsonArray(raw)
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var o = arr[i]
    if (!o || typeof o !== "object") continue
    out.push({
      id: String(o.id || ""),
      name: String(o.name || "Organization"),
      status: Number(o.status || 0)
    })
  }
  return out
}

function parseFolders(raw) {
  var arr = parseJsonArray(raw)
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var f = arr[i]
    if (!f || typeof f !== "object") continue
    // bw represents "no folder" as an entry with a null id on some versions.
    // The panel has its own control for that, so drop it here.
    if (!f.id) continue
    out.push({ id: String(f.id), name: String(f.name || "Folder") })
  }

  out.sort(compareNames)
  return out
}

function folderName(folders, folderId) {
  return nameById(folders, folderId)
}

var ITEM_TYPES = {
  "1": "login",
  "2": "secureNote",
  "3": "card",
  "4": "identity",
  "5": "sshKey"
}

function itemTypeName(type) {
  return ITEM_TYPES[String(type)] || "login"
}

// The same glyphs the type filter chips use, so an item row and the chip
// that selects it agree. Two of these used to be neither: the comments said
// "note icon" and "credit card icon", but the codepoints were md-fan and
// md-close_octagon_outline -- a ceiling fan and a stop sign.
function itemTypeGlyph(type) {
  var t = itemTypeName(type)
  switch (t) {
    case "login": return "󰌋"      // md-key_variant
    case "secureNote": return "󰈙" // md-file_document
    case "card": return "󰿯"       // md-credit_card
    case "identity": return ""   // fa-user
    case "sshKey": return "󰣀"     // md-ssh
    default: return "󰞀"           // md-shield_half_full
  }
}

function itemTypeLabel(type) {
  var t = itemTypeName(type)
  switch (t) {
    case "login": return "Login"
    case "secureNote": return "Secure Note"
    case "card": return "Card"
    case "identity": return "Identity"
    case "sshKey": return "SSH Key"
    default: return "Item"
  }
}

// -------------------------------------------------------------------------
// Attachments
// -------------------------------------------------------------------------
//
// `bw list items` carries the attachment metadata with the cipher -- id, file
// name and size -- so the panel can list an item's files without asking the
// CLI anything. Only the bytes need a round trip, and those are fetched on
// demand by attachmentDownloadCommand().

// -------------------------------------------------------------------------
// Array.isArray is not safe on anything that came back out of QML
// -------------------------------------------------------------------------
//
// `bw`'s JSON parses into real arrays, and every check below used to say
// Array.isArray(). That holds right up until the parsed cipher is stored in a
// QML `var` property -- root.items -- and read back out to build the detail
// view. Qt converts the nested arrays on that round trip into array-like
// objects: `typeof` is "object", `.length` is right, indexing works, and
// Array.isArray() returns false. So the check passes in Node and fails in the
// panel, silently, yielding an empty list rather than an error.
//
// That is exactly how an item the list had already marked as having twelve
// attachments opened with no attachments section at all -- and, it turns out,
// why the detail view's WEBSITE section has been empty for logins that
// plainly have a URI.
//
// Duck-type instead: anything with a sane numeric length is a list.
//
// Bounded, because duck-typing takes the server's word for how long the list
// is. `{"attachments":{"length":200000000}}` is forty bytes of JSON that asked
// for a two-hundred-million-element array, and the process that dies of it is
// the whole shell -- bar, panel and all. The item-list byte cap is no defence
// here: the lie costs the server nothing to tell. No item carries thousands of
// URIs, attachments or custom fields, so past the ceiling there is no list
// worth building.
var MAX_LIST_ENTRIES = 4096

function toList(value) {
  if (Array.isArray(value)) {
    return value.length > MAX_LIST_ENTRIES ? value.slice(0, MAX_LIST_ENTRIES) : value
  }
  if (!value || typeof value !== "object") return []
  var n = value.length
  if (typeof n !== "number" || n < 0 || n !== Math.floor(n)) return []
  if (n > MAX_LIST_ENTRIES) n = MAX_LIST_ENTRIES
  var out = []
  for (var i = 0; i < n; i++) out.push(value[i])
  return out
}

function parseAttachments(raw) {
  var out = []
  var list = toList(raw)
  for (var i = 0; i < list.length; i++) {
    var a = list[i]
    if (!a || !a.id) continue
    out.push({
      id: String(a.id),
      fileName: String(a.fileName || "") || "attachment",
      size: String(a.size || ""),
      sizeName: String(a.sizeName || "") || formatAttachmentSize(a.size)
    })
  }
  return out
}

var ATTACHMENT_UNITS = ["B", "KB", "MB", "GB", "TB"]

// bw normally supplies its own `sizeName`, so this is the fallback for the
// attachments that arrive with only a byte count.
function formatAttachmentSize(bytes) {
  // Nothing at all is no size text; zero bytes is a size, and a real one.
  if (bytes === null || bytes === undefined || String(bytes).trim() === "") return ""
  var n = Number(bytes)
  if (!isFinite(n) || n < 0) return ""
  var unit = 0
  while (n >= 1024 && unit < ATTACHMENT_UNITS.length - 1) {
    n = n / 1024
    unit++
  }
  var value = unit === 0
    ? String(Math.round(n))
    : (Math.round(n * 100) / 100).toFixed(2).replace(/\.?0+$/, "")
  return value + " " + ATTACHMENT_UNITS[unit]
}

// A file name out of the vault is attacker-controlled text, and it is about to
// become part of a path we create. "../../.bashrc", an embedded newline or a
// NUL all have to come out as an inert basename: path separators and control
// characters are replaced rather than stripped, so nothing can be spliced back
// together into a traversal, and a leading dot or dash cannot turn the result
// into a hidden file or into something that reads as a flag.
function safeAttachmentFileName(raw) {
  var name = String(raw || "")
  name = name.replace(/^.*[\\/]/, "")               // best-effort basename
  name = name.replace(/[\x00-\x1f\x7f\\/]/g, "_")   // the part that guarantees it
  name = name.replace(/^[\s.\-]+/, "").replace(/\s+$/, "")
  if (name.length > 128) {
    var ext = ""
    var dot = name.lastIndexOf(".")
    if (dot > 0 && name.length - dot <= 12) ext = name.slice(dot)
    name = name.slice(0, 128 - ext.length) + ext
  }
  return name || "attachment"
}

function parentDirectory(path) {
  var p = String(path || "")
  var cut = p.lastIndexOf("/")
  if (cut < 0) return ""
  return cut === 0 ? "/" : p.slice(0, cut)
}

function baseName(path) {
  var p = String(path || "")
  var cut = p.lastIndexOf("/")
  return cut < 0 ? p : p.slice(cut + 1)
}

// Saves one attachment into the user's download directory and prints the path
// it landed on -- which is the only way the panel learns where that was, since
// the directory is resolved at run time. An existing file of the same name is
// never overwritten: " (1)", " (2)" and so on go before the extension until
// the name is free.
//
// The attachment id, the item id and the file name all come out of the vault,
// so all three are quoted rather than interpolated bare, and the file name has
// been through safeAttachmentFileName() before it gets here.
//
// Two things this must not do, neither of which a `[ -e ]` test can prevent.
//
// It must not write *through* whatever happens to sit at the chosen path. `-e`
// follows symlinks, so a dangling one reads as a free name and bw would then
// create the file the link points at; and even a correct test is only true for
// as long as it takes to return, so a link dropped in afterwards still wins.
// The bytes therefore land in a freshly made private directory first, and the
// finished file claims its name with link(), which never follows the last
// component of the new path and fails outright if anything is already there.
// That single call is the existence test and the creation at once, so there is
// no window between them to race, and nothing to redirect.
//
// It must not accept an unbounded transfer. The size the vault reports is the
// server's word rather than proof, so it only buys an early, readable refusal;
// RLIMIT_FSIZE, a timeout, and a free-space check are the limits that hold when
// it lies.
function attachmentDownloadCommand(attachmentId, itemId, fileName, declaredSize) {
  var maxBytes = MAX_ATTACHMENT_BYTES
  var maxMb = Math.round(maxBytes / (1024 * 1024))
  var maxBlocks = Math.ceil(maxBytes / 1024)          // ulimit -f counts 1 KB blocks

  // The declared size is the only thing out of the vault that reaches the
  // script as a bare word rather than a quoted one, and JavaScript prints a
  // large enough number in exponential notation. "1e+30" is not an integer to
  // `[ ]`, so a server that declares an absurd size made both comparisons
  // below fail as errors rather than as answers -- and a check that errors
  // inside an `if` is simply skipped, which left the download running with no
  // declared-size ceiling and no free-space check at all, silently.
  //
  // Nothing above the limit needs an exact figure, since it is refused either
  // way, so anything larger is clamped to one byte over it. That keeps every
  // number written into the script a plain decimal integer and turns the lie
  // into the refusal it was always meant to be.
  var numericSize = Number(declaredSize)
  var sizeKnown = declaredSize !== undefined && declaredSize !== null
    && String(declaredSize).trim() !== "" && isFinite(numericSize) && numericSize >= 0
  var want = sizeKnown ? Math.floor(numericSize) : 0
  if (want > maxBytes) want = maxBytes + 1

  // When metadata omits the size, reserve for the largest transfer the kernel
  // limit permits. Treating unknown as zero let a bounded 512 MB download start
  // on a nearly full disk after checking for only the 64 MB safety margin.
  var reserveBytes = sizeKnown ? want : maxBytes
  var needKb = Math.ceil((reserveBytes + ATTACHMENT_FREE_SLACK_BYTES) / 1024)

  var script = [
    "set -e",
    // A decrypted attachment must not be readable by anyone else while it sits
    // in the staging directory, nor after it lands.
    "umask 077",
    "exec 2> >(head -c " + MAX_STDERR_BYTES + " >&2)",
    "name=" + shellQuote(safeAttachmentFileName(fileName)),
    "max=" + maxBytes,
    "want=" + want,
    "dir=\"$(xdg-user-dir DOWNLOAD 2>/dev/null || true)\"",
    // xdg-user-dir answers $HOME for a directory it does not know about, and
    // $HOME is not somewhere to drop files.
    "if [ -z \"$dir\" ] || [ \"$dir\" = \"$HOME\" ]; then dir=\"$HOME/Downloads\"; fi",
    "mkdir -p -- \"$dir\"",

    "if [ \"$want\" -gt \"$max\" ]; then",
    "  echo 'Attachment is larger than the " + maxMb + " MB download limit.' >&2; exit 1",
    "fi",

    // A download that fits the limit can still be the one that fills the disk.
    "avail=$(df -Pk -- \"$dir\" 2>/dev/null | awk 'NR==2 {print $4}')",
    "case \"$avail\" in ''|*[!0-9]*) avail='' ;; esac",
    "if [ -n \"$avail\" ] && [ \"$avail\" -lt " + needKb + " ]; then",
    "  echo 'Not enough free space in the download folder.' >&2; exit 1",
    "fi",

    // Staged inside the destination directory, so the finished file can be
    // linked into place without crossing a filesystem boundary.
    "work=$(mktemp -d -- \"$dir/.qsbw-XXXXXXXX\")",
    "trap 'rm -rf -- \"$work\"' EXIT HUP INT TERM",
    "tmp=\"$work/part\"",

    // RLIMIT_FSIZE stops the write itself, so an oversized attachment dies
    // mid-transfer instead of on a check that trusted the declared size.
    "rc=0",
    "( ulimit -f " + maxBlocks + "; exec timeout " + ATTACHMENT_TIMEOUT_SECS + "s bw get attachment --itemid " + shellQuote(itemId)
      + " --output \"$tmp\" -- " + shellQuote(attachmentId) + " >/dev/null ) || rc=$?",
    "if [ \"$rc\" -ne 0 ]; then",
    "  case \"$rc\" in",
    "    124) echo 'Download timed out.' >&2 ;;",
    "    153) echo 'Attachment exceeded the " + maxMb + " MB download limit.' >&2 ;;",
    "  esac",
    "  exit 1",
    "fi",

    // Belt and braces: the limit above is the kernel's, this one holds even
    // where it was not applied.
    "got=$(wc -c < \"$tmp\" 2>/dev/null || echo 0)",
    "if [ \"$got\" -gt \"$max\" ]; then",
    "  echo 'Attachment exceeded the " + maxMb + " MB download limit.' >&2; exit 1",
    "fi",

    // Asked once, rather than inferred from a failure that could equally mean
    // the name was taken.
    "hardlink=1",
    ": > \"$work/probe\"",
    "ln -- \"$work/probe\" \"$work/probe2\" 2>/dev/null || hardlink=0",
    "rm -f -- \"$work/probe\" \"$work/probe2\"",

    "stem=\"$name\"; ext=\"\"",
    "case \"$name\" in *.*) stem=\"${name%.*}\"; ext=\".${name##*.}\";; esac",
    "out=''; n=0",
    "while [ \"$n\" -le 999 ]; do",
    "  if [ \"$n\" -eq 0 ]; then cand=\"$dir/$name\"; else cand=\"$dir/$stem ($n)$ext\"; fi",
    "  if [ \"$hardlink\" = 1 ]; then",
    "    if ln -- \"$tmp\" \"$cand\" 2>/dev/null; then out=\"$cand\"; break; fi",
    // Some removable and FUSE filesystems do not support hard links. Keep the
    // same no-overwrite contract there with mv -n after rejecting both an
    // existing entry and a dangling symlink.
    "  elif [ ! -e \"$cand\" ] && [ ! -L \"$cand\" ] && mv -n -- \"$tmp\" \"$cand\" 2>/dev/null; then",
    "    out=\"$cand\"; break",
    "  fi",
    "  n=$((n+1))",
    "done",
    "if [ -z \"$out\" ]; then",
    "  echo 'Could not find a free name in the download folder.' >&2; exit 1",
    "fi",
    "printf %s \"$out\" | head -c 4096"
  ].join("\n")
  // The panel cancels this Process on lock/logout. Supervision gives the
  // attachment shell and every child a private process group, so SIGTERM
  // reaches timeout, bw, and the staging cleanup rather than only the wrapper.
  return supervisedProcessCommand(script)
}

function loginUris(login) {
  var uris = []
  var rawUris = toList(login.uris)
  for (var i = 0; i < rawUris.length; i++) {
    if (rawUris[i] && rawUris[i].uri) uris.push(String(rawUris[i].uri))
  }
  return uris
}

function cardDetail(card) {
  if (!card) return null
  return {
    cardholderName: String(card.cardholderName || ""),
    brand: String(card.brand || ""),
    number: String(card.number || ""),
    expMonth: String(card.expMonth || ""),
    expYear: String(card.expYear || ""),
    code: String(card.code || "")
  }
}

function identityDetail(identity) {
  if (!identity) return null
  return {
    title: String(identity.title || ""),
    firstName: String(identity.firstName || ""),
    lastName: String(identity.lastName || ""),
    email: String(identity.email || ""),
    phone: String(identity.phone || ""),
    address1: String(identity.address1 || ""),
    city: String(identity.city || ""),
    state: String(identity.state || ""),
    postalCode: String(identity.postalCode || ""),
    country: String(identity.country || "")
  }
}

function itemCustomFields(fields) {
  var customFields = []
  var rawFields = toList(fields)
  for (var i = 0; i < rawFields.length; i++) {
    var field = rawFields[i]
    if (!field || !field.name) continue
    customFields.push({
      name: String(field.name || ""),
      value: String(field.value || ""),
      type: Number(field.type || 0) // 0: text, 1: hidden, 2: boolean, 3: linked
    })
  }
  return customFields
}

function parseItems(raw) {
  var arr = parseJsonArray(raw)
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var it = arr[i]
    if (!it || typeof it !== "object") continue

    var login = it.login || {}
    var uris = loginUris(login)
    var attachments = parseAttachments(it.attachments)

    var card = it.card || null
    var cardSubtitle = ""
    if (card) {
      var num = String(card.number || "")
      var last4 = num.length >= 4 ? num.slice(-4) : num
      cardSubtitle = (card.brand ? card.brand + " " : "") + (last4 ? "•••• " + last4 : "")
    }

    var subtitle = ""
    if (login.username) {
      subtitle = String(login.username)
    } else if (uris.length > 0) {
      subtitle = uris[0].replace(/^https?:\/\//, "").replace(/\/.*$/, "")
    } else if (cardSubtitle) {
      subtitle = cardSubtitle
    } else if (it.type === 2) {
      subtitle = "Secure Note"
    }

    out.push({
      id: String(it.id || ""),
      organizationId: it.organizationId ? String(it.organizationId) : null,
      folderId: it.folderId ? String(it.folderId) : null,
      name: String(it.name || "Untitled"),
      type: itemTypeName(it.type),
      typeCode: Number(it.type || 1),
      favorite: Boolean(it.favorite),
      username: String(login.username || ""),
      password: String(login.password || ""),
      hasPassword: Boolean(login.password),
      hasTotp: Boolean(login.totp),
      totpKey: String(login.totp || ""),
      uris: uris,
      attachments: attachments,
      hasAttachments: attachments.length > 0,
      subtitle: subtitle,
      notes: String(it.notes || ""),
      rawObject: it
    })
  }

  // Sort by favorite first, then alphabetically by name
  out.sort(function(a, b) {
    if (a.favorite !== b.favorite) {
      return a.favorite ? -1 : 1
    }
    return compareNames(a, b)
  })

  return out
}

function parseSshKeys(keys) {
  var arr = Array.isArray(keys) ? keys : []
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var it = arr[i]
    if (!it || typeof it !== "object" || !it.id) continue
    var key = it.sshKey || {}
    var publicKey = String(key.publicKey || it.publicKey || "")
    var fingerprint = String(key.fingerprint || key.keyFingerprint || it.fingerprint || it.keyFingerprint || "")
    var raw = {
      id: String(it.id), name: String(it.name || "Untitled"), type: 5,
      organizationId: it.organizationId ? String(it.organizationId) : null,
      folderId: it.folderId ? String(it.folderId) : null,
      favorite: Boolean(it.favorite), reprompt: Number(it.reprompt || 0),
      sshKey: { publicKey: publicKey, fingerprint: fingerprint }
    }
    out.push({ id: String(it.id), organizationId: raw.organizationId, folderId: raw.folderId,
      name: raw.name, type: "sshKey", typeCode: 5, favorite: raw.favorite,
      username: "", password: "", hasPassword: false, hasTotp: false, totpKey: "",
      uris: [], attachments: [], hasAttachments: false,
      subtitle: fingerprint || publicKey || "SSH Key", notes: "",
      publicKey: publicKey, fingerprint: fingerprint, rawObject: raw })
  }
  out.sort(function(a, b) { if (a.favorite !== b.favorite) return a.favorite ? -1 : 1; return compareNames(a, b) })
  return out
}

function parseSanitizedEnvelope(raw) {
  var envelope = null
  try { envelope = JSON.parse(raw) } catch (e) { return null }
  if (!envelope || typeof envelope !== "object" || !Array.isArray(envelope.items) || !Array.isArray(envelope.sshKeys)) return null
  // The capability flag is derived from the key list, so the envelope is read
  // without it. A flag that contradicts the list means the document was not
  // produced by this filter, and the whole read fails closed.
  var expectedCapability = envelope.sshKeys.length > 0 ? "confirmed" : "unconfirmed"
  if (envelope.sshCapability !== undefined && envelope.sshCapability !== expectedCapability) return null
  var sshKeys = parseSshKeys(envelope.sshKeys)
  var items = parseItems(JSON.stringify(envelope.items)).concat(sshKeys)
  items.sort(function(a, b) { if (a.favorite !== b.favorite) return a.favorite ? -1 : 1; return compareNames(a, b) })
  return {
    items: items,
    sshKeys: sshKeys,
    sshCapability: expectedCapability
  }
}

function parseSanitizedItems(raw) {
  var envelope = parseSanitizedEnvelope(raw)
  return envelope ? envelope.items : []
}

function parseSanitizedCapability(raw) {
  var envelope = parseSanitizedEnvelope(raw)
  return envelope ? envelope.sshCapability : "unconfirmed"
}

function parseItemDetail(raw) {
  var it = null
  try {
    it = JSON.parse(raw)
  } catch (e) {
    return null
  }
  return itemDetailFromObject(it)
}

// `bw list items` already returns complete cipher objects -- password, TOTP
// key, card, identity and custom fields included -- and parseItems keeps each
// one as `rawObject`. So opening an item needs no second trip to the CLI: the
// detail view is built from what the list already fetched, which is the
// difference between a spinner and an instant open. `bw get item` costs a full
// CLI bootstrap (~0.9s) plus service init (~2s) before it decrypts anything.
function itemDetailFromObject(it) {
  if (!it || typeof it !== "object") return null

  if (Number(it.type) === 5) {
    var sshKey = it.sshKey || {}
    return { id: String(it.id || ""), organizationId: it.organizationId ? String(it.organizationId) : null,
      folderId: it.folderId ? String(it.folderId) : null, name: String(it.name || "Untitled"),
      type: "sshKey", typeCode: 5, favorite: Boolean(it.favorite), notes: "",
      username: "", password: "", hasTotp: false, totpKey: "", uris: [], attachments: [],
      hasAttachments: false, card: null, identity: null, fields: [],
      publicKey: String(sshKey.publicKey || it.publicKey || ""),
      fingerprint: String(sshKey.fingerprint || sshKey.keyFingerprint || it.fingerprint || it.keyFingerprint || ""), rawObject: it }
  }

  var login = it.login || {}
  var uris = loginUris(login)
  var attachments = parseAttachments(it.attachments)

  return {
    id: String(it.id || ""),
    organizationId: it.organizationId ? String(it.organizationId) : null,
    folderId: it.folderId ? String(it.folderId) : null,
    name: String(it.name || "Untitled"),
    type: itemTypeName(it.type),
    typeCode: Number(it.type || 1),
    favorite: Boolean(it.favorite),
    notes: String(it.notes || ""),
    username: String(login.username || ""),
    password: String(login.password || ""),
    hasTotp: Boolean(login.totp),
    totpKey: String(login.totp || ""),
    uris: uris,
    attachments: attachments,
    hasAttachments: attachments.length > 0,
    card: cardDetail(it.card),
    identity: identityDetail(it.identity),
    fields: itemCustomFields(it.fields),
    rawObject: it
  }
}

// -------------------------------------------------------------------------
// Filtering & Searching
// -------------------------------------------------------------------------

function matchesQuery(item, query) {
  if (!query) return true
  var q = String(query).toLowerCase().trim()
  if (!q) return true

  if (String(item.name).toLowerCase().indexOf(q) !== -1) return true
  if (String(item.username).toLowerCase().indexOf(q) !== -1) return true
  if (String(item.notes).toLowerCase().indexOf(q) !== -1) return true
  if (String(item.publicKey || "").toLowerCase().indexOf(q) !== -1) return true
  if (String(item.fingerprint || "").toLowerCase().indexOf(q) !== -1) return true

  // toList, not Array.isArray: this item came back out of a QML `var`
  // property, and the array nested inside it did not survive that trip as one.
  // The check that reads right is the check that quietly turned URL search off
  // in the panel while every test here went on passing.
  var uris = toList(item.uris)
  for (var i = 0; i < uris.length; i++) {
    if (String(uris[i]).toLowerCase().indexOf(q) !== -1) return true
  }
  return false
}

function matchesOrganizationFilter(item, organization) {
  if (organization === "personal") return !item.organizationId
  return organization === "all" || item.organizationId === organization
}

function matchesFolderFilter(item, folder) {
  if (folder === "none") return !item.folderId
  return folder === "all" || item.folderId === folder
}

function matchesCategoryFilter(item, category) {
  if (category === "favorite") return Boolean(item.favorite)
  return category === "all" || String(item.type || "").toLowerCase() === String(category || "").toLowerCase()
}

function filterItems(items, query, category, selectedOrg, selectedFolder) {
  if (!Array.isArray(items)) return []
  var q = String(query || "").toLowerCase().trim()
  var cat = String(category || "all").toLowerCase()
  var org = String(selectedOrg || "all")
  var folder = String(selectedFolder || "all")

  var out = []
  for (var i = 0; i < items.length; i++) {
    var it = items[i]
    if (!matchesOrganizationFilter(it, org)) continue
    if (!matchesFolderFilter(it, folder)) continue
    if (!matchesCategoryFilter(it, cat)) continue
    if (q && !matchesQuery(it, q)) continue
    out.push(it)
  }
  return out
}

// Returns "" when the form is savable, or the reason it is not.
function validateItemForm(name, organizationId, collectionIds) {
  if (!String(name || "").trim()) return "Item title is required"
  var isOrg = organizationId && organizationId !== "personal" && organizationId !== "all"
  if (isOrg && (!Array.isArray(collectionIds) || collectionIds.length === 0)) {
    return "Pick at least one collection for an organization item"
  }
  return ""
}

function maskString(str) {
  if (!str) return ""
  return "•".repeat(Math.min(str.length, 16))
}

// There is deliberately no local password generator here. QML's Math.random()
// is not a CSPRNG -- it is seeded predictably and its output can be recovered
// from a handful of samples -- which makes it unfit to produce a password that
// will guard an account. The only generator is generateCommand() further down,
// which delegates to `bw generate`, and the item form reaches it by way of the
// generator screen. See openGenerator() in Panel.qml.

// -------------------------------------------------------------------------
// Payload Builders for Create & Edit
// -------------------------------------------------------------------------

function selectedOrganizationId(organizationId) {
  if (!organizationId || organizationId === "personal" || organizationId === "all") return null
  return String(organizationId)
}

function selectedFolderId(folderId) {
  if (!folderId || folderId === "all" || folderId === "none") return null
  return String(folderId)
}

function selectedCollectionIds(collectionIds) {
  if (!Array.isArray(collectionIds) || collectionIds.length === 0) return null
  return collectionIds.slice()
}

function updateLoginFields(login, username, password, totp) {
  login.username = String(username || "").trim()
  login.password = String(password || "").trim()
  login.totp = totp && totp.trim() ? totp.trim() : null
}

function buildCreatePayload(typeCode, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds) {
  if (Number(typeCode) === 5) return null
  var payload = {
    type: Number(typeCode || 1),
    name: String(name || "Untitled").trim(),
    notes: String(notes || "").trim(),
    favorite: Boolean(favorite),
    organizationId: selectedOrganizationId(organizationId),
    folderId: selectedFolderId(folderId)
  }

  // Only org-owned items carry collections, and such an item must be in at
  // least one -- Bitwarden rejects it otherwise. Omit the key entirely when
  // none were chosen rather than sending an empty array, which would change
  // what existing callers send.
  var collections = selectedCollectionIds(collectionIds)
  if (payload.organizationId && collections) payload.collectionIds = collections

  if (Number(typeCode) === 1) { // Login
    var login = {}
    updateLoginFields(login, username, password, totp)
    login.uris = uri && uri.trim() ? [{ match: null, uri: uri.trim() }] : []
    payload.login = login
  } else if (Number(typeCode) === 2) { // Secure Note
    payload.secureNote = { type: 0 }
  }

  return payload
}

function buildEditPayload(existingItem, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds) {
  if (existingItem && (Number(existingItem.typeCode || existingItem.type) === 5
      || (existingItem.rawObject && Number(existingItem.rawObject.type) === 5))) return null
  var payload = existingItem && existingItem.rawObject ? JSON.parse(JSON.stringify(existingItem.rawObject)) : {}
  payload.name = String(name || "Untitled").trim()
  payload.notes = String(notes || "").trim()
  payload.favorite = Boolean(favorite)
  // Set *and* clear. Only assigning meant picking "My Vault" for an item that
  // belonged to an organization left it in the organization, so the form said
  // one thing and the vault kept another.
  payload.organizationId = selectedOrganizationId(organizationId)
  // An explicit empty selection means "no folder", so this must be able to
  // clear an existing assignment, not only set one.
  payload.folderId = selectedFolderId(folderId)

  if (payload.organizationId) {
    payload.collectionIds = selectedCollectionIds(collectionIds) || payload.collectionIds || []
  } else {
    delete payload.collectionIds
  }

  if (payload.type === 1 || !payload.type) {
    if (!payload.login) payload.login = {}
    updateLoginFields(payload.login, username, password, totp)
    if (uri && uri.trim()) {
      payload.login.uris = [{ match: null, uri: uri.trim() }]
    }
  }

  return payload
}

// -------------------------------------------------------------------------
// Context-Aware Window & Active Tab Matching
// -------------------------------------------------------------------------
//
// Hyprland exposes only the window class and title -- browsers do not publish
// the active tab URL over any interface we can read, so the page title is the
// only signal available. Everything below is built to squeeze a reliable
// domain/brand out of a title while refusing to guess when the title says
// nothing useful.

// Labels that carry no identity. Never matched against a page title, and
// dropped when tokenising titles and item names.
var GENERIC_LABELS = {
  "www": 1, "www2": 1, "web": 1, "app": 1, "apps": 1, "mobile": 1, "my": 1,
  "secure": 1, "login": 1, "signin": 1, "sign": 1, "logon": 1, "auth": 1,
  "oauth": 1, "sso": 1, "idp": 1, "account": 1, "accounts": 1, "portal": 1,
  "admin": 1, "dash": 1, "dashboard": 1, "console": 1, "home": 1, "welcome": 1,
  "overview": 1, "page": 1, "site": 1, "online": 1, "cloud": 1, "server": 1,
  "service": 1, "services": 1, "api": 1, "cdn": 1, "static": 1, "assets": 1,
  "local": 1, "localhost": 1, "localdomain": 1, "internal": 1, "intranet": 1,
  "lan": 1, "dev": 1, "test": 1, "staging": 1, "prod": 1, "the": 1, "and": 1,
  "for": 1, "with": 1, "your": 1, "new": 1, "inbox": 1, "settings": 1
}

// Public suffixes we accept as the tail of a hostname. Deliberately a closed
// list: it is what stops "config.json" or "v1.2" from being read as a domain.
var TLDS = {
  "com": 1, "org": 1, "net": 1, "edu": 1, "gov": 1, "mil": 1, "int": 1,
  "io": 1, "co": 1, "ai": 1, "app": 1, "dev": 1, "me": 1, "tv": 1, "cc": 1,
  "info": 1, "biz": 1, "name": 1, "pro": 1, "xyz": 1, "online": 1, "site": 1,
  "shop": 1, "store": 1, "tech": 1, "cloud": 1, "page": 1, "blog": 1, "wiki": 1,
  "news": 1, "media": 1, "email": 1, "chat": 1, "social": 1, "games": 1,
  "software": 1, "systems": 1, "network": 1, "digital": 1, "finance": 1,
  "bank": 1, "money": 1, "health": 1, "life": 1, "world": 1, "space": 1,
  "link": 1, "click": 1, "one": 1, "run": 1, "sh": 1, "gg": 1, "fm": 1,
  "to": 1, "ly": 1, "us": 1, "uk": 1, "ca": 1, "au": 1, "nz": 1, "de": 1,
  "fr": 1, "es": 1, "it": 1, "nl": 1, "be": 1, "ch": 1, "at": 1, "se": 1,
  "no": 1, "dk": 1, "fi": 1, "pl": 1, "cz": 1, "pt": 1, "ie": 1, "gr": 1,
  "ru": 1, "ua": 1, "tr": 1, "il": 1, "in": 1, "jp": 1, "cn": 1, "kr": 1,
  "hk": 1, "tw": 1, "sg": 1, "my": 1, "id": 1, "th": 1, "vn": 1, "ph": 1,
  "br": 1, "mx": 1, "ar": 1, "cl": 1, "za": 1, "eu": 1,
  // Non-public suffixes that still appear on self-hosted LAN services.
  "local": 1, "lan": 1, "home": 1, "internal": 1, "arpa": 1, "localdomain": 1
}

// Second-level suffixes: only ever treated as part of the suffix when a third
// label follows (bbc.co.uk -> bbc, but co.uk alone stays as-is).
var MULTI_SLD = { "co": 1, "com": 1, "net": 1, "org": 1, "ac": 1, "gov": 1, "edu": 1, "or": 1, "ne": 1 }

// Brands whose sites are commonly titled with a different word than the domain
// that ends up on the vault item. Conservative on purpose -- each entry maps a
// title word to the registrable name it should also count as.
var BRAND_ALIASES = {
  "gmail": "google", "googlemail": "google", "youtube": "google",
  "hotmail": "microsoft", "outlook": "microsoft", "live": "microsoft",
  "onedrive": "microsoft", "office": "microsoft", "microsoft365": "microsoft",
  "icloud": "apple", "appleid": "apple",
  "fb": "facebook", "messenger": "facebook", "instagram": "facebook"
}

var BROWSER_CLASS_RE = /chrome|chromium|firefox|brave|zen|vivaldi|edge|opera|epiphany|qutebrowser|librewolf|floorp|waterfox|thorium|helium/i
var TERMINAL_CLASS_RE = /foot|alacritty|kitty|ghostty|terminal|konsole|wezterm|xterm|rxvt|tilix|st-256color/i
var SHELL_CLASS_RE = /^(quickshell|omarchy|omarchy-shell|omarchy-menu)$/i
var REMOTE_SESSION_RE = /(?:^|\s)(?:ssh|mosh|sftp)\s+(?:-\S+\s+)*(?:[a-zA-Z0-9_.-]+@)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)/i

var BROWSER_BRAND_RE = /\s*[-—–|·•]\s*(Google Chrome|Chromium|Mozilla Firefox|Firefox Developer Edition|Firefox|Brave(?:\s*Browser)?|Zen(?:\s*Browser)?|Vivaldi|Microsoft.​Edge|Microsoft Edge|Edge|Opera(?:\s*GX)?|LibreWolf|Floorp|Waterfox|Thorium|Helium|Epiphany|GNOME Web|qutebrowser)\s*$/i

var TITLE_SEPARATOR_RE = /\s*[|·•—–]\s*|\s+[-]\s+|\s*::\s*/

// How much of a window title is ever looked at. A page writes its own title
// and nothing obliges it to be short, while every part of the match runs over
// the whole of it once per vault item -- so a title long enough is a vault
// large enough away from a visible freeze of the shell. Nothing past a couple
// of hundred characters identifies a site anyway; the rest is prose.
var MAX_TITLE_CHARS = 512

// Strip anything that is chrome rather than content: unread counters, media
// indicators, private-window markers, and leading sign-in verbs.
function stripTitleNoise(title) {
  var t = String(title || "").trim()
  t = t.replace(BROWSER_BRAND_RE, "").trim()
  t = t.replace(/\s*[-—–|]?\s*\((?:Private Browsing|Incognito|Private)\)\s*$/i, "").trim()
  t = t.replace(/\s*[-—–|]\s*(?:Audio playing|Muted|Playing|Paused)\s*$/i, "").trim()
  t = t.replace(/^[\s]*[\(\[]\s*\d+\+?\s*[\)\]]\s*/, "").trim()
  t = t.replace(/^\s*\d+\s*[-—–|·]\s*/, "").trim()
  t = t.replace(/^(?:Sign in to|Sign into|Sign in|Sign In|Log in to|Log into|Log in|Login to|Login|Welcome to|Welcome back to|Welcome|Authenticate to|Authenticate)\b[\s:·—–|-]*/i, "").trim()
  t = t.replace(/^[\s:·—–|-]+/, "").replace(/[\s:·—–|-]+$/, "").trim()
  return t
}

// Collapse to bare alphanumerics so "Home Assistant" and "homeassistant" compare equal.
function squash(str) {
  return String(str || "").toLowerCase().replace(/[^a-z0-9]/g, "")
}

function splitSegments(title) {
  var raw = String(title || "").split(TITLE_SEPARATOR_RE)
  var out = []
  for (var i = 0; i < raw.length; i++) {
    var s = raw[i].trim()
    if (s) out.push(s)
  }
  return out
}

function extractTokens(str) {
  if (!str) return []
  var clean = String(str).toLowerCase().replace(/[^a-z0-9]+/g, " ")
  var words = clean.split(/\s+/)
  var tokens = []
  var seen = {}
  for (var i = 0; i < words.length; i++) {
    var w = words[i].trim()
    if (w.length < 3) continue
    if (GENERIC_LABELS[w] || TLDS[w]) continue
    if (/^\d+$/.test(w)) continue
    if (seen[w]) continue
    seen[w] = 1
    tokens.push(w)
  }
  return tokens
}

// The registrable names a title implies purely through a brand alias, e.g. a
// "Gmail" title implies "google". Kept separate from the literal title tokens:
// only an alias may stand in for a domain the title never actually spelled.
function aliasesFor(tokens) {
  var out = []
  var seen = {}
  for (var i = 0; i < tokens.length; i++) {
    var alias = BRAND_ALIASES[tokens[i]]
    if (alias && tokens.indexOf(alias) === -1 && !seen[alias]) {
      seen[alias] = 1
      out.push(alias)
    }
  }
  return out
}

function isIpAddress(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
}

// Split a hostname into { host, baseDomain, rootName }. rootName is the
// registrable label -- the only part ever compared against a page title.
function parseHost(host) {
  var h = String(host || "").toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "")
  if (!h) return null

  if (isIpAddress(h)) {
    return { host: h, baseDomain: h, rootName: null, isIp: true }
  }

  var parts = h.split(".")
  if (parts.length === 1) {
    return { host: h, baseDomain: h, rootName: parts[0], isIp: false }
  }

  var suffixCount = 1
  if (parts.length >= 3 && MULTI_SLD[parts[parts.length - 2]]) {
    suffixCount = 2
  }
  var rootIdx = parts.length - suffixCount - 1
  if (rootIdx < 0) rootIdx = 0

  return {
    host: h,
    baseDomain: parts.slice(rootIdx).join("."),
    rootName: parts[rootIdx],
    isIp: false
  }
}

function parseDomain(urlStr) {
  if (!urlStr) return null
  var clean = String(urlStr).trim().toLowerCase()
  var match = clean.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^\/@\s]+@)?([a-z0-9._-]+(?::\d+)?)/i)
  if (!match) return null
  return parseHost(match[1])
}

// Pull a hostname out of free text (a page title). Requires a known public
// suffix so version numbers and filenames are not mistaken for domains.
//
// Scanned by splitting rather than by one pass of a host-shaped regex, because
// that regex was quadratic on exactly the input this function exists to read.
// `[a-z0-9-]+(?:\.[a-z0-9-]+)+` against a long run of letters with no dot in
// it makes the engine swallow the whole run, discover the dot is missing, give
// a character back, fail again, and so on to the end of the run -- and then do
// it all over from the next offset. A page decides its own title, so a title of
// 60 kB of one word is a page's to send, and it cost ~2.5 s of the GUI thread
// per scan: the whole shell, bar included, frozen every time the panel opened
// over that tab. Splitting on the characters a host cannot contain and then
// walking the labels between the dots reads the same hosts out in the same
// order, in one linear pass.
function detectDomainInText(text) {
  var s = String(text || "").toLowerCase()
  var runs = s.split(/[^a-z0-9.\-]+/)
  for (var r = 0; r < runs.length; r++) {
    var labels = runs[r].split(".")
    var group = []
    // One past the end, so a group that reaches the end of the run is closed
    // by the same branch that closes one interrupted by an empty label.
    for (var i = 0; i <= labels.length; i++) {
      if (i < labels.length && labels[i]) {
        group.push(labels[i])
        continue
      }
      if (group.length >= 2) {
        var host = group.join(".")
        var tld = group[group.length - 1]
        group = []
        if (!TLDS[tld]) continue
        var parsed = parseHost(host)
        if (!parsed || !parsed.rootName) continue
        if (parsed.rootName.length < 2) continue
        if (GENERIC_LABELS[parsed.rootName]) continue
        return parsed
      }
      group = []
    }
  }
  return null
}

function itemDomains(item) {
  var out = []
  if (!item) return out
  // Same round trip, same reason as matchesQuery: an Array.isArray here is a
  // domain match that works in Node and never fires in the panel.
  var uris = toList(item.uris)
  for (var i = 0; i < uris.length; i++) {
    var d = parseDomain(uris[i])
    if (d) out.push(d)
  }
  return out
}

function hasWholeWord(haystack, word) {
  if (!haystack || !word) return false
  var escaped = String(word).replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")
  return new RegExp("(?:^|[^a-z0-9])" + escaped + "(?:$|[^a-z0-9])", "i").test(haystack)
}

// -------------------------------------------------------------------------

function getActiveWindowFromData(windowData) {
  if (!windowData) return null

  if (Array.isArray(windowData)) {
    // hyprctl clients -j: focusHistoryID 0 is the most recently focused window.
    var clients = windowData.slice().filter(function(c) {
      return c && c.mapped !== false && String(c.class || c.initialClass || "").trim() !== ""
    })
    clients.sort(function(a, b) {
      return (a.focusHistoryID === undefined ? 999 : a.focusHistoryID) - (b.focusHistoryID === undefined ? 999 : b.focusHistoryID)
    })
    for (var i = 0; i < clients.length; i++) {
      if (!SHELL_CLASS_RE.test(String(clients[i].class || clients[i].initialClass || ""))) {
        return clients[i]
      }
    }
    return clients[0] || null
  }

  if (!windowData.class && !windowData.initialClass && !windowData.title) return null
  if (SHELL_CLASS_RE.test(String(windowData.class || windowData.initialClass || ""))) return null
  return windowData
}

function windowIdentity(cls, title) {
  var isBrowser = BROWSER_CLASS_RE.test(cls)
  var isTerminal = TERMINAL_CLASS_RE.test(cls)

  if (isBrowser) {
    var browserTitle = stripTitleNoise(title)
    var browserDomain = detectDomainInText(browserTitle)
    return {
      cleanTitle: browserTitle,
      detectedDomain: browserDomain,
      displayName: browserDomain ? browserDomain.baseDomain : browserTitle,
      isBrowser: isBrowser,
      isTerminal: isTerminal
    }
  }

  if (isTerminal) {
    // Only remote sessions are worth suggesting for; a local shell title
    // ("hostname: ~/dir") describes the machine, not a credential.
    var remoteSession = title.match(REMOTE_SESSION_RE)
    if (!remoteSession) return null
    return {
      cleanTitle: remoteSession[1],
      detectedDomain: parseHost(remoteSession[1]),
      displayName: "SSH: " + remoteSession[1],
      isBrowser: isBrowser,
      isTerminal: isTerminal
    }
  }

  // Native desktop app: the leading segment is the app, the rest is document state.
  var segments = splitSegments(stripTitleNoise(title))
  var appTitle = segments.length > 0 ? segments[0] : ""
  return {
    cleanTitle: appTitle,
    detectedDomain: null,
    displayName: appTitle || cls,
    isBrowser: isBrowser,
    isTerminal: isTerminal
  }
}

function cleanWindowContext(windowData) {
  var w = getActiveWindowFromData(windowData)
  if (!w) return null

  var cls = String(w.class || w.initialClass || "").toLowerCase().trim().slice(0, MAX_TITLE_CHARS)
  var title = String(w.title || w.initialTitle || "").trim().slice(0, MAX_TITLE_CHARS)
  if (!cls && !title) return null

  var identity = windowIdentity(cls, title)
  if (!identity) return null
  var cleanTitle = identity.cleanTitle
  var detectedDomain = identity.detectedDomain
  var displayName = identity.displayName

  if (!cleanTitle && !cls) return null

  // Words belonging to a hostname printed in the title must not be reusable as
  // free text, or every item sharing a label ("example") with the current host
  // would match. Strip the host, then re-seed the one name that does count.
  var matchText = cleanTitle
  if (detectedDomain) {
    matchText = matchText.replace(new RegExp(detectedDomain.host.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&"), "gi"), " ").trim()
  }

  var rawTokens = extractTokens(matchText)
  if (detectedDomain && detectedDomain.rootName && !GENERIC_LABELS[detectedDomain.rootName]) {
    if (rawTokens.indexOf(detectedDomain.rootName) === -1) rawTokens.push(detectedDomain.rootName)
  }
  var aliasTokens = aliasesFor(rawTokens)
  var titleTokens = rawTokens.concat(aliasTokens)

  if (displayName.length > 40) {
    displayName = displayName.slice(0, 37) + "..."
  }

  return {
    cls: cls,
    clsSquashed: squash(cls),
    title: cleanTitle,
    rawTitle: title,
    matchText: matchText,
    squashedTitle: squash(cleanTitle),
    squashedMatchText: squash(matchText),
    segments: splitSegments(cleanTitle),
    titleTokens: titleTokens,
    aliasTokens: aliasTokens,
    displayName: displayName,
    detectedDomain: detectedDomain,
    isBrowser: identity.isBrowser,
    isTerminal: identity.isTerminal
  }
}

// Domain to domain. Only reachable when the title actually spelled a host.
function directDomainScore(domains, detectedDomain) {
  if (!detectedDomain) return 0
  var score = 0
  for (var i = 0; i < domains.length; i++) {
    var domain = domains[i]
    if (domain.host === detectedDomain.host) return 100
    if (domain.baseDomain && domain.baseDomain === detectedDomain.baseDomain) score = Math.max(score, 96)
  }
  return score
}

// The item's registrable name appears in the page title.
function domainTitleScore(domains, ctx) {
  var score = 0
  for (var i = 0; i < domains.length; i++) {
    var root = domains[i].rootName
    if (!root || root.length < 3 || GENERIC_LABELS[root] || TLDS[root]) continue

    if (hasWholeWord(ctx.matchText, root)) {
      score = Math.max(score, 90)
    } else if (root.length >= 5 && ctx.squashedMatchText.indexOf(root) !== -1) {
      // "Home Assistant" -> homeassistant.local
      score = Math.max(score, 88)
    } else if (ctx.aliasTokens.indexOf(root) !== -1) {
      // Reached only via a brand alias, e.g. a "Gmail" title -> google.com
      score = Math.max(score, 86)
    }
  }
  return score
}

// The item name matches a whole title segment.
function itemNameTitleScore(nameSquashed, ctx) {
  if (nameSquashed.length < 3) return 0
  var score = 0
  for (var i = 0; i < ctx.segments.length; i++) {
    if (squash(ctx.segments[i]) === nameSquashed) {
      score = 92
      break
    }
  }
  if (nameSquashed.length >= 5 && ctx.squashedTitle.indexOf(nameSquashed) !== -1) {
    score = Math.max(score, 84)
  }
  return score
}

// Shared significant words between the item name and the title.
function sharedTitleTokenScore(nameTokens, titleTokens) {
  var overlap = 0
  for (var i = 0; i < nameTokens.length; i++) {
    if (titleTokens.indexOf(nameTokens[i]) !== -1) overlap++
  }
  return overlap > 0 ? 78 + Math.min(overlap, 3) * 2 : 0
}

// Native app: match the window class against the item.
function nativeAppScore(domains, nameSquashed, ctx) {
  if (ctx.isBrowser || ctx.isTerminal || ctx.clsSquashed.length < 3) return 0
  var score = 0
  for (var i = 0; i < domains.length; i++) {
    var root = domains[i].rootName
    if (root && root.length >= 3 && !GENERIC_LABELS[root] && root === ctx.clsSquashed) {
      score = 92
    }
  }
  if (nameSquashed.length >= 3 && (nameSquashed === ctx.clsSquashed
      || nameSquashed.indexOf(ctx.clsSquashed) !== -1
      || ctx.clsSquashed.indexOf(nameSquashed) !== -1)) {
    score = Math.max(score, 88)
  }
  return score
}

// Score one vault item against the active window. 0 means no match; the bands
// are deliberately spread so a real domain hit always outranks a word hit.
function matchItem(item, ctx) {
  if (!ctx || !item) return 0
  if (ctx.isTerminal && !ctx.detectedDomain) return 0

  var domains = itemDomains(item)
  var nameSquashed = squash(item.name)
  var nameTokens = extractTokens(item.name)

  var score = directDomainScore(domains, ctx.detectedDomain)
  if (score === 100) return score
  score = Math.max(score, domainTitleScore(domains, ctx))
  score = Math.max(score, itemNameTitleScore(nameSquashed, ctx))
  score = Math.max(score, sharedTitleTokenScore(nameTokens, ctx.titleTokens))
  score = Math.max(score, nativeAppScore(domains, nameSquashed, ctx))

  return score
}

var MATCH_THRESHOLD = 80
var MAX_SUGGESTIONS = 6

function resolveLearnedMatches(items, associations, ctx) {
  // What you taught it comes first, and is never filtered out by the score
  // banding -- an explicit choice outranks anything inferred.
  var byId = {}
  for (var i = 0; i < items.length; i++) {
    if (items[i] && items[i].id) byId[items[i].id] = items[i]
  }

  var matches = []
  var ids = {}
  var learnedRanked = learnedMatchIds(associations, ctx)
  for (var j = 0; j < learnedRanked.length; j++) {
    var hit = byId[learnedRanked[j].itemId]
    if (hit && isLoginItem(hit)) {
      matches.push(hit)
      ids[hit.id] = true
    }
  }
  return { matches: matches, ids: ids }
}

function scoreContextualMatches(items, ctx) {
  var scored = []
  for (var i = 0; i < items.length; i++) {
    if (!isLoginItem(items[i])) continue
    var score = matchItem(items[i], ctx)
    if (score >= MATCH_THRESHOLD) {
      scored.push({ item: items[i], score: score, index: i })
    }
  }
  return scored
}

function isLoginItem(item) {
  return Boolean(item && (Number(item.typeCode) === 1 || item.type === "login"
    || (item.typeCode === undefined && item.type === undefined)))
}

function compareContextualMatches(a, b) {
  if (b.score !== a.score) return b.score - a.score
  if (a.item.favorite !== b.item.favorite) return a.item.favorite ? -1 : 1
  return a.index - b.index
}

function findContextualMatches(items, windowData, associations) {
  var empty = { matches: [], context: null, learnedIds: {} }

  var ctx = cleanWindowContext(windowData)
  if (!ctx || !Array.isArray(items) || items.length === 0) return empty
  if (ctx.isTerminal && !ctx.detectedDomain) return empty
  if (!ctx.title && !ctx.detectedDomain && !ctx.clsSquashed) return empty

  var learned = resolveLearnedMatches(items, associations, ctx)
  var scored = scoreContextualMatches(items, ctx)
  if (scored.length === 0 && learned.matches.length === 0) return empty
  if (scored.length === 0) {
    return { matches: learned.matches.slice(0, MAX_SUGGESTIONS), context: ctx, learnedIds: learned.ids }
  }

  scored.sort(compareContextualMatches)

  // Keep only the strongest band. A confirmed domain hit discards everything
  // weaker (so a second account on the same site survives, but unrelated items
  // that merely share a word do not).
  var best = scored[0].score
  var cutoff = best >= 96 ? 96 : Math.max(MATCH_THRESHOLD, best - 8)

  var matches = learned.matches.slice()
  for (var m = 0; m < scored.length && matches.length < MAX_SUGGESTIONS; m++) {
    if (scored[m].score >= cutoff && !learned.ids[scored[m].item.id]) {
      matches.push(scored[m].item)
    }
  }

  return { matches: matches.slice(0, MAX_SUGGESTIONS), context: ctx, learnedIds: learned.ids }
}

// -------------------------------------------------------------------------
// Learned Associations
// -------------------------------------------------------------------------
//
// Titles are a weak signal and some sites cannot be matched from one at all:
// a page titled "Home - authentik" served from auth.example.xyz shares no word
// with the stored credential, so no heuristic will ever connect them. Instead
// of guessing harder, the panel remembers. Picking an item while a window is
// active records that window's identifying keys against the item, and the next
// visit suggests it outright. Learning beats every heuristic tier below it.

var ASSOC_VERSION = 1
var ASSOC_ENV = "QSBW_ASSOC"
var ASSOC_DIR = "${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli"

function associationsEnvVar() {
  return ASSOC_ENV
}

function associationsReadCommand() {
  var script = "d=\"" + ASSOC_DIR + "\"; f=\"$d/associations.json\"; "
    + "if [ -d \"$d\" ] && [ ! -L \"$d\" ] && [ -f \"$f\" ] && [ ! -L \"$f\" ]; then "
    + "head -c " + MAX_ASSOC_BYTES + " \"$f\" 2>/dev/null || printf '{}'; else printf '{}'; fi"
  return ["bash", "-c", script]
}

// Written through the environment for the same reason the keyring stores are:
// Process.write() cannot deliver EOF, so a shell supplies the payload instead.
function associationsWriteCommand() {
  // Replace atomically from a private temporary file. Redirection straight to
  // the destination would follow a symlink and would preserve an old 0644
  // mode; rename replaces the directory entry itself and the fresh file is
  // born 0600 under this umask.
  var script = "set -e; d=\"" + ASSOC_DIR + "\"; "
    + "if [ -e \"$d\" ]; then [ -d \"$d\" ] && [ ! -L \"$d\" ] || exit 1; "
    + "else (umask 077 && mkdir -p \"$d\") || exit 1; fi; chmod 700 \"$d\"; "
    + "umask 077; tmp=$(mktemp -- \"$d/.associations.XXXXXXXX\"); "
    + "trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; "
    + "printf '%s' \"$" + ASSOC_ENV + "\" > \"$tmp\"; chmod 600 \"$tmp\"; "
    + "mv -fT -- \"$tmp\" \"$d/associations.json\"; trap - EXIT HUP INT TERM"
  return ["bash", "-c", script]
}

// Logging out has to take this with it. The store is a list of the domains,
// app names and title words the user has credentials for, each stamped with
// when it was last used -- a browsing-shaped record of the account, in the
// clear, under an account that is no longer signed in. The keyring entries
// are already cleared for exactly that reason; this file was the one piece of
// the account's data left behind, and it has no expiry of its own.
//
// The directory stays: it is created 700 on the next write. The panel waits
// for an in-flight atomic writer to exit before it runs this clear, so logout
// cannot be followed by that writer resurrecting the file.
function associationsClearCommand() {
  var script = "d=\"" + ASSOC_DIR + "\"; "
    + "if [ -d \"$d\" ] && [ ! -L \"$d\" ]; then rm -f -- \"$d/associations.json\" 2>/dev/null; fi; exit 0"
  return ["bash", "-c", script]
}

function emptyAssociations() {
  return { version: ASSOC_VERSION, keys: {} }
}

function associationKeyWeight(key) {
  var value = String(key || "")
  if (value.length > MAX_TITLE_CHARS + 16) return 0
  if (/^domain:[a-z0-9][a-z0-9.-]*$/.test(value)) return 3
  if (/^app:[a-z0-9]+$/.test(value)) return 2
  if (/^word:[a-z0-9]+$/.test(value)) return 1
  return 0
}

function cleanAssociationEntry(key, entry) {
  var weight = associationKeyWeight(key)
  if (!weight || !entry || typeof entry !== "object" || Array.isArray(entry)) return null

  if (typeof entry.itemId !== "string"
      || entry.itemId.length === 0 || entry.itemId.length > 256
      || /[\x00-\x1f\x7f]/.test(entry.itemId)) return null

  var count = Number(entry.count)
  if (!isFinite(count) || count < 1) count = 1
  count = Math.min(1000000, Math.floor(count))

  var updated = typeof entry.updated === "string" ? entry.updated : ""
  if (updated.length > 64 || /[\x00-\x1f\x7f]/.test(updated)) updated = ""

  return { itemId: entry.itemId, weight: weight, count: count, updated: updated }
}

function parseAssociations(raw) {
  var parsed = null
  try {
    parsed = JSON.parse(String(raw || "").trim() || "{}")
  } catch (e) {
    return emptyAssociations()
  }
  var version = Number(parsed && parsed.version === undefined ? ASSOC_VERSION : parsed.version)
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || version !== ASSOC_VERSION || !parsed.keys
      || typeof parsed.keys !== "object" || Array.isArray(parsed.keys)) {
    return emptyAssociations()
  }

  var clean = emptyAssociations()
  for (var key in parsed.keys) {
    if (!Object.prototype.hasOwnProperty.call(parsed.keys, key)) continue
    var entry = cleanAssociationEntry(key, parsed.keys[key])
    if (entry) clean.keys[key] = entry
  }
  return clean
}

function serializeAssociations(assoc) {
  return JSON.stringify(assoc && assoc.keys ? assoc : emptyAssociations())
}

// The identifying keys for a window, strongest first. A domain is definitive;
// an app class is nearly so; individual title words are the weak fallback that
// makes an untitled-domain site like authentik learnable at all.
function contextKeys(ctx) {
  if (!ctx) return []
  var keys = []

  if (ctx.detectedDomain && ctx.detectedDomain.baseDomain && !ctx.detectedDomain.isIp) {
    keys.push({ key: "domain:" + ctx.detectedDomain.baseDomain, weight: 3 })
  }
  if (!ctx.isBrowser && !ctx.isTerminal && ctx.clsSquashed && ctx.clsSquashed.length >= 3) {
    keys.push({ key: "app:" + ctx.clsSquashed, weight: 2 })
  }
  for (var i = 0; i < ctx.titleTokens.length; i++) {
    keys.push({ key: "word:" + ctx.titleTokens[i], weight: 1 })
  }
  return keys
}

// How large the store may get on the way out. It only ever grew, and it is
// read back through a `head -c` cap: the first read past that cap returns a
// truncated object, which does not parse, which is indistinguishable here from
// no store at all -- so the next pick overwrites everything the user ever
// taught it with a fresh empty file. Since a title's words each become a key
// and a page picks its own title, that erasure is something a page can drive.
// Half the reader's cap, so the estimate below has room to be wrong.
var MAX_ASSOC_WRITE_BYTES = MAX_ASSOC_BYTES / 2

// Last pick wins: re-recording a key that pointed elsewhere retargets it, so a
// word learned from the wrong page corrects itself the next time you choose.
function recordAssociation(assoc, ctx, itemId, timestamp) {
  var next = { version: ASSOC_VERSION, keys: {} }
  var k
  for (k in assoc.keys) next.keys[k] = assoc.keys[k]

  var keys = contextKeys(ctx)
  if (keys.length === 0 || !itemId) return next

  for (var i = 0; i < keys.length; i++) {
    var existing = next.keys[keys[i].key]
    var count = (existing && existing.itemId === itemId) ? Number(existing.count || 0) + 1 : 1
    next.keys[keys[i].key] = {
      itemId: String(itemId),
      weight: keys[i].weight,
      count: count,
      updated: String(timestamp || "")
    }
  }

  return trimAssociations(next)
}

// Newest kept first, by the ISO timestamp each entry carries, until the budget
// is spent. An entry with no timestamp predates the field, so it sorts oldest
// and is the first to go.
function trimAssociations(assoc) {
  var all = []
  var k
  for (k in assoc.keys) all.push(k)

  all.sort(function(a, b) {
    var ua = String((assoc.keys[a] && assoc.keys[a].updated) || "")
    var ub = String((assoc.keys[b] && assoc.keys[b].updated) || "")
    if (ua !== ub) return ua < ub ? 1 : -1
    return a < b ? 1 : -1
  })

  var used = 0
  var kept = []
  for (var i = 0; i < all.length; i++) {
    used += all[i].length + String(JSON.stringify(assoc.keys[all[i]])).length + 4
    if (used > MAX_ASSOC_WRITE_BYTES) break
    kept.push(all[i])
  }
  if (kept.length === all.length) return assoc

  var trimmed = { version: assoc.version, keys: {} }
  for (var j = 0; j < kept.length; j++) trimmed.keys[kept[j]] = assoc.keys[kept[j]]
  return trimmed
}

function forgetAssociation(assoc, ctx, itemId) {
  var next = { version: ASSOC_VERSION, keys: {} }
  var keys = contextKeys(ctx)
  var drop = {}
  for (var i = 0; i < keys.length; i++) drop[keys[i].key] = 1

  for (var k in assoc.keys) {
    var entry = assoc.keys[k]
    if (drop[k] && (!itemId || entry.itemId === itemId)) continue
    next.keys[k] = entry
  }
  return next
}

// True when this exact item is already what the context resolves to, used to
// decide whether a pick is worth recording and how to label the pin action.
function isAssociated(assoc, ctx, itemId) {
  if (!assoc || !ctx || !itemId) return false
  var keys = contextKeys(ctx)
  for (var i = 0; i < keys.length; i++) {
    var entry = assoc.keys[keys[i].key]
    if (entry && entry.itemId === itemId) return true
  }
  return false
}

function learnedMatchIds(assoc, ctx) {
  if (!assoc || !assoc.keys || !ctx) return []
  var keys = contextKeys(ctx)
  var best = {}

  for (var i = 0; i < keys.length; i++) {
    var entry = assoc.keys[keys[i].key]
    if (!entry || !entry.itemId) continue
    var rank = keys[i].weight * 1000 + Number(entry.count || 1)
    if (!best[entry.itemId] || best[entry.itemId] < rank) best[entry.itemId] = rank
  }

  var out = []
  for (var id in best) out.push({ itemId: id, rank: best[id] })
  out.sort(function(a, b) { return b.rank - a.rank })
  return out
}

// -------------------------------------------------------------------------
// Dependency Checks (Setup Wizard)
// -------------------------------------------------------------------------
//
// What the wizard asks the user to install, checked in one process rather than
// one per tool. Each entry reports present/absent plus the package that
// provides it, so the wizard can offer an exact install command instead of
// advice.
//
// Only tools Omarchy does not already ship belong here. `wl-clipboard`,
// `libsecret` and `hyprland` are in omarchy-base.packages, and `glib2`,
// `systemd` and `openssl` come with the system, so listing them turned a
// first-run screen into a checklist of rows that are green on every machine
// this plugin can run on -- noise in front of the one row that is not. The
// plugin still shells out to all of them; they are simply not a decision the
// user has to make. Anything added here must be something an Omarchy install
// can genuinely lack.
var DEPENDENCIES = [
  {
    key: "bw", label: "Bitwarden CLI", binary: "bw", pkg: "bitwarden-cli", aur: false,
    required: true,
    purpose: "Reads and writes your vault. The panel installs it for you on first run."
  },
  {
    key: "jq", label: "jq", binary: "jq", pkg: "jq", aur: false,
    required: true,
    purpose: "Safely strips SSH private keys before the panel reads your vault."
  },
  {
    // Not an `omarchy pkg add` row. Installing fprintd on its own gets nobody
    // anywhere: `ready` also wants an enrolled finger and the PAM stack at
    // /etc/pam.d/omarchy-lock-fingerprint, and a package install produces
    // neither -- the row would stay red however many times it was pressed.
    // `omarchy setup security fingerprint` is the whole job in one command
    // (reader detection, libfprint/fprintd/usbutils, enrolment, verification,
    // then the PAM stacks), so it owns this row outright.
    key: "fprintd", label: "Fingerprint unlock", binary: "fprintd-list", pkg: "fprintd", aur: false,
    required: false, setup: true,
    // Only shown on a machine with a reader; see `applicable` below.
    purpose: "Unlock the vault with your finger. Omarchy installs the reader stack and enrols you in one step."
  }
]

// One shell round trip: `key=1` or `key=0` per line, plus the fingerprint
// enrolment state, which needs more than a binary being on PATH.
function dependencyCheckCommand() {
  var parts = []
  for (var i = 0; i < DEPENDENCIES.length; i++) {
    var d = DEPENDENCIES[i]
    parts.push("if command -v " + d.binary + " >/dev/null 2>&1; then echo "
      + shellQuote(d.key + "=1") + "; else echo " + shellQuote(d.key + "=0") + "; fi")
  }
  // Never forward arbitrary version output into QML. The CLI gets 64 bytes,
  // and only a strict calendar-version token survives the producer boundary.
  parts.push("if command -v bw >/dev/null 2>&1; then "
    + "__qsbw_bw_version=$(bw -v 2>/dev/null | head -c 64); "
    + "if [[ \"$__qsbw_bw_version\" =~ ^v?[0-9]{4}\\.[0-9]{1,2}\\.[0-9]{1,6}$ ]]; then "
    + "printf 'bw_version=%s\\n' \"$__qsbw_bw_version\"; else echo bw_version=; fi; "
    + "else echo bw_version=; fi")
  parts.push("if [ -f /etc/pam.d/omarchy-lock-fingerprint ] && command -v fprintd-list >/dev/null 2>&1 "
    + "&& fprintd-list \"$USER\" 2>/dev/null | grep -qi finger; then echo fingerprint_ready=1; else echo fingerprint_ready=0; fi")
  // Omarchy's own reader detection, which reads sysfs rather than asking
  // fprintd -- so it answers before anything is installed, which is exactly
  // when the wizard needs to know whether to offer the row at all. A desktop
  // with no reader should not be shown a fingerprint option it can never
  // satisfy.
  parts.push("if command -v omarchy-hw-fingerprint >/dev/null 2>&1 && omarchy-hw-fingerprint >/dev/null 2>&1; "
    + "then echo fingerprint_hw=1; else echo fingerprint_hw=0; fi")
  parts.push("if command -v omarchy >/dev/null 2>&1; then echo omarchy=1; else echo omarchy=0; fi")
  return ["bash", "-c", cappedScript("{ " + parts.join("; ") + "; } | head -c 4096")]
}

function parseDependencies(raw) {
  var found = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    var cut = line.indexOf("=")
    if (cut <= 0) continue
    found[line.slice(0, cut)] = line.slice(cut + 1)
  }

  var bwVersionRaw = String(found["bw_version"] || "").trim()
  var bwVersion = normalizeReleaseVersion(bwVersionRaw)
  var sshCliStatus = "missing"
  if (found["bw"] === "1") sshCliStatus = sshCliSupport(bwVersion)

  var out = []
  for (var d = 0; d < DEPENDENCIES.length; d++) {
    var dep = DEPENDENCIES[d]
    var installed = found[dep.key] === "1"
    var ready = dep.key === "fprintd" ? found["fingerprint_ready"] === "1" : installed
    var note = ""
    if (dep.key === "bw" && installed) {
      if (sshCliStatus === "unsupported") {
        note = "SSH keys need Bitwarden CLI " + SSH_CLI_MIN_VERSION + " or newer"
          + (bwVersion ? "; found " + bwVersion + "." : ".")
      } else if (sshCliStatus === "unknown") {
        note = "Could not read the Bitwarden CLI version. SSH support stays unconfirmed until that is fixed."
      }
    }
    out.push({
      key: dep.key,
      label: dep.label,
      binary: dep.binary,
      pkg: dep.pkg,
      required: dep.required,
      purpose: dep.purpose,
      // Omarchy owns this one end to end, so the wizard offers its setup
      // command rather than a package install. See DEPENDENCIES.
      setup: Boolean(dep.setup),
      // Whether this machine can satisfy the row at all. Hardware the box does
      // not have is not a missing dependency, and listing it as one is how a
      // setup screen grows rows nobody can ever turn green.
      applicable: dep.key === "fprintd" ? found["fingerprint_hw"] === "1" : true,
      installed: installed,
      // fprintd on PATH is not the same as a usable reader with an enrolled finger.
      ready: ready,
      version: dep.key === "bw" ? bwVersion : "",
      note: note
    })
  }
  return {
    items: out,
    hasOmarchy: found["omarchy"] === "1",
    hasFingerprintReader: found["fingerprint_hw"] === "1",
    bwVersion: bwVersion,
    sshCliMinVersion: SSH_CLI_MIN_VERSION,
    sshCliStatus: sshCliStatus
  }
}

// What the setup screen actually draws: the rows this machine can do something
// about. Everything else stays in `items`, where the settings screen and the
// fingerprint wiring still look tools up by key.
function applicableDependencies(deps) {
  var out = []
  if (!deps || !deps.items) return out
  for (var i = 0; i < deps.items.length; i++) {
    if (deps.items[i].applicable) out.push(deps.items[i])
  }
  return out
}

function missingRequired(deps) {
  var missing = []
  if (!deps || !deps.items) return missing
  for (var i = 0; i < deps.items.length; i++) {
    if (deps.items[i].required && !deps.items[i].installed) missing.push(deps.items[i])
  }
  return missing
}

function normalizeReleaseVersion(raw) {
  var match = String(raw || "").trim().match(/^v?(\d{4})\.(\d{1,2})\.(\d{1,6})$/)
  if (!match) return ""
  return Number(match[1]) + "." + Number(match[2]) + "." + Number(match[3])
}

function compareReleaseVersions(a, b) {
  var left = normalizeReleaseVersion(a)
  var right = normalizeReleaseVersion(b)
  if (!left || !right) return null
  var la = left.split(".")
  var ra = right.split(".")
  for (var i = 0; i < 3; i++) {
    var lv = Number(la[i] || 0)
    var rv = Number(ra[i] || 0)
    if (lv < rv) return -1
    if (lv > rv) return 1
  }
  return 0
}

function dependencyByKey(deps, key) {
  if (!deps || !Array.isArray(deps.items)) return null
  for (var i = 0; i < deps.items.length; i++) {
    if (deps.items[i].key === key) return deps.items[i]
  }
  return null
}

function dependencyInstalled(deps, key) {
  var dep = dependencyByKey(deps, key)
  return Boolean(dep && dep.installed)
}

function vaultListMode(deps) {
  return dependencyInstalled(deps, "bw") && dependencyInstalled(deps, "jq") ? "sanitized" : "blocked"
}

function vaultListBlockedMessage(deps) {
  if (!dependencyInstalled(deps, "bw")) return "Bitwarden CLI is not installed yet."
  if (!dependencyInstalled(deps, "jq")) {
    return "jq is required to safely read vault items. Finish setup to continue."
  }
  return "Could not determine how to safely read vault items."
}

// The SSH filter -- and later the agent's setup -- appear only once the
// dependency probe has confirmed a CLI that can decrypt SSH key items. An
// unreadable version counts as unsupported: hiding the SSH surface costs a
// user on an unknown build nothing, while showing it promises a read the CLI
// may not be able to perform.
function sshUiAvailable(deps, checked) {
  return Boolean(checked) && Boolean(deps) && deps.sshCliStatus === "supported"
}

function defaultSshCapability() {
  return {
    state: "unknown",
    keyCount: 0,
    message: "SSH key availability has not been checked yet."
  }
}

function inspectSanitizedVault(raw) {
  var parsed = parseSanitizedEnvelope(raw)
  if (!parsed) return defaultSshCapability()
  if (parsed.sshCapability === "confirmed") {
    return {
      state: "confirmed",
      keyCount: parsed.sshKeys.length,
      message: parsed.sshKeys.length === 1
        ? "1 SSH key found."
        : parsed.sshKeys.length + " SSH keys found."
    }
  }
  return {
    state: "unconfirmed",
    keyCount: 0,
    message: "No SSH keys were returned. Server support remains unconfirmed."
  }
}

// "supported" | "unsupported" | "unknown" for one probed `bw --version`
// string. Anything the probe could not read stays "unknown": SSH stays hidden,
// while ordinary vault items keep working.
function sshCliSupport(version) {
  var normalized = normalizeReleaseVersion(version)
  if (!normalized) return "unknown"
  return compareReleaseVersions(normalized, SSH_CLI_MIN_VERSION) < 0 ? "unsupported" : "supported"
}

function vaultListFailureMessage(stderrText, deps, mode) {
  if (mode === "blocked") return vaultListBlockedMessage(deps)
  // Never pass producer diagnostics through: bw and jq can quote decrypted
  // values in failures. The only detail added here comes from the version the
  // dependency probe already read, never from what the failed read printed.
  var version = deps && deps.bwVersion ? deps.bwVersion : ""
  if (version && compareReleaseVersions(version, SSH_MALFORMED_ITEM_FIX_VERSION) < 0) {
    return SANITIZED_LIST_ERROR + SANITIZED_LIST_SSH_FIX_HINT
  }
  return SANITIZED_LIST_ERROR
}

// -------------------------------------------------------------------------
// SSH companion supervision
// -------------------------------------------------------------------------
//
// The companion is a separate process holding decrypted private keys, so the
// panel supervises it rather than launching and forgetting it: a tracked,
// non-detached Process with stdin held open, stdout parsed a line at a time
// from the moment it starts, and a cleared environment carrying nothing but
// the runtime directory it needs to find its own socket.
//
// Everything here is pure. The panel owns the Process, the timers and the
// clock; this file owns the decisions. That is what keeps the supervision
// asynchronous -- there is no point in this state machine where QML could
// wait for the helper, because none of it can block, and the panel's only
// response to any event is to set a property or arm a timer.
//
// The signing gate is the safety property. It opens on exactly one transition
// -- a well-formed v1 `ready` answering the panel's `hello` -- and closes on
// every other outcome: a malformed or overlong line, an unexpected message
// type, a version mismatch, a stalled handshake, EOF, or a crash. Nothing in
// the ordinary vault reads it, so a helper that never starts costs the user
// nothing but the SSH feature.

// Matches MAX_CONTROL_LINE in the companion. The panel enforces the same
// ceiling on the way back so a helper that has lost its mind cannot make the
// shell allocate without bound.
var SSH_AGENT_CONTROL_VERSION = 1
var SSH_AGENT_MAX_LINE_BYTES = 64 * 1024

// The development helper, built by `cargo build --manifest-path agent/Cargo.toml`.
// Task 18 replaces this with the checksum-validated bundled binary; until then
// the path is still resolved the same way -- inside the plugin directory, from
// an absolute base, with no shell and no PATH lookup between here and exec.
var SSH_AGENT_HELPER_RELATIVE = "agent/target/debug/qs-bitwarden-ssh-agent"

// A handshake is two writes and a read on an already-running process. Five
// seconds is far past any honest answer and still short enough that a helper
// wedged before `ready` is reported rather than waited on.
var SSH_AGENT_HANDSHAKE_TIMEOUT_MS = 5000
var SSH_AGENT_BACKOFF_BASE_MS = 500
var SSH_AGENT_BACKOFF_MAX_MS = 30000
var SSH_AGENT_MAX_RESTARTS = 5
// The hard ceiling on `sshAgentApprovalWindowSec`. A grant is a window in
// which a live process signs without asking again, so the cap is a security
// bound and belongs next to the protocol constants rather than in the
// settings screen that happens to draw it.
var SSH_AGENT_APPROVAL_WINDOW_MAX_SEC = 900
// A run that served for this long was working, whatever killed it afterwards.
// Without this, one healthy helper restarted at the end of a long session
// would carry the failure count from a crash loop hours earlier; with it, only
// genuinely consecutive quick deaths reach the restart cap.
var SSH_AGENT_HEALTHY_MS = 60 * 1000

// Messages the companion is allowed to send. An unknown type is a mismatch
// between the panel and a helper binary that should have been replaced with
// it, which is exactly the case the protocol version exists to catch.
var SSH_AGENT_EVENT_TYPES = [
  "ready", "unlock_required", "approval_required", "request_cancelled",
  "keys_loaded", "public_key", "locked", "grants_changed", "state_changed", "error"
]

function sshAgentMaxLineBytes() { return SSH_AGENT_MAX_LINE_BYTES }
function sshAgentApprovalWindowMax() { return SSH_AGENT_APPROVAL_WINDOW_MAX_SEC }
function sshAgentMaxRestarts() { return SSH_AGENT_MAX_RESTARTS }
function sshAgentHandshakeTimeoutMs() { return SSH_AGENT_HANDSHAKE_TIMEOUT_MS }

// The plugin's own directory, from the `file://` URL QML resolves for it.
// This is the base for the only executable the panel launches by path rather
// than by name, so it is validated rather than trusted: absolute, `file:`
// scheme or nothing, and no traversal segment either literal or percent-
// encoded. A URL that fails any of those yields "", which disables the helper
// instead of resolving an executable somewhere else on the disk.
function pluginDirFromUrl(url) {
  if (typeof url !== "string" || url === "") return ""
  var raw = url
  if (raw.indexOf("file://") === 0) {
    raw = raw.slice("file://".length)
  } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) {
    return ""
  }
  var decoded = raw
  try {
    decoded = decodeURIComponent(raw)
  } catch (e) {
    return ""
  }
  if (decoded.charAt(0) !== "/") return ""
  while (decoded.length > 1 && decoded.charAt(decoded.length - 1) === "/") {
    decoded = decoded.slice(0, decoded.length - 1)
  }
  var parts = decoded.split("/")
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === "." || parts[i] === "..") return ""
  }
  return decoded
}

function sshAgentHelperPath(pluginDir) {
  if (typeof pluginDir !== "string" || pluginDir.charAt(0) !== "/") return ""
  var base = pluginDir
  while (base.length > 1 && base.charAt(base.length - 1) === "/") {
    base = base.slice(0, base.length - 1)
  }
  var parts = base.split("/")
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === "." || parts[i] === "..") return ""
  }
  return base + "/" + SSH_AGENT_HELPER_RELATIVE
}

// No `bash -c` wrapper, unlike every `bw` call in this file. Those need a
// shell for their output caps; this one needs the opposite -- an unwrapped
// child whose stdin, stdout and lifetime belong to the Process object, so
// closing stdin reaches the helper itself and killing the Process kills the
// thing holding the keys rather than a shell that spawned it.
function sshAgentHelperCommand(pluginDir, source) {
  var candidates = sshAgentHelperCandidates(pluginDir)
  for (var i = 0; i < candidates.length; i++) {
    if (candidates[i].source === source) return [candidates[i].path]
  }
  // No accepted source means the inspection has not run or did not accept
  // anything, and launching a guess would defeat the point of inspecting.
  return []
}

// The companion needs no PATH, no HOME, and no vault credential of any kind:
// it spawns nothing and runs no `bw`. XDG_RUNTIME_DIR is the single variable
// it reads, to find the private directory its socket and FIFO live in. Paired
// with `clearEnvironment: true` on the Process, this is the whole environment
// the helper is given -- BW_SESSION cannot leak into it because it is not
// there to leak.
function sshAgentHelperEnv(runtimeDir) {
  if (typeof runtimeDir !== "string" || runtimeDir.charAt(0) !== "/") return null
  return { XDG_RUNTIME_DIR: runtimeDir }
}

function sshAgentHelloLine() {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "hello" }) + "\n"
}

function sshAgentShutdownLine() {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "shutdown" }) + "\n"
}

// The cap is in bytes because the companion's is. Counting UTF-16 units would
// let a line of three-byte characters through at three times the ceiling.
function utf8ByteLength(text) {
  // A UTF-8 byte count is never below the UTF-16 unit count, so anything
  // already longer than the cap in characters is over it in bytes. Checking
  // that first keeps the loop off a line that is megabytes of junk.
  if (text.length > SSH_AGENT_MAX_LINE_BYTES) return text.length
  var bytes = 0
  for (var i = 0; i < text.length; i++) {
    var code = text.charCodeAt(i)
    if (code < 0x80) bytes += 1
    else if (code < 0x800) bytes += 2
    else if (code >= 0xd800 && code <= 0xdbff) { bytes += 4; i++ }
    else bytes += 3
  }
  return bytes
}

// One line of companion stdout. Returns {ok:true, message} or {ok:false, code,
// fatal}. Only a blank line is non-fatal: SplitParser can hand back the empty
// remainder around a final newline, and that is not a protocol failure.
// Everything else that is not a well-formed, v1, known-type object closes the
// signing gate, because the panel cannot tell a bug from a helper that is no
// longer the binary it shipped with.
// The panel caps each line, but the line itself is assembled by SplitParser,
// which has no ceiling of its own: a helper that wrote without ever emitting a
// newline would grow that buffer. That is inside the same-UID boundary this
// feature does not defend against -- the process concerned is the plugin's own
// binary -- and every line it does terminate is bounded here.
function parseAgentEvent(line) {
  var text = (line === undefined || line === null) ? "" : String(line)
  if (text.charAt(text.length - 1) === "\n") text = text.slice(0, text.length - 1)
  if (text.charAt(text.length - 1) === "\r") text = text.slice(0, text.length - 1)
  if (text === "") return { ok: false, code: "EMPTY", fatal: false }
  if (utf8ByteLength(text) > SSH_AGENT_MAX_LINE_BYTES) {
    return { ok: false, code: "LINE_TOO_LONG", fatal: true }
  }
  var parsed
  try {
    parsed = JSON.parse(text)
  } catch (e) {
    return { ok: false, code: "MALFORMED", fatal: true }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "MALFORMED", fatal: true }
  }
  if (parsed.v !== SSH_AGENT_CONTROL_VERSION) {
    return { ok: false, code: "VERSION_MISMATCH", fatal: true }
  }
  if (typeof parsed.type !== "string" || SSH_AGENT_EVENT_TYPES.indexOf(parsed.type) < 0) {
    return { ok: false, code: "UNKNOWN_TYPE", fatal: true }
  }
  if (parsed.type === "ready") {
    if (typeof parsed.socketPath !== "string" || parsed.socketPath === ""
        || typeof parsed.fifoPath !== "string" || parsed.fifoPath === ""
        || typeof parsed.agentVersion !== "string" || parsed.agentVersion === "") {
      return { ok: false, code: "MALFORMED", fatal: true }
    }
  }
  return { ok: true, message: parsed }
}

// 500ms doubling to a 30s ceiling. The first retry is quick because the
// overwhelmingly likely cause is a helper that was replaced under a running
// shell; the ceiling is what stops a permanently broken build from spinning.
function sshAgentRestartDelayMs(failures) {
  var n = Math.floor(Number(failures))
  if (!isFinite(n) || n < 1) return SSH_AGENT_BACKOFF_BASE_MS
  var delay = SSH_AGENT_BACKOFF_BASE_MS * Math.pow(2, n - 1)
  return Math.min(SSH_AGENT_BACKOFF_MAX_MS, delay)
}

// -------------------------------------------------------------------------
// Client routing: the managed UWSM fragment and SSH_AUTH_SOCK diagnostics
// -------------------------------------------------------------------------
//
// Nothing in this section decides whether the companion runs. The companion
// binds a deterministic path and never reads SSH_AUTH_SOCK; that variable is
// how *clients* -- ssh, git, ssh-add, ssh-keygen -Y sign, and everything that
// spawns them -- find an agent. So routing is a separate, advisory concern,
// and the panel's view of it is a hint rather than a verdict: it sees the
// graphical session's environment, while a ~/.bashrc export, a systemd --user
// unit, a TTY login, or an incoming SSH session can each differ and are all
// invisible from here.

function sshAgentSocketPath(runtimeDir) {
  if (typeof runtimeDir !== "string" || runtimeDir.charAt(0) !== "/") return ""
  return runtimeDir + "/" + RUNTIME_SUBDIR + "/ssh-agent.sock"
}

function sshAgentFifoPath(runtimeDir) {
  if (typeof runtimeDir !== "string" || runtimeDir.charAt(0) !== "/") return ""
  return runtimeDir + "/" + RUNTIME_SUBDIR + "/ssh-keys.fifo"
}

// The per-load nonce. It is what stops another same-UID process writing its
// own key set into an open FIFO window: it cannot guess a value it cannot
// read. The panel delivers it to the companion over the private stdin pipe
// and to `jq` through the environment -- never argv, because
// /proc/<pid>/cmdline is world-readable while /proc/<pid>/environ is not.
var LOAD_ID_ENV = "QSBW_LOAD_ID"
var LOAD_ID_RE = /^[0-9a-f]{32}$/

function loadIdEnvVar() { return LOAD_ID_ENV }

function isValidLoadId(value) {
  return typeof value === "string" && LOAD_ID_RE.test(value)
}

// 128 bits from the kernel CSPRNG. Math.random() is not a source for a value
// whose whole job is being unguessable by a process running as this user.
function loadIdCommand() {
  var script = "LC_ALL=C od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n'"
  return ["bash", "-c", script]
}

function sshAgentLoadBeginLine(epoch, loadId) {
  if (!isValidLoadId(loadId)) return ""
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "key_load_begin",
    epoch: Math.floor(Number(epoch)) || 0, loadId: loadId }) + "\n"
}

function sshAgentLoadEndLine(epoch, ok) {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "key_load_end",
    epoch: Math.floor(Number(epoch)) || 0, status: ok ? "ok" : "failed" }) + "\n"
}

function sshAgentVaultLockedLine(epoch) {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "vault_locked",
    epoch: Math.floor(Number(epoch)) || 0 }) + "\n"
}

function sshAgentLoggedOutLine() {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "vault_logged_out" }) + "\n"
}

// Omarchy runs the graphical session through UWSM, which reads env.d
// fragments at login. Exactly one file is plugin-owned, and it is identified
// by its full contents rather than by its name, so nothing the user wrote is
// ever replaced or deleted on the strength of a filename match.
var UWSM_FRAGMENT_REL = ".config/uwsm/env.d/50-qs-bitwarden-ssh-agent"

function uwsmFragmentDisplayPath() {
  return "~/" + UWSM_FRAGMENT_REL
}

// ${XDG_RUNTIME_DIR} is left for the shell that sources this at login, not
// expanded now: the runtime directory belongs to the session that will read
// it, and baking today's path into a login fragment would survive into
// sessions where it is wrong.
function uwsmFragmentContent() {
  return "# Managed by the qs-bitwarden-cli Quickshell plugin.\n"
    + "# Routes SSH clients to the Bitwarden agent. Delete this file to stop.\n"
    + "export SSH_AUTH_SOCK=\"${XDG_RUNTIME_DIR}/" + RUNTIME_SUBDIR + "/ssh-agent.sock\"\n"
}

// Exit codes shared by the write and remove scripts. They are the whole
// vocabulary between the shell and parseUwsmActionResult(), so each one means
// exactly one thing and none of them overlap with a shell's own.
var UWSM_EXIT_NO_HOME = 3
var UWSM_EXIT_PARENT = 4
var UWSM_EXIT_SYMLINK = 5
var UWSM_EXIT_FOREIGN = 6
var UWSM_EXIT_WRITE = 7

// The comparison both scripts make. `$(cat)` strips trailing newlines, so the
// expected value is stripped the same way rather than the file being rewritten
// to match a comparison artefact.
function uwsmExpectedShell() {
  var expected = uwsmFragmentContent().replace(/\n+$/, "")
  return "__want=" + shellQuote(expected) + "; "
    + "__frag=\"$HOME/" + UWSM_FRAGMENT_REL + "\"; "
}

function uwsmForeignShell() {
  return "[ ! -f \"$__frag\" ] || [ \"$(cat \"$__frag\" 2>/dev/null)\" != \"$__want\" ]"
}

function uwsmInspectCommand() {
  var script = "test -n \"${HOME:-}\" || { echo no-home; exit 0; }; "
    + uwsmExpectedShell()
    // -L first, and lstat throughout: a symlink here must be reported as one
    // rather than resolved into whatever it points at.
    + "if [ -L \"$__frag\" ]; then echo symlink; exit 0; fi; "
    + "if [ ! -e \"$__frag\" ]; then echo absent; exit 0; fi; "
    + "if [ ! -f \"$__frag\" ]; then echo foreign; exit 0; fi; "
    + "if [ ! -r \"$__frag\" ]; then echo unreadable; exit 0; fi; "
    + "if [ \"$(cat \"$__frag\")\" = \"$__want\" ]; then echo managed; else echo foreign; fi"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function uwsmWriteCommand() {
  var script = "test -n \"${HOME:-}\" || exit " + UWSM_EXIT_NO_HOME + "; "
    + uwsmExpectedShell()
    + "__dir=\"$(dirname \"$__frag\")\"; "
    // -m applies only to directories this actually creates, so an existing
    // ~/.config keeps whatever mode the user gave it.
    + "mkdir -p -m 700 \"$__dir\" || exit " + UWSM_EXIT_PARENT + "; "
    + "if [ -L \"$__frag\" ]; then exit " + UWSM_EXIT_SYMLINK + "; fi; "
    // Anything already there that is not byte-for-byte ours is somebody
    // else's file. Rewriting our own content is allowed and is a no-op.
    + "if [ -e \"$__frag\" ]; then "
    + "  if " + uwsmForeignShell() + "; then exit " + UWSM_EXIT_FOREIGN + "; fi; "
    + "fi; "
    // Same directory, so the rename is atomic: a reader at login time sees
    // either the old file or the complete new one, never a half-written
    // fragment that would break the session's environment.
    + "__tmp=\"$(mktemp \"$__dir/.50-qs-bitwarden-ssh-agent.XXXXXX\")\" || exit " + UWSM_EXIT_WRITE + "; "
    + "{ printf '%s\\n' \"$__want\" > \"$__tmp\" && chmod 644 \"$__tmp\" && mv -f \"$__tmp\" \"$__frag\"; } "
    + "|| { rm -f \"$__tmp\"; exit " + UWSM_EXIT_WRITE + "; }; "
    + "echo written"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Everything this plugin leaves outside its own folder, removed in one pass.
//
// It exists because removal cannot do it. `omarchy plugin remove` has no
// uninstall hook -- it disables the plugin and deletes the directory -- so the
// last moment any of this code can run is while the plugin is still
// installed. What is not cleared here has to be cleared by hand afterwards,
// from instructions, which is how it was until now.
//
// Deliberately not included: the vault. `bw logout` is the user's own call and
// removing a panel is no reason to make it. Nor the shell.json entry, which
// belongs to the shell and is rewritten by `omarchy bar` rather than by us.
function pluginDataRemoveCommand() {
  var script = "test -n \"${HOME:-}\" || exit " + PLUGIN_DATA_EXIT_NO_HOME + "; "
    + "__state=\"${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli\"; "
    + "__data=\"${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli\"; "
    // Each step reports rather than aborting the rest: a keyring that is
    // already empty, or a directory already gone, must not stop the others.
    + "__done=''; "
    + "if secret-tool clear service qs-bitwarden-cli 2>/dev/null; then __done=\"$__done keyring\"; fi; "
    + "if [ -e \"$__state\" ]; then rm -rf -- \"$__state\" && __done=\"$__done state\"; fi; "
    + "if [ -e \"$__data\" ]; then rm -rf -- \"$__data\" && __done=\"$__done data\"; fi; "
    + "printf 'removed%s\\n' \"$__done\""
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

var PLUGIN_DATA_EXIT_NO_HOME = 3

function parsePluginDataRemoval(exitCode, stdout) {
  var code = Math.floor(Number(exitCode))
  if (code === PLUGIN_DATA_EXIT_NO_HOME) {
    return { ok: false, message: "No HOME is set, so there is nothing to clear." }
  }
  if (code !== 0) {
    return { ok: false, message: "Could not remove the plugin's stored data." }
  }
  var line = String(stdout === undefined || stdout === null ? "" : stdout).trim()
  var cleared = []
  if (line.indexOf("keyring") >= 0) cleared.push("keyring entries")
  if (line.indexOf("state") >= 0) cleared.push("learned suggestions")
  if (line.indexOf("data") >= 0) cleared.push("exported public keys")
  if (cleared.length === 0) {
    return { ok: true, message: "Nothing was left to remove." }
  }
  return { ok: true,
    message: "Removed " + cleared.join(", ")
      + ". Your vault is untouched; run `bw logout` separately if you want that too." }
}

function uwsmRemoveCommand() {
  var script = "test -n \"${HOME:-}\" || exit " + UWSM_EXIT_NO_HOME + "; "
    + uwsmExpectedShell()
    + "if [ -L \"$__frag\" ]; then exit " + UWSM_EXIT_SYMLINK + "; fi; "
    + "if [ ! -e \"$__frag\" ]; then echo absent; exit 0; fi; "
    + "if " + uwsmForeignShell() + "; then exit " + UWSM_EXIT_FOREIGN + "; fi; "
    + "rm -f \"$__frag\" || exit " + UWSM_EXIT_WRITE + "; "
    + "echo removed"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

var UWSM_LOGIN_NOTE = "UWSM applies this at your next graphical login, so log out and log back in. "
  + "Restarting the shell is not enough: it cannot change the environment of programs that are already running."

function parseExitCodeResult(exitCode, stdout, parseSuccess, failureMap, defaultFailureMessage) {
  var code = Math.floor(Number(exitCode))
  var out = String(stdout === undefined || stdout === null ? "" : stdout).trim()
  if (code === 0) {
    var success = parseSuccess(out)
    if (success) return success
  }
  if (failureMap && failureMap[code] !== undefined) {
    return { ok: false, code: failureMap[code].code, message: failureMap[code].message }
  }
  return { ok: false, code: "FAILED", message: defaultFailureMessage || "" }
}

function parseUwsmInspection(raw) {
  var verdict = String(raw === undefined || raw === null ? "" : raw).trim()
  switch (verdict) {
    case "managed":
      return { state: "managed", removable: true,
        message: "Routing is set up. " + uwsmFragmentDisplayPath() + " is the file this plugin wrote, "
          + "and turning the agent off removes it." }
    case "absent":
      return { state: "absent", removable: false,
        message: "No routing file. SSH clients will keep using whatever agent your session already has." }
    case "symlink":
      return { state: "symlink", removable: false,
        message: uwsmFragmentDisplayPath() + " is a symlink, so this plugin will not write to it or "
          + "remove it. Replace it with a regular file yourself if you want it managed here." }
    case "unreadable":
      return { state: "unreadable", removable: false,
        message: uwsmFragmentDisplayPath() + " exists but cannot be read, so it is left alone." }
    case "no-home":
      return { state: "no-home", removable: false,
        message: "No HOME is set, so there is nowhere to put a routing file." }
    default:
      return { state: "foreign", removable: false,
        message: uwsmFragmentDisplayPath() + " already exists and is not the file this plugin writes, "
          + "so it is left untouched. Remove or edit it yourself to change routing." }
  }
}

// The status block's one line about routing, decided by the file rather than
// by this session's SSH_AUTH_SOCK.
//
// The variable was fixed at login, so it says what routing *was*; the file
// says what routing *will be*. Reading the variable hides a missing fragment
// for the whole life of a session that started routed -- the warning then
// arrives at the next boot, which is the one moment it can no longer help.
function sshAgentRoutingNotice(fragment, routing) {
  var fragmentState = fragment && fragment.state ? String(fragment.state) : "unknown"
  var routingState = routing && routing.state ? String(routing.state) : "unknown"
  // States the plugin refuses to act on say their piece in the routing
  // section itself, in full. Repeating a summary here would be noise.
  if (fragmentState === "unknown" || fragmentState === "no-home") {
    return { text: "", urgent: false }
  }
  if (fragmentState !== "managed") {
    return { text: "SSH clients are not routed here, and will not be at your next login.",
      urgent: true }
  }
  if (routingState !== "matches") {
    return { text: "Routing is written. It takes effect at your next login.", urgent: false }
  }
  return { text: "", urgent: false }
}

function parseUwsmActionResult(exitCode, stdout) {
  var failures = {}
  failures[UWSM_EXIT_NO_HOME] = { code: "NO_HOME",
    message: "No HOME is set, so there is nowhere to put a routing file." }
  failures[UWSM_EXIT_PARENT] = { code: "PARENT",
    message: "Could not create " + uwsmFragmentDisplayPath() + "'s parent directory." }
  failures[UWSM_EXIT_SYMLINK] = { code: "SYMLINK",
    message: uwsmFragmentDisplayPath() + " is a symlink. This plugin will not write through it "
      + "or delete it; sort that path out yourself first." }
  failures[UWSM_EXIT_FOREIGN] = { code: "FOREIGN",
    message: uwsmFragmentDisplayPath() + " already exists and is not this plugin's file, so it was "
      + "left untouched. Remove or edit it yourself to change routing." }

  return parseExitCodeResult(exitCode, stdout, function(out) {
    if (out === "written") {
      return { ok: true, code: "WRITTEN",
        message: "Routing file written to " + uwsmFragmentDisplayPath() + ". " + UWSM_LOGIN_NOTE }
    }
    if (out === "removed" || out === "absent") {
      return { ok: true, code: out === "removed" ? "REMOVED" : "ABSENT",
        message: out === "removed"
          ? "Routing file removed. Programs already running keep the old value until you log out and back in."
          : "There was no routing file to remove." }
    }
    return null
  }, failures, "Could not update " + uwsmFragmentDisplayPath() + ".")
}

// Which agent the graphical session is actually pointed at. Matched most
// specific first, because this plugin's own socket also contains "bitwarden"
// and would otherwise be attributed to Bitwarden Desktop.
var SSH_AUTH_SOCK_OWNERS = [
  { re: /\/gcr\/|\/keyring\//i, name: "GNOME Keyring" },
  { re: /1password/i, name: "1Password" },
  { re: /gpg-agent/i, name: "GPG Agent" },
  { re: /bitwarden/i, name: "Bitwarden Desktop" },
  { re: /^\/tmp\/ssh-[^/]+\/agent\./, name: "OpenSSH ssh-agent" }
]

function sshAuthSockTerminalCheck() {
  return "echo \"$SSH_AUTH_SOCK\"; ssh-add -L"
}

// Three outcomes, and a fourth for "there is nothing to compare against".
// None of them gate anything: the wording stays descriptive on purpose, so a
// diagnostic can never read as a prerequisite the user has to satisfy.
function sshAuthSockDiagnostic(sock, runtimeDir) {
  var value = (sock === undefined || sock === null) ? "" : String(sock)
  var ours = sshAgentSocketPath(runtimeDir)
  var check = sshAuthSockTerminalCheck()
  if (!ours) {
    return { state: "unknown", owner: "", terminalCheck: check,
      message: "Without a runtime directory there is no socket path to compare against." }
  }
  if (value === "") {
    return { state: "unset", owner: "", terminalCheck: check,
      message: "This session has no SSH_AUTH_SOCK, so SSH clients started from it have no agent yet." }
  }
  if (value === ours) {
    return { state: "matches", owner: "", terminalCheck: check,
      message: "This session points at the Bitwarden agent. Terminals you opened earlier may not; check with:" }
  }
  var owner = ""
  for (var i = 0; i < SSH_AUTH_SOCK_OWNERS.length; i++) {
    if (SSH_AUTH_SOCK_OWNERS[i].re.test(value)) { owner = SSH_AUTH_SOCK_OWNERS[i].name; break }
  }
  return { state: "elsewhere", owner: owner, terminalCheck: check,
    message: "This session points at " + (owner ? owner : "another agent")
      + " instead of the Bitwarden agent. Changing that is your choice; check any terminal with:" }
}

// -------------------------------------------------------------------------
// The bundled helper
// -------------------------------------------------------------------------
//
// The plugin ships a compiled helper rather than downloading one, so the
// panel checks it before trusting it: that it is there, executable, the right
// architecture, matches its recorded checksum, passes its own self-test, and
// speaks this panel's protocol version.
//
// What the checksum is and is not. `bin/SHA256SUMS` sits beside the binary and
// beside the QML that reads it, so anyone who can replace one can replace all
// three. This is not tamper detection, and presenting it as such would be a
// lie. What it does catch is what actually goes wrong: a partial clone, a Git
// LFS placeholder, a truncated file, and -- most often -- a stale binary left
// behind by a `git pull` that updated the source. Provenance is a separate
// mechanism with a different root of trust; see the release documentation.
var SSH_AGENT_BUNDLED_RELATIVE = "bin/x86_64-linux/qs-bitwarden-ssh-agent"
var SSH_AGENT_SUMS_RELATIVE = "bin/SHA256SUMS"
// Cargo's ordinary debug output. Preferring the shipped artifact but falling
// back to this keeps a developer's `cargo build` meaningful without a release
// round-trip, and the settings screen says which one is in use so the two are
// never confused.
var SSH_AGENT_DEVELOPMENT_RELATIVE = "agent/target/debug/qs-bitwarden-ssh-agent"

function sshAgentBundledRelative() { return SSH_AGENT_BUNDLED_RELATIVE }
function sshAgentDevelopmentRelative() { return SSH_AGENT_DEVELOPMENT_RELATIVE }

// In preference order. The shipped artifact first, because that is what a
// user installed and what CI verified; the local build second, because a
// developer who just compiled one means to run it.
function sshAgentHelperCandidates(pluginDir) {
  var base = sshAgentHelperPath(pluginDir) === "" ? "" : pluginDir
  if (base === "") return []
  var root = base
  while (root.length > 1 && root.charAt(root.length - 1) === "/") root = root.slice(0, root.length - 1)
  return [
    { source: "bundled", path: root + "/" + SSH_AGENT_BUNDLED_RELATIVE },
    { source: "development", path: root + "/" + SSH_AGENT_DEVELOPMENT_RELATIVE }
  ]
}

// What the banner says when a local build is serving SSH keys. It has to
// carry why that is worth knowing, not just that it is true: the shipped
// binary is the one with a recorded digest and a CI provenance attestation
// behind it, and a development build has neither. When the shipped one was
// rejected rather than absent, say which -- "yours is broken" and "you built
// one" are different situations. The remedy is the same either way and is
// named in the words a user has: reinstall the plugin. Rebuilding from source
// is a maintainer's answer, and this banner is not only read by maintainers.
function sshAgentDevelopmentHelperWarning(helper) {
  var checksum = helper && helper.checksum ? helper.checksum : "unchecked"
  var why = checksum === "mismatch"
    ? "The shipped helper failed its checksum, so a locally built one is serving your SSH keys."
    : "A locally built helper is serving your SSH keys, not the shipped one."
  return why + " It carries no recorded digest and no build provenance. "
    + "Reinstall the plugin to restore the shipped helper before trusting a signature from it."
}

function sshAgentHelperSourceLabel(source) {
  if (source === "bundled") return "the helper shipped with this plugin"
  if (source === "development") return "a locally built development helper, not the shipped artifact"
  return ""
}

// One pass over both candidates, in the shell, reporting the first that is
// usable. Written as one script rather than several commands because the
// panel must not sequence six probes through six Process round-trips before
// it can decide whether a feature is available.
//
// Emits `key=value` lines, which the parser below reads. Nothing from the
// helper's own output is interpolated into a message.
function sshAgentHelperInspectCommand(pluginDir) {
  var candidates = sshAgentHelperCandidates(pluginDir)
  if (candidates.length === 0) return ["bash", "-c", "echo state=missing"]
  var root = candidates[0].path.slice(0, candidates[0].path.length - SSH_AGENT_BUNDLED_RELATIVE.length - 1)

  var script = "__root=" + shellQuote(root) + "; "
    + "__report() { printf '%s\\n' \"$@\"; exit 0; }; "
    + "__found=''; "
    // The shipped artifact first; a development build only if it is absent or
    // unusable, so a broken release never strands a working local build.
    + "for __pair in " + shellQuote("bundled:" + SSH_AGENT_BUNDLED_RELATIVE)
    + " " + shellQuote("development:" + SSH_AGENT_DEVELOPMENT_RELATIVE) + "; do "
    + "  __source=\"${__pair%%:*}\"; __rel=\"${__pair#*:}\"; __bin=\"$__root/$__rel\"; "
    + "  [ -e \"$__bin\" ] || continue; "
    + "  __found=\"$__source\"; "
    + "  [ -f \"$__bin\" ] || { __state=not-a-file; continue; }; "
    + "  [ -x \"$__bin\" ] || { __state=not-executable; continue; }; "
    // ELF magic, before anything tries to run it. A Git LFS placeholder and a
    // truncated download both fail here rather than as a confusing exec error.
    + "  __magic=\"$(head -c 4 -- \"$__bin\" 2>/dev/null | od -An -tx1 | tr -d ' \\n')\"; "
    + "  [ \"$__magic\" = \"7f454c46\" ] || { __state=not-elf; continue; }; "
    + "  __arch=\"$(od -An -tx1 -j 18 -N 1 -- \"$__bin\" 2>/dev/null | tr -d ' \\n')\"; "
    + "  [ \"$__arch\" = \"3e\" ] || { __state=wrong-architecture; continue; }; "
    // The checksum applies to the shipped artifact only. A local build has no
    // recorded digest and claiming one would be meaningless.
    + "  __checksum=unchecked; "
    + "  if [ \"$__source\" = bundled ] && [ -f \"$__root/" + SSH_AGENT_SUMS_RELATIVE + "\" ]; then "
    + "    if ( cd \"$__root/bin\" && sha256sum -c --status " + shellQuote(baseName(SSH_AGENT_SUMS_RELATIVE)) + " ) 2>/dev/null; then "
    + "      __checksum=match; "
    + "    else __checksum=mismatch; __state=checksum-mismatch; continue; fi; "
    + "  fi; "
    // Its own account of itself, bounded: a helper that hangs must not hang
    // the panel's startup decision.
    + "  __version=\"$(timeout 5 \"$__bin\" --version 2>/dev/null | head -c 200)\"; "
    + "  case \"$__version\" in *'qs-bitwarden-ssh-agent '*) ;; *) __state=no-version; continue;; esac; "
    + "  __semver=\"$(printf '%s' \"$__version\" | sed -n 's/.*qs-bitwarden-ssh-agent \\([0-9.]*\\).*/\\1/p')\"; "
    + "  __proto=\"$(printf '%s' \"$__version\" | sed -n 's/.*protocol \\([0-9]*\\).*/\\1/p')\"; "
    + "  if timeout 20 \"$__bin\" --self-test >/dev/null 2>&1; then __self=pass; "
    + "  else __self=fail; __state=self-test-failed; continue; fi; "
    + "  __report state=ok \"source=$__source\" \"version=$__semver\" \"protocol=$__proto\" "
    + "\"checksum=$__checksum\" \"selfTest=$__self\"; "
    + "done; "
    + "if [ -z \"$__found\" ]; then __report state=missing; fi; "
    // Carry the checksum verdict into the failure report too. Without it a
    // mismatch arrives as "unchecked", which reads as "we did not look"
    // rather than "we looked and it was wrong".
    + "__report \"state=${__state:-unusable}\" \"source=$__found\" "
    + "\"checksum=${__checksum:-unchecked}\" \"selfTest=${__self:-}\""
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

var SSH_AGENT_HELPER_MESSAGES = {
  "missing": "No SSH agent helper was found. A release ships one; a source checkout needs "
    + "`cargo build --manifest-path agent/Cargo.toml --locked`.",
  "not-a-file": "The SSH agent helper path is not a file.",
  "not-executable": "The SSH agent helper is not executable. A clone from an archive can drop "
    + "file modes; `chmod +x` on it is enough.",
  "not-elf": "The SSH agent helper is not a program. A partial clone, or Git LFS leaving a "
    + "placeholder, both look like this.",
  "wrong-architecture": "The SSH agent helper was built for a different architecture. This "
    + "release ships x86_64 only.",
  "checksum-mismatch": "The SSH agent helper does not match its recorded checksum. That usually "
    + "means a stale binary after an update, or an incomplete clone.",
  "no-version": "The SSH agent helper did not report a usable version.",
  "self-test-failed": "The SSH agent helper failed its own self-test on this machine.",
  "protocol-mismatch": "The SSH agent helper speaks a different control protocol than this "
    + "version of the plugin. Reinstall the plugin so both come from the same release.",
  "unusable": "The SSH agent helper could not be used."
}

function parseSshAgentHelperInspection(raw) {
  var fields = { state: "missing", source: "", version: "", protocol: 0,
    checksum: "unchecked", selfTest: "" }
  var lines = String(raw === undefined || raw === null ? "" : raw).split("\n")
  for (var i = 0; i < lines.length; i++) {
    var cut = lines[i].indexOf("=")
    if (cut <= 0) continue
    var key = lines[i].slice(0, cut)
    var value = lines[i].slice(cut + 1)
    if (key === "protocol") fields.protocol = Math.floor(Number(value)) || 0
    else if (fields[key] !== undefined) fields[key] = value
  }
  // The protocol version is the panel's own compatibility check rather than
  // something the shell script judges: the panel knows what it speaks.
  if (fields.state === "ok" && fields.protocol !== SSH_AGENT_CONTROL_VERSION) {
    fields.state = "protocol-mismatch"
  }
  fields.message = fields.state === "ok" ? "" : (SSH_AGENT_HELPER_MESSAGES[fields.state]
    || SSH_AGENT_HELPER_MESSAGES.unusable)
  return fields
}

// Whether the supervisor may start at all. Every failure here disables this
// optional feature and nothing else -- no socket, no FIFO, no agent branch in
// the vault read.
function sshAgentHelperReady(inspection) {
  return Boolean(inspection) && inspection.state === "ok"
}

// -------------------------------------------------------------------------
// Public-key file projection
// -------------------------------------------------------------------------
//
// Git SSH signing needs paths, not inline keys: `user.signingkey` takes a
// file, and `gpg.ssh.allowedSignersFile` has no inline form at all. So the
// panel writes the companion's validated public identities to disk.
//
// Public keys are not secret, so this does not cross the private boundary --
// but the files are still written 0600 inside a 0700 directory, because a
// projection of your vault's contents is nobody else's business either.
// Private material is never written here under any circumstance.
//
// Not into ~/.ssh: that directory belongs to the user and to OpenSSH, and a
// plugin that rewrites a set of files in it would eventually delete something
// it did not create.
var SSH_EXPORT_SUBDIR = "qs-bitwarden-cli/ssh"

function sshExportDisplayDir() {
  return "~/.local/share/" + SSH_EXPORT_SUBDIR
}

// An item name is decrypted vault content about to become a path, and the
// collection it came from may be writable by somebody else. It goes through
// the same sanitizer the attachment path uses, then gets ".pub" appended --
// after sanitizing, so nothing in the name can consume the extension.
//
// `taken` accumulates the names already used by this projection. Two items may
// legitimately share a name; neither may overwrite the other, so the loser
// gains its item ID rather than the file being clobbered.
function sshExportFileName(name, itemId, taken) {
  var used = taken || {}
  var base = safeAttachmentFileName(name)
  if (base === "attachment") base = "ssh-key"
  var candidate = base + ".pub"
  if (used[candidate] !== undefined && used[candidate] !== itemId) {
    var suffix = safeAttachmentFileName(String(itemId || "")).slice(0, 64)
    candidate = base + "." + (suffix || "key") + ".pub"
  }
  used[candidate] = itemId
  return candidate
}

// The OpenSSH one-line public form, and nothing that is not one. The
// companion derives these from keys it validated, but this is the last gate
// before bytes reach the filesystem and it costs nothing to check the shape.
var SSH_PUBLIC_KEY_RE = /^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+(\s|$)/

function sshExportIdentities(identities) {
  if (!identities || !Array.isArray(identities)) return []
  var out = []
  for (var i = 0; i < identities.length; i++) {
    var identity = identities[i] || {}
    var publicKey = String(identity.publicKey || "").trim()
    if (!SSH_PUBLIC_KEY_RE.test(publicKey)) continue
    if (publicKey.indexOf("PRIVATE") >= 0) continue
    var itemId = String(identity.itemId || "")
    if (itemId === "") continue
    out.push({
      itemId: itemId,
      name: String(identity.name || ""),
      fingerprint: String(identity.fingerprint || ""),
      publicKey: publicKey
    })
  }
  return out
}

// What the export script reads on stdin. Not argv: a hundred keys of RSA
// public material would push at the argument limit, and stdin keeps the
// vault-derived names out of /proc/<pid>/cmdline as a matter of habit.
function sshExportPayload(identities) {
  var taken = {}
  var entries = []
  var validated = sshExportIdentities(identities)
  for (var i = 0; i < validated.length; i++) {
    entries.push({
      fileName: sshExportFileName(validated[i].name, validated[i].itemId, taken),
      publicKey: validated[i].publicKey
    })
  }
  return JSON.stringify(entries)
}

var SSH_EXPORT_EXIT_NO_HOME = 3
var SSH_EXPORT_EXIT_UNSAFE_DIR = 5
var SSH_EXPORT_EXIT_WRITE = 7

// The directory the projection lives in, resolved and checked the same way in
// both the export and the clear script.
function sshExportDirPrelude() {
  return "__base=\"${XDG_DATA_HOME:-}\"; "
    + "if [ -z \"$__base\" ]; then "
    + "  [ -n \"${HOME:-}\" ] || exit " + SSH_EXPORT_EXIT_NO_HOME + "; "
    + "  __base=\"$HOME/.local/share\"; "
    + "fi; "
    + "case \"$__base\" in /*) ;; *) exit " + SSH_EXPORT_EXIT_NO_HOME + ";; esac; "
    + "__dir=\"$__base/" + SSH_EXPORT_SUBDIR + "\"; "
    + "if [ -L \"$__dir\" ]; then exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; fi; "
}

function sshExportCommand() {
  var script = sshExportDirPrelude()
    // Safe parent creation, then the directory itself. A symlink at the
    // export path was refused by sshExportDirPrelude() rather than followed:
    // writing through it would let anything that could plant it choose where
    // these land.
    + "mkdir -p -m 700 \"$(dirname \"$__dir\")\" || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    + "if [ -e \"$__dir\" ]; then "
    + "  [ -d \"$__dir\" ] || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    + "else (umask 077 && mkdir -- \"$__dir\") || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; fi; "
    + "chmod 700 -- \"$__dir\" || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    // The payload is read once into a variable so a partial stdin cannot
    // leave a half-written projection behind.
    + "__payload=\"$(cat)\"; "
    + "printf '%s' \"$__payload\" | jq -e 'type == \"array\"' >/dev/null 2>&1 || exit "
    + SSH_EXPORT_EXIT_WRITE + "; "
    // NUL-delimited so a filename can never split a record, whatever the
    // sanitizer let through.
    // A bash array, not an accumulated string: "$x\n" inside double quotes
    // appends a literal backslash-n, which silently made every freshly
    // written file look stale and deleted it again.
    + "__keep=(); "
    + "while IFS= read -r -d '' __file && IFS= read -r -d '' __key; do "
    + "  case \"$__file\" in */*|..|.|\"\") exit " + SSH_EXPORT_EXIT_WRITE + ";; esac; "
    // Each file lands by rename, so a reader never sees a partial key, and an
    // existing symlink at the name is replaced rather than written through.
    + "  __tmp=\"$(mktemp \"$__dir/.export.XXXXXX\")\" || exit " + SSH_EXPORT_EXIT_WRITE + "; "
    + "  printf '%s\\n' \"$__key\" > \"$__tmp\" || { rm -f -- \"$__tmp\"; exit "
    + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  chmod 600 -- \"$__tmp\" || { rm -f -- \"$__tmp\"; exit " + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  mv -f -- \"$__tmp\" \"$__dir/$__file\" || { rm -f -- \"$__tmp\"; exit "
    + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  __keep+=(\"$__file\"); "
    + "done < <(printf '%s' \"$__payload\" | jq -j '.[] | .fileName, \"\\u0000\", .publicKey, \"\\u0000\"'); "
    // Anything left in the directory belonged to a previous epoch. Only files
    // this projection creates are removed -- the pattern is ours, so a file a
    // user dropped in here by hand is left alone.
    + "for __existing in \"$__dir\"/*.pub; do "
    + "  [ -e \"$__existing\" ] || [ -L \"$__existing\" ] || continue; "
    + "  __name=\"$(basename -- \"$__existing\")\"; "
    + "  __found=0; "
    + "  for __k in ${__keep[@]+\"${__keep[@]}\"}; do "
    + "    if [ \"$__k\" = \"$__name\" ]; then __found=1; break; fi; "
    + "  done; "
    + "  [ \"$__found\" = \"1\" ] || rm -f -- \"$__existing\"; "
    + "done; "
    + "rm -f -- \"$__dir\"/.export.* 2>/dev/null; "
    + "echo exported"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Logout, account change, and disabling the feature all remove the whole
// projection. A lock does not: public identities stay advertised while
// locked, so the files stay too.
function sshExportClearCommand() {
  var script = sshExportDirPrelude()
    + "[ -d \"$__dir\" ] || { echo cleared; exit 0; }; "
    + "rm -f -- \"$__dir\"/*.pub \"$__dir\"/.export.* 2>/dev/null; "
    + "rmdir -- \"$__dir\" 2>/dev/null; "
    + "echo cleared"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function parseSshExportResult(exitCode, stdout) {
  var failures = {}
  failures[SSH_EXPORT_EXIT_NO_HOME] = { code: "NO_HOME",
    message: "No data directory is set, so public key files cannot be written." }
  failures[SSH_EXPORT_EXIT_UNSAFE_DIR] = { code: "UNSAFE_DIR",
    message: sshExportDisplayDir() + " is not a directory this plugin will write to. "
      + "Remove or rename whatever is at that path." }

  return parseExitCodeResult(exitCode, stdout, function(out) {
    if (out === "exported" || out === "cleared" || out === "") {
      return { ok: true, code: "OK", message: "" }
    }
    return null
  }, failures, "Could not write public key files to " + sshExportDisplayDir() + ".")
}

// -------------------------------------------------------------------------
// Signing authorization UX
// -------------------------------------------------------------------------
//
// The prompt is the only place a person is asked to authorise a signature, so
// what it says has to match what the companion actually checked. It verifies
// the peer's UID and nothing else: the PID, the executable path and the name
// derived from it are context for a human, not an identity claim, and the
// prompt says so rather than implying otherwise.

// Matches REQUEST_LIFETIME_MS in the companion. The panel only draws the
// countdown; the companion is what actually expires the request. Two minutes
// rather than thirty seconds because this waits on a person reading a
// fingerprint, not on a machine -- see docs/decisions/0003-request-deadline.md.
var SSH_AGENT_REQUEST_DEADLINE_MS = 120 * 1000

// Bounds on anything drawn from a vault item or another process. A name comes
// from a collection somebody else may be able to edit, and a path comes from
// outside the panel entirely.
var SSH_AGENT_MAX_NAME_CHARS = 256
var SSH_AGENT_MAX_PATH_CHARS = 512

function sshAgentRequestDeadlineMs() { return SSH_AGENT_REQUEST_DEADLINE_MS }

function boundedText(value, limit) {
  var text = (value === undefined || value === null) ? "" : String(value)
  return text.length > limit ? text.slice(0, limit) : text
}

function isRequestId(value) {
  return typeof value === "number" && isFinite(value) && Math.floor(value) === value && value >= 0
}

function sshAgentApproveLine(requestId, grantSeconds) {
  if (!isRequestId(requestId)) return ""
  var seconds = Math.floor(Number(grantSeconds))
  if (!isFinite(seconds) || seconds < 0) seconds = 0
  seconds = Math.min(seconds, SSH_AGENT_APPROVAL_WINDOW_MAX_SEC)
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "approve",
    requestId: requestId, grantSeconds: seconds }) + "\n"
}

function sshAgentDenyLine(requestId) {
  if (!isRequestId(requestId)) return ""
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "deny", requestId: requestId }) + "\n"
}

// The companion has no way to tell a dismissed unlock dialog from a user who
// wandered off, so the panel says which it was rather than letting the
// request burn its deadline.
function sshAgentUnlockCancelledLine(requestId) {
  if (!isRequestId(requestId)) return ""
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "unlock_cancelled",
    requestId: requestId, reason: "user-cancelled" }) + "\n"
}

function sshAgentRevokeGrantLine(grantId) {
  if (!isRequestId(grantId)) return ""
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "revoke_grant", grantId: grantId }) + "\n"
}

// "/usr/bin/ssh" -> "ssh". Only ever for display beside the full path, never
// as a substitute for it: a basename is the easiest part of this to fake.
function processNameFromPath(processPath) {
  var text = String(processPath === undefined || processPath === null ? "" : processPath)
  var cut = text.lastIndexOf("/")
  var name = cut >= 0 ? text.slice(cut + 1) : text
  return boundedText(name, SSH_AGENT_MAX_NAME_CHARS)
}

function formatDuration(seconds) {
  var total = Math.max(0, Math.floor(Number(seconds)) || 0)
  var minutes = Math.floor(total / 60)
  var rest = total % 60
  if (minutes > 0 && rest > 0) return minutes + "m " + rest + "s"
  if (minutes > 0) return minutes + "m"
  return rest + "s"
}

var SSH_AGENT_PROVENANCE_NOTE =
  "Reported by the system, not verified. Only the requesting user was checked."
var SSH_AGENT_FORWARDED_WARNING =
  "This request arrived over agent forwarding, which this release does not support. "
  + "The process shown is not the one that will use the signature."

// One approval_required message, reduced to what the prompt draws. Everything
// attacker-influenced is bounded here rather than at the point it is rendered.
function sshAgentPromptView(message, approvalWindowSec) {
  var request = message || {}
  var window = Math.max(0, Math.min(SSH_AGENT_APPROVAL_WINDOW_MAX_SEC,
    Math.floor(Number(approvalWindowSec)) || 0))
  var forwarded = request.forwarded === true
  // A grant is a window in which this process signs without asking again, so
  // it is offered only when the companion offered one, the user has a
  // non-zero window configured, and nothing about the request is unusual.
  var grantOffered = request.grantOffered === true && window > 0 && !forwarded
  return {
    requestId: isRequestId(request.requestId) ? request.requestId : -1,
    keyId: boundedText(request.keyId, SSH_AGENT_MAX_NAME_CHARS),
    keyName: boundedText(request.keyName, SSH_AGENT_MAX_NAME_CHARS),
    fingerprint: boundedText(request.fingerprint, SSH_AGENT_MAX_NAME_CHARS),
    pid: Math.floor(Number(request.pid)) || 0,
    processPath: boundedText(request.processPath, SSH_AGENT_MAX_PATH_CHARS),
    processName: processNameFromPath(boundedText(request.processPath, SSH_AGENT_MAX_PATH_CHARS)),
    operation: request.operation === "ssh-sign" ? "ssh-sign" : "",
    grantOffered: grantOffered,
    grantSeconds: grantOffered ? window : 0,
    // "program", not "process": a grant matches the executable path and the
    // key, so a fresh process running the same program rides it. That is what
    // makes it useful for Git signing, which spawns one ssh-keygen per commit.
    // See docs/decisions/0002-grant-scope.md.
    grantLabel: grantOffered ? "Approve for this program · " + formatDuration(window) : "",
    forwardedWarning: forwarded ? SSH_AGENT_FORWARDED_WARNING : "",
    provenanceNote: SSH_AGENT_PROVENANCE_NOTE
  }
}

// FIFO queueing for concurrent SSH requests. Bounded to match the companion's
// MAX_PENDING capacity.
function sshAgentEnqueuePrompt(queue, message, maxQueue) {
  var cap = typeof maxQueue === "number" && maxQueue > 0 ? maxQueue : 4
  var list = Array.isArray(queue) ? queue.slice() : []
  if (!message || !isRequestId(message.requestId)) return list
  for (var i = 0; i < list.length; i++) {
    if (list[i] && list[i].requestId === message.requestId) return list
  }
  if (list.length >= cap) return list
  list.push(message)
  return list
}

function sshAgentDequeuePrompt(queue) {
  if (!Array.isArray(queue) || queue.length === 0) {
    return { next: null, remaining: [] }
  }
  return { next: queue[0], remaining: queue.slice(1) }
}

function sshAgentRemovePrompt(queue, requestId) {
  if (!Array.isArray(queue)) return []
  return queue.filter(function(item) {
    return item && item.requestId !== requestId
  })
}

function sshAgentPendingCount(activePrompt, queue) {
  var active = activePrompt ? 1 : 0
  var queued = Array.isArray(queue) ? queue.length : 0
  return active + queued
}

// The live grant set, as the settings screen draws it. Public metadata only:
// the companion never sends key material here and nothing below would carry
// it if it did.
function sshAgentGrantViews(grants, nowMs) {
  if (!grants || !Array.isArray(grants)) return []
  var now = Number(nowMs) || 0
  var out = []
  for (var i = 0; i < grants.length; i++) {
    var grant = grants[i] || {}
    if (!isRequestId(grant.grantId)) continue
    var remaining = Math.max(0, Math.floor(Number(grant.expiresInSec)) || 0)
    out.push({
      grantId: grant.grantId,
      keyName: boundedText(grant.keyName, SSH_AGENT_MAX_NAME_CHARS),
      fingerprint: boundedText(grant.fingerprint, SSH_AGENT_MAX_NAME_CHARS),
      pid: Math.floor(Number(grant.pid)) || 0,
      processPath: boundedText(grant.processPath, SSH_AGENT_MAX_PATH_CHARS),
      processName: processNameFromPath(boundedText(grant.processPath, SSH_AGENT_MAX_PATH_CHARS)),
      // When it runs out, not how long it had left when it was announced.
      // The label below is a snapshot of one instant; this is what lets a
      // later instant be worked out without another announcement.
      expiresAtMs: now + remaining * 1000,
      remainingSec: remaining,
      remainingLabel: remaining > 0 ? formatDuration(remaining) + " left" : "expiring"
    })
  }
  return out
}

// The announced set as it stands at a given moment.
//
// The companion announces a grant once and says nothing more until something
// changes, so a view rendered straight from an announcement is frozen at the
// number it was born with -- a two-minute grant reading "1m 59s left" for its
// whole life, then vanishing without ever having counted down. Re-deriving
// against a ticking clock is what makes the remaining time mean anything, and
// it drops a grant the moment it lapses rather than waiting to be told.
function sshAgentGrantsAt(views, nowMs) {
  if (!views || !Array.isArray(views)) return []
  var now = Number(nowMs) || 0
  var out = []
  for (var i = 0; i < views.length; i++) {
    var view = views[i] || {}
    // Nothing to re-derive from: an announcement that has not been stamped,
    // or a tick that has not run yet. Show it as announced rather than drop a
    // live grant on a technicality.
    if (typeof view.expiresAtMs !== "number" || now <= 0) {
      out.push(view)
      continue
    }
    var remaining = Math.max(0, Math.ceil((view.expiresAtMs - now) / 1000))
    if (remaining <= 0) continue
    out.push({
      grantId: view.grantId,
      keyName: view.keyName,
      fingerprint: view.fingerprint,
      pid: view.pid,
      processPath: view.processPath,
      processName: view.processName,
      expiresAtMs: view.expiresAtMs,
      remainingSec: remaining,
      remainingLabel: formatDuration(remaining) + " left"
    })
  }
  return out
}

// Unlocking runs the panel's ordinary vault read, which decrypts the whole
// vault and takes seconds. The SSH request that triggered the unlock is held
// across it rather than failed, so the user needs to see that something is
// happening -- otherwise unlocking appears to do nothing until the approval
// prompt arrives. There is no faster path: `bw` has no server-side type
// filter, so an SSH-only read would decrypt exactly as much and cost the
// same seconds.
function sshAgentLoadingNote() {
  return "Loading your SSH keys from the vault. The signing request is still waiting."
}

// The agent never opens an approval UI over the lock screen. An unknown screen
// state counts as locked: the cost of not prompting is a failed SSH request,
// and the cost of prompting is a credential decision on a locked desktop.
function sshAgentShouldPrompt(context) {
  if (!context || typeof context !== "object") return false
  return context.screenLocked !== true
}

// A same-UID process can ask for a signature as often as it likes. It cannot
// be stopped from trying, but it can be stopped from reopening the panel every
// time: two consecutive refusals and the panel stops raising prompts for a
// while. Approving clears the run, because a user who is engaging is not being
// pestered.
var SSH_AGENT_COOLDOWN_AFTER = 2
var SSH_AGENT_COOLDOWN_MS = 5 * 60 * 1000

function sshAgentCooldownInitial() {
  return { refusals: 0, untilMs: 0 }
}

function sshAgentCooldownAfter(state, outcome, nowMs) {
  var current = state || sshAgentCooldownInitial()
  var now = Number(nowMs) || 0
  // Approving clears the run because the user is engaging. So does resuming,
  // and that one matters more than it looks: a running cooldown suppresses the
  // prompts an approval would have to come from, so an approval can never end
  // one that has already started. Without an explicit resume the only exit is
  // waiting the full window out.
  if (outcome === "approved" || outcome === "resumed") return { refusals: 0, untilMs: 0 }
  if (outcome !== "denied" && outcome !== "timeout") {
    return { refusals: current.refusals, untilMs: current.untilMs }
  }
  var refusals = current.refusals + 1
  return {
    refusals: refusals,
    untilMs: refusals >= SSH_AGENT_COOLDOWN_AFTER ? now + SSH_AGENT_COOLDOWN_MS : current.untilMs
  }
}

function sshAgentCooldownActive(state, nowMs) {
  var current = state || sshAgentCooldownInitial()
  return (Number(nowMs) || 0) < current.untilMs
}

// A cooldown that fails signatures silently is worse than the pestering it
// prevents: SSH stops working for minutes with no explanation anywhere, and
// the user has no reason to connect the two. So it says what it is doing and
// when it stops -- in general terms only, naming neither the key nor the
// process, because the whole point is that the requests are unattended.
function sshAgentCooldownStatus(state, nowMs) {
  var current = state || sshAgentCooldownInitial()
  var now = Number(nowMs) || 0
  if (now >= current.untilMs) return { active: false, remainingSec: 0, message: "" }
  var remaining = Math.ceil((current.untilMs - now) / 1000)
  return {
    active: true,
    remainingSec: remaining,
    message: "SSH signing requests are being refused after repeated unanswered prompts. "
      + "Normal service resumes in " + formatDuration(remaining) + "."
  }
}

// -------------------------------------------------------------------------
// Vault lifecycle
// -------------------------------------------------------------------------
//
// The companion's state follows the vault's, and both are stated explicitly
// rather than inferred from whether a socket or a key happens to exist. The
// two functions below are the design's state table; sshAgentLifecycleTransition
// is what each vault event does about it.

// The panel waits this long for the companion's `locked` acknowledgment and
// then kills it. The acknowledgment is what lets the panel say "keys cleared"
// as well as "vault locked" -- it is never a precondition for locking, because
// a companion that cannot confirm a lock is one that must not keep running.
var SSH_AGENT_LOCK_ACK_TIMEOUT_MS = 2000

function sshAgentLockAckTimeoutMs() { return SSH_AGENT_LOCK_ACK_TIMEOUT_MS }

// Settings the companion has to act on. Sent after the handshake and again
// whenever they change, because the companion has no other way to learn them.
function sshAgentOptionsLine(unlockOnDemand) {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "options",
    unlockOnDemand: unlockOnDemand === true }) + "\n"
}

function sshAgentRevokeGrantsLine() {
  return JSON.stringify({ v: SSH_AGENT_CONTROL_VERSION, type: "revoke_grants" }) + "\n"
}

// Ordered most-restrictive first, so a stale public cache can never outrank a
// logout: an account change has to leave nothing behind, whatever was loaded a
// moment earlier.
function sshAgentVaultState(context) {
  var ctx = context || {}
  if (!ctx.enabled || !ctx.helperReady) return "disabled"
  if (!ctx.loggedIn) return "logged-out"
  if (ctx.loading) return "loading"
  if (ctx.unlocked) return "unlocked"
  return ctx.hasPublicCache ? "locked-cached" : "locked-empty"
}

// What each state offers. Public keys are not secret, so they survive a lock
// and spare the user an unlock prompt for an identity listing; private keys
// exist in exactly one state, and it is the only one that can sign without a
// further unlock.
var SSH_AGENT_STATE_POLICY = {
  "disabled":      { publicIdentities: false, privateKeys: false, signing: "denied" },
  "logged-out":    { publicIdentities: false, privateKeys: false, signing: "denied" },
  "locked-empty":  { publicIdentities: false, privateKeys: false, signing: "needs-unlock" },
  // A load publishes nothing until it completes, so the previous public cache
  // is all that is on offer and no signature may cross.
  "loading":       { publicIdentities: true,  privateKeys: false, signing: "denied" },
  "unlocked":      { publicIdentities: true,  privateKeys: true,  signing: "allowed" },
  "locked-cached": { publicIdentities: true,  privateKeys: false, signing: "needs-unlock" }
}

function sshAgentIdentityPolicy(state) {
  var policy = SSH_AGENT_STATE_POLICY[state]
  if (!policy) return { publicIdentities: false, privateKeys: false, signing: "denied" }
  return { publicIdentities: policy.publicIdentities, privateKeys: policy.privateKeys, signing: policy.signing }
}

// Events that end the current epoch's private material. Screen lock and
// suspend are listed rather than left for a reader to infer from the panel:
// they are locks, and the table should say so.
var SSH_AGENT_LOCK_EVENTS = ["lock", "screen-lock", "suspend"]
// Events that end the account itself, taking the public projection with it.
var SSH_AGENT_LOGOUT_EVENTS = ["logout", "account-change"]
// Events that ride the panel's own vault read. Only `startup` needs a caller:
// unlock and sync already run loadItems(), which carries the agent branch
// whenever the gate is open, so sending them here would load twice. They stay
// in the table because the table is the specification of what each event
// means, not a list of what happens to need a trigger today.
var SSH_AGENT_LOAD_EVENTS = ["unlock", "sync", "startup"]

function sshAgentLifecycleTransition(event, context) {
  var ctx = context || {}
  var action = {
    controlLines: [],
    cancelLoad: false,
    startLoad: false,
    awaitLockAck: false,
    stopHelper: false,
    clearPublic: false
  }
  var live = Boolean(ctx.enabled) && Boolean(ctx.helperReady)

  if (event === "disable" || event === "shutdown") {
    action.stopHelper = true
    action.cancelLoad = true
    // Nothing of this account survives the feature being turned off, and the
    // companion's socket and FIFO go with the process.
    action.clearPublic = true
    return action
  }

  if (SSH_AGENT_LOCK_EVENTS.indexOf(event) >= 0) {
    // The cancel happens whether or not a companion is listening: the load is
    // the panel's own process group, and a lock has to stop it either way.
    action.cancelLoad = true
    if (live) {
      action.controlLines.push(sshAgentVaultLockedLine(ctx.epoch))
      action.awaitLockAck = true
    }
    return action
  }

  if (SSH_AGENT_LOGOUT_EVENTS.indexOf(event) >= 0) {
    action.cancelLoad = true
    action.clearPublic = true
    // No acknowledgment is waited on here. Logout already tears the account
    // down on the panel's side, and the companion's public cache goes with it
    // rather than being retained the way a lock retains it.
    if (live) action.controlLines.push(sshAgentLoggedOutLine())
    return action
  }

  if (SSH_AGENT_LOAD_EVENTS.indexOf(event) >= 0) {
    // Startup is not evidence that the vault is locked: `rememberSession` can
    // restore a session key, leaving the panel unlocked while a freshly
    // started companion still has no cache. That case needs the same load an
    // interactive unlock would have run.
    action.startLoad = live && Boolean(ctx.unlocked)
    return action
  }

  return action
}

// Setup is an explicit state, not something inferred from whether a socket
// happens to exist. There are exactly three, and the transient face of
// starting up is `enabled` with `busy` set rather than a fourth:
//
//   disabled  nothing runs; no socket, no FIFO, no agent branch
//   enabled   the helper is running, or is on its way to running
//   error     the helper is stopped or backing off; the vault is unaffected
//
// Client routing is deliberately absent. Where SSH_AUTH_SOCK points changes
// nothing here: the companion binds a deterministic path and never reads that
// variable, so routing is a diagnostic about the user's terminal, not a
// verdict on the feature. See sshAuthSockDiagnostic().
function sshAgentSetupState(opts) {
  var o = opts || {}
  if (!o.enabled) {
    return {
      state: "disabled", busy: false,
      message: "The SSH agent is off. Your vault works normally; SSH keys stay read-only records."
    }
  }
  // The one hard prerequisite. XDG_RUNTIME_DIR is set by pam_systemd at login,
  // and falling back to a guessable path would put the socket somewhere
  // another user could have prepared first.
  if (!o.supervisable) {
    return {
      state: "error", busy: false,
      message: "The SSH agent needs a per-login runtime directory and could not find one. "
        + "Without XDG_RUNTIME_DIR it refuses to start rather than use a path it cannot trust."
    }
  }
  if (o.phase === "ready") {
    return { state: "enabled", busy: false, message: "The SSH agent is running and serving its socket." }
  }
  if (o.phase === "starting" || o.phase === "handshaking") {
    return { state: "enabled", busy: true, message: "Starting the SSH agent helper..." }
  }
  return {
    state: "error", busy: false,
    message: o.errorCode ? sshAgentErrorMessage(o.errorCode) : sshAgentErrorMessage("EXITED")
  }
}

// phase:
//   "disabled"    nothing runs and nothing is scheduled
//   "starting"    Process.running is true, waiting for onStarted
//   "handshaking" hello written, waiting for `ready` under a bounded timeout
//   "ready"       handshake complete; this is the only phase with an open gate
//   "restarting"  a failure was detected mid-run; waiting for the child to go
//   "backoff"     a restart timer is armed
//   "failed"      the restart cap was reached; the feature is off until it is
//                 explicitly re-enabled, and the rest of the plugin is untouched
function sshAgentInitialState() {
  return {
    phase: "disabled",
    gateOpen: false,
    socketPath: "",
    fifoPath: "",
    agentVersion: "",
    failures: 0,
    readyAtMs: 0,
    errorCode: "",
    errorMessage: ""
  }
}

function sshAgentNoAction() {
  return { start: false, stop: false, writeHello: false, cancelRestart: false, restartInMs: -1, message: null }
}

function sshAgentCopyState(state) {
  var src = state || sshAgentInitialState()
  return {
    phase: src.phase, gateOpen: src.gateOpen,
    socketPath: src.socketPath, fifoPath: src.fifoPath, agentVersion: src.agentVersion,
    failures: src.failures, readyAtMs: src.readyAtMs,
    errorCode: src.errorCode, errorMessage: src.errorMessage
  }
}

var SSH_AGENT_ERROR_MESSAGES = {
  MALFORMED: "The SSH agent helper sent something the panel could not read.",
  LINE_TOO_LONG: "The SSH agent helper sent an oversized message.",
  VERSION_MISMATCH: "The SSH agent helper does not match this version of the plugin.",
  UNKNOWN_TYPE: "The SSH agent helper does not match this version of the plugin.",
  PROTOCOL: "The SSH agent helper broke its side of the control protocol.",
  HANDSHAKE_TIMEOUT: "The SSH agent helper did not finish starting up.",
  EXITED: "The SSH agent helper stopped unexpectedly.",
  CRASH_LOOP: "The SSH agent helper keeps failing to start, so it has been left off."
}

// Every message the user can see is a fixed string chosen by a stable code.
// Nothing the helper wrote reaches the UI: its stdout is the one input here
// that could be shaped by a vault item's name or a parser error.
function sshAgentErrorMessage(code) {
  return SSH_AGENT_ERROR_MESSAGES[code] || SSH_AGENT_ERROR_MESSAGES.EXITED
}

// A failure noticed while the child is still alive. The gate shuts now; the
// restart is decided when the exit actually arrives, so the backoff always
// counts real runs.
function sshAgentFailMidRun(next, action, code) {
  next.gateOpen = false
  next.phase = "restarting"
  next.errorCode = code
  next.errorMessage = sshAgentErrorMessage(code)
  action.stop = true
  action.cancelRestart = true
}

// A run has ended. A run that lasted counts as healthy and clears the history
// behind it; anything else advances the backoff, and passing the cap turns the
// feature off rather than restarting forever.
function sshAgentFailOnExit(state, next, action, nowMs) {
  next.gateOpen = false
  next.socketPath = ""
  next.fifoPath = ""
  next.agentVersion = ""
  if (!next.errorCode) {
    next.errorCode = "EXITED"
    next.errorMessage = sshAgentErrorMessage("EXITED")
  }
  var wasHealthy = state.readyAtMs > 0 && (Number(nowMs) - state.readyAtMs) >= SSH_AGENT_HEALTHY_MS
  next.readyAtMs = 0
  next.failures = (wasHealthy ? 0 : state.failures) + 1
  if (next.failures > SSH_AGENT_MAX_RESTARTS) {
    next.phase = "failed"
    next.errorCode = "CRASH_LOOP"
    next.errorMessage = sshAgentErrorMessage("CRASH_LOOP")
    action.restartInMs = -1
    return
  }
  next.phase = "backoff"
  action.restartInMs = sshAgentRestartDelayMs(next.failures)
}

// The whole supervisor, as one pure transition. The panel hands in an event
// with the current clock and gets back the next state plus the side effects to
// perform; it never has to work out what phase means what.
function sshAgentReduce(state, event) {
  var current = state || sshAgentInitialState()
  var next = sshAgentCopyState(current)
  var action = sshAgentNoAction()
  var ev = event || {}
  var nowMs = Number(ev.nowMs) || 0

  if (ev.kind === "enabled") {
    if (!ev.value) {
      if (current.phase === "disabled") return { state: next, action: action }
      next = sshAgentInitialState()
      action.stop = true
      action.cancelRestart = true
      return { state: next, action: action }
    }
    // Re-enabling is the deliberate reset: it clears a crash-loop verdict and
    // the failure history that produced it. Nothing else does, so a broken
    // helper stays off until the user says otherwise.
    if (current.phase !== "disabled" && current.phase !== "failed") {
      return { state: next, action: action }
    }
    next = sshAgentInitialState()
    next.phase = "starting"
    action.start = true
    return { state: next, action: action }
  }

  if (current.phase === "disabled" || current.phase === "failed") {
    return { state: next, action: action }
  }

  switch (ev.kind) {
    case "started":
      if (current.phase !== "starting") return { state: next, action: action }
      next.phase = "handshaking"
      action.writeHello = true
      return { state: next, action: action }

    case "handshakeTimeout":
      if (current.phase !== "starting" && current.phase !== "handshaking") {
        return { state: next, action: action }
      }
      sshAgentFailMidRun(next, action, "HANDSHAKE_TIMEOUT")
      return { state: next, action: action }

    case "line": {
      if (current.phase !== "handshaking" && current.phase !== "ready") {
        return { state: next, action: action }
      }
      var parsed = parseAgentEvent(ev.line)
      if (!parsed.ok) {
        if (!parsed.fatal) return { state: next, action: action }
        sshAgentFailMidRun(next, action, parsed.code)
        return { state: next, action: action }
      }
      var isReady = parsed.message.type === "ready"
      // `ready` answers `hello` exactly once. A second one, or any other
      // message before the first, means the helper is not in the state the
      // panel believes it is -- which is a signing-gate failure, not a
      // message to interpret.
      if (isReady !== (current.phase === "handshaking")) {
        sshAgentFailMidRun(next, action, "PROTOCOL")
        return { state: next, action: action }
      }
      if (isReady) {
        next.phase = "ready"
        next.gateOpen = true
        next.socketPath = parsed.message.socketPath
        next.fifoPath = parsed.message.fifoPath
        next.agentVersion = parsed.message.agentVersion
        next.readyAtMs = nowMs
        // Deliberately not resetting `failures` here. A handshake proves the
        // helper started, not that it works: a helper that answers hello and
        // dies a second later, every time, is exactly the crash loop this
        // bound exists to stop. Only a run that actually lasted clears the
        // history, and that is decided at exit against SSH_AGENT_HEALTHY_MS.
        next.errorCode = ""
        next.errorMessage = ""
        return { state: next, action: action }
      }
      action.message = parsed.message
      return { state: next, action: action }
    }

    case "exited":
      sshAgentFailOnExit(current, next, action, nowMs)
      return { state: next, action: action }

    case "restartTimer":
      if (current.phase !== "backoff") return { state: next, action: action }
      next.phase = "starting"
      action.start = true
      return { state: next, action: action }

    default:
      return { state: next, action: action }
  }
}

// Whether the panel should be sitting on the setup screen instead of talking
// to `bw`. The plugin is installed and enabled before the CLI it drives
// necessarily exists -- `omarchy plugin add` does not install anything else --
// so a fresh install has to lead with "here is what is missing, install it"
// rather than a status probe. Without `bw` that probe can only ever come back
// "not logged in", and the login form it lands on is a dead end until the CLI
// is there.
//
// The gate closes on three conditions rather than one: nothing is decided
// until the probe has actually run (`checked`), it only holds while a required
// tool is genuinely absent, and the user can always step past it (`dismissed`)
// to reach the login screen anyway.
function setupGateActive(deps, checked, dismissed) {
  if (!checked || dismissed) return false
  return missingRequired(deps).length > 0
}

// What a finished dependency probe should do next. The panel has exactly three
// reactions available and choosing the wrong one is what a fresh install
// experiences as breakage, so the decision sits here in the open rather than
// inside a signal handler where nothing can reach it.
//
//   "setup" -- a required tool is absent and the user has not waved setup
//              away: show it, and ask `bw` nothing.
//   "probe" -- the required tools are all present, and either this session has
//              never looked at the vault or an install just arrived and the
//              panel has been waiting on it. Either way, go ask.
//   "idle"  -- nothing to do. The ordinary case on a machine already set up,
//              and also the case where a required tool is still missing but
//              the user chose to carry on regardless.
//
// `wasGated` is the caller's memory of having seen a required tool missing. It
// is what makes an install finishing in a terminal we do not own -- no exit
// code, no signal, nothing to wait on -- turn into a panel that moves on.
function dependencyProbeOutcome(deps, dismissed, probeStarted, wasGated) {
  if (missingRequired(deps).length > 0) return dismissed ? "idle" : "setup"
  if (!probeStarted || wasGated) return "probe"
  return "idle"
}

// The packages a first-run install should ask for: everything absent, required
// or not, so one trip through the terminal leaves the whole feature set
// working instead of the bare minimum.
function missingPackages(deps) {
  var pkgs = []
  if (!deps || !deps.items) return pkgs
  for (var i = 0; i < deps.items.length; i++) {
    var d = deps.items[i]
    // A row this machine cannot use, or one Omarchy sets up through its own
    // command, is not something to hand to `pkg add`.
    if (!d.applicable || d.setup || d.installed) continue
    if (pkgs.indexOf(d.pkg) === -1) pkgs.push(d.pkg)
  }
  return pkgs
}

// Package names reach the installer through an unquoted shell expansion
// (omarchy-install-app runs `omarchy-pkg-add ${packages}`, where the splitting
// is the point). Everything here comes from the DEPENDENCIES constant above,
// so this guards a constant rather than user input -- but the guard is what
// keeps that true if a package name ever starts coming from somewhere else.
function isPlainPackageName(name) {
  return typeof name === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)
}

// Installs are surfaced through Omarchy's own installer: a floating, centred,
// themed terminal with the Omarchy logo, the package output, and a "press any
// key to close" at the end. Same window every other app install on the system
// opens, and it means we neither pick a terminal nor invent our own wait-for-
// keypress. A password prompt has somewhere to be answered.
function installPackagesCommand(pkgs, displayName) {
  if (!pkgs || pkgs.length === 0) return null
  for (var i = 0; i < pkgs.length; i++) {
    if (!isPlainPackageName(pkgs[i])) return null
  }
  var name = displayName || (pkgs.length === 1 ? pkgs[0] : "Bitwarden plugin dependencies")
  return ["omarchy", "install", "app", name, pkgs.join(" ")]
}

// Fingerprint is Omarchy's to set up, not ours: `omarchy setup security
// fingerprint` detects the reader, installs libfprint/fprintd/usbutils,
// enrols a finger, verifies it, and only then writes the PAM stacks -- the
// last of which is what this plugin's `ready` check is actually looking for.
// It runs in the same floating terminal as an install, since it is interactive
// (sudo, then "keep moving the finger around on the sensor").
function fingerprintSetupCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy setup security fingerprint"]
}

// -------------------------------------------------------------------------
// Settings Persistence
// -------------------------------------------------------------------------
//
// Settings belong in the widget's own entry in ~/.config/omarchy/shell.json --
// that is where Panel.setting() reads them and where Omarchy's own tooling
// expects them. Writing goes through `omarchy bar set` rather than editing the
// file directly, so Omarchy owns the parsing, merging and formatting, and the
// shell picks the change up on its usual hot reload.

var SETTINGS_GROUPS = [
  { id: "security", label: "Security" },
  { id: "sshAgent", label: "SSH Agent" },
  { id: "behavior", label: "Behavior" },
  { id: "suggestions", label: "Suggestions" }
]

var SETTINGS_SCHEMA = [
  { key: "autoLockMinutes", group: "security", type: "int", label: "Auto-lock after", unit: "minutes",
    min: 0, max: 1440, step: 5, zeroLabel: "Never", defaultValue: 15,
    description: "Lock the vault after this long without activity." },
  { key: "clearClipboardSec", group: "security", type: "int", label: "Clear clipboard after", unit: "seconds",
    min: 0, max: 300, step: 5, zeroLabel: "Never", defaultValue: 30,
    description: "Wipe a copied password or code from the clipboard." },
  { key: "lockOnScreenLock", group: "security", type: "bool", label: "Lock when the screen locks", defaultValue: true,
    description: "Lock as soon as the screen locks, rather than waiting out the auto-lock." },
  { key: "lockOnSuspend", group: "security", type: "bool", label: "Lock when the machine suspends", defaultValue: true,
    description: "Lock before sleep, so no session key is left in the suspended machine's memory." },
  { key: "rememberSession", group: "security", type: "bool", label: "Remember session in keyring", defaultValue: true,
    description: "Keep the unlocked session in the OS keyring so it survives a shell restart." },
  { key: "fingerprintUnlock", group: "security", type: "bool", label: "Unlock with fingerprint", defaultValue: false,
    requires: "fprintd", action: "fingerprint",
    description: "Store the master password in the OS keyring, gated behind a fingerprint." },
  { key: "pinUnlock", group: "security", type: "bool", label: "Unlock with PIN", defaultValue: false,
    action: "pin",
    description: "Encrypt the master password with a key derived from a PIN. Use 6 digits or more; 4 is the floor and is flagged as weak." },

  { key: "sshAgentEnabled", group: "sshAgent", type: "bool", label: "Act as your SSH agent", defaultValue: false,
    description: "Serve SSH keys from your vault to ssh, Git and signing, while the vault is unlocked. Private keys stay in a separate helper process and are never written to disk." },
  { key: "sshAgentUnlockOnDemand", group: "sshAgent", type: "bool", label: "Unlock on demand", defaultValue: false,
    description: "Let an SSH client open the unlock prompt when the vault is locked. Off by default because every ssh connection asks for identities, including ones with nothing to do with your vault." },
  { key: "sshAgentApprovalPopup", group: "sshAgent", type: "bool", label: "Use centered approval popup", defaultValue: true,
    description: "Show SSH unlock and signing requests in a transient card in the middle of the screen instead of opening the anchored panel. Disable to show them in the panel." },
  { key: "sshAgentApprovalWindowSec", group: "sshAgent", type: "int", label: "Approve for this long", unit: "seconds",
    min: 0, max: SSH_AGENT_APPROVAL_WINDOW_MAX_SEC, step: 30, zeroLabel: "Always ask", defaultValue: 120,
    description: "How long one approval covers further signatures from the same process. Grants live only in the helper's memory and never survive a restart." },

  { key: "closeOnCopy", group: "behavior", type: "bool", label: "Close panel on copy", defaultValue: true,
    description: "Return focus to your app as soon as Enter copies a credential." },
  { key: "autoCopyTotpSec", group: "behavior", type: "int", label: "Auto-copy TOTP after", unit: "seconds",
    min: 0, max: 30, step: 1, zeroLabel: "Off", defaultValue: 3,
    description: "Replace the clipboard with the 2FA code this long after the password." },

  { key: "suggestOnOpen", group: "suggestions", type: "bool", label: "Suggest for active window", defaultValue: true,
    description: "Match the focused window or browser tab against your vault." }
]

// Schema entries in group order, each tagged with whether it opens a new
// section, so the settings screen can draw one header per group.
function groupedSettings() {
  var out = []
  for (var g = 0; g < SETTINGS_GROUPS.length; g++) {
    var group = SETTINGS_GROUPS[g]
    var first = true
    for (var i = 0; i < SETTINGS_SCHEMA.length; i++) {
      if (SETTINGS_SCHEMA[i].group !== group.id) continue
      var entry = {}
      for (var k in SETTINGS_SCHEMA[i]) entry[k] = SETTINGS_SCHEMA[i][k]
      entry.groupLabel = first ? group.label : ""
      out.push(entry)
      first = false
    }
  }
  return out
}

// The settings the panel should actually draw. The SSH agent rows are held
// back behind the same probe that hides the SSH type filter: a toggle for a
// feature the installed `bw` cannot serve is worse than no toggle at all.
//
// A group heading is its own row rather than a label carried by the first
// setting under it. That is what makes collapsing work: the panel walks this
// list with one index, so a hidden row has to be absent from the list and not
// merely invisible, or the keyboard cursor traverses rows nobody can see. A
// heading that owned itself through another row would vanish with the last
// setting it labelled, leaving a collapsed group with nothing left to click.
//
// `collapsed` is a plain object of group id to true. An unknown or missing
// group reads as expanded, so a caller that has never set one gets every
// group open and nothing has to be initialised.
function visibleSettings(deps, checked, collapsed) {
  var showSsh = sshUiAvailable(deps, checked)
  var shut = collapsed || {}
  var rows = groupedSettings().filter(function(entry) {
    return showSsh || entry.group !== "sshAgent"
  })

  var out = []
  var seen = {}
  for (var i = 0; i < rows.length; i++) {
    var entry = rows[i]
    if (!seen[entry.group]) {
      seen[entry.group] = true
      out.push({
        kind: "group",
        group: entry.group,
        label: groupLabelFor(entry.group),
        collapsed: Boolean(shut[entry.group]),
        count: countSettingsInGroup(rows, entry.group)
      })
    }
    if (shut[entry.group]) continue
    entry.kind = "setting"
    // The label lived on the first row of each group. It has a row of its own
    // now, and leaving the old field set would draw both.
    entry.groupLabel = ""
    out.push(entry)
  }
  return out
}

function countSettingsInGroup(rows, group) {
  var n = 0
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].group === group) n++
  }
  return n
}

// Which groups a freshly opened settings screen shows expanded. Security is
// the one people come here for; the rest are opened deliberately. Returned
// fresh each time so a caller cannot mutate a shared default.
function defaultCollapsedGroups() {
  var out = {}
  for (var i = 0; i < SETTINGS_GROUPS.length; i++) {
    if (SETTINGS_GROUPS[i].id !== "security") out[SETTINGS_GROUPS[i].id] = true
  }
  return out
}

function toggleCollapsedGroup(collapsed, group) {
  var out = {}
  for (var k in (collapsed || {})) out[k] = collapsed[k]
  if (out[group]) delete out[group]
  else out[group] = true
  return out
}

function groupLabelFor(id) {
  for (var i = 0; i < SETTINGS_GROUPS.length; i++) {
    if (SETTINGS_GROUPS[i].id === id) return SETTINGS_GROUPS[i].label
  }
  return ""
}

function settingSchemaEntry(key) {
  for (var i = 0; i < SETTINGS_SCHEMA.length; i++) {
    if (SETTINGS_SCHEMA[i].key === key) return SETTINGS_SCHEMA[i]
  }
  return null
}

// Every integer setting is read straight back out of shell.json, and nothing
// validates what goes in there. `omarchy bar set` stores whatever value it is
// handed -- a bare word becomes a JSON string, `--json` stores any number at
// all -- and the README documents editing the file by hand as well. The
// settings screen clamps to the schema on the way out; this is the same clamp
// on the way in, which is the direction that was missing.
//
// It matters most for the auto-lock, because QML turns a bad minute count into
// a dangerous one rather than an obvious one. `Number("fifteen")` is NaN, and
// NaN assigned to an `int` property is 0 -- which is exactly how "never lock"
// is spelled. A count past the schema's ceiling fails the same way from the
// other end: 999999 minutes is 59,999,940,000 ms, which overflows the `int`
// behind Timer.interval and lands negative, and a Timer with a negative
// interval never fires. Both readings leave a vault that never locks itself,
// silently, so an unreadable value falls back to the schema's default rather
// than to zero.
function intSetting(key, raw) {
  // Number() is too generous to be the whole test here: it reads null, "" and
  // false as 0, and 0 is a meaningful setting rather than a missing one. Only
  // something that was written as a number, or as the decimal string that
  // `omarchy bar set` writes without --json, counts as a value at all.
  var n = (typeof raw === "number" || (typeof raw === "string" && String(raw).trim() !== ""))
    ? Math.floor(Number(raw))
    : NaN
  var entry = settingSchemaEntry(key)
  if (!entry || entry.type !== "int") return isFinite(n) ? n : 0
  // Below the floor is treated as unreadable rather than clamped up to it,
  // because on every integer setting here the floor is also the sentinel for
  // "off": clamping -1 minutes to 0 spells "never lock" and clamping -1
  // seconds to 0 spells "never clear the clipboard". That is the same silent
  // failure this function exists to refuse, arrived at from the other side.
  // Past the ceiling still clamps down, since that direction only ever locks
  // sooner than asked.
  if (!isFinite(n) || n < entry.min) n = Math.floor(Number(entry.defaultValue))
  if (!isFinite(n)) n = entry.min
  return Math.max(entry.min, Math.min(entry.max, n))
}

// shell.json is external input. Only a JSON boolean may enable a boolean
// setting; strings such as "false" are truthy in JavaScript and previously
// enabled opt-in PIN/fingerprint storage when the file was malformed.
function boolSetting(key, raw) {
  if (typeof raw === "boolean") return raw
  var entry = settingSchemaEntry(key)
  if (!entry || entry.type !== "bool") return false
  return entry.defaultValue === true
}

function settingWriteCommand(key, value, type) {
  var raw
  if (type === "bool") raw = value ? "true" : "false"
  // `omarchy bar set --json` stores whatever JSON it is handed, which is how a
  // per-account map reaches shell.json. Only the value's own shape travels
  // here; nothing secret is ever a setting.
  else if (type === "json") raw = JSON.stringify(value === undefined ? null : value)
  else raw = String(Number(value) || 0)
  var script = "omarchy bar set io.github.elevate08.qs-bitwarden-cli "
    + shellQuote(String(key)) + " " + shellQuote(raw) + " --json | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// -------------------------------------------------------------------------
// Auto-lock
// -------------------------------------------------------------------------
//
// Qt schedules every Timer on CLOCK_MONOTONIC, and Linux stops that clock
// while the machine is suspended -- CLOCK_BOOTTIME on a laptop that has slept
// overnight runs hours ahead of it. So a fifteen-minute auto-lock armed just
// before the lid closed still had its full fifteen minutes to run when the lid
// opened, and a vault left unattended all night came back to the desk exactly
// as open as it was left. The countdown was only ever measuring the time the
// shell was awake for, which is not the time the vault was exposed for.
//
// Only the wall clock knows about the part in between, so the deadline is kept
// in wall-clock terms as well and polled. The monotonic Timer stays: it is the
// one that is immune to the clock being stepped, and between the two it is
// whichever notices first that does the locking.
var AUTO_LOCK_POLL_MS = 30000

// Poll often enough that waking a suspended machine locks the vault in seconds
// rather than minutes, but never longer than the window itself -- a one-minute
// auto-lock must not be checked every thirty seconds and nothing shorter than
// a second is worth waking up for.
function autoLockPollMs(minutes) {
  var m = Math.floor(Number(minutes))
  if (!isFinite(m) || m <= 0) return AUTO_LOCK_POLL_MS
  return Math.max(1000, Math.min(m * 60 * 1000, AUTO_LOCK_POLL_MS))
}

// `armedAt` and `now` are both Date.now(). Zero minutes is the user asking for
// no auto-lock at all, and an unarmed window has no deadline to have passed,
// so both answer false rather than "lock immediately".
function autoLockExpired(armedAt, minutes, now) {
  var m = Math.floor(Number(minutes))
  if (!isFinite(m) || m <= 0) return false
  var start = Number(armedAt)
  var at = Number(now)
  if (!isFinite(start) || start <= 0 || !isFinite(at)) return false
  return (at - start) >= m * 60 * 1000
}

// -------------------------------------------------------------------------
// Password / Passphrase Generator
// -------------------------------------------------------------------------
//
// Mirrors the option set of the Bitwarden browser extension's generator and
// delegates the actual generation to `bw generate`, so the output comes from
// Bitwarden's own generator rather than a reimplementation of it.

var GENERATOR_DEFAULTS = {
  type: "password",       // "password" | "passphrase"
  length: 14,
  uppercase: true,
  lowercase: true,
  numbers: true,
  special: false,
  minNumber: 1,
  minSpecial: 1,
  ambiguous: false,       // true = avoid ambiguous characters
  words: 3,
  separator: "-",
  capitalize: false,
  includeNumber: false
}

var GENERATOR_LIMITS = {
  length: { min: 5, max: 128 },
  words: { min: 3, max: 20 },
  minNumber: { min: 0, max: 9 },
  minSpecial: { min: 0, max: 9 }
}

function generatorDefaults() {
  var out = {}
  for (var k in GENERATOR_DEFAULTS) out[k] = GENERATOR_DEFAULTS[k]
  return out
}

function clampInt(value, limit) {
  var n = Math.floor(Number(value))
  if (isNaN(n)) n = limit.min
  return Math.max(limit.min, Math.min(limit.max, n))
}

// At least one character set must be on, or `bw generate` errors out. Falling
// back to lowercase keeps the control usable while the user toggles the rest.
function normalizeGeneratorOptions(opts) {
  var o = generatorDefaults()
  for (var k in opts) if (opts[k] !== undefined) o[k] = opts[k]

  o.length = clampInt(o.length, GENERATOR_LIMITS.length)
  o.words = clampInt(o.words, GENERATOR_LIMITS.words)
  o.minNumber = clampInt(o.minNumber, GENERATOR_LIMITS.minNumber)
  o.minSpecial = clampInt(o.minSpecial, GENERATOR_LIMITS.minSpecial)

  if (!o.uppercase && !o.lowercase && !o.numbers && !o.special) o.lowercase = true
  if (!o.numbers) o.minNumber = 0
  if (!o.special) o.minSpecial = 0

  // Asking for more required characters than there is room for cannot be met.
  var required = (o.numbers ? o.minNumber : 0) + (o.special ? o.minSpecial : 0)
  if (required > o.length) o.length = Math.min(GENERATOR_LIMITS.length.max, required)

  if (!o.separator) o.separator = "-"
  return o
}

// -------------------------------------------------------------------------
// Generator over `bw serve`
// -------------------------------------------------------------------------
//
// `bw generate` costs ~2.9s on this machine, and none of it is generation:
// ~0.9s is the CLI's Node bootstrap and ~2s is Bitwarden's service container
// coming up, all of it repaid on every option toggle. `bw serve` pays that
// once and answers /generate in ~2ms.
//
// The served instance is deliberately started with **no session**, so it is a
// locked vault that can generate passwords and nothing else -- /list and the
// rest return errors. That matters: a loopback port has no authentication and
// is reachable by every user on the machine, so an unlocked `bw serve` would
// hand the whole vault to anyone who could curl it. A locked one exposes the
// generator, which is not a secret. Vault reads stay on the CLI, where the
// session key is ours alone.
var GENERATE_HOST = "127.0.0.1"
var GENERATE_PORT = 8087

// Started as a managed child so it dies with the shell rather than lingering.
// BW_SESSION is cleared by the caller; see generatorServeEnv() in Panel.qml.
function generateServeCommand() {
  return ["bw", "serve", "--hostname", GENERATE_HOST, "--port", String(GENERATE_PORT)]
}

// Whether whatever answered the generator port is someone else's server.
//
// A refused connection arrives as status 0, and that is the only answer that
// leaves the port free for ours. Any HTTP status at all -- including the error
// codes a careless squatter returns -- came from a process already bound to it,
// and a "generated password" from a stranger's server is a password they know.
function generatorPortIsForeign(status) {
  return Number(status) !== 0
}

// -------------------------------------------------------------------------
// Generator request bounds
// -------------------------------------------------------------------------
//
// Refusing to trust a squatter's password is only half of it. The port is
// loopback, unauthenticated and first-come. A process holding 8087 that accepts
// the connection and answers nothing could stall indefinitely, and a squatter
// could stream an endless body at loopback speeds.
//
// To enforce hard limits on both duration and volume, every request to bw serve
// is executed via a managed curl child process whose output is bounded on the
// producer side with `| head -c` and `--max-time`. This avoids Qt/QML's
// XMLHttpRequest, which buffers responses directly into the shared shell
// process memory before JavaScript can inspect or abort them.
var GENERATE_RESPONSE_CAP = 64 * 1024
var GENERATE_REQUEST_TIMEOUT_MS = 2000

function generatorResponseCap() { return GENERATE_RESPONSE_CAP }
function generatorRequestTimeoutMs() { return GENERATE_REQUEST_TIMEOUT_MS }

// Builds a producer-bounded command to query the generator server.
// Output is capped via `head -c` so no more than GENERATE_RESPONSE_CAP bytes
// can pass through the pipe into the shell process heap.
function generateServeRequestCommand(opts) {
  var url = generateServeUrl(opts)
  var timeoutSecs = Math.max(1, Math.round(GENERATE_REQUEST_TIMEOUT_MS / 1000))
  // -q must be curl's first option to suppress ~/.curlrc. --noproxy makes the
  // loopback guarantee independent of HTTP_PROXY/ALL_PROXY in the shell.
  var script = "curl -q -s -S --noproxy '*' --max-time " + timeoutSecs + " --connect-timeout " + timeoutSecs
    + " " + shellQuote(url) + " | head -c " + Number(GENERATE_RESPONSE_CAP)
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Both the declared length and what has actually arrived are checked. A
// chunked response declares nothing at all, and a declared length is the
// sender's word for it either way.
function generatorResponseTooLarge(contentLength, received) {
  var declared = Number(contentLength)
  if (isFinite(declared) && declared > GENERATE_RESPONSE_CAP) return true
  return Number(received) > GENERATE_RESPONSE_CAP
}

// What a finished probe means.
//
// When checking via a curl process: exit code 7 (CURLE_COULDNT_CONNECT) with
// empty output is the only outcome that proves the port was silent and free
// for our own server. Exit code 0 means another server answered; exit code 28
// means a connection timed out; exit code 23/141 means an oversized stream was
// cut short. All of those mean another process was bound to the port.
//
// When called with (status, aborted): status 0 is a refused connection (free),
// while non-zero status or an aborted request means the port is occupied.
function generatorProbeIsForeign(statusOrExitCode, abortedOrStdout) {
  if (typeof abortedOrStdout === "boolean") {
    if (abortedOrStdout) return true
    return generatorPortIsForeign(statusOrExitCode)
  }
  var code = Number(statusOrExitCode)
  var out = String(abortedOrStdout || "").trim()
  if (code === 7 && out === "") return false
  return true
}

// What to do when our own `bw serve` exits.
//
// The distinction that matters is between a shutdown we asked for and one we
// did not. A server that dies on its own never bound, or died trying, and our
// bind failing is exactly what a squatted port looks like from here -- so a
// value the ready-poll already accepted may never have come from us at all and
// cannot be left on screen to be copied into the vault.
function generatorServeExitAction(state) {
  var st = state || {}
  if (st.stopping) return { giveUp: false, dropValue: false, useCli: false }
  var strandedValue = !!st.wasReady
  return {
    giveUp: true,
    dropValue: strandedValue,
    useCli: (strandedValue || !!st.busy) && !!st.onGeneratorScreen
  }
}

// The serve API takes the same options as the CLI flags, as query parameters.
function generateServeUrl(opts) {
  var o = normalizeGeneratorOptions(opts)
  var q = []

  if (o.type === "passphrase") {
    q.push("passphrase=true")
    q.push("words=" + encodeURIComponent(String(o.words)))
    q.push("separator=" + encodeURIComponent(String(o.separator)))
    if (o.capitalize) q.push("capitalize=true")
    if (o.includeNumber) q.push("includeNumber=true")
  } else {
    if (o.uppercase) q.push("uppercase=true")
    if (o.lowercase) q.push("lowercase=true")
    if (o.numbers) q.push("number=true")
    if (o.special) q.push("special=true")
    q.push("length=" + encodeURIComponent(String(o.length)))
    if (o.numbers) q.push("minNumber=" + encodeURIComponent(String(o.minNumber)))
    if (o.special) q.push("minSpecial=" + encodeURIComponent(String(o.minSpecial)))
    if (o.ambiguous) q.push("ambiguous=true")
  }

  return "http://" + GENERATE_HOST + ":" + GENERATE_PORT + "/generate?" + q.join("&")
}

// { success: true, data: { data: "<password>" } } on the way out.
function parseServeGenerated(raw) {
  var parsed = null
  try {
    parsed = JSON.parse(raw)
  } catch (e) {
    return ""
  }
  if (!parsed || parsed.success !== true || !parsed.data) return ""
  return String(parsed.data.data || "")
}

function generateCommand(opts) {
  var o = normalizeGeneratorOptions(opts)
  var args = ["generate"]

  if (o.type === "passphrase") {
    args.push("--passphrase", "--words", String(o.words), "--separator", String(o.separator))
    if (o.capitalize) args.push("--capitalize")
    if (o.includeNumber) args.push("--includeNumber")
    return buildCappedCommand(args, MAX_TOKEN_BYTES)
  }

  if (o.uppercase) args.push("--uppercase")
  if (o.lowercase) args.push("--lowercase")
  if (o.numbers) args.push("--number")
  if (o.special) args.push("--special")
  args.push("--length", String(o.length))
  if (o.numbers) args.push("--minNumber", String(o.minNumber))
  if (o.special) args.push("--minSpecial", String(o.minSpecial))
  if (o.ambiguous) args.push("--ambiguous")

  return buildCappedCommand(args, MAX_TOKEN_BYTES)
}

function generatorEntropyBits(options) {
  if (options.type === "passphrase") {
    // EFF-style wordlist, ~12.9 bits per word.
    return options.words * 12.9 + (options.includeNumber ? 3.3 : 0)
  }

  var pool = 0
  if (options.uppercase) pool += 26
  if (options.lowercase) pool += 26
  if (options.numbers) pool += 10
  if (options.special) pool += 26
  if (options.ambiguous) pool -= 6
  return options.length * (Math.log(Math.max(pool, 2)) / Math.log(2))
}

function generatorStrengthLabel(bits) {
  if (bits >= 120) return "Excellent"
  if (bits >= 90) return "Strong"
  if (bits >= 60) return "Good"
  if (bits >= 40) return "Fair"
  return "Weak"
}

// Rough strength read for the meter. Deliberately simple: it describes the
// search space the options imply, not the specific string produced.
function generatorStrength(opts) {
  var bits = generatorEntropyBits(normalizeGeneratorOptions(opts))
  return {
    bits: Math.round(bits),
    label: generatorStrengthLabel(bits),
    fraction: Math.max(0, Math.min(1, bits / 128))
  }
}

// -------------------------------------------------------------------------
// Bitwarden Send
// -------------------------------------------------------------------------
//
// Field names below are taken from a real `bw send --fullObject` response
// rather than guessed: accessUrl carries the shareable link, passwordSet is a
// boolean rather than the password itself, and type is 0 for text, 1 for file.

var SEND_TYPE_TEXT = 0
var SEND_TYPE_FILE = 1

function listSendsCommand() {
  return buildCappedCommand(["send", "list"], MAX_SENDS_BYTES)
}

function deleteSendCommand(sendId) {
  return buildCappedCommand(["send", "delete", "--", String(sendId)], MAX_MISC_BYTES)
}

// The payload travels in the environment, not argv. Both the flag form's
// --password and an inlined `printf %s '<json>'` would land the Send password
// in /proc/<pid>/cmdline, which other users can read.
var SEND_ENV = "QSBW_SEND"

function sendEnvVar() {
  return SEND_ENV
}

function createSendCommand() {
  var script = "printf '%s' \"$" + SEND_ENV + "\" | bw encode | bw send create | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function buildSendPayload(name, text, hidden, deleteInDays, maxAccessCount, password, notes) {
  var days = Math.max(1, Math.min(31, Number(deleteInDays) || 7))
  var deletion = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()

  var max = Number(maxAccessCount)
  var payload = {
    object: "send",
    name: String(name || "").trim() || "Untitled Send",
    notes: notes && String(notes).trim() ? String(notes).trim() : null,
    type: SEND_TYPE_TEXT,
    text: { text: String(text || ""), hidden: Boolean(hidden) },
    file: null,
    maxAccessCount: (max > 0) ? max : null,
    deletionDate: deletion,
    expirationDate: null,
    password: password && String(password).length ? String(password) : null,
    emails: null,
    disabled: false,
    hideEmail: false
  }
  return payload
}

function parseSends(raw) {
  var arr = parseJsonArray(raw)
  var out = []
  for (var i = 0; i < arr.length; i++) {
    var s = arr[i]
    if (!s || typeof s !== "object") continue
    out.push({
      id: String(s.id || ""),
      name: String(s.name || "Untitled Send"),
      type: Number(s.type || 0),
      isFile: Number(s.type) === SEND_TYPE_FILE,
      accessUrl: String(s.accessUrl || ""),
      accessCount: Number(s.accessCount || 0),
      maxAccessCount: (s.maxAccessCount === null || s.maxAccessCount === undefined) ? null : Number(s.maxAccessCount),
      deletionDate: String(s.deletionDate || ""),
      expirationDate: s.expirationDate ? String(s.expirationDate) : "",
      passwordSet: Boolean(s.passwordSet),
      disabled: Boolean(s.disabled),
      notes: s.notes ? String(s.notes) : "",
      textPreview: (s.text && s.text.text) ? String(s.text.text) : "",
      textHidden: Boolean(s.text && s.text.hidden),
      fileName: (s.file && s.file.fileName) ? String(s.file.fileName) : ""
    })
  }

  out.sort(function(a, b) {
    return String(a.deletionDate).localeCompare(String(b.deletionDate))
  })
  return out
}

// "in 3 days" / "in 5 hours" / "expired" -- a Send's whole point is that it
// goes away, so the countdown matters more than the timestamp.
function sendExpiryLabel(send, now) {
  if (!send || !send.deletionDate) return ""
  var target = Date.parse(send.deletionDate)
  if (isNaN(target)) return ""

  var ms = target - (now || Date.now())
  if (ms <= 0) return "expired"

  var mins = Math.floor(ms / 60000)
  if (mins < 60) return "in " + mins + (mins === 1 ? " minute" : " minutes")
  var hours = Math.floor(mins / 60)
  if (hours < 24) return "in " + hours + (hours === 1 ? " hour" : " hours")
  var days = Math.floor(hours / 24)
  return "in " + days + (days === 1 ? " day" : " days")
}

function sendAccessLabel(send) {
  if (!send) return ""
  if (send.maxAccessCount === null) return send.accessCount + " views"
  return send.accessCount + " of " + send.maxAccessCount + " views"
}

// ---------------------------------------------------------------------------
// Rendering vault text safely
// ---------------------------------------------------------------------------

// Qt's Text -- and every control built on one -- defaults to Text.AutoText,
// which sniffs the string and renders it as HTML the moment it looks like
// markup. Every Text this plugin owns pins `textFormat: Text.PlainText`, but
// the shared kit controls (Ui.Button's label and tooltip) build their own Text
// internally and expose no way to set the format, so a folder named
// "<img src=x onerror=...>" would be parsed as markup in a credential UI.
//
// So neutralize the string before it is handed over. A value with no "<" and
// no "&" cannot trip Qt's sniffer and passes through untouched -- which is
// nearly everything. Anything else is HTML-escaped and wrapped in a <span>:
// the escape means no character can be read as a tag, and the wrapper forces
// the rich-text path deterministically so those entities are decoded back to
// the literal characters the vault holds instead of being shown raw. The
// white-space rule keeps the spacing plain text would have given.
function plainLabel(value) {
  var text = (value === undefined || value === null) ? "" : String(value)
  if (text.indexOf("<") < 0 && text.indexOf("&") < 0) return text
  return "<span style=\"white-space:pre-wrap\">"
    + text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    + "</span>"
}
