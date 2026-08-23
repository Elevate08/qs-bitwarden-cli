// BitwardenModel.js — Helper module for Bitwarden plugin.
// Pure JavaScript: CLI command constructors, output parsers, filtering, and CRUD builders.

.pragma library

const KEYRING_SERVICE = "qs-bitwarden-cli"
const KEYRING_ACCOUNT = "session"
const KEYRING_CLIENT_ID = "client_id"
const KEYRING_CLIENT_SECRET = "client_secret"
const KEYRING_EMAIL = "user_email"
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

function keyringStoreScript(label, account) {
  return "printf '%s' \"$" + KEYRING_SECRET_ENV + "\" | secret-tool store --label=" + shellQuote(label)
    + " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(account)
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
// interaction disabled and fails fast instead of hanging.
const NOINTERACTION_ENV = "BW_NOINTERACTION"

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

function buildCommand(args) {
  return buildCappedCommand(args, MAX_MISC_BYTES)
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

// How long the panel keeps coming back for a process that was still running
// when the vault locked. Its buffer cannot be scrubbed while it is being
// written; a `bw` that has not finished inside this is one whose own next run
// will replace the buffer anyway.
var SCRUB_RETRY_MS = 1000
var SCRUB_RETRY_LIMIT = 120

function scrubRetryMs() { return SCRUB_RETRY_MS }
function scrubRetryLimit() { return SCRUB_RETRY_LIMIT }

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

// -------------------------------------------------------------------------
// CLI Commands
// -------------------------------------------------------------------------

function statusCommand(session) {
  return buildCappedCommand(["status"], MAX_STATUS_BYTES)
}

// Password is in the environment; output is capped to session token size.
function unlockCommand() {
  return buildCappedCommand(["unlock", "--passwordenv", PASSWORD_ENV, "--raw"], MAX_TOKEN_BYTES, MAX_STDERR_BYTES)
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

function validateServerUrl(raw) {
  var url = String(raw || "").trim()
  if (!url) return ""

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

function emailLoginCommand(email, hasCode, serverUrl) {
  var script = ""

  if (serverUrl && serverUrl.trim()) {
    script += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  script += "bw login " + shellQuote(email) + " --passwordenv " + PASSWORD_ENV
  if (hasCode) script += " --code \"$" + TWOFACTOR_CODE_ENV + "\""
  script += " --raw | head -c " + MAX_TOKEN_BYTES

  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
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
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
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
var HANDOFF_SUBDIR = "qs-bitwarden-cli"
var HANDOFF_BASENAME = "session-handoff"

// `mode` is "login" when logged out and "unlock" when merely locked. The panel
// already knows which, so this does not probe with `bw status` first -- that
// probe measured at ~3.3s, spent before the user was even shown a prompt.
function terminalLoginCommand(mode) {
  var verb = (mode === "unlock") ? "unlock" : "login"
  var inner = "set -u; "
    + "d=\"${XDG_RUNTIME_DIR:?no XDG_RUNTIME_DIR -- refusing to write a session key}/"
    + HANDOFF_SUBDIR + "\"; f=\"$d/" + HANDOFF_BASENAME + "\"; "
    // umask before mkdir, so the directory is born 700 rather than created
    // world-readable and narrowed a moment later. The chmod then covers a
    // directory that already existed, and both are checked: a chmod that
    // fails means the directory is not ours, which is not a place for a key.
    + "umask 077; mkdir -p \"$d\" || exit 1; chmod 700 \"$d\" || exit 1; "
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
    + "f=\"$d/" + HANDOFF_SUBDIR + "/" + HANDOFF_BASENAME + "\"; "
    + "[ -s \"$f\" ] || exit 0; "
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

  if (HTTP_URL_RE.test(target)) return { ok: true, url: target }

  var scheme = target.match(URL_SCHEME_RE)
  if (scheme) return { ok: false, scheme: scheme[1].toLowerCase() }

  // No scheme: a bare host, optionally with a port and path.
  return { ok: true, url: "https://" + target }
}

function logoutCommand() {
  return ["bw", "logout"]
}

function listCommand(session) {
  return buildCappedCommand(["list", "items"], MAX_ITEMS_BYTES, MAX_STDERR_BYTES)
}

function listOrganizationsCommand(session) {
  return buildCappedCommand(["list", "organizations"], MAX_ORGS_BYTES)
}

function listFoldersCommand(session) {
  return buildCappedCommand(["list", "folders"], MAX_FOLDERS_BYTES)
}

// An organization's collections. Bitwarden files org-owned items into
// collections rather than folders, and refuses to create one without at least
// one collection, so the form has to offer them.
function listOrgCollectionsCommand(organizationId) {
  return buildCappedCommand(["list", "org-collections", "--organizationid", String(organizationId)], MAX_COLLECTIONS_BYTES)
}

function parseCollections(raw) {
  var arr = null
  try {
    arr = JSON.parse(raw)
  } catch (e) {
    return []
  }
  if (!Array.isArray(arr)) return []

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
  out.sort(function(a, b) {
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
  })
  return out
}

function collectionName(collections, id) {
  if (!id || !Array.isArray(collections)) return ""
  for (var i = 0; i < collections.length; i++) {
    if (collections[i].id === id) return collections[i].name
  }
  return ""
}

function createFolderCommand(name, session) {
  var jsonStr = JSON.stringify({ name: String(name || "").trim() })
  var script = "printf %s " + shellQuote(jsonStr) + " | bw encode | bw create folder | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function deleteFolderCommand(folderId) {
  return buildCappedCommand(["delete", "folder", "--", String(folderId)], MAX_MISC_BYTES)
}

function getItemCommand(id, session) {
  return buildCappedCommand(["get", "item", "--", String(id)], MAX_DETAIL_BYTES, MAX_STDERR_BYTES)
}

function getTotpCommand(id, session) {
  return buildCappedCommand(["get", "totp", "--raw", "--", String(id)], MAX_TOKEN_BYTES)
}

// Fetching a secret straight into the clipboard keeps it out of QML entirely:
// nothing comes back on stdout, so there is no property holding a password
// that has to be remembered to clear afterwards.
//
// These two were the only bw invocations the panel assembled by hand, and both
// had drifted from the invariant every builder above keeps: `--` before the
// id. Quoting an id defends against the shell, not against bw's own option
// parser -- a quoted `--help` is still `--help` by the time bw sees it -- so
// `--` is the part that makes an id shaped like a flag read as the id it is.
function clipboardPipeCommand(producer, maxBytes) {
  return ["bash", "-c", cappedScript(producer + " | head -c " + Number(maxBytes)
    + " | wl-copy --sensitive", MAX_STDERR_BYTES)]
}

function copyPasswordToClipboardCommand(id) {
  return clipboardPipeCommand("bw get password --raw -- " + shellQuote(String(id)), MAX_TOKEN_BYTES)
}

function copyTotpToClipboardCommand(id) {
  return clipboardPipeCommand("bw get totp --raw -- " + shellQuote(String(id)), 1024)
}

function syncCommand(session) {
  return buildCappedCommand(["sync"], MAX_MISC_BYTES)
}

function lockCommand(session) {
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

function createItemCommand(itemData, session) {
  var orgArg = (itemData && itemData.organizationId) ? (" --organizationid " + shellQuote(itemData.organizationId)) : ""
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw create item" + orgArg + " | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function editItemCommand(itemId, session) {
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw edit item -- " + shellQuote(itemId) + " | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function deleteItemCommand(itemId) {
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
  var attrs = " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(KEYRING_ACCOUNT)
  // The secret still travels in the environment (see keyringStoreScript); only
  // the boot id, which is not a secret, is read inside the script.
  var script = "store() { printf '%s %s' \"$(cat " + shellQuote(BOOT_ID_PATH) + ")\" \"$"
    + KEYRING_SECRET_ENV + "\" | secret-tool store \"$@\" --label="
    + shellQuote("Bitwarden Vault Session") + attrs + "; }; "
    + "store --collection=" + shellQuote(KEYRING_SESSION_COLLECTION) + " 2>/dev/null || store"
  return ["bash", "-c", script]
}

function keyringLookupCommand() {
  var attrs = " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(KEYRING_ACCOUNT)
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
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringStoreApiKeyIdCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden API Client ID", KEYRING_CLIENT_ID)]
}

function keyringLookupApiKeyIdCommand() {
  return ["bash", "-c", cappedScript("secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_CLIENT_ID) + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES)]
}

function keyringStoreApiKeySecretCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden API Client Secret", KEYRING_CLIENT_SECRET)]
}

function keyringLookupApiKeySecretCommand() {
  return ["bash", "-c", cappedScript("secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_CLIENT_SECRET) + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES)]
}

function keyringStoreEmailCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden User Email", KEYRING_EMAIL)]
}

function keyringLookupEmailCommand() {
  return ["bash", "-c", cappedScript("secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_EMAIL) + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES)]
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
  return ["bash", "-c", cappedScript("secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_MASTER) + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES)]
}

function keyringClearMasterPasswordCommand() {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_MASTER]
}

// Presence check that never puts the secret on stdout, so the panel can show
// the right prompt without reading the password until a finger is verified.
function keyringHasMasterPasswordCommand() {
  var script = "if secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_MASTER) + " >/dev/null 2>&1; then echo yes; else echo no; fi"
  return ["bash", "-c", script]
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
    + " -salt -pass env:" + PIN_ENV + " -base64 -A"
    + " | secret-tool store --label=" + shellQuote("Bitwarden Master Password (PIN unlock)")
    + " service " + shellQuote(KEYRING_SERVICE) + " account " + shellQuote(KEYRING_PIN)
  return ["bash", "-c", script]
}

// Non-zero exit means the PIN was wrong (or the blob is gone). stdout carries
// the master password only on success.
function pinUnlockCommand() {
  var script = "secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_PIN) + " 2>/dev/null | head -c 8192"
    + " | openssl enc -d -aes-256-cbc -pbkdf2 -iter " + PIN_ITERATIONS
    + " -pass env:" + PIN_ENV + " -base64 -A | head -c " + MAX_TOKEN_BYTES
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearPinCommand() {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_PIN]
}

function keyringHasPinCommand() {
  var script = "if secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_PIN) + " >/dev/null 2>&1; then echo yes; else echo no; fi"
  return ["bash", "-c", script]
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
// there is not an error, so asking for all of them unconditionally costs
// nothing and is the only version that cannot be talked out of running.
var KEYRING_ALL_ACCOUNTS = [KEYRING_ACCOUNT, KEYRING_MASTER, KEYRING_PIN]

function keyringClearAllCommand() {
  var script = ""
  for (var i = 0; i < KEYRING_ALL_ACCOUNTS.length; i++) {
    script += "secret-tool clear service " + shellQuote(KEYRING_SERVICE)
      + " account " + shellQuote(KEYRING_ALL_ACCOUNTS[i]) + " >/dev/null 2>&1; "
  }
  // A missing entry exits non-zero, and that is the ordinary case rather than
  // a failure worth reporting, so the script always succeeds.
  script += "exit 0"
  return ["bash", "-c", script]
}

// Reports "yes" only when every piece is in place: the Omarchy PAM stack, a
// reader, and at least one enrolled finger. Mirrors the omarchy lock screen.
function fingerprintAvailableCommand() {
  var script = "if [[ -f /etc/pam.d/omarchy-lock-fingerprint ]] && command -v fprintd-list >/dev/null 2>&1 && fprintd-list \"$USER\" 2>/dev/null | grep -qi 'finger'; then echo yes; else echo no; fi"
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
  var arr = null
  try {
    arr = JSON.parse(raw)
  } catch (e) {
    return []
  }
  if (!Array.isArray(arr)) return []

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
  var arr = null
  try {
    arr = JSON.parse(raw)
  } catch (e) {
    return []
  }
  if (!Array.isArray(arr)) return []

  var out = []
  for (var i = 0; i < arr.length; i++) {
    var f = arr[i]
    if (!f || typeof f !== "object") continue
    // bw represents "no folder" as an entry with a null id on some versions.
    // The panel has its own control for that, so drop it here.
    if (!f.id) continue
    out.push({ id: String(f.id), name: String(f.name || "Folder") })
  }

  out.sort(function(a, b) {
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
  })
  return out
}

function folderName(folders, folderId) {
  if (!folderId || !Array.isArray(folders)) return ""
  for (var i = 0; i < folders.length; i++) {
    if (folders[i].id === folderId) return folders[i].name
  }
  return ""
}

var ITEM_TYPES = {
  "1": "login",
  "2": "secureNote",
  "3": "card",
  "4": "identity"
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
  var want = Math.floor(Number(declaredSize))
  if (!isFinite(want) || want < 0) want = 0
  if (want > maxBytes) want = maxBytes + 1

  var needKb = Math.ceil((want + ATTACHMENT_FREE_SLACK_BYTES) / 1024)

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
    "tmo=''",
    "if command -v timeout >/dev/null 2>&1; then tmo=\"timeout " + ATTACHMENT_TIMEOUT_SECS + "\"; fi",
    "rc=0",
    "( ulimit -f " + maxBlocks + "; exec $tmo bw get attachment --itemid " + shellQuote(itemId)
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
    // A filesystem with no hard links (FAT, exFAT, most phone mounts) has no
    // symlinks either, so on those there is nothing left to redirect a write
    // through and a plain no-clobber move is enough.
    "  elif [ ! -e \"$cand\" ] && [ ! -L \"$cand\" ] && mv -- \"$tmp\" \"$cand\" 2>/dev/null; then",
    "    out=\"$cand\"; break",
    "  fi",
    "  n=$((n+1))",
    "done",
    "if [ -z \"$out\" ]; then",
    "  echo 'Could not find a free name in the download folder.' >&2; exit 1",
    "fi",
    "printf %s \"$out\" | head -c 4096"
  ].join("\n")
  return ["bash", "-c", script]
}

function parseItems(raw) {
  var arr = null
  try {
    arr = JSON.parse(raw)
  } catch (e) {
    return []
  }
  if (!Array.isArray(arr)) return []

  var out = []
  for (var i = 0; i < arr.length; i++) {
    var it = arr[i]
    if (!it || typeof it !== "object") continue

    var login = it.login || {}
    var uris = []
    var rawUris = toList(login.uris)
    for (var j = 0; j < rawUris.length; j++) {
      var u = rawUris[j]
      if (u && u.uri) uris.push(String(u.uri))
    }

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
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
  })

  return out
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

  var login = it.login || {}
  var uris = []
  var rawUris = toList(login.uris)
  for (var j = 0; j < rawUris.length; j++) {
    var u = rawUris[j]
    if (u && u.uri) uris.push(String(u.uri))
  }

  var card = null
  if (it.card) {
    card = {
      cardholderName: String(it.card.cardholderName || ""),
      brand: String(it.card.brand || ""),
      number: String(it.card.number || ""),
      expMonth: String(it.card.expMonth || ""),
      expYear: String(it.card.expYear || ""),
      code: String(it.card.code || "")
    }
  }

  var identity = null
  if (it.identity) {
    identity = {
      title: String(it.identity.title || ""),
      firstName: String(it.identity.firstName || ""),
      lastName: String(it.identity.lastName || ""),
      email: String(it.identity.email || ""),
      phone: String(it.identity.phone || ""),
      address1: String(it.identity.address1 || ""),
      city: String(it.identity.city || ""),
      state: String(it.identity.state || ""),
      postalCode: String(it.identity.postalCode || ""),
      country: String(it.identity.country || "")
    }
  }

  var attachments = parseAttachments(it.attachments)

  var customFields = []
  var rawFields = toList(it.fields)
  for (var k = 0; k < rawFields.length; k++) {
    var f = rawFields[k]
    if (f && f.name) {
      customFields.push({
        name: String(f.name || ""),
        value: String(f.value || ""),
        type: Number(f.type || 0) // 0: text, 1: hidden, 2: boolean, 3: linked
      })
    }
  }

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
    card: card,
    identity: identity,
    fields: customFields,
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

function filterItems(items, query, category, selectedOrg, selectedFolder) {
  if (!Array.isArray(items)) return []
  var q = String(query || "").toLowerCase().trim()
  var cat = String(category || "all").toLowerCase()
  var org = String(selectedOrg || "all")
  var folder = String(selectedFolder || "all")

  var out = []
  for (var i = 0; i < items.length; i++) {
    var it = items[i]

    // Organization filter
    if (org === "personal") {
      if (it.organizationId) continue
    } else if (org !== "all") {
      if (it.organizationId !== org) continue
    }

    // Folder filter: "all" | "none" (unfiled) | folder id
    if (folder === "none") {
      if (it.folderId) continue
    } else if (folder !== "all") {
      if (it.folderId !== folder) continue
    }

    // Category filter
    if (cat === "favorite") {
      if (!it.favorite) continue
    } else if (cat !== "all" && it.type !== cat) {
      continue
    }

    // Search query match
    if (q && !matchesQuery(it, q)) {
      continue
    }

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

function buildCreatePayload(typeCode, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds) {
  var payload = {
    type: Number(typeCode || 1),
    name: String(name || "Untitled").trim(),
    notes: String(notes || "").trim(),
    favorite: Boolean(favorite),
    organizationId: organizationId && organizationId !== "personal" && organizationId !== "all" ? String(organizationId) : null,
    folderId: folderId && folderId !== "all" && folderId !== "none" ? String(folderId) : null
  }

  // Only org-owned items carry collections, and such an item must be in at
  // least one -- Bitwarden rejects it otherwise. Omit the key entirely when
  // none were chosen rather than sending an empty array, which would change
  // what existing callers send.
  if (payload.organizationId && Array.isArray(collectionIds) && collectionIds.length) {
    payload.collectionIds = collectionIds.slice()
  }

  if (Number(typeCode) === 1) { // Login
    var uris = []
    if (uri && uri.trim()) {
      uris.push({ match: null, uri: uri.trim() })
    }
    payload.login = {
      username: String(username || "").trim(),
      password: String(password || "").trim(),
      totp: totp && totp.trim() ? totp.trim() : null,
      uris: uris
    }
  } else if (Number(typeCode) === 2) { // Secure Note
    payload.secureNote = { type: 0 }
  }

  return payload
}

function buildEditPayload(existingItem, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds) {
  var payload = existingItem && existingItem.rawObject ? JSON.parse(JSON.stringify(existingItem.rawObject)) : {}
  payload.name = String(name || "Untitled").trim()
  payload.notes = String(notes || "").trim()
  payload.favorite = Boolean(favorite)
  // Set *and* clear. Only assigning meant picking "My Vault" for an item that
  // belonged to an organization left it in the organization, so the form said
  // one thing and the vault kept another.
  if (organizationId && organizationId !== "personal" && organizationId !== "all") {
    payload.organizationId = String(organizationId)
  } else {
    payload.organizationId = null
  }
  // An explicit empty selection means "no folder", so this must be able to
  // clear an existing assignment, not only set one.
  payload.folderId = folderId && folderId !== "all" && folderId !== "none" ? String(folderId) : null

  if (payload.organizationId) {
    payload.collectionIds = Array.isArray(collectionIds) && collectionIds.length
      ? collectionIds.slice() : (payload.collectionIds || [])
  } else {
    delete payload.collectionIds
  }

  if (payload.type === 1 || !payload.type) {
    if (!payload.login) payload.login = {}
    payload.login.username = String(username || "").trim()
    payload.login.password = String(password || "").trim()
    payload.login.totp = totp && totp.trim() ? totp.trim() : null
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

function cleanWindowContext(windowData) {
  var w = getActiveWindowFromData(windowData)
  if (!w) return null

  var cls = String(w.class || w.initialClass || "").toLowerCase().trim().slice(0, MAX_TITLE_CHARS)
  var title = String(w.title || w.initialTitle || "").trim().slice(0, MAX_TITLE_CHARS)
  if (!cls && !title) return null

  var isBrowser = BROWSER_CLASS_RE.test(cls)
  var isTerminal = TERMINAL_CLASS_RE.test(cls)

  var cleanTitle = ""
  var detectedDomain = null
  var displayName = ""

  if (isBrowser) {
    cleanTitle = stripTitleNoise(title)
    detectedDomain = detectDomainInText(cleanTitle)
    displayName = detectedDomain ? detectedDomain.baseDomain : cleanTitle
  } else if (isTerminal) {
    // Only remote sessions are worth suggesting for; a local shell title
    // ("hostname: ~/dir") describes the machine, not a credential.
    var sshMatch = title.match(/(?:^|\s)(?:ssh|mosh|sftp)\s+(?:-\S+\s+)*(?:[a-zA-Z0-9_.-]+@)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)/i)
    if (sshMatch) {
      detectedDomain = parseHost(sshMatch[1])
      cleanTitle = sshMatch[1]
      displayName = "SSH: " + sshMatch[1]
    } else {
      return null
    }
  } else {
    // Native desktop app: the leading segment is the app, the rest is document state.
    var segs = splitSegments(stripTitleNoise(title))
    cleanTitle = segs.length > 0 ? segs[0] : ""
    displayName = cleanTitle || cls
  }

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
    isBrowser: isBrowser,
    isTerminal: isTerminal
  }
}

// Score one vault item against the active window. 0 means no match; the bands
// are deliberately spread so a real domain hit always outranks a word hit.
function matchItem(item, ctx) {
  if (!ctx || !item) return 0
  if (ctx.isTerminal && !ctx.detectedDomain) return 0

  var score = 0
  var domains = itemDomains(item)
  var nameSquashed = squash(item.name)
  var nameTokens = extractTokens(item.name)
  var d, i

  // 1. Domain to domain. Only reachable when the title actually spelled a host.
  if (ctx.detectedDomain) {
    for (i = 0; i < domains.length; i++) {
      d = domains[i]
      if (d.host === ctx.detectedDomain.host) return 100
      if (d.baseDomain && d.baseDomain === ctx.detectedDomain.baseDomain) score = Math.max(score, 96)
    }
  }

  // 2. The item's registrable name appears in the page title.
  for (i = 0; i < domains.length; i++) {
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

  // 3. The item name matches a whole title segment.
  if (nameSquashed.length >= 3) {
    for (i = 0; i < ctx.segments.length; i++) {
      if (squash(ctx.segments[i]) === nameSquashed) {
        score = Math.max(score, 92)
        break
      }
    }
    if (nameSquashed.length >= 5 && ctx.squashedTitle.indexOf(nameSquashed) !== -1) {
      score = Math.max(score, 84)
    }
  }

  // 4. Shared significant words between the item name and the title.
  var overlap = 0
  for (i = 0; i < nameTokens.length; i++) {
    if (ctx.titleTokens.indexOf(nameTokens[i]) !== -1) overlap++
  }
  if (overlap > 0) {
    score = Math.max(score, 78 + Math.min(overlap, 3) * 2)
  }

  // 5. Native app: match the window class against the item.
  if (!ctx.isBrowser && !ctx.isTerminal && ctx.clsSquashed.length >= 3) {
    for (i = 0; i < domains.length; i++) {
      var r = domains[i].rootName
      if (r && r.length >= 3 && !GENERIC_LABELS[r] && r === ctx.clsSquashed) {
        score = Math.max(score, 92)
      }
    }
    if (nameSquashed.length >= 3 && (nameSquashed === ctx.clsSquashed
        || nameSquashed.indexOf(ctx.clsSquashed) !== -1
        || ctx.clsSquashed.indexOf(nameSquashed) !== -1)) {
      score = Math.max(score, 88)
    }
  }

  return score
}

var MATCH_THRESHOLD = 80
var MAX_SUGGESTIONS = 6

function findContextualMatches(items, windowData, associations) {
  var empty = { matches: [], context: null, learnedIds: {} }

  var ctx = cleanWindowContext(windowData)
  if (!ctx || !Array.isArray(items) || items.length === 0) return empty
  if (ctx.isTerminal && !ctx.detectedDomain) return empty
  if (!ctx.title && !ctx.detectedDomain && !ctx.clsSquashed) return empty

  // What you taught it comes first, and is never filtered out by the score
  // banding below -- an explicit choice outranks anything inferred.
  var byId = {}
  for (var b = 0; b < items.length; b++) {
    if (items[b] && items[b].id) byId[items[b].id] = items[b]
  }

  var learned = []
  var learnedIds = {}
  var learnedRanked = learnedMatchIds(associations, ctx)
  for (var l = 0; l < learnedRanked.length; l++) {
    var hit = byId[learnedRanked[l].itemId]
    if (hit) {
      learned.push(hit)
      learnedIds[hit.id] = true
    }
  }

  var scored = []
  for (var i = 0; i < items.length; i++) {
    var score = matchItem(items[i], ctx)
    if (score >= MATCH_THRESHOLD) {
      scored.push({ item: items[i], score: score, index: i })
    }
  }
  if (scored.length === 0 && learned.length === 0) return empty
  if (scored.length === 0) {
    return { matches: learned.slice(0, MAX_SUGGESTIONS), context: ctx, learnedIds: learnedIds }
  }

  scored.sort(function(a, b) {
    if (b.score !== a.score) return b.score - a.score
    if (a.item.favorite !== b.item.favorite) return a.item.favorite ? -1 : 1
    return a.index - b.index
  })

  // Keep only the strongest band. A confirmed domain hit discards everything
  // weaker (so a second account on the same site survives, but unrelated items
  // that merely share a word do not).
  var best = scored[0].score
  var cutoff = best >= 96 ? 96 : Math.max(MATCH_THRESHOLD, best - 8)

  var matches = learned.slice()
  for (var m = 0; m < scored.length && matches.length < MAX_SUGGESTIONS; m++) {
    if (scored[m].score >= cutoff && !learnedIds[scored[m].item.id]) {
      matches.push(scored[m].item)
    }
  }

  return { matches: matches.slice(0, MAX_SUGGESTIONS), context: ctx, learnedIds: learnedIds }
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
var ASSOC_FILE = "${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli/associations.json"

function associationsEnvVar() {
  return ASSOC_ENV
}

function associationsReadCommand() {
  return ["bash", "-c", "head -c " + MAX_ASSOC_BYTES + " \"" + ASSOC_FILE + "\" 2>/dev/null || echo '{}'"]
}

// Written through the environment for the same reason the keyring stores are:
// Process.write() cannot deliver EOF, so a shell supplies the payload instead.
function associationsWriteCommand() {
  var script = "d=\"$(dirname \"" + ASSOC_FILE + "\")\"; mkdir -p \"$d\" && chmod 700 \"$d\" && "
    + "umask 077 && printf '%s' \"$" + ASSOC_ENV + "\" > \"" + ASSOC_FILE + "\""
  return ["bash", "-c", script]
}

// Logging out has to take this with it. The store is a list of the domains,
// app names and title words the user has credentials for, each stamped with
// when it was last used -- a browsing-shaped record of the account, in the
// clear, under an account that is no longer signed in. The keyring entries
// are already cleared for exactly that reason; this file was the one piece of
// the account's data left behind, and it has no expiry of its own.
//
// The directory stays: it is created 700 on the next write, and removing it
// would race a write already in flight.
function associationsClearCommand() {
  return ["bash", "-c", "rm -f -- \"" + ASSOC_FILE + "\" 2>/dev/null; exit 0"]
}

function emptyAssociations() {
  return { version: ASSOC_VERSION, keys: {} }
}

function parseAssociations(raw) {
  var parsed = null
  try {
    parsed = JSON.parse(String(raw || "").trim() || "{}")
  } catch (e) {
    return emptyAssociations()
  }
  if (!parsed || typeof parsed !== "object" || !parsed.keys || typeof parsed.keys !== "object") {
    return emptyAssociations()
  }
  return { version: Number(parsed.version || ASSOC_VERSION), keys: parsed.keys }
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
// Everything the plugin shells out to, checked in one process rather than one
// per tool. Each entry reports present/absent plus the package that provides
// it, so the wizard can offer an exact install command instead of advice.

var DEPENDENCIES = [
  {
    key: "bw", label: "Bitwarden CLI", binary: "bw", pkg: "bitwarden-cli", aur: false,
    required: true,
    purpose: "Reads and writes your vault. Nothing works without it."
  },
  {
    key: "wlcopy", label: "wl-clipboard", binary: "wl-copy", pkg: "wl-clipboard", aur: false,
    required: true,
    purpose: "Copies passwords and TOTP codes to the Wayland clipboard."
  },
  {
    key: "hyprctl", label: "Hyprland", binary: "hyprctl", pkg: "hyprland", aur: false,
    required: false,
    purpose: "Identifies the active window so the right login can be suggested."
  },
  {
    key: "secrettool", label: "libsecret", binary: "secret-tool", pkg: "libsecret", aur: false,
    required: false,
    purpose: "Stores the session in the OS keyring, and the master password when fingerprint unlock is on."
  },
  {
    key: "fprintd", label: "fprintd", binary: "fprintd-list", pkg: "fprintd", aur: false,
    required: false,
    purpose: "Fingerprint unlock. Also needs an enrolled finger via 'omarchy setup security fingerprint'."
  }
]

// One shell round trip: `key=1` or `key=0` per line, plus the fingerprint
// enrolment state, which needs more than a binary being on PATH.
function dependencyCheckCommand() {
  var parts = []
  for (var i = 0; i < DEPENDENCIES.length; i++) {
    var d = DEPENDENCIES[i]
    parts.push("if command -v " + shellQuote(d.binary) + " >/dev/null 2>&1; then echo "
      + shellQuote(d.key + "=1") + "; else echo " + shellQuote(d.key + "=0") + "; fi")
  }
  parts.push("if [ -f /etc/pam.d/omarchy-lock-fingerprint ] && command -v fprintd-list >/dev/null 2>&1 "
    + "&& fprintd-list \"$USER\" 2>/dev/null | grep -qi finger; then echo fingerprint_ready=1; else echo fingerprint_ready=0; fi")
  parts.push("if command -v omarchy >/dev/null 2>&1; then echo omarchy=1; else echo omarchy=0; fi")
  return ["bash", "-c", cappedScript("{ " + parts.join("; ") + "; } | head -c 4096")]
}

function parseDependencies(raw) {
  var found = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var kv = lines[i].trim().split("=")
    if (kv.length === 2) found[kv[0]] = kv[1] === "1"
  }

  var out = []
  for (var d = 0; d < DEPENDENCIES.length; d++) {
    var dep = DEPENDENCIES[d]
    out.push({
      key: dep.key,
      label: dep.label,
      binary: dep.binary,
      pkg: dep.pkg,
      required: dep.required,
      purpose: dep.purpose,
      installed: Boolean(found[dep.key]),
      // fprintd on PATH is not the same as a usable reader with an enrolled finger.
      ready: dep.key === "fprintd" ? Boolean(found["fingerprint_ready"]) : Boolean(found[dep.key])
    })
  }
  return { items: out, hasOmarchy: Boolean(found["omarchy"]) }
}

function missingRequired(deps) {
  var missing = []
  if (!deps || !deps.items) return missing
  for (var i = 0; i < deps.items.length; i++) {
    if (deps.items[i].required && !deps.items[i].installed) missing.push(deps.items[i])
  }
  return missing
}

// Installs run in a terminal: they need a password prompt and the user should
// see what is being installed rather than have it happen silently.
function installPackagesCommand(pkgs) {
  if (!pkgs || pkgs.length === 0) return null
  var list = []
  for (var i = 0; i < pkgs.length; i++) list.push(shellQuote(pkgs[i]))
  var inner = "omarchy pkg add " + list.join(" ")
    + "; echo; read -p 'Done. Press enter to close...'"
  return ["bash", "-c", "omarchy launch terminal -e bash -c " + shellQuote(inner)]
}

function fingerprintSetupCommand() {
  var inner = "omarchy setup security fingerprint; echo; read -p 'Done. Press enter to close...'"
  return ["bash", "-c", "omarchy launch terminal -e bash -c " + shellQuote(inner)]
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
  { key: "lockOnScreenLock", group: "security", type: "bool", label: "Lock when the screen locks",
    description: "Lock as soon as the screen locks, rather than waiting out the auto-lock." },
  { key: "lockOnSuspend", group: "security", type: "bool", label: "Lock when the machine suspends",
    description: "Lock before sleep, so no session key is left in the suspended machine's memory." },
  { key: "rememberSession", group: "security", type: "bool", label: "Remember session in keyring",
    description: "Keep the unlocked session in the OS keyring so it survives a shell restart." },
  { key: "fingerprintUnlock", group: "security", type: "bool", label: "Unlock with fingerprint",
    requires: "fprintd", action: "fingerprint",
    description: "Store the master password in the OS keyring, gated behind a fingerprint." },
  { key: "pinUnlock", group: "security", type: "bool", label: "Unlock with PIN",
    action: "pin",
    description: "Encrypt the master password with a key derived from a PIN. Use 6 digits or more; 4 is the floor and is flagged as weak." },

  { key: "closeOnCopy", group: "behavior", type: "bool", label: "Close panel on copy",
    description: "Return focus to your app as soon as Enter copies a credential." },
  { key: "autoCopyTotpSec", group: "behavior", type: "int", label: "Auto-copy TOTP after", unit: "seconds",
    min: 0, max: 30, step: 1, zeroLabel: "Off", defaultValue: 3,
    description: "Replace the clipboard with the 2FA code this long after the password." },

  { key: "suggestOnOpen", group: "suggestions", type: "bool", label: "Suggest for active window",
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

function settingWriteCommand(key, value, type) {
  var raw
  if (type === "bool") raw = value ? "true" : "false"
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

function generateServeHost() { return GENERATE_HOST }
function generateServePort() { return GENERATE_PORT }

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
  var script = "curl -s -S --max-time " + timeoutSecs + " --connect-timeout " + timeoutSecs
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

// Rough strength read for the meter. Deliberately simple: it describes the
// search space the options imply, not the specific string produced.
function generatorStrength(opts) {
  var o = normalizeGeneratorOptions(opts)
  var bits

  if (o.type === "passphrase") {
    // EFF-style wordlist, ~12.9 bits per word.
    bits = o.words * 12.9 + (o.includeNumber ? 3.3 : 0)
  } else {
    var pool = 0
    if (o.uppercase) pool += 26
    if (o.lowercase) pool += 26
    if (o.numbers) pool += 10
    if (o.special) pool += 26
    if (o.ambiguous) pool -= 6
    bits = o.length * (Math.log(Math.max(pool, 2)) / Math.log(2))
  }

  var label = "Weak"
  if (bits >= 120) label = "Excellent"
  else if (bits >= 90) label = "Strong"
  else if (bits >= 60) label = "Good"
  else if (bits >= 40) label = "Fair"

  return { bits: Math.round(bits), label: label, fraction: Math.max(0, Math.min(1, bits / 128)) }
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

function listSendsCommand(session) {
  return buildCappedCommand(["send", "list"], MAX_SENDS_BYTES)
}

function deleteSendCommand(sendId, session) {
  return buildCappedCommand(["send", "delete", "--", String(sendId)], MAX_MISC_BYTES)
}

function removeSendPasswordCommand(sendId, session) {
  return buildCappedCommand(["send", "remove-password", "--", String(sendId)], MAX_MISC_BYTES)
}

// The payload travels in the environment, not argv. Both the flag form's
// --password and an inlined `printf %s '<json>'` would land the Send password
// in /proc/<pid>/cmdline, which other users can read.
var SEND_ENV = "QSBW_SEND"

function sendEnvVar() {
  return SEND_ENV
}

function createSendCommand(session) {
  var script = "printf '%s' \"$" + SEND_ENV + "\" | bw encode | bw send create | head -c " + MAX_MISC_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// A file Send cannot go through stdin JSON -- bw wants the path on the command
// line -- but a path is not a secret, unlike a password.
function createFileSendCommand(filePath, name, deleteInDays, maxAccessCount, session) {
  var args = ["send", "--file", String(filePath)]
  if (name) args = args.concat(["--name", String(name)])
  args = args.concat(["-d", String(deleteInDays || 7)])
  if (maxAccessCount) args = args.concat(["-a", String(maxAccessCount)])
  args.push("--fullObject")
  return buildCappedCommand(args, MAX_MISC_BYTES, MAX_STDERR_BYTES)
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
  var arr = null
  try {
    arr = JSON.parse(raw)
  } catch (e) {
    return []
  }
  if (!Array.isArray(arr)) return []

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
