// BitwardenModel.js -- pure helpers for the plugin: CLI command builders,
// output parsers, filtering and form builders.

.pragma library

const KEYRING_SERVICE = "qs-bitwarden-cli"
const KEYRING_ACCOUNT = "session"
const KEYRING_MASTER = "master_password"
const KEYRING_FIDO = "fido_password"

// `secret-tool store` reads stdin to EOF and Process.write() cannot close
// stdin, so secrets reach it through this env var, piped in by a shell. Never
// put a secret in argv: /proc/<pid>/cmdline is world-readable.
const KEYRING_SECRET_ENV = "QSBW_SECRET"
const KEYRING_PIN = "pin_blob"
const PIN_ENV = "QSBW_PIN"

// PBKDF2 rounds of the legacy PIN blob (AES-256-CBC, no MAC). Read only, to
// migrate it into the envelope on the next PIN unlock.
const PIN_ITERATIONS = 600000

// Each PIN guess costs Argon2id at 256 MiB x 4 passes (~0.75 s) on this
// machine, as this user. Six digits is recommended; four is allowed with a
// warning that names the cost.
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

// A capped `secret-tool lookup` of one entry.
function keyringReadScript(account) {
  return "secret-tool lookup" + keyringAttributes(account) + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES
}

function keyringLookupEntryCommand(account) {
  // Strip only secret-tool's trailing newline; trim() would also eat
  // meaningful spaces in a password or client secret.
  var script = "stored=$(" + keyringReadScript(account) + "); "
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

// -------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------
//
// `bw` holds one account per data directory, so each account the panel knows
// lives in a slot: "default" is bw's own directory (the account a terminal
// `bw` sees, and the only one before multi-account), any other slot a private
// directory named by 16 hex digits, given to bw in BITWARDENCLI_APPDATA_DIR.
// A slot's keyring entries are the legacy names with "@<slot>" appended, so
// the default slot keeps its entries as they are, and no lookup for one slot
// can match another's (secret-tool matches attributes exactly).
var DEFAULT_ACCOUNT_SLOT = "default"
var ACCOUNT_SLOT_RE = /^[0-9a-f]{16}$/
var APPDATA_ENV = "BITWARDENCLI_APPDATA_DIR"
var ACCOUNTS_ENV = "QSBW_ACCOUNTS"
var ACCOUNTS_VERSION = 1
var MAX_ACCOUNTS = 10
var MAX_ACCOUNTS_BYTES = 64 * 1024
var ACCOUNTS_SUBDIR = "qs-bitwarden-cli/accounts"
var ACCOUNTS_DIR = "${XDG_DATA_HOME:-$HOME/.local/share}/" + ACCOUNTS_SUBDIR

function defaultAccountSlot() { return DEFAULT_ACCOUNT_SLOT }
function appDataEnvVar() { return APPDATA_ENV }
function accountsEnvVar() { return ACCOUNTS_ENV }
function maxAccounts() { return MAX_ACCOUNTS }

function isAccountSlot(slot) {
  return slot === DEFAULT_ACCOUNT_SLOT || ACCOUNT_SLOT_RE.test(String(slot))
}

// Anything that is not a slot means the default one, which is what every
// caller got before slots existed.
function accountSlot(slot) {
  return typeof slot === "string" && isAccountSlot(slot) ? slot : DEFAULT_ACCOUNT_SLOT
}

function keyringEntryName(base, slot) {
  var s = accountSlot(slot)
  return s === DEFAULT_ACCOUNT_SLOT ? base : base + "@" + s
}

// The slot's bw data directory, or "" for the default slot (bw's own). Built
// from the caller's environment, since a Process environment is not a shell.
function accountAppDataDir(slot, xdgDataHome, home) {
  var s = accountSlot(slot)
  if (s === DEFAULT_ACCOUNT_SLOT) return ""
  var base = String(xdgDataHome || "")
  if (!base || base.charAt(0) !== "/") {
    var h = String(home || "")
    if (!h || h.charAt(0) !== "/") return ""
    base = h.replace(/\/+$/, "") + "/.local/share"
  }
  return base.replace(/\/+$/, "") + "/" + ACCOUNTS_SUBDIR + "/" + s
}

// For scripts not started with the vault's environment (a terminal login):
// the same directory, derived in the shell.
function accountAppDataExport(slot) {
  var s = accountSlot(slot)
  if (s === DEFAULT_ACCOUNT_SLOT) return ""
  return "export " + APPDATA_ENV + "=\"" + ACCOUNTS_DIR + "/" + s + "\"; "
}

// bw creates its data directory with its default umask; create a slot's
// first, private, and refuse a symlink in its place.
function appDataDirPrelude() {
  return "if [ -n \"${" + APPDATA_ENV + ":-}\" ]; then "
    + "__acct_parent=\"$(dirname -- \"$" + APPDATA_ENV + "\")\"; "
    + "if [ -L \"$__acct_parent\" ]; then exit 1; fi; "
    + "(umask 077 && mkdir -p -- \"$__acct_parent\") || exit 1; "
    + "__acct_dir=\"$" + APPDATA_ENV + "\"; " + privateDirScript("__acct_dir")
    + "fi; "
}

// A fresh slot not already in `taken`. Not a secret, so Math.random is enough.
function newAccountSlot(taken) {
  var used = {}
  for (var i = 0; taken && i < taken.length; i++) used[taken[i]] = true
  for (var attempt = 0; attempt < 32; attempt++) {
    var slot = ""
    while (slot.length < 16) slot += Math.floor(Math.random() * 16).toString(16)
    if (!used[slot]) return slot
  }
  return ""
}

function emptyAccountRegistry() {
  return { version: ACCOUNTS_VERSION, active: DEFAULT_ACCOUNT_SLOT, accounts: [] }
}

function cleanAccountText(value, max) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/[\x00-\x1f\x7f]/g, "").slice(0, max)
}

// The registry file: which slots hold which account, and the active one.
// Nothing in it is secret; anything malformed is dropped rather than trusted.
function parseAccountRegistry(raw) {
  var parsed = null
  try { parsed = JSON.parse(String(raw || "")) } catch (e) { parsed = null }
  var out = emptyAccountRegistry()
  if (!parsed || typeof parsed !== "object" || Number(parsed.version) !== ACCOUNTS_VERSION) return out
  var seen = {}
  var list = Array.isArray(parsed.accounts) ? parsed.accounts : []
  for (var i = 0; i < list.length && out.accounts.length < MAX_ACCOUNTS; i++) {
    var a = list[i]
    if (!a || typeof a !== "object" || typeof a.slot !== "string" || !isAccountSlot(a.slot)) continue
    if (seen[a.slot]) continue
    seen[a.slot] = true
    out.accounts.push({
      slot: a.slot,
      email: cleanAccountText(a.email, 320),
      userId: cleanAccountText(a.userId, 128),
      server: cleanAccountText(a.server, 512),
      lastUsed: Math.max(0, Math.floor(Number(a.lastUsed)) || 0)
    })
  }
  if (typeof parsed.active === "string" && isAccountSlot(parsed.active)) out.active = parsed.active
  return out
}

function serializeAccountRegistry(registry) {
  var r = registry || emptyAccountRegistry()
  return JSON.stringify({ version: ACCOUNTS_VERSION, active: accountSlot(r.active), accounts: r.accounts || [] })
}

function copyAccountRegistry(registry) {
  var r = registry || emptyAccountRegistry()
  var accounts = []
  for (var i = 0; r.accounts && i < r.accounts.length; i++) {
    var a = r.accounts[i]
    accounts.push({ slot: a.slot, email: a.email, userId: a.userId, server: a.server, lastUsed: a.lastUsed })
  }
  return { version: ACCOUNTS_VERSION, active: accountSlot(r.active), accounts: accounts }
}

function registryAccount(registry, slot) {
  var list = registry && registry.accounts ? registry.accounts : []
  for (var i = 0; i < list.length; i++) if (list[i].slot === slot) return list[i]
  return null
}

function registryHasAccount(registry, slot) {
  return registryAccount(registry, slot) !== null
}

// Records what `bw status` says the slot holds. Another slot already holding
// the same account (same user on the same server) is retired: two sign-ins of
// one account would only disagree. Returns { registry, retired: [slots] }.
function registryNoteAccount(registry, slot, info, now) {
  var r = copyAccountRegistry(registry)
  var s = accountSlot(slot)
  var userId = cleanAccountText(info && info.userId, 128)
  var server = cleanAccountText(info && info.server, 512)
  var retired = []
  var kept = []
  for (var i = 0; i < r.accounts.length; i++) {
    var a = r.accounts[i]
    if (a.slot !== s && userId && a.userId === userId && a.server === server) retired.push(a.slot)
    else kept.push(a)
  }
  r.accounts = kept
  var entry = registryAccount(r, s)
  if (!entry) {
    if (r.accounts.length >= MAX_ACCOUNTS) return { registry: registry, retired: [], full: true }
    entry = { slot: s, email: "", userId: "", server: "", lastUsed: 0 }
    r.accounts.push(entry)
  }
  entry.email = cleanAccountText(info && info.email, 320) || entry.email
  entry.userId = userId || entry.userId
  entry.server = server
  entry.lastUsed = Math.max(0, Math.floor(Number(now)) || 0)
  r.active = s
  return { registry: r, retired: retired, full: false }
}

function registryRemoveAccount(registry, slot) {
  var r = copyAccountRegistry(registry)
  r.accounts = r.accounts.filter(function(a) { return a.slot !== slot })
  return r
}

function registrySetActive(registry, slot, now) {
  var r = copyAccountRegistry(registry)
  r.active = accountSlot(slot)
  var entry = registryAccount(r, r.active)
  if (entry && now !== undefined) entry.lastUsed = Math.max(0, Math.floor(Number(now)) || 0)
  return r
}

// Where a new sign-in goes: the default slot while nothing holds it, so a
// single account always lives where a terminal `bw` finds it.
function slotForNewAccount(registry) {
  if (!registryHasAccount(registry, DEFAULT_ACCOUNT_SLOT)) return DEFAULT_ACCOUNT_SLOT
  var taken = (registry.accounts || []).map(function(a) { return a.slot })
  return newAccountSlot(taken)
}

// The account to show after `leaving` goes away: the most recently used
// other one, or "" if none.
function registryNextAccount(registry, leaving) {
  var best = null
  var list = registry && registry.accounts ? registry.accounts : []
  for (var i = 0; i < list.length; i++) {
    if (list[i].slot === leaving) continue
    if (!best || list[i].lastUsed > best.lastUsed) best = list[i]
  }
  return best ? best.slot : ""
}

function accountServerLabel(server) {
  var s = String(server || "").trim().replace(/\/+$/, "")
  if (!s || s === BITWARDEN_US_SERVER || s === "https://bitwarden.com") return ""
  if (s === BITWARDEN_EU_SERVER || s === "https://bitwarden.eu") return "EU"
  return s.replace(/^https?:\/\//i, "")
}

// Rows for the account picker, sorted by email; nothing secret.
function accountRows(registry, activeSlot) {
  var list = registry && registry.accounts ? registry.accounts.slice() : []
  list.sort(function(a, b) {
    var x = String(a.email).toLowerCase()
    var y = String(b.email).toLowerCase()
    return x < y ? -1 : (x > y ? 1 : (a.slot < b.slot ? -1 : 1))
  })
  return list.map(function(a) {
    var server = accountServerLabel(a.server)
    return {
      slot: a.slot,
      email: a.email || "Account",
      server: server,
      label: (a.email || "Account") + (server ? " (" + server + ")" : ""),
      active: a.slot === activeSlot
    }
  })
}

// A slot that another sign-in replaced: its keyring entries and learned
// suggestions too (a logout clears those itself first).
function accountSlotRetireCommand(slot) {
  var s = accountSlot(slot)
  var script = nestedScript(keyringClearAllCommand(s)) + "; "
    + nestedScript(associationsClearCommand(s)) + "; "
    + nestedScript(accountSlotRemoveCommand(s))
  return ["bash", "-c", script]
}

function accountRegistryReadCommand() {
  var script = "d=\"" + ACCOUNTS_DIR + "\"; f=\"$d/registry.json\"; "
    + "if [ -d \"$d\" ] && [ ! -L \"$d\" ] && [ -f \"$f\" ] && [ ! -L \"$f\" ]; then "
    + "head -c " + MAX_ACCOUNTS_BYTES + " \"$f\" 2>/dev/null || printf '{}'; else printf '{}'; fi"
  return ["bash", "-c", script]
}

// Payload in the environment; written to a private temp file and renamed,
// like the learned associations.
function accountRegistryWriteCommand() {
  var script = "set -e; __parent=\"$(dirname -- \"" + ACCOUNTS_DIR + "\")\"; "
    + "[ ! -L \"$__parent\" ]; (umask 077 && mkdir -p -- \"$__parent\"); "
    + "d=\"" + ACCOUNTS_DIR + "\"; " + privateDirScript("d")
    + "umask 077; tmp=$(mktemp -- \"$d/.registry.XXXXXXXX\"); "
    + "trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; "
    + "printf '%s' \"$" + ACCOUNTS_ENV + "\" > \"$tmp\"; chmod 600 \"$tmp\"; "
    + "mv -fT -- \"$tmp\" \"$d/registry.json\"; trap - EXIT HUP INT TERM"
  return ["bash", "-c", script]
}

// Signs a slot out of bw and deletes its data directory. The default slot's
// directory is bw's own and is never deleted, only signed out of.
function accountSlotRemoveCommand(slot) {
  var s = accountSlot(slot)
  var script = accountAppDataExport(s) + "bw logout >/dev/null 2>&1; "
  if (s !== DEFAULT_ACCOUNT_SLOT) {
    script += "d=\"" + ACCOUNTS_DIR + "\"; "
      + "if [ -d \"$d\" ] && [ ! -L \"$d\" ] && [ -e \"$d/" + s + "\" ]; then rm -rf -- \"$d/" + s + "\"; fi; "
  }
  script += "exit 0"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Secrets never go in argv. The session token travels in BW_SESSION.
const SESSION_ENV = "BW_SESSION"

// bw reads these natively (--passwordenv, `login --apikey`), so the master
// password and API key reach no argv. Values are set by authEnv() in Service.qml.
const PASSWORD_ENV = "BW_PASSWORD"
const CLIENT_ID_ENV = "BW_CLIENTID"
const CLIENT_SECRET_ENV = "BW_CLIENTSECRET"

// bw has no env option for the two-step code, so it lands in bw's argv via
// --code. The env var keeps it out of the wrapping shell's longer-lived argv;
// the code is single-use and short-lived.
const TWOFACTOR_CODE_ENV = "QSBW_CODE"

// Auth commands run non-interactively so a hidden prompt fails fast. The
// exception is deviceVerificationLoginCommand().
const NOINTERACTION_ENV = "BW_NOINTERACTION"
// First bw release Bitwarden documents SSH keys for.
const SSH_CLI_MIN_VERSION = "2025.1.2"
// Earlier bw releases throw on SSH items with missing public fields, failing
// the whole `bw list items`; the panel names this release as the fix.
const SSH_MALFORMED_ITEM_FIX_VERSION = "2026.8.0"

// The new-device verification code: piped to bw by printf, so it reaches no argv.
const DEVICE_CODE_ENV = "QSBW_DEVICE_CODE"

function sessionEnvVar() {
  return SESSION_ENV
}

// NODE_OPTIONS for every `bw`: the user's own, plus bw-fast-exit.js from the
// plugin directory, which saves the ~2 s bw idles after answering. Node reads
// NODE_OPTIONS with double quotes and backslash escapes. No plugin directory
// (not a file URL) leaves the options as they were.
var BW_FAST_EXIT_FILE = "bw-fast-exit.js"

function bwNodeOptions(pluginDir, existing) {
  var base = String(existing || "").trim()
  var dir = String(pluginDir || "").replace(/\/+$/, "")
  if (dir === "") return base
  var file = dir + "/" + BW_FAST_EXIT_FILE
  var option = "--require \"" + file.replace(/(["\\])/g, "\\$1") + "\""
  return base ? base + " " + option : option
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

function deviceCodeEnvVar() {
  return DEVICE_CODE_ENV
}

// Producer-side (`head -c`) caps on every stream the shell collects.
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

// Attachments stream to disk: cap the file size, the transfer time, and keep
// free space in reserve.
var MAX_ATTACHMENT_BYTES = 512 * 1024 * 1024        // 512 MB: Bitwarden's own per-file ceiling
var ATTACHMENT_TIMEOUT_SECS = 900                   // 15 min: a stalled transfer must not hold the queue
var ATTACHMENT_FREE_SLACK_BYTES = 64 * 1024 * 1024  // 64 MB: never fill the disk to the last byte

// `pipefail` keeps bw's exit status through a `head -c` cap, except 141: the
// SIGPIPE the cap sends when it truncates a healthy stream.
function cappedScript(script, maxStderrBytes) {
  var out = ""
  if (maxStderrBytes) {
    out += "exec 2> >(head -c " + Number(maxStderrBytes) + " >&2); "
  }
  out += "set -o pipefail; " + script
  // `case`, not `[ ] &&`, which fails on no match and would trip `set -e`.
  out += "\n__rc=$?\ncase \"$__rc\" in 141) __rc=0 ;; esac\nexit \"$__rc\""
  return out
}

// Arguments are shell-quoted. Callers put `--` before server-chosen ids so an
// id shaped like a flag stays positional; our own flags go before it.
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

// A bw session key is base64 (88 chars for bw's 64 bytes). Anything not
// shaped like one yields "", which callers treat as failure.
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
// Nothing cancels a running `bw`, so a read started before a lock can land
// afterwards and repopulate the panel. Every reader records the vault
// generation it started under; the generation advances on lock, logout and
// unlock, and a result from an older generation is discarded.
function vaultReadIsStale(startedEpoch, currentEpoch, hasSession) {
  if (!hasSession) return true
  return Number(startedEpoch) !== Number(currentEpoch)
}

// -------------------------------------------------------------------------
// Collector scrubbing
// -------------------------------------------------------------------------
//
// A StdioCollector keeps its last output until its process runs again; there
// is no clear(). So after a lock, secrets (session keys, passwords, item
// lists, TOTPs) would stay in the shell's memory. A buffer is emptied by
// re-running its process with a command that prints nothing, and that
// command doubles as the marker that an empty result is a scrub, not an answer.
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

// Retry interval for a process still running at lock time. No retry limit:
// giving up would leave its final output resident.
var SCRUB_RETRY_MS = 1000

function scrubRetryMs() { return SCRUB_RETRY_MS }

// One pass over the scrub queue: `start` is scrubbed now, `waiting` is checked
// again next tick, anything else is done. Running processes are left alone
// (their read is still wanted); already-scrubbed ones need nothing.
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

// Drop a process from the queue once its scrub finished. Checking `command`
// later cannot prove that, since it describes the newest run.
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
// A password FIFO lets bw start up while the user types: bw waits on it via
// --passwordfile and the password is written only on submit. FIFOs live in a
// private dir under XDG_RUNTIME_DIR, one per auth flow, and are removed on
// every exit path.
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

// Creates the directory in shell variable `name` mode 0700, or accepts it if
// it is a real directory (not a symlink); exits 1 otherwise.
function privateDirScript(name) {
  var d = "\"$" + name + "\""
  return "if [ -e " + d + " ]; then [ -d " + d + " ] && [ ! -L " + d + " ] || exit 1; "
    + "else (umask 077 && mkdir -p -- " + d + ") || exit 1; fi; chmod 700 -- " + d + " || exit 1; "
}

function authFifoPrelude(channel) {
  var fifoName = authPasswordFifoName(channel)
  if (!fifoName) return ""

  // Refuse a symlinked directory so the FIFO cannot be redirected.
  var script = "test -n \"${XDG_RUNTIME_DIR:-}\" || exit 1; "
  script += "__auth_dir=\"$XDG_RUNTIME_DIR/" + RUNTIME_SUBDIR + "\"; "
  script += privateDirScript("__auth_dir")
  script += "__auth_fifo=\"$__auth_dir/" + fifoName + "\"; "
  script += "rm -f -- \"$__auth_fifo\"; "
  script += "mkfifo -m 600 -- \"$__auth_fifo\" || exit 1; "
  // QProcess kills only this wrapper, so bw runs in its own process group
  // that the cleanup trap can signal.
  script += supervisedProcessPrelude("rm -f -- \"$__auth_fifo\"")
  return script
}

// `prelude` runs first, outside the supervised job (appDataDirPrelude()).
function supervisedProcessCommand(command, prelude) {
  var script = (prelude || "") + supervisedProcessPrelude("")
  script += supervisedProcessRun(command)
  return ["bash", "-c", script]
}

function supervisedProcessRun(command) {
  // Clear the job id after a normal wait so the EXIT trap cannot signal a
  // reaped (and possibly reused) process group.
  var script = "set -m; (" + cappedScript(command, MAX_STDERR_BYTES) + ") & "
  script += "__auth_job=$!; wait \"$__auth_job\"; __auth_rc=$?; "
  script += "__auth_job=''; exit \"$__auth_rc\""
  return script
}

function supervisedAuthCommand(channel, command, prelude) {
  var script = (prelude || "") + authFifoPrelude(channel)
  // `set -m` gives bw its own process group; the interruptible `wait` lets the
  // signal traps run while bw blocks on the FIFO.
  script += supervisedProcessRun(command)
  return ["bash", "-c", script]
}

function unlockPrewarmCommand() {
  var command = "bw unlock --passwordfile \"$__auth_fifo\" --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("unlock", command)
}

// Every two-step method bw can act on, in bw's order. The CLI never offers
// Duo or WebAuthn, and bw cannot report which methods an account has, so a
// picker over these three is complete.
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

// --method is the only unquoted login argument, so only values from this
// table may reach it.
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

// Remembered two-step methods, keyed by account email.
var MAX_REMEMBERED_ACCOUNTS = 10

// Bitwarden compares login emails case-insensitively.
function twoFactorAccountKey(email) {
  return String(email || "").trim().toLowerCase()
}

// shell.json is unvalidated and the method goes into argv, so it is checked
// against the table on read; anything else is "not remembered" (-1).
function rememberedTwoFactorMethodFor(store, email) {
  var key = twoFactorAccountKey(email)
  if (!key || !store || typeof store !== "object") return -1
  var raw = store[key]
  // Number() alone reads null, "" and false as 0 (Authenticator).
  var m = (typeof raw === "number" || (typeof raw === "string" && String(raw).trim() !== ""))
    ? Math.floor(Number(raw))
    : NaN
  return isFinite(m) && isTwoFactorMethod(m) ? m : -1
}

// Rebuilt, not mutated, so unknown or invalid entries are dropped; capped at
// MAX_REMEMBERED_ACCOUNTS.
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

// `bw config server <url> && `, or "" for the default server.
function serverConfigPrefix(serverUrl) {
  var url = String(serverUrl || "").trim()
  return url ? "bw config server " + shellQuote(url) + " >/dev/null 2>&1 && " : ""
}

function emailLoginPrewarmCommand(email, hasCode, serverUrl, method) {
  var command = serverConfigPrefix(serverUrl)
  command += "bw login " + shellQuote(email) + " --passwordfile \"$__auth_fifo\""
  if (isTwoFactorMethod(method)) command += " --method " + String(method)
  if (hasCode) command += " --code \"$" + TWOFACTOR_CODE_ENV + "\""
  command += " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("login", command, appDataDirPrelude())
}

// Bounds the one interactive login so one that never prompts cannot hold the
// master password until the panel closes.
var DEVICE_VERIFICATION_TIMEOUT_S = 60

// The only login with bw's prompts enabled. New-device verification reads its
// code from an inquirer prompt and no flag, so the code is piped to stdin
// (from the env, so it reaches no argv). A pipe still ends: an unexpected
// second prompt fails with ERR_USE_AFTER_CLOSE instead of hanging, and
// `timeout` covers a bw that never prompts.
function deviceVerificationLoginCommand(email, serverUrl, method) {
  var command = serverConfigPrefix(serverUrl)
  command += "printf '%s\\n' \"$" + DEVICE_CODE_ENV + "\" | "
  command += "timeout " + DEVICE_VERIFICATION_TIMEOUT_S + "s bw login " + shellQuote(email)
    + " --passwordfile \"$__auth_fifo\""
  if (isTwoFactorMethod(method)) command += " --method " + String(method)
  command += " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedAuthCommand("login", command, appDataDirPrelude())
}

// stderr then stdout, lower-cased, for matching bw's messages.
function combinedOutput(stdoutText, stderrText) {
  return (String(stderrText || "") + "\n" + String(stdoutText || "")).toLowerCase()
}

// inquirer's error for input that is not coming: bw hit an unexpected prompt.
function loginPromptRanOutOfInput(stdoutText, stderrText) {
  return /err_use_after_close|readline was closed/.test(combinedOutput(stdoutText, stderrText))
}

// Interactive bw echoes its prompt and keystrokes on stderr. Strip escapes,
// prompt lines and any line containing the code, leaving bw's own message.
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
  // One line of context at most (a node crash prints a stack trace).
  return kept.join(" ").slice(0, 300)
}

// The shape of a login attempt for the journal, never its content: stdout is
// counted, stderr is sanitised.
function loginDiagnostic(stdoutText, stderrText, exitCode, branch) {
  return "exit=" + String(exitCode)
    + " stdout=" + String(stdoutText || "").length + "b"
    + " branch=" + String(branch || "?")
    + " stderr=" + JSON.stringify(sanitizeInteractiveStderr(stderrText, "").slice(0, 200))
}

function loginCodeIsRequiredChallenge(stdoutText, stderrText) {
  return /(?:^|[\r\n])\s*code\s+is\s+required[.!]?\s*(?=$|[\r\n])/.test(combinedOutput(stdoutText, stderrText))
}

function loginNeedsSecondFactor(stdoutText, stderrText) {
  return /(?:two[ _-]?(?:step|factor)|2fa|verification[ _-]?code)/.test(combinedOutput(stdoutText, stderrText))
    || loginCodeIsRequiredChallenge(stdoutText, stderrText)
}

// New-device verification, which --code cannot answer. Its first reply is the
// same "Code is required." as a two-step challenge; only a retry that sent a
// code and still gets it tells them apart (a rejected code says "invalid").
function loginNeedsDeviceVerification(stdoutText, stderrText, codeWasSent) {
  if (!codeWasSent) return false
  return loginCodeIsRequiredChallenge(stdoutText, stderrText)
}

// bw's reply when several providers are usable and none was chosen: a menu it
// cannot show. The panel asks the user for --method instead of guessing.
function loginNeedsMethodChoice(stdoutText, stderrText) {
  return /no\s+provider\s+selected/.test(combinedOutput(stdoutText, stderrText))
}

// Every two-step method on the account is one the CLI cannot do (passkey,
// Duo): only an API key login works.
function loginHasNoUsableProvider(stdoutText, stderrText) {
  return /no\s+providers\s+available\s+for\s+this\s+client/.test(combinedOutput(stdoutText, stderrText))
}

// Writes BW_PASSWORD into the FIFO. The script names the variable, never its
// value; `timeout` stops a dead reader from blocking the writer forever.
function authPasswordWriteCommand(channel) {
  var fifoName = authPasswordFifoName(channel)
  if (!fifoName) return []

  var script = "test -n \"${XDG_RUNTIME_DIR:-}\" || exit 1; "
  script += "__auth_dir=\"$XDG_RUNTIME_DIR/" + RUNTIME_SUBDIR + "\"; "
  script += "__auth_fifo=\"$__auth_dir/" + fifoName + "\"; "
  // Started alongside the reader, so on the first login after boot the dir
  // and FIFO may not exist yet: wait for both.
  script += "for __auth_wait in {1..200}; do "
  script += "if [ -d \"$__auth_dir\" ] && [ ! -L \"$__auth_dir\" ] && [ -p \"$__auth_fifo\" ] && [ ! -L \"$__auth_fifo\" ]; then "
  script += "exec timeout 10s bash -c 'printf \"%s\" \"$" + PASSWORD_ENV + "\" > \"$1\"' _ \"$__auth_fifo\"; "
  script += "fi; sleep 0.01; done; exit 1"
  return ["bash", "-c", script]
}

// The custom server receives the master password. Returns "" if the URL is
// usable (empty means the default server), else why it was refused: only
// http(s), and plain http only to loopback (e.g. a local Vaultwarden or tunnel).
var SERVER_SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//
var LOOPBACK_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i
var BITWARDEN_US_SERVER = "https://vault.bitwarden.com"
var BITWARDEN_EU_SERVER = "https://vault.bitwarden.eu"

// Both regions are explicit because bw remembers its last server. Unknown
// input falls back to US, never to a stale custom URL.
function loginServerUrlFor(region, customUrl) {
  var choice = String(region || "").toLowerCase()
  if (choice === "eu") return BITWARDEN_EU_SERVER
  if (choice === "custom") return String(customUrl || "").trim()
  return BITWARDEN_US_SERVER
}

function validateServerUrl(raw) {
  var url = String(raw || "").trim()
  if (!url) return ""

  // bw's URL parser treats `\` as `/` in http(s) authorities; the parser below
  // does not, so `http://evil\@localhost` could pass as loopback.
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
  var script = serverConfigPrefix(serverUrl)
  script += "bw login --apikey >/dev/null 2>&1 && "
  script += "bw unlock --passwordenv " + PASSWORD_ENV + " --raw | head -c " + MAX_TOKEN_BYTES
  return supervisedProcessCommand(script, appDataDirPrelude())
}

// -------------------------------------------------------------------------
// Terminal login handoff
// -------------------------------------------------------------------------
//
// `bw login` in a terminal handles what the panel cannot (SSO, Duo, hardware
// keys). The terminal writes its session key to a file under XDG_RUNTIME_DIR,
// which the panel reads once and deletes. `--raw` keeps prompts on stderr.

// No /tmp fallback if XDG_RUNTIME_DIR is unset: fail closed rather than write
// a session key somewhere world-writable.
var HANDOFF_BASENAME = "session-handoff"

// `mode` is "login" or "unlock"; the panel already knows which, so no slow
// `bw status` probe first. `slot` is the account's (a detached terminal gets
// none of the vault's environment).
function terminalLoginCommand(mode, serverUrl, slot) {
  var verb = (mode === "unlock") ? "unlock" : "login"
  var configureServer = verb === "login" ? serverConfigPrefix(serverUrl) : ""
  var inner = "set -u; " + accountAppDataExport(slot) + appDataDirPrelude()
    + "d=\"${XDG_RUNTIME_DIR:?no XDG_RUNTIME_DIR -- refusing to write a session key}/"
    + RUNTIME_SUBDIR + "\"; f=\"$d/" + HANDOFF_BASENAME + "\"; "
    // umask before mkdir so the dir is created 0700; a failed chmod means the
    // dir is not ours.
    + "umask 077; " + privateDirScript("d")
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

// How long after launching a terminal login its handoff is still accepted.
var HANDOFF_WINDOW_MS = 10 * 60 * 1000

// How long a login awaiting a second factor survives the panel closing, so an
// emailed code can be read. Shorter than the handoff window: it holds the
// master password, not a session key.
var SECOND_FACTOR_WINDOW_MS = 5 * 60 * 1000

// Wall-clock, like the auto-lock, so time spent suspended counts. A clock
// stepped backwards closes the window rather than reopening it.
function windowOpen(startedAt, now, windowMs) {
  var began = Number(startedAt)
  if (!isFinite(began) || began <= 0) return false
  var elapsed = Number(now) - began
  if (!isFinite(elapsed) || elapsed < 0) return false
  return elapsed <= windowMs
}

function secondFactorWindowOpen(startedAt, now) {
  return windowOpen(startedAt, now, SECOND_FACTOR_WINDOW_MS)
}

function handoffWindowOpen(startedAt, now) {
  return windowOpen(startedAt, now, HANDOFF_WINDOW_MS)
}

// Reads and deletes the handoff file. The key is only read while `expecting`
// (shortly after we launched a terminal login), so no other process can hand
// the panel a session key at a time of its choosing; the file is deleted
// either way. A missing runtime dir means nothing was handed over.
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
// Screen lock and suspend both lock the vault, like `omarchy-system-lock`
// does for 1Password.

// Screen lock is polled: Omarchy's lock screen (ext-session-lock) never tells
// logind, so only the shell's lock plugin knows, via IPC. Only "true" means
// locked; a missing plugin must never read as locked.
function screenLockStateCommand() {
  return ["bash", "-c", "omarchy-shell lock isLocked 2>/dev/null | head -c 16"]
}

function screenIsLocked(raw) {
  return String(raw || "").trim() === "true"
}

// Polled only while the setting is on and the vault unlocked (~50 ms per call).
var SCREEN_LOCK_POLL_MS = 3000

function screenLockPollMs() {
  return SCREEN_LOCK_POLL_MS
}

// Suspend is an event: logind's PrepareForSleep(true), for every path into
// sleep. A delay inhibitor, held until a second after the announcement, gives
// the panel time to drop the key before memory is frozen. Inhibitors release
// only on exit, so each loop iteration takes a fresh one. The monitor is
// killed by pid once sed matches; waiting for a broken pipe would hold the
// inhibitor until the next signal, which is the resume.
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
    // Time for the panel to act before the inhibitor is released.
    + "sleep 1"

  // Never exits on its own; failures wait before retrying so it cannot spin.
  // Quickshell kills only its direct child on reload, so a watcher on stdin
  // kills this process group (setsid makes $$ its id) when the owner dies.
  // The panel must keep stdinEnabled true.
  var script = "(while IFS= read -r _; do :; done; kill -KILL -- -$$) <&0 & "
    + "while :; do "
    + "command -v gdbus >/dev/null 2>&1 || { sleep 300; continue; }; "
    + "if systemd-inhibit --what=sleep --mode=delay"
    + " --who=" + shellQuote("Bitwarden")
    + " --why=" + shellQuote("Locking the vault before sleep")
    + " bash -c " + shellQuote(inner) + "; then "
    // Resume. Reported once the inhibitor is gone, since nothing waits on it.
    + "echo " + shellQuote(WAKE_SIGNAL_TOKEN) + "; "
    + "else sleep 5; fi; "
    + "done"
  return ["setsid", "bash", "-c", script]
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
// Item URIs are untrusted (shared collections are editable by others) and
// xdg-open launches any scheme, so only http(s) is opened. `host:8080` is a
// port, not a scheme.
var HTTP_URL_RE = /^https?:\/\//i
var URL_SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):(?!\d)/

// Returns { ok: true, url } for something safe to open, or { ok: false,
// scheme } naming what was refused.
function normalizeOpenableUrl(raw) {
  var target = String(raw || "").trim()
  if (!target) return { ok: false, scheme: "" }
  // Browsers treat `\` as `/` in http(s) authorities; refuse the ambiguity.
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

// `bw list items` returns decrypted ciphers, SSH private keys included. A jq
// filter keeps only supported types: 1-4 whole (edit and detail need
// rawObject; an sshKey subtree on one fails the read), type 5 as public
// metadata only, others dropped.
var JQ_ITEM_HELPERS = [
  "def string_or_empty: if type == \"string\" then . else \"\" end;",
  "def string_or_null: if type == \"string\" then . else null end;",
  "def bool_or_false: if type == \"boolean\" then . else false end;",
  "def reprompt_or_zero: if . == 0 or . == 1 then . else 0 end;",
  "def item_type: try (.type | tonumber) catch null;",
  "def ordinary_type: item_type as $t | ($t == 1 or $t == 2 or $t == 3 or $t == 4);",
  "def ssh_type: item_type == 5;"
]

var SANITIZED_ITEMS_FILTER = JQ_ITEM_HELPERS.concat([
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
]).join("\n")

// The agent branch's projection: eligible private keys framed by the load
// nonce. Re-prompt items and empty keys are dropped here (the companion also
// refuses them) so fewer copies travel. The shape must match the companion's
// `deny_unknown_fields` decoder exactly.
var AGENT_KEYS_FILTER = JQ_ITEM_HELPERS.concat([
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
]).join("\n")

// jq accepts non-JSON extensions and rewrites bad UTF-8, so input is first
// validated as strict JSON by node (which bw already requires). Nothing is
// written unless the whole input parses.
function strictJsonStdinScript(rejectExpr, writeStmt) {
  return [
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
    "    if (" + rejectExpr + ") process.exit(1);",
    "  } catch (error) {",
    "    process.exit(1);",
    "  }",
    "  " + writeStmt,
    "});"
  ].join("\n")
}

var STRICT_JSON_PASSTHROUGH = strictJsonStdinScript(
  "!Array.isArray(parsed)",
  "process.stdout.write(raw);"
)

// The same validator for the single object `bw create/edit item` prints,
// wrapped in [] so the array-based sanitizing filter applies unchanged. Node
// must parse the untrusted bytes first, so this is not left to `jq -s`.
var STRICT_JSON_ONE_OBJECT = strictJsonStdinScript(
  "parsed === null || typeof parsed !== \"object\" || Array.isArray(parsed)",
  "process.stdout.write(\"[\"); process.stdout.write(raw); process.stdout.write(\"]\");"
)

// Printed when the save succeeded but sanitizing its output failed; the panel
// then reloads the list instead of reporting a failure.
var SAVED_UNSANITIZED_MARKER = "__QSBW_SAVED_UNSANITIZED__"

var SANITIZED_LIST_ERROR = "Could not safely read vault items."
var SANITIZED_LIST_SSH_FIX_HINT = " Bitwarden CLI before " + SSH_MALFORMED_ITEM_FIX_VERSION
  + " can fail on malformed SSH key items. Upgrading to " + SSH_MALFORMED_ITEM_FIX_VERSION
  + " or newer may fix this."

// The optional `tee` branch feeding the SSH agent's FIFO. It must never break
// the item list it sits inside:
//  1. It never blocks: O_RDWR on a FIFO does not wait for a reader.
//  2. It writes only to the fd opened with O_NOFOLLOW and fstat-checked, so
//     the path cannot be swapped under it.
//  3. It always drains stdin (the trailing `cat`), so `tee` never sees EPIPE.
// Its status is invisible to pipefail by design; the agent validates each
// load by nonce and schema.
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
    // A cheap pre-check (the fstat is the real one) that skips the whole
    // decrypt-and-filter pass when the agent is gone.
    + "if [ -p \"$__qsbw_fifo\" ]; then "
    + "timeout 10 jq -c --arg loadId \"${" + LOAD_ID_ENV + ":-}\" "
    + shellQuote(AGENT_KEYS_FILTER) + " 2>/dev/null | timeout 10 node -e "
    + shellQuote(fifoWriter) + " \"$__qsbw_fifo\" 2>/dev/null || true; "
    + "fi; "
    + "cat >/dev/null 2>&1 || true"
  return "tee >(" + inner + ") | "
}

function sanitizedListCommand(opts) {
  // Caps allow one byte over the limit so overflow is detectable. All
  // diagnostics are suppressed (bw and jq may quote decrypted data); QML sees
  // only SANITIZED_LIST_ERROR. vaultListFailureMessage() adds the SSH hint.
  var agentBranch = Boolean(opts && opts.agentBranch)
  var maxPlusOne = MAX_ITEMS_BYTES + 1
  var script = "export LC_ALL=C BW_NOINTERACTION=true; set -o pipefail; "
  script += "__qsbw_items=$({ bw list items | head -c " + maxPlusOne
    + " | node -e " + shellQuote(STRICT_JSON_PASSTHROUGH) + " " + MAX_ITEMS_BYTES
    // After the validator, so the agent only sees a strict JSON array.
    + " | " + (agentBranch ? agentBranchScript() : "")
    + "jq -c " + shellQuote(SANITIZED_ITEMS_FILTER)
    + " | head -c " + maxPlusOne + "; } 2>/dev/null)\n"
  script += "__rc=$?\n"
  script += "if [ \"$__rc\" -ne 0 ] || [ \"${#__qsbw_items}\" -gt " + MAX_ITEMS_BYTES + " ]; then\n"
  script += "  printf '%s\\n' " + shellQuote(SANITIZED_LIST_ERROR) + " >&2\n"
  script += "  exit 1\n"
  script += "fi\n"
  script += "printf '%s' \"$__qsbw_items\""
  // Only the fan-out form has extra processes a lock must reap.
  return agentBranch ? supervisedProcessCommand(script) : ["bash", "-c", script]
}

function listOrganizationsCommand() {
  return buildCappedCommand(["list", "organizations"], MAX_ORGS_BYTES)
}

function listFoldersCommand() {
  return buildCappedCommand(["list", "folders"], MAX_FOLDERS_BYTES)
}

// Org-owned items go in collections (at least one is required), not folders.
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

// Favorites first, then by name.
function compareItems(a, b) {
  if (a.favorite !== b.favorite) return a.favorite ? -1 : 1
  return compareNames(a, b)
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

var FOLDER_ENV = "QSBW_FOLDER"

function folderEnvVar() {
  return FOLDER_ENV
}

function folderPayload(name) {
  return JSON.stringify({ name: String(name || "").trim() })
}

// `bw encode` is plain base64 but costs a full CLI startup (~2.7 s per save);
// coreutils gives identical output (asserted by a test) in milliseconds.
var ENCODE_CMD = "base64 -w0"

function createFolderCommand() {
  var script = "printf '%s' \"$" + FOLDER_ENV + "\" | " + ENCODE_CMD + " | bw create folder | head -c " + MAX_MISC_BYTES
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
// Create, edit, delete
// -------------------------------------------------------------------------

// Item JSON contains the password, so it travels in the environment.
var ITEM_ENV = "QSBW_ITEM"

function itemEnvVar() {
  return ITEM_ENV
}

// `bw create/edit item` print the saved cipher, which lets the panel update
// one item instead of re-listing the vault. It is fully decrypted, so it goes
// through the same strict-JSON + jq sanitizer as the list. The save's status
// is captured first: a sanitizer failure after a successful save prints
// SAVED_UNSANITIZED_MARKER (the panel reloads) instead of a false failure.
function savePipelineScript(saveCommand) {
  var maxPlusOne = MAX_MISC_BYTES + 1
  // Keep stderr separate so bw warnings cannot corrupt the captured JSON.
  var script = "exec 2> >(head -c " + MAX_STDERR_BYTES + " >&2); "
  script += "export LC_ALL=C BW_NOINTERACTION=true; set -o pipefail; "
  script += "__qsbw_saved=$(printf '%s' \"$" + ITEM_ENV + "\" | " + ENCODE_CMD
    + " | " + saveCommand + " | head -c " + maxPlusOne + ")\n"
  script += "__rc=$?\n"
  script += "case \"$__rc\" in 141) __rc=0 ;; esac\n"
  script += "if [ \"$__rc\" -ne 0 ]; then exit \"$__rc\"; fi\n"
  // Saved. From here nothing may turn a stored item into a reported failure.
  script += "__qsbw_env=$({ printf '%s' \"$__qsbw_saved\""
    + " | node -e " + shellQuote(STRICT_JSON_ONE_OBJECT) + " " + MAX_MISC_BYTES
    + " | jq -c " + shellQuote(SANITIZED_ITEMS_FILTER)
    + " | head -c " + maxPlusOne + "; } 2>/dev/null)\n"
  script += "if [ $? -ne 0 ] || [ -z \"$__qsbw_env\" ] || [ \"${#__qsbw_env}\" -gt " + MAX_MISC_BYTES + " ]; then\n"
  script += "  printf '%s' " + shellQuote(SAVED_UNSANITIZED_MARKER) + "\n"
  script += "  exit 0\n"
  script += "fi\n"
  script += "printf '%s' \"$__qsbw_env\""
  return ["bash", "-c", script]
}

function createItemCommand(itemData) {
  var orgArg = (itemData && itemData.organizationId) ? (" --organizationid " + shellQuote(itemData.organizationId)) : ""
  return savePipelineScript("bw create item" + orgArg)
}

function editItemCommand(itemId, typeCode) {
  if (Number(typeCode) === 5) return []
  return savePipelineScript("bw edit item -- " + shellQuote(itemId))
}

function deleteItemCommand(itemId, typeCode) {
  if (Number(typeCode) === 5) return []
  return buildCappedCommand(["delete", "item", "--", String(itemId)], MAX_MISC_BYTES, MAX_STDERR_BYTES)
}

// -------------------------------------------------------------------------
// Remembered session
// -------------------------------------------------------------------------
//
// The session token must not survive a reboot. It is stored in libsecret's
// in-memory `session` collection where available (falling back to the
// default), and prefixed with the kernel boot id, so a token from another
// boot is refused and cleared. Every failure reads as "no token".
const KEYRING_SESSION_COLLECTION = "session"
const BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"

function keyringStoreCommand(slot) {
  var attrs = keyringAttributes(keyringEntryName(KEYRING_ACCOUNT, slot))
  // Only the boot id is read in the script; the token comes from the env.
  var script = "store() { printf '%s %s' \"$(cat " + shellQuote(BOOT_ID_PATH) + ")\" \"$"
    + KEYRING_SECRET_ENV + "\" | secret-tool store \"$@\" --label="
    + shellQuote("Bitwarden Vault Session") + attrs + "; }; "
    + "store --collection=" + shellQuote(KEYRING_SESSION_COLLECTION) + " 2>/dev/null || store"
  return ["bash", "-c", script]
}

function keyringLookupCommand(slot) {
  var attrs = keyringAttributes(keyringEntryName(KEYRING_ACCOUNT, slot))
  var script = "boot=$(cat " + shellQuote(BOOT_ID_PATH) + " 2>/dev/null | head -c 128) || exit 0; "
    + "[ -n \"$boot\" ] || exit 0; "
    + "stored=$(secret-tool lookup" + attrs + " 2>/dev/null | head -c " + MAX_TOKEN_BYTES + ") || exit 0; "
    + "case \"$stored\" in "
    + "\"$boot \"?*) printf '%s' \"${stored#* }\" ;; "
    // From another boot, or unprefixed: clear it.
    + "*) [ -n \"$stored\" ] && secret-tool clear" + attrs + " >/dev/null 2>&1 ;; "
    + "esac; exit 0"
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearCommand(slot) {
  return keyringClearEntryCommand(keyringEntryName(KEYRING_ACCOUNT, slot))
}

// -------------------------------------------------------------------------
// Legacy quick-unlock entries
// -------------------------------------------------------------------------
//
// Before the envelope, fingerprint and FIDO2 unlock kept the master password
// in plaintext keyring entries and PIN unlock kept an AES-CBC blob. They are
// now only read, migrated into the envelope and deleted.

function keyringLookupMasterPasswordCommand(slot) {
  return keyringLookupEntryCommand(keyringEntryName(KEYRING_MASTER, slot))
}

function keyringClearMasterPasswordCommand(slot) {
  return keyringClearEntryCommand(keyringEntryName(KEYRING_MASTER, slot))
}

// Presence check that never prints the secret.
function keyringHasMasterPasswordCommand(slot) {
  return keyringHasEntryCommand(keyringEntryName(KEYRING_MASTER, slot))
}

function keyringClearFidoPasswordCommand(slot) {
  return keyringClearEntryCommand(keyringEntryName(KEYRING_FIDO, slot))
}

// Presence check that never puts the secret on stdout.
function keyringHasFidoPasswordCommand(slot) {
  return keyringHasEntryCommand(keyringEntryName(KEYRING_FIDO, slot))
}

// -------------------------------------------------------------------------
// PIN
// -------------------------------------------------------------------------

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

// Argon2id cost of one PIN guess at the envelope's parameters, measured on a
// current laptop; used only in the warning text.
var PIN_GUESS_SECONDS = 0.75

function pinGuessTime(length) {
  var seconds = Math.pow(10, length) * PIN_GUESS_SECONDS
  var hours = seconds / 3600
  if (hours < 48) return "about " + Math.max(1, Math.round(hours)) + " hours"
  return "about " + Math.round(hours / 24) + " days"
}

function pinWeakWarning(pin) {
  var p = String(pin || "")
  if (p.length < PIN_MIN_LENGTH || p.length >= PIN_RECOMMENDED_LENGTH) return ""
  var combinations = Math.pow(10, p.length).toLocaleString("en-US")
  return "A " + p.length + "-digit PIN is only " + combinations + " combinations: a program running "
    + "as you could try them all in " + pinGuessTime(p.length) + " on one CPU core. "
    + "Use " + PIN_RECOMMENDED_LENGTH + " or more: " + PIN_RECOMMENDED_LENGTH + " digits is "
    + pinGuessTime(PIN_RECOMMENDED_LENGTH) + "."
}

function isPinWeak(pin) {
  return pinWeakWarning(pin) !== ""
}

// Decrypts the legacy PIN blob. Non-zero exit: wrong PIN or no blob.
function pinUnlockCommand(slot) {
  var script = "secret-tool lookup" + keyringAttributes(keyringEntryName(KEYRING_PIN, slot)) + " 2>/dev/null | head -c 8192"
    + " | openssl enc -d -aes-256-cbc -pbkdf2 -iter " + PIN_ITERATIONS
    + " -md sha256 -pass env:" + PIN_ENV + " -base64 -A | head -c " + MAX_TOKEN_BYTES
  return ["bash", "-c", cappedScript(script)]
}

function keyringClearPinCommand(slot) {
  return keyringClearEntryCommand(keyringEntryName(KEYRING_PIN, slot))
}

function keyringHasPinCommand(slot) {
  return keyringHasEntryCommand(keyringEntryName(KEYRING_PIN, slot))
}

// -------------------------------------------------------------------------
// The quick-unlock envelope in the keyring
// -------------------------------------------------------------------------
//
// One keyring item holds the master password, encrypted once, plus a way in
// per enabled quick-unlock method (layout: unlock-key/src/lib.rs). Each
// builder is one pipeline:
//
//   secret-tool lookup -> systemd-creds --user decrypt -> qs-bitwarden-unlock-key
//     -> systemd-creds --user encrypt -> verify -> secret-tool store
//
// with `argon2` deriving keys from the password or PIN. QML only ever gets a
// secret-free summary, or the password on unlock. Secrets travel only in env
// vars via `printf` (a builtin); salts, parameters and ids may be in argv.
// Writes commit last: the new envelope is re-opened and checked before
// `secret-tool store`, so any failure leaves the old one intact.
var KEYRING_ENVELOPE = "unlock_envelope"
var ENVELOPE_LABEL = "Bitwarden quick unlock (encrypted)"
// The systemd-creds name, bound into the seal.
var ENVELOPE_CREDENTIAL_NAME = "qs-bitwarden-unlock"
var NEW_SECRET_ENV = "QSBW_NEW_SECRET"
var FIDO_HMAC_ENV = "QSBW_FIDO_HMAC"
var FIDO_SALT_ENV = "QSBW_FIDO_SALT"
// Argon2id for new wraps (~0.75 s). Existing wraps use their recorded
// parameters; the tool refuses any below Bitwarden's defaults.
var ENVELOPE_ARGON2 = { m: 262144, t: 4, p: 1 }
var MAX_ENVELOPE_SEALED_BYTES = 256 * 1024

// Exit statuses of these scripts. 2-8 are the unlock tool's own, passed
// through: 3 wrong key, 4 malformed, 5 limits, 6 another account, 7 no such
// method, 8 internal.
var ENVELOPE_EXIT = {
  absent: 10,     // no envelope in the keyring
  unseal: 11,     // systemd-creds could not open it, or it is not an envelope
  kdf: 12,        // argon2 failed
  store: 13,      // secret-tool could not store the new envelope
  verify: 14      // the new envelope did not re-open as it should have
}

function envelopeNewSecretEnvVar() { return NEW_SECRET_ENV }
function envelopeExitCodes() { return ENVELOPE_EXIT }

var ENVELOPE_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/

// Exits as a usage error, for arguments that should never reach a builder.
function envelopeRefused() { return ["bash", "-c", "exit 2"] }

// A ["bash", "-c", script] command as a step inside another script.
function nestedScript(cmd) { return "bash -c " + shellQuote(cmd[2]) }

function envelopeArgsOk(tool, account) {
  return typeof tool === "string" && tool.charAt(0) === "/"
    && account && typeof account.id === "string" && account.id !== ""
    && typeof account.server === "string"
    && (account.slot === undefined || isAccountSlot(account.slot))
    && !/[\x00-\x1f\x7f]/.test(account.id + account.server)
}

function envelopeAccountArgs(account) {
  return " --account-id " + shellQuote(account.id) + " --server " + shellQuote(account.server)
}

// Functions every envelope script starts with.
// `slot` picks the account's envelope entry; see keyringEntryName().
function envelopePrelude(tool, slot) {
  return "__tool=" + shellQuote(tool) + "; "
    + "__name=" + shellQuote(ENVELOPE_CREDENTIAL_NAME) + "; "
    + "__lookup() { secret-tool lookup" + keyringAttributes(keyringEntryName(KEYRING_ENVELOPE, slot))
    + " 2>/dev/null | head -c " + MAX_ENVELOPE_SEALED_BYTES + "; }; "
    + "__unseal() { printf '%s' \"$1\" | systemd-creds --user decrypt --name=\"$__name\" - - 2>/dev/null; }; "
    // The sealed bytes must hold no CR or LF. systemd-creds wraps its base64 at
    // 79 columns, and a passwordless gnome-keyring (Omarchy's default, from
    // /usr/share/omarchy/install/user/default-keyring.sh) writes the secret
    // verbatim into the text file behind the default collection. A multi-line
    // secret makes that file unreadable at the next login ("keyring was in an
    // invalid or unrecognized format") and the whole collection disappears.
    // decrypt takes the joined form, so envelopes stored wrapped still open.
    // A failed seal must fail, not report tr's 0: cappedScript() sets pipefail
    // already, and the subshell keeps that true of __seal on its own.
    + "__seal() { (set -o pipefail; "
    + "systemd-creds --user encrypt --name=\"$__name\" - - 2>/dev/null | tr -d '\\n\\r'); }; "
    // secret salt t m(KiB) p -> 64 hex digits; the secret reaches argon2 on stdin.
    + "__kdf() { printf '%s' \"$1\" | argon2 \"$2\" -id -t \"$3\" -k \"$4\" -p \"$5\" -l 32 -r 2>/dev/null; }; "
    + "__salt() { head -c 16 /dev/urandom | base64 -w0; }; "
    // The current envelope, sealed, and its secret-free summary.
    + "__load() { "
    + "__sealed=\"$(__lookup)\"; [ -n \"$__sealed\" ] || exit " + ENVELOPE_EXIT.absent + "; "
    + "__summary=\"$(__unseal \"$__sealed\" | \"$__tool\" inspect)\" || exit " + ENVELOPE_EXIT.unseal + "; }; "
    // `<jq path>` of a wrap's kdf -> "salt t m p", or nothing if absent.
    + "__params() { printf '%s' \"$__summary\" | jq -r \"$1\"' // empty | \"\\(.salt) \\(.t) \\(.m) \\(.p)\"'; }; "
    // Derive the key for a wrap already in the envelope, from a secret.
    + "__wrap_key() { local __line __s __t __m __p; __line=\"$(__params \"$1\")\"; "
    + "[ -n \"$__line\" ] || exit 7; read -r __s __t __m __p <<< \"$__line\"; "
    + "__kdf \"$2\" \"$__s\" \"$__t\" \"$__m\" \"$__p\" || exit " + ENVELOPE_EXIT.kdf + "; }; "
    // The new envelope must re-open, for the right account...
    + "__verify_account() { __unseal \"$__new\" | \"$__tool\" inspect "
    + "| jq -e --arg id \"$1\" --arg server \"$2\" '.account.id == $id and .account.server == $server' "
    + ">/dev/null || exit " + ENVELOPE_EXIT.verify + "; }; "
    // ...and yield exactly the password through the way just written. cmp on
    // streams keeps a trailing newline significant; the way's key ($__vk)
    // goes in the tool's env, never argv.
    + "__verify_opens() { cmp -s <(printf '%s' \"$1\") "
    + "<(__unseal \"$__new\" | QSBW_UNLOCK_KEY=\"$__vk\" \"$__tool\" open \"${@:2}\") "
    + "|| exit " + ENVELOPE_EXIT.verify + "; }; "
    + "__store() { printf '%s' \"$__new\" | secret-tool store --label=" + shellQuote(ENVELOPE_LABEL)
    + keyringAttributes(keyringEntryName(KEYRING_ENVELOPE, slot)) + " || exit " + ENVELOPE_EXIT.store + "; }; "
}

function envelopeArgon2Args(saltVar) {
  return " --salt \"$" + saltVar + "\" --m " + ENVELOPE_ARGON2.m
    + " --t " + ENVELOPE_ARGON2.t + " --p " + ENVELOPE_ARGON2.p
}

function envelopeNewKey(secretExpr, saltVar) {
  return "__kdf " + secretExpr + " \"$" + saltVar + "\" " + ENVELOPE_ARGON2.t + " "
    + ENVELOPE_ARGON2.m + " " + ENVELOPE_ARGON2.p
}

// Secret-free summary: enabled methods, staleness, FIDO2 credentials and
// salts. Exit 10: no envelope.
function unlockEnvelopeInspectCommand(tool, slot) {
  if (typeof tool !== "string" || tool.charAt(0) !== "/") return envelopeRefused()
  var script = envelopePrelude(tool, slot) + "__load; printf '%s' \"$__summary\""
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// The master password, through one method. `via` is
//   { kind: "master" }        password in KEYRING_SECRET_ENV (a check, not an unlock)
//   { kind: "pin" }           PIN in PIN_ENV
//   { kind: "fingerprint" }   no secret: the caller has already had PAM's yes
//   { kind: "fido", cred }    hmac-secret for `cred` in FIDO_HMAC_ENV
function unlockEnvelopeOpenCommand(tool, account, via) {
  if (!envelopeArgsOk(tool, account) || !via) return envelopeRefused()
  var open = "\"$__tool\" open" + envelopeAccountArgs(account)
  var script = envelopePrelude(tool, account.slot) + "__load; "
  if (via.kind === "master" || via.kind === "pin") {
    var secret = via.kind === "master" ? KEYRING_SECRET_ENV : PIN_ENV
    script += "__k=\"$(__wrap_key '." + via.kind + "' \"$" + secret + "\")\" || exit $?; "
      + "__unseal \"$__sealed\" | QSBW_UNLOCK_KEY=\"$__k\" " + open + " --via " + via.kind
  } else if (via.kind === "fingerprint") {
    script += "__unseal \"$__sealed\" | " + open + " --via fingerprint"
  } else if (via.kind === "fido" && ENVELOPE_BASE64_RE.test(String(via.cred || ""))) {
    script += "__unseal \"$__sealed\" | QSBW_UNLOCK_KEY=\"$" + FIDO_HMAC_ENV + "\" " + open
      + " --via fido --cred " + shellQuote(via.cred)
  } else {
    return envelopeRefused()
  }
  script += " | head -c " + MAX_TOKEN_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Creates the envelope from a password `bw` just accepted (KEYRING_SECRET_ENV),
// replacing any existing one. The only writer of the stored password.
function unlockEnvelopeCreateCommand(tool, account) {
  if (!envelopeArgsOk(tool, account)) return envelopeRefused()
  var script = envelopePrelude(tool, account.slot)
    + "__s=\"$(__salt)\"; "
    + "__k=\"$(" + envelopeNewKey("\"$" + KEYRING_SECRET_ENV + "\"", "__s") + ")\" || exit "
    + ENVELOPE_EXIT.kdf + "; "
    + "__new=\"$(QSBW_UNLOCK_PASSWORD=\"$" + KEYRING_SECRET_ENV + "\" QSBW_UNLOCK_NEW_KEY=\"$__k\" "
    + "\"$__tool\" create" + envelopeAccountArgs(account) + envelopeArgon2Args("__s") + " | __seal)\" "
    + "|| exit $?; "
    + "__verify_account " + shellQuote(account.id) + " " + shellQuote(account.server) + "; "
    + "__vk=\"$__k\"; __verify_opens \"$" + KEYRING_SECRET_ENV + "\"" + envelopeAccountArgs(account)
    + " --via master; "
    + "__store"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Change the envelope in the keyring. `op` is one of
//   { kind: "add-pin" }                       password in KEYRING_SECRET_ENV, PIN in PIN_ENV
//   { kind: "add-fingerprint" }               password in KEYRING_SECRET_ENV
//   { kind: "add-fido", cred, rp, salt }      password in KEYRING_SECRET_ENV,
//                                             hmac-secret for `salt` in FIDO_HMAC_ENV
//   { kind: "remove", method, cred }          no secret
//   { kind: "mark-stale" }                    no secret
//   { kind: "rotate", auth }                  new password in NEW_SECRET_ENV; `auth` is a
//                                             `via` as for opening, with its secret where
//                                             unlockEnvelopeOpenCommand expects it
// Adds are authorized by the typed master password opening the `master`
// wrap; nothing typed is stored.
function unlockEnvelopeUpdateCommand(tool, account, op) {
  if (!envelopeArgsOk(tool, account) || !op) return envelopeRefused()
  var acct = envelopeAccountArgs(account)
  var masterKey = "__mk=\"$(__wrap_key '.master' \"$" + KEYRING_SECRET_ENV + "\")\" || exit $?; "
  var transform = ""
  var verifyOpen = ""
  var pre = ""

  if (op.kind === "add-pin") {
    pre = masterKey + "__s=\"$(__salt)\"; "
      + "__pk=\"$(" + envelopeNewKey("\"$" + PIN_ENV + "\"", "__s") + ")\" || exit " + ENVELOPE_EXIT.kdf + "; "
    transform = "QSBW_UNLOCK_KEY=\"$__mk\" QSBW_UNLOCK_NEW_KEY=\"$__pk\" \"$__tool\" add" + acct
      + " --auth master --method pin" + envelopeArgon2Args("__s")
    verifyOpen = "__vk=\"$__pk\"; __verify_opens \"$" + KEYRING_SECRET_ENV + "\"" + acct + " --via pin; "
  } else if (op.kind === "add-fingerprint") {
    pre = masterKey
    transform = "QSBW_UNLOCK_KEY=\"$__mk\" \"$__tool\" add" + acct + " --auth master --method fingerprint"
    verifyOpen = "__vk=''; __verify_opens \"$" + KEYRING_SECRET_ENV + "\"" + acct + " --via fingerprint; "
  } else if (op.kind === "add-fido") {
    // `saltFromEnv`: a fresh salt drawn earlier in the same pipeline.
    var saltArg = op.saltFromEnv ? "\"$" + FIDO_SALT_ENV + "\"" : shellQuote(op.salt)
    if (!ENVELOPE_BASE64_RE.test(String(op.cred || ""))
        || (!op.saltFromEnv && !ENVELOPE_BASE64_RE.test(String(op.salt || "")))
        || !op.rp || /[\x00-\x1f\x7f]/.test(String(op.rp))) return envelopeRefused()
    pre = masterKey
    transform = "QSBW_UNLOCK_KEY=\"$__mk\" QSBW_UNLOCK_NEW_KEY=\"$" + FIDO_HMAC_ENV + "\" \"$__tool\" add" + acct
      + " --auth master --method fido --cred " + shellQuote(op.cred) + " --rp " + shellQuote(op.rp)
      + " --fido-salt " + saltArg
    verifyOpen = "__vk=\"$" + FIDO_HMAC_ENV + "\"; __verify_opens \"$" + KEYRING_SECRET_ENV + "\"" + acct
      + " --via fido --cred " + shellQuote(op.cred) + "; "
  } else if (op.kind === "remove") {
    if (op.method === "pin" || op.method === "fingerprint") {
      transform = "\"$__tool\" remove --method " + op.method
    } else if (op.method === "fido" && ENVELOPE_BASE64_RE.test(String(op.cred || ""))) {
      transform = "\"$__tool\" remove --method fido --cred " + shellQuote(op.cred)
    } else {
      return envelopeRefused()
    }
  } else if (op.kind === "mark-stale") {
    transform = "\"$__tool\" mark-stale"
  } else if (op.kind === "rotate" && op.auth) {
    var auth = op.auth
    var authArgs = ""
    if (auth.kind === "master" || auth.kind === "pin") {
      var authSecret = auth.kind === "master" ? KEYRING_SECRET_ENV : PIN_ENV
      pre = "__ak=\"$(__wrap_key '." + auth.kind + "' \"$" + authSecret + "\")\" || exit $?; "
      authArgs = "QSBW_UNLOCK_KEY=\"$__ak\" "
    } else if (auth.kind === "fido" && ENVELOPE_BASE64_RE.test(String(auth.cred || ""))) {
      authArgs = "QSBW_UNLOCK_KEY=\"$" + FIDO_HMAC_ENV + "\" "
    } else if (auth.kind !== "fingerprint") {
      return envelopeRefused()
    }
    pre += "__s=\"$(__salt)\"; "
      + "__nk=\"$(" + envelopeNewKey("\"$" + NEW_SECRET_ENV + "\"", "__s") + ")\" || exit " + ENVELOPE_EXIT.kdf + "; "
    transform = authArgs + "QSBW_UNLOCK_PASSWORD=\"$" + NEW_SECRET_ENV + "\" QSBW_UNLOCK_NEW_KEY=\"$__nk\" "
      + "\"$__tool\" rotate" + acct + " --auth " + auth.kind
      + (auth.kind === "fido" ? " --auth-cred " + shellQuote(auth.cred) : "")
      + envelopeArgon2Args("__s")
    verifyOpen = "__vk=\"$__nk\"; __verify_opens \"$" + NEW_SECRET_ENV + "\"" + acct + " --via master; "
  } else {
    return envelopeRefused()
  }

  var script = envelopePrelude(tool, account.slot) + "__load; " + pre
    + "__new=\"$(__unseal \"$__sealed\" | " + transform + " | __seal)\" || exit $?; "
    + "__verify_account " + shellQuote(account.id) + " " + shellQuote(account.server) + "; "
    + verifyOpen
    + "__store"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Run at every start, ahead of other envelope work: undoes what __seal()
// stored before it joined its lines (see there).
//  1. An envelope the keyring still serves with a line break in it is stored
//     again on one line, once the joined form is shown to decrypt. The keyring
//     rewrites its file cleanly, before the next login can refuse it.
//  2. scripts/repair-keyring.sh --auto repairs a default keyring file that
//     already holds one, which gnome-keyring has refused to load.
// `slots` are the accounts whose entries to look at. Prints rejoined=<n>, a
// rejoin_failed=<account> line for each one that would not decrypt or store,
// then the script's file=<status>. No secret leaves the pipes.
function keyringRepairCommand(pluginDir, slots) {
  if (typeof pluginDir !== "string" || pluginDir.charAt(0) !== "/") return envelopeRefused()
  var names = []
  var list = [DEFAULT_ACCOUNT_SLOT].concat(Array.isArray(slots) ? slots : [])
  for (var i = 0; i < list.length; i++) {
    if (!isAccountSlot(list[i])) continue
    var name = keyringEntryName(KEYRING_ENVELOPE, list[i])
    if (names.indexOf(name) < 0) names.push(name)
  }
  var script = "__n=0; "
    + "for __a in " + names.map(shellQuote).join(" ") + "; do "
    + "__v=\"$(secret-tool lookup service " + shellQuote(KEYRING_SERVICE) + " account \"$__a\" 2>/dev/null "
    + "| head -c " + MAX_ENVELOPE_SEALED_BYTES + ")\" || continue; "
    + "case \"$__v\" in *$'\\n'*|*$'\\r'*) ;; *) continue ;; esac; "
    + "__j=\"$(printf '%s' \"$__v\" | tr -d '\\n\\r')\"; __v=''; "
    + "if printf '%s' \"$__j\" | systemd-creds --user decrypt --name=" + shellQuote(ENVELOPE_CREDENTIAL_NAME)
    + " - - >/dev/null 2>&1 && printf '%s' \"$__j\" | secret-tool store --label=" + shellQuote(ENVELOPE_LABEL)
    + " service " + shellQuote(KEYRING_SERVICE) + " account \"$__a\"; "
    + "then __n=$((__n + 1)); else echo \"rejoin_failed=$__a\"; fi; __j=''; "
    + "done; "
    + "echo \"rejoined=$__n\"; "
    + "bash " + shellQuote(pluginDir.replace(/\/+$/, "") + "/scripts/repair-keyring.sh") + " --auto"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// keyringRepairCommand()'s output -> { rejoined, rejoinFailed: [account],
// file: "skipped" | "clean" | "repaired" | "failed" }. No status line means
// the script died, which counts as failed.
function parseKeyringRepair(raw) {
  var out = { rejoined: 0, rejoinFailed: [], file: "failed" }
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var m = /^(rejoined|rejoin_failed|file)=(.*)$/.exec(lines[i].replace(/\r$/, ""))
    if (!m) continue
    if (m[1] === "rejoined") out.rejoined = Math.max(0, parseInt(m[2], 10) || 0)
    else if (m[1] === "rejoin_failed") out.rejoinFailed.push(m[2])
    else if (/^(skipped|clean|repaired|failed)$/.test(m[2])) out.file = m[2]
  }
  return out
}

// Desktop notification after a keyring file repair: gnome-keyring loads a
// refused file cleanly only after a restart (Omarchy has no logout).
function repairedKeyringNoticeCommand() {
  return ["notify-send", "-a", "Bitwarden", "Keyring repaired",
    "Restart the computer to get your saved passwords and keys back."]
}

// Quick unlock also needs `argon2` (ships with bitwarden-cli) and a working
// `systemd-creds --user` (systemd 256+), probed with a real throwaway seal.
function quickUnlockPrereqCommand() {
  var script = "if command -v argon2 >/dev/null 2>&1; then echo argon2=1; else echo argon2=0; fi; "
    + "if printf probe | systemd-creds --user encrypt --name=qs-bitwarden-probe - - >/dev/null 2>&1; "
    + "then echo creds=1; else echo creds=0; fi"
  return ["bash", "-c", script]
}

function parseQuickUnlockPrereqs(raw) {
  var text = String(raw || "")
  var argon2 = /^argon2=1$/m.test(text)
  var creds = /^creds=1$/m.test(text)
  var message = ""
  if (!argon2) {
    message = "Quick unlock needs `argon2`, which comes with the Bitwarden CLI package. "
      + "Reinstall bitwarden-cli."
  } else if (!creds) {
    message = "Quick unlock needs `systemd-creds --user` (systemd 256 or later) to seal the "
      + "stored password to this machine, and it is not working here."
  }
  return { argon2: argon2, creds: creds, ready: argon2 && creds, message: message }
}

// Verifies a typed master password with `bw` when there is no envelope to
// check it against. `bw unlock` mints a new session key, which the caller
// adopts.
function bwVerifyPasswordCommand() {
  var script = "bw unlock --passwordenv " + KEYRING_SECRET_ENV + " --raw 2>/dev/null | head -c " + MAX_TOKEN_BYTES
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Legacy migration exits: 0 migrated (legacy entry deleted), 20 no legacy
// entry, 21 envelope for this account will not open with this password (one
// is stale; left alone), else the failing envelope step's code.
var LEGACY_MIGRATION_EXIT = { none: 20, mismatch: 21 }

function legacyMigrationExitCodes() { return LEGACY_MIGRATION_EXIT }

// Moves a legacy entry into the envelope in one shell, so the password never
// reaches QML. The legacy entry is deleted only after the envelope opens
// through the new wrap. The password comes from the legacy entry
// (`passwordFromKeyring`) or is already in KEYRING_SECRET_ENV.
function legacyMigrationCommand(tool, account, legacyAccount, addOp, passwordFromKeyring) {
  if (!envelopeArgsOk(tool, account)) return envelopeRefused()
  var script = ""
  if (passwordFromKeyring) {
    script += "__pw=\"$(" + keyringReadScript(keyringEntryName(legacyAccount, account.slot)) + ")\"; "
      + "[ -n \"$__pw\" ] || exit " + LEGACY_MIGRATION_EXIT.none + "; "
      + "export " + KEYRING_SECRET_ENV + "=\"$__pw\"; unset __pw; "
  } else {
    script += "[ -n \"${" + KEYRING_SECRET_ENV + ":-}\" ] || exit " + LEGACY_MIGRATION_EXIT.none + "; "
  }
  // Is there an envelope, and does this password open it?
  script += nestedScript(unlockEnvelopeOpenCommand(tool, account, { kind: "master" })) + " >/dev/null; __rc=$?; "
    + "case \"$__rc\" in "
    + "0) ;; "
    // None, another account's, or unsealable: this password becomes the envelope.
    + ENVELOPE_EXIT.absent + "|6|" + ENVELOPE_EXIT.unseal + ") "
    + nestedScript(unlockEnvelopeCreateCommand(tool, account)) + " || exit $? ;; "
    + "3) exit " + LEGACY_MIGRATION_EXIT.mismatch + " ;; "
    + "*) exit \"$__rc\" ;; esac; "
    + nestedScript(unlockEnvelopeUpdateCommand(tool, account, addOp)) + " || exit $?; "
    // The update verified the new wrap before storing, so this is safe.
    + "secret-tool clear" + keyringAttributes(keyringEntryName(legacyAccount, account.slot))
    + " >/dev/null 2>&1; exit 0"
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

function legacyFingerprintMigrationCommand(tool, account) {
  return legacyMigrationCommand(tool, account, KEYRING_MASTER, { kind: "add-fingerprint" }, true)
}

// Run at the PIN unlock that decrypted the blob: password in
// KEYRING_SECRET_ENV, PIN in PIN_ENV.
function legacyPinMigrationCommand(tool, account) {
  return legacyMigrationCommand(tool, account, KEYRING_PIN, { kind: "add-pin" }, false)
}

// -------------------------------------------------------------------------
// FIDO2 through hmac-secret
// -------------------------------------------------------------------------
//
// Uses the existing pam-u2f registration in /etc/fido2/fido2 (rp
// `pam://<hostname>`). `fido2-assert -h` returns the credential's
// hmac-secret, which is the key to the envelope's FIDO wrap; the key requires
// a touch for it. The random client data hash is discarded: only the
// hmac-secret is used.
var FIDO_EXIT = {
  assert: 31,     // fido2-assert failed: no touch in time, a refusal, or a busy key
  noSecret: 32,   // it answered, but without an hmac-secret
  legacyUsed: 40  // unlocked with the old plaintext entry; migration did not finish
}

function fidoExitCodes() { return FIDO_EXIT }

function fidoTargetOk(target) {
  return target && typeof target.device === "string" && /^\/dev\/[A-Za-z0-9_.\/-]+$/.test(target.device)
    && ENVELOPE_BASE64_RE.test(String(target.cred || ""))
    && typeof target.rp === "string" && /^pam:\/\/[A-Za-z0-9.-]+$/.test(target.rp)
}

// One touch; the hmac-secret for `saltExpr` is exported in FIDO_HMAC_ENV,
// never as an argument.
function fidoAssertScript(target, saltExpr) {
  return "__cdh=\"$(head -c 32 /dev/urandom | base64 -w0)\"; "
    + "__out=\"$(printf '%s\\n%s\\n%s\\n%s\\n' \"$__cdh\" " + shellQuote(target.rp) + " "
    + shellQuote(target.cred) + " " + saltExpr + " | timeout 45 fido2-assert -G -h "
    + shellQuote(target.device) + " 2>/dev/null)\" || exit " + FIDO_EXIT.assert + "; "
    + "__hmac=\"$(printf '%s\\n' \"$__out\" | sed -n 5p)\"; unset __out; "
    + "[ -n \"$__hmac\" ] || exit " + FIDO_EXIT.noSecret + "; "
    + "export " + FIDO_HMAC_ENV + "=\"$__hmac\"; unset __hmac; "
}

function fidoNewSaltScript() {
  return "export " + FIDO_SALT_ENV + "=\"$(head -c 32 /dev/urandom | base64 -w0)\"; "
}

// Unlock through an existing FIDO wrap, using its salt.
function fidoUnlockCommand(tool, account, target) {
  if (!envelopeArgsOk(tool, account) || !fidoTargetOk(target)
      || !ENVELOPE_BASE64_RE.test(String(target.salt || ""))) return envelopeRefused()
  var script = fidoAssertScript(target, shellQuote(target.salt))
    + nestedScript(unlockEnvelopeOpenCommand(tool, account, { kind: "fido", cred: target.cred }))
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Adds a FIDO wrap: the typed master password authorizes, one touch gives the
// hmac-secret for a fresh salt. Exit 10: no envelope yet.
function fidoEnrollCommand(tool, account, target) {
  if (!envelopeArgsOk(tool, account) || !fidoTargetOk(target)) return envelopeRefused()
  var script = fidoNewSaltScript() + fidoAssertScript(target, "\"$" + FIDO_SALT_ENV + "\"")
    + nestedScript(unlockEnvelopeUpdateCommand(tool, account,
      { kind: "add-fido", cred: target.cred, rp: target.rp, saltFromEnv: true }))
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// First unlock after upgrading: one touch migrates the legacy plaintext entry
// into a new FIDO wrap and opens through it. If that fails, the legacy
// password is printed anyway with exit 40, and the entry stays.
function fidoLegacyUnlockCommand(tool, account, target) {
  if (!envelopeArgsOk(tool, account) || !fidoTargetOk(target)) return envelopeRefused()
  var migrate = legacyMigrationCommand(tool, account, KEYRING_FIDO,
    { kind: "add-fido", cred: target.cred, rp: target.rp, saltFromEnv: true }, false)
  var script = "__pw=\"$(" + keyringReadScript(keyringEntryName(KEYRING_FIDO, account.slot)) + ")\"; "
    + "[ -n \"$__pw\" ] || exit " + LEGACY_MIGRATION_EXIT.none + "; "
    + fidoNewSaltScript() + fidoAssertScript(target, "\"$" + FIDO_SALT_ENV + "\"")
    + "export " + KEYRING_SECRET_ENV + "=\"$__pw\"; "
    + "if " + nestedScript(migrate) + " >/dev/null; then "
    + nestedScript(unlockEnvelopeOpenCommand(tool, account, { kind: "fido", cred: target.cred }))
    + " && exit 0; fi; "
    + "printf '%s' \"$__pw\"; exit " + FIDO_EXIT.legacyUsed
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// -------------------------------------------------------------------------
// Clear everything on logout
// -------------------------------------------------------------------------
//
// Every entry the plugin has ever written for the account's slot, legacy ones
// included, is cleared regardless of the panel's flags (which reflect
// settings, not the keyring). Other accounts' entries are left alone.
// `secret-tool clear` skips locked matches and exits 1 on absence, so each
// account is searched, unlocked, cleared and searched again; logout succeeds
// only if nothing remains.
var KEYRING_ALL_ACCOUNTS = [KEYRING_ACCOUNT, KEYRING_ENVELOPE, KEYRING_MASTER, KEYRING_FIDO, KEYRING_PIN]

function keyringSearchStateScript(account, resultVar) {
  // Count the output with wc rather than capture it: it contains the secret.
  var attrs = keyringAttributes(account)
  return resultVar + "=$(secret-tool search --all" + attrs
    + " 2>/dev/null | wc -c | tr -d '[:space:]'; "
    + "__keyring_pipe=(\"${PIPESTATUS[@]}\"); "
    + "printf ':%s' \"${__keyring_pipe[0]}\"); "
}

function keyringClearAllCommand(slot) {
  var script = "rc=0; "
  for (var i = 0; i < KEYRING_ALL_ACCOUNTS.length; i++) {
    var entry = keyringEntryName(KEYRING_ALL_ACCOUNTS[i], slot)
    var attrs = keyringAttributes(entry)
    script += keyringSearchStateScript(entry, "__keyring_before")
    script += "__keyring_count=${__keyring_before%%:*}; "
      + "__keyring_search_rc=${__keyring_before##*:}; "
      + "if [ \"$__keyring_search_rc\" -ne 0 ]; then rc=1; "
      + "elif [ \"$__keyring_count\" -gt 0 ]; then "
      + "secret-tool search --all --unlock" + attrs + " >/dev/null 2>&1 || true; "
      + "secret-tool clear" + attrs + " >/dev/null 2>&1 || true; "
    script += keyringSearchStateScript(entry, "__keyring_after")
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
    // Some bw versions list "no folder" as an entry with a null id.
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

// The same glyphs as the type filter chips.
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
// Attachment metadata comes with `bw list items`; only the bytes are fetched,
// on demand, by attachmentDownloadCommand().

// Arrays stored in a QML `var` and read back are array-like objects for which
// Array.isArray() is false, so lists are duck-typed by length. Capped, since
// the length is the server's claim ({"length": 2e8} would take down the shell).
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

// Fallback for attachments without bw's `sizeName`.
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

// Vault file names are untrusted: reduce to an inert basename. Separators and
// control characters are replaced (not stripped, so nothing re-joins into a
// traversal) and leading dots/dashes removed.
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

// Saves one attachment to the download dir without overwriting (" (1)", ...)
// and prints the final path. Vault ids and names are quoted. The file is
// staged in a private temp dir and claimed with link(), which never follows a
// symlink and fails if the name exists, so there is no check-then-write race.
// The declared size is only the server's claim; RLIMIT_FSIZE, a timeout and a
// free-space check bound the transfer.
function attachmentDownloadCommand(attachmentId, itemId, fileName, declaredSize) {
  var maxBytes = MAX_ATTACHMENT_BYTES
  var maxMb = Math.round(maxBytes / (1024 * 1024))
  var maxBlocks = Math.ceil(maxBytes / 1024)          // ulimit -f counts 1 KB blocks

  // The declared size reaches the script unquoted, and JS prints huge numbers
  // as "1e+30", which `[ ]` errors on (silently skipping the checks). Clamp
  // anything over the limit to limit + 1 so it is refused.
  var numericSize = Number(declaredSize)
  var sizeKnown = declaredSize !== undefined && declaredSize !== null
    && String(declaredSize).trim() !== "" && isFinite(numericSize) && numericSize >= 0
  var want = sizeKnown ? Math.floor(numericSize) : 0
  if (want > maxBytes) want = maxBytes + 1

  // Unknown size: reserve for the largest allowed transfer.
  var reserveBytes = sizeKnown ? want : maxBytes
  var needKb = Math.ceil((reserveBytes + ATTACHMENT_FREE_SLACK_BYTES) / 1024)

  var script = [
    "set -e",
    // Decrypted bytes stay private, staged and final.
    "umask 077",
    "exec 2> >(head -c " + MAX_STDERR_BYTES + " >&2)",
    "name=" + shellQuote(safeAttachmentFileName(fileName)),
    "max=" + maxBytes,
    "want=" + want,
    "dir=\"$(xdg-user-dir DOWNLOAD 2>/dev/null || true)\"",
    // xdg-user-dir falls back to $HOME, which is not a download dir.
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

    // Staged in the destination dir so link() stays on one filesystem.
    "work=$(mktemp -d -- \"$dir/.qsbw-XXXXXXXX\")",
    "trap 'rm -rf -- \"$work\"' EXIT HUP INT TERM",
    "tmp=\"$work/part\"",

    // RLIMIT_FSIZE stops an oversized write mid-transfer.
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

    // Backstop in case the rlimit was not applied.
    "got=$(wc -c < \"$tmp\" 2>/dev/null || echo 0)",
    "if [ \"$got\" -gt \"$max\" ]; then",
    "  echo 'Attachment exceeded the " + maxMb + " MB download limit.' >&2; exit 1",
    "fi",

    // Probe hard-link support once rather than guess from a failure.
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
    // No hard links (some removable/FUSE filesystems): mv -n after rejecting
    // an existing entry or dangling symlink.
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
  // Its own process group, so cancelling on lock reaches bw, timeout and the
  // cleanup trap.
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
    middleName: String(identity.middleName || ""),
    lastName: String(identity.lastName || ""),
    username: String(identity.username || ""),
    company: String(identity.company || ""),
    email: String(identity.email || ""),
    phone: String(identity.phone || ""),
    ssn: String(identity.ssn || ""),
    passportNumber: String(identity.passportNumber || ""),
    licenseNumber: String(identity.licenseNumber || ""),
    address1: String(identity.address1 || ""),
    address2: String(identity.address2 || ""),
    address3: String(identity.address3 || ""),
    city: String(identity.city || ""),
    state: String(identity.state || ""),
    postalCode: String(identity.postalCode || ""),
    country: String(identity.country || "")
  }
}

// Title and names, skipping empty parts.
function identityFullName(identity) {
  if (!identity) return ""
  return nonEmptyParts([identity.title, identity.firstName, identity.middleName, identity.lastName]).join(" ")
}

// The trimmed, non-empty strings among `parts`.
function nonEmptyParts(parts) {
  return parts.map(function(part) { return String(part || "").trim() })
    .filter(function(part) { return part !== "" })
}

// Linked fields point at one of the cipher's own fields by Bitwarden's
// LinkedIdType id. Resolve the value for display; linkedId is kept for edits.
function linkedCustomFieldValue(item, linkedId) {
  var it = item || {}
  var login = it.login || {}
  var card = it.card || {}
  var identity = it.identity || {}
  var id = Number(linkedId)
  var values = {
    100: login.username, 101: login.password,
    300: card.cardholderName, 301: card.expMonth, 302: card.expYear,
    303: card.code, 304: card.brand, 305: card.number,
    400: identity.title, 401: identity.middleName,
    402: identity.address1, 403: identity.address2, 404: identity.address3,
    405: identity.city, 406: identity.state, 407: identity.postalCode,
    408: identity.country, 409: identity.company, 410: identity.email,
    411: identity.phone, 412: identity.ssn, 413: identity.username,
    414: identity.passportNumber, 415: identity.licenseNumber,
    416: identity.firstName, 417: identity.lastName,
    418: identityFullName(identity)
  }
  var value = values[id]
  return value === undefined || value === null ? "" : String(value)
}

function linkedCustomFieldIsSensitive(linkedId) {
  var id = Number(linkedId)
  return id === 101 || id === 303 || id === 305
    || id === 412 || id === 414 || id === 415
}

function itemCustomFields(fields, item) {
  var customFields = []
  var rawFields = toList(fields)
  for (var i = 0; i < rawFields.length; i++) {
    var field = rawFields[i]
    if (!field || !field.name) continue
    var type = Number(field.type || 0)
    var linkedId = field.linkedId === undefined || field.linkedId === null
      ? null : Number(field.linkedId)
    customFields.push({
      name: String(field.name || ""),
      // Keep an explicit boolean false.
      value: type === 3
        ? linkedCustomFieldValue(item, linkedId)
        : (field.value === undefined || field.value === null ? "" : String(field.value)),
      type: type, // 0: text, 1: hidden, 2: boolean, 3: linked
      linkedId: linkedId,
      sensitive: type === 1 || (type === 3 && linkedCustomFieldIsSensitive(linkedId))
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

    var identity = it.identity || null
    var identitySubtitle = ""
    if (identity) {
      identitySubtitle = identityFullName(identity) || String(identity.email || "")
    }

    var subtitle = ""
    if (login.username) {
      subtitle = String(login.username)
    } else if (uris.length > 0) {
      subtitle = uris[0].replace(/^https?:\/\//, "").replace(/\/.*$/, "")
    } else if (cardSubtitle) {
      subtitle = cardSubtitle
    } else if (identitySubtitle) {
      subtitle = identitySubtitle
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
      // So search can match what the subtitle shows (card brand/last four,
      // identity name/email).
      card: cardDetail(it.card),
      identity: identityDetail(it.identity),
      notes: String(it.notes || ""),
      rawObject: it
    })
  }

  out.sort(compareItems)

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
  out.sort(compareItems)
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
  items.sort(compareItems)
  return {
    items: items,
    sshKeys: sshKeys,
    sshCapability: expectedCapability
  }
}

// The row shown while a save is in flight, built from the payload through
// parseItems so it has the same shape as the real row that replaces it. A
// create gets a provisional id with this prefix (vault ids are UUIDs).
var PENDING_ID_PREFIX = "qsbw-pending:"

function pendingItemId(seed) { return PENDING_ID_PREFIX + String(seed) }
function isPendingItemId(id) { return String(id || "").indexOf(PENDING_ID_PREFIX) === 0 }

function findItemById(items, id) {
  var existing = toList(items)
  for (var i = 0; i < existing.length; i++) {
    if (existing[i] && existing[i].id === id) return existing[i]
  }
  return null
}

function optimisticItem(payload, itemId) {
  if (!payload) return null
  var draft = JSON.parse(JSON.stringify(payload))
  draft.id = String(itemId || "")
  draft.object = "item"
  var parsed = parseItems(JSON.stringify([draft]))
  if (parsed.length !== 1) return null
  parsed[0].pending = true
  return parsed[0]
}

// Replace-or-insert by id (or remove, with no replacement), then sort.
function replaceItemById(items, id, replacement) {
  var out = []
  var existing = toList(items)
  var replaced = false
  for (var i = 0; i < existing.length; i++) {
    if (existing[i] && existing[i].id === id) {
      if (replacement) out.push(replacement)
      replaced = true
    } else {
      out.push(existing[i])
    }
  }
  if (!replaced && replacement) out.push(replacement)
  out.sort(compareItems)
  return out
}

function savedUnsanitizedMarker() { return SAVED_UNSANITIZED_MARKER }

// Puts the item a save returned into the list. null if the output is not a
// sanitized envelope; the caller then reloads.
function spliceSavedItem(items, raw, replacingId) {
  var envelope = parseSanitizedEnvelope(raw)
  if (!envelope) return null
  var saved = envelope.items.concat(envelope.sshKeys)
  if (saved.length !== 1) return null
  var one = saved[0]
  if (!one || !one.id) return null

  // On a create, `replacingId` is the provisional row's id.
  return replaceItemById(items, replacingId ? String(replacingId) : one.id, one)
}

function parseSanitizedItems(raw) {
  var envelope = parseSanitizedEnvelope(raw)
  return envelope ? envelope.items : []
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

// The list already holds each full cipher as `rawObject`, so the detail view
// is built from it without a slow `bw get item`.
function itemDetailFromObject(it) {
  if (!it || typeof it !== "object") return null

  if (Number(it.type) === 5) {
    var sshKey = it.sshKey || {}
    return { id: String(it.id || ""), organizationId: it.organizationId ? String(it.organizationId) : null,
      folderId: it.folderId ? String(it.folderId) : null, name: String(it.name || "Untitled"),
      type: "sshKey", typeCode: 5, favorite: Boolean(it.favorite), notes: "",
      username: "", password: "", hasPassword: false, hasTotp: false, totpKey: "", uris: [], attachments: [],
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
    // The password row's `visible` binding reads this.
    hasPassword: Boolean(login.password),
    hasTotp: Boolean(login.totp),
    totpKey: String(login.totp || ""),
    uris: uris,
    attachments: attachments,
    hasAttachments: attachments.length > 0,
    card: cardDetail(it.card),
    identity: identityDetail(it.identity),
    fields: itemCustomFields(it.fields, it),
    rawObject: it
  }
}

// -------------------------------------------------------------------------
// Filtering and search
// -------------------------------------------------------------------------

function matchesQuery(item, query) {
  if (!query) return true
  var q = String(query).toLowerCase().trim()
  if (!q) return true

  var has = function(value) { return String(value || "").toLowerCase().indexOf(q) !== -1 }
  if (has(item.name) || has(item.username) || has(item.notes)
      || has(item.publicKey) || has(item.fingerprint)) return true

  // Match what card and identity rows display; for a card number, only the
  // last four digits.
  if (item.card) {
    if (has(item.card.brand) || has(item.card.cardholderName)) return true
    var digits = String(item.card.number || "").replace(/\D/g, "")
    if (digits.length >= 4 && digits.slice(-4).indexOf(q.replace(/\D/g, "")) !== -1
        && q.replace(/\D/g, "") !== "") return true
  }
  if (item.identity) {
    if (has(identityFullName(item.identity)) || has(item.identity.email)
        || has(item.identity.username) || has(item.identity.company)) return true
  }

  // toList: arrays read back from QML are not real arrays.
  var uris = toList(item.uris)
  for (var i = 0; i < uris.length; i++) {
    if (has(uris[i])) return true
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
function validateItemForm(name, organizationId, collectionIds, customFields) {
  if (!String(name || "").trim()) return "Item title is required"
  var isOrg = organizationId && organizationId !== "personal" && organizationId !== "all"
  if (isOrg && (!Array.isArray(collectionIds) || collectionIds.length === 0)) {
    return "Pick at least one collection for an organization item"
  }
  var fields = toList(customFields)
  for (var i = 0; i < fields.length; i++) {
    if (!fields[i] || !String(fields[i].name || "").trim()) {
      return "Custom field " + (i + 1) + " needs a label"
    }
  }
  return ""
}

function maskString(str) {
  if (!str) return ""
  return "•".repeat(Math.min(str.length, 16))
}

// No local password generator: Math.random() is not a CSPRNG. Passwords come
// from `bw generate` via generateCommand().

// -------------------------------------------------------------------------
// Create and edit payloads
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

// Shared by create and edit. Absent fields are written as "" (not left
// undefined) so a cleared box clears the value.
function updateCardFields(card, fields) {
  var f = fields || {}
  card.cardholderName = String(f.cardholderName || "").trim()
  card.brand = String(f.brand || "").trim()
  card.number = String(f.number || "").trim()
  card.expMonth = String(f.expMonth || "").trim()
  card.expYear = String(f.expYear || "").trim()
  card.code = String(f.code || "").trim()
}

function updateIdentityFields(identity, fields) {
  var f = fields || {}
  var keys = ["title", "firstName", "middleName", "lastName", "username",
              "company", "email", "phone", "ssn", "passportNumber",
              "licenseNumber", "address1", "address2", "address3",
              "city", "state", "postalCode", "country"]
  for (var i = 0; i < keys.length; i++) {
    identity[keys[i]] = String(f[keys[i]] || "").trim()
  }
}

// Drops form-only state and writes values as Bitwarden clients do: booleans as
// "true"/"false", linked fields as a linkedId with a null value.
function customFieldsPayload(fields) {
  var raw = toList(fields)
  var out = []
  for (var i = 0; i < raw.length; i++) {
    var field = raw[i]
    if (!field || !String(field.name || "").trim()) continue
    var type = Number(field.type)
    if (type < 0 || type > 3 || isNaN(type)) type = 0
    var clean = { name: String(field.name), type: type }
    if (type === 3) {
      clean.value = null
      if (field.linkedId !== undefined && field.linkedId !== null) {
        clean.linkedId = Number(field.linkedId)
      }
    } else if (type === 2) {
      clean.value = field.value === true || String(field.value).toLowerCase() === "true"
        ? "true" : "false"
    } else {
      clean.value = field.value === undefined || field.value === null ? "" : String(field.value)
    }
    out.push(clean)
  }
  return out
}

// `typeFields` holds the card or identity fields as one object rather than
// two dozen positional arguments.
function buildCreatePayload(typeCode, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds, typeFields, customFields) {
  if (Number(typeCode) === 5) return null
  var payload = {
    type: Number(typeCode || 1),
    name: String(name || "Untitled").trim(),
    notes: String(notes || "").trim(),
    favorite: Boolean(favorite),
    organizationId: selectedOrganizationId(organizationId),
    folderId: selectedFolderId(folderId)
  }

  // Org items need at least one collection; omit the key when none are chosen.
  var collections = selectedCollectionIds(collectionIds)
  if (payload.organizationId && collections) payload.collectionIds = collections

  if (Number(typeCode) === 1) { // Login
    var login = {}
    updateLoginFields(login, username, password, totp)
    login.uris = uri && uri.trim() ? [{ match: null, uri: uri.trim() }] : []
    payload.login = login
  } else if (Number(typeCode) === 2) { // Secure Note
    payload.secureNote = { type: 0 }
  } else if (Number(typeCode) === 3) { // Card
    payload.card = {}
    updateCardFields(payload.card, typeFields)
  } else if (Number(typeCode) === 4) { // Identity
    payload.identity = {}
    updateIdentityFields(payload.identity, typeFields)
  }

  if (customFields !== undefined) payload.fields = customFieldsPayload(customFields)

  return payload
}

function buildEditPayload(existingItem, name, username, password, totp, uri, notes, favorite, organizationId, folderId, collectionIds, typeFields, customFields) {
  if (existingItem && (Number(existingItem.typeCode || existingItem.type) === 5
      || (existingItem.rawObject && Number(existingItem.rawObject.type) === 5))) return null
  var payload = existingItem && existingItem.rawObject ? JSON.parse(JSON.stringify(existingItem.rawObject)) : {}
  payload.name = String(name || "Untitled").trim()
  payload.notes = String(notes || "").trim()
  payload.favorite = Boolean(favorite)
  // Assign and clear: personal/none must move the item out.
  payload.organizationId = selectedOrganizationId(organizationId)
  payload.folderId = selectedFolderId(folderId)

  if (payload.organizationId) {
    payload.collectionIds = selectedCollectionIds(collectionIds) || payload.collectionIds || []
  } else {
    delete payload.collectionIds
  }

  // The payload is a clone of the stored item, so each branch writes only its
  // own type's fields. `&& typeFields` matters: the writers set every key, so
  // calling one without fields would blank a card or identity on rename.
  if (payload.type === 1 || !payload.type) {
    if (!payload.login) payload.login = {}
    updateLoginFields(payload.login, username, password, totp)
    if (uri && uri.trim()) {
      payload.login.uris = [{ match: null, uri: uri.trim() }]
    }
  } else if (payload.type === 3 && typeFields) {
    if (!payload.card) payload.card = {}
    updateCardFields(payload.card, typeFields)
  } else if (payload.type === 4 && typeFields) {
    if (!payload.identity) payload.identity = {}
    updateIdentityFields(payload.identity, typeFields)
  }

  // undefined leaves the cloned fields alone; any array (even empty) replaces them.
  if (customFields !== undefined) payload.fields = customFieldsPayload(customFields)

  return payload
}

// -------------------------------------------------------------------------
// Context matching
// -------------------------------------------------------------------------
//
// Hyprland exposes only a window's class and title (no tab URL), so the site
// is inferred from the title, refusing to guess when it says nothing useful.

// Labels that carry no identity; ignored in titles and item names.
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

// Accepted hostname suffixes. A closed list, so "config.json" or "v1.2" is not
// read as a domain.
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

// Second-level suffixes, only when a third label follows (bbc.co.uk -> bbc).
var MULTI_SLD = { "co": 1, "com": 1, "net": 1, "org": 1, "ac": 1, "gov": 1, "edu": 1, "or": 1, "ne": 1 }

// Title words that stand for a different registrable name.
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

// Only this much of a title is examined: matching runs over it per vault item,
// and a page controls its own title length.
var MAX_TITLE_CHARS = 512

// Strip browser chrome: brand suffixes, counters, media and private markers,
// leading sign-in verbs.
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

// Names implied only through a brand alias ("Gmail" -> "google"), kept apart
// from literal title tokens.
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
// Split on non-host characters and walk the labels, one linear pass. A
// host-shaped regex backtracks quadratically on long dotless runs, and a page
// controls its own title (60 kB froze the shell for ~2.5 s).
function detectDomainInText(text) {
  var s = String(text || "").toLowerCase()
  var runs = s.split(/[^a-z0-9.\-]+/)
  for (var r = 0; r < runs.length; r++) {
    var labels = runs[r].split(".")
    var group = []
    // Run to one past the end so the final group is closed by the same branch.
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
  // toList: see matchesQuery.
  var uris = toList(item.uris)
  for (var i = 0; i < uris.length; i++) {
    var d = parseDomain(uris[i])
    if (d) out.push(d)
  }
  return out
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")
}

function hasWholeWord(haystack, word) {
  if (!haystack || !word) return false
  var escaped = escapeRegExp(word)
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
    // Only remote sessions; a local shell title describes this machine.
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

  // Remove the title's hostname so its labels do not match as free words,
  // then add back its registrable name.
  var matchText = cleanTitle
  if (detectedDomain) {
    matchText = matchText.replace(new RegExp(escapeRegExp(detectedDomain.host), "gi"), " ").trim()
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

// Score one item against the window; 0 is no match. Bands are spread so a
// domain hit always outranks a word hit.
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
  // Learned picks come first and bypass the score bands.
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

  // Keep only the strongest band: a domain hit drops word-only matches but
  // keeps other accounts on the same site.
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
// Learned associations
// -------------------------------------------------------------------------
//
// Some sites cannot be matched from their title at all, so picking an item
// records the window's keys against it and the next visit suggests it first.

var ASSOC_VERSION = 1
var ASSOC_ENV = "QSBW_ASSOC"
var ASSOC_DIR = "${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli"

function associationsEnvVar() {
  return ASSOC_ENV
}

// One file per account slot: item ids mean nothing in another vault.
function associationsFileName(slot) {
  var s = accountSlot(slot)
  return s === DEFAULT_ACCOUNT_SLOT ? "associations.json" : "associations@" + s + ".json"
}

function associationsReadCommand(slot) {
  var script = "d=\"" + ASSOC_DIR + "\"; f=\"$d/" + associationsFileName(slot) + "\"; "
    + "if [ -d \"$d\" ] && [ ! -L \"$d\" ] && [ -f \"$f\" ] && [ ! -L \"$f\" ]; then "
    + "head -c " + MAX_ASSOC_BYTES + " \"$f\" 2>/dev/null || printf '{}'; else printf '{}'; fi"
  return ["bash", "-c", script]
}

// Payload in the environment (Process.write() cannot send EOF).
function associationsWriteCommand(slot) {
  // Write a private temp file and rename it, so a symlink is replaced, not
  // followed, and the file is always 0600.
  var script = "set -e; d=\"" + ASSOC_DIR + "\"; "
    + privateDirScript("d")
    + "umask 077; tmp=$(mktemp -- \"$d/.associations.XXXXXXXX\"); "
    + "trap 'rm -f -- \"$tmp\"' EXIT HUP INT TERM; "
    + "printf '%s' \"$" + ASSOC_ENV + "\" > \"$tmp\"; chmod 600 \"$tmp\"; "
    + "mv -fT -- \"$tmp\" \"$d/" + associationsFileName(slot) + "\"; trap - EXIT HUP INT TERM"
  return ["bash", "-c", script]
}

// Cleared on logout: it records the sites the account has credentials for.
// The panel waits for any in-flight write first so it cannot recreate the file.
function associationsClearCommand(slot) {
  var script = "d=\"" + ASSOC_DIR + "\"; "
    + "if [ -d \"$d\" ] && [ ! -L \"$d\" ]; then rm -f -- \"$d/" + associationsFileName(slot) + "\" 2>/dev/null; fi; exit 0"
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

// A window's keys, strongest first: domain, app class, then title words (the
// weak fallback for sites with no domain in the title).
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

// Write budget, half the read cap: a store truncated by the read cap fails to
// parse and would be replaced by an empty one, and a page's title words can
// grow it.
var MAX_ASSOC_WRITE_BYTES = MAX_ASSOC_BYTES / 2

// Last pick wins, so a key learned from the wrong page corrects itself.
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

// Keeps the newest entries within budget; entries without a timestamp go first.
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

// Whether the context already resolves to this item.
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
// Dependency checks (setup)
// -------------------------------------------------------------------------
//
// Only tools an Omarchy install can actually lack; the rest (wl-clipboard,
// libsecret, glib2, systemd, openssl...) ship with it. Probed in one process.
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
    // Set up by `omarchy setup security fingerprint` (packages, enrolment,
    // PAM), not a package install: `ready` needs an enrolled finger too.
    key: "fprintd", label: "Fingerprint unlock", binary: "fprintd-list", pkg: "fprintd", aur: false,
    required: false, setup: true,
    // Only shown on a machine with a reader; see `applicable` below.
    purpose: "Unlock the vault with your finger. Omarchy installs the reader stack and enrols you in one step."
  }
]

// One round trip: `key=1|0` per tool, the bw binary's identity and
// fingerprint state. It runs on every panel open, so it must stay cheap: the
// version (a ~1.2 s Node start) is bwVersionCommand(), asked again only when
// `bw_id` changes.
function dependencyCheckCommand() {
  var parts = []
  for (var i = 0; i < DEPENDENCIES.length; i++) {
    var d = DEPENDENCIES[i]
    parts.push("if command -v " + d.binary + " >/dev/null 2>&1; then echo "
      + shellQuote(d.key + "=1") + "; else echo " + shellQuote(d.key + "=0") + "; fi")
  }
  // Device, inode, size and mtime of the resolved file: an upgrade or a
  // different bw on PATH changes it.
  parts.push("if __qsbw_bw=$(command -v bw 2>/dev/null); then "
    + "printf 'bw_id=%s\\n' \"$(stat -L -c '%d:%i:%s:%Y' -- \"$__qsbw_bw\" 2>/dev/null | head -c 128)\"; "
    + "else echo bw_id=; fi")
  parts.push("if [ -f /etc/pam.d/omarchy-lock-fingerprint ] && command -v fprintd-list >/dev/null 2>&1 "
    + "&& fprintd-list \"$USER\" 2>/dev/null | grep -qi finger; then echo fingerprint_ready=1; else echo fingerprint_ready=0; fi")
  // Reader detection via sysfs, which works before anything is installed, so
  // machines without a reader are not offered fingerprint unlock.
  parts.push("if command -v omarchy-hw-fingerprint >/dev/null 2>&1 && omarchy-hw-fingerprint >/dev/null 2>&1; "
    + "then echo fingerprint_hw=1; else echo fingerprint_hw=0; fi")
  parts.push("if command -v omarchy >/dev/null 2>&1; then echo omarchy=1; else echo omarchy=0; fi")
  return ["bash", "-c", cappedScript("{ " + parts.join("; ") + "; } | head -c 4096")]
}

// Only a strict calendar-version token reaches QML.
function bwVersionCommand() {
  var script = "__qsbw_bw_version=$(bw -v 2>/dev/null | head -c 64); "
    + "if [[ \"$__qsbw_bw_version\" =~ ^v?[0-9]{4}\\.[0-9]{1,2}\\.[0-9]{1,6}$ ]]; then "
    + "printf 'bw_version=%s\\n' \"$__qsbw_bw_version\"; else echo bw_version=; fi"
  return ["bash", "-c", cappedScript("{ " + script + "; } | head -c 4096")]
}

function probeFields(raw) {
  var found = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    var cut = line.indexOf("=")
    if (cut <= 0) continue
    found[line.slice(0, cut)] = line.slice(cut + 1)
  }
  return found
}

// The bw binary's identity from dependencyCheckCommand(), or "" if unknown.
function dependencyBwId(raw) {
  var id = String(probeFields(raw)["bw_id"] || "").trim()
  return /^[0-9]{1,20}(:[0-9]{1,20}){3}$/.test(id) ? id : ""
}

function parseBwVersionProbe(raw) {
  return normalizeReleaseVersion(probeFields(raw)["bw_version"])
}

// `probedVersion` is the result of bwVersionCommand(); null while it has not
// answered for this binary, which leaves SSH support "checking". A
// `bw_version` line in `raw` itself takes precedence.
function parseDependencies(raw, probedVersion) {
  var found = probeFields(raw)

  var inline = found["bw_version"] !== undefined
  var pending = !inline && (probedVersion === null || probedVersion === undefined)
  var bwVersionRaw = String(inline ? found["bw_version"] : (probedVersion || "")).trim()
  var bwVersion = normalizeReleaseVersion(bwVersionRaw)
  var sshCliStatus = "missing"
  if (found["bw"] === "1") sshCliStatus = pending ? "checking" : sshCliSupport(bwVersion)

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
      // Offer Omarchy's setup command instead of a package install.
      setup: Boolean(dep.setup),
      // Missing hardware is not a missing dependency.
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
    bwId: dependencyBwId(raw),
    sshCliMinVersion: SSH_CLI_MIN_VERSION,
    sshCliStatus: sshCliStatus
  }
}

// The rows the setup screen draws; `items` keeps them all for lookups by key.
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

// SSH UI shows only once the probe confirmed a supporting CLI; an unknown
// version counts as unsupported.
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

// "supported" | "unsupported" | "unknown" for a probed `bw --version`.
function sshCliSupport(version) {
  var normalized = normalizeReleaseVersion(version)
  if (!normalized) return "unknown"
  return compareReleaseVersions(normalized, SSH_CLI_MIN_VERSION) < 0 ? "unsupported" : "supported"
}

function vaultListFailureMessage(stderrText, deps, mode) {
  if (mode === "blocked") return vaultListBlockedMessage(deps)
  // Never echo the failed read's output (it can quote decrypted values); only
  // the already-probed version adds detail.
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
// The companion holds decrypted private keys, so the panel supervises it: a
// tracked Process with stdin held open, stdout parsed line by line, and an
// environment of just XDG_RUNTIME_DIR. Everything here is pure; the panel
// owns the Process, timers and clock. The signing gate opens only on a
// well-formed v1 `ready` answering `hello`, and closes on anything else.

// MAX_CONTROL_LINE in the companion, enforced on its output too.
var SSH_AGENT_CONTROL_VERSION = 1
var SSH_AGENT_MAX_LINE_BYTES = 64 * 1024

// How long a started helper has to answer `hello`.
var SSH_AGENT_HANDSHAKE_TIMEOUT_MS = 5000
var SSH_AGENT_BACKOFF_BASE_MS = 500
var SSH_AGENT_BACKOFF_MAX_MS = 30000
var SSH_AGENT_MAX_RESTARTS = 5
// Cap on `sshAgentApprovalWindowSec`: a grant lets a program sign without
// asking, so this is a security bound.
var SSH_AGENT_APPROVAL_WINDOW_MAX_SEC = 900
// A run this long counts as healthy and resets the failure count, so only
// consecutive quick deaths reach the restart cap.
var SSH_AGENT_HEALTHY_MS = 60 * 1000

// Messages the companion may send; anything else is a version mismatch.
var SSH_AGENT_EVENT_TYPES = [
  "ready", "unlock_required", "approval_required", "request_cancelled",
  "keys_loaded", "public_key", "locked", "load_failed", "grants_changed", "state_changed", "error"
]

function sshAgentMaxLineBytes() { return SSH_AGENT_MAX_LINE_BYTES }
function sshAgentMaxRestarts() { return SSH_AGENT_MAX_RESTARTS }
function sshAgentHandshakeTimeoutMs() { return SSH_AGENT_HANDSHAKE_TIMEOUT_MS }

// The plugin directory from QML's `file://` URL. It is the base of the only
// executable launched by path, so it must be absolute with no traversal
// segment (literal or percent-encoded); otherwise "" disables the helper.
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
  return cleanAbsoluteDir(decoded)
}

// `dir` without trailing slashes, or "" unless it is absolute with no "." or
// ".." segment.
function cleanAbsoluteDir(dir) {
  if (typeof dir !== "string" || dir.charAt(0) !== "/") return ""
  var base = dir
  while (base.length > 1 && base.charAt(base.length - 1) === "/") base = base.slice(0, -1)
  var parts = base.split("/")
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === "." || parts[i] === "..") return ""
  }
  return base
}

// Run directly, not via `bash -c`, so closing stdin and killing the Process
// reach the process holding the keys.
function sshAgentHelperCommand(pluginDir, source) {
  var path = helperPath(pluginDir, SSH_AGENT_HELPER_SPEC, source)
  return path ? [path] : []
}

// The helper's whole environment (with `clearEnvironment: true`): it only
// needs XDG_RUNTIME_DIR, and no credential can leak into it.
function sshAgentHelperEnv(runtimeDir) {
  if (typeof runtimeDir !== "string" || runtimeDir.charAt(0) !== "/") return null
  return { XDG_RUNTIME_DIR: runtimeDir }
}

// One control-protocol line to the companion: {v, type, ...fields}.
function agentControlLine(type, fields) {
  var message = { v: SSH_AGENT_CONTROL_VERSION, type: type }
  for (var k in fields) message[k] = fields[k]
  return JSON.stringify(message) + "\n"
}

function agentEpoch(epoch) { return Math.floor(Number(epoch)) || 0 }

function sshAgentHelloLine() {
  return agentControlLine("hello")
}

function sshAgentShutdownLine() {
  return agentControlLine("shutdown")
}

// Bytes, not UTF-16 units, to match the companion's cap.
function utf8ByteLength(text) {
  // Bytes >= UTF-16 units, so skip counting a line already over the cap.
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

// One line of companion stdout: {ok:true, message} or {ok:false, code,
// fatal}. Only a blank line (SplitParser's remainder) is non-fatal; anything
// not a well-formed v1 known-type object closes the gate.
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

// 500 ms doubling to 30 s: quick for a helper replaced under a running shell,
// bounded for a broken build.
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
// SSH_AUTH_SOCK is how clients find an agent; the companion ignores it.
// Routing is advisory: the panel sees only the graphical session's
// environment, not shell rc files, TTYs or SSH sessions.

// Retry interval while another process (usually another shell mid-restart)
// holds the agent's runtime lock. Not a failure, so no backoff.
var SSH_AGENT_ELSEWHERE_RETRY_MS = 30 * 1000

// Whether another process holds the helper's runtime lock (the helper exits 1
// for every startup failure). Tests the file first, since flock(1) would
// create it; never follows a symlink. Exit 75: held.
function sshAgentLockProbeCommand(runtimeDir) {
  var lock = runtimeFilePath(runtimeDir, "ssh-agent.lock")
  if (!lock) return null
  return ["bash", "-c",
    "[ -f \"$1\" ] && [ ! -L \"$1\" ] || exit 0; exec flock -n -E 75 \"$1\" true",
    "_", lock]
}

// Removes the helper's runtime files once nothing holds its lock, as its own
// shutdown would. For a helper killed with the shell objects (plugin disabled
// or removed), which cannot clean up after itself. Run detached; waits up to
// 5 s for the lock and deletes while holding it, so a helper starting
// meanwhile cannot lose a fresh socket. Never follows a symlink.
function sshAgentRuntimeCleanupCommand(runtimeDir) {
  var dir = runtimeFilePath(runtimeDir, "")
  if (!dir) return null
  return ["bash", "-c",
    "d=\"${1%/}\"; l=\"$d/ssh-agent.lock\"; "
    + "[ -d \"$d\" ] && [ ! -L \"$d\" ] && [ -f \"$l\" ] && [ ! -L \"$l\" ] || exit 0; "
    + "for _ in $(seq 50); do "
    + "flock -n -E 75 \"$l\" rm -f -- \"$d/ssh-agent.sock\" \"$d/ssh-keys.fifo\" \"$l\"; "
    + "[ $? -eq 75 ] || { rmdir -- \"$d\" 2>/dev/null; exit 0; }; sleep 0.1; done",
    "_", dir]
}

function sshAgentLockHeld(exitCode) {
  return Number(exitCode) === 75
}

// `name` in the plugin's runtime directory, or "" without an absolute runtimeDir.
function runtimeFilePath(runtimeDir, name) {
  if (typeof runtimeDir !== "string" || runtimeDir.charAt(0) !== "/") return ""
  return runtimeDir + "/" + RUNTIME_SUBDIR + "/" + name
}

function sshAgentSocketPath(runtimeDir) { return runtimeFilePath(runtimeDir, "ssh-agent.sock") }
function sshAgentFifoPath(runtimeDir) { return runtimeFilePath(runtimeDir, "ssh-keys.fifo") }

// Per-load nonce, so no other same-UID process can inject keys into the FIFO.
// Sent to the companion on stdin and to jq in the environment, never argv.
var LOAD_ID_ENV = "QSBW_LOAD_ID"
var LOAD_ID_RE = /^[0-9a-f]{32}$/

function loadIdEnvVar() { return LOAD_ID_ENV }

function isValidLoadId(value) {
  return typeof value === "string" && LOAD_ID_RE.test(value)
}

// 128 bits from the kernel CSPRNG.
function loadIdCommand() {
  var script = "LC_ALL=C od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n'"
  return ["bash", "-c", script]
}

function sshAgentLoadBeginLine(epoch, loadId) {
  if (!isValidLoadId(loadId)) return ""
  return agentControlLine("key_load_begin", { epoch: agentEpoch(epoch), loadId: loadId })
}

function sshAgentLoadEndLine(epoch, ok) {
  return agentControlLine("key_load_end", { epoch: agentEpoch(epoch), status: ok ? "ok" : "failed" })
}

function sshAgentVaultLockedLine(epoch) {
  return agentControlLine("vault_locked", { epoch: agentEpoch(epoch) })
}

function sshAgentLoggedOutLine() {
  return agentControlLine("vault_logged_out")
}

// UWSM reads env.d fragments at login. The plugin owns one file, recognised by
// its exact contents, never by name alone.
var UWSM_FRAGMENT_REL = ".config/uwsm/env.d/50-qs-bitwarden-ssh-agent"

function uwsmFragmentDisplayPath() {
  return "~/" + UWSM_FRAGMENT_REL
}

// ${XDG_RUNTIME_DIR} is expanded at login, not now.
function uwsmFragmentContent() {
  return "# Managed by the qs-bitwarden-cli Quickshell plugin.\n"
    + "# Routes SSH clients to the Bitwarden agent. Delete this file to stop.\n"
    + "export SSH_AUTH_SOCK=\"${XDG_RUNTIME_DIR}/" + RUNTIME_SUBDIR + "/ssh-agent.sock\"\n"
}

// Exit codes of the write and remove scripts, read by parseUwsmActionResult().
var UWSM_EXIT_NO_HOME = 3
var UWSM_EXIT_PARENT = 4
var UWSM_EXIT_SYMLINK = 5
var UWSM_EXIT_FOREIGN = 6
var UWSM_EXIT_WRITE = 7

// `$(cat)` strips trailing newlines, so the expected content is compared
// stripped too.
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

// Removes everything the plugin stores outside its folder (keyring, state,
// data), since `omarchy plugin remove` has no uninstall hook. Leaves bw's own
// sign-in (the default account) and shell.json alone; the other accounts'
// sign-ins live in the plugin's data and go with it.
function pluginDataRemoveCommand() {
  var script = "test -n \"${HOME:-}\" || exit " + PLUGIN_DATA_EXIT_NO_HOME + "; "
    + "__state=\"${XDG_STATE_HOME:-$HOME/.local/state}/qs-bitwarden-cli\"; "
    + "__data=\"${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli\"; "
    // Each step reports independently; one failing does not stop the rest.
    + "__done=''; "
    + "if secret-tool clear service qs-bitwarden-cli 2>/dev/null; then __done=\"$__done keyring\"; fi; "
    + "if [ -e \"$__state\" ]; then rm -rf -- \"$__state\" && __done=\"$__done state\"; fi; "
    + "if [ -d \"$__data/accounts\" ] && [ ! -L \"$__data/accounts\" ] "
    + "&& find \"$__data/accounts\" -mindepth 1 -maxdepth 1 -type d -name '????????????????' | grep -q .; "
    + "then __done=\"$__done accounts\"; fi; "
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
  if (line.indexOf("accounts") >= 0) cleared.push("the sign-ins of accounts added in the panel")
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

// The status line about routing, judged by the fragment file (what the next
// login will get), not by this session's SSH_AUTH_SOCK (fixed at login).
function sshAgentRoutingNotice(fragment, routing) {
  var fragmentState = fragment && fragment.state ? String(fragment.state) : "unknown"
  var routingState = routing && routing.state ? String(routing.state) : "unknown"
  // Those states are explained in full in the routing section.
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

// Most specific first: this plugin's socket also contains "bitwarden".
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

// Descriptive only; never a prerequisite.
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
// Shipped helpers are checked before use: present, executable, right
// architecture, matching checksum, passing self-test, matching protocol.
// SHA256SUMS sits beside the binary, so it catches stale or incomplete files,
// not tampering; provenance is covered by the release attestation.
var SSH_AGENT_BUNDLED_RELATIVE = "bin/x86_64-linux/qs-bitwarden-ssh-agent"
var SSH_AGENT_SUMS_RELATIVE = "bin/SHA256SUMS"
// Cargo's debug build, used when the shipped binary is absent or unusable;
// the settings screen names which one is running.
var SSH_AGENT_DEVELOPMENT_RELATIVE = "agent/target/debug/qs-bitwarden-ssh-agent"

// In preference order: shipped artifact, then local build.
function helperCandidates(pluginDir, spec) {
  var root = cleanAbsoluteDir(pluginDir)
  if (!root) return []
  return [
    { source: "bundled", path: root + "/" + spec.bundled },
    { source: "development", path: root + "/" + spec.development }
  ]
}

// The absolute path of the candidate the inspection accepted, or "". Never a
// guess: an unaccepted source launches nothing.
function helperPath(pluginDir, spec, source) {
  var candidates = helperCandidates(pluginDir, spec)
  for (var i = 0; i < candidates.length; i++) {
    if (candidates[i].source === source) return candidates[i].path
  }
  return ""
}

// Banner text when a local build serves SSH keys: it has no digest or
// provenance. Says whether the shipped one was rejected or just absent; the
// fix is to reinstall the plugin.
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

// Checks both candidates in one shell and reports the first usable one as
// `key=value` lines; none of the helper's own output reaches a message.
// `spec` gives the binary name, candidate paths and the sed expression that
// reads its protocol version from `--version`.
function helperInspectCommand(pluginDir, spec) {
  var root = cleanAbsoluteDir(pluginDir)
  if (!root) return ["bash", "-c", "echo state=missing"]
  // The binary's line in SHA256SUMS: its path relative to bin/, exactly.
  var sumsPath = spec.bundled.replace(/^bin\//, "")
  var sumsLine = "^[0-9a-f]{64}  " + sumsPath.replace(/[.]/g, "\\.") + "$"

  var script = "__root=" + shellQuote(root) + "; "
    + "__report() { printf '%s\\n' \"$@\"; exit 0; }; "
    + "__found=''; "
    // Shipped first; a local build only if that is absent or unusable.
    + "for __pair in " + shellQuote("bundled:" + spec.bundled)
    + " " + shellQuote("development:" + spec.development) + "; do "
    + "  __source=\"${__pair%%:*}\"; __rel=\"${__pair#*:}\"; __bin=\"$__root/$__rel\"; "
    + "  [ -e \"$__bin\" ] || continue; "
    + "  __found=\"$__source\"; "
    + "  [ -f \"$__bin\" ] || { __state=not-a-file; continue; }; "
    + "  [ -x \"$__bin\" ] || { __state=not-executable; continue; }; "
    // ELF magic first, so LFS placeholders and truncated files fail clearly.
    + "  __magic=\"$(head -c 4 -- \"$__bin\" 2>/dev/null | od -An -tx1 | tr -d ' \\n')\"; "
    + "  [ \"$__magic\" = \"7f454c46\" ] || { __state=not-elf; continue; }; "
    + "  __arch=\"$(od -An -tx1 -j 18 -N 1 -- \"$__bin\" 2>/dev/null | tr -d ' \\n')\"; "
    + "  [ \"$__arch\" = \"3e\" ] || { __state=wrong-architecture; continue; }; "
    // Shipped artifact only, and only its own SHA256SUMS line, so one stale
    // helper cannot disable the other. A missing line is a mismatch.
    + "  __checksum=unchecked; "
    + "  if [ \"$__source\" = bundled ] && [ -f \"$__root/" + SSH_AGENT_SUMS_RELATIVE + "\" ]; then "
    + "    __line=\"$(grep -E " + shellQuote(sumsLine) + " \"$__root/" + SSH_AGENT_SUMS_RELATIVE + "\" | head -1)\"; "
    + "    if [ -n \"$__line\" ] && ( cd \"$__root/bin\" && printf '%s\\n' \"$__line\" | sha256sum -c --status ) 2>/dev/null; then "
    + "      __checksum=match; "
    + "    else __checksum=mismatch; __state=checksum-mismatch; continue; fi; "
    + "  fi; "
    // Bounded, so a hung helper cannot stall startup.
    + "  __version=\"$(timeout 5 \"$__bin\" --version 2>/dev/null | head -c 200)\"; "
    + "  case \"$__version\" in *" + shellQuote(spec.name + " ") + "*) ;; *) __state=no-version; continue;; esac; "
    + "  __semver=\"$(printf '%s' \"$__version\" | sed -n " + shellQuote("s/.*" + spec.name + " \\([0-9.]*\\).*/\\1/p") + ")\"; "
    + "  __proto=\"$(printf '%s' \"$__version\" | sed -n " + shellQuote(spec.protocolSed) + ")\"; "
    + "  if timeout 20 \"$__bin\" --self-test >/dev/null 2>&1; then __self=pass; "
    + "  else __self=fail; __state=self-test-failed; continue; fi; "
    + "  __report state=ok \"source=$__source\" \"version=$__semver\" \"protocol=$__proto\" "
    + "\"checksum=$__checksum\" \"selfTest=$__self\"; "
    + "done; "
    + "if [ -z \"$__found\" ]; then __report state=missing; fi; "
    // Keep the checksum verdict in failures, so "mismatch" is not "unchecked".
    + "__report \"state=${__state:-unusable}\" \"source=$__found\" "
    + "\"checksum=${__checksum:-unchecked}\" \"selfTest=${__self:-}\""
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

var SSH_AGENT_HELPER_SPEC = {
  name: "qs-bitwarden-ssh-agent",
  bundled: SSH_AGENT_BUNDLED_RELATIVE,
  development: SSH_AGENT_DEVELOPMENT_RELATIVE,
  protocolSed: "s/.*protocol \\([0-9]*\\).*/\\1/p"
}

function sshAgentHelperInspectCommand(pluginDir) {
  return helperInspectCommand(pluginDir, SSH_AGENT_HELPER_SPEC)
}

// A helper's state before its inspection has run.
function uninspectedHelper() {
  return { state: "unknown", source: "", version: "", protocol: 0,
    checksum: "unchecked", selfTest: "", message: "" }
}

// Parses the inspection lines; the panel, not the script, judges the protocol.
function parseHelperInspection(raw, expectedProtocol, messages) {
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
  if (fields.state === "ok" && fields.protocol !== expectedProtocol) {
    fields.state = "protocol-mismatch"
  }
  fields.message = fields.state === "ok" ? "" : (messages[fields.state] || messages.unusable)
  return fields
}

// User-facing text for each failed inspection state of a helper.
function helperMessages(noun, manifest, protocolMismatch) {
  var the = "The " + noun
  return {
    "missing": the + " was not found. A release ships one; a source checkout needs "
      + "`cargo build --manifest-path " + manifest + " --locked`.",
    "not-a-file": the + " path is not a file.",
    "not-executable": the + " is not executable. A clone from an archive can drop "
      + "file modes; `chmod +x` on it is enough.",
    "not-elf": the + " is not a program. A partial clone, or Git LFS leaving a "
      + "placeholder, both look like this.",
    "wrong-architecture": the + " was built for a different architecture. This "
      + "release ships x86_64 only.",
    "checksum-mismatch": the + " does not match its recorded checksum. That usually "
      + "means a stale binary after an update, or an incomplete clone.",
    "no-version": the + " did not report a usable version.",
    "self-test-failed": the + " failed its own self-test on this machine.",
    "protocol-mismatch": the + " " + protocolMismatch + " than this version of the plugin. "
      + "Reinstall the plugin so both come from the same release.",
    "unusable": the + " could not be used."
  }
}

var SSH_AGENT_HELPER_MESSAGES = helperMessages("SSH agent helper", "agent/Cargo.toml",
  "speaks a different control protocol")

function parseSshAgentHelperInspection(raw) {
  return parseHelperInspection(raw, SSH_AGENT_CONTROL_VERSION, SSH_AGENT_HELPER_MESSAGES)
}

// Whether a helper passed inspection. A failure disables only its feature.
function helperReady(inspection) {
  return Boolean(inspection) && inspection.state === "ok"
}

// -------------------------------------------------------------------------
// The quick-unlock tool
// -------------------------------------------------------------------------
//
// `qs-bitwarden-unlock-key` encrypts the master password under keys from
// argon2, fido2-assert and systemd-creds. Shipped and inspected like the SSH
// helper. If it fails, only quick unlock is disabled.
var UNLOCK_KEY_ENVELOPE_VERSION = 1
var UNLOCK_KEY_BUNDLED_RELATIVE = "bin/x86_64-linux/qs-bitwarden-unlock-key"
var UNLOCK_KEY_DEVELOPMENT_RELATIVE = "unlock-key/target/debug/qs-bitwarden-unlock-key"

var UNLOCK_KEY_SPEC = {
  name: "qs-bitwarden-unlock-key",
  bundled: UNLOCK_KEY_BUNDLED_RELATIVE,
  development: UNLOCK_KEY_DEVELOPMENT_RELATIVE,
  protocolSed: "s/.*envelope v\\([0-9]*\\).*/\\1/p"
}

function unlockKeyInspectCommand(pluginDir) {
  return helperInspectCommand(pluginDir, UNLOCK_KEY_SPEC)
}

var UNLOCK_KEY_MESSAGES = helperMessages("quick-unlock tool", "unlock-key/Cargo.toml",
  "uses a different envelope format")

function parseUnlockKeyInspection(raw) {
  return parseHelperInspection(raw, UNLOCK_KEY_ENVELOPE_VERSION, UNLOCK_KEY_MESSAGES)
}

// The settings that go through the quick-unlock tool.
var QUICK_UNLOCK_SETTINGS = ["fingerprintUnlock", "pinUnlock", "fidoUnlock"]

function isQuickUnlockSetting(key) {
  return QUICK_UNLOCK_SETTINGS.indexOf(String(key)) !== -1
}

// The absolute path of the unlock tool the inspection chose, or "".
function unlockKeyPath(pluginDir, source) {
  return helperPath(pluginDir, UNLOCK_KEY_SPEC, source)
}

// -------------------------------------------------------------------------
// Public-key file projection
// -------------------------------------------------------------------------
//
// Git SSH signing needs key files, so the companion's validated public keys
// are written 0600 into a 0700 dir under XDG_DATA_HOME (not ~/.ssh, which the
// plugin must not manage). Private material never goes here.
var SSH_EXPORT_SUBDIR = "qs-bitwarden-cli/ssh"

function sshExportDisplayDir() {
  return "~/.local/share/" + SSH_EXPORT_SUBDIR
}

// Vault item names are untrusted: sanitized like attachment names, then
// ".pub" added. Duplicate names get the item id instead of overwriting.
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

// OpenSSH one-line public form only: the last check before disk.
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

// Sent on stdin: argv has size limits and is world-readable.
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

// Resolves and checks the export dir; shared by export and clear.
function sshExportDirPrelude() {
  return "__base=\"${XDG_DATA_HOME:-}\"; "
    + "if [ -z \"$__base\" ]; then "
    + "  [ -n \"${HOME:-}\" ] || exit " + SSH_EXPORT_EXIT_NO_HOME + "; "
    + "  __base=\"$HOME/.local/share\"; "
    + "fi; "
    + "case \"$__base\" in /*) ;; *) exit " + SSH_EXPORT_EXIT_NO_HOME + ";; esac; "
    + "__dir=\"$__base/" + SSH_EXPORT_SUBDIR + "\"; "
    // Both components the plugin owns, not just the last: through a symlinked
    // parent, export and clear would write and prune *.pub files elsewhere.
    + "for __own in \"$(dirname \"$__dir\")\" \"$__dir\"; do "
    + "  if [ -L \"$__own\" ]; then exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; fi; "
    + "done; "
}

function sshExportCommand() {
  var script = sshExportDirPrelude()
    // A symlinked export dir or parent was already refused by the prelude.
    + "mkdir -p -m 700 \"$(dirname \"$__dir\")\" || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    // mkdir -p accepts an existing directory of any kind; recheck the parent
    // it may have just created or found, before anything is written under it.
    + "[ -d \"$(dirname \"$__dir\")\" ] && [ ! -L \"$(dirname \"$__dir\")\" ] || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    + "if [ -e \"$__dir\" ]; then "
    + "  [ -d \"$__dir\" ] || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    + "else (umask 077 && mkdir -- \"$__dir\") || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; fi; "
    + "chmod 700 -- \"$__dir\" || exit " + SSH_EXPORT_EXIT_UNSAFE_DIR + "; "
    // Read stdin whole so a partial payload writes nothing.
    + "__payload=\"$(cat)\"; "
    + "printf '%s' \"$__payload\" | jq -e 'type == \"array\"' >/dev/null 2>&1 || exit "
    + SSH_EXPORT_EXIT_WRITE + "; "
    // NUL-delimited records. Kept names go in a bash array ("$x\n" in a
    // string would add a literal backslash-n).
    + "__keep=(); "
    + "while IFS= read -r -d '' __file && IFS= read -r -d '' __key; do "
    + "  case \"$__file\" in */*|..|.|\"\") exit " + SSH_EXPORT_EXIT_WRITE + ";; esac; "
    // Write by rename: no partial files, and symlinks are replaced.
    + "  __tmp=\"$(mktemp \"$__dir/.export.XXXXXX\")\" || exit " + SSH_EXPORT_EXIT_WRITE + "; "
    + "  printf '%s\\n' \"$__key\" > \"$__tmp\" || { rm -f -- \"$__tmp\"; exit "
    + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  chmod 600 -- \"$__tmp\" || { rm -f -- \"$__tmp\"; exit " + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  mv -f -- \"$__tmp\" \"$__dir/$__file\" || { rm -f -- \"$__tmp\"; exit "
    + SSH_EXPORT_EXIT_WRITE + "; }; "
    + "  __keep+=(\"$__file\"); "
    + "done < <(printf '%s' \"$__payload\" | jq -j '.[] | .fileName, \"\\u0000\", .publicKey, \"\\u0000\"'); "
    // Remove stale *.pub files from earlier loads; other files are left alone.
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

// Run on logout, account change and disable, not on lock (public keys stay
// advertised while locked).
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
// The companion verifies only the peer's UID. PID, path and process name are
// shown as unverified context.

// REQUEST_LIFETIME_MS in the companion, which enforces it. Two minutes, since
// a person is reading a fingerprint; expiries count toward the cooldown.
var SSH_AGENT_REQUEST_DEADLINE_MS = 120 * 1000

// Bounds on text from vault items and other processes.
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
  return agentControlLine("approve", { requestId: requestId, grantSeconds: seconds })
}

function sshAgentDenyLine(requestId) {
  if (!isRequestId(requestId)) return ""
  return agentControlLine("deny", { requestId: requestId })
}

// Tells the companion the unlock was dismissed, so the request ends now.
function sshAgentUnlockCancelledLine(requestId) {
  if (!isRequestId(requestId)) return ""
  return agentControlLine("unlock_cancelled", { requestId: requestId, reason: "user-cancelled" })
}

function sshAgentRevokeGrantLine(grantId) {
  if (!isRequestId(grantId)) return ""
  return agentControlLine("revoke_grant", { grantId: grantId })
}

// "/usr/bin/ssh" -> "ssh", for display beside the full path only.
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
  "Forwarded from a remote host. The program shown is the local ssh relaying it, "
  + "not the one that will use the signature, so it can only be approved once."

// Label for what a request would sign. The detail comes from the client, so
// it is bounded.
var SSH_AGENT_MAX_DETAIL_CHARS = 256

function sshAgentOperationLabel(operation, detail) {
  var text = boundedText(detail, SSH_AGENT_MAX_DETAIL_CHARS)
  if (operation === "sshsig") {
    // Git signs commits and tags in the "git" namespace.
    if (text === "git") return "Git commit or tag signature"
    return "Signature for \"" + text + "\""
  }
  if (operation === "ssh-auth") return "SSH login as " + text
  if (operation === "ssh-sign") return "Unrecognised data -- approve only if you expect it"
  return ""
}

function sshAgentOperation(value) {
  return value === "sshsig" || value === "ssh-auth" || value === "ssh-sign" ? value : ""
}

// The server a login goes to, as the SSH client bound its session: a host key
// fingerprint in `ssh-keygen -l` form, or "" if absent or any other shape.
var SSH_HOST_KEY_RE = /^SHA256:[A-Za-z0-9+/]{43}$/

function sshAgentHostKey(operation, hostKey) {
  if (operation !== "ssh-auth" || typeof hostKey !== "string") return ""
  return SSH_HOST_KEY_RE.test(hostKey) ? hostKey : ""
}

// Where a login goes. A login grant covers that one server, so the prompt
// names it, or says the client did not (older OpenSSH, other clients).
function sshAgentDestinationLabel(operation, hostKey) {
  if (operation !== "ssh-auth") return ""
  return hostKey
    ? "Server host key " + hostKey
    : "Server not reported by the SSH client"
}

// An approval_required message reduced to what the prompt draws, with every
// client-supplied field bounded.
function sshAgentPromptView(message, approvalWindowSec) {
  var request = message || {}
  var window = Math.max(0, Math.min(SSH_AGENT_APPROVAL_WINDOW_MAX_SEC,
    Math.floor(Number(approvalWindowSec)) || 0))
  var forwarded = request.forwarded === true
  // Offer a grant only if the companion did, a window is set, and the request
  // is not forwarded.
  var grantOffered = request.grantOffered === true && window > 0 && !forwarded
  var operation = sshAgentOperation(request.operation)
  var hostKey = sshAgentHostKey(operation, request.hostKey)
  return {
    requestId: isRequestId(request.requestId) ? request.requestId : -1,
    keyId: boundedText(request.keyId, SSH_AGENT_MAX_NAME_CHARS),
    keyName: boundedText(request.keyName, SSH_AGENT_MAX_NAME_CHARS),
    fingerprint: boundedText(request.fingerprint, SSH_AGENT_MAX_NAME_CHARS),
    pid: Math.floor(Number(request.pid)) || 0,
    processPath: boundedText(request.processPath, SSH_AGENT_MAX_PATH_CHARS),
    processName: processNameFromPath(boundedText(request.processPath, SSH_AGENT_MAX_PATH_CHARS)),
    operation: operation,
    operationLabel: sshAgentOperationLabel(operation, request.operationDetail),
    hostKey: hostKey,
    destinationLabel: sshAgentDestinationLabel(operation, hostKey),
    grantOffered: grantOffered,
    grantSeconds: grantOffered ? window : 0,
    // A grant covers the program (path + key + kind of signature, and for a
    // login the server), so each new ssh-keygen that Git spawns rides it.
    grantLabel: grantOffered ? "Approve for this program · " + formatDuration(window) : "",
    // The same, short enough for its tile in the decision row.
    grantShortLabel: grantOffered ? "Approve " + formatDuration(window) : "",
    forwardedWarning: forwarded ? SSH_AGENT_FORWARDED_WARNING : "",
    provenanceNote: SSH_AGENT_PROVENANCE_NOTE
  }
}

// FIFO queue of prompts, capped at the companion's MAX_PENDING.
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

// Grant views for the settings screen (public metadata only).
function sshAgentGrantViews(grants, nowMs) {
  if (!grants || !Array.isArray(grants)) return []
  var now = Number(nowMs) || 0
  var out = []
  for (var i = 0; i < grants.length; i++) {
    var grant = grants[i] || {}
    if (!isRequestId(grant.grantId)) continue
    var remaining = Math.max(0, Math.floor(Number(grant.expiresInSec)) || 0)
    var operation = sshAgentOperation(grant.operation)
    var hostKey = sshAgentHostKey(operation, grant.hostKey)
    out.push({
      grantId: grant.grantId,
      keyName: boundedText(grant.keyName, SSH_AGENT_MAX_NAME_CHARS),
      fingerprint: boundedText(grant.fingerprint, SSH_AGENT_MAX_NAME_CHARS),
      pid: Math.floor(Number(grant.pid)) || 0,
      processPath: boundedText(grant.processPath, SSH_AGENT_MAX_PATH_CHARS),
      processName: processNameFromPath(boundedText(grant.processPath, SSH_AGENT_MAX_PATH_CHARS)),
      operationLabel: sshAgentOperationLabel(operation, grant.operationDetail),
      hostKey: hostKey,
      // Absolute expiry, so the countdown can be recomputed each tick.
      expiresAtMs: now + remaining * 1000,
      remainingSec: remaining,
      remainingLabel: remaining > 0 ? formatDuration(remaining) + " left" : "expiring"
    })
  }
  return out
}

// Grant views recomputed for `nowMs`: the companion announces each grant only
// once, so this makes the countdown tick and drops lapsed grants.
function sshAgentGrantsAt(views, nowMs) {
  if (!views || !Array.isArray(views)) return []
  var now = Number(nowMs) || 0
  var out = []
  for (var i = 0; i < views.length; i++) {
    var view = views[i] || {}
    // No expiry stamp or no clock yet: show as announced.
    if (typeof view.expiresAtMs !== "number" || now <= 0) {
      out.push(view)
      continue
    }
    var remaining = Math.max(0, Math.ceil((view.expiresAtMs - now) / 1000))
    if (remaining <= 0) continue
    var copy = {}
    for (var k in view) copy[k] = view[k]
    copy.remainingSec = remaining
    copy.remainingLabel = formatDuration(remaining) + " left"
    out.push(copy)
  }
  return out
}

// Shown while an SSH request waits on the (slow, full-vault) read an unlock
// runs; bw cannot read only SSH items.
function sshAgentLoadingNote() {
  return "Loading your SSH keys from the vault. The signing request is still waiting."
}

// Never prompt over the lock screen; an unknown screen state counts as locked.
function sshAgentShouldPrompt(context) {
  if (!context || typeof context !== "object") return false
  return context.screenLocked !== true
}

// After two consecutive refusals the panel stops raising prompts for a while,
// so an unattended process cannot keep reopening it.
var SSH_AGENT_COOLDOWN_AFTER = 2
var SSH_AGENT_COOLDOWN_MS = 5 * 60 * 1000

function sshAgentCooldownInitial() {
  return { refusals: 0, untilMs: 0 }
}

function sshAgentCooldownAfter(state, outcome, nowMs) {
  var current = state || sshAgentCooldownInitial()
  var now = Number(nowMs) || 0
  // Approving or explicitly resuming resets it (while cooling down there are
  // no prompts to approve).
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

// Tells the user signing is paused and until when, without naming the key or
// process.
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
// The companion's state is derived explicitly from the vault's: the state
// table below, and sshAgentLifecycleTransition() for each vault event.

// How long to wait for the companion's `locked` ack before killing it. The ack
// only lets the panel report "keys cleared"; locking never waits on it.
var SSH_AGENT_LOCK_ACK_TIMEOUT_MS = 2000

function sshAgentLockAckTimeoutMs() { return SSH_AGENT_LOCK_ACK_TIMEOUT_MS }

// Settings the companion acts on; sent after the handshake and on change.
function sshAgentOptionsLine(unlockOnDemand) {
  return agentControlLine("options", { unlockOnDemand: unlockOnDemand === true })
}

function sshAgentRevokeGrantsLine() {
  return agentControlLine("revoke_grants")
}

// Most restrictive first, so a cached key set never outranks a logout.
function sshAgentVaultState(context) {
  var ctx = context || {}
  if (!ctx.enabled || !ctx.helperReady) return "disabled"
  if (!ctx.loggedIn) return "logged-out"
  if (ctx.loading) return "loading"
  if (ctx.unlocked) return "unlocked"
  return ctx.hasPublicCache ? "locked-cached" : "locked-empty"
}

// Events that end the current private key set.
var SSH_AGENT_LOCK_EVENTS = ["lock", "screen-lock", "suspend"]
// Events that end the account itself, taking the public projection with it.
var SSH_AGENT_LOGOUT_EVENTS = ["logout", "account-change"]
// Events that load keys. Only `startup` needs a caller; unlock and sync
// already run loadItems() with the agent branch. Listed for completeness.
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
    // Nothing of this account survives disabling.
    action.clearPublic = true
    return action
  }

  if (SSH_AGENT_LOCK_EVENTS.indexOf(event) >= 0) {
    // The load is the panel's own process, so cancel it either way.
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
    // No ack needed: logout drops the public cache too.
    if (live) action.controlLines.push(sshAgentLoggedOutLine())
    return action
  }

  if (SSH_AGENT_LOAD_EVENTS.indexOf(event) >= 0) {
    // A remembered session can start unlocked while the companion has no keys.
    action.startLoad = live && Boolean(ctx.unlocked)
    return action
  }

  return action
}

// Setup state for the settings screen:
//
//   disabled  nothing runs; no socket, no FIFO, no agent branch
//   enabled   running or starting (`busy`)
//   error     stopped or backing off; the vault is unaffected
//
// Routing (SSH_AUTH_SOCK) does not affect it; see sshAuthSockDiagnostic().
function sshAgentSetupState(opts) {
  var o = opts || {}
  if (!o.enabled) {
    return {
      state: "disabled", busy: false,
      message: "The SSH agent is off. Your vault works normally; SSH keys stay read-only records."
    }
  }
  // Never fall back to a guessable socket path.
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
//   "disabled"    nothing runs or is scheduled
//   "starting"    process launched, waiting for onStarted
//   "handshaking" hello sent, waiting for `ready`
//   "ready"       the only phase with an open gate
//   "restarting"  failure seen mid-run; waiting for the child to exit
//   "backoff"     restart timer armed
//   "elsewhere"   runtime lock held by another process; slow retry, no failure
//   "failed"      restart cap reached; off until re-enabled
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
  CRASH_LOOP: "The SSH agent helper keeps failing to start, so it has been left off.",
  ELSEWHERE: "Another process is already serving the SSH agent on this machine -- another "
    + "Omarchy shell, most likely. This one is standing by and will take over when it stops."
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
      // `ready` answers `hello` exactly once; anything out of order fails.
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
        // `failures` is not reset here: only a run that lasts
        // SSH_AGENT_HEALTHY_MS clears it, at exit.
        next.errorCode = ""
        next.errorMessage = ""
        return { state: next, action: action }
      }
      action.message = parsed.message
      return { state: next, action: action }
    }

    case "exited":
      // An exit before `ready` with the runtime lock held elsewhere is a wait,
      // not a crash, and must not count toward CRASH_LOOP.
      if (ev.lockHeld === true && current.readyAtMs === 0) {
        next.gateOpen = false
        next.socketPath = ""
        next.fifoPath = ""
        next.agentVersion = ""
        next.phase = "elsewhere"
        next.errorCode = "ELSEWHERE"
        next.errorMessage = sshAgentErrorMessage("ELSEWHERE")
        action.restartInMs = SSH_AGENT_ELSEWHERE_RETRY_MS
        return { state: next, action: action }
      }
      sshAgentFailOnExit(current, next, action, nowMs)
      return { state: next, action: action }

    case "restartTimer":
      if (current.phase !== "backoff" && current.phase !== "elsewhere") return { state: next, action: action }
      next.phase = "starting"
      action.start = true
      return { state: next, action: action }

    default:
      return { state: next, action: action }
  }
}

// Whether to show the setup screen instead of talking to `bw`: a fresh install
// may lack the CLI (`omarchy plugin add` installs nothing else). Only after the
// probe ran (`checked`), only while a required tool is missing, and never once
// the user skipped it (`dismissed`).
function setupGateActive(deps, checked, dismissed) {
  if (!checked || dismissed) return false
  return missingRequired(deps).length > 0
}

// What a finished dependency probe should do next:
//
//   "setup" -- a required tool is missing and setup was not skipped
//   "probe" -- all required tools present, and the vault was never probed or
//              an install just completed (`wasGated`)
//   "idle"  -- nothing to do
//
// `wasGated` is how an install in a terminal we do not own is noticed.
function dependencyProbeOutcome(deps, dismissed, probeStarted, wasGated) {
  if (missingRequired(deps).length > 0) return dismissed ? "idle" : "setup"
  if (!probeStarted || wasGated) return "probe"
  return "idle"
}

// Every missing package, required or not, so one install enables everything.
function missingPackages(deps) {
  var pkgs = []
  if (!deps || !deps.items) return pkgs
  for (var i = 0; i < deps.items.length; i++) {
    var d = deps.items[i]
    // Skip rows this machine cannot use and ones Omarchy sets up itself.
    if (!d.applicable || d.setup || d.installed) continue
    if (pkgs.indexOf(d.pkg) === -1) pkgs.push(d.pkg)
  }
  return pkgs
}

// Package names are word-split unquoted by the installer; they come from
// DEPENDENCIES, and this keeps it that way.
function isPlainPackageName(name) {
  return typeof name === "string" && /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(name)
}

// Omarchy's own installer window, which also handles the sudo prompt.
function installPackagesCommand(pkgs, displayName) {
  if (!pkgs || pkgs.length === 0) return null
  for (var i = 0; i < pkgs.length; i++) {
    if (!isPlainPackageName(pkgs[i])) return null
  }
  var name = displayName || (pkgs.length === 1 ? pkgs[0] : "Bitwarden plugin dependencies")
  return ["omarchy", "install", "app", name, pkgs.join(" ")]
}

// Omarchy's interactive fingerprint setup (packages, enrolment, PAM stack),
// in a floating terminal.
function fingerprintSetupCommand() {
  return ["omarchy", "launch", "floating", "terminal", "with", "presentation",
    "omarchy setup security fingerprint"]
}

// -------------------------------------------------------------------------
// Settings
// -------------------------------------------------------------------------
//
// Stored in the widget's entry in ~/.config/omarchy/shell.json and written
// with `omarchy bar set`, which the shell hot-reloads.

// In screen order; Security opens expanded.
var SETTINGS_GROUPS = [
  { id: "general", label: "General" },
  { id: "security", label: "Security" },
  { id: "sshAgent", label: "SSH Agent" }
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
    description: "A verified fingerprint opens your master password, stored once, encrypted and sealed to this machine." },
  { key: "fidoUnlock", group: "security", type: "bool", label: "Unlock with FIDO2 key", defaultValue: false,
    action: "fido",
    description: "A FIDO2 key touch opens your master password, stored once, encrypted and sealed to this machine. Requires 'omarchy setup security fido2'; the same registration also serves the system's own authentication prompts." },
  { key: "pinUnlock", group: "security", type: "bool", label: "Unlock with PIN", defaultValue: false,
    action: "pin",
    description: "A PIN opens your master password, stored once, encrypted and sealed to this machine. Use 6 digits or more; 4 is the floor and is flagged as weak." },

  { key: "sshAgentEnabled", group: "sshAgent", type: "bool", label: "Act as your SSH agent", defaultValue: false,
    description: "Serve SSH keys from your vault to ssh, Git and signing, while the vault is unlocked. Private keys stay in a separate helper process and are never written to disk." },
  { key: "sshAgentUnlockOnDemand", group: "sshAgent", type: "bool", label: "Unlock on demand", defaultValue: false,
    description: "Let an SSH client open the unlock prompt when the vault is locked. Off by default because every ssh connection asks for identities, including ones with nothing to do with your vault." },
  { key: "sshAgentApprovalPopup", group: "sshAgent", type: "bool", label: "Use centered approval popup", defaultValue: true,
    description: "Show SSH unlock and signing requests in a transient card in the middle of the screen instead of opening the anchored panel. Disable to show them in the panel." },
  { key: "sshAgentApprovalWindowSec", group: "sshAgent", type: "int", label: "Approve for this long", unit: "seconds",
    min: 0, max: SSH_AGENT_APPROVAL_WINDOW_MAX_SEC, step: 30, zeroLabel: "Always ask", defaultValue: 120,
    description: "How long one approval covers further signatures from the same process. Grants live only in the helper's memory and never survive a restart." },

  { key: "closeOnCopy", group: "general", type: "bool", label: "Close panel on copy", defaultValue: true,
    description: "Return focus to your app as soon as Enter copies a credential." },
  { key: "colorizeIcon", group: "general", type: "bool", label: "Colorize menu-bar icon", defaultValue: false,
    description: "Use the active Omarchy theme accent for the primary menu-bar icon." },
  { key: "autoCopyTotpSec", group: "general", type: "int", label: "Auto-copy TOTP after", unit: "seconds",
    min: 0, max: 30, step: 1, zeroLabel: "Off", defaultValue: 3,
    description: "Replace the clipboard with the 2FA code this long after the password." },

  { key: "suggestOnOpen", group: "general", type: "bool", label: "Suggest for active window", defaultValue: true,
    description: "Match the focused window or browser tab against your vault." }
]

// Schema entries in group order; the first of each carries `groupLabel`.
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

// The rows the settings screen draws: a heading row per group, then its
// settings. SSH agent rows only when the CLI supports SSH keys. Headings are
// rows of their own because the panel reads section positions off this list.
function visibleSettings(deps, checked) {
  var showSsh = sshUiAvailable(deps, checked)
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
        label: groupLabelFor(entry.group)
      })
    }
    entry.kind = "setting"
    // The heading row replaces the old label field.
    entry.groupLabel = ""
    // Lets a group's extra block (SSH status and routing) attach to its end.
    entry.lastInGroup = (i + 1 >= rows.length) || rows[i + 1].group !== entry.group
    out.push(entry)
  }
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

// Integer settings read from shell.json, which nothing validates. Unreadable
// values fall back to the default, never to 0: in QML NaN becomes 0 ("never
// lock"), and an oversized minute count overflows Timer.interval so it never
// fires.
function intSetting(key, raw) {
  // Only a number or a decimal string counts; Number() reads null, "" and
  // false as 0.
  var n = (typeof raw === "number" || (typeof raw === "string" && String(raw).trim() !== ""))
    ? Math.floor(Number(raw))
    : NaN
  var entry = settingSchemaEntry(key)
  if (!entry || entry.type !== "int") return isFinite(n) ? n : 0
  // Below the floor falls back to the default rather than clamping up, since
  // the floor means "off". Above the ceiling clamps down.
  if (!isFinite(n) || n < entry.min) n = Math.floor(Number(entry.defaultValue))
  if (!isFinite(n)) n = entry.min
  return Math.max(entry.min, Math.min(entry.max, n))
}

// Only a JSON boolean counts; "false" is truthy.
function boolSetting(key, raw) {
  if (typeof raw === "boolean") return raw
  var entry = settingSchemaEntry(key)
  if (!entry || entry.type !== "bool") return false
  return entry.defaultValue === true
}

function settingWriteCommand(key, value, type) {
  var raw
  if (type === "bool") raw = value ? "true" : "false"
  // For per-account maps. Settings never hold secrets.
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
// Qt Timers use CLOCK_MONOTONIC, which stops during suspend, so the deadline
// is also tracked on the wall clock and polled. Whichever notices first locks.
var AUTO_LOCK_POLL_MS = 30000

// Poll at most every 30 s (and at least every second), never longer than the
// window itself.
function autoLockPollMs(minutes) {
  var m = Math.floor(Number(minutes))
  if (!isFinite(m) || m <= 0) return AUTO_LOCK_POLL_MS
  return Math.max(1000, Math.min(m * 60 * 1000, AUTO_LOCK_POLL_MS))
}

// Times are Date.now(). Zero minutes (off) or an unarmed timer never expires.
function autoLockExpired(armedAt, minutes, now) {
  var m = Math.floor(Number(minutes))
  if (!isFinite(m) || m <= 0) return false
  var start = Number(armedAt)
  var at = Number(now)
  if (!isFinite(start) || start <= 0 || !isFinite(at)) return false
  return (at - start) >= m * 60 * 1000
}

// -------------------------------------------------------------------------
// Password generator
// -------------------------------------------------------------------------
//
// The browser extension's options; generation is done by `bw`.

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

// At least one character set must be on, or `bw generate` fails.
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
// `bw generate` costs ~2.9 s of CLI startup per call; `bw serve` pays it once
// and answers in ~2 ms. It runs with no session, so it can only generate: the
// loopback port is unauthenticated and open to every local user.
var GENERATE_HOST = "127.0.0.1"
var GENERATE_PORT = 8087

// A managed child, so it dies with the shell. The caller clears BW_SESSION
// (generatorServeEnv() in Service.qml).
function generateServeCommand() {
  return ["bw", "serve", "--hostname", GENERATE_HOST, "--port", String(GENERATE_PORT)]
}

// -------------------------------------------------------------------------
// Generator request bounds
// -------------------------------------------------------------------------
//
// The port is first-come, so whoever holds it could stall or stream forever.
// Requests go through curl with a timeout and a `head -c` cap, keeping the
// response out of the shell's memory until it is bounded.
var GENERATE_RESPONSE_CAP = 64 * 1024
var GENERATE_REQUEST_TIMEOUT_MS = 2000

function generateServeRequestCommand(opts) {
  var url = generateServeUrl(opts)
  var timeoutSecs = Math.max(1, Math.round(GENERATE_REQUEST_TIMEOUT_MS / 1000))
  // -q (first) ignores ~/.curlrc; --noproxy keeps it on loopback.
  var script = "curl -q -s -S --noproxy '*' --max-time " + timeoutSecs + " --connect-timeout " + timeoutSecs
    + " " + shellQuote(url) + " | head -c " + Number(GENERATE_RESPONSE_CAP)
  return ["bash", "-c", cappedScript(script, MAX_STDERR_BYTES)]
}

// Whether a curl probe of the port found another server. Only a refused
// connection (exit 7, no output) leaves it free for ours: an answer, a timeout
// or a truncated stream all mean someone else is bound, and a password from a
// stranger's server is one they know.
function generatorProbeIsForeign(exitCode, stdout) {
  return !(Number(exitCode) === 7 && String(stdout || "").trim() === "")
}

// What to do when our `bw serve` exits. An exit we did not ask for means it
// never bound, so the port was squatted and any value already shown may not
// be ours: drop it.
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

// The options as [name, value] pairs, where `true` is a bare flag. `bw
// generate` takes them as --name flags and `bw serve` as query parameters.
function generatorParams(opts) {
  var o = normalizeGeneratorOptions(opts)
  var p = []
  var flag = function(name, on) { if (on) p.push([name, true]) }
  if (o.type === "passphrase") {
    p.push(["passphrase", true], ["words", o.words], ["separator", o.separator])
    flag("capitalize", o.capitalize)
    flag("includeNumber", o.includeNumber)
  } else {
    flag("uppercase", o.uppercase)
    flag("lowercase", o.lowercase)
    flag("number", o.numbers)
    flag("special", o.special)
    p.push(["length", o.length])
    if (o.numbers) p.push(["minNumber", o.minNumber])
    if (o.special) p.push(["minSpecial", o.minSpecial])
    flag("ambiguous", o.ambiguous)
  }
  return p
}

function generateServeUrl(opts) {
  var q = generatorParams(opts).map(function(p) {
    return p[0] + "=" + (p[1] === true ? "true" : encodeURIComponent(String(p[1])))
  })
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
  var args = ["generate"]
  generatorParams(opts).forEach(function(p) {
    args.push("--" + p[0])
    if (p[1] !== true) args.push(String(p[1]))
  })
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

// Strength of the search space the options imply, for the meter.
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
// Field names from a real `bw send --fullObject`; type 0 is text, 1 file.

var SEND_TYPE_TEXT = 0
var SEND_TYPE_FILE = 1

function listSendsCommand() {
  return buildCappedCommand(["send", "list"], MAX_SENDS_BYTES)
}

function deleteSendCommand(sendId) {
  return buildCappedCommand(["send", "delete", "--", String(sendId)], MAX_MISC_BYTES)
}

// The payload (which may hold the Send password) travels in the environment.
var SEND_ENV = "QSBW_SEND"

function sendEnvVar() {
  return SEND_ENV
}

function createSendCommand() {
  var script = "printf '%s' \"$" + SEND_ENV + "\" | " + ENCODE_CMD + " | bw send create | head -c " + MAX_MISC_BYTES
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

// Qt Text defaults to AutoText, which renders anything that looks like markup
// as HTML, and kit controls (Ui.Button) give no way to change that. So vault
// text containing "<" or "&" is HTML-escaped and wrapped in a pre-wrap <span>,
// which renders back to the literal characters; anything else passes as is.
function plainLabel(value) {
  var text = (value === undefined || value === null) ? "" : String(value)
  if (text.indexOf("<") < 0 && text.indexOf("&") < 0) return text
  return "<span style=\"white-space:pre-wrap\">"
    + text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    + "</span>"
}

// Ui.Button sizes to its label without eliding, so vault text is clipped to
// `max` characters (the font is monospace; the "..." counts). Call before
// plainLabel(), which may add markup that must not be cut.
function clipLabel(value, max) {
  var text = (value === undefined || value === null) ? "" : String(value)
  var limit = Math.max(1, Math.floor(Number(max) || 0))
  if (text.length <= limit) return text
  if (limit <= 3) return text.slice(0, limit)
  return text.slice(0, limit - 3) + "..."
}

// -------------------------------------------------------------------------
// Vault host
// -------------------------------------------------------------------------
//
// The bar (and this widget) exists once per monitor; the vault lives in
// Service.qml, loaded once per shell and reached via `bar.shell.serviceFor()`.
// A widget that cannot reach it (no shell facade, standalone tests) hosts a
// private Service. The shared service can appear shortly after the widget is
// created, so "not found" waits up to the timeout before going private.
var VAULT_HOST_TIMEOUT_MS = 3000

function vaultHostTimeoutMs() {
  return VAULT_HOST_TIMEOUT_MS
}

// "shared" | "private" | "wait", given whether the shared service was found
// and how long this view has been asking.
function vaultHostDecision(found, elapsedMs, timeoutMs) {
  if (found) return "shared"
  var limit = Number(timeoutMs)
  if (!(limit >= 0)) limit = VAULT_HOST_TIMEOUT_MS
  return Number(elapsedMs) >= limit ? "private" : "wait"
}

// Which view acts when the vault needs the screen (raise the popout, show an
// SSH prompt). `views` is `{ opened, screen }` per view in attach order:
// prefer an open popout, then the focused monitor, then the first view.
// -1 only when there is no view.
function presenterIndex(views, focusedScreen) {
  var list = Array.isArray(views) ? views : []
  if (list.length === 0) return -1
  for (var i = 0; i < list.length; i++) {
    if (list[i] && list[i].opened === true) return i
  }
  var focused = String(focusedScreen || "")
  if (focused) {
    for (var j = 0; j < list.length; j++) {
      if (list[j] && String(list[j].screen || "") === focused) return j
    }
  }
  return 0
}
