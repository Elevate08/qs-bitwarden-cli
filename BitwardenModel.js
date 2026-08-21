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
const PIN_MIN_LENGTH = 4

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

function buildCommand(args, session, useSession) {
  var cmd = ["bw"].concat(args || [])
  if (useSession && session) {
    cmd.push("--session", String(session).trim())
  }
  return cmd
}

function extractSessionToken(raw) {
  var s = String(raw || "").trim()
  var match = s.match(/BW_SESSION="?([^"\n\r]+)"?/)
  if (match && match[1]) {
    return match[1].trim()
  }
  var lines = s.split("\n")
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim()
    if (line && line.indexOf(" ") === -1 && line.length > 20) {
      return line
    }
  }
  return s
}

// -------------------------------------------------------------------------
// CLI Commands
// -------------------------------------------------------------------------

function statusCommand(session) {
  return buildCommand(["status"], session, Boolean(session))
}

function unlockCommand(password) {
  var p = shellQuote(password)
  var script = "BW_PASSWORD=" + p + " BW_NOINTERACTION=true bw unlock --passwordenv BW_PASSWORD --raw"
  return ["bash", "-c", script]
}

function emailLoginCommand(email, password, code, serverUrl) {
  var e = shellQuote(email)
  var p = shellQuote(password)
  var c = code ? (" --code " + shellQuote(code)) : ""
  var script = ""

  if (serverUrl && serverUrl.trim()) {
    script += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  script += "BW_PASSWORD=" + p + " BW_NOINTERACTION=true bw login " + e + " --passwordenv BW_PASSWORD" + c + " --raw"
  return ["bash", "-c", script]
}

function apiKeyLoginCommand(clientId, clientSecret, password, serverUrl) {
  var id = shellQuote(clientId)
  var sec = shellQuote(clientSecret)
  var p = shellQuote(password)
  var script = ""

  if (serverUrl && serverUrl.trim()) {
    script += "bw config server " + shellQuote(serverUrl.trim()) + " >/dev/null 2>&1 && "
  }

  script += "BW_CLIENTID=" + id + " BW_CLIENTSECRET=" + sec + " BW_PASSWORD=" + p + " BW_NOINTERACTION=true bw login --apikey >/dev/null 2>&1 && "
  script += "BW_PASSWORD=" + p + " BW_NOINTERACTION=true bw unlock --passwordenv BW_PASSWORD --raw"
  return ["bash", "-c", script]
}

function logoutCommand() {
  return ["bw", "logout"]
}

function listCommand(session) {
  return buildCommand(["list", "items"], session, true)
}

function listOrganizationsCommand(session) {
  return buildCommand(["list", "organizations"], session, true)
}

function listFoldersCommand(session) {
  return buildCommand(["list", "folders"], session, true)
}

function createFolderCommand(name, session) {
  var jsonStr = JSON.stringify({ name: String(name || "").trim() })
  var script = "printf %s " + shellQuote(jsonStr) + " | bw encode | bw create folder --session " + shellQuote(session)
  return ["bash", "-c", script]
}

function deleteFolderCommand(folderId, session) {
  return ["bw", "delete", "folder", String(folderId), "--session", String(session).trim()]
}

function getItemCommand(id, session) {
  return buildCommand(["get", "item", String(id)], session, true)
}

function getTotpCommand(id, session) {
  return buildCommand(["get", "totp", String(id), "--raw"], session, true)
}

function syncCommand(session) {
  return buildCommand(["sync"], session, true)
}

function lockCommand(session) {
  return buildCommand(["lock"], session, Boolean(session))
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
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw create item" + orgArg
    + " --session " + shellQuote(session)
  return ["bash", "-c", script]
}

function editItemCommand(itemId, session) {
  var script = "printf '%s' \"$" + ITEM_ENV + "\" | bw encode | bw edit item " + shellQuote(itemId)
    + " --session " + shellQuote(session)
  return ["bash", "-c", script]
}

function deleteItemCommand(itemId, session) {
  return ["bw", "delete", "item", String(itemId), "--session", String(session).trim()]
}

// -------------------------------------------------------------------------
// Keyring (libsecret / secret-tool) Commands
// -------------------------------------------------------------------------

function keyringStoreCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden Vault Session", KEYRING_ACCOUNT)]
}

function keyringLookupCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringClearCommand() {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringStoreApiKeyIdCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden API Client ID", KEYRING_CLIENT_ID)]
}

function keyringLookupApiKeyIdCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_ID]
}

function keyringStoreApiKeySecretCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden API Client Secret", KEYRING_CLIENT_SECRET)]
}

function keyringLookupApiKeySecretCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_SECRET]
}

function keyringStoreEmailCommand() {
  return ["bash", "-c", keyringStoreScript("Bitwarden User Email", KEYRING_EMAIL)]
}

function keyringLookupEmailCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_EMAIL]
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
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_MASTER]
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

function validatePin(pin, confirm) {
  var p = String(pin || "")
  if (p.length < PIN_MIN_LENGTH) return "PIN must be at least " + PIN_MIN_LENGTH + " digits"
  if (!/^[0-9]+$/.test(p)) return "PIN must contain only digits"
  if (confirm !== undefined && String(confirm || "") !== p) return "PINs do not match"
  return ""
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
  var script = "set -o pipefail; secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_PIN)
    + " | openssl enc -d -aes-256-cbc -pbkdf2 -iter " + PIN_ITERATIONS
    + " -pass env:" + PIN_ENV + " -base64 -A"
  return ["bash", "-c", script]
}

function keyringClearPinCommand() {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_PIN]
}

function keyringHasPinCommand() {
  var script = "if secret-tool lookup service " + shellQuote(KEYRING_SERVICE)
    + " account " + shellQuote(KEYRING_PIN) + " >/dev/null 2>&1; then echo yes; else echo no; fi"
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

function itemTypeGlyph(type) {
  var t = itemTypeName(type)
  switch (t) {
    case "login": return "󰌋"      // key icon
    case "secureNote": return "󰈐" // note icon
    case "card": return "󰅝"       // credit card icon
    case "identity": return ""   // person icon
    default: return "󰞀"           // shield icon
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
    if (Array.isArray(login.uris)) {
      for (var j = 0; j < login.uris.length; j++) {
        var u = login.uris[j]
        if (u && u.uri) uris.push(String(u.uri))
      }
    }

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
  if (!it || typeof it !== "object") return null

  var login = it.login || {}
  var uris = []
  if (Array.isArray(login.uris)) {
    for (var j = 0; j < login.uris.length; j++) {
      var u = login.uris[j]
      if (u && u.uri) uris.push(String(u.uri))
    }
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

  var customFields = []
  if (Array.isArray(it.fields)) {
    for (var k = 0; k < it.fields.length; k++) {
      var f = it.fields[k]
      if (f && f.name) {
        customFields.push({
          name: String(f.name || ""),
          value: String(f.value || ""),
          type: Number(f.type || 0) // 0: text, 1: hidden, 2: boolean, 3: linked
        })
      }
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

  if (Array.isArray(item.uris)) {
    for (var i = 0; i < item.uris.length; i++) {
      if (String(item.uris[i]).toLowerCase().indexOf(q) !== -1) return true
    }
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

function maskString(str) {
  if (!str) return ""
  return "•".repeat(Math.min(str.length, 16))
}

// -------------------------------------------------------------------------
// Password Generator
// -------------------------------------------------------------------------

function generatePassword(length, upper, lower, numbers, special) {
  var u = "ABCDEFGHJKLMNPQRSTUVWXYZ"
  var l = "abcdefghijkmnopqrstuvwxyz"
  var n = "23456789"
  var s = "!@#$%^&*()-_=+[]{}|;:,.<>?"
  var charset = ""
  if (upper !== false) charset += u
  if (lower !== false) charset += l
  if (numbers !== false) charset += n
  if (special !== false) charset += s
  if (!charset) charset = u + l + n + s

  var len = Math.max(8, Number(length) || 20)
  var res = ""
  for (var i = 0; i < len; i++) {
    var idx = Math.floor(Math.random() * charset.length)
    res += charset.charAt(idx)
  }
  return res
}

// -------------------------------------------------------------------------
// Payload Builders for Create & Edit
// -------------------------------------------------------------------------

function buildCreatePayload(typeCode, name, username, password, totp, uri, notes, favorite, organizationId, folderId) {
  var payload = {
    type: Number(typeCode || 1),
    name: String(name || "Untitled").trim(),
    notes: String(notes || "").trim(),
    favorite: Boolean(favorite),
    organizationId: organizationId && organizationId !== "personal" && organizationId !== "all" ? String(organizationId) : null,
    folderId: folderId && folderId !== "all" && folderId !== "none" ? String(folderId) : null
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

function buildEditPayload(existingItem, name, username, password, totp, uri, notes, favorite, organizationId, folderId) {
  var payload = existingItem && existingItem.rawObject ? JSON.parse(JSON.stringify(existingItem.rawObject)) : {}
  payload.name = String(name || "Untitled").trim()
  payload.notes = String(notes || "").trim()
  payload.favorite = Boolean(favorite)
  if (organizationId && organizationId !== "personal" && organizationId !== "all") {
    payload.organizationId = String(organizationId)
  }
  // An explicit empty selection means "no folder", so this must be able to
  // clear an existing assignment, not only set one.
  payload.folderId = folderId && folderId !== "all" && folderId !== "none" ? String(folderId) : null

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
function detectDomainInText(text) {
  var s = String(text || "").toLowerCase()
  var re = /(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/g
  var m
  while ((m = re.exec(s)) !== null) {
    var host = m[1].replace(/\.$/, "")
    var parts = host.split(".")
    var tld = parts[parts.length - 1]
    if (!TLDS[tld]) continue
    var parsed = parseHost(host)
    if (!parsed || !parsed.rootName) continue
    if (parsed.rootName.length < 2) continue
    if (GENERIC_LABELS[parsed.rootName]) continue
    return parsed
  }
  return null
}

function itemDomains(item) {
  var out = []
  if (!item || !Array.isArray(item.uris)) return out
  for (var i = 0; i < item.uris.length; i++) {
    var d = parseDomain(item.uris[i])
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

  var cls = String(w.class || w.initialClass || "").toLowerCase().trim()
  var title = String(w.title || w.initialTitle || "").trim()
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
    } else if (root.length >= 5 && squash(ctx.matchText).indexOf(root) !== -1) {
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
  return ["bash", "-c", "cat \"" + ASSOC_FILE + "\" 2>/dev/null || echo '{}'"]
}

// Written through the environment for the same reason the keyring stores are:
// Process.write() cannot deliver EOF, so a shell supplies the payload instead.
function associationsWriteCommand() {
  var script = "d=\"$(dirname \"" + ASSOC_FILE + "\")\"; mkdir -p \"$d\" && chmod 700 \"$d\" && "
    + "umask 077 && printf '%s' \"$" + ASSOC_ENV + "\" > \"" + ASSOC_FILE + "\""
  return ["bash", "-c", script]
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
  return next
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
  return ["bash", "-c", parts.join("; ")]
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
    min: 0, max: 1440, step: 5, zeroLabel: "Never",
    description: "Lock the vault after this long without activity." },
  { key: "clearClipboardSec", group: "security", type: "int", label: "Clear clipboard after", unit: "seconds",
    min: 0, max: 300, step: 5, zeroLabel: "Never",
    description: "Wipe a copied password or code from the clipboard." },
  { key: "rememberSession", group: "security", type: "bool", label: "Remember session in keyring",
    description: "Keep the unlocked session in the OS keyring so it survives a shell restart." },
  { key: "fingerprintUnlock", group: "security", type: "bool", label: "Unlock with fingerprint",
    requires: "fprintd", action: "fingerprint",
    description: "Store the master password in the OS keyring, gated behind a fingerprint." },
  { key: "pinUnlock", group: "security", type: "bool", label: "Unlock with PIN",
    action: "pin",
    description: "Encrypt the master password with a key derived from a PIN. Minimum 4 digits; longer is stronger." },

  { key: "closeOnCopy", group: "behavior", type: "bool", label: "Close panel on copy",
    description: "Return focus to your app as soon as Enter copies a credential." },
  { key: "autoCopyTotpSec", group: "behavior", type: "int", label: "Auto-copy TOTP after", unit: "seconds",
    min: 0, max: 30, step: 1, zeroLabel: "Off",
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

function settingWriteCommand(key, value, type) {
  var raw
  if (type === "bool") raw = value ? "true" : "false"
  else raw = String(Number(value) || 0)
  return ["omarchy", "bar", "set", "qs-bitwarden-cli", String(key), raw, "--json"]
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

function generateCommand(opts) {
  var o = normalizeGeneratorOptions(opts)
  var args = ["generate"]

  if (o.type === "passphrase") {
    args.push("--passphrase", "--words", String(o.words), "--separator", String(o.separator))
    if (o.capitalize) args.push("--capitalize")
    if (o.includeNumber) args.push("--includeNumber")
    return ["bw"].concat(args)
  }

  if (o.uppercase) args.push("--uppercase")
  if (o.lowercase) args.push("--lowercase")
  if (o.numbers) args.push("--number")
  if (o.special) args.push("--special")
  args.push("--length", String(o.length))
  if (o.numbers) args.push("--minNumber", String(o.minNumber))
  if (o.special) args.push("--minSpecial", String(o.minSpecial))
  if (o.ambiguous) args.push("--ambiguous")

  return ["bw"].concat(args)
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
  return buildCommand(["send", "list"], session, true)
}

function deleteSendCommand(sendId, session) {
  return buildCommand(["send", "delete", String(sendId)], session, true)
}

function removeSendPasswordCommand(sendId, session) {
  return buildCommand(["send", "remove-password", String(sendId)], session, true)
}

// The payload travels in the environment, not argv. Both the flag form's
// --password and an inlined `printf %s '<json>'` would land the Send password
// in /proc/<pid>/cmdline, which other users can read.
var SEND_ENV = "QSBW_SEND"

function sendEnvVar() {
  return SEND_ENV
}

function createSendCommand(session) {
  var script = "printf '%s' \"$" + SEND_ENV + "\" | bw encode | bw send create --session " + shellQuote(session)
  return ["bash", "-c", script]
}

// A file Send cannot go through stdin JSON -- bw wants the path on the command
// line -- but a path is not a secret, unlike a password.
function createFileSendCommand(filePath, name, deleteInDays, maxAccessCount, session) {
  var args = ["send", "--file", String(filePath)]
  if (name) args = args.concat(["--name", String(name)])
  args = args.concat(["-d", String(deleteInDays || 7)])
  if (maxAccessCount) args = args.concat(["-a", String(maxAccessCount)])
  args.push("--fullObject")
  return buildCommand(args, session, true)
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
