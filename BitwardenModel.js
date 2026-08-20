// BitwardenModel.js — Helper module for Bitwarden plugin.
// Pure JavaScript: CLI command constructors, output parsers, filtering, and CRUD builders.

.pragma library

const KEYRING_SERVICE = "qs-bitwarden-cli"
const KEYRING_ACCOUNT = "session"
const KEYRING_CLIENT_ID = "client_id"
const KEYRING_CLIENT_SECRET = "client_secret"
const KEYRING_EMAIL = "user_email"

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

function createItemCommand(itemData, session) {
  var jsonStr = JSON.stringify(itemData)
  var orgArg = (itemData && itemData.organizationId) ? (" --organizationid " + shellQuote(itemData.organizationId)) : ""
  var script = "printf %s " + shellQuote(jsonStr) + " | bw encode | bw create item" + orgArg + " --session " + shellQuote(session)
  return ["bash", "-c", script]
}

function editItemCommand(itemId, itemData, session) {
  var jsonStr = JSON.stringify(itemData)
  var script = "printf %s " + shellQuote(jsonStr) + " | bw encode | bw edit item " + shellQuote(itemId) + " --session " + shellQuote(session)
  return ["bash", "-c", script]
}

function deleteItemCommand(itemId, session) {
  return ["bw", "delete", "item", String(itemId), "--session", String(session).trim()]
}

// -------------------------------------------------------------------------
// Keyring (libsecret / secret-tool) Commands
// -------------------------------------------------------------------------

function keyringStoreCommand() {
  return ["secret-tool", "store", "--label=Bitwarden Vault Session", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringLookupCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringClearCommand() {
  return ["secret-tool", "clear", "service", KEYRING_SERVICE, "account", KEYRING_ACCOUNT]
}

function keyringStoreApiKeyIdCommand() {
  return ["secret-tool", "store", "--label=Bitwarden API Client ID", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_ID]
}

function keyringLookupApiKeyIdCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_ID]
}

function keyringStoreApiKeySecretCommand() {
  return ["secret-tool", "store", "--label=Bitwarden API Client Secret", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_SECRET]
}

function keyringLookupApiKeySecretCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_CLIENT_SECRET]
}

function keyringStoreEmailCommand() {
  return ["secret-tool", "store", "--label=Bitwarden User Email", "service", KEYRING_SERVICE, "account", KEYRING_EMAIL]
}

function keyringLookupEmailCommand() {
  return ["secret-tool", "lookup", "service", KEYRING_SERVICE, "account", KEYRING_EMAIL]
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

function filterItems(items, query, category, selectedOrg) {
  if (!Array.isArray(items)) return []
  var q = String(query || "").toLowerCase().trim()
  var cat = String(category || "all").toLowerCase()
  var org = String(selectedOrg || "all")

  var out = []
  for (var i = 0; i < items.length; i++) {
    var it = items[i]

    // Organization filter
    if (org === "personal") {
      if (it.organizationId) continue
    } else if (org !== "all") {
      if (it.organizationId !== org) continue
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

function buildCreatePayload(typeCode, name, username, password, totp, uri, notes, favorite, organizationId) {
  var payload = {
    type: Number(typeCode || 1),
    name: String(name || "Untitled").trim(),
    notes: String(notes || "").trim(),
    favorite: Boolean(favorite),
    organizationId: organizationId && organizationId !== "personal" && organizationId !== "all" ? String(organizationId) : null,
    folderId: null
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

function buildEditPayload(existingItem, name, username, password, totp, uri, notes, favorite, organizationId) {
  var payload = existingItem && existingItem.rawObject ? JSON.parse(JSON.stringify(existingItem.rawObject)) : {}
  payload.name = String(name || "Untitled").trim()
  payload.notes = String(notes || "").trim()
  payload.favorite = Boolean(favorite)
  if (organizationId && organizationId !== "personal" && organizationId !== "all") {
    payload.organizationId = String(organizationId)
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
