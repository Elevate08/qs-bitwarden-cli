// BitwardenModel.js — Helper module for Bitwarden plugin.
// Pure JavaScript: CLI command constructors, output parsers, and filtering.

.pragma library

const KEYRING_SERVICE = "qs-bitwarden-cli"
const KEYRING_ACCOUNT = "session"
const PASSWORD_ENV = "BW_PASSWORD"

function buildCommand(args, session, useSession) {
  var cmd = ["bw"].concat(args || [])
  if (useSession && session) {
    cmd.push("--session", String(session).trim())
  }
  return cmd
}

function passwordEnvironment(password) {
  var env = ({})
  env[PASSWORD_ENV] = String(password || "")
  env["BW_NOINTERACTION"] = "true"
  return env
}

// -------------------------------------------------------------------------
// CLI Commands
// -------------------------------------------------------------------------

function statusCommand(session) {
  return buildCommand(["status"], session, Boolean(session))
}

function unlockCommand() {
  return ["bw", "unlock", "--passwordenv", PASSWORD_ENV, "--raw"]
}

function listCommand(session) {
  return buildCommand(["list", "items"], session, true)
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
    case "identity": return "󰓹"   // id card icon
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
      name: String(it.name || "Untitled"),
      type: itemTypeName(it.type),
      typeCode: Number(it.type || 1),
      favorite: Boolean(it.favorite),
      username: String(login.username || ""),
      hasPassword: Boolean(login.password),
      hasTotp: Boolean(login.totp),
      uris: uris,
      subtitle: subtitle,
      notes: String(it.notes || "")
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
    name: String(it.name || "Untitled"),
    type: itemTypeName(it.type),
    typeCode: Number(it.type || 1),
    favorite: Boolean(it.favorite),
    notes: String(it.notes || ""),
    username: String(login.username || ""),
    password: String(login.password || ""),
    hasTotp: Boolean(login.totp),
    uris: uris,
    card: card,
    identity: identity,
    fields: customFields
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

function filterItems(items, query, category) {
  if (!Array.isArray(items)) return []
  var q = String(query || "").toLowerCase().trim()
  var cat = String(category || "all").toLowerCase()

  var out = []
  for (var i = 0; i < items.length; i++) {
    var it = items[i]
    if (cat === "favorite") {
      if (!it.favorite) continue
    } else if (cat !== "all" && it.type !== cat) {
      continue
    }

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
