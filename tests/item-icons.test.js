#!/usr/bin/env node
// Item icons as Bitwarden's clients draw them (buildCipherIcon() in
// bitwarden/clients), the "Show website icons" and "Show details beside the
// list" settings, and the side-by-side layout's wiring.
//
//   node tests/item-icons.test.js

const { createSuite, loadModule, read, readPluginSource } = require("./harness")
const Model = loadModule()

const { check, done } = createSuite("item-icons")

const login = (uri, extra) => Object.assign({ typeCode: 1, type: "login", uris: uri === null ? [] : [uri] }, extra || {})
const NET = "https://icons.bitwarden.net"

// --- which host Bitwarden fetches an icon for ---------------------------------

const hosts = [
  ["https://github.com/login", "github.com"],
  ["http://Example.COM:8080/path?q=1#x", "example.com"],
  ["https://user:pw@vault.example.org/", "vault.example.org"],
  ["github.com", "github.com"],          // no scheme, has a dot: a website
  ["github.com/login", "github.com"],
  ["https://10.0.0.1/", "10.0.0.1"],
  ["https://example.com./", "example.com"],
  ["localhost", ""],                      // no dot
  ["https://localhost/", ""],
  ["ftp://files.example.com", ""],        // a scheme other than http(s)
  ["ssh://git@github.com", ""],
  ["androidapp://com.example.app", ""],
  ["iosapp://com.example.app", ""],
  ["http://abcdefghijklmnop.onion/", ""], // Bitwarden never fetches these
  ["eepsite.i2p", ""],
  ["https://exa mple.com/", ""],
  ["https://例え.jp/", ""],               // only plain ASCII hosts go in the URL
  ["https://evil.com\\@good.com/", ""],
  ["https://-bad-.com/", ""],
  ["", ""],
  [null, ""]
]
for (const [uri, want] of hosts) {
  check(`icon host for ${JSON.stringify(uri)}`, Model.websiteIconHost(uri) === want,
    `got ${JSON.stringify(Model.websiteIconHost(uri))}, want ${JSON.stringify(want)}`)
}

// --- which icon service --------------------------------------------------------

const services = [
  ["", NET],
  [null, NET],
  ["https://vault.bitwarden.com", NET],
  ["https://bitwarden.com", NET],
  ["https://vault.bitwarden.eu", "https://icons.bitwarden.eu"],
  ["https://vault.example.com", "https://vault.example.com/icons"],
  ["https://vault.example.com/", "https://vault.example.com/icons"],
  ["https://example.com/bitwarden/", "https://example.com/bitwarden/icons"],
  ["http://localhost:8080", "http://localhost:8080/icons"],
  ["vault.example.com", "https://vault.example.com/icons"],
  ["https://notbitwarden.com", "https://notbitwarden.com/icons"],
  ["https://bitwarden.com.evil.net", "https://bitwarden.com.evil.net/icons"],
  ["javascript:alert(1)", ""],
  ["https://vault.example.com/a b", ""],
  ["https://vault.example.com/?x=1", ""],
  ["https://u@vault.example.com", ""]
]
for (const [server, want] of services) {
  check(`icon service for ${JSON.stringify(server)}`, Model.iconServiceUrl(server) === want,
    `got ${JSON.stringify(Model.iconServiceUrl(server))}, want ${JSON.stringify(want)}`)
}

// --- the icon URL an item gets -------------------------------------------------

check("a login with a website gets its icon",
  Model.websiteIconUrl(login("https://github.com/login"), true, "") === NET + "/github.com/icon.png",
  Model.websiteIconUrl(login("https://github.com/login"), true, ""))
check("the first URI decides, as in Bitwarden",
  Model.websiteIconUrl(login("androidapp://x", { uris: ["androidapp://x", "https://github.com"] }), true, "") === "")
check("URI objects are read too (edit/detail shapes)",
  Model.websiteIconUrl(login(null, { uris: [{ uri: "https://gitlab.com", match: null }] }), true, "") === NET + "/gitlab.com/icon.png")
check("a self-hosted account asks its own server",
  Model.websiteIconUrl(login("https://github.com"), true, "https://vault.example.com") === "https://vault.example.com/icons/github.com/icon.png")
check("nothing is fetched with website icons off",
  Model.websiteIconUrl(login("https://github.com"), false, "") === "")
check("only a real true turns them on",
  Model.websiteIconUrl(login("https://github.com"), "true", "") === "")
check("non-logins never get a website icon",
  Model.websiteIconUrl({ typeCode: 2, type: "secureNote", uris: ["https://github.com"] }, true, "") === ""
    && Model.websiteIconUrl({ typeCode: 3, type: "card", card: { brand: "Visa" } }, true, "") === "")
check("a login without a URI gets none", Model.websiteIconUrl(login(null), true, "") === "")
check("no item gets none", Model.websiteIconUrl(null, true, "") === "")
check("an unusable server address means no icon rather than a guess",
  Model.websiteIconUrl(login("https://github.com"), true, "javascript:alert(1)") === "")

// --- glyphs --------------------------------------------------------------------

check("a plain login keeps the type glyph",
  Model.itemIconGlyph(login("https://github.com"), true) === Model.itemTypeGlyph(1))
check("an Android app URI gets the Android mark, icons on or off",
  Model.itemIconGlyph(login("androidapp://com.x"), true) === "\u{F0032}"
    && Model.itemIconGlyph(login("androidapp://com.x"), false) === "\u{F0032}")
check("an iOS app URI gets the Apple mark",
  Model.itemIconGlyph(login("iosapp://com.x"), false) === "\u{F0035}")
const visa = { typeCode: 3, type: "card", card: { brand: "Visa" } }
check("a card gets its brand mark with website icons on", Model.itemIconGlyph(visa, true) === "")
check("and the card glyph with them off", Model.itemIconGlyph(visa, false) === Model.itemTypeGlyph(3))
check("a brand without a mark keeps the card glyph",
  Model.itemIconGlyph({ typeCode: 3, card: { brand: "Maestro" } }, true) === Model.itemTypeGlyph(3)
    && Model.itemIconGlyph({ typeCode: 3, card: { brand: "__proto__" } }, true) === Model.itemTypeGlyph(3))
for (const code of [2, 4, 5]) {
  check(`type ${code} keeps its type glyph`, Model.itemIconGlyph({ typeCode: code }, true) === Model.itemTypeGlyph(code))
}
check("no item draws the login glyph", Model.itemIconGlyph(null, true) === Model.itemTypeGlyph(1))

// --- settings ------------------------------------------------------------------

const manifest = JSON.parse(read("manifest.json"))
for (const key of ["showWebsiteIcons", "sideBySide"]) {
  const entry = Model.SETTINGS_SCHEMA.find(e => e.key === key)
  const inManifest = manifest.barWidget.schema.find(e => e.key === key)
  check(`${key} is a General bool, on by default as in Bitwarden desktop`,
    !!entry && entry.group === "general" && entry.type === "bool" && entry.defaultValue === true,
    JSON.stringify(entry))
  check(`${key} matches the manifest`,
    !!inManifest && inManifest.type === "boolean" && inManifest.defaultValue === true
      && inManifest.label === entry.label && inManifest.description === entry.description
      && manifest.barWidget.defaults[key] === true,
    JSON.stringify(inManifest))
  check(`${key} rejects malformed input`,
    Model.boolSetting(key, "false") === true && Model.boolSetting(key, false) === false)
}
check("the website icon setting says what it discloses",
  /icon service/.test(Model.SETTINGS_SCHEMA.find(e => e.key === "showWebsiteIcons").description))

const service = read("Service.qml")
check("the service reads both settings through boolSetting",
  /readonly property bool showWebsiteIcons: Model\.boolSetting\("showWebsiteIcons", setting\("showWebsiteIcons", true\)\)/.test(service)
    && /readonly property bool sideBySide: Model\.boolSetting\("sideBySide", setting\("sideBySide", true\)\)/.test(service)
    && /case "showWebsiteIcons": return showWebsiteIcons/.test(service)
    && /case "sideBySide": return sideBySide/.test(service))

// --- the view ------------------------------------------------------------------

const panel = read("Panel.qml")
const icon = read("ItemIcon.qml")
check("list rows and the detail header draw ItemIcon with the setting and server",
  (panel.match(/ItemIcon \{[^}]*showWebsiteIcons: root\.vault\.showWebsiteIcons[^}]*serverUrl: root\.vault\.accountServer/g) || []).length === 2)
check("ItemIcon draws only the URL websiteIconUrl() gives",
  /Model\.websiteIconUrl\(item, showWebsiteIcons, serverUrl\)/.test(icon)
    && (icon.match(/source:/g) || []).length === 1 && /source: icon\.imageUrl/.test(icon))
check("the glyph stays until the image has loaded",
  /imageShown: imageUrl !== "" && favicon\.status === Image\.Ready/.test(icon)
    && /visible: !icon\.imageShown/.test(icon))
check("icons load off the GUI thread", /asynchronous: true/.test(icon))
check("icons are decoded at device pixels, not logical ones",
  /pixelSize: Math\.ceil\(size \* Math\.max\(1, Screen\.devicePixelRatio/.test(icon)
    && /sourceSize\.width: icon\.pixelSize/.test(icon) && /sourceSize\.height: icon\.pixelSize/.test(icon))
check("search spans both panes", /id: vaultSearchBar[\s\S]{0,600}id: searchField/.test(panel)
    && panel.indexOf("id: vaultSearchBar") < panel.indexOf("id: vaultSplit"))
check("x reaches the detail and Sends list through the kit's deleteRequested",
  /onDeleteRequested: \{[\s\S]{0,300}deleteSend[\s\S]{0,300}showDeleteConfirm = true/.test(panel)
    && !/lower === "x"/.test(panel))

check("the panel widens only for the split",
  /contentWidth: panel\.fittedContentWidth\(root\.splitView \? root\.splitPanelWidth : root\.compactPanelWidth\)/.test(panel)
    && /readonly property int compactPanelWidth: Style\.space\(450\)/.test(panel))
check("the split needs the setting, an unlocked vault and room",
  /readonly property bool splitView: root\.vault\.sideBySide && root\.vault\.status === "unlocked"\s*&& panel\.fittedContentWidth\(root\.splitPanelWidth\) >= Style\.space\(440\)/.test(panel))
check("the list stays beside an open item",
  /id: vaultListColumn\s*\/\/[^\n]*\n\s*visible: root\.vault\.activeScreen === "main" \|\| root\.splitView/.test(panel))
check("the detail pane is level with the list",
  /height: root\.splitView \? vaultListColumn\.height : implicitHeight/.test(panel))
check("an empty right pane says how to fill it",
  /visible: root\.splitView && root\.vault\.activeScreen === "main"/.test(panel) && /No item selected/.test(panel))
check("arrows walk the list with an item open beside it",
  /currentScreen === "detail" && root\.splitView\) \{[\s\S]{0,200}root\.vault\.browseDetail\(dy\)/.test(panel))
check("browsing does not teach suggestions",
  /function openDetail\(item, browsing\)/.test(service) && /if \(!browsing\) learnFromPick\(item\)/.test(service)
    && /openDetail\(item, true\)/.test(service))
check("browsing waits for the cursor to settle",
  /browseDetailTimer\.restart\(\)/.test(service) && /onTriggered: root\.openBrowsedDetail\(\)/.test(service))

// readPluginSource() folds the service into the view; it must still parse
// the new properties as the view's.
check("readPluginSource() still sees the split", /splitView/.test(readPluginSource("Panel.qml")))

done()
