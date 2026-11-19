#!/usr/bin/env node
// The window-title suggestion matcher: heuristic, so easy to regress either
// way (right login missing, or every .com item suggested everywhere).
//
//   node tests/context-match.test.js

const { createSuite, loadModule } = require("./harness")

const Model = loadModule()

const items = [
  { id: "1",  name: "GitHub",        uris: ["https://github.com"] },
  { id: "2",  name: "Amazon",        uris: ["https://www.amazon.com"] },
  { id: "3",  name: "Home Assistant",uris: ["https://homeassistant.local:8123"] },
  { id: "4",  name: "Google",        uris: ["https://accounts.google.com"] },
  { id: "5",  name: "Reddit",        uris: ["https://reddit.com"] },
  { id: "6",  name: "Proton Mail",   uris: ["https://account.proton.me"] },
  { id: "7",  name: "Cloudflare",    uris: ["https://dash.cloudflare.com"] },
  { id: "8",  name: "My Bank",       uris: ["https://www.chase.com"] },
  { id: "9",  name: "Netflix",       uris: ["https://www.netflix.com"] },
  { id: "10", name: "Jellyfin",      uris: ["http://192.168.1.50:8096"] },
  { id: "11", name: "GitHub (work)", uris: ["https://github.com"] },
  { id: "12", name: "BBC iPlayer",   uris: ["https://www.bbc.co.uk"] },
  { id: "13", name: "Discord",       uris: ["https://discord.com"] },
  { id: "14", name: "Slack",         uris: ["https://acme.slack.com"] },
  { id: "15", name: "Spotify",       uris: ["https://open.spotify.com"] },
  { id: "16", name: "Nextcloud",     uris: ["https://cloud.example.org"] },
  { id: "17", name: "Router Admin",  uris: ["http://192.168.1.1"] },
  { id: "18", name: "AWS Console",   uris: ["https://console.aws.amazon.com"] },
]

// [window class, window title, expected suggestion names]
const cases = [
  // Site name lives in the title but the domain does not -- the common case.
  ["chromium", "Settings – Home Assistant - Chromium",                    ["Home Assistant"]],
  ["chromium", "Reddit - Dive into anything - Chromium",                  ["Reddit"]],
  ["chromium", "Netflix - Chromium",                                      ["Netflix"]],
  ["chromium", "Proton Mail - Chromium",                                  ["Proton Mail"]],
  ["chromium", "Cloudflare Dashboard - Chromium",                         ["Cloudflare"]],
  ["chromium", "Chase Online - Credit Cards, Mortgages, Auto - Chromium", ["My Bank"]],
  ["chromium", "Jellyfin - Chromium",                                     ["Jellyfin"]],
  ["chromium", "Files - Nextcloud - Chromium",                            ["Nextcloud"]],
  ["chromium", "Acme Corp Slack - Chromium",                              ["Slack"]],
  ["chromium", "Spotify – Web Player - Chromium",                         ["Spotify"]],
  ["chromium", "AWS Management Console - Chromium",                       ["AWS Console"]],
  ["firefox",  "BBC iPlayer - Home — Mozilla Firefox",                    ["BBC iPlayer"]],
  ["chromium", "Discord | #general | My Server - Chromium",               ["Discord"]],

  // Sign-in prefixes, unread counters and browser branding are noise.
  ["firefox",  "Sign in to GitHub · GitHub — Mozilla Firefox",            ["GitHub", "GitHub (work)"]],
  ["chromium", "(3) Inbox (1,204) - me@gmail.com - Gmail - Chromium",     ["Google"]],

  // Brand alias: the title never says "google".
  ["chromium", "Gmail - Chromium",                                        ["Google"]],
  ["chromium", "Untitled document - Google Docs - Chromium",              ["Google"]],

  // A domain in the title must not drag in every item sharing its TLD.
  ["chromium", "Amazon.com. Spend less. Smile more. - Chromium",          ["Amazon", "AWS Console"]],

  // Nothing identifiable: suggest nothing rather than guess.
  ["chromium", "New Tab - Chromium",                                      []],
  ["chromium", "Sign in - Chromium",                                      []],
  ["chromium", "How to fix config.json v1.2 errors - Stack Overflow - Chromium", []],

  // Terminals: local shells describe a machine, not a credential.
  ["foot",     "workstation: notes",                                        []],
  // ...and a remote host must not match a different domain sharing a label.
  ["foot",     "ssh user@git.example.com",                            []],

  // Native desktop apps match on window class.
  ["discord",  "Discord | #general",                                      ["Discord"]],
  ["spotify",  "Spotify Premium",                                         ["Spotify"]],
]

// A large vault of .com sites: a single site must not suggest all of them.
const floodItems = ["github","amazon","google","reddit","proton","cloudflare","chase",
  "netflix","discord","slack","spotify","dropbox","twitch","ebay","paypal","stripe",
  "linode","digitalocean","namecheap","fastmail","zoom","notion","figma","linear",
  "vercel","heroku","atlassian","gitlab","bitbucket","sentry","datadog","okta",
  "auth0","twilio","sendgrid","mailgun","shopify","squarespace","wordpress","medium"]
  .map((b, i) => ({ id: String(i), name: b, uris: ["https://www." + b + ".com"] }))

const { check, done } = createSuite("context-match")

const sshLike = { id: "ssh-public", name: "GitHub deploy key", typeCode: 5,
  uris: ["https://github.com"], publicKey: "ssh-ed25519 AAAA" }
check("context suggestions exclude SSH public records",
  Model.findContextualMatches(items.concat([sshLike]),
    { class: "chromium", title: "GitHub - Chromium", mapped: true }).matches.every(m => m.id !== "ssh-public"),
  "SSH key leaked into contextual suggestions")

for (const [cls, title, expected] of cases) {
  const got = Model.findContextualMatches(items, { class: cls, title, mapped: true })
    .matches.map(m => m.name).sort()
  check(`[${cls}] ${title}`,
    JSON.stringify(got) === JSON.stringify(expected.slice().sort()),
    `expected [${expected}] but got [${got}]`)
}

for (const [title, max] of [["Amazon.com. Spend less. Smile more. - Chromium", 1],
                            ["Some Random Blog Post About Nothing - Chromium", 0]]) {
  const got = Model.findContextualMatches(floodItems, { class: "chromium", title, mapped: true }).matches
  check(`flood: ${title}`, got.length <= max,
    `expected at most ${max} suggestion(s) from a 40-item vault, got ${got.length}: [${got.map(g => g.name)}]`)
}

// Hostname parsing feeds every domain comparison.
for (const [host, root, base] of [
  ["github.com", "github", "github.com"],
  ["dash.cloudflare.com", "cloudflare", "cloudflare.com"],
  ["www.bbc.co.uk", "bbc", "bbc.co.uk"],
  ["homeassistant.local", "homeassistant", "homeassistant.local"],
  ["console.aws.amazon.com", "amazon", "amazon.com"],
]) {
  const p = Model.parseHost(host)
  check(`parseHost(${host})`, p && p.rootName === root && p.baseDomain === base,
    `expected root=${root} base=${base}, got root=${p && p.rootName} base=${p && p.baseDomain}`)
}

// The most recently focused non-shell client wins in a `hyprctl clients` list.
const clients = [
  { class: "quickshell", title: "shell", focusHistoryID: 0, mapped: true },
  { class: "chromium", title: "Netflix - Chromium", focusHistoryID: 1, mapped: true },
  { class: "foot", title: "workstation: notes", focusHistoryID: 2, mapped: true },
]
check("clients list picks most recent non-shell window",
  Model.findContextualMatches(items, clients).matches.map(m => m.name).join() === "Netflix",
  `got [${Model.findContextualMatches(items, clients).matches.map(m => m.name)}]`)


// ---------------------------------------------------------------------------
// Learned associations
// ---------------------------------------------------------------------------

// No heuristic can match this: an authentik portal titled "Home - authentik"
// whose name and URL share no word with the title. Pinning it with "Suggest
// here" must.
const authentikItem = { id: "auth-1", name: "Personal SSO", uris: ["https://auth.example.xyz"] }
const withAuthentik = items.concat([authentikItem])
const authentikWindow = { class: "chromium", title: "Home - authentik - Chromium", mapped: true }

let assoc = Model.emptyAssociations()

check("authentik: unmatched before learning",
  Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.length === 0,
  `got [${Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.map(m => m.name)}]`)

const ctx = Model.cleanWindowContext(authentikWindow)

// An ordinary pick learns the domain or app only, never the title's words: a
// learned match skips scoring and a page picks its own title, so a word
// learned from a pick let any page sharing it (a lookalike) have the real
// site's login suggested first.
const picked = Model.recordAssociation(assoc, ctx, authentikItem.id, "2026-08-20T00:00:00Z")
check("an ordinary pick records no title words",
  Object.keys(picked.keys).every(k => !k.startsWith("word:")), Object.keys(picked.keys).join(","))
check("so a title-only site is not suggested from a pick",
  Model.findContextualMatches(withAuthentik, authentikWindow, picked).matches.length === 0,
  `got [${Model.findContextualMatches(withAuthentik, authentikWindow, picked).matches.map(m => m.name)}]`)
const domainWindow = { class: "chromium", title: "Dashboard - status.example.org - Chromium", mapped: true }
const domainPicked = Model.recordAssociation(assoc, Model.cleanWindowContext(domainWindow), authentikItem.id, "2026-08-20T00:00:00Z")
check("a pick still learns the site's domain",
  Object.keys(domainPicked.keys).join() === "domain:example.org"
    && Model.findContextualMatches(withAuthentik, domainWindow, domainPicked).matches[0].id === "auth-1",
  Object.keys(domainPicked.keys).join(","))
// Stores written before this rule hold word keys learned from picks.
const legacyWords = Model.parseAssociations(JSON.stringify({ version: 1, keys: {
  "word:authentik": { itemId: "auth-1", weight: 1, count: 3, updated: "2026-08-01T00:00:00Z" } } }))
check("an unpinned word key from an older store no longer suggests",
  Model.findContextualMatches(withAuthentik, authentikWindow, legacyWords).matches.length === 0
    && !Model.isAssociated(legacyWords, ctx, "auth-1"),
  `got [${Model.findContextualMatches(withAuthentik, authentikWindow, legacyWords).matches.map(m => m.name)}]`)

// Pin the credential with "Suggest here" while that window is active.
assoc = Model.recordAssociation(assoc, ctx, authentikItem.id, "2026-08-20T00:00:00Z", true)
check("a pin records the title's words, marked pinned",
  Object.keys(assoc.keys).some(k => k.startsWith("word:"))
    && Object.keys(assoc.keys).every(k => assoc.keys[k].pinned === true),
  JSON.stringify(assoc.keys))
const pickedAfterPin = Model.recordAssociation(assoc, ctx, authentikItem.id, "2026-08-21T00:00:00Z")
check("a later ordinary pick keeps the pin",
  Object.keys(assoc.keys).every(k => pickedAfterPin.keys[k] && pickedAfterPin.keys[k].pinned === true),
  JSON.stringify(pickedAfterPin.keys))

check("authentik: suggested after one pin",
  Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.map(m => m.id).join() === "auth-1",
  `got [${Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.map(m => m.name)}]`)

// Learning generalises across pages of the same site, which share the word.
check("authentik: generalises to another page of the same site",
  Model.findContextualMatches(withAuthentik,
    { class: "chromium", title: "Applications - authentik - Chromium", mapped: true }, assoc)
    .matches.map(m => m.id).join() === "auth-1",
  "expected the learned item on a sibling page")

check("authentik: does not leak to unrelated sites",
  Model.findContextualMatches(withAuthentik,
    { class: "chromium", title: "Netflix - Chromium", mapped: true }, assoc)
    .matches.map(m => m.name).join() === "Netflix",
  "a learned key must not fire on an unrelated title")

check("isAssociated reports the learned pair", Model.isAssociated(assoc, ctx, "auth-1"), "expected true")

// Last pin wins, so a key learned from the wrong page corrects itself.
const retargeted = Model.recordAssociation(assoc, ctx, "9", "2026-08-21T00:00:00Z", true)
check("re-picking retargets the key",
  Model.findContextualMatches(withAuthentik, authentikWindow, retargeted).matches.map(m => m.id).join() === "9",
  "expected the newly picked item to win")

// Explicit unlearn.
const forgotten = Model.forgetAssociation(assoc, ctx, "auth-1")
check("forgetting removes the suggestion",
  Model.findContextualMatches(withAuthentik, authentikWindow, forgotten).matches.length === 0,
  "expected no suggestions after forgetting")

// A learned item outranks a heuristic match on the same window.
let netflixAssoc = Model.recordAssociation(Model.emptyAssociations(),
  Model.cleanWindowContext({ class: "chromium", title: "Netflix - Chromium", mapped: true }), "11", undefined, true)
check("learned item is ranked ahead of a heuristic match",
  Model.findContextualMatches(items, { class: "chromium", title: "Netflix - Chromium", mapped: true }, netflixAssoc)
    .matches[0].id === "11",
  "expected the learned item first")

// Round-tripping through the on-disk format must preserve behaviour.
const roundTripped = Model.parseAssociations(Model.serializeAssociations(assoc))
check("associations survive a save/load round trip",
  Model.findContextualMatches(withAuthentik, authentikWindow, roundTripped).matches.map(m => m.id).join() === "auth-1",
  "expected the learned item after reload")

check("corrupt association file degrades to empty",
  Model.parseAssociations("{{not json").keys && Object.keys(Model.parseAssociations("{{not json").keys).length === 0,
  "expected an empty store")

const hostileAssociations = Model.parseAssociations(
  '{"version":1,"keys":{"__proto__":{"polluted":true},"arbitrary":{"itemId":"x"},'
  + '"word:valid":{"itemId":"auth-1","weight":1,"count":2,"updated":"2026-08-24T00:00:00Z"}}}')
const copiedHostile = Model.recordAssociation(hostileAssociations, ctx, "auth-1", "2026-12-31T00:00:00Z")
check("association parsing drops keys outside the domain/app/word schema",
  !Object.prototype.hasOwnProperty.call(hostileAssociations.keys, "__proto__")
    && !Object.prototype.hasOwnProperty.call(hostileAssociations.keys, "arbitrary")
    && Object.prototype.hasOwnProperty.call(hostileAssociations.keys, "word:valid"),
  Object.keys(hostileAssociations.keys).join(","))
check("hostile association keys cannot become the prototype of a copied store",
  copiedHostile.keys.polluted === undefined, JSON.stringify(copiedHostile.keys))
check("association entries without a bounded string item id are dropped",
  Object.keys(Model.parseAssociations(
    '{"version":1,"keys":{"word:bad":{"itemId":{}},"word:good":{"itemId":"x"}}}').keys).join()
    === "word:good",
  "invalid item id survived")
check("unknown association schema versions fail closed",
  Object.keys(Model.parseAssociations(
    '{"version":999,"keys":{"word:old":{"itemId":"x"}}}').keys).length === 0,
  "unknown schema was accepted")

// Suggestions must still work with no association store at all.
check("undefined associations are safe",
  Model.findContextualMatches(items, { class: "chromium", title: "Netflix - Chromium", mapped: true })
    .matches.map(m => m.name).join() === "Netflix",
  "expected heuristics to work without a store")


// ---------------------------------------------------------------------------
// A window title is written by the page, not by the user
// ---------------------------------------------------------------------------
//
// document.title is chosen by the page, and matched on the GUI thread against
// the whole vault on every open.

// The title reaches the matcher clipped, so the per-item work the matcher does
// over it cannot be scaled up by the page.
const longTitle = "verylongword".repeat(6000)
const clippedCtx = Model.cleanWindowContext({ class: "chromium", title: longTitle, mapped: true })
check("a page-chosen title is clipped before matching",
  clippedCtx.matchText.length <= Model.MAX_TITLE_CHARS
    && clippedCtx.rawTitle.length <= Model.MAX_TITLE_CHARS,
  `matchText=${clippedCtx.matchText.length} rawTitle=${clippedCtx.rawTitle.length}`)

// Long dotless runs once drove the host regex quadratic (~2.5 s for 63 kB);
// hyprctl can hand over a megabyte.
const hostileTitle = "a".repeat(100000) + " - Chromium"
const hostileWindow = { class: "chromium", title: hostileTitle, mapped: true }
const bigVault = []
for (let i = 0; i < 2000; i++) {
  bigVault.push({ id: `big-${i}`, name: `Account ${i}`, uris: [`https://site${i}example.com`] })
}
const started = Date.now()
Model.findContextualMatches(bigVault, hostileWindow, Model.emptyAssociations())
const elapsed = Date.now() - started
check("a hostile window title does not stall the matcher", elapsed < 2000,
  `matching a 100 kB title against 2000 items took ${elapsed}ms`)

// Splitting replaced the regex, so prove it still reads the same hosts out.
for (const [text, expected] of [
  ["Files - Nextcloud - cloud.example.org", "example.org"],
  ["https://sub.example.co.uk/path", "example.co.uk"],
  ["see .example.com now", "example.com"],
  ["a..b.example.com", "example.com"],
  ["config.json is not a host", null],
  ["version 1.2.3.4 released", null],
  ["nothing here at all", null],
]) {
  const got = Model.cleanWindowContext({ class: "chromium", title: text, mapped: true })
  const base = got && got.detectedDomain ? got.detectedDomain.baseDomain : null
  check(`host detection in ${JSON.stringify(text)}`, base === expected,
    `expected ${expected}, got ${base}`)
}

// Every word of a title becomes a stored key, and the store is read back
// through a byte cap that turns an oversized file into no file at all. The
// write side has to stay under that cap on its own.
let grown = Model.emptyAssociations()
for (let p = 0; p < 300; p++) {
  const words = []
  for (let w = 0; w < 80; w++) words.push(`tok${p}x${w}zz`)
  grown = Model.recordAssociation(grown,
    Model.cleanWindowContext({ class: "chromium", title: words.join(" "), mapped: true }),
    "auth-1", `2026-08-${String((p % 28) + 1).padStart(2, "0")}T00:00:00Z`, true)
}
const grownBytes = Model.serializeAssociations(grown).length
check("the association store stays inside the cap it is read back through",
  grownBytes < Model.MAX_ASSOC_BYTES,
  `store grew to ${grownBytes} bytes against a ${Model.MAX_ASSOC_BYTES} byte read cap`)

// Trimming must not cost the most recent lesson.
const recentCtx = Model.cleanWindowContext(authentikWindow)
const stillLearned = Model.recordAssociation(grown, recentCtx, "auth-1", "2026-12-31T00:00:00Z", true)
check("the newest lesson survives trimming",
  Model.findContextualMatches(withAuthentik, authentikWindow, stillLearned).matches.map(m => m.id).join() === "auth-1",
  "expected the just-learned item to still be suggested")

// --- whole words: the shortcut answers as the expression alone did ---------

// hasWholeWord() refuses a word that is nowhere in the lowercased text before
// building its RegExp. That must never change an answer, including where
// case-insensitive matching and toLowerCase() disagree about a character.
{
  const reference = (haystack, word) => {
    if (!haystack || !word) return false
    return new RegExp("(?:^|[^a-z0-9])" + Model.escapeRegExp(word) + "(?:$|[^a-z0-9])", "i").test(haystack)
  }
  const texts = ["", "GitHub", "github", "Sign in to GITHUB - Mozilla Firefox", "mygithub", "github2", "git-hub",
    "Home Assistant", "my-site login", "MY-SITE", "x my-site", "a1b2c3", "A1B2C3 d", "amazon.com: shopping",
    "\u0130stanbul", "D\u0130YAN", "\u0131nfo", "\u212Aelvin k", "ma\u017Fs mass", "STRASSE stra\u00DFe",
    "\u03A3\u039F\u03A6\u039F\u03A3 sofos", "SI\u0130 si", "\u00C9cole ecole", "caf\u00E9", "a.b", "a+b (c)", "tab\tsite\nline",
    "site", " site ", "_site_", "site.", "SITE!", "websites", "\uD83D\uDD12 Secure \u2014 bank"]
  const words = ["github", "git", "hub", "my-site", "site", "a1b2c3", "amazon", "istanbul", "i", "info", "k", "kelvin",
    "mass", "strasse", "ss", "sofos", "si", "ecole", "cafe", "bank", "secure", "a.b", "a+b", "GitHub", "SITE",
    "\u0131nfo", "caf\u00E9", "stra\u00DFe", "\u03C3", "-", "0", "(c)", "\\", "^", "$"]
  let compared = 0
  const wrong = []
  const compare = (text, word) => {
    compared += 1
    if (Model.hasWholeWord(text, word) !== reference(text, word)) wrong.push(JSON.stringify([text, word]))
  }
  for (const text of texts) for (const word of words) compare(text, word)
  // And at random, from an alphabet that mixes both cases with the characters
  // whose case mappings are not one to one.
  const alphabet = "abcABCxyzXYZ019- ._\u0130\u0131\u212A\u017F\u00DF\u03A3\u03C3\u03C2\u00E9\u00C9"
  let seed = 20261119
  const next = n => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n }
  const random = max => {
    let out = ""
    for (let n = 1 + next(max); n > 0; n--) out += alphabet[next(alphabet.length)]
    return out
  }
  for (let i = 0; i < 20000; i++) compare(random(14), random(3))
  check("the whole-word shortcut never changes an answer",
    wrong.length === 0 && compared > 21000, wrong.slice(0, 8).join(" ") + " of " + compared)
  check("a haystack that is not a string is still the expression's to coerce",
    Model.hasWholeWord(123, "123") === true && Model.hasWholeWord(123, "12") === false
      && Model.hasWholeWord({ toString() { return "my site" } }, "site") === true
      && Model.hasWholeWord(["a", "site"], "site") === true)
  {
    // Coerced once, by the expression: a word that reads differently the
    // second time must not be judged by the shortcut first.
    let reads = 0
    const shifty = { toString() { return reads++ === 0 ? "site" : "zzz" } }
    check("a word that is not a string is the expression's to coerce as well",
      Model.hasWholeWord("my site", shifty) === true && reads === 1
        && Model.hasWholeWord("a 123 b", 123) === true && Model.hasWholeWord("a 123 b", 12) === false)
  }
  // The point of the shortcut: no RegExp is built for a word that is absent.
  // Literals do not go through the constructor, so counting it counts those.
  const RealRegExp = RegExp
  let built = 0
  const counting = fn => {
    built = 0
    global.RegExp = function (...args) { built += 1; return new RealRegExp(...args) }
    global.RegExp.prototype = RealRegExp.prototype
    try { return [fn(), built] } finally { global.RegExp = RealRegExp }
  }
  check("an absent word is refused without building a RegExp",
    counting(() => Model.hasWholeWord("Sign in to GitHub - Mozilla Firefox", "amazon")).join() === "false,0"
      && counting(() => Model.hasWholeWord("Sign in to GitHub - Mozilla Firefox", "github")).join() === "true,1"
      && counting(() => Model.hasWholeWord("mygithub", "github")).join() === "false,1"
      && counting(() => Model.hasWholeWord("caf\u00E9", "caf\u00E9")).join() === "true,1",
    String(built))
  const hits = texts.filter(t => Model.hasWholeWord(t, "site")).length
  check("...and both answers occur among those", hits > 3 && hits < texts.length, String(hits))
}

// --- opening the panel matches once, not twice ------------------------------------
// An open asks for suggestions with the window the panel already knew
// (ensureItemsFresh()), then again when the compositor names the focused one.
// The service's own functions, as written, over a counting matcher.
{
  const { functionBody, read } = require("./harness")
  const svc = read("Service.qml")
  function service(state) {
    let itemsValue = [], associationsValue = Model.emptyAssociations()
    const counting = Object.create(Model)
    const v = Object.assign({ Model: counting, matches: 0, rebuilds: 0, loads: 0, suggestOnOpen: true,
      activeWindowData: null, suggestedItems: [], detectedContext: null, learnedIds: {},
      contextMatchKey: "", contextInputsGen: 0, itemsLoadedAt: Date.now(), itemsFreshMs: 60000,
      rebuildFilter() { v.rebuilds++ }, beginInitialVaultLoad() { v.loads++ }, invalidateHelperSearch() {} }, state)
    counting.findContextualMatches = function () { v.matches++; return Model.findContextualMatches.apply(Model, arguments) }
    // As onItemsChanged / onAssociationsChanged do (tests/qml/tst_var_change.qml
    // holds what they rest on): another array or object moves the count.
    Object.defineProperty(v, "items", { get: () => itemsValue,
      set(next) { if (next !== itemsValue) { itemsValue = next; v.contextInputsGen += 1 } } })
    Object.defineProperty(v, "associations", { get: () => associationsValue,
      set(next) { if (next !== associationsValue) { associationsValue = next; v.contextInputsGen += 1 } } })
    const names = ["clearContextMatch", "windowDetectionFailed", "handleActiveWindowDetected", "ensureItemsFresh", "refreshDerivedFromItems"]
    Object.assign(v, new Function("scope", "with (scope) {\n" + names.map(nm => functionBody(svc, nm)).join("\n")
      + "\nreturn { " + names.join(", ") + " } }")(v))
    // What the compositor's answer does: a fresh parse each time.
    v.detected = win => v.handleActiveWindowDetected(JSON.parse(JSON.stringify(win)))
    // One open: the stale-window pass, then the detection's answer.
    v.open = win => { v.ensureItemsFresh(); v.detected(win) }
    return v
  }
  const shown = v => JSON.stringify([v.suggestedItems.map(i => i.id), v.detectedContext, v.learnedIds])
  const fresh = v => {
    const res = v.suggestOnOpen && v.items.length ? Model.findContextualMatches(v.items, v.activeWindowData, v.associations)
      : { matches: [], context: null, learnedIds: {} }
    return JSON.stringify([res.matches.map(i => i.id), res.context, res.learnedIds || {}])
  }
  const github = { class: "firefox", title: "GitHub - Mozilla Firefox", mapped: true }
  const netflix = { class: "chromium", title: "Netflix - Chromium", mapped: true }

  check("the service counts every replacement of the list and of the learned picks, and keys the match by it",
    /\n  onItemsChanged: contextInputsGen \+= 1\n  onAssociationsChanged: contextInputsGen \+= 1\n/.test(svc)
      && /var key = Model\.contextMatchKey\(contextInputsGen, data\)\s+if \(key === "" \|\| key !== contextMatchKey\) \{\s+var res = Model\.findContextualMatches\(items, data, associations\)/.test(functionBody(svc, "handleActiveWindowDetected"))
      && (svc.match(/Model\.findContextualMatches\(/g) || []).length === 1)
  check("the key spells the window out and carries the count; a window that cannot be spelled equals nothing",
    Model.contextMatchKey(3, github) === "3|" + JSON.stringify(github)
      && Model.contextMatchKey(3, github) !== Model.contextMatchKey(4, github)
      && Model.contextMatchKey(3, github) !== Model.contextMatchKey(3, netflix)
      && Model.contextMatchKey(3, undefined) === "" && Model.contextMatchKey(3, () => 1) === ""
      && (() => { const loop = {}; loop.self = loop; return Model.contextMatchKey(3, loop) === "" })())

  const v = service({})
  v.items = items.slice()
  v.detected(github)
  check("the first answer is matched", v.matches === 1 && shown(v) === fresh(v) && v.suggestedItems.length > 0, shown(v))
  v.matches = 0; v.rebuilds = 0
  v.open(netflix)
  check("an open from another window matches once (it used to be twice), and shows that window's suggestions",
    v.matches === 1 && shown(v) === fresh(v) && v.suggestedItems[0].name === "Netflix", `${v.matches} ${shown(v)}`)
  check("...and still rebuilds the list both times", v.rebuilds === 2, String(v.rebuilds))
  v.matches = 0
  v.open(netflix)
  check("an open from the same window, with nothing changed, matches no more", v.matches === 0 && shown(v) === fresh(v), String(v.matches))
  const before = v.suggestedItems
  v.open(netflix)
  check("...and leaves the very suggestions that were on show", v.suggestedItems === before)

  // Whatever changes the answer is matched again, at once.
  v.matches = 0
  v.items = v.items.filter(i => i.name !== "Netflix")
  v.refreshDerivedFromItems()
  check("a list replaced is matched again by the refresh that follows it",
    v.matches === 1 && shown(v) === fresh(v) && v.suggestedItems.every(i => i.name !== "Netflix"), shown(v))
  v.matches = 0
  v.items = v.items.slice()
  v.open(netflix)
  check("...and so is one replaced by an equal list: it is another list", v.matches === 1 && shown(v) === fresh(v))
  v.matches = 0
  const ctx = Model.findContextualMatches(items, github).context
  v.associations = Model.recordAssociation(v.associations, ctx, "5", "2026-01-01T00:00:00Z", true)
  v.open(github)
  check("a pick learned since the last match shows on the next open, from the first of its two passes",
    v.matches === 2 && shown(v) === fresh(v) && v.suggestedItems[0].id === "5", `${v.matches} ${shown(v)}`)
  v.matches = 0
  v.suggestOnOpen = false
  v.open(github)
  check("suggestions turned off: nothing is matched and nothing is suggested",
    v.matches === 0 && v.suggestedItems.length === 0 && v.detectedContext === null && v.contextMatchKey === "")
  v.suggestOnOpen = true
  v.open(github)
  check("...and turned on again, the same window is matched afresh, not taken from before",
    v.matches === 1 && shown(v) === fresh(v) && v.suggestedItems.length > 0, `${v.matches}`)
  check("whatever clears the suggestions clears the key, the context and the learned marks with them",
    /^function clearContextMatch\(\) \{\s+contextMatchKey = ""\s+suggestedItems = \[\]\s+detectedContext = null\s+learnedIds = \(\{\}\)\s+\}$/.test(functionBody(svc, "clearContextMatch"))
      // The one place that spells it out instead is the vault purge.
      && (svc.match(/contextMatchKey = ""\n\s+suggestedItems = \[\]\n\s+detectedContext = null\n\s+learnedIds = \(\{\}\)/g) || []).length === 2
      && (svc.match(/\bclearContextMatch\(\)\n/g) || []).length === 5
      && (svc.match(/\bsuggestedItems = /g) || []).length === 3)
  check("the vault purge (a lock, a logout, an account left) drops the suggestions and the key that names the window",
    /items = \[\]\s+filteredItems = \[\]\s+(?:\/\/[^\n]*\n\s+)*contextMatchKey = ""\s+suggestedItems = \[\]\s+detectedContext = null\s+learnedIds = \(\{\}\)/.test(functionBody(svc, "dropVaultState")))

  // An emptied vault: nothing is left to suggest, and nothing stays on show.
  const e = service({})
  e.items = items.slice()
  e.open(github)
  const hadSuggestions = e.suggestedItems.length > 0 && e.contextMatchKey !== "" && e.detectedContext !== null
  e.matches = 0; e.rebuilds = 0
  e.items = []
  e.refreshDerivedFromItems()
  check("a list that has become empty takes the suggestions, the context, the learned marks and the key with it, and the list is rebuilt",
    hadSuggestions && e.matches === 0 && e.suggestedItems.length === 0 && e.detectedContext === null
      && JSON.stringify(e.learnedIds) === "{}" && e.contextMatchKey === "" && e.rebuilds >= 1,
    JSON.stringify([hadSuggestions, e.matches, e.suggestedItems.length, e.contextMatchKey, e.rebuilds]))
  e.items = items.slice()
  e.open(github)
  check("...and a list that comes back is matched afresh", e.matches === 1 && shown(e) === fresh(e) && e.suggestedItems.length > 0)

  // The compositor's answer could not be read, or was empty.
  const f = service({})
  f.items = items.slice()
  f.open(github)
  const showing = f.suggestedItems.length > 0 && f.contextMatchKey !== ""
  f.matches = 0; f.rebuilds = 0
  f.windowDetectionFailed()
  check("a window read that failed leaves no suggestions, context, learned marks or key from the last window, and the list is rebuilt without its rows",
    showing && f.suggestedItems.length === 0 && f.detectedContext === null && JSON.stringify(f.learnedIds) === "{}"
      && f.contextMatchKey === "" && f.activeWindowData === null && f.rebuilds === 1 && f.matches === 0)
  f.items = f.items.slice()
  f.refreshDerivedFromItems()
  check("...and a list reloaded after it does not match the old window again", f.matches === 0 && f.suggestedItems.length === 0)
  f.open(github)
  check("...until a window is read again", f.matches === 1 && shown(f) === fresh(f) && f.suggestedItems.length > 0)
  check("both ways a read fails end there: output that does not parse, and no output",
    /if \(text && text\.trim\(\)\) \{\s+try \{\s+var data = JSON\.parse\(text\)\s+root\.handleActiveWindowDetected\(data\)\s+\} catch \(e\) \{\s+root\.windowDetectionFailed\(\)\s+\}\s+\} else \{\s+root\.windowDetectionFailed\(\)\s+\}/.test(svc)
      && /^function windowDetectionFailed\(\) \{\s+activeWindowData = null\s+clearContextMatch\(\)\s+rebuildFilter\(\)\s+\}$/.test(functionBody(svc, "windowDetectionFailed")))

  // Two windows JSON spells alike are not one question.
  const huge = JSON.parse('{"class":"firefox","title":"GitHub - Mozilla Firefox","mapped":true,"focusHistoryID":1e400}')
  const nulled = JSON.parse('{"class":"firefox","title":"GitHub - Mozilla Firefox","mapped":true,"focusHistoryID":null}')
  check("a window with a number JSON cannot write (1e400 reads as Infinity and would be written as null) gets no key",
    huge.focusHistoryID === Infinity && JSON.stringify(huge) === JSON.stringify(nulled)
      && Model.contextMatchKey(3, huge) === "" && Model.contextMatchKey(3, nulled) !== ""
      && Model.contextMatchKey(3, { a: [1, { b: NaN }] }) === "" && Model.contextMatchKey(3, { a: [1, { b: -Infinity }] }) === ""
      && Model.contextMatchKey(3, { a: undefined }) === "" && Model.contextMatchKey(3, { a: () => 1 }) === ""
      && Model.contextMatchKey(3, { a: [1, { b: 2.5 }] }) !== "")
  const n = service({})
  n.items = items.slice()
  n.handleActiveWindowDetected(nulled)
  n.matches = 0
  n.handleActiveWindowDetected(huge)
  n.handleActiveWindowDetected(huge)
  check("...so it is matched every time, never answered from the window it is spelled like",
    n.matches === 2 && n.contextMatchKey === "" && shown(n) === fresh(n), String(n.matches))
  n.handleActiveWindowDetected(nulled)
  check("...and the other one is matched again after it", n.matches === 3 && shown(n) === fresh(n))

  // Every sequence of opens and changes shows what a match made then would.
  let seed = 7
  // Math.imul: the plain product leaves 2^53 and the low bits go to zero.
  const rnd = n => { seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff; return (seed >>> 12) % n }
  const ran = { open: 0, reload: 0, emptied: 0, pick: 0, forget: 0, toggle: 0 }
  const windows = [github, netflix, { class: "kitty", title: "zsh", mapped: true },
    { class: "firefox", title: "Reddit - Mozilla Firefox", mapped: true }, {}]
  const r = service({})
  r.items = items.slice()
  let wrong = "", total = 0, opens = 0
  for (let step = 0; step < 400 && !wrong; step++) {
    const what = rnd(10)
    if (what < 6) { opens++; ran.open++; r.open(windows[rnd(windows.length)]) }
    else if (what === 6) {
      const empty = rnd(5) === 0
      ran[empty ? "emptied" : "reload"]++
      r.items = empty ? [] : items.filter((_, i) => rnd(4) !== 0 || i < 3); r.refreshDerivedFromItems()
    } else if (what === 7 && r.detectedContext) {
      ran.pick++
      r.associations = Model.recordAssociation(r.associations, r.detectedContext, items[rnd(items.length)].id, "2026-01-0" + (1 + rnd(9)), rnd(2) === 0)
      r.handleActiveWindowDetected(r.activeWindowData)
    } else if (what === 8 && r.detectedContext) {
      ran.forget++
      r.associations = Model.forgetAssociation(r.associations, r.detectedContext, "")
      r.handleActiveWindowDetected(r.activeWindowData)
    } else if (what === 9) { ran.toggle++; r.suggestOnOpen = !r.suggestOnOpen; if (r.activeWindowData) r.handleActiveWindowDetected(r.activeWindowData) }
    if (r.activeWindowData && shown(r) !== fresh(r)) wrong = `step ${step}: ${shown(r)} != ${fresh(r)}`
  }
  total = r.matches
  check("over 400 random opens, reloads, picks and toggles the suggestions are always what a fresh match gives", wrong === "", wrong)
  check("...and every kind of step was among them, several times each",
    Object.keys(ran).every(kind => ran[kind] >= 3), JSON.stringify(ran))
  check("...with fewer matches than the two per open it used to take", opens > 100 && total < 2 * opens, `${total} matches for ${opens} opens`)
}

done()
