#!/usr/bin/env node
// Regression tests for the context-aware suggestion matcher in BitwardenModel.js.
//
// The matcher is heuristic and works from window titles alone, so it is easy to
// regress in both directions: too strict and the right login stops appearing,
// too loose and every .com item is suggested on every site. Run with:
//
//   node tests/context-match.test.js

const fs = require("fs")
const path = require("path")

const src = fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
const Model = {}
new Function("exports", src.replace(/^\.pragma library\s*$/m, "") + `
  exports.findContextualMatches = findContextualMatches
  exports.cleanWindowContext = cleanWindowContext
  exports.parseHost = parseHost
  exports.parseAssociations = parseAssociations
  exports.serializeAssociations = serializeAssociations
  exports.recordAssociation = recordAssociation
  exports.forgetAssociation = forgetAssociation
  exports.isAssociated = isAssociated
  exports.emptyAssociations = emptyAssociations
`)(Model)

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

let pass = 0
const failures = []

function check(label, ok, detail) {
  if (ok) { pass++ } else { failures.push(label + "\n    " + detail) }
}

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

// The case that no title heuristic can solve: an authentik portal on
// auth.example.xyz titled "Home - authentik". The title and the stored URL
// share no word at all.
// Named so that neither the name nor the URL shares a word with the page title.
const authentikItem = { id: "auth-1", name: "Personal SSO", uris: ["https://auth.example.xyz"] }
const withAuthentik = items.concat([authentikItem])
const authentikWindow = { class: "chromium", title: "Home - authentik - Chromium", mapped: true }

let assoc = Model.emptyAssociations()

check("authentik: unmatched before learning",
  Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.length === 0,
  `got [${Model.findContextualMatches(withAuthentik, authentikWindow, assoc).matches.map(m => m.name)}]`)

// Pick the credential once while that window is active.
const ctx = Model.cleanWindowContext(authentikWindow)
assoc = Model.recordAssociation(assoc, ctx, authentikItem.id, "2026-08-20T00:00:00Z")

check("authentik: suggested after one pick",
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

// Last pick wins, so a key learned from the wrong page corrects itself.
const retargeted = Model.recordAssociation(assoc, ctx, "9", "2026-08-21T00:00:00Z")
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
  Model.cleanWindowContext({ class: "chromium", title: "Netflix - Chromium", mapped: true }), "11")
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

// Suggestions must still work with no association store at all.
check("undefined associations are safe",
  Model.findContextualMatches(items, { class: "chromium", title: "Netflix - Chromium", mapped: true })
    .matches.map(m => m.name).join() === "Netflix",
  "expected heuristics to work without a store")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
