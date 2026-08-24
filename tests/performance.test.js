#!/usr/bin/env node
// Deterministic synthetic-vault performance guardrails. These measure the
// work the plugin owns after `bw list items` returns; they never read a real
// vault or make a network request.
//
//   node tests/performance.test.js


const fs = require("fs")
const path = require("path")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.parseItems = parseItems
  exports.filterItems = filterItems
  exports.findContextualMatches = findContextualMatches
`)(Model)

const MIB = 1024 * 1024
const tiers = [
  { name: "small", items: 100, bytes: Math.round(0.25 * MIB), folders: 10, orgs: 1,
    parseP95Ms: 75, filterP95Ms: 50, contextP95Ms: 75 },
  { name: "typical", items: 500, bytes: 1 * MIB, folders: 50, orgs: 3,
    parseP95Ms: 100, filterP95Ms: 75, contextP95Ms: 100 },
  { name: "large", items: 2000, bytes: 5 * MIB, folders: 200, orgs: 10,
    parseP95Ms: 175, filterP95Ms: 100, contextP95Ms: 150 },
  { name: "stress", items: 5000, bytes: 14 * MIB, folders: 500, orgs: 25,
    parseP95Ms: 300, filterP95Ms: 150, contextP95Ms: 250 }
]

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

function fakeItem(index, tier) {
  const ordinal = String(index).padStart(5, "0")
  const kind = index % 10
  const item = {
    object: "item",
    id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
    organizationId: index % 4 === 0 ? null : `org-${index % tier.orgs}`,
    folderId: `folder-${index % tier.folders}`,
    type: kind < 7 ? 1 : kind === 7 ? 2 : kind === 8 ? 3 : 4,
    name: `Service ${ordinal}`,
    notes: `Synthetic fixture note ${ordinal}`,
    favorite: index % 17 === 0,
    fields: [{ name: "fixture-field", value: `value-${ordinal}`, type: index % 2 }],
    attachments: index % 23 === 0
      ? [{ id: `attachment-${index}`, fileName: `fixture-${ordinal}.txt`, size: "1024" }]
      : []
  }

  if (item.type === 1) {
    item.login = {
      username: `user-${ordinal}@example.test`,
      password: `not-a-real-password-${ordinal}`,
      totp: index % 11 === 0 ? "JBSWY3DPEHPK3PXP" : null,
      uris: [{ match: null, uri: `https://service-${index % 80}.example.test/login/${ordinal}` }]
    }
  } else if (item.type === 3) {
    item.card = {
      cardholderName: "Fixture Person", brand: "Visa", number: "4111111111111111",
      expMonth: "04", expYear: "2030", code: "123"
    }
  } else if (item.type === 4) {
    item.identity = {
      firstName: "Fixture", lastName: ordinal, email: `identity-${ordinal}@example.test`,
      phone: "5550100", address1: "1 Fixture Road", city: "Testville",
      state: "TS", postalCode: "00000", country: "US"
    }
  }
  return item
}

function buildFixture(tier) {
  const items = []
  for (let i = 0; i < tier.items; i++) items.push(fakeItem(i, tier))

  // Spread deterministic padding across the entries so parseItems still does
  // realistic per-item work instead of parsing one giant outlier note.
  let raw = JSON.stringify(items)
  const remaining = tier.bytes - Buffer.byteLength(raw)
  if (remaining > 0) {
    const paddingPerItem = Math.floor(remaining / tier.items)
    const tail = remaining % tier.items
    for (let i = 0; i < items.length; i++) {
      items[i].notes += "x".repeat(paddingPerItem + (i < tail ? 1 : 0))
    }
    raw = JSON.stringify(items)
  }
  return raw
}

function timed(fn) {
  const start = process.hrtime.bigint()
  const value = fn()
  return { value, ms: Number(process.hrtime.bigint() - start) / 1e6 }
}

function p95(values) {
  const sorted = values.slice().sort((a, b) => a - b)
  return sorted[Math.ceil(sorted.length * 0.95) - 1]
}

const results = []
for (const tier of tiers) {
  const raw = buildFixture(tier)
  const actualBytes = Buffer.byteLength(raw)
  check(`${tier.name}: fixture item count`, JSON.parse(raw).length === tier.items,
    `expected ${tier.items}`)
  check(`${tier.name}: fixture payload size`,
    actualBytes >= tier.bytes && actualBytes <= tier.bytes + tier.items * 2,
    `expected approximately ${tier.bytes} bytes, got ${actualBytes}`)

  // Warm V8 before collecting the samples so the guard measures steady-state
  // panel work rather than Node's compilation of the test itself.
  let parsed = Model.parseItems(raw)
  Model.filterItems(parsed, "service 0004", "all", "all", "all")
  Model.findContextualMatches(parsed,
    { class: "firefox", title: "Service 42 - Mozilla Firefox" }, {})

  const parseSamples = []
  const filterSamples = []
  const contextSamples = []
  for (let sample = 0; sample < 20; sample++) {
    const parseRun = timed(() => Model.parseItems(raw))
    parsed = parseRun.value
    parseSamples.push(parseRun.ms)
    filterSamples.push(timed(() => Model.filterItems(parsed,
      sample % 2 ? "service 0042" : "user-0004", "all", "all", "all")).ms)
    contextSamples.push(timed(() => Model.findContextualMatches(parsed,
      { class: "firefox", title: "Service 42 login - Mozilla Firefox" }, {})).ms)
  }

  const row = {
    tier: tier.name,
    items: tier.items,
    mib: actualBytes / MIB,
    parse: p95(parseSamples),
    filter: p95(filterSamples),
    context: p95(contextSamples)
  }
  results.push(row)
  check(`${tier.name}: parse p95`, row.parse <= tier.parseP95Ms,
    `${row.parse.toFixed(2)}ms > ${tier.parseP95Ms}ms`)
  check(`${tier.name}: filter p95`, row.filter <= tier.filterP95Ms,
    `${row.filter.toFixed(2)}ms > ${tier.filterP95Ms}ms`)
  check(`${tier.name}: contextual match p95`, row.context <= tier.contextP95Ms,
    `${row.context.toFixed(2)}ms > ${tier.contextP95Ms}ms`)
}

console.log("tier     items    MiB  parse p95  filter p95  context p95")
for (const row of results) {
  console.log(`${row.tier.padEnd(8)} ${String(row.items).padStart(5)}  ${row.mib.toFixed(2).padStart(5)}`
    + `  ${(row.parse.toFixed(2) + "ms").padStart(9)}`
    + `  ${(row.filter.toFixed(2) + "ms").padStart(10)}`
    + `  ${(row.context.toFixed(2) + "ms").padStart(11)}`)
}
console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
