#!/usr/bin/env node
// The detail screen draws every labelled, copyable field through DetailField.
// These assertions guard the properties that make a card safe to put on
// screen -- masking, empty-field suppression, and the promise that a copy
// still goes through the panel's one clipboard path.
//
//   node tests/detail-field.test.js

const fs = require("fs")
const path = require("path")

const read = f => fs.existsSync(path.join(__dirname, "..", f))
  ? fs.readFileSync(path.join(__dirname, "..", f), "utf8") : ""

const fieldSrc = read("DetailField.qml")
const panelSrc = read("Panel.qml")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

check("DetailField exists", fieldSrc !== "", "DetailField.qml is missing")

// --- the component itself ----------------------------------------------------

check("an empty field draws nothing at all",
  /visible:\s*root\.value\s*!==\s*""/.test(fieldSrc),
  "an identity fills in a handful of its fields; the rest must not leave labelled blanks")

check("a sensitive field is masked until it is revealed",
  /masked:\s*root\.sensitive\s*&&\s*!root\.revealed/.test(fieldSrc)
    && /text:\s*root\.masked\s*\?\s*Model\.maskString\(root\.value\)\s*:\s*root\.value/.test(fieldSrc),
  fieldSrc)

check("the reveal button appears only on sensitive fields",
  /visible:\s*root\.sensitive/.test(fieldSrc), fieldSrc)

check("the component reports intent rather than reaching for the clipboard",
  /signal copyRequested\(\)/.test(fieldSrc)
    && /signal revealToggled\(\)/.test(fieldSrc)
    && !/copyToClipboard/.test(fieldSrc),
  "DetailField must not know how a copy is performed")

check("field text is pinned to plain text",
  /textFormat:\s*Text\.PlainText/.test(fieldSrc), fieldSrc)

check("long values elide rather than pushing the row wider",
  /elide:\s*Text\.ElideRight/.test(fieldSrc), fieldSrc)

// --- how the detail screen uses it -------------------------------------------

const uses = panelSrc.match(/DetailField \{[\s\S]*?\n              \}/g) || []
check("the detail screen draws its fields through the component",
  uses.length >= 14, `found ${uses.length} DetailField uses`)

check("every use routes its copy through the panel's one clipboard path",
  uses.every(u => /onCopyRequested:\s*root\.copyToClipboard\(/.test(u)),
  uses.filter(u => !/onCopyRequested:\s*root\.copyToClipboard\(/.test(u)).join("\n---\n"))

// A card number, a security code, an SSN, a passport and a licence. Nothing
// here can be rotated after it leaks, which is the argument for masking them
// that a password does not have.
for (const [label, value] of [
  ["Card Number", "number"],
  ["Security Code", "code"],
  ["Social Security Number", "ssn"],
  ["Passport Number", "passportNumber"],
  ["Licence Number", "licenseNumber"],
]) {
  const use = uses.find(u => u.includes(`label: "${label}"`))
  check(`${label} is masked on screen`,
    Boolean(use) && /sensitive:\s*true/.test(use),
    use || `no DetailField labelled ${label}`)
  check(`${label} reads the value the model parsed`,
    Boolean(use) && use.includes(value), use || "")
}

// Brand and cardholder are printed on the front of the card in plain sight;
// masking them would be theatre.
for (const label of ["Brand", "Cardholder Name", "Expires"]) {
  const use = uses.find(u => u.includes(`label: "${label}"`))
  check(`${label} is not needlessly masked`,
    Boolean(use) && !/sensitive:\s*true/.test(use), use || `no DetailField labelled ${label}`)
}

// --- gating ------------------------------------------------------------------

check("login fields are gated on the type, not on 'not an SSH key'",
  /readonly property bool detailIsLoginLike: detailTypeCode === 1 \|\| detailTypeCode === 2/.test(panelSrc)
    && !/typeCode !== 5 && \(root\.detailPassword/.test(panelSrc),
  "a card answers 'not an SSH key' too, and would draw an empty password row")

check("card fields are drawn only for cards, identity fields only for identities",
  (panelSrc.match(/visible: root\.detailIsCard/g) || []).length >= 5
    && (panelSrc.match(/visible: root\.detailIsIdentity/g) || []).length >= 8,
  "each block must gate on its own type")

check("an address is one copyable block, not seven rows",
  /detailIdentityAddress/.test(panelSrc)
    && /tooltipText: "Copy address"/.test(panelSrc),
  "an address is copied as an address")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
