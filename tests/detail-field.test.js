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

// --- reveals are per field ---------------------------------------------------
//
// One shared flag served every masked field to begin with, which was invisible
// while a login had exactly one secret. A card has two and an identity three,
// so revealing a card number also uncovered its security code, and an identity
// showed its social security, passport and licence numbers together.

const revealKeys = uses
  .filter(u => /sensitive:\s*true/.test(u))
  .map(u => (u.match(/revealed: root\.isFieldRevealed\("([^"]+)"\)/) || [])[1])

check("every masked field has a reveal key", revealKeys.every(Boolean),
  JSON.stringify(revealKeys))
check("no two masked fields share a reveal key",
  new Set(revealKeys).size === revealKeys.length, JSON.stringify(revealKeys))
check("each toggles only its own key",
  uses.filter(u => /sensitive:\s*true/.test(u)).every(u => {
    const shown = (u.match(/revealed: root\.isFieldRevealed\("([^"]+)"\)/) || [])[1]
    const toggled = (u.match(/onRevealToggled: root\.toggleFieldReveal\("([^"]+)"\)/) || [])[1]
    return shown && shown === toggled
  }), "a field must reveal and hide the same key")

check("no single shared reveal flag is left",
  !/root\.passwordRevealed/.test(panelSrc),
  "one flag for every masked field is what caused them to move together")

check("toggling one key leaves the others alone",
  /if \(next\[key\]\) delete next\[key\]\s*\n\s*else next\[key\] = true/.test(panelSrc),
  "expected a per-key toggle over a copy of the map")

// `v` cannot mean five things at once, so it reaches the one secret the item is
// mostly about and the tooltips only advertise it there.
check("v reaches the item's principal secret only",
  /primaryRevealKey:\s*\n?\s*detailIsCard \? "cardNumber" : \(detailIsLoginLike \? "password" : ""\)/.test(panelSrc),
  "expected a single primary key per item type")
check("the reveal hint is a property rather than a hardcoded (v)",
  /property string revealHint: ""/.test(fieldSrc)
    && !/\+ " \(v\)"/.test(fieldSrc),
  "every masked field claimed the v shortcut")

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
