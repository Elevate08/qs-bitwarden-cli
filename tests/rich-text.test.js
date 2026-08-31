#!/usr/bin/env node
// Vault values are attacker-controlled text, and Qt renders text as HTML the
// moment it looks like markup. These tests pin both halves of the defence:
// the neutralizer used for the shared kit controls, and the `textFormat`
// every Text in the plugin's own QML must declare.
//
//   node tests/rich-text.test.js

const fs = require("fs")
const path = require("path")
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.plainLabel = plainLabel
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// --- plainLabel ---
// Ordinary names cannot trip Qt's sniffer, so they must survive byte for byte:
// this runs on labels a user reads next to their credentials.
for (const name of ["Work", "Personal Vault", "e-mail (old)", "日本語", "", "a > b"]) {
  check(`plainLabel leaves ${JSON.stringify(name)} untouched`,
    Model.plainLabel(name) === name, JSON.stringify(Model.plainLabel(name)))
}
check("plainLabel maps null and undefined to an empty label",
  Model.plainLabel(null) === "" && Model.plainLabel(undefined) === "",
  JSON.stringify([Model.plainLabel(null), Model.plainLabel(undefined)]))

// Nothing that reaches the control may still read as a tag.
const markup = Model.plainLabel("<img src=x onerror=alert(1)>")
check("plainLabel escapes a tag out of existence",
  markup === '<span style="white-space:pre-wrap">&lt;img src=x onerror=alert(1)&gt;</span>', markup)
check("plainLabel escapes bold markup",
  Model.plainLabel("<b>Work</b>").indexOf("<b>") < 0, Model.plainLabel("<b>Work</b>"))

// Escaping alone is not enough: without the wrapper Qt may decide the escaped
// string is plain text and show the entities raw. The wrapper forces the
// rich-text path so "&" survives as "&".
const amp = Model.plainLabel("AT&T <holdings>")
check("plainLabel escapes ampersands and forces the rich-text path",
  amp === '<span style="white-space:pre-wrap">AT&amp;T &lt;holdings&gt;</span>', amp)
check("plainLabel neutralizes a value that is already entity-encoded",
  Model.plainLabel("&lt;script&gt;") === '<span style="white-space:pre-wrap">&amp;lt;script&amp;gt;</span>',
  Model.plainLabel("&lt;script&gt;"))
check("plainLabel is idempotent in the sense that re-running it cannot inject",
  Model.plainLabel(Model.plainLabel("<b>x</b>")).indexOf("<b>") < 0,
  Model.plainLabel(Model.plainLabel("<b>x</b>")))

// --- the QML side ---
// Text defaults to Text.AutoText. Vault names, usernames, URIs, notes and Send
// names all land in one of these, so every one of them has to say otherwise --
// including the ones that only render a constant today.
for (const file of ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml", "FormPickerRow.qml"]) {
  const src = fs.readFileSync(path.join(__dirname, "..", file), "utf8").split("\n")
  const bare = []
  src.forEach((line, i) => {
    if (!/(?<![A-Za-z0-9_.])Text\s*\{/.test(line)) return
    const body = line.slice(line.search(/(?<![A-Za-z0-9_.])Text\s*\{/))
    const declared = body.includes("textFormat:") || (src[i + 1] || "").includes("textFormat:")
    if (!declared) bare.push(`${file}:${i + 1}`)
  })
  check(`every Text in ${file} pins textFormat`, bare.length === 0, bare.join(", "))
}

// The kit's Button builds its own Text and exposes no textFormat, so the
// strings we hand it have to arrive already neutralized.
// Every QML file that draws vault-derived text, not just the largest one.
const panel = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml", "FormPickerRow.qml"]
  .map(file => fs.readFileSync(path.join(__dirname, "..", file), "utf8"))
  .join("\n")
for (const binding of ["formFolderLabel()", "formOrgLabel()", 'modelData.name + ": " + modelData.value']) {
  const line = panel.split("\n").find(l => l.includes(binding) && /^\s*(text|tooltipText):/.test(l))
  check(`the button label built from ${binding} goes through plainLabel`,
    Boolean(line) && line.includes("Model.plainLabel("), String(line))
}
check("the suggestion tooltip neutralizes the window title it quotes",
  /tooltipText: Model\.plainLabel\(\(pinned/.test(panel), "expected Model.plainLabel around the tooltip")

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
