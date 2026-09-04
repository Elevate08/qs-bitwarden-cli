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
  exports.clipLabel = clipLabel
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
for (const file of ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml", "FormPickerRow.qml", "StatusNotice.qml", "DetailField.qml", "WheelScroll.qml"]) {
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
const panel = ["Panel.qml", "SshAgentSettings.qml", "SshApprovalScreen.qml", "FormPickerRow.qml", "StatusNotice.qml", "DetailField.qml", "WheelScroll.qml"]
  .map(file => fs.readFileSync(path.join(__dirname, "..", file), "utf8"))
  .join("\n")
for (const binding of ["formFolderLabel()", "formOrgLabel()", "Model.clipLabel(value, 20)",
                       'name + " filter (" + shortcut + "): " + value']) {
  const line = panel.split("\n").find(l => l.includes(binding) && /^\s*(text|tooltipText):/.test(l))
  check(`the button label built from ${binding} goes through plainLabel`,
    Boolean(line) && line.includes("Model.plainLabel("), String(line))
}

// Order matters, and only one order is safe. plainLabel may return a <span>
// wrapper, so clipping its output could cut a tag in half and hand the control
// the markup the wrapper exists to prevent. Clip the raw value, then neutralize.
const clipLine = panel.split("\n").find(l => l.includes("Model.clipLabel("))
check("the vault value is clipped before it is neutralized, never after",
  Boolean(clipLine)
    && clipLine.indexOf("Model.plainLabel(") >= 0
    && clipLine.indexOf("Model.plainLabel(") < clipLine.indexOf("Model.clipLabel(")
    && !/Model\.clipLabel\(\s*Model\.plainLabel\(/.test(clipLine),
  String(clipLine))
check("the suggestion tooltip neutralizes the window title it quotes",
  /tooltipText: Model\.plainLabel\(\(pinned/.test(panel), "expected Model.plainLabel around the tooltip")

// --- clipping vault text to a width the panel can hold ---
// Ui.Button has no elide, so a folder name decides how wide a button is. The
// clip is what keeps that decision ours; the ellipsis lives inside the budget,
// so `max` is a real ceiling and not a suggestion.
check("a value already within the budget is returned untouched",
  Model.clipLabel("Work", 20) === "Work", Model.clipLabel("Work", 20))
check("a value exactly at the budget is not clipped",
  Model.clipLabel("12345678901234567890", 20) === "12345678901234567890",
  Model.clipLabel("12345678901234567890", 20))
check("a longer value is cut to the budget, ellipsis included",
  Model.clipLabel("123456789012345678901", 20) === "12345678901234567...",
  Model.clipLabel("123456789012345678901", 20))
for (const [value, max] of [["Client Projects 2026", 20], ["x".repeat(400), 20],
                            ["short", 4], ["abc", 2], ["abcd", 3]]) {
  check(`clipLabel(${JSON.stringify(value).slice(0, 24)}, ${max}) never exceeds its budget`,
    Model.clipLabel(value, max).length <= max, Model.clipLabel(value, max))
}
check("a missing or unusable value clips to the empty string, never to \"null\"",
  Model.clipLabel(null, 20) === "" && Model.clipLabel(undefined, 20) === "",
  JSON.stringify([Model.clipLabel(null, 20), Model.clipLabel(undefined, 20)]))
check("a nonsense budget still returns something drawable",
  Model.clipLabel("Work", 0).length > 0 && Model.clipLabel("Work", -5).length > 0,
  JSON.stringify([Model.clipLabel("Work", 0), Model.clipLabel("Work", -5)]))
// The clip runs on raw vault text, so it must not be what introduces markup.
check("clipping cannot manufacture markup that plainLabel then has to catch",
  Model.plainLabel(Model.clipLabel("<img src=x onerror=alert(1)>", 20)).indexOf("<img") < 0,
  Model.plainLabel(Model.clipLabel("<img src=x onerror=alert(1)>", 20)))

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
