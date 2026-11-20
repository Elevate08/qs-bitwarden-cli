#!/usr/bin/env node
// Vault values are untrusted and Qt renders markup-like text as HTML. Pins the
// neutralizer for kit controls and the `textFormat` every plugin Text declares.
//
//   node tests/rich-text.test.js

const { createSuite, loadModule, read, readPluginSource, repoRoot } = require("./harness")
const fs = require("fs")
const path = require("path")
const Model = loadModule()

const { check, done } = createSuite("rich-text")

// --- plainLabel ---
// Omarchy 4.0.4's kit draws the labels it is handed with Text.PlainText, so
// plainLabel passes vault text through unchanged. It used to HTML-escape
// anything with "<" or "&" into a <span>, which that kit then drew literally
// ("<span ...>Bills &amp; Banking</span>" in place of a folder name).
for (const name of ["Work", "Personal Vault", "e-mail (old)", "日本語", "", "a > b",
                    "Bills & Banking", "<b>Work</b>", "AT&T <holdings>", "&lt;script&gt;"]) {
  check(`plainLabel passes ${JSON.stringify(name)} through unchanged`,
    Model.plainLabel(name) === name, JSON.stringify(Model.plainLabel(name)))
}
check("plainLabel maps null and undefined to an empty label",
  Model.plainLabel(null) === "" && Model.plainLabel(undefined) === "",
  JSON.stringify([Model.plainLabel(null), Model.plainLabel(undefined)]))

// That is only safe while the kit pins PlainText on every Text it draws a
// label or tooltip with. Read the installed kit and hold it to that; a kit
// that drops it would render vault markup again.
const kitDir = process.env.QSBW_KIT_DIR || "/usr/share/omarchy/shell/Ui"
const kitFiles = ["Button.qml"]
if (fs.existsSync(kitDir)) {
  for (const file of kitFiles) {
    const kit = fs.readFileSync(path.join(kitDir, file), "utf8")
    const texts = [...kit.matchAll(/(?<![A-Za-z0-9_.])Text\s*\{/g)]
    const bare = []
    for (const m of texts) {
      let depth = 0
      let own = ""
      for (let i = kit.indexOf("{", m.index); i < kit.length; i++) {
        if (kit[i] === "{") depth++
        else if (kit[i] === "}" && --depth === 0) break
        else if (depth === 1) own += kit[i]
      }
      if (!/textFormat:\s*Text\.PlainText/.test(own)) bare.push(`${file}:${kit.slice(0, m.index).split("\n").length}`)
    }
    check(`the kit's ${file} draws every label and tooltip as plain text`,
      texts.length > 0 && bare.length === 0, bare.join(", ") || "no Text found")
  }
} else {
  console.log(`rich-text: no Omarchy kit at ${kitDir}; the kit's PlainText is not checked here`)
}

// --- the QML side ---
// Text defaults to AutoText, so every Text declares PlainText, even constant
// ones.
const qmlFiles = fs.readdirSync(repoRoot)
  .filter((name) => name.endsWith(".qml"))
for (const file of qmlFiles) {
  const src = read(file)
  const bare = []
  // The element's own body, not a line window: a window lets a bare Text pass
  // on a neighbour's textFormat. Nested blocks are left out for the same reason.
  for (const m of src.matchAll(/(?<![A-Za-z0-9_.])Text\s*\{/g)) {
    let depth = 0
    let own = ""
    for (let i = src.indexOf("{", m.index); i < src.length; i++) {
      if (src[i] === "{") depth++
      else if (src[i] === "}" && --depth === 0) break
      else if (depth === 1) own += src[i]
    }
    if (!own.includes("textFormat:")) bare.push(`${file}:${src.slice(0, m.index).split("\n").length}`)
  }
  check(`every Text in ${file} pins textFormat`, bare.length === 0, bare.join(", "))
}

// The kit's Button builds its own Text and exposes no textFormat, so the
// strings we hand it have to arrive already neutralized.
// Every QML file that draws vault-derived text, not just the largest one.
const panel = qmlFiles.map(readPluginSource).join("\n")
const detailField = read("DetailField.qml")
for (const binding of ["formFolderLabel()", "formOrgLabel()", "Model.clipLabel(value, 20)",
                       'name + " filter (" + shortcut + "): " + value']) {
  const line = panel.split("\n").find(l => l.includes(binding) && /^\s*(text|tooltipText):/.test(l))
  check(`the button label built from ${binding} goes through plainLabel`,
    Boolean(line) && line.includes("Model.plainLabel("), String(line))
}

// Clip the raw value, then hand it through plainLabel: the one place a label
// is prepared for a kit control, whatever that has to do for a given kit.
const clipLine = panel.split("\n").find(l => l.includes("Model.clipLabel("))
check("the vault value is clipped before it is neutralized, never after",
  Boolean(clipLine)
    && clipLine.indexOf("Model.plainLabel(") >= 0
    && clipLine.indexOf("Model.plainLabel(") < clipLine.indexOf("Model.clipLabel(")
    && !/Model\.clipLabel\(\s*Model\.plainLabel\(/.test(clipLine),
  String(clipLine))
check("the suggestion tooltip neutralizes the window title it quotes",
  /tooltipText: Model\.plainLabel\(\(pinned/.test(panel), "expected Model.plainLabel around the tooltip")
check("custom-field names are neutralized before reaching action tooltips",
  /tooltipText:\s*Model\.plainLabel\([\s\S]{0,180}root\.copyLabel\.toLowerCase\(\)/.test(detailField)
    && (detailField.match(/tooltipText:\s*Model\.plainLabel\(/g) || []).length >= 2,
  "both DetailField action tooltips must neutralize their dynamic label")

// --- clipping vault text to a width the panel can hold ---
// Ui.Button cannot elide, so vault text is clipped; the "..." counts toward
// `max`.
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
// The clip only shortens: it never adds characters that could read as markup.
check("clipping adds nothing but the ellipsis",
  Model.clipLabel("<img src=x onerror=alert(1)>", 20) === "<img src=x onerro...",
  Model.clipLabel("<img src=x onerror=alert(1)>", 20))

done()
