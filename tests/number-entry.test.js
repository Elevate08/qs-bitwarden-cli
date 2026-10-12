#!/usr/bin/env node
// The kit's NumberField is a SpinBox over an editable TextInput, which on Qt
// 6.12 reads the Wayland clipboard offer on the GUI thread at every clipboard
// change (see tests/line-field.test.js). The plugin's NumberEntry types into a
// TextEdit instead. This pins that no plugin QML brings an editable text
// input back.
//
//   node tests/number-entry.test.js

const fs = require("fs")
const path = require("path")
const { createSuite, repoRoot } = require("./harness")

const { check, done } = createSuite("number-entry")

function qmlFiles(dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    if (name === "tests" || name === "node_modules" || name.startsWith(".")) continue
    const full = path.join(dir, name)
    const stat = fs.statSync(full)
    if (stat.isDirectory()) qmlFiles(full, out)
    else if (name.endsWith(".qml")) out.push(path.relative(repoRoot, full))
  }
  return out
}

// The body of every `Type {` block, braces balanced.
function blocks(src, type) {
  const found = []
  const opener = new RegExp(`\\b${type}\\s*\\{`, "g")
  let m
  while ((m = opener.exec(src))) {
    let depth = 0
    let i = src.indexOf("{", m.index)
    const start = i
    for (; i < src.length; i++) {
      if (src[i] === "{") depth++
      else if (src[i] === "}" && --depth === 0) break
    }
    found.push(src.slice(start, i + 1))
  }
  return found
}

for (const file of qmlFiles(repoRoot)) {
  const src = fs.readFileSync(path.join(repoRoot, file), "utf8")
  check(`${file} does not construct the kit NumberField`, !/\bNumberField\s*\{/.test(src), file)
  check(`${file} does not construct a TextField`, !/\bTextField\s*\{/.test(src), file)
  check(`${file} has no editable SpinBox`,
    !blocks(src, "SpinBox").some(b => !/editable:\s*false/.test(b)),
    "a SpinBox must set editable: false")
  check(`${file} has no editable TextInput`,
    !blocks(src, "TextInput").some(b => !/readOnly:\s*true/.test(b)),
    "a TextInput must be readOnly: true")
}

const entry = fs.readFileSync(path.join(repoRoot, "NumberEntry.qml"), "utf8")
check("NumberEntry types into a TextEdit", /contentItem: TextEdit \{/.test(entry))
check("NumberEntry swallows paste", /event\.matches\(StandardKey\.Paste\)/.test(entry))
check("NumberEntry swallows middle-click",
  /acceptedButtons: Qt\.MiddleButton/.test(entry))
check("NumberEntry never calls the clipboard",
  !/clipboard\(|\.paste\(\)|mimeData/.test(entry))
check("Panel uses NumberEntry",
  (fs.readFileSync(path.join(repoRoot, "Panel.qml"), "utf8").match(/\bNumberEntry \{/g) || []).length === 4)

done()
