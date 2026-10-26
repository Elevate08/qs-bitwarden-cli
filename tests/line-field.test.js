#!/usr/bin/env node
// The shell's editable TextFields are TextInputs. On Qt 6.12 a clipboard
// change makes every live one read the Wayland offer on the GUI thread with
// no total cap. Production fields are LineFields (a TextArea, which only
// checks the offered type) and paste is capped outside the process.
//
//   node tests/line-field.test.js

const fs = require("fs")
const path = require("path")
const { createSuite, repoRoot, read, functionBody } = require("./harness")

const { check, done } = createSuite("line-field")

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

const production = qmlFiles(repoRoot).filter(file => file !== "LineField.qml")
for (const file of production) {
  const src = fs.readFileSync(path.join(repoRoot, file), "utf8")
  check(`${file} does not construct a TextField`, !/TextField\s*\{/.test(src), file)
  check(`${file} does not construct a TextInput`, !/TextInput\s*\{/.test(src), file)
}

const line = fs.readFileSync(path.join(repoRoot, "LineField.qml"), "utf8")
check("the visible editor is a TextArea",
  /FocusScope \{/.test(line) && /TextArea \{/.test(line) && !/TextField\s*\{/.test(line),
  "root must not be a TextInput")
check("the value is a read-only TextInput",
  /TextInput \{[\s\S]*?readOnly: true/.test(line),
  "an editable TextInput reads the clipboard offer on the GUI thread")
check("paste is capped outside the process",
  /head -c " \+ pasteByteCap/.test(line) && /readonly property int pasteByteCap: 65536/.test(line),
  line.match(/pasteCommand[\s\S]*?\n  \}/)?.[0] || "pasteCommand missing")
check("paste asks wl-paste for text only",
  (line.match(/--type text /g) || []).length === 1 && /"--primary " : ""\) \+ "--type text "/.test(line),
  "an image-only clipboard would paste binary")
check("destroying the field kills the paste's process group",
  /Component\.onDestruction: killPasteGroup\(\)/.test(line) && /execDetached\(\["kill", "-KILL", "--", "-" \+ pid\]\)/.test(line),
  "Process teardown kills only timeout and orphans the pipeline")
check("paste does not read the clipboard in-process",
  !/clipboard\(|\.paste\(\)|mimeData/.test(line),
  "an in-process text() or paste() reads the offer on the GUI thread")
check("masked text is not published as a selection",
  /selectByMouse: !root\.password/.test(line) && /StandardKey\.SelectAll/.test(line) && /if \(root\.password && selectedText\) deselect\(\)/.test(line),
  "TextEdit copies a selection to the primary selection")
check("a masked field's select-all is virtual",
  /StandardKey\.SelectAll/.test(line) && /_maskedAll = root\.enabled && !root\.readOnly && store\.text\.length > 0/.test(line)
    && /function editRange\(\)[\s\S]*?if \(!_maskedAll\)/.test(line) && /visible: root\.password && root\._maskedAll/.test(line),
  "a real select-all would be published to the primary selection")
check("a masked field draws its own blinking caret",
  /id: maskedCaret/.test(line) && /root\._maskedCaretWanted && root\._blinkOn/.test(line)
    && /Qt\.styleHints\.cursorFlashTime/.test(line) && /opacity: root\.password \? 0 : 1/.test(line),
  "a read-only TextEdit draws no caret and keyboard selection would publish one")
check("masked edit ranges snap to whole characters",
  /function snapIndex/.test(line) && /snapIndex\(text, from, -1\)/.test(line) && /snapIndex\(text, to, 1\)/.test(line),
  "bullets map to UTF-16 units")
check("a masked document is bullets",
  /"\\u2022"\.repeat\(store\.text\.length\)/.test(line) && /echoMode: root\.password \? TextInput\.Password : TextInput\.Normal/.test(line),
  "TextArea's accessible text is the document")
check("the editing menu cannot paste",
  /ContextMenu\.menu: null/.test(line),
  "the style menu calls TextEdit.paste()")
check("a finished paste destroys its collector",
  /function finishPaste[\s\S]*?proc\.destroy\(\)/.test(line),
  "StdioCollector keeps its last output until the process is destroyed")
check("a paste started before the field closed is dropped",
  /pasteEpoch/.test(line) && /function acceptPaste[\s\S]*?editingOpen\(\)/.test(line),
  "closing a form hides it without disabling the field")

// Enter saves the item form from a text field. The editable TextEdit claims
// Return in ShortcutOverride, so the form's Shortcut never sees it; the field
// hands it to the form instead. Behaviour: tests/qml-kit/tst_item_form_enter.qml.
function blocks(src, type) {
  const found = []
  const opener = new RegExp(`\\b${type}\\s*\\{`, "g")
  let m
  while ((m = opener.exec(src))) found.push(balanced(src, m.index))
  return found
}

function balanced(src, from) {
  let depth = 0
  let i = src.indexOf("{", from)
  const start = i
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++
    else if (src[i] === "}" && --depth === 0) break
  }
  return src.slice(start, i + 1)
}

const submit = functionBody(line, "submit")
check("Return and Enter both submit",
  /Keys\.onReturnPressed: function\(event\) \{\s*event\.accepted = true\s*root\.submit\(\)/.test(line)
    && /Keys\.onEnterPressed: function\(event\) \{\s*event\.accepted = true\s*root\.submit\(\)/.test(line),
  "keypad Enter must do what Return does")
check("a field's Return reaches the form around it",
  /if \(!enabled \|\| readOnly\) return\s*accepted\(\)\s*if \(!submitsForm\) return/.test(submit)
    && /typeof item\.submitForm === "function"/.test(submit) && /item = item\.parent/.test(submit),
  submit || "submit() missing")

const panel = read("Panel.qml")
const formAt = panel.indexOf("id: editFormCol")
const itemForm = balanced(panel, panel.lastIndexOf("Column {", formAt))
const submitForm = functionBody(itemForm, "submitForm")
const saveButton = itemForm.match(/\/\/ Save Action Button\s*Button \{[\s\S]*?\n {14}\}/)?.[0] || ""
check("the item form saves on Enter with the Save button's guards",
  /root\.vault\.formPicker !== ""/.test(submitForm) && /root\.vault\.isLoading/.test(submitForm)
    && /root\.vault\.saveItemForm\(\)/.test(submitForm)
    && /enabled: !root\.vault\.isLoading && root\.vault\.formPicker === ""/.test(saveButton),
  submitForm || "editFormCol has no submitForm()")
check("the form's Enter Shortcut saves through submitForm()",
  /Shortcut \{\s*sequences: \["Return", "Enter"\][\s\S]*?onActivated: editFormCol\.submitForm\(\)/.test(itemForm),
  "the Shortcut and a field's Return must share one guarded path")

// A field whose own Return does something else (a new folder, a custom field)
// must not also save the item; every other field must.
const formFields = [itemForm, read("CustomFieldsEditor.qml")]
  .flatMap(src => [...blocks(src, "LineField"), ...blocks(src, "SecretField")])
check("the item form has its fields", formFields.length > 30, `${formFields.length} fields`)
for (const field of formFields) {
  const ownReturn = /\bonAccepted:/.test(field)
  const optedOut = /\bsubmitsForm: false\b/.test(field)
  check("a form field saves on Enter unless its own Return does something else",
    ownReturn === optedOut, field.split("\n").slice(0, 6).join("\n"))
}

done()
