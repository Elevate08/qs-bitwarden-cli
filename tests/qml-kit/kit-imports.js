#!/usr/bin/env node
// Builds a `qs` import tree from the installed Omarchy shell kit that a plain
// qmltestrunner can load, so a test can build the plugin's own view files
// (which import qs.Commons and qs.Ui) with the kit's real controls.
//
// The kit's Commons singletons read theme files and run hyprctl/fc-match
// through Quickshell, which exists only inside the shell. Those members become
// inert stand-ins (`property var name: null`, an empty env, a no-op exec);
// everything else is copied unchanged, so a Button here is the shell's Button.
// Ui files that need Quickshell themselves (the layer-shell windows) are copied
// too but only compile if a test uses them.
//
//   node tests/qml-kit/kit-imports.js /usr/share/omarchy/shell <out-dir>
//
// leaves <out-dir>/qs/{Commons,Ui}; pass <out-dir> to qmltestrunner -import.

const fs = require("fs")
const path = require("path")

const [kit, out] = process.argv.slice(2)
if (!kit || !out) {
  console.error("usage: kit-imports.js <omarchy-shell-dir> <out-dir>")
  process.exit(2)
}

// `property Process name: Process { ... }` (and FileView), braces balanced.
function stubMember(src, type) {
  const opener = new RegExp(`^([ \\t]*)property ${type} (\\w+): ${type} \\{`, "m")
  let m
  while ((m = opener.exec(src))) {
    let depth = 0
    let i = src.indexOf("{", m.index)
    for (; i < src.length; i++) {
      if (src[i] === "{") depth++
      else if (src[i] === "}" && --depth === 0) break
    }
    src = src.slice(0, m.index) + `${m[1]}property var ${m[2]}: null` + src.slice(i + 1)
  }
  return src
}

function strip(src) {
  let s = src.replace(/^import Quickshell(?:\.\w+)*[ \t]*$/gm, "")
  s = s.replace(/Quickshell\.env\([^)]*\)/g, '""')
  s = s.replace(/Quickshell\.execDetached\(/g, "(function() {})(")
  s = stubMember(s, "Process")
  s = stubMember(s, "FileView")
  return s
}

for (const dir of ["Commons", "Ui"]) {
  const from = path.join(kit, dir)
  const to = path.join(out, "qs", dir)
  fs.mkdirSync(to, { recursive: true })
  for (const name of fs.readdirSync(from)) {
    const src = fs.readFileSync(path.join(from, name), "utf8")
    // Only Commons is rewritten: its singletons load for every control.
    const text = dir === "Commons" && name.endsWith(".qml") ? strip(src) : src
    fs.writeFileSync(path.join(to, name), text)
  }
}
