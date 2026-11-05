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
  // The `import Quickshell[.Io]` lines stay: the stand-in modules below
  // supply Singleton, FileView, SplitParser and Process, so the kit's
  // child-object declarations of them compile too.
  let s = src
  s = s.replace(/Quickshell\.env\([^)]*\)/g, '""')
  s = s.replace(/Quickshell\.execDetached\(/g, "(function() {})(")
  s = stubMember(s, "Process")
  s = stubMember(s, "FileView")
  return s
}

// qmltestrunner has no `qs` binary, and Quickshell.Io's types are linked into
// that binary (`prefer :/qt/qml/Quickshell/Io/`). A QML stand-in lets a field
// construct Process without starting one. The shell itself still loads the
// real module.
const ioDir = path.join(out, "Quickshell", "Io")
fs.mkdirSync(ioDir, { recursive: true })
fs.writeFileSync(path.join(ioDir, "qmldir"), [
  "module Quickshell.Io",
  "depends QtQuick",
  "Process 0.0 Process.qml",
  "StdioCollector 0.0 StdioCollector.qml",
  "SplitParser 0.0 SplitParser.qml",
  "IpcHandler 0.0 IpcHandler.qml",
  "FileView 0.0 FileView.qml",
  "",
].join("\n"))
fs.writeFileSync(path.join(ioDir, "Process.qml"), [
  "import QtQuick",
  "QtObject {",
  "  property bool running: false",
  "  property int processId: 0",
  "  property var command: []",
  "  property var environment: ({})",
  "  property bool stdinEnabled: false",
  "  property var stderr: null",
  "  function write(data) {}",
  "  property var stdout: null",
  "  signal exited(int exitCode, int exitStatus)",
  "  function signal(number) { running = false }",
  "  function exec(cmd) { command = cmd }",
  "}",
  "",
].join("\n"))
fs.writeFileSync(path.join(ioDir, "StdioCollector.qml"), [
  "import QtQuick",
  "QtObject {",
  "  property bool waitForEnd: true",
  "  property string text: \"\"",
  "  signal streamFinished()",
  "}",
  "",
].join("\n"))

// The kit's Commons singletons also declare these as child objects
// (`FileView { ... }`, `Process { stdout: SplitParser { ... } }`), which the
// textual strip above does not reach, and the whole Commons module must
// compile for any one of its types to load. Inert: nothing is ever read.
fs.writeFileSync(path.join(ioDir, "SplitParser.qml"), [
  "import QtQuick",
  "QtObject {",
  "  property string splitMarker: \"\\n\"",
  "  signal read(string data)",
  "}",
  "",
].join("\n"))
fs.writeFileSync(path.join(ioDir, "IpcHandler.qml"), [
  "import QtQuick",
  "QtObject {",
  "  property bool enabled: true",
  "  property string target: \"\"",
  "}",
  "",
].join("\n"))
fs.writeFileSync(path.join(ioDir, "FileView.qml"), [
  "import QtQuick",
  "QtObject {",
  "  property string path: \"\"",
  "  property bool blockLoading: false",
  "  property bool watchChanges: false",
  "  property bool printErrors: true",
  "  property bool preload: false",
  "  function text() { return \"\" }",
  "  function reload() {}",
  "  signal loaded()",
  "  signal loadFailed(var error)",
  "  signal fileChanged()",
  "}",
  "",
].join("\n"))

// Plugin files that import Quickshell for execDetached get a recording stand-in.
fs.writeFileSync(path.join(out, "Quickshell", "qmldir"), [
  "module Quickshell",
  "depends QtQuick",
  "singleton Quickshell 0.0 Quickshell.qml",
  "Singleton 0.0 Singleton.qml",
  "",
].join("\n"))
fs.writeFileSync(path.join(out, "Quickshell", "Quickshell.qml"), [
  "pragma Singleton",
  "import QtQuick",
  "QtObject {",
  "  property var detached: []",
  "  function execDetached(cmd) { detached = detached.concat([cmd]) }",
  "}",
  "",
].join("\n"))

// Style.qml listens for Hyprland's raw events.
const hyprDir = path.join(out, "Quickshell", "Hyprland")
fs.mkdirSync(hyprDir, { recursive: true })
fs.writeFileSync(path.join(hyprDir, "qmldir"), [
  "module Quickshell.Hyprland",
  "depends QtQuick",
  "singleton Hyprland 0.0 Hyprland.qml",
  "",
].join("\n"))
fs.writeFileSync(path.join(hyprDir, "Hyprland.qml"), [
  "pragma Singleton",
  "import QtQuick",
  "QtObject {",
  "  signal rawEvent(var event)",
  "}",
  "",
].join("\n"))

// UntypedInput.qml reads the default audio input; none here.
const pwDir = path.join(out, "Quickshell", "Services", "Pipewire")
fs.mkdirSync(pwDir, { recursive: true })
fs.writeFileSync(path.join(pwDir, "qmldir"), [
  "module Quickshell.Services.Pipewire",
  "depends QtQuick",
  "singleton Pipewire 0.0 Pipewire.qml",
  "",
].join("\n"))
fs.writeFileSync(path.join(pwDir, "Pipewire.qml"), [
  "pragma Singleton",
  "import QtQuick",
  "QtObject {",
  "  property var defaultAudioSource: null",
  "  property var defaultAudioSink: null",
  "}",
  "",
].join("\n"))

fs.writeFileSync(path.join(out, "Quickshell", "Singleton.qml"), [
  "import QtQuick",
  "Item { visible: false }",
  "",
].join("\n"))

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
