#!/usr/bin/env node
// Registering the auto-type keybinding from the settings screen: the chord
// grammar, reading `hyprctl binds -j` and bindings.lua, the line the plugin
// appends, and the real register and remove scripts run against a throwaway
// HOME with a stand-in hyprctl (never the real one, and never the real
// ~/.config/hypr).
//
//   node tests/auto-type-keybind.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const { createSuite, loadModule, readPluginSource } = require("./harness")

const Model = loadModule()
const { check, eq, done } = createSuite("auto-type-keybind")

const COMMAND = "omarchy-shell io.github.elevate08.qs-bitwarden-cli autoType"
const COMMENT = Model.autoTypeBindComment()
const lineFor = chord => `o.bind("${chord}", "Bitwarden auto-type", "${COMMAND}")`

// --- the chord grammar --------------------------------------------------------

for (const [raw, chord] of [
  ["SUPER + SHIFT + A", "SUPER + SHIFT + A"],
  ["super+shift+a", "SUPER + SHIFT + A"],
  ["  Super  +  Ctrl + backslash ", "SUPER + CTRL + BACKSLASH"],
  ["SUPER + CONTROL + SLASH", "SUPER + CTRL + SLASH"],
  ["ALT + F9", "ALT + F9"],
  ["CTRL + ALT + 1", "CTRL + ALT + 1"],
  ["SUPER + xf86audiomute", "SUPER + XF86audiomute"],
  ["SUPER + KP_Enter", "SUPER + KP_ENTER"],
]) {
  const parsed = Model.autoTypeChord(raw)
  check(`"${raw}" is a chord`, parsed.ok && parsed.chord === chord, JSON.stringify(parsed))
}
eq("the chord's modmask uses Hyprland's bits", Model.autoTypeChord("SUPER + SHIFT + A").modmask, 65)
eq("SUPER + ALT is 72, as hyprctl reports it", Model.autoTypeChord("SUPER + ALT + SLASH").modmask, 72)

for (const raw of [
  "", "   ", "A", "SHIFT + A", "SUPER", "SUPER + ALT", "SUPER + SUPER + A", "SUPER + + A", "SUPER +",
  "SUPER SHIFT A", "HYPER + A", "SUPER + SHIFT + \"A", "SUPER + A\")", "SUPER + A'", "SUPER + A\\",
  "SUPER + A\n", "SUPER + A\r", "SUPER + A; rm -rf ~", "SUPER + $(id)", "SUPER + `id`", "SUPER + A -- x",
  "SUPER + code:38", "SUPER + mouse:272", "SUPER + é", "SUPER + " + "A".repeat(80), null, undefined,
]) {
  const parsed = Model.autoTypeChord(raw)
  check(`${JSON.stringify(raw)} is refused with a reason`,
    !parsed.ok && parsed.chord === "" && typeof parsed.message === "string" && parsed.message.length > 10,
    JSON.stringify(parsed))
}
check("Shift alone is not enough to hold",
  /SUPER, CTRL or ALT/.test(Model.autoTypeChord("SHIFT + A").message), Model.autoTypeChord("SHIFT + A").message)
check("an unknown modifier is named",
  /"HYPER" is not a modifier/.test(Model.autoTypeChord("HYPER + A").message), Model.autoTypeChord("HYPER + A").message)

// --- the line ------------------------------------------------------------------

eq("the bind line is in bindings.lua's own style",
  Model.autoTypeBindLine("super + ctrl + backslash"), lineFor("SUPER + CTRL + BACKSLASH"))
eq("an invalid chord has no line", Model.autoTypeBindLine("SUPER + \"); os.execute(\"id"), "")
check("the comment is a Lua comment naming the plugin",
  /^-- /.test(COMMENT) && COMMENT.includes("qs-bitwarden-cli") && !COMMENT.includes("\n"), COMMENT)
check("the suggestions are valid chords, none of them Omarchy's SUPER + SHIFT + A",
  Model.autoTypeChordSuggestions().every(c => Model.autoTypeChord(c).chord === c)
    && !Model.autoTypeChordSuggestions().includes("SUPER + SHIFT + A"),
  JSON.stringify(Model.autoTypeChordSuggestions()))

// --- argv, never a spliced string ------------------------------------------------

const reg = Model.autoTypeKeybindRegisterCommand("SUPER + ALT + Q")
check("register runs bash with the script, then the line and comment as arguments",
  reg[0] === "bash" && reg[1] === "-c" && reg[3] === "qsbw-keybind"
    && reg[4] === lineFor("SUPER + ALT + Q") && reg[5] === COMMENT && reg.length === 6,
  JSON.stringify(reg.slice(3)))
check("the register script never contains the chord or the line",
  !reg[2].includes("SUPER + ALT + Q") && !reg[2].includes("o.bind(") && /"\$1"/.test(reg[2]) && /"\$2"/.test(reg[2]),
  reg[2])
const rem = Model.autoTypeKeybindRemoveCommand("SUPER + ALT + Q")
check("remove passes the line and comment as arguments, never in the script",
  rem[4] === lineFor("SUPER + ALT + Q") && rem[5] === COMMENT && !rem[2].includes("SUPER + ALT + Q")
    && /QSBW_LINE="\$1"/.test(rem[2]),
  JSON.stringify(rem))
check("an unsafe chord builds no command at all",
  Model.autoTypeKeybindRegisterCommand("SUPER + A\"; touch /tmp/x; \"").length === 0
    && Model.autoTypeKeybindRemoveCommand("SUPER + 'A'").length === 0, "expected []")
check("the inspection is read-only",
  !/>>|\bmv\b|\brm\b|reload|printf '%b/.test(Model.autoTypeKeybindInspectCommand()[2]),
  Model.autoTypeKeybindInspectCommand()[2])

// --- hyprctl binds -j ------------------------------------------------------------

// As `hyprctl binds -j` printed them on Omarchy 4 (Hyprland's Lua config):
// every o.bind() is dispatcher "__lua" with a closure number.
const live = [
  { locked: false, mouse: false, release: false, repeat: false, longPress: false, non_consuming: false,
    auto_consuming: false, has_description: true, modmask: 65, submap: "", submap_universal: "false",
    key: "", keycode: 0, catch_all: false, description: "Move window to workspace 1",
    allow_input_capture: false, dispatcher: "__lua", arg: "119" },
  { locked: false, mouse: false, release: false, repeat: false, longPress: false, non_consuming: false,
    auto_consuming: false, has_description: true, modmask: 65, submap: "", submap_universal: "false",
    key: "A", keycode: 0, catch_all: false, description: "ChatGPT", allow_input_capture: false,
    dispatcher: "__lua", arg: "178" },
  { locked: false, mouse: false, release: false, repeat: false, longPress: false, non_consuming: false,
    auto_consuming: false, has_description: true, modmask: 65, submap: "", submap_universal: "false",
    key: "SLASH", keycode: 0, catch_all: false, description: "Bitwarden vault", allow_input_capture: false,
    dispatcher: "__lua", arg: "246" },
  { modmask: 64, key: "mouse:272", mouse: true, description: "Move window", dispatcher: "__lua", arg: "3", submap: "" },
  { modmask: 72, key: "R", mouse: false, description: "", dispatcher: "__lua", arg: "9", submap: "resize" },
]
const ours = { modmask: 68, key: "BACKSLASH", mouse: false, description: "Bitwarden auto-type",
  dispatcher: "__lua", arg: "301", submap: "" }
const execShape = { modmask: 72, key: "T", mouse: false, description: "", dispatcher: "exec",
  arg: COMMAND, submap: "" }

const parsedBinds = Model.parseHyprBinds(JSON.stringify(live))
check("hyprctl's binds parse into their fields",
  parsedBinds.length === 5 && parsedBinds[1].modmask === 65 && parsedBinds[1].key === "A"
    && parsedBinds[1].description === "ChatGPT" && parsedBinds[1].dispatcher === "__lua",
  JSON.stringify(parsedBinds[1]))
for (const bad of ["", "not json", "{}", "null", "\"[]\""]) {
  eq(`hyprctl output ${JSON.stringify(bad)} is not binds`, Model.parseHyprBinds(bad), null)
}
check("an o.bind() of ours is found by its description",
  Model.hyprBindRunsAutoType(Model.parseHyprBinds(JSON.stringify([ours]))[0]), "expected a match")
check("an exec bind of the command is found by its argument",
  Model.hyprBindRunsAutoType(Model.parseHyprBinds(JSON.stringify([execShape]))[0]), "expected a match")
check("the panel toggle's bind is not auto-type",
  !Model.hyprBindRunsAutoType(parsedBinds[2]), "matched the toggle")
eq("a bind's chord reads back in the usual order", Model.chordFromHyprBind(parsedBinds[2]), "SUPER + SHIFT + SLASH")
eq("a keycode bind has no chord to show", Model.chordFromHyprBind(parsedBinds[0]), "")

// --- bindings.lua ----------------------------------------------------------------

const userFile = [
  "-- Keep only your personal keybinding overrides here.",
  "-- o.bind(\"SUPER + SHIFT + R\", \"SSH\", \"alacritty -e ssh your-server\")",
  "-- o.bind(\"SUPER + CTRL + BACKSLASH\", \"x\", \"" + COMMAND + "\")",
  "hl.unbind(\"SUPER + SHIFT + SLASH\")",
  "o.bind(\"SUPER + SHIFT + SLASH\", \"Bitwarden vault\", \"omarchy-shell io.github.elevate08.qs-bitwarden-cli toggle\")",
  "o.bind(\"SUPER + SHIFT + S\", nil, \"omarchy-capture-screenshot\")",
  "do",
  "  hl.bind(\"Escape\", function() end)",
  "end",
  "",
].join("\n")
const plain = Model.parseBindingsLua(userFile)
check("bindings.lua's o.bind() lines are read, commented ones skipped",
  plain.binds.length === 2 && plain.binds[0].chord === "SUPER + SHIFT + SLASH"
    && plain.binds[0].description === "Bitwarden vault" && plain.binds[1].description === ""
    && plain.binds[1].command === "omarchy-capture-screenshot" && plain.binds[0].line === 5,
  JSON.stringify(plain.binds))
check("a commented-out auto-type line is not a binding",
  plain.autoType === null && plain.autoTypeCount === 0, JSON.stringify(plain.autoType))
check("the toggle command is not the auto-type command",
  !Model.isAutoTypeCommand("omarchy-shell io.github.elevate08.qs-bitwarden-cli toggle")
    && !Model.isAutoTypeCommand("omarchy-shell io.github.elevate08.qs-bitwarden-cli autoTypeX")
    && Model.isAutoTypeCommand(COMMAND), "isAutoTypeCommand")

const withOurs = userFile + "\n" + COMMENT + "\n" + lineFor("SUPER + CTRL + BACKSLASH") + "\n"
const mine = Model.parseBindingsLua(withOurs)
check("the plugin's own pair is found and removable",
  mine.autoType && mine.autoType.chord === "SUPER + CTRL + BACKSLASH" && mine.autoType.ours
    && mine.removable && mine.removableChord === "SUPER + CTRL + BACKSLASH" && mine.autoTypeCount === 1,
  JSON.stringify(mine))

const handWritten = userFile + "o.bind(\"SUPER + CTRL + T\", \"Type it\", \"" + COMMAND + "\")\n"
const theirs = Model.parseBindingsLua(handWritten)
check("a line the user wrote is found but never removable",
  theirs.autoType && theirs.autoType.chord === "SUPER + CTRL + T" && !theirs.autoType.ours
    && !theirs.removable && theirs.autoType.line === 10,
  JSON.stringify(theirs))
const edited = Model.parseBindingsLua(userFile + COMMENT + "\n"
  + lineFor("SUPER + CTRL + BACKSLASH").replace("Bitwarden auto-type", "Type") + "\n")
check("our comment above a line the user changed is not removable",
  edited.autoType && !edited.removable, JSON.stringify(edited))

// --- the row's state ---------------------------------------------------------------

const inspect = (binds, file, opts = {}) => {
  const head = ["home=" + (opts.home === false ? "0" : "1"),
    "binds=" + (binds === null ? "" : JSON.stringify(binds)),
    "requires=" + (opts.requires === false ? "0" : "1"),
    "file=" + (file === null ? (opts.state || "absent") : "present")]
  return head.join("\n") + (file === null ? "\n" : "\n---\n" + file)
}
const stateOf = (binds, file, opts) => Model.autoTypeKeybindState(Model.parseAutoTypeKeybindInspection(inspect(binds, file, opts)))

const unchecked = Model.autoTypeKeybindState(null)
check("before the first inspection the row says it is checking",
  !unchecked.checked && !unchecked.canRegister && /Checking/.test(unchecked.status) && unchecked.setupNote === "",
  JSON.stringify(unchecked))

const none = stateOf(live, userFile)
check("no binding: says so, and can register",
  none.checked && !none.bound && none.status === "No keybinding yet" && none.canRegister && none.hyprctl
    && /register one under Settings/.test(none.setupNote),
  JSON.stringify(none))

const bound = stateOf(live.concat([ours]), withOurs)
check("our binding, live: Bound to its chord, removable",
  bound.bound && bound.live && bound.status === "Bound to SUPER + CTRL + BACKSLASH" && bound.removable
    && !bound.canRegister && /Added by this plugin on line 12/.test(bound.detail)
    && bound.setupNote === "Keybinding: SUPER + CTRL + BACKSLASH.",
  JSON.stringify(bound))

const pending = stateOf(live, withOurs)
check("in the file but not in Hyprland yet: bound, with a reload hint",
  pending.bound && !pending.live && /not loaded it yet/.test(pending.detail), JSON.stringify(pending))

const userLive = stateOf(live.concat([{ modmask: 68, key: "T", description: "Type it", dispatcher: "__lua", arg: "5" }]), handWritten)
check("a hand-written binding: bound, live by its own description, explained, not removable",
  userLive.bound && userLive.live && userLive.status === "Bound to SUPER + CTRL + T" && !userLive.removable
    && /line 10 of ~\/\.config\/hypr\/bindings\.lua; change or remove it there/.test(userLive.detail),
  JSON.stringify(userLive))

const elsewhere = stateOf(live.concat([execShape]), userFile)
check("a hyprland.conf-style exec bind elsewhere: bound, from hyprctl",
  elsewhere.bound && elsewhere.status === "Bound to SUPER + ALT + T" && !elsewhere.removable
    && /Set outside/.test(elsewhere.detail),
  JSON.stringify(elsewhere))

const noHypr = stateOf(null, withOurs)
check("without hyprctl the file alone decides (the fallback)",
  noHypr.bound && !noHypr.hyprctl && noHypr.status === "Bound to SUPER + CTRL + BACKSLASH"
    && !/not loaded/.test(noHypr.detail),
  JSON.stringify(noHypr))

const create = stateOf(live, null, { requires: true })
check("no bindings.lua but hyprland.lua loads it: register creates it",
  create.canRegister && /creates it/.test(create.detail), JSON.stringify(create))
const refuse = stateOf(live, null, { requires: false })
check("no bindings.lua and nothing loads it: refused, Copy Line offered",
  !refuse.canRegister && /will not create it/.test(refuse.blocked) && /Copy the line/.test(refuse.blocked),
  JSON.stringify(refuse))
const odd = stateOf(live, null, { state: "unusable" })
check("a bindings.lua that is not a readable file is left alone",
  !odd.canRegister && /left alone/.test(odd.blocked), JSON.stringify(odd))
check("no HOME: nothing to register into",
  !stateOf(live, null, { home: false }).canRegister, "expected canRegister false")
eq("an empty probe is no inspection", Model.parseAutoTypeKeybindInspection(""), null)

// --- conflicts --------------------------------------------------------------------------

const taken = Model.autoTypeChordCheck("SUPER + SHIFT + A", none)
check("Omarchy's SUPER + SHIFT + A is taken, named by its description",
  !taken.ok && /already bound to "ChatGPT"/.test(taken.message) && taken.line === lineFor("SUPER + SHIFT + A"),
  JSON.stringify(taken))
const toggle = Model.autoTypeChordCheck("super + shift + slash", none)
check("a binding from bindings.lua is named with its command",
  !toggle.ok && toggle.message.includes("\"Bitwarden vault\" (omarchy-shell io.github.elevate08.qs-bitwarden-cli toggle)"),
  toggle.message)
check("a mouse bind and another submap do not conflict",
  Model.autoTypeChordCheck("SUPER + ALT + R", none).ok, JSON.stringify(Model.autoTypeChordCheck("SUPER + ALT + R", none)))
const free = Model.autoTypeChordCheck("SUPER + CTRL + BACKSLASH", none)
check("a free chord passes, with its line",
  free.ok && free.chord === "SUPER + CTRL + BACKSLASH" && free.line === lineFor("SUPER + CTRL + BACKSLASH")
    && free.message === "" && free.note === "",
  JSON.stringify(free))
const execTaken = Model.autoTypeChordCheck("SUPER + ALT + T", elsewhere)
check("a chord that already runs auto-type says so",
  !execTaken.ok && /already runs auto-type/.test(execTaken.message), execTaken.message)
const fileOnly = Model.autoTypeChordCheck("SUPER + SHIFT + SLASH", stateOf(null, userFile))
check("without hyprctl, bindings.lua is checked, and the row says only it was",
  !fileOnly.ok && /Bitwarden vault/.test(fileOnly.message), JSON.stringify(fileOnly))
check("without hyprctl, a free chord carries the note",
  /hyprctl is not available/.test(Model.autoTypeChordCheck("SUPER + ALT + A", stateOf(null, userFile)).note),
  JSON.stringify(Model.autoTypeChordCheck("SUPER + ALT + A", stateOf(null, userFile))))
check("an unbound file line is not a conflict when hyprctl says the key is free",
  Model.autoTypeChordCheck("SUPER + SHIFT + S", none).ok, JSON.stringify(Model.autoTypeChordCheck("SUPER + SHIFT + S", none)))
eq("the suggestion skips taken chords",
  Model.autoTypeChordSuggestion(stateOf(live.concat([{ modmask: 68, key: "BACKSLASH", description: "Other", dispatcher: "__lua", arg: "1" }]), userFile)),
  "SUPER + ALT + A")
eq("the suggestion is the first free one", Model.autoTypeChordSuggestion(none), "SUPER + CTRL + BACKSLASH")

// --- result messages ----------------------------------------------------------------

const ok = Model.parseAutoTypeKeybindResult(0, "appended\nreloaded\n", "SUPER + ALT + A")
check("registered and reloaded: says the chord",
  ok.ok && ok.code === "APPENDED" && /^Registered SUPER \+ ALT \+ A\./.test(ok.message) && !ok.warning, JSON.stringify(ok))
const noReload = Model.parseAutoTypeKeybindResult(0, "appended\nno-hyprctl\n", "SUPER + ALT + A")
check("registered without hyprctl: says it applies on reload",
  noReload.ok && /hyprctl reload/.test(noReload.message), noReload.message)
const errs = Model.parseAutoTypeKeybindResult(0, "appended\nreloaded\nerrors=bindings.lua:40: bad key\n", "SUPER + ALT + A")
check("a config error after the reload is shown as a warning",
  errs.ok && errs.warning && /config error: bindings\.lua:40: bad key/.test(errs.message), JSON.stringify(errs))
check("each refusal has its own message",
  /already has a line/.test(Model.parseAutoTypeKeybindResult(5, "").message)
    && /not created/.test(Model.parseAutoTypeKeybindResult(6, "").message)
    && /not a regular file/.test(Model.parseAutoTypeKeybindResult(4, "").message)
    && /nothing was removed/.test(Model.parseAutoTypeKeybindResult(8, "").message)
    && /Could not update/.test(Model.parseAutoTypeKeybindResult(1, "").message),
  "refusal messages")
check("removed: says so",
  /^Removed the keybinding/.test(Model.parseAutoTypeKeybindResult(0, "removed\nreloaded").message), "removed")

// --- the real scripts, in a throwaway HOME ---------------------------------------------

const work = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-keybind-"))
const stubs = path.join(work, "bin")
fs.mkdirSync(stubs)
const hyprLog = path.join(work, "hyprctl.log")
const bindsJson = path.join(work, "binds.json")
fs.writeFileSync(bindsJson, JSON.stringify(live))
fs.writeFileSync(path.join(stubs, "hyprctl"), `#!/bin/bash
printf '%s\\n' "$*" >> ${JSON.stringify(hyprLog)}
case "$1" in
  binds) cat ${JSON.stringify(bindsJson)} ;;
  reload) echo ok ;;
  configerrors) printf '[\\n\\t""\\n]\\n' ;;
esac
`, { mode: 0o755 })
// A PATH without any hyprctl: the tools the scripts use, linked one by one.
const noHyprBin = path.join(work, "nohypr")
fs.mkdirSync(noHyprBin)
for (const tool of ["bash", "grep", "tail", "head", "jq", "awk", "mktemp", "readlink", "dirname", "chmod", "mv", "rm", "cat", "tr"]) {
  const found = spawnSync("bash", ["-c", "command -v " + tool], { encoding: "utf8" }).stdout.trim()
  if (found) fs.symlinkSync(found, path.join(noHyprBin, tool))
}

// A copy of the shape of Omarchy 4's own template files.
const template = fs.existsSync("/usr/share/omarchy/config/hypr/bindings.lua")
  ? fs.readFileSync("/usr/share/omarchy/config/hypr/bindings.lua", "utf8") : userFile
const hyprlandLua = "require(\"default.hypr.omarchy\")\nrequire(\"hypr.monitors\")\nrequire(\"hypr.bindings\")\n"

function makeHome(name, files) {
  const home = path.join(work, name)
  fs.mkdirSync(path.join(home, ".config", "hypr"), { recursive: true })
  for (const [rel, content] of Object.entries(files)) fs.writeFileSync(path.join(home, ".config", "hypr", rel), content)
  return home
}
function run(cmd, home, pathDirs = [stubs, "/usr/bin", "/bin"]) {
  const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8",
    env: { HOME: home, PATH: pathDirs.join(":"), LC_ALL: "C" } })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
const hyprDir = home => path.join(home, ".config", "hypr")
const fileIn = home => path.join(hyprDir(home), "bindings.lua")
const listing = home => fs.readdirSync(hyprDir(home)).sort().join(",")
const chord = "SUPER + CTRL + BACKSLASH"

try {
  check("the stand-in hyprctl comes first on PATH",
    run(["bash", "-c", "command -v hyprctl"], work).out.trim() === path.join(stubs, "hyprctl"), "PATH")

  // Append once.
  const home = makeHome("home", { "bindings.lua": template, "hyprland.lua": hyprlandLua })
  const before = listing(home)
  const first = run(Model.autoTypeKeybindRegisterCommand(chord), home)
  const after = fs.readFileSync(fileIn(home), "utf8")
  check("register appends the comment and line once, after a blank line, leaving the rest byte for byte",
    first.code === 0 && after === template + (template.endsWith("\n") ? "" : "\n") + "\n" + COMMENT + "\n" + lineFor(chord) + "\n",
    JSON.stringify({ code: first.code, err: first.err, tail: after.slice(-300) }))
  check("register reloads Hyprland's config without the monitors, and reads its errors",
    /^appended\nreloaded\n?$/.test(first.out)
      && /^reload config-only$/m.test(fs.readFileSync(hyprLog, "utf8"))
      && /^configerrors -j$/m.test(fs.readFileSync(hyprLog, "utf8")),
    first.out + fs.readFileSync(hyprLog, "utf8"))
  check("register creates nothing else", listing(home) === before, listing(home))

  // The inspection sees it.
  const seen = Model.autoTypeKeybindState(Model.parseAutoTypeKeybindInspection(
    run(Model.autoTypeKeybindInspectCommand(), home).out))
  check("the real inspection reads it back as ours (not yet live in the stand-in)",
    seen.bound && seen.chord === chord && seen.removable && seen.hyprctl && !seen.live, JSON.stringify(seen))

  // Refuse twice.
  const second = run(Model.autoTypeKeybindRegisterCommand("SUPER + ALT + A"), home)
  check("a second register is refused and changes nothing",
    second.code === 5 && fs.readFileSync(fileIn(home), "utf8") === after && listing(home) === before,
    JSON.stringify(second))

  // Remove exactly the pair.
  const removed = run(Model.autoTypeKeybindRemoveCommand(chord), home)
  check("remove takes out exactly what register added",
    removed.code === 0 && /^removed\nreloaded/.test(removed.out)
      && fs.readFileSync(fileIn(home), "utf8") === template.replace(/([^\n])$/, "$1\n"),
    JSON.stringify(removed))
  check("remove leaves no temporary file behind", listing(home) === before, listing(home))
  const again = run(Model.autoTypeKeybindRemoveCommand(chord), home)
  check("removing again finds nothing of ours and changes nothing",
    again.code === 8 && fs.readFileSync(fileIn(home), "utf8") === template.replace(/([^\n])$/, "$1\n"),
    JSON.stringify(again))

  // A hand-edited line is the user's.
  fs.writeFileSync(fileIn(home), template + "\n" + COMMENT + "\n" + lineFor(chord).replace("BACKSLASH", "SLASH") + "\n")
  const editedRun = run(Model.autoTypeKeybindRemoveCommand(chord), home)
  check("a line the user changed is not removed",
    editedRun.code === 8 && fs.readFileSync(fileIn(home), "utf8").includes("SUPER + CTRL + SLASH"), JSON.stringify(editedRun))
  check("and it still counts as a binding, so register refuses",
    run(Model.autoTypeKeybindRegisterCommand(chord), home).code === 5, "expected 5")

  // A file with no final newline, a hand-written binding, a commented one.
  const noNl = makeHome("nonl", { "bindings.lua": "o.bind(\"SUPER + B\", \"Browser\", \"chromium\")", "hyprland.lua": hyprlandLua })
  check("a last line with no newline gets one before the blank line",
    run(Model.autoTypeKeybindRegisterCommand(chord), noNl).code === 0
      && fs.readFileSync(fileIn(noNl), "utf8") === "o.bind(\"SUPER + B\", \"Browser\", \"chromium\")\n\n" + COMMENT + "\n" + lineFor(chord) + "\n",
    JSON.stringify(fs.readFileSync(fileIn(noNl), "utf8")))
  const commented = makeHome("commented", { "bindings.lua": "-- o.bind(\"SUPER + T\", nil, \"" + COMMAND + "\")\n", "hyprland.lua": hyprlandLua })
  check("a commented-out auto-type line does not block register",
    run(Model.autoTypeKeybindRegisterCommand(chord), commented).code === 0, "expected 0")
  const theirsHome = makeHome("theirs", { "bindings.lua": "o.bind(\"SUPER + T\", nil, \"" + COMMAND + "\")\n", "hyprland.lua": hyprlandLua })
  check("a hand-written auto-type line blocks register",
    run(Model.autoTypeKeybindRegisterCommand(chord), theirsHome).code === 5
      && fs.readFileSync(fileIn(theirsHome), "utf8") === "o.bind(\"SUPER + T\", nil, \"" + COMMAND + "\")\n", "expected 5")

  // A missing file: created only where hyprland.lua loads it.
  const fresh = makeHome("fresh", { "hyprland.lua": hyprlandLua })
  check("a missing bindings.lua is created when hyprland.lua requires it, holding only the pair",
    run(Model.autoTypeKeybindRegisterCommand(chord), fresh).code === 0
      && fs.readFileSync(fileIn(fresh), "utf8") === COMMENT + "\n" + lineFor(chord) + "\n"
      && listing(fresh) === "bindings.lua,hyprland.lua",
    listing(fresh))
  const foreign = makeHome("foreign", { "hyprland.lua": "-- require(\"hypr.bindings\")\n" })
  check("a missing bindings.lua is not created when nothing loads it",
    run(Model.autoTypeKeybindRegisterCommand(chord), foreign).code === 6 && listing(foreign) === "hyprland.lua",
    listing(foreign))
  const bare = path.join(work, "bare")
  fs.mkdirSync(bare)
  check("with no ~/.config/hypr at all nothing is created",
    run(Model.autoTypeKeybindRegisterCommand(chord), bare).code === 6 && fs.readdirSync(bare).length === 0,
    fs.readdirSync(bare).join(","))

  // Not a regular file.
  const dirHome = makeHome("dir", { "hyprland.lua": hyprlandLua })
  fs.mkdirSync(fileIn(dirHome))
  check("a directory named bindings.lua is refused",
    run(Model.autoTypeKeybindRegisterCommand(chord), dirHome).code === 4, "expected 4")
  const dangling = makeHome("dangling", { "hyprland.lua": hyprlandLua })
  fs.symlinkSync(path.join(work, "nowhere.lua"), fileIn(dangling))
  check("a dangling symlink is refused, and its target is not created",
    run(Model.autoTypeKeybindRegisterCommand(chord), dangling).code === 4 && !fs.existsSync(path.join(work, "nowhere.lua")),
    "expected 4")

  // A symlink to a regular file (a dotfiles checkout) is followed and kept.
  const dots = path.join(work, "dotfiles")
  fs.mkdirSync(dots)
  fs.writeFileSync(path.join(dots, "bindings.lua"), template)
  fs.chmodSync(path.join(dots, "bindings.lua"), 0o640)
  const linked = makeHome("linked", { "hyprland.lua": hyprlandLua })
  fs.symlinkSync(path.join(dots, "bindings.lua"), fileIn(linked))
  const linkedAdd = run(Model.autoTypeKeybindRegisterCommand(chord), linked)
  const linkedRemove = run(Model.autoTypeKeybindRemoveCommand(chord), linked)
  check("through a symlink: appended to its target, removed again, the link and mode kept",
    linkedAdd.code === 0 && linkedRemove.code === 0 && fs.lstatSync(fileIn(linked)).isSymbolicLink()
      && fs.readFileSync(path.join(dots, "bindings.lua"), "utf8") === template.replace(/([^\n])$/, "$1\n")
      && (fs.statSync(path.join(dots, "bindings.lua")).mode & 0o777) === 0o640
      && fs.readdirSync(dots).join(",") === "bindings.lua",
    JSON.stringify({ linkedAdd, linkedRemove, files: fs.readdirSync(dots) }))

  // No hyprctl: the file is still written, and the message says to reload.
  const quiet = makeHome("quiet", { "bindings.lua": template, "hyprland.lua": hyprlandLua })
  const quietRun = run(Model.autoTypeKeybindRegisterCommand(chord), quiet, [noHyprBin])
  check("without hyprctl the line is still added, with no reload",
    quietRun.code === 0 && /^appended\nno-hyprctl/.test(quietRun.out)
      && /hyprctl reload/.test(Model.parseAutoTypeKeybindResult(quietRun.code, quietRun.out, chord).message),
    JSON.stringify(quietRun))
  const quietState = Model.autoTypeKeybindState(Model.parseAutoTypeKeybindInspection(
    run(Model.autoTypeKeybindInspectCommand(), quiet, [noHyprBin]).out))
  check("without hyprctl the inspection falls back to bindings.lua",
    quietState.bound && !quietState.hyprctl && quietState.chord === chord, JSON.stringify(quietState))

  // The real inspection against the stand-in's binds: conflicts as on Omarchy.
  const inspected = Model.autoTypeKeybindState(Model.parseAutoTypeKeybindInspection(
    run(Model.autoTypeKeybindInspectCommand(), makeHome("probe", { "bindings.lua": template, "hyprland.lua": hyprlandLua })).out))
  check("the real inspection reads hyprctl's binds through jq",
    inspected.hyprctl && inspected.binds.length === live.length && !inspected.bound
      && /ChatGPT/.test(Model.autoTypeChordCheck("SUPER + SHIFT + A", inspected).message),
    JSON.stringify(inspected).slice(0, 400))
} finally {
  fs.rmSync(work, { recursive: true, force: true })
}

// --- the wiring stays thin ------------------------------------------------------------

const service = readPluginSource("Service.qml")
const row = readPluginSource("AutoTypeKeybind.qml")
check("the Service runs the model's commands, the action's argv built per click",
  /command: Model\.autoTypeKeybindInspectCommand\(\)/.test(service)
    && /Model\.autoTypeKeybindRegisterCommand\(check\.chord\)/.test(service)
    && /Model\.autoTypeKeybindRemoveCommand\(autoTypeKeybind\.removableChord\)/.test(service),
  "expected the model's commands")
check("Copy Line puts the line on the clipboard as a non-secret, through the environment",
  /Model\.clipboardCopyPlainCommand\(\)/.test(service) && !Model.clipboardCopyPlainCommand()[2].includes("--sensitive")
    && !Model.clipboardCopyPlainCommand()[2].includes("timeout") && Model.clipboardCopyPlainCommand()[2].includes("env -u QSBW_CLIP"),
  JSON.stringify(Model.clipboardCopyPlainCommand()))
check("the row draws the model's text, not its own",
  /text: section\.keybind\.status/.test(row) && /text: section\.chordCheck\.message/.test(row)
    && /readonly property var keybind: section\.panel\.autoTypeKeybind/.test(row)
    && !/"Bound to/.test(row) && !/"No keybinding/.test(row),
  "status and messages come from BitwardenModel.js")

// The Service's own steps, run with a stand-in scope.
{
  const { functionBody } = require("./harness")
  const names = ["inspectAutoTypeKeybind", "onAutoTypeKeybindInspected", "registerAutoTypeKeybind",
    "removeAutoTypeKeybind", "onAutoTypeKeybindActionFinished", "copyAutoTypeBindLine"]
  const make = v => {
    v.root = v
    const fns = new Function("root", "with (root) {\n" + names.map(n => functionBody(service, n)).join("\n")
      + "\nreturn {" + names.map(n => `${n}: ${n}`).join(", ") + "} }")(v)
    return Object.assign(v, fns)
  }
  const proc = () => ({ running: false, command: [], chord: "" })
  const v = make({
    Model, autoTypeKeybind: Model.autoTypeKeybindState(null), autoTypeChordText: "", autoTypeKeybindBusy: false,
    autoTypeKeybindResult: null, autoTypeKeybindRecheck: false, autoTypeChordCheck: null,
    autoTypeKeybindInspectProc: proc(), autoTypeKeybindActionProc: proc(), flashes: [], detached: [],
    flashNotification(m) { v.flashes.push(m) },
    Quickshell: { execDetached(o) { v.detached.push(o) } },
  })
  const recheck = () => { v.autoTypeChordCheck = Model.autoTypeChordCheck(v.autoTypeChordText, v.autoTypeKeybind) }

  v.inspectAutoTypeKeybind()
  v.inspectAutoTypeKeybind()
  check("an inspection asked for while one runs runs again after it",
    v.autoTypeKeybindInspectProc.running && v.autoTypeKeybindRecheck, "expected a queued recheck")
  v.autoTypeKeybindInspectProc.running = false
  v.onAutoTypeKeybindInspected(inspect(live, userFile))
  recheck()
  check("the first answer fills the field with a free chord, once",
    v.autoTypeChordText === "SUPER + CTRL + BACKSLASH" && v.autoTypeKeybind.canRegister
      && v.autoTypeKeybindInspectProc.running && !v.autoTypeKeybindRecheck, v.autoTypeChordText)

  v.autoTypeChordText = "SUPER + SHIFT + A"
  recheck()
  v.registerAutoTypeKeybind()
  check("a taken chord is not registered, and the row says why",
    !v.autoTypeKeybindActionProc.running && /ChatGPT/.test(v.autoTypeKeybindResult.message), JSON.stringify(v.autoTypeKeybindResult))

  v.autoTypeChordText = "super + alt + a"
  recheck()
  v.registerAutoTypeKeybind()
  check("a free chord runs the register script for the normalised chord",
    v.autoTypeKeybindActionProc.running && v.autoTypeKeybindBusy && v.autoTypeKeybindActionProc.chord === "SUPER + ALT + A"
      && JSON.stringify(v.autoTypeKeybindActionProc.command) === JSON.stringify(Model.autoTypeKeybindRegisterCommand("SUPER + ALT + A")),
    JSON.stringify(v.autoTypeKeybindActionProc))
  v.autoTypeKeybindActionProc.running = false
  v.autoTypeKeybindInspectProc.running = false
  v.onAutoTypeKeybindActionFinished(0, "appended\nreloaded\n")
  check("its answer is shown and the state read again",
    !v.autoTypeKeybindBusy && /^Registered SUPER \+ ALT \+ A/.test(v.autoTypeKeybindResult.message)
      && v.autoTypeKeybindInspectProc.running, JSON.stringify(v.autoTypeKeybindResult))

  v.removeAutoTypeKeybind()
  check("remove does nothing unless the plugin's own pair is there", !v.autoTypeKeybindActionProc.running, "ran")
  v.autoTypeKeybind = Model.autoTypeKeybindState(Model.parseAutoTypeKeybindInspection(inspect(live, withOurs)))
  v.removeAutoTypeKeybind()
  check("remove runs for the pair's own chord",
    v.autoTypeKeybindActionProc.running
      && JSON.stringify(v.autoTypeKeybindActionProc.command) === JSON.stringify(Model.autoTypeKeybindRemoveCommand("SUPER + CTRL + BACKSLASH")),
    JSON.stringify(v.autoTypeKeybindActionProc.command))

  recheck()
  v.copyAutoTypeBindLine()
  const copied = v.detached[0]
  check("Copy Line hands the line to wl-copy in the environment, not argv",
    copied && copied.environment[Model.clipboardEnvVar()] === lineFor("SUPER + ALT + A")
      && !JSON.stringify(copied.command).includes("o.bind") && v.flashes.includes("Keybinding line copied"),
    JSON.stringify(copied))
}

done()
