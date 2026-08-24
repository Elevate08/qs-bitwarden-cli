#!/usr/bin/env node
// Tests for the generator's option handling. Generation itself is `bw generate`;
// what is worth testing is that we never hand it a combination it rejects.
//
//   node tests/generator.test.js

const fs = require("fs")
const path = require("path")
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const bodyOf = (name) => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}
const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.generateCommand = generateCommand
  exports.generateServeUrl = generateServeUrl
  exports.generateServeRequestCommand = generateServeRequestCommand
  exports.parseServeGenerated = parseServeGenerated
  exports.generateServeCommand = generateServeCommand
  exports.normalizeGeneratorOptions = normalizeGeneratorOptions
  exports.generatorDefaults = generatorDefaults
  exports.generatorStrength = generatorStrength
  exports.generatorPortIsForeign = generatorPortIsForeign
  exports.generatorServeExitAction = generatorServeExitAction
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)
const args = o => Model.generateCommand(o).join(" ")

// `bw generate` errors if every character set is off; fall back rather than fail.
const none = Model.normalizeGeneratorOptions({ uppercase: false, lowercase: false, numbers: false, special: false })
check("all character sets off falls back to lowercase",
  none.lowercase === true, JSON.stringify(none))

// Requiring more special/numeric characters than the length allows is impossible.
const tight = Model.normalizeGeneratorOptions({ length: 5, numbers: true, minNumber: 9, special: true, minSpecial: 9 })
check("length grows to fit the required character minimums",
  tight.length >= tight.minNumber + tight.minSpecial, JSON.stringify(tight))

// Minimums for a disabled set would be rejected by bw.
const noNums = Model.normalizeGeneratorOptions({ numbers: false, minNumber: 5, special: false, minSpecial: 5 })
check("minimums are zeroed for disabled character sets",
  noNums.minNumber === 0 && noNums.minSpecial === 0, JSON.stringify(noNums))
check("disabled sets emit no minimum flags",
  !args({ numbers: false, special: false }).includes("--minNumber")
  && !args({ numbers: false, special: false }).includes("--minSpecial"),
  args({ numbers: false, special: false }))

// Clamping to the documented CLI limits.
for (const [k, v, lo, hi] of [["length", 1, 5, 128], ["length", 999, 5, 128],
                              ["words", 1, 3, 20], ["words", 99, 3, 20],
                              ["minNumber", -3, 0, 9], ["minSpecial", 99, 0, 9]]) {
  const got = Model.normalizeGeneratorOptions({ [k]: v, numbers: true, special: true })[k]
  check(`${k}=${v} clamps into [${lo}, ${hi}]`, got >= lo && got <= hi, `got ${got}`)
}

// Passphrase mode must not leak password-only flags, and vice versa.
const pp = args({ type: "passphrase", words: 5, capitalize: true, includeNumber: true })
check("passphrase passes --passphrase and word options",
  pp.includes("--passphrase") && pp.includes("--words 5") && pp.includes("--capitalize") && pp.includes("--includeNumber"), pp)
check("passphrase omits password-only flags",
  !pp.includes("--length") && !pp.includes("--minNumber") && !pp.includes("--uppercase"), pp)
const pw = args({ type: "password" })
check("password omits passphrase-only flags",
  !pw.includes("--passphrase") && !pw.includes("--words") && !pw.includes("--capitalize"), pw)

check("an empty separator falls back rather than producing a bare flag",
  Model.normalizeGeneratorOptions({ separator: "" }).separator === "-",
  Model.normalizeGeneratorOptions({ separator: "" }).separator)

// Strength must move in the right direction, or the meter misleads.
const s = o => Model.generatorStrength(o).bits
check("longer passwords score higher", s({ length: 32 }) > s({ length: 8 }), `${s({length:32})} vs ${s({length:8})}`)
check("more character sets score higher",
  s({ length: 16, special: true }) > s({ length: 16, special: false }),
  `${s({length:16,special:true})} vs ${s({length:16,special:false})}`)
check("more words score higher", s({ type: "passphrase", words: 8 }) > s({ type: "passphrase", words: 3 }),
  `${s({type:"passphrase",words:8})} vs ${s({type:"passphrase",words:3})}`)
check("strength fraction stays within 0..1",
  [{}, { length: 128, special: true }, { length: 5 }].every(o => {
    const f = Model.generatorStrength(o).fraction; return f >= 0 && f <= 1 }), "out of range")

check("defaults are a fresh object each call",
  Model.generatorDefaults() !== Model.generatorDefaults(), "same reference returned")


// --- the same options over `bw serve` ---------------------------------------
// `bw generate` spends ~2.9s on CLI bootstrap and service init before it
// generates anything; the serve API answers the same request in ~2ms. These
// URLs were verified against a live locked `bw serve`.

const url = (o) => Model.generateServeUrl(o)

check("the server is addressed on loopback only",
  url({}).startsWith("http://127.0.0.1:"), url({}))
check("a password request carries the character sets and length",
  url({ length: 20, uppercase: true, lowercase: true, numbers: true, special: true })
    .includes("length=20") && url({ length: 20, special: true }).includes("special=true"),
  url({ length: 20, uppercase: true, lowercase: true, numbers: true, special: true }))
check("a disabled set is omitted rather than sent false",
  !url({ special: false, numbers: false }).includes("special=")
    && !url({ special: false, numbers: false }).includes("number="),
  url({ special: false, numbers: false }))
check("minimums ride along only when their set is on",
  url({ numbers: true, minNumber: 3 }).includes("minNumber=3")
    && !url({ numbers: false, minNumber: 3 }).includes("minNumber"),
  url({ numbers: true, minNumber: 3 }))
check("a passphrase request switches shape entirely",
  url({ type: "passphrase", words: 5 }).includes("passphrase=true")
    && url({ type: "passphrase", words: 5 }).includes("words=5")
    && !url({ type: "passphrase", words: 5 }).includes("length="),
  url({ type: "passphrase", words: 5 }))
check("a separator that means something in a URL is encoded",
  url({ type: "passphrase", separator: "&" }).includes("separator=%26"),
  url({ type: "passphrase", separator: "&" }))
check("the serve options are clamped the same way the CLI ones are",
  url({ length: 9999 }).includes("length=128") && url({ length: 1 }).includes("length=5"),
  url({ length: 9999 }) + " / " + url({ length: 1 }))

// The server is started without a session on purpose: a loopback port has no
// authentication, so it must never hold an unlocked vault.
check("the serve command binds loopback and names no session",
  JSON.stringify(Model.generateServeCommand()) ===
    JSON.stringify(["bw", "serve", "--hostname", "127.0.0.1", "--port", "8087"]),
  JSON.stringify(Model.generateServeCommand()))

const serveReq = Model.generateServeRequestCommand({ length: 20, special: true })
check("the serve request command targets the generated url with timeout and stream cap",
  serveReq[2].includes("curl -q -s -S") && serveReq[2].includes("http://127.0.0.1:8087/generate")
    && serveReq[2].includes("--max-time 2") && serveReq[2].includes("head -c 65536"),
  serveReq[2])
check("loopback generator requests ignore proxy variables and curl config",
  serveReq[2].includes("curl -q ") && serveReq[2].includes("--noproxy '*'"), serveReq[2])

check("a successful response yields the value",
  Model.parseServeGenerated('{"success":true,"data":{"object":"string","data":"abc123"}}') === "abc123",
  Model.parseServeGenerated('{"success":true,"data":{"object":"string","data":"abc123"}}'))
check("a failed response yields nothing, so the caller falls back",
  Model.parseServeGenerated('{"success":false,"message":"locked"}') === "", "expected empty")
check("garbage yields nothing rather than throwing",
  Model.parseServeGenerated("<html>not json</html>") === "", "expected empty")
check("an empty body yields nothing", Model.parseServeGenerated("") === "", "expected empty")


// --- the loopback server is not trusted just because it answers --------------
//
// `bw serve` has no authentication and a loopback port is reachable by every
// account on the machine, so an HTTP 200 is not evidence that the process which
// sent it is ours. The only answer that leaves the port free for our own server
// is a refused connection.

check("a refused connection is the one answer that frees the port",
  Model.generatorPortIsForeign(0) === false, "status 0 was treated as occupied")
for (const status of [200, 404, 500, 401, 302]) {
  check(`an HTTP ${status} means someone else is already bound`,
    Model.generatorPortIsForeign(status) === true, `status ${status} was trusted`)
}
check("a status arriving as a string is still not mistaken for silence",
  Model.generatorPortIsForeign("200") === true, "string status was trusted")

// --- what our own server exiting means ---------------------------------------

const stopped = Model.generatorServeExitAction({ stopping: true, wasReady: true, busy: false,
  onGeneratorScreen: false })
check("a shutdown we asked for is not a bind failure",
  stopped.giveUp === false && stopped.dropValue === false && stopped.useCli === false,
  JSON.stringify(stopped))

// Our bind failing is what a squatted port looks like from here, so a value the
// ready-poll already accepted cannot be left on screen to be copied.
const stranded = Model.generatorServeExitAction({ stopping: false, wasReady: true, busy: false,
  onGeneratorScreen: true })
check("a value delivered before our server died is dropped, not left to be copied",
  stranded.dropValue === true && stranded.giveUp === true && stranded.useCli === true,
  JSON.stringify(stranded))

const neverBound = Model.generatorServeExitAction({ stopping: false, wasReady: false, busy: true,
  onGeneratorScreen: true })
check("a server that never bound gives up the port and falls back to the CLI",
  neverBound.giveUp === true && neverBound.dropValue === false && neverBound.useCli === true,
  JSON.stringify(neverBound))

const offScreen = Model.generatorServeExitAction({ stopping: false, wasReady: true, busy: false,
  onGeneratorScreen: false })
check("nothing is regenerated for a screen the user has already left",
  offScreen.useCli === false && offScreen.dropValue === true, JSON.stringify(offScreen))

const idle = Model.generatorServeExitAction({ stopping: false, wasReady: false, busy: false,
  onGeneratorScreen: true })
check("an idle failure gives up the port without generating anything",
  idle.giveUp === true && idle.useCli === false, JSON.stringify(idle))

// A process already answering an older option set must not have its callback
// relabelled as the newest request. Queue one regeneration and discard the old
// result; the follow-up reads the latest root.genOpts.
const regenerate = bodyOf("regenerate")
const generated = bodyOf("onGenerated")
check("rapid option changes queue behind the active generator operation",
  /if\s*\(genBusy\)[\s\S]*genRegeneratePending\s*=\s*true/.test(regenerate), regenerate)
check("a queued regeneration discards the old value before rerunning",
  /genRegeneratePending[\s\S]*regenerate\(\)/.test(generated)
    && generated.indexOf("genRegeneratePending") < generated.indexOf("genValue = v"),
  generated)
check("a value from the previous option set cannot be copied while regeneration is busy",
  /if\s*\(genBusy\s*\|\|\s*!genValue\)\s*return/.test(bodyOf("copyGenerated"))
    && /if\s*\(!generatorFeedsForm\s*\|\|\s*genBusy\s*\|\|\s*!genValue\)\s*return/.test(bodyOf("useGeneratedPassword"))
    && /enabled:\s*!root\.genBusy\s*&&\s*root\.genValue\s*!==\s*""/.test(panelSrc),
  bodyOf("copyGenerated") + "\n" + bodyOf("useGeneratedPassword"))

const stopGenerator = bodyOf("stopGeneratorServe")
check("canceling an in-flight generator request cannot leave generation wedged busy",
  /genBusy\s*=\s*false/.test(stopGenerator)
    && /genRegeneratePending\s*=\s*false/.test(stopGenerator)
    && /genRequestSignature\s*=\s*""/.test(stopGenerator),
  stopGenerator)
check("leaving during CLI fallback cancels the late result instead of restarting off-screen",
  /cancelCliGeneration\s*=\s*genBusy\s*&&\s*generateProc\.running/.test(stopGenerator)
    && /generateCliStopping\s*=\s*true[\s\S]*generateProc\.running\s*=\s*false/.test(stopGenerator),
  stopGenerator)
const generateProcBlock = panelSrc.slice(panelSrc.indexOf("id: generateProc"),
  panelSrc.indexOf("id: generateServeProc"))
check("a canceled CLI result is discarded and a quick reopen restarts only after exit",
  /if\s*\(generateCliStopping\)[\s\S]*genRegeneratePending\s*=\s*true[\s\S]*return/.test(regenerate)
    && /generateCliStopping[\s\S]*currentScreen\s*===\s*"generator"[\s\S]*Qt\.callLater\(root\.regenerate\)[\s\S]*return/.test(generateProcBlock),
  regenerate + "\n" + generateProcBlock)
const serveRequest = bodyOf("generatorRequest")
const resumeServeRequest = bodyOf("resumePendingGeneratorRequest")
const serveRequestProcBlock = panelSrc.slice(panelSrc.indexOf("id: generateServeRequestProc"),
  panelSrc.indexOf("id: generateServePoll"))
check("a quick reopen cannot attach a new callback to the request being canceled",
  /generateServeRequestStopping\s*\|\|\s*generateServeRequestProc\.running/.test(serveRequest)
    && /generateServeRequestPendingCallback\s*=\s*done/.test(serveRequest)
    && /generateServeRequestStopping\s*=\s*true[\s\S]*generateServeRequestProc\.running\s*=\s*false/.test(stopGenerator)
    && /resumePendingGeneratorRequest\(\)[\s\S]*return/.test(serveRequestProcBlock),
  serveRequest + "\n" + stopGenerator + "\n" + serveRequestProcBlock)
check("a deferred generator request restarts only if the generator is still open",
  /root\.opened\s*&&\s*root\.currentScreen\s*===\s*"generator"[\s\S]*generatorRequest\(pendingOptions,\s*pendingCallback\)/.test(
    resumeServeRequest),
  resumeServeRequest)

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
