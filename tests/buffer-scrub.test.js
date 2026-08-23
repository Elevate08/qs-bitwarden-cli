#!/usr/bin/env node
// Two things a lock and a logout were leaving behind.
//
//   node tests/buffer-scrub.test.js
//
//  1. A StdioCollector keeps whatever its process last printed until that
//     process runs again, so every secret that has come back through a pipe
//     outlives the lock that was supposed to end it. Emptying one means
//     running a command through it that prints nothing, which is what these
//     assertions describe: what that command is, how a handler recognises a
//     run of it, and which processes a pass over the queue touches.
//  2. The generator port is loopback and first-come, and QML's
//     XMLHttpRequest has no timeout of its own. What bounds a request to a
//     squatter is checked here; what happens to one is checked in
//     tests/qml/tst_collector_scrub.qml, which needs Qt.

const fs = require("fs")
const path = require("path")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.scrubCommand = scrubCommand
  exports.isScrubCommand = isScrubCommand
  exports.scrubPass = scrubPass
  exports.scrubRetryMs = scrubRetryMs
  exports.scrubRetryLimit = scrubRetryLimit
  exports.generatorResponseCap = generatorResponseCap
  exports.generatorRequestTimeoutMs = generatorRequestTimeoutMs
  exports.generatorResponseTooLarge = generatorResponseTooLarge
  exports.generatorPortIsForeign = generatorPortIsForeign
  exports.generatorProbeIsForeign = generatorProbeIsForeign
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// ---------------------------------------------------------------------------
// The scrub command
// ---------------------------------------------------------------------------

const scrub = Model.scrubCommand()

check("the scrub command prints nothing",
  scrub.length === 3 && scrub[0] === "bash" && scrub[1] === "-c" && scrub[2] === "",
  `got ${JSON.stringify(scrub)}`)

check("a fresh array each time, so one process cannot alias another's",
  Model.scrubCommand() !== Model.scrubCommand(),
  "scrubCommand() returned the same array twice")

check("mutating what a caller was given does not change the next one",
  (() => { const c = Model.scrubCommand(); c[2] = "rm -rf /"; return Model.scrubCommand()[2] === "" })(),
  "the shared array leaked")

check("the scrub command is recognised as one",
  Model.isScrubCommand(Model.scrubCommand()) === true, "not recognised")

check("a real bw command is not",
  Model.isScrubCommand(["bw", "list", "items"]) === false, "bw list read as a scrub")

check("nor is a command that merely starts the same way",
  Model.isScrubCommand(["bash", "-c", "bw list items"]) === false, "a bash command read as a scrub")

check("nor a shorter one",
  Model.isScrubCommand(["bash", "-c"]) === false, "a truncated command read as a scrub")

check("nor a longer one",
  Model.isScrubCommand(["bash", "-c", "", "extra"]) === false, "a padded command read as a scrub")

// A Process that has never run reports an empty command, and one that is
// missing entirely is what a typo in the process list looks like. Neither is a
// scrub, and neither may throw: this runs inside a signal handler.
check("an empty command is not a scrub", Model.isScrubCommand([]) === false, "empty read as a scrub")
check("an absent command is not a scrub", Model.isScrubCommand(null) === false, "null read as a scrub")
check("an undefined command is not a scrub",
  Model.isScrubCommand(undefined) === false, "undefined read as a scrub")

// QML hands JS a QStringList, whose members arrive as strings but whose
// identity is not a plain Array.
check("a list-like command is read the same as an array",
  Model.isScrubCommand({ length: 3, 0: "bash", 1: "-c", 2: "" }) === true,
  "a QStringList-shaped command was not recognised")

// ---------------------------------------------------------------------------
// One pass over the queue
// ---------------------------------------------------------------------------

const idle = (cmd) => ({ running: false, command: cmd })
const busy = (cmd) => ({ running: true, command: cmd })

{
  const p = Model.scrubPass([idle(["bw", "list", "items"])])
  check("an idle process with a real command is scrubbed now",
    p.start.length === 1, `start=${p.start.length}`)
  check("and is asked about again, to confirm the scrub finished",
    p.waiting.length === 1, `waiting=${p.waiting.length}`)
}

{
  const p = Model.scrubPass([busy(["bw", "list", "items"])])
  check("a process still reading is not scrubbed out from under itself",
    p.start.length === 0, `start=${p.start.length}`)
  check("but stays in the queue for the next pass",
    p.waiting.length === 1, `waiting=${p.waiting.length}`)
}

{
  const p = Model.scrubPass([idle(Model.scrubCommand())])
  check("a process already scrubbed is left alone",
    p.start.length === 0, `start=${p.start.length}`)
  check("and drops out of the queue",
    p.waiting.length === 0, `waiting=${p.waiting.length}`)
}

{
  // The scrub itself is still running on the pass right after it was started.
  const p = Model.scrubPass([busy(Model.scrubCommand())])
  check("a scrub in flight is waited on rather than started again",
    p.start.length === 0 && p.waiting.length === 1,
    `start=${p.start.length} waiting=${p.waiting.length}`)
}

{
  const running = busy(["bw", "get", "item", "x"])
  const p = Model.scrubPass([idle(["bw", "list", "items"]), running, idle(Model.scrubCommand())])
  check("a mixed queue starts only what it can",
    p.start.length === 1, `start=${p.start.length}`)
  check("and carries the rest that is not finished",
    p.waiting.length === 2 && p.waiting.indexOf(running) !== -1,
    `waiting=${p.waiting.length}`)
}

check("an empty queue is a no-op",
  Model.scrubPass([]).start.length === 0 && Model.scrubPass([]).waiting.length === 0,
  "empty queue did something")

check("and so is a missing one",
  Model.scrubPass(null).waiting.length === 0, "null queue threw or produced work")

check("a hole in the process list is skipped rather than thrown on",
  Model.scrubPass([null, idle(["bw", "sync"])]).start.length === 1,
  "a null entry stopped the pass")

// The retry exists for processes that were mid-read; it has to give up rather
// than poll for the rest of the session.
check("the retry is spaced in seconds, not milliseconds",
  Model.scrubRetryMs() >= 250, `retry every ${Model.scrubRetryMs()}ms`)
check("and gives up eventually",
  Model.scrubRetryLimit() > 0 && Model.scrubRetryLimit() * Model.scrubRetryMs() <= 10 * 60 * 1000,
  `limit ${Model.scrubRetryLimit()} ticks of ${Model.scrubRetryMs()}ms`)

// ---------------------------------------------------------------------------
// Generator request bounds
// ---------------------------------------------------------------------------

const cap = Model.generatorResponseCap()

check("the response cap is far above a generated password",
  cap >= 4096, `cap is ${cap} bytes`)
check("and far below anything that would hurt to hold",
  cap <= 1024 * 1024, `cap is ${cap} bytes`)
check("the request deadline is short enough to be a loopback deadline",
  Model.generatorRequestTimeoutMs() > 0 && Model.generatorRequestTimeoutMs() <= 10000,
  `deadline is ${Model.generatorRequestTimeoutMs()}ms`)

check("a real answer is under the cap",
  Model.generatorResponseTooLarge("67", 67) === false, "a 67-byte answer was refused")

check("a declared length past the cap is refused before the body arrives",
  Model.generatorResponseTooLarge(String(cap + 1), 0) === true,
  "an oversized Content-Length was accepted")

check("a body past the cap is refused however much was declared",
  Model.generatorResponseTooLarge("10", cap + 1) === true,
  "an oversized body was accepted")

check("a chunked response declares nothing and is judged on what arrives",
  Model.generatorResponseTooLarge("", 12) === false && Model.generatorResponseTooLarge("", cap + 1) === true,
  "the chunked case was misjudged")

check("an absent Content-Length is not read as an enormous one",
  Model.generatorResponseTooLarge(null, 12) === false, "a missing header refused a small body")

check("nor is a garbage one",
  Model.generatorResponseTooLarge("not-a-number", 12) === false, "an unparseable header refused a small body")

// The port check, once a request can be cut short. status 0 is both "nothing
// answered" and "we hung up", and only the first of those leaves the port free.
check("a refused connection leaves the port free",
  Model.generatorProbeIsForeign(0, false) === false, "a refused connection read as occupied")

check("any HTTP answer means someone is already bound",
  Model.generatorProbeIsForeign(200, false) === true && Model.generatorProbeIsForeign(404, false) === true,
  "an HTTP answer read as a free port")

check("a request we had to cut short means someone is already bound",
  Model.generatorProbeIsForeign(0, true) === true,
  "an aborted probe read as a free port -- a stalling squatter would get our trust")

check("even one that answered before stalling",
  Model.generatorProbeIsForeign(200, true) === true, "an aborted probe read as free")

// ---------------------------------------------------------------------------

if (failures.length) {
  console.error(`\n${failures.length} failure(s):\n`)
  failures.forEach((f) => console.error(`  ✗ ${f}\n`))
  process.exit(1)
}
console.log(`buffer-scrub: ${pass} checks passed`)
