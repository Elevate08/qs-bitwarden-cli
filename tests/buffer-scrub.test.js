#!/usr/bin/env node
// What a lock must not leave behind:
//
//   node tests/buffer-scrub.test.js
//
//  1. Collector buffers: emptied by re-running each process with a command
//     that prints nothing; checks the command, how handlers recognise it, and
//     which processes a pass touches.
//  2. Generator requests to the first-come loopback port are bounded
//     (lifecycle in generator.test.js).

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")

const panelSource = readPluginSource("Panel.qml")
const panelBodyOf = name => functionBody(panelSource, name)

const Model = loadModule()

const { check, done } = createSuite("buffer-scrub")

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

// The retry exists for processes that were mid-read. It must keep the process
// queued until the empty scrub run finishes, even if a completion handler
// immediately reuses that same Process for another command.
check("the retry is spaced in seconds, not milliseconds",
  Model.scrubRetryMs() >= 250, `retry every ${Model.scrubRetryMs()}ms`)
check("the retry never abandons a collector that is still being written",
  /if\s*\(!root\.scrubPending\.length\)\s*stop\(\)/.test(panelSource)
    && !/scrubRetryLimit/.test(panelSource),
  "the scrub timer can stop with a process still in its queue")

{
  const late = busy(["bw", "unlock"])
  let p = Model.scrubPass([late])
  late.running = false
  p = Model.scrubPass(p.waiting)
  late.command = Model.scrubCommand()
  late.running = false
  const queue = Model.finishScrub(p.waiting, late)

  // unlockProc does this from its scrub completion handler: the collector is
  // clean, then prewarming immediately reuses the Process. Queue completion
  // must not depend on observing its command afterward.
  late.command = ["bw", "unlock", "--passwordfile", "fifo"]
  late.running = true
  check("a completed scrub drains before its Process is immediately reused",
    p.start.length === 1 && queue.length === 0,
    `started=${p.start.length} remaining=${queue.length}`)
}

check("Panel completion handlers dequeue scrubbed processes explicitly",
  /function\s+finishScrubRun\s*\(proc\)/.test(panelSource)
    && /scrubPending\s*=\s*Model\.finishScrub\(scrubPending,\s*proc\)/.test(panelSource),
  "Panel does not record scrub completion independently of Process reuse")

check("a one-shot password copy scrubs its collector immediately after use",
  /clearProcessCollectorSoon\(copyPasswordProc\)/.test(panelBodyOf("onPasswordCopyFinished")),
  panelBodyOf("onPasswordCopyFinished"))
check("a TOTP read also scrubs its collector after copying the value into active state",
  /continueTotpQueue\(false\)/.test(panelBodyOf("onTotpProcessExited"))
    && /!collectorIsClean[\s\S]*clearProcessCollectorSoon\(getTotpProc\)/.test(
      panelBodyOf("continueTotpQueue")),
  panelBodyOf("onTotpProcessExited") + "\n" + panelBodyOf("continueTotpQueue"))
const totpProcBlock = panelSource.slice(panelSource.indexOf("id: getTotpProc"),
  panelSource.indexOf("id: copyPasswordProc"))
const totpScrubCheck = totpProcBlock.indexOf("finishScrubRun(getTotpProc)")
const totpScrubResume = totpProcBlock.indexOf("continueTotpQueue(true)")
const totpScrubReturn = totpProcBlock.indexOf("return", totpScrubResume)
const totpNormalExit = totpProcBlock.indexOf("onTotpProcessExited")
check("a TOTP scrub exits without recursively scheduling another scrub",
  totpScrubCheck !== -1 && totpScrubCheck < totpScrubResume
    && totpScrubResume < totpScrubReturn && totpScrubReturn < totpNormalExit,
  totpProcBlock)
check("a queued real TOTP request replaces the collector instead of racing an empty scrub",
  /if\s*\(queued\)[\s\S]*startTotpFetch\(queued\)[\s\S]*!collectorIsClean[\s\S]*clearProcessCollectorSoon\(getTotpProc\)/.test(
    panelBodyOf("continueTotpQueue")),
  panelBodyOf("continueTotpQueue"))
check("a request queued during a TOTP scrub is resumed after that scrub exits",
  /getTotpProc\.running[\s\S]*totpQueuedItemId\s*=/.test(panelBodyOf("fetchTotp"))
    && /finishScrubRun\(getTotpProc\)[\s\S]*continueTotpQueue\(true\)/.test(totpProcBlock),
  panelBodyOf("fetchTotp") + "\n" + totpProcBlock)
check("the deferred TOTP restart reserves the Process against a newer direct start",
  /getTotpProc\.running\s*\|\|\s*totpRestartPending/.test(panelBodyOf("fetchTotp"))
    && /totpRestartPending\s*=\s*true[\s\S]*totpRequestItemId\s*=\s*queued[\s\S]*Qt\.callLater/.test(
      panelBodyOf("continueTotpQueue"))
    && /totpRestartPending\s*=\s*false/.test(panelBodyOf("dropVaultSecrets")),
  panelBodyOf("fetchTotp") + "\n" + panelBodyOf("continueTotpQueue"))

// ---------------------------------------------------------------------------
// Generator request bounds
// ---------------------------------------------------------------------------

const cap = Model.GENERATE_RESPONSE_CAP

check("the response cap is far above a generated password",
  cap >= 4096, `cap is ${cap} bytes`)
check("and far below anything that would hurt to hold",
  cap <= 1024 * 1024, `cap is ${cap} bytes`)
check("the request deadline is short enough to be a loopback deadline",
  Model.GENERATE_REQUEST_TIMEOUT_MS > 0 && Model.GENERATE_REQUEST_TIMEOUT_MS <= 10000,
  `deadline is ${Model.GENERATE_REQUEST_TIMEOUT_MS}ms`)

// Process-based probe checks (curl exit codes)
check("curl CURLE_COULDNT_CONNECT (exit 7) with empty stdout indicates a free port",
  Model.generatorProbeIsForeign(7, "") === false, "curl exit 7 was read as occupied")

check("curl exit 0 with HTTP response indicates an occupied port",
  Model.generatorProbeIsForeign(0, '{"success":true}') === true, "curl exit 0 was read as free")

check("curl timeout (exit 28) indicates an occupied (stalling) port",
  Model.generatorProbeIsForeign(28, "") === true, "curl timeout was read as free")

check("curl write error / truncation (exit 23) indicates an occupied (flooding) port",
  Model.generatorProbeIsForeign(23, "") === true, "curl exit 23 was read as free")

// Producer-side bounding of generateServeRequestCommand
const serveReqCmd = Model.generateServeRequestCommand({ length: 16 })
check("generateServeRequestCommand uses curl with timeout and head -c byte cap",
  serveReqCmd[2].includes("curl -q -s -S") && serveReqCmd[2].includes("--max-time 2") && serveReqCmd[2].includes(`head -c ${cap}`),
  serveReqCmd[2])

// ---------------------------------------------------------------------------

done()
