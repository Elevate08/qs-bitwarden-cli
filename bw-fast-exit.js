// bw-fast-exit.js -- preloaded into `bw` through NODE_OPTIONS (bwNodeOptions()
// in BitwardenModel.js) so it exits as soon as it has answered.
//
// The CLI prints its result and records process.exitCode, then idles about
// 2 s while rxjs timers drain before Node exits; every caller waits on that
// exit. Once the exit code is set the command is done (its storage writes are
// synchronous), so this flushes stdout and exits with that code.
//
// NODE_OPTIONS reaches every process in a pipeline, including the `node -e`
// validators, so it acts only inside the Bitwarden CLI's own entry point, and
// never in `bw serve`, which runs until stopped.

"use strict"

;(function () {
  var entry = ""
  try {
    entry = require("fs").realpathSync(process.argv[1] || "")
  } catch (e) {
    return
  }
  if (!/[\\/]@bitwarden[\\/]cli[\\/]build[\\/]bw\.js$/.test(entry)) return

  var args = process.argv.slice(2)
  for (var i = 0; i < args.length; i++) {
    if (args[i].charAt(0) === "-") continue
    if (args[i] === "serve") return
    break
  }

  var poll = setInterval(function () {
    if (process.exitCode === undefined) return
    clearInterval(poll)
    var code = process.exitCode
    process.stdout.write("", function () { process.exit(code) })
  }, 10)
  // Never what keeps bw alive.
  poll.unref()
})()
