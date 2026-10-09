// bw-login-code.js -- preloaded into `bw` through NODE_OPTIONS (bwNodeOptions()
// in BitwardenModel.js) so the two-step login code never reaches an argv.
//
// bw takes the code only from --code, and /proc/<pid>/cmdline is readable by
// every local user. So the login command carries a placeholder flag instead,
// and this swaps it for --code=<QSBW_CODE> in bw's own process.argv before bw
// parses it. That copy lives in Node's heap; the kernel's cmdline still shows
// the placeholder.
//
// Fails closed: if this does not run (a standalone bw ignores NODE_OPTIONS) or
// has no code, the placeholder stays and bw rejects it as an unknown option
// before it contacts the server. loginCodeChannelMissing() detects that.

"use strict"

;(function () {
  var FLAG = "--qsbw-code-from-env"
  var ENV = "QSBW_CODE"

  var at = process.argv.indexOf(FLAG, 2)
  if (at === -1) return
  var entry = ""
  try {
    entry = require("fs").realpathSync(process.argv[1] || "")
  } catch (e) {
    return
  }
  if (!/[\\/]@bitwarden[\\/]cli[\\/]build[\\/]bw\.js$/.test(entry)) return
  if (process.argv[2] !== "login") return

  var code = process.env[ENV]
  // Nothing bw starts needs it.
  delete process.env[ENV]
  if (typeof code !== "string" || code === "") return
  // One element, so a value starting with "-" cannot be read as an option.
  process.argv.splice(at, 1, "--code=" + code)
})()
