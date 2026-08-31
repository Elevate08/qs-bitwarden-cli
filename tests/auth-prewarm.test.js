#!/usr/bin/env node
// Regression coverage for password-FIFO auth prewarming. The expensive bw
// process must be alive before the password is submitted, while the password
// itself stays out of argv and is written only after the user submits.
//
//   node tests/auth-prewarm.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync } = require("child_process")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.unlockPrewarmCommand = typeof unlockPrewarmCommand === "function" ? unlockPrewarmCommand : null
  exports.emailLoginPrewarmCommand = typeof emailLoginPrewarmCommand === "function" ? emailLoginPrewarmCommand : null
  exports.apiKeyLoginCommand = typeof apiKeyLoginCommand === "function" ? apiKeyLoginCommand : null
  exports.authPasswordWriteCommand = typeof authPasswordWriteCommand === "function" ? authPasswordWriteCommand : null
  exports.passwordEnvVar = passwordEnvVar
`)(Model)

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const flat = command => (command || []).join(" ")

check("the model exposes the three prewarming commands",
  !!Model.unlockPrewarmCommand && !!Model.emailLoginPrewarmCommand && !!Model.authPasswordWriteCommand,
  "unlock, email login and writer commands are required")

if (Model.unlockPrewarmCommand && Model.emailLoginPrewarmCommand && Model.authPasswordWriteCommand) {
  const unlock = Model.unlockPrewarmCommand()
  const email = Model.emailLoginPrewarmCommand("person@example.com", false, "")
  const email2fa = Model.emailLoginPrewarmCommand("person@example.com", true, "https://vault.example.com")
  const writer = Model.authPasswordWriteCommand("unlock")
  const distinctive = "  exact master password with spaces  "

  check("prewarmed unlock makes bw itself wait on a password FIFO",
    /bw unlock .*--passwordfile/.test(flat(unlock)) && !flat(unlock).includes("--passwordenv"), flat(unlock))
  check("prewarmed email login makes bw itself wait on a password FIFO",
    /bw login .*--passwordfile/.test(flat(email)) && !flat(email).includes("--passwordenv"), flat(email))
  check("email and server inputs remain shell-quoted",
    flat(email2fa).includes("'person@example.com'")
      && flat(email2fa).includes("'https://vault.example.com'"), flat(email2fa))
  check("2FA still expands from its environment binding",
    flat(email2fa).includes('--code "$QSBW_CODE"'), flat(email2fa))
  check("the writer reads the password from the existing protected environment binding",
    flat(writer).includes('"$' + Model.passwordEnvVar() + '"'), flat(writer))
  check("neither half embeds a password in its command",
    !flat(unlock).includes(distinctive) && !flat(writer).includes(distinctive), flat(unlock) + "\n" + flat(writer))
  check("an unknown FIFO name is rejected instead of becoming a path",
    Model.authPasswordWriteCommand("../elsewhere").length === 0,
    flat(Model.authPasswordWriteCommand("../elsewhere")))
  check("a normally completed child is disarmed before the EXIT cleanup trap runs",
    /wait "\$__auth_job"; __auth_rc=\$\?; __auth_job=''; exit "\$__auth_rc"/.test(flat(unlock)),
    flat(unlock))

  // Exercise the real command pair against a fake bw. The fake announces that
  // it has started, then blocks while reading the FIFO. Only after observing
  // that announcement do we launch the writer. Leading and trailing spaces
  // prove the panel cannot normalize a real master password along the way.
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-prewarm-"))
  const bin = path.join(temp, "bin")
  const runtime = path.join(temp, "runtime")
  fs.mkdirSync(bin)
  fs.mkdirSync(runtime, { mode: 0o700 })
  const started = path.join(temp, "started")
  const received = path.join(temp, "received")
  const output = path.join(temp, "output")
  const error = path.join(temp, "error")
  const token = "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk9PQ=="

  fs.writeFileSync(path.join(bin, "bw"), `#!/usr/bin/env bash
set -u
password_file=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--passwordfile" ]; then password_file="$2"; shift 2; else shift; fi
done
printf started > "$QSBW_STUB_STARTED"
[ -n "$password_file" ] || exit 9
IFS= read -r password < "$password_file" || true
printf '%s' "$password" > "$QSBW_STUB_RECEIVED"
printf '%s' "$QSBW_STUB_TOKEN"
`)
  fs.chmodSync(path.join(bin, "bw"), 0o755)

  try {
    execFileSync("bash", ["-c", `
set -euo pipefail
bash -c "$QSBW_PREWARM_SCRIPT" >"$QSBW_OUTPUT" 2>"$QSBW_ERROR" &
auth_pid=$!
started=false
for unused in {1..200}; do
  if [ -s "$QSBW_STUB_STARTED" ]; then started=true; break; fi
  sleep 0.01
done
[ "$started" = true ]
bash -c "$QSBW_WRITER_SCRIPT"
wait "$auth_pid"
`], {
      env: Object.assign({}, process.env, {
        PATH: `${bin}:${process.env.PATH}`,
        XDG_RUNTIME_DIR: runtime,
        BW_PASSWORD: distinctive,
        QSBW_PREWARM_SCRIPT: unlock[2],
        QSBW_WRITER_SCRIPT: writer[2],
        QSBW_STUB_STARTED: started,
        QSBW_STUB_RECEIVED: received,
        QSBW_STUB_TOKEN: token,
        QSBW_OUTPUT: output,
        QSBW_ERROR: error,
      }),
      stdio: ["ignore", "pipe", "pipe"],
    })
    check("bw starts before the writer supplies the password", fs.readFileSync(started, "utf8") === "started", "no start marker")
    check("the FIFO preserves the exact password bytes", fs.readFileSync(received, "utf8") === distinctive,
      JSON.stringify(fs.readFileSync(received, "utf8")))
    check("the prewarmed command still returns the session token", fs.readFileSync(output, "utf8") === token,
      fs.readFileSync(output, "utf8"))
    const fifo = path.join(runtime, "qs-bitwarden-cli", "unlock-password.fifo")
    check("the password FIFO is removed when auth finishes", !fs.existsSync(fifo), fifo)
  } catch (errorCaught) {
    failures.push(`the prewarm command pair completes successfully\n    ${errorCaught.stderr || errorCaught.message}`)
  } finally {
    fs.rmSync(temp, { recursive: true, force: true })
  }

  // QML stops a Process by sending SIGTERM to its immediate child. A shell
  // waiting for a foreground FIFO reader can defer that signal until the
  // reader exits, which would strand both after the panel closes. Exercise
  // cancellation separately and require the wrapper, its bw child and the
  // FIFO to disappear promptly.
  const cancelTemp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-prewarm-cancel-"))
  const cancelBin = path.join(cancelTemp, "bin")
  const cancelRuntime = path.join(cancelTemp, "runtime")
  fs.mkdirSync(cancelBin)
  fs.mkdirSync(cancelRuntime, { mode: 0o700 })
  const childPid = path.join(cancelTemp, "child-pid")
  fs.writeFileSync(path.join(cancelBin, "bw"), `#!/usr/bin/env bash
printf '%s' "$$" > "$QSBW_STUB_CHILD_PID"
password_file=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--passwordfile" ]; then password_file="$2"; shift 2; else shift; fi
done
[ -n "$password_file" ] || exit 9
IFS= read -r unused < "$password_file" || true
`)
  fs.chmodSync(path.join(cancelBin, "bw"), 0o755)

  try {
    const result = execFileSync("bash", ["-c", `
set -u
bash -c "$QSBW_PREWARM_SCRIPT" >"$QSBW_CANCEL_OUTPUT" 2>"$QSBW_CANCEL_ERROR" &
auth_pid=$!
for unused in {1..200}; do [ -s "$QSBW_STUB_CHILD_PID" ] && break; sleep 0.01; done
[ -s "$QSBW_STUB_CHILD_PID" ] || exit 8
bw_pid=$(cat "$QSBW_STUB_CHILD_PID")
kill -TERM "$auth_pid"
parent_stopped=no
for unused in {1..200}; do
  if ! kill -0 "$auth_pid" 2>/dev/null; then parent_stopped=yes; break; fi
  sleep 0.01
done
if [ "$parent_stopped" = no ]; then kill -KILL "$auth_pid" 2>/dev/null || true; fi
wait "$auth_pid" 2>/dev/null || true
child_stopped=no
for unused in {1..200}; do
  if ! kill -0 "$bw_pid" 2>/dev/null; then child_stopped=yes; break; fi
  sleep 0.01
done
if [ "$child_stopped" = no ]; then kill -KILL "$bw_pid" 2>/dev/null || true; fi
fifo_gone=no
[ ! -e "$XDG_RUNTIME_DIR/qs-bitwarden-cli/unlock-password.fifo" ] && fifo_gone=yes
printf '%s %s %s' "$parent_stopped" "$child_stopped" "$fifo_gone"
`], {
      env: Object.assign({}, process.env, {
        PATH: `${cancelBin}:${process.env.PATH}`,
        XDG_RUNTIME_DIR: cancelRuntime,
        QSBW_PREWARM_SCRIPT: unlock[2],
        QSBW_STUB_CHILD_PID: childPid,
        QSBW_CANCEL_OUTPUT: path.join(cancelTemp, "output"),
        QSBW_CANCEL_ERROR: path.join(cancelTemp, "error"),
      }),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    })
    check("cancelling prewarm stops the wrapper and bw child and removes the FIFO",
      result === "yes yes yes", result)
  } catch (errorCaught) {
    failures.push(`cancelling prewarm completes cleanly\n    ${errorCaught.stderr || errorCaught.message}`)
  } finally {
    fs.rmSync(cancelTemp, { recursive: true, force: true })
  }
}

// API-key login does not use a password FIFO, but it still runs through the
// same cancellable Process. Stopping that Process must terminate the active bw
// child rather than orphaning an authentication attempt behind the panel.
if (Model.apiKeyLoginCommand) {
  const cancelTemp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-apikey-cancel-"))
  const cancelBin = path.join(cancelTemp, "bin")
  fs.mkdirSync(cancelBin)
  const childPid = path.join(cancelTemp, "child-pid")
  fs.writeFileSync(path.join(cancelBin, "bw"), `#!/usr/bin/env bash
printf '%s' "$$" > "$QSBW_STUB_CHILD_PID"
sleep 30
`)
  fs.chmodSync(path.join(cancelBin, "bw"), 0o755)

  try {
    const result = execFileSync("bash", ["-c", `
set -u
bash -c "$QSBW_APIKEY_SCRIPT" >/dev/null 2>&1 &
auth_pid=$!
for unused in {1..200}; do [ -s "$QSBW_STUB_CHILD_PID" ] && break; sleep 0.01; done
[ -s "$QSBW_STUB_CHILD_PID" ] || exit 8
bw_pid=$(cat "$QSBW_STUB_CHILD_PID")
kill -TERM "$auth_pid"
parent_stopped=no
for unused in {1..200}; do
  if ! kill -0 "$auth_pid" 2>/dev/null; then parent_stopped=yes; break; fi
  sleep 0.01
done
if [ "$parent_stopped" = no ]; then kill -KILL "$auth_pid" 2>/dev/null || true; fi
wait "$auth_pid" 2>/dev/null || true
child_stopped=no
for unused in {1..200}; do
  if ! kill -0 "$bw_pid" 2>/dev/null; then child_stopped=yes; break; fi
  sleep 0.01
done
if [ "$child_stopped" = no ]; then kill -KILL "$bw_pid" 2>/dev/null || true; fi
printf '%s %s' "$parent_stopped" "$child_stopped"
`], {
      env: Object.assign({}, process.env, {
        PATH: `${cancelBin}:${process.env.PATH}`,
        QSBW_APIKEY_SCRIPT: Model.apiKeyLoginCommand("")[2],
        QSBW_STUB_CHILD_PID: childPid,
      }),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    })
    check("cancelling API-key login stops the wrapper and active bw child",
      result === "yes yes", result)
  } catch (errorCaught) {
    failures.push(`cancelling API-key login completes cleanly\n    ${errorCaught.stderr || errorCaught.message}`)
  } finally {
    fs.rmSync(cancelTemp, { recursive: true, force: true })
  }
}

// The QML lifecycle is part of the security boundary: start early, write only
// on submit, and stop a waiting process when the panel closes.
const panelSrc = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const bodyOf = name => {
  const start = panelSrc.indexOf(`function ${name}(`)
  if (start === -1) return ""
  let depth = 0
  for (let i = panelSrc.indexOf("{", start); i < panelSrc.length; i++) {
    if (panelSrc[i] === "{") depth++
    else if (panelSrc[i] === "}" && --depth === 0) return panelSrc.slice(start, i + 1)
  }
  return ""
}

check("opening an already-locked panel starts unlock prewarming",
  /prepareUnlock\(\)/.test(bodyOf("onPanelOpened")), bodyOf("onPanelOpened"))
check("submitting unlock writes to the prepared FIFO",
  /writeAuthPassword\("unlock",\s*p\)/.test(bodyOf("unlockVaultWithPassword")), bodyOf("unlockVaultWithPassword"))
check("closing the panel cancels auth prewarming",
  /cancelAuthPrewarm/.test(bodyOf("close")), bodyOf("close"))
check("an unreadable status result cancels a prewarm that can no longer be used",
  /if\s*\(!st\)\s*\{\s*cancelAuthPrewarm\(\)/.test(bodyOf("onStatusFinished")),
  bodyOf("onStatusFinished"))
check("an externally unlocked status cancels the obsolete locked-state prewarm",
  /if\s*\(st\.unlocked\)\s*\{\s*cancelAuthPrewarm\(\)/.test(bodyOf("onStatusFinished")),
  bodyOf("onStatusFinished"))
check("master-password validation preserves whitespace",
  /var p\s*=\s*String\(/.test(bodyOf("unlockVaultWithPassword"))
    && !/var p\s*=\s*String\([^\n]+\.trim\(\)/.test(bodyOf("unlockVaultWithPassword")),
  bodyOf("unlockVaultWithPassword"))
check("focusing the email-login password field prepares login",
  /id:\s*loginPassField[\s\S]{0,700}onActiveFocusChanged:[\s\S]{0,160}prepareEmailLogin/.test(panelSrc),
  "loginPassField has no prewarm focus handler")
const prepareEmail = bodyOf("prepareEmailLogin")
check("a custom server is not configured by focus-only prewarming",
  /String\(loginServerUrl\s*\|\|\s*""\)\.trim\(\)[\s\S]{0,80}return/.test(prepareEmail)
    && prepareEmail.indexOf("String(loginServerUrl") < prepareEmail.indexOf("loginProc.command"),
  prepareEmail)
check("submitting while an obsolete login prewarm stops queues a clean restart",
  /loginSubmitAfterPrewarmStop\s*=\s*true/.test(bodyOf("submitLogin"))
    && /loginProc\.running\s*=\s*false/.test(bodyOf("submitLogin")),
  bodyOf("submitLogin"))
const loginProcBlock = panelSrc.slice(panelSrc.indexOf("id: loginProc"), panelSrc.indexOf("id: authPasswordWriterProc"))
// The dispatch lives in resumeDeferredLogin() so both ways the process can end
// -- its own exit, and the buffer scrub that may follow it -- go through it.
// A scrub that returned early used to drop the queued login silently.
const resumeDeferredBlock = bodyOf("resumeDeferredLogin")
check("the obsolete prewarm exit starts the queued login instead of consuming its result",
  /loginSubmitAfterPrewarmStop[\s\S]*submitLogin/.test(resumeDeferredBlock)
    && /resumeDeferredLogin\(true\)/.test(loginProcBlock),
  resumeDeferredBlock)
check("a queued login survives the buffer scrub taking the process first",
  /finishScrubRun\(loginProc\)\)\s*\{[\s\S]{0,140}resumeDeferredLogin\(false\)/.test(loginProcBlock),
  loginProcBlock)
check("focusing during prewarm shutdown queues another prewarm",
  /loginPrepareAfterPrewarmStop\s*=\s*true/.test(bodyOf("prepareEmailLogin")),
  bodyOf("prepareEmailLogin"))
check("the stopped process services a queued prewarm when no submit is waiting",
  /loginPrepareAfterPrewarmStop[\s\S]*prepareEmailLogin/.test(resumeDeferredBlock),
  resumeDeferredBlock)
check("a cancelled login with no queued restart scrubs any token that won the exit race",
  /else if \(mayScrub\) \{\s*\n\s*clearProcessCollectorSoon\(loginProc\)/.test(resumeDeferredBlock),
  resumeDeferredBlock)
// The scrub is the fallback, so a queued restart must be preferred to it --
// otherwise the restart is what gets dropped.
check("a queued restart is dispatched in preference to the scrub",
  resumeDeferredBlock.indexOf("loginSubmitAfterPrewarmStop")
    < resumeDeferredBlock.indexOf("clearProcessCollectorSoon"),
  resumeDeferredBlock)
const unlockProcBlock = panelSrc.slice(panelSrc.indexOf("id: unlockProc"), panelSrc.indexOf("id: logoutProc"))
check("a cancelled unlock scrubs any token that won the exit race",
  /!root\.unlockSubmitted[\s\S]{0,120}clearProcessCollectorSoon\(unlockProc\)/.test(unlockProcBlock),
  unlockProcBlock)

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.error("\nFAILURES:\n  " + failures.join("\n  "))
  process.exit(1)
}
