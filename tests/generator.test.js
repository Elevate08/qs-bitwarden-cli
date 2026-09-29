#!/usr/bin/env node
// Generator options: never hand `bw generate` a combination it rejects.
//
//   node tests/generator.test.js

const { createSuite, functionBody, loadModule, readPluginSource } = require("./harness")
const panelSrc = readPluginSource("Panel.qml")
const bodyOf = name => functionBody(panelSrc, name)
const Model = loadModule()

const { check, done } = createSuite("generator")
// Checks that need a live server finish before the report.
const asyncChecks = []
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
// `bw serve` URLs, verified against a live locked `bw serve`.

const url = (o) => Model.generateServeUrl(o)

check("requests name the generate endpoint, with no port to reach from elsewhere",
  url({}).startsWith("http://localhost/generate?"), url({}))
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

// A loopback port let every local user POST /unlock (guessing the master
// password with no second factor or lockout) and read /status (the email and
// user id). The server now listens on a socket in the private runtime
// directory, and still holds no session.
const serveCmd = Model.generateServeCommand()
check("the server listens on a socket in the private runtime directory, on no port",
  serveCmd[0] === "bash" && /exec bw serve --hostname "unix:\/\/\$__gen_sock"$/.test(serveCmd[2])
    && serveCmd[2].includes("$XDG_RUNTIME_DIR/qs-bitwarden-cli") && serveCmd[2].includes("generator.sock")
    && serveCmd[2].includes("chmod 700") && !/--port|127\.0\.0\.1|8087/.test(serveCmd[2]),
  serveCmd[2])
const serveEnv = functionBody(panelSrc, "generatorServeEnv")
check("the server's environment carries no session",
  /env\[Model\.sessionEnvVar\(\)\]\s*=\s*null/.test(serveEnv), serveEnv)

const serveReq = Model.generateServeRequestCommand({ length: 20, special: true })
check("the serve request command targets the socket with timeout and stream cap",
  serveReq[2].includes("curl -q -s -S") && serveReq[2].includes('--unix-socket "$__gen_sock"')
    && serveReq[2].includes("http://localhost/generate")
    && serveReq[2].includes("--max-time 2") && serveReq[2].includes("head -c 65536"),
  serveReq[2])
check("generator requests ignore proxy variables and curl config",
  serveReq[2].includes("curl -q ") && serveReq[2].includes("--noproxy '*'"), serveReq[2])

// Run for real against a throwaway runtime directory and a stand-in server,
// so the path, the probe and the private directory are what the code uses.
{
  const os = require("os")
  const fs = require("fs")
  const path = require("path")
  const http = require("http")
  const { execFile, execFileSync } = require("child_process")
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-gen-"))
  const env = Object.assign({}, process.env, { XDG_RUNTIME_DIR: runtime })
  const request = () => new Promise(resolve => {
    const cmd = Model.generateServeRequestCommand({ length: 12 })
    execFile(cmd[0], cmd.slice(1), { env, encoding: "utf8" }, (err, stdout) =>
      resolve({ code: err ? err.code : 0, stdout }))
  })
  const pending = (async () => {
    const free = await request()
    check("no runtime directory yet reads as a free socket (curl's 7)",
      Model.generatorProbeIsForeign(free.code, free.stdout) === false, JSON.stringify(free))

    // The serve command's own preparation, with bw swapped for a no-op, makes
    // the directory private and clears a stale socket file.
    const dir = path.join(runtime, "qs-bitwarden-cli")
    fs.mkdirSync(dir, { mode: 0o755 })
    fs.writeFileSync(path.join(dir, "generator.sock"), "stale")
    const prep = serveCmd[2].replace(/exec bw serve .*$/, "exit 0")
    execFileSync("bash", ["-c", prep], { env })
    check("starting the server narrows the directory to 0700 and removes a stale socket",
      (fs.statSync(dir).mode & 0o777) === 0o700 && !fs.existsSync(path.join(dir, "generator.sock")),
      (fs.statSync(dir).mode & 0o777).toString(8))

    const server = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json")
      res.end(JSON.stringify({ success: true, data: { object: "string", data: "from-the-socket " + req.url } }))
    })
    await new Promise(resolve => server.listen(path.join(dir, "generator.sock"), resolve))
    try {
      const answered = await request()
      check("a request reaches the server on the socket",
        answered.code === 0 && Model.parseServeGenerated(answered.stdout).startsWith("from-the-socket /generate?"),
        JSON.stringify(answered))
      check("a server already on the socket is not taken for a free one",
        Model.generatorProbeIsForeign(answered.code, answered.stdout) === true, JSON.stringify(answered))
    } finally {
      await new Promise(resolve => server.close(resolve))
    }
  })()
  pending.finally(() => fs.rmSync(runtime, { recursive: true, force: true }))
  asyncChecks.push(pending)
}

check("a successful response yields the value",
  Model.parseServeGenerated('{"success":true,"data":{"object":"string","data":"abc123"}}') === "abc123",
  Model.parseServeGenerated('{"success":true,"data":{"object":"string","data":"abc123"}}'))
check("a failed response yields nothing, so the caller falls back",
  Model.parseServeGenerated('{"success":false,"message":"locked"}') === "", "expected empty")
check("garbage yields nothing rather than throwing",
  Model.parseServeGenerated("<html>not json</html>") === "", "expected empty")
check("an empty body yields nothing", Model.parseServeGenerated("") === "", "expected empty")


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

Promise.all(asyncChecks).then(done, error => { console.error(error); process.exit(1) })
