#!/usr/bin/env node
// bw-login-code.js, the NODE_OPTIONS preload that hands bw the two-step code:
// the code must reach bw's parsed argv and never the kernel's copy, which
// /proc/<pid>/cmdline shows every local user. Anything else fails closed.
//
//   node tests/bw-login-code.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const { createSuite, loadModule, read, repoRoot } = require("./harness")

const Model = loadModule()
const { check, done } = createSuite("bw-login-code")

const FLAG = Model.twoFactorCodeFlag()
const ENV = Model.twoFactorCodeEnvVar()
const CODE = "249213"

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-login-code-"))
const pluginDir = path.join(tmp, "plug in\"s")
fs.mkdirSync(pluginDir)
for (const file of ["bw-fast-exit.js", "bw-login-code.js"]) {
  fs.copyFileSync(path.join(repoRoot, file), path.join(pluginDir, file))
}

// Reports what bw would parse beside what the kernel shows other users.
const report = `
  process.stdout.write(JSON.stringify({
    argv: process.argv.slice(2),
    cmdline: require("fs").readFileSync("/proc/self/cmdline", "utf8"),
    env: process.env[${JSON.stringify(ENV)}]
  }))
`
const fakeBw = path.join(tmp, "node_modules", "@bitwarden", "cli", "build", "bw.js")
fs.mkdirSync(path.dirname(fakeBw), { recursive: true })
fs.writeFileSync(fakeBw, report)
const link = path.join(tmp, "bw")
fs.symlinkSync(fakeBw, link)
const other = path.join(tmp, "validator.js")
fs.writeFileSync(other, report)

const options = Model.bwNodeOptions(pluginDir, "")
const run = (file, args, env = {}, nodeOptions = options) => {
  const base = { ...process.env, NODE_OPTIONS: nodeOptions }
  delete base[ENV]
  const r = spawnSync(process.execPath, [file, ...args], { env: { ...base, ...env }, encoding: "utf8" })
  try {
    return { rc: r.status, ...JSON.parse(r.stdout) }
  } catch (e) {
    return { rc: r.status, err: r.stderr }
  }
}
const loginArgs = ["login", "a@b.c", "--passwordfile", "/dev/null", "--method", "0", FLAG, "--raw"]
const withCode = { [ENV]: CODE }

const swapped = run(fakeBw, loginArgs, withCode)
check("bw parses the code as --code, where the placeholder was",
  JSON.stringify(swapped.argv) === JSON.stringify(
    ["login", "a@b.c", "--passwordfile", "/dev/null", "--method", "0", "--code=" + CODE, "--raw"]),
  JSON.stringify(swapped))
check("the kernel's command line never shows the code",
  typeof swapped.cmdline === "string" && !swapped.cmdline.includes(CODE) && swapped.cmdline.includes(FLAG),
  JSON.stringify(swapped.cmdline))
check("the code leaves bw's environment once handed over", swapped.env === undefined, JSON.stringify(swapped))

const viaLink = run(link, loginArgs, withCode)
check("bw reached through a symlink (/usr/bin/bw) is still recognised",
  viaLink.argv && viaLink.argv.includes("--code=" + CODE) && !viaLink.cmdline.includes(CODE),
  JSON.stringify(viaLink))

const dashed = run(fakeBw, loginArgs, { [ENV]: "--raw" })
check("a code starting with a dash stays the option's value",
  dashed.argv && dashed.argv.includes("--code=--raw") && dashed.argv.filter(a => a === "--raw").length === 1,
  JSON.stringify(dashed))

// --- every other case leaves the placeholder, which bw refuses ----------------
const noPreload = run(fakeBw, loginArgs, withCode, "")
check("without the preload the placeholder is all bw sees",
  noPreload.argv && noPreload.argv.includes(FLAG) && !noPreload.argv.some(a => a.startsWith("--code")),
  JSON.stringify(noPreload))
const noCode = run(fakeBw, loginArgs, {})
check("no code leaves the placeholder rather than an empty --code",
  noCode.argv && noCode.argv.includes(FLAG) && !noCode.argv.some(a => a.startsWith("--code")),
  JSON.stringify(noCode))
const emptyCode = run(fakeBw, loginArgs, { [ENV]: "" })
check("an empty code leaves the placeholder too",
  emptyCode.argv && emptyCode.argv.includes(FLAG), JSON.stringify(emptyCode))

const notLogin = run(fakeBw, ["unlock", FLAG], withCode)
check("only bw login is given the code",
  notLogin.argv && notLogin.argv.includes(FLAG) && notLogin.env === CODE, JSON.stringify(notLogin))
const notBw = run(other, loginArgs, withCode)
check("any other node in the pipeline is left alone",
  notBw.argv && notBw.argv.includes(FLAG) && notBw.env === CODE, JSON.stringify(notBw))
const plain = run(fakeBw, ["login", "a@b.c", "--raw"], withCode)
check("a login without the placeholder is untouched",
  plain.argv && JSON.stringify(plain.argv) === JSON.stringify(["login", "a@b.c", "--raw"]),
  JSON.stringify(plain))

// --- the names the preload repeats --------------------------------------------
const preload = read("bw-login-code.js")
check("the preload looks for the model's placeholder and environment variable",
  preload.includes(`var FLAG = "${FLAG}"`) && preload.includes(`var ENV = "${ENV}"`),
  "bw-login-code.js must match TWOFACTOR_CODE_FLAG and TWOFACTOR_CODE_ENV")

// --- a real bw refuses the placeholder before contacting a server --------------
const realBw = spawnSync("bash", ["-c", "command -v bw"], { encoding: "utf8" }).stdout.trim()
if (realBw) {
  const appData = path.join(tmp, "appdata")
  fs.mkdirSync(appData, { mode: 0o700 })
  const r = spawnSync("bw", ["login", "a@b.invalid", "--passwordfile", "/dev/null", FLAG, "--raw"], {
    env: { ...process.env, NODE_OPTIONS: "", BW_NOINTERACTION: "true", BITWARDENCLI_APPDATA_DIR: appData,
      [ENV]: CODE },
    encoding: "utf8", timeout: 30000
  })
  check("a bw without the preload refuses the placeholder, which the panel recognises",
    r.status !== 0 && Model.loginCodeChannelMissing(r.stdout, r.stderr),
    JSON.stringify({ rc: r.status, err: String(r.stderr).slice(-300) }))
}

fs.rmSync(tmp, { recursive: true, force: true })
done()
