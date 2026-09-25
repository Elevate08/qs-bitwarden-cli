#!/usr/bin/env node
// bw-fast-exit.js, the NODE_OPTIONS preload that lets `bw` exit once it has
// answered: it must cut the idle tail of the Bitwarden CLI and nothing else,
// since NODE_OPTIONS reaches every node in a pipeline.
//
//   node tests/bw-fast-exit.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")
const { createSuite, functionBody, loadModule, read, repoRoot } = require("./harness")

const Model = loadModule()
const { check, done } = createSuite("bw-fast-exit")

// A plugin directory with a space and a quote, so the NODE_OPTIONS quoting is
// exercised by Node itself rather than only by string comparison.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-fast-exit-"))
const pluginDir = path.join(tmp, "plug in\"s")
fs.mkdirSync(pluginDir)
fs.copyFileSync(path.join(repoRoot, "bw-fast-exit.js"), path.join(pluginDir, "bw-fast-exit.js"))

// Behaves like the CLI: answers, records an exit code, then a timer keeps the
// process alive. `late` output after the exit code shows whether it was cut.
const script = code => `
  process.stdout.write("x".repeat(1024 * 1024) + "\\n")
  process.exitCode = ${code}
  setTimeout(() => process.stdout.write("late\\n"), 300)
  const t = setInterval(() => {}, 1000)
  setTimeout(() => clearInterval(t), 2500)
`
const fakeBw = path.join(tmp, "node_modules", "@bitwarden", "cli", "build", "bw.js")
fs.mkdirSync(path.dirname(fakeBw), { recursive: true })
fs.writeFileSync(fakeBw, script(0))
const failingBw = path.join(tmp, "fail", "@bitwarden", "cli", "build", "bw.js")
fs.mkdirSync(path.dirname(failingBw), { recursive: true })
fs.writeFileSync(failingBw, script(3))
const other = path.join(tmp, "validator.js")
fs.writeFileSync(other, script(0))
const link = path.join(tmp, "bw")
fs.symlinkSync(fakeBw, link)

const options = Model.bwNodeOptions(pluginDir, "--max-old-space-size=512")
const run = (file, args = [], nodeOptions = options) => {
  const started = Date.now()
  const r = spawnSync(process.execPath, [file, ...args], {
    env: { ...process.env, NODE_OPTIONS: nodeOptions }, encoding: "utf8", maxBuffer: 8 * 1024 * 1024
  })
  return { ms: Date.now() - started, rc: r.status, out: r.stdout || "", err: r.stderr || "" }
}
const complete = out => out.startsWith("x".repeat(1024 * 1024) + "\n")

const fast = run(fakeBw, ["list", "items"])
check("bw exits once its exit code is set, with its whole answer",
  fast.rc === 0 && fast.ms < 1500 && complete(fast.out) && !fast.out.includes("late"),
  JSON.stringify({ rc: fast.rc, ms: fast.ms, err: fast.err.slice(0, 300) }))

const plain = run(fakeBw, ["list", "items"], "")
check("without the preload the same process idles on",
  plain.rc === 0 && plain.ms >= 2000 && plain.out.includes("late"),
  JSON.stringify({ rc: plain.rc, ms: plain.ms }))

const viaLink = run(link, ["status"])
check("bw reached through a symlink (/usr/bin/bw) is still recognised",
  viaLink.rc === 0 && viaLink.ms < 1500 && !viaLink.out.includes("late"),
  JSON.stringify({ rc: viaLink.rc, ms: viaLink.ms }))

const failing = run(failingBw, ["get", "item", "x"])
check("bw's own exit code is kept", failing.rc === 3 && complete(failing.out),
  JSON.stringify({ rc: failing.rc, ms: failing.ms }))

const validator = run(other)
check("any other node in the pipeline runs to its natural end",
  validator.rc === 0 && validator.out.includes("late") && validator.ms >= 2000,
  JSON.stringify({ rc: validator.rc, ms: validator.ms }))

const serve = run(fakeBw, ["serve", "--hostname", "127.0.0.1"])
check("bw serve is left alone", serve.out.includes("late") && serve.ms >= 2000,
  JSON.stringify({ rc: serve.rc, ms: serve.ms }))

const search = run(fakeBw, ["list", "items", "--search", "serve"])
check("only the command word counts as serve", search.ms < 1500 && !search.out.includes("late"),
  JSON.stringify({ rc: search.rc, ms: search.ms }))

// --- NODE_OPTIONS composition ------------------------------------------------
check("the user's NODE_OPTIONS are kept ahead of the preload",
  options.startsWith("--max-old-space-size=512 --require \"")
    && options.endsWith("bw-fast-exit.js\""),
  options)
check("no plugin directory adds nothing",
  Model.bwNodeOptions("", "--trace-warnings") === "--trace-warnings" && Model.bwNodeOptions("", undefined) === "",
  Model.bwNodeOptions("", "--trace-warnings"))

// --- Service wiring -------------------------------------------------------------
const svc = read("Service.qml")
check("every bw environment carries the preload",
  /env\.NODE_OPTIONS\s*=\s*bwNodeOptions/.test(functionBody(svc, "bwEnv"))
    && /bwNodeOptions:\s*Model\.bwNodeOptions\(sshAgentPluginDir,\s*Quickshell\.env\("NODE_OPTIONS"\)\)/.test(svc),
  functionBody(svc, "bwEnv"))

fs.rmSync(tmp, { recursive: true, force: true })
done()
