#!/usr/bin/env node
// End to end: a vault the panel locks stops the SSH agent signing. A headless
// shell (shell.js) with the agent on signs in to a fake account holding an SSH
// key, a client signs under a grant, and then the vault closes without the
// panel's lock button:
//
// - the vault helper dies (it held the session key) while a `bw status` is
//   running, whose failure once read as a sign-out, and
// - `bw` reports the vault locked (a `bw lock` in a terminal).
//
// Each time the panel says locked, and the same client, still inside its
// grant, must get no signature. Both once left the agent signing.
//
// Needs the vault and agent helpers (shipped in bin/, or built in vault/ and
// agent/), `ssh-keygen`, and what shell.js needs.
//
//   node tests/e2e/ssh-lock.e2e.js

const { createSuite } = require("../harness")
const { createShell, sleep } = require("./shell")
const fs = require("fs")
const path = require("path")
const { spawnSync } = require("child_process")

const { check, done } = createSuite("e2e-ssh-lock")

if (spawnSync("ssh-keygen", ["-?"]).error) {
  console.error("e2e-ssh-lock: needs ssh-keygen")
  process.exit(1)
}

function childHelperPid(parent) {
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue
    try {
      const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8")
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
      if (ppid === parent && /^qs-bitwarden-va/.test(fs.readFileSync(`/proc/${entry}/comm`, "utf8"))) return Number(entry)
    } catch (e) {}
  }
  return 0
}

const shell = createShell("e2e-ssh-lock", check, { env: { QSBW_E2E_SSH_AGENT: "1" } })
const data = path.join(shell.home, ".config", "Bitwarden CLI")
const keyDir = path.join(shell.root, "key")
const socket = path.join(shell.env.XDG_RUNTIME_DIR, "qs-bitwarden-cli", "ssh-agent.sock")
const message = path.join(shell.root, "message")

// A signature by the agent's key, by public key only, in the background so an
// approval can be given meanwhile. Returns a poll for its exit status.
let signs = 0
function sign(seconds = 10) {
  signs += 1
  const rc = path.join(shell.root, `sign-${signs}.rc`)
  spawnSync("bash", ["-c",
    '(timeout "$4" ssh-keygen -q -Y sign -n file -f "$1" "$2" </dev/null >/dev/null 2>"$3.err"; echo $? > "$3") &',
    "_", path.join(keyDir, "id.pub"), message, rc, String(seconds)],
  // No pipes: the background job would hold them, and this would wait for it.
  { env: Object.assign({}, shell.env, { SSH_AUTH_SOCK: socket }), stdio: "ignore" })
  return () => (fs.existsSync(rc) && fs.readFileSync(rc, "utf8").trim() !== "" ? Number(fs.readFileSync(rc, "utf8")) : null)
}

function waitFor(poll, ms = 15000) {
  for (let t = 0; t < ms; t += 100) {
    const v = poll()
    if (v !== null) return v
    sleep(100)
  }
  return null
}

function cleanSigs() {
  for (const f of fs.readdirSync(shell.root)) if (f.endsWith(".sig")) fs.rmSync(path.join(shell.root, f))
}

const signed = (label, rc) => check(label, rc === 0, `exit ${rc}`)

// Signs under a fresh grant, then once more inside it without a prompt.
function signUnderGrant(label) {
  const first = sign()
  shell.expect(`${label}: the signature asks for approval`, s => s.ssh.prompt)
  shell.q("approveSsh", "300")
  signed(`${label}: approved, the agent signs`, waitFor(first))
  cleanSigs()
  signed(`${label}: inside the grant it signs again without asking`, waitFor(sign()))
  cleanSigs()
}

// A locked agent holds a request for a key it knows and asks for an unlock;
// one still unlocked would sign at once under the grant.
function refusedAfterLock(label) {
  cleanSigs()
  // Held for an unlock, so this client gives up after a few seconds.
  const poll = sign(3)
  shell.expect(`${label}: the agent asks for an unlock, not an approval`, s => s.ssh.unlock && !s.ssh.prompt)
  const rc = waitFor(poll)
  check(`${label}: the same client, inside its grant, gets no signature`, rc !== null && rc !== 0, `exit ${rc}`)
  // The client gave up, so the agent withdraws the request.
  shell.expect(`${label}: the unlock request goes with the client`, s => !s.ssh.unlock)
}

try {
  fs.mkdirSync(keyDir, { mode: 0o700 })
  spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "e2e", "-f", path.join(keyDir, "id")])
  fs.writeFileSync(message, "sign me\n")
  const pub = fs.readFileSync(path.join(keyDir, "id.pub"), "utf8").trim()
  const fingerprint = spawnSync("ssh-keygen", ["-l", "-E", "sha256", "-f", path.join(keyDir, "id.pub")], { encoding: "utf8" })
    .stdout.split(" ")[1]
  fs.mkdirSync(data, { recursive: true })
  fs.writeFileSync(path.join(data, "fake-ssh-item"), JSON.stringify({
    object: "item", id: "ssh-1", organizationId: null, folderId: null, type: 5, reprompt: 0,
    name: "Deploy key", notes: null, favorite: false, collectionIds: [],
    revisionDate: "2026-01-01T00:00:00.000Z",
    sshKey: { privateKey: fs.readFileSync(path.join(keyDir, "id"), "utf8"), publicKey: pub, keyFingerprint: fingerprint }
  }))
  // Only the vault holds the key now: given just the public half, ssh-keygen
  // would otherwise sign with the file beside it when the agent cannot.
  fs.rmSync(path.join(keyDir, "id"))

  shell.start()
  shell.q("open")
  shell.q("login", "a@x", "pw-a@x")
  shell.expect("signed in", s => s.status === "unlocked")
  shell.expect("the vault helper is up", s => s.helper === "active")
  shell.expect("the agent serves the vault's key", s => s.ssh.phase === "ready" && s.ssh.keys === 1)
  // No prompt is raised without a reading that the screen is unlocked.
  shell.expect("the screen lock has been read", s => s.ssh.screenChecked)

  // --- the vault helper dies with a `bw status` in flight --------------------
  signUnderGrant("before the helper dies")
  const statusRuns = () => (fs.readFileSync(shell.bwLog, "utf8").match(/\tstatus\b/g) || []).length
  const before = statusRuns()
  fs.writeFileSync(path.join(data, "fake-status-delay"), "5")
  shell.q("refresh")
  check("a status check is running", waitFor(() => (statusRuns() > before ? true : null)) === true, "")
  const helper = childHelperPid(shell.pid())
  check("the helper runs under the shell", helper > 0, "")
  if (helper) process.kill(helper, "SIGKILL")
  fs.rmSync(path.join(data, "fake-status-delay"))
  shell.expect("losing the helper locks the vault, and says why",
    s => s.status === "locked" && s.screen === "locked" && /vault helper stopped/.test(s.error))
  shell.expect("the list went with it", s => s.items.length === 0)
  refusedAfterLock("after the helper died")
  check("still locked, not signed out by the failed check", shell.state().status === "locked", "")

  // --- unlocked again, then `bw lock` behind the panel's back ----------------
  shell.expect("the helper comes back", s => s.helper === "active")
  shell.q("unlock", "pw-a@x")
  shell.expect("the vault unlocks again", s => s.status === "unlocked")
  shell.expect("and the agent serves the key again", s => s.ssh.keys === 1)
  signUnderGrant("unlocked again")
  fs.rmSync(path.join(data, "fake-session"))
  // The panel finds out on a status check, as waking from sleep runs one.
  shell.q("refresh")
  shell.expect("the panel finds the vault locked", s => s.status === "locked")
  refusedAfterLock("after bw locked the vault")

  const errors = shell.scriptErrors()
  check("no script errors", errors.length === 0, errors.join("\n"))
} catch (e) {
  check("ran to the end", false, String(e && e.stack))
} finally {
  if (process.exitCode || process.env.KEEP_E2E) console.error(shell.logTail())
  shell.cleanup()
}
done()
