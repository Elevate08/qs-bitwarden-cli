#!/usr/bin/env node
// scripts/repair-keyring.sh, run on fixture keyring files: it joins a wrapped
// qs-bitwarden-cli secret back onto one line, touches nothing else, keeps the
// original, and never prints a secret. A stand-in `systemd-creds` checks what
// the repaired envelope decrypts from; the suite reruns with a real sealed
// envelope where `systemd-creds --user` works.
//
//   node tests/keyring-repair.test.js

const { createSuite, repoRoot } = require("./harness")
const crypto = require("crypto")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const { check, eq, done } = createSuite("keyring-repair")

const script = path.join(repoRoot, "scripts", "repair-keyring.sh")
const wrap = s => s.match(/.{1,79}/g).join("\n")

// A passwordless keyring as gnome-keyring writes it, with `ours` stored raw.
function keyring(ours, theirs) {
  return `[keyring]
display-name=Default keyring
ctime=0
mtime=0
lock-on-idle=false
lock-after=false

[1]
item-type=0
display-name=Some other app
secret=${theirs || "their-secret"}
mtime=1758500000
ctime=1758500000

[1:attribute0]
name=service
type=string
value=other-app

[2]
item-type=0
display-name=Bitwarden quick unlock (encrypted)
secret=${ours}
mtime=1758550000
ctime=1758550000

[2:attribute0]
name=account
type=string
value=unlock_envelope

[2:attribute1]
name=service
type=string
value=qs-bitwarden-cli

[3]
item-type=0
display-name=Bitwarden session
secret=single-line-session
mtime=1758550001
ctime=1758550001

[3:attribute0]
name=service
type=string
value=qs-bitwarden-cli
`
}

function suite(sealed, realCreds) {
  const tag = realCreds ? "[real systemd-creds] " : ""
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-repair-"))
  try {
    const bin = path.join(dir, "bin")
    fs.mkdirSync(bin)
    if (realCreds) {
      fs.symlinkSync("/usr/bin/systemd-creds", path.join(bin, "systemd-creds"))
    } else {
      // Opens only the exact joined secret, under the envelope's name.
      fs.writeFileSync(path.join(bin, "systemd-creds"), `#!/bin/bash
case "$*" in *decrypt*--name=qs-bitwarden-unlock*) ;; *) exit 1 ;; esac
[ "$(cat)" = ${JSON.stringify(sealed)} ] || exit 1
printf 'opened'`, { mode: 0o755 })
    }
    const file = path.join(dir, "Default_keyring.keyring")
    const run = (...args) => {
      const r = spawnSync("bash", [script, ...args], {
        encoding: "utf8",
        env: Object.assign({}, process.env, { PATH: `${bin}:/usr/bin:/bin` })
      })
      return { code: r.status, out: r.stdout + r.stderr }
    }
    const backups = () => fs.readdirSync(dir).filter(f => f.includes(".before-repair-"))

    const broken = keyring(wrap(sealed))
    const fixed = keyring(sealed)
    fs.writeFileSync(file, broken, { mode: 0o600 })

    let r = run("--check", file)
    eq(tag + "--check reports a split secret", r.code, 3)
    eq(tag + "and writes nothing", fs.readFileSync(file, "utf8"), broken)
    eq(tag + "and keeps no copy", backups().length, 0)

    r = run(file)
    eq(tag + "the repair succeeds", r.code, 0)
    eq(tag + "the secret is on one line and nothing else changed", fs.readFileSync(file, "utf8"), fixed)
    eq(tag + "the file stays private", fs.statSync(file).mode & 0o777, 0o600)
    eq(tag + "the original is kept beside it", backups().length, 1)
    eq(tag + "byte for byte", backups().length && fs.readFileSync(path.join(dir, backups()[0]), "utf8"), broken)
    check(tag + "the repaired envelope is checked and opens", /opens with systemd-creds/.test(r.out), r.out)
    check(tag + "no secret is printed",
      !r.out.includes(sealed.slice(0, 40)) && !r.out.includes("their-secret") && !r.out.includes("single-line-session"),
      "the output holds a secret")
    check(tag + "no temporary file is left", !fs.readdirSync(dir).some(f => f.startsWith(".repair-keyring")), "")

    // --auto, as the plugin runs it at start: status on stdout's last line.
    fs.writeFileSync(file, broken, { mode: 0o600 })
    const auto = () => {
      const a = spawnSync("bash", [script, "--auto", file], {
        encoding: "utf8", env: Object.assign({}, process.env, { PATH: `${bin}:/usr/bin:/bin` })
      })
      return { code: a.status, last: a.stdout.trim().split("\n").pop(), all: a.stdout + a.stderr }
    }
    r = auto()
    check(tag + "--auto repairs and says so", r.code === 0 && r.last === "file=repaired", r.all)
    eq(tag + "with the same result", fs.readFileSync(file, "utf8"), fixed)
    check(tag + "and prints no secret", !r.all.includes(sealed.slice(0, 40)), "")
    r = auto()
    check(tag + "--auto on a clean file says clean, and nothing else on stdout",
      r.code === 0 && r.last === "file=clean" && !/repair-keyring:/.test(r.all), r.all)
    for (const f of backups().slice(1)) fs.rmSync(path.join(dir, f))

    r = run(file)
    eq(tag + "a second run has nothing to do", r.code, 0)
    eq(tag + "and changes nothing", fs.readFileSync(file, "utf8"), fixed)
    eq(tag + "--check agrees", run("--check", file).code, 0)
    eq(tag + "and keeps no second copy", backups().length, 1)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

// 4 KB, as a real envelope is, so the wrapping ends on a short padded line.
const fakeSealed = crypto.randomBytes(3070).toString("base64")
check("the fixture wraps like systemd-creds, padding and all",
  wrap(fakeSealed).split("\n").length > 50 && /=$/.test(fakeSealed), "")
suite(fakeSealed, false)

const real = spawnSync("bash", ["-c",
  "head -c 4096 /dev/urandom | systemd-creds --user encrypt --name=qs-bitwarden-unlock - - 2>/dev/null | tr -d '\\n'"],
  { encoding: "utf8" })
if (real.status === 0 && real.stdout) {
  suite(real.stdout, true)
} else {
  console.log("keyring-repair: systemd-creds --user unavailable here; the real-seal pass was skipped")
}

// -------------------------------------------------------------------------
// What it must leave alone
// -------------------------------------------------------------------------

{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-repair-"))
  try {
    const run = file => {
      const r = spawnSync("bash", [script, file], { encoding: "utf8", env: Object.assign({}, process.env, { PATH: "/usr/bin:/bin" }) })
      return { code: r.status, out: r.stdout + r.stderr }
    }

    // Someone else's wrapped secret is theirs to fix.
    const theirs = crypto.randomBytes(300).toString("base64")
    const foreign = path.join(dir, "foreign.keyring")
    const text = keyring("one-line-envelope", wrap(theirs))
    fs.writeFileSync(foreign, text, { mode: 0o600 })
    let r = run(foreign)
    eq("another app's split secret is not touched", fs.readFileSync(foreign, "utf8"), text)
    check("but is reported", /not qs-bitwarden-cli's/.test(r.out), r.out)
    check("without printing it", !r.out.includes(theirs.slice(0, 40)), "")

    // A keyring with a password is binary and cannot hold this break.
    const binary = path.join(dir, "login.keyring")
    const bytes = Buffer.concat([Buffer.from("GnomeKeyring\n\r\0\n"), crypto.randomBytes(64)])
    fs.writeFileSync(binary, bytes)
    r = run(binary)
    eq("a binary keyring is refused", r.code, 1)
    check("and left as it was", fs.readFileSync(binary).equals(bytes), "")

    eq("a missing file is an error", run(path.join(dir, "absent.keyring")).code, 1)
    const auto = f => spawnSync("bash", [script, "--auto", f], { encoding: "utf8" })
    let a = auto(path.join(dir, "absent.keyring"))
    check("but --auto skips it quietly", a.status === 0 && a.stdout === "file=skipped\n", a.stdout + a.stderr)
    a = auto(binary)
    check("and skips a binary keyring", a.status === 0 && a.stdout === "file=skipped\n", a.stdout + a.stderr)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
}

done()
