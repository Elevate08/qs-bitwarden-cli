#!/usr/bin/env node
// scripts/verify-helpers.sh and REVIEWING.md: the script parses, documents
// itself and rejects unknown flags without touching the network; the review
// guide names every file an automated review flags, and its file:line
// citations still point at the code they describe.
//
//   node tests/verify-helpers.test.js

const { createSuite, repoRoot, read } = require("./harness")
const fs = require("fs")
const path = require("path")
const { spawnSync } = require("child_process")

const { check, eq, done } = createSuite("verify-helpers")

const scriptPath = path.join(repoRoot, "scripts/verify-helpers.sh")
const script = read("scripts/verify-helpers.sh")
const reviewing = read("REVIEWING.md")
const bash = (...args) => spawnSync("bash", args, { cwd: repoRoot, encoding: "utf8" })

check("the script is executable", (fs.statSync(scriptPath).mode & 0o111) !== 0,
  "chmod +x scripts/verify-helpers.sh")
eq("bash -n accepts it", bash("-n", scriptPath).status, 0)
check("it runs under set -euo pipefail", /^set -euo pipefail$/m.test(script), "")
// Outside comments and quoted messages (which name what build-agent.sh tries).
const code = script.replace(/#.*$/gm, "").replace(/'[^']*'|"[^"]*"/g, "")
check("it never calls sudo itself", !/\bsudo\b/.test(code), "verify-helpers.sh must not escalate")

const help = bash(scriptPath, "--help")
eq("--help exits 0", help.status, 0)
for (const flag of ["--attestations", "--rebuild", "--arch"]) {
  check(`--help documents ${flag}`, help.stdout.includes(flag), help.stdout)
}
eq("an unknown flag exits 2", bash(scriptPath, "--no-such-flag").status, 2)

check("attestations are pinned to this repository and its release workflow",
  script.includes('REPO="Elevate08/qs-bitwarden-cli"')
    && script.includes('SIGNER="$REPO/.github/workflows/release.yml"')
    && /--repo "\$REPO" --signer-workflow "\$SIGNER"/.test(script), "")
check("the rebuild delegates to build-agent.sh --compare-tracked",
  /scripts\/build-agent\.sh" --arch "\$a" --compare-tracked/.test(script), "")

// Every helper the script checks is one the release ships.
const sums = read("bin/SHA256SUMS")
for (const arch of ["x86_64", "aarch64"]) {
  for (const name of ["qs-bitwarden-ssh-agent", "qs-bitwarden-unlock-key", "qs-bitwarden-vault"]) {
    check(`SHA256SUMS lists ${arch}-linux/${name}`, sums.includes(`  ${arch}-linux/${name}\n`), sums)
    check(`REVIEWING.md names ${name}`, reviewing.includes(name), "")
  }
}

// The files an automated marketplace review flagged.
for (const file of ["BitwardenModel.js", "README.md", "scripts/build-agent.sh", "bin/*/qs-bitwarden-*",
  "scripts/verify-helpers.sh", "docs/ssh-agent.md", "docs/vault-helper.md"]) {
  check(`REVIEWING.md references ${file}`, reviewing.includes(file), "")
}

// file:line citations must still land on the code they describe.
const lineOf = (file, n) => read(file).split("\n")[n - 1] || ""
const cites = [
  ["BitwardenModel.js", 7227, "sudo pacman -S --needed"],
  ["BitwardenModel.js", 7212, '"omarchy", "install", "app"'],
  ["BitwardenModel.js", 7252, "sudo pacman -S --needed"],
  ["BitwardenModel.js", 7232, "function installNeedsConfirmation"],
  ["BitwardenModel.js", 5145, "var DEPENDENCIES"],
  ["BitwardenModel.js", 7258, "function fingerprintSetupCommand"],
  ["BitwardenModel.js", 7621, "curl -q -s -S --noproxy"],
  ["README.md", 38, "sudo pacman -S --needed"],
  ["scripts/build-agent.sh", 191, "sudo -n docker info"],
  ["Service.qml", 5320, "function installMissing"],
  ["Panel.qml", 2336, "installOne("],
  ["Panel.qml", 2364, "installMissing()"],
  ["FidoModel.js", 15, "function fidoSetupCommand"],
]
// Every `file:N` or `file:A-B` citation in the guide.
const citations = [...reviewing.matchAll(/([\w./-]+\.(?:js|qml|md|sh)):(\d+)(?:-(\d+))?/g)]
  .map(m => ({ file: m[1], from: +m[2], to: +(m[3] || m[2]) }))
for (const [file, n, text] of cites) {
  check(`${file}:${n} still holds ${text}`, lineOf(file, n).includes(text),
    `line ${n} is now: ${lineOf(file, n).trim()} -- update REVIEWING.md and this test`)
  check(`REVIEWING.md cites ${file}:${n}`,
    citations.some(c => c.file === file && c.from <= n && n <= c.to), "")
}

done()
