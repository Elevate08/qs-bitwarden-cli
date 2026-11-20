#!/usr/bin/env node
// scripts/verify-helpers.sh and REVIEWING.md: the script parses, documents
// itself and rejects unknown flags without touching the network; the review
// guide names every file an automated review flags, and every identifier it
// cites is still in the file it names.
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

// The marketplace scan reads scripts/: no install hint should add a
// package-manager or privilege match of its own.
check("no package-manager command in the script's messages",
  !/\b(?:pacman|paru|yay|apt|apt-get|dnf)\s+(?:-[A-Za-z]*[SRU]|install)\b/.test(script), "")
check("no sudo outside comments, even in messages",
  !/\bsudo\b/.test(script.replace(/^\s*#.*$/gm, "")), "")
// The container mounts only the checkout; a linked worktree cannot rebuild.
check("the rebuild stops early in a linked worktree",
  /\[ -f "\$ROOT\/\.git" \][\s\S]{0,200}?regular clone/.test(script), "")
const buildScript = read("scripts/build-agent.sh")
check("build-agent.sh refuses to re-enter the image from a linked worktree",
  /reexec_in_container\(\) \{[\s\S]{0,400}?\[ ! -f "\$REPO_ROOT\/\.git" \][\s\S]{0,300}?regular clone/.test(buildScript), "")
check("build-agent.sh needs cargo only where it builds, not to re-enter the image",
  /require_native\(\) \{[\s\S]{0,700}?command -v cargo[^\n]*fail "cargo is not on PATH"\n\}/.test(buildScript)
    && !/^main\(\) \{[\s\S]*command -v cargo/m.test(buildScript), "")

// Every helper the script checks is one the release ships.
const sums = read("bin/SHA256SUMS")
for (const name of ["qs-bitwarden-ssh-agent", "qs-bitwarden-unlock-key", "qs-bitwarden-vault"]) {
  for (const arch of ["x86_64", "aarch64"]) {
    check(`SHA256SUMS lists ${arch}-linux/${name}`, sums.includes(`  ${arch}-linux/${name}\n`), sums)
  }
  check(`REVIEWING.md names ${name}`, reviewing.includes(name), "")
}

// The files an automated marketplace review flagged.
for (const file of ["BitwardenModel.js", "README.md", "scripts/build-agent.sh", "bin/*/qs-bitwarden-*",
  "scripts/verify-helpers.sh", "docs/ssh-agent.md", "docs/vault-helper.md"]) {
  check(`REVIEWING.md references ${file}`, reviewing.includes(file), "")
}

// The guide cites code by name, not line, so a forward-merge does not stale
// it. Each identifier it names must still be in the file it names.
const cites = [
  ["BitwardenModel.js", "function helperInspectCommand"],
  ["BitwardenModel.js", "var DEPENDENCIES"],
  ["BitwardenModel.js", "function isPlainPackageName"],
  ["BitwardenModel.js", "^[A-Za-z0-9][A-Za-z0-9._+-]*$"],
  ["BitwardenModel.js", "function installPackagesCommand"],
  ["BitwardenModel.js", '"omarchy", "install", "app"'],
  ["BitwardenModel.js", "function confirmedInstallCommand"],
  ["BitwardenModel.js", "function installNeedsConfirmation"],
  ["BitwardenModel.js", "function dependencyInstallHint"],
  ["BitwardenModel.js", "function fingerprintSetupCommand"],
  ["BitwardenModel.js", "function generateServeRequestCommand"],
  ["BitwardenModel.js", "curl -q -s -S --noproxy"],
  ["BitwardenModel.js", "BITWARDENCLI_APPDATA_DIR"],
  ["BitwardenModel.js", "bw-login-code.js"],
  ["BitwardenModel.js", "bw-fast-exit.js"],
  ["Service.qml", "function installMissing"],
  ["Service.qml", "function installOne"],
  ["Service.qml", "allowVaultWithoutHelper"],
  ["Panel.qml", "installOne("],
  ["Panel.qml", "installMissing()"],
  ["FidoModel.js", "function fidoSetupCommand"],
  ["FidoUnlock.qml", "fidoSetupCommand()"],
  ["scripts/build-agent.sh", "container_runtime()"],
  // The scan's own evidence, which the guide quotes by file and commit.
  ["scripts/build-agent.sh", "sudo -n docker info"],
  ["README.md", "sudo pacman -S --needed"],
  ["BitwardenModel.js", "sudo pacman -S --needed"],
  ["scripts/build-agent.sh", "PINNED_IMAGE="],
  ["scripts/repair-keyring.sh", "Default_keyring.keyring"],
  ["agent/src/main.rs", "harden_process()"],
  ["unlock-key/src/main.rs", "harden_process()"],
  ["vault/src/main.rs", "harden_process()"],
]
for (const [file, text] of cites) {
  check(`${file} still holds ${text}`, read(file).includes(text),
    `update REVIEWING.md and this test`)
}
for (const name of ["helperInspectCommand", "DEPENDENCIES", "isPlainPackageName", "installPackagesCommand",
  "confirmedInstallCommand", "installNeedsConfirmation", "dependencyInstallHint", "fingerprintSetupCommand",
  "generateServeRequestCommand", "installMissing", "installOne", "fidoSetupCommand", "container_runtime",
  "PINNED_IMAGE", "harden_process", "allowVaultWithoutHelper", "BITWARDENCLI_APPDATA_DIR"]) {
  check(`REVIEWING.md cites ${name}`, reviewing.includes("`" + name), "")
}
// Line numbers only where they quote the scan's own evidence at 8e1ab7b.
const lineCites = [...reviewing.matchAll(/[\w./-]+\.(?:js|qml|md|sh):\d+/g)].map(m => m[0])
eq("the only file:line citations are the scan's evidence",
  lineCites.sort().join(" "), "README.md:38 scripts/build-agent.sh:191")
check("each is marked as evidence at 8e1ab7b",
  /`README\.md:38` at 8e1ab7b/.test(reviewing) && /`scripts\/build-agent\.sh:191` at 8e1ab7b/.test(reviewing), "")
check("the rebuild caveat names linked worktrees, and no longer claims cargo is needed to start",
  /linked `git worktree`/.test(reviewing) && !/cargo` on `PATH`/.test(reviewing), "")

done()
