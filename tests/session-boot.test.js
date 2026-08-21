#!/usr/bin/env node
// The remembered session must not survive the machine it was minted on.
//
// These run the real shell scripts the panel executes, against a stand-in
// secret-tool, so what is checked is the behaviour and not a string.
//
//   node tests/session-boot.test.js

const fs = require("fs")
const os = require("os")
const path = require("path")
const { execFileSync } = require("child_process")

const Model = {}
new Function("exports", fs.readFileSync(path.join(__dirname, "..", "BitwardenModel.js"), "utf8")
  .replace(/^\.pragma library\s*$/m, "") + `
  exports.keyringStoreCommand = keyringStoreCommand
  exports.keyringLookupCommand = keyringLookupCommand
  exports.keyringClearCommand = keyringClearCommand
  exports.keyringSecretEnvVar = keyringSecretEnvVar
  exports.bootIdPath = bootIdPath
`)(Model)

let pass = 0
const failures = []
const check = (l, ok, d) => ok ? pass++ : failures.push(`${l}\n    ${d}`)

// A stand-in for libsecret. Keeps the stored blob in a file, records every
// call, and can be told to refuse the session collection the way a secret
// service without one would.
const stub = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-keyring-"))
fs.writeFileSync(path.join(stub, "secret-tool"), `#!/usr/bin/env bash
set -uo pipefail
echo "$*" >> "$STUB/calls"
cmd="\${1:-}"; shift || true
collection=""
for a in "$@"; do case "$a" in --collection=*) collection="\${a#--collection=}" ;; esac; done
case "$cmd" in
  store)
    if [ "\${STUB_NO_SESSION_COLLECTION:-}" = "1" ] && [ "$collection" = "session" ]; then
      cat >/dev/null; exit 1
    fi
    cat > "$STUB/value"; printf '%s' "$collection" > "$STUB/collection"; exit 0 ;;
  lookup) [ -s "$STUB/value" ] || exit 1; cat "$STUB/value"; exit 0 ;;
  clear)  rm -f "$STUB/value"; exit 0 ;;
esac
exit 1
`)
fs.chmodSync(path.join(stub, "secret-tool"), 0o755)

const TOKEN = "not-a-real-session-token"
const bootId = fs.readFileSync(Model.bootIdPath(), "utf8").trim()

const reset = () => {
  for (const f of ["value", "collection", "calls"]) fs.rmSync(path.join(stub, f), { force: true })
}
const run = (command, extraEnv) => {
  const env = Object.assign({}, process.env, { PATH: `${stub}:${process.env.PATH}`, STUB: stub }, extraEnv || {})
  return execFileSync(command[0], command.slice(1), { env, encoding: "utf8" })
}
const stored = () => fs.existsSync(path.join(stub, "value"))
  ? fs.readFileSync(path.join(stub, "value"), "utf8") : null
const calls = () => fs.existsSync(path.join(stub, "calls"))
  ? fs.readFileSync(path.join(stub, "calls"), "utf8") : ""

const secretEnv = { [Model.keyringSecretEnvVar()]: TOKEN }

// --- storing ---
reset()
run(Model.keyringStoreCommand(), secretEnv)
check("the session is stored in the memory-only session collection",
  fs.readFileSync(path.join(stub, "collection"), "utf8") === "session",
  fs.readFileSync(path.join(stub, "collection"), "utf8"))
check("the stored blob carries the boot id that minted the session",
  stored() === `${bootId} ${TOKEN}`, JSON.stringify(stored()))
check("the token still never reaches a command line",
  !Model.keyringStoreCommand().join(" ").includes(TOKEN) && !calls().includes(TOKEN),
  Model.keyringStoreCommand().join(" ") + " || " + calls())

// A secret service with no session collection must not cost the user the
// setting entirely -- the boot id is what enforces the lock either way.
reset()
run(Model.keyringStoreCommand(), Object.assign({ STUB_NO_SESSION_COLLECTION: "1" }, secretEnv))
check("a service without a session collection falls back to the default one",
  fs.readFileSync(path.join(stub, "collection"), "utf8") === "" && stored() === `${bootId} ${TOKEN}`,
  JSON.stringify(stored()))

// --- looking up on the same boot ---
reset()
run(Model.keyringStoreCommand(), secretEnv)
check("a session from this boot is handed back, boot id stripped",
  run(Model.keyringLookupCommand()) === TOKEN, JSON.stringify(run(Model.keyringLookupCommand())))
check("a usable session is left in the keyring",
  stored() !== null, "expected the entry to survive a lookup")

// --- looking up after a reboot ---
reset()
fs.writeFileSync(path.join(stub, "value"), `11111111-2222-3333-4444-555555555555 ${TOKEN}`)
check("a session from another boot is not handed back",
  run(Model.keyringLookupCommand()) === "", JSON.stringify(run(Model.keyringLookupCommand())))
check("a session from another boot is cleared out of the keyring",
  stored() === null, JSON.stringify(stored()))

// An entry written before the boot id existed has no provenance at all, so it
// gets the same treatment rather than the benefit of the doubt.
reset()
fs.writeFileSync(path.join(stub, "value"), TOKEN)
check("a bare pre-boot-id entry is refused and cleared",
  run(Model.keyringLookupCommand()) === "" && stored() === null, JSON.stringify(stored()))

// --- nothing to find ---
reset()
check("an empty keyring is not an error, so the panel falls through to bw status",
  run(Model.keyringLookupCommand()) === "", "expected empty output and exit 0")

fs.rmSync(stub, { recursive: true, force: true })

console.log(`${pass} passed, ${failures.length} failed`)
if (failures.length) { console.error("\nFAILURES:\n  " + failures.join("\n  ")); process.exit(1) }
