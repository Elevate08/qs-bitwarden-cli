#!/usr/bin/env node
// A shell crash must not write the decrypted vault to disk: once a secret is
// in the shell, its soft core limit goes to 0 for the rest of its life,
// unless crashDumpsAfterUnlock opts back in.
//
//   node tests/core-dumps.test.js

const { createSuite, functionBody, loadModule, read, readPluginSource } = require("./harness")
const { spawnSync } = require("child_process")

const Model = loadModule()
const src = readPluginSource("Panel.qml")
const body = name => functionBody(src, name)
const { check, eq, done } = createSuite("core-dumps")

// --- the command, run for real on a throwaway parent ---------------------------
// The command lowers its parent's limit, as the shell's Process child does.
// The parent here is a bash started for the test, never the real shell.
{
  const cmd = Model.coreDumpsOffCommand()
  const script = `ulimit -S -c "$(ulimit -H -c)" 2>/dev/null
before=$(awk '/Max core file size/ {print $5 " " $6}' /proc/$$/limits)
${cmd[0]} -c ${JSON.stringify(cmd[2]).replace(/\$/g, "\\$")}
rc=$?
after=$(awk '/Max core file size/ {print $5 " " $6}' /proc/$$/limits)
echo "$rc|$before|$after"`
  const r = spawnSync("bash", ["-c", script], { encoding: "utf8" })
  const [rc, before, after] = String(r.stdout).trim().split("|")
  eq("the command succeeds", rc, "0")
  check("the parent's soft core limit becomes 0", after.split(" ")[0] === "0", `${before} -> ${after}`)
  check("its hard limit is left alone", after.split(" ")[1] === before.split(" ")[1], `${before} -> ${after}`)
  check("it only ever targets its own parent", /prlimit --pid "\$PPID" --core=0:/.test(cmd[2])
    && /\[ "\$PPID" -gt 1 \] \|\| exit 3/.test(cmd[2]), cmd[2])
}

// --- when the shell calls it --------------------------------------------------------

const protect = body("protectFromCoreDumps")
check("it runs once, only in a live vault, and not when the user opted out",
  /coreDumpsOffRequested \|\| crashDumpsAfterUnlock \|\| !live\) return/.test(protect)
    && /coreDumpsOffRequested = true/.test(protect) && /coreLimitProc\.running = true/.test(protect), protect)
check("turning it off is logged once, with no secret in the line",
  /console\.log\("qs-bitwarden: core dumps are off/.test(body("onCoreLimitSet")), body("onCoreLimitSet"))

for (const fn of ["submitLogin", "submitDeviceVerification", "unlockVaultWithPassword", "submitPinUnlock",
                  "writeAuthPassword", "queueEnvelopeJob"]) {
  check(`${fn} turns core dumps off before a secret moves`, /protectFromCoreDumps\(\)/.test(body(fn)), body(fn))
}
check("an adopted session key turns them off (terminal handoff)",
  /if \(handed\) \{\s*protectFromCoreDumps\(\)/.test(body("onSessionHandoff")), body("onSessionHandoff"))
check("and a remembered one read from the keyring",
  /if \(token\) \{\s*protectFromCoreDumps\(\)/.test(body("onKeyringLookupFinished")), body("onKeyringLookupFinished"))
check("an unlocked vault turns them off however it got there",
  /onStatusChanged:\s*\{\s*if \(status === "unlocked"\) protectFromCoreDumps\(\)/.test(src), "")
for (const prop of ["masterPassword", "loginPassword", "loginClientSecret", "pinEntry", "pinSetupMaster",
                    "fpSetupMaster", "fidoSetupMaster"]) {
  const name = "on" + prop.charAt(0).toUpperCase() + prop.slice(1) + "Changed"
  check(`typing into ${prop} turns them off`,
    new RegExp(name + ":\\s*if \\(" + prop + "\\) protectFromCoreDumps\\(\\)").test(src), name)
}
check("a FIDO2 touch, whose answer is the password, turns them off",
  /vault\.protectFromCoreDumps\(\)/.test(functionBody(read("FidoUnlock.qml"), "launchAssert")), "")

// --- the setting ----------------------------------------------------------------------

const manifest = JSON.parse(read("manifest.json"))
const entry = manifest.barWidget.schema.find(e => e.key === "crashDumpsAfterUnlock")
check("crashDumpsAfterUnlock defaults to false (cores off after unlock)",
  manifest.barWidget.defaults.crashDumpsAfterUnlock === false && entry && entry.type === "boolean"
    && entry.defaultValue === false, JSON.stringify(entry))
check("its description states the trade-off",
  entry && /core dump/.test(entry.description) && /diagnose/.test(entry.description), entry && entry.description)
check("the settings screen offers it, off by default",
  Model.boolSetting("crashDumpsAfterUnlock", undefined) === false
    && Model.SETTINGS_SCHEMA.some(e => e.key === "crashDumpsAfterUnlock" && e.group === "security"), "")

done()
