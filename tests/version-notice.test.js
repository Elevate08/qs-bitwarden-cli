#!/usr/bin/env node
// Version label, update notice and the once-a-day release check: the pure
// functions in BitwardenModel.js and how Service.qml and the manifest use them.
//
//   node tests/version-notice.test.js

const { createSuite, loadModule, readPluginSource } = require("./harness")
const { execFileSync } = require("child_process")
const fs = require("fs")
const os = require("os")
const path = require("path")

const Model = loadModule()
const { check, done } = createSuite("version-notice")
const readRepo = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8")

// --- semver ----------------------------------------------------------------

const cmp = Model.compareSemver
check("equal versions compare equal", cmp("1.2.3", "1.2.3") === 0 && cmp("v1.2.3", "1.2.3") === 0)
check("numbers compare numerically", cmp("1.9.0", "1.10.0") === -1 && cmp("2.0.0", "1.99.99") === 1)
check("a prerelease sorts before its release", cmp("2.0.0-rc.1", "2.0.0") === -1 && cmp("2.0.0", "2.0.0-rc.1") === 1)
check("prerelease identifiers follow SemVer 2.0.0 (the spec's own chain)", [
  "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"
].every((v, i, a) => i === 0 || cmp(a[i - 1], v) === -1))
check("build metadata is ignored", cmp("1.0.0+abc", "1.0.0+def") === 0 && cmp("1.0.0-rc.1+x", "1.0.0-rc.1") === 0)
for (const bad of ["", "1.2", "1.2.3.4", "a.b.c", "1.2.x", "01.2.3", "1.2.3-", "1.2.3-01", "1.2.3-a..b", "1.2.3 beta", "1e3.0.0",
  "9999999999.0.0", null, undefined, 5, {}, "v", "1.2.3-é"]) {
  check(`malformed ${JSON.stringify(bad)} is refused`,
    Model.parseSemver(bad) === null && cmp(bad, "1.0.0") === null && cmp("1.0.0", bad) === null)
}
check("a long string is refused", Model.parseSemver("1.2.3-" + "a".repeat(100)) === null)

// --- release JSON ----------------------------------------------------------

const rel = obj => JSON.stringify(obj)
check("latest release tag is read", Model.parseLatestRelease(rel({ tag_name: "v1.14.0" })) === "1.14.0")
check("a draft or prerelease is not the latest",
  Model.parseLatestRelease(rel({ tag_name: "v2.0.0", draft: true })) === ""
    && Model.parseLatestRelease(rel({ tag_name: "v2.0.0", prerelease: true })) === ""
    && Model.parseLatestRelease(rel({ tag_name: "v2.0.0-rc.1" })) === "")
for (const bad of ["", "not json", "null", "[]", "{}", rel({ tag_name: 5 }), rel({ tag_name: "1.2.3" }), rel({ tag_name: "vx" }),
  rel({ message: "API rate limit exceeded" }), "x".repeat(300 * 1024), null, undefined]) {
  check(`unusable release answer ${JSON.stringify(String(bad).slice(0, 24))} gives nothing`, Model.parseLatestRelease(bad) === "")
}

// --- the probe -------------------------------------------------------------

const release = { version: "1.13.0", git: true, branch: "master", commit: "abc1234", dirty: false, terminal: true }
check("probe output parses", JSON.stringify(Model.parsePluginVersionProbe(
  "version=1.13.0\nterminal=1\nbranch=master\ncommit=abc1234\ndirty=0\n")) === JSON.stringify(release))
check("a directory that is not a clone is only a version",
  JSON.stringify(Model.parsePluginVersionProbe("version=1.13.0\n")) ===
    JSON.stringify({ version: "1.13.0", git: false, branch: "", commit: "", dirty: false, terminal: false }))
const hostile = Model.parsePluginVersionProbe("version=1.0.0; rm -rf ~\nbranch=a b\ncommit=zzz\n")
check("hostile probe values are dropped", hostile.version === "" && !hostile.git && hostile.branch === "")
check("empty probe output is harmless",
  Model.parsePluginVersionProbe("").version === "" && Model.parsePluginVersionProbe(null).git === false)

check("a release build is labelled with branch and commit", Model.versionLabel(release) === "1.13.0 (master @ abc1234)")
check("a feature branch is a dev build",
  Model.versionLabel({ ...release, branch: "feat/x" }) === "dev build (branch feat/x @ abc1234)")
check("uncommitted changes are named",
  Model.versionLabel({ ...release, branch: "feat/x", dirty: true }) === "dev build (branch feat/x @ abc1234, uncommitted changes)"
    && Model.versionLabel({ ...release, dirty: true }) === "dev build (branch master @ abc1234, uncommitted changes)")
check("a detached HEAD is a dev build",
  Model.versionLabel({ ...release, branch: "HEAD" }) === "dev build (detached HEAD @ abc1234)")
check("no git shows only the version",
  Model.versionLabel({ ...release, git: false }) === "1.13.0"
    && Model.versionLabel({ ...release, git: false, version: "" }) === "unknown version")

// Run the real probe against a throwaway clone.
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-version-"))
  const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" }
  const git = args => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...args], { cwd: tmp, env, encoding: "utf8" })
  const probe = dir => {
    const argv = Model.pluginVersionProbeCommand(dir)
    return Model.parsePluginVersionProbe(execFileSync(argv[0], argv.slice(1), { env, encoding: "utf8" }))
  }
  try {
    fs.writeFileSync(path.join(tmp, "manifest.json"), '{\n  "schemaVersion": 1,\n  "version": "3.4.5"\n}\n')
    const plain = probe(tmp)
    check("probe reads the manifest version outside a repository", plain.version === "3.4.5" && !plain.git, JSON.stringify(plain))
    git(["init", "-q", "-b", "master"])
    git(["add", "manifest.json"])
    git(["commit", "-q", "-m", "x"])
    const clean = probe(tmp)
    check("probe reports a clean master clone",
      clean.git && clean.branch === "master" && !clean.dirty && Model.isReleaseBuild(clean), JSON.stringify(clean))
    fs.appendFileSync(path.join(tmp, "manifest.json"), "\n")
    check("probe sees uncommitted changes", probe(tmp).dirty === true)
    git(["checkout", "-q", "-b", "feat/x"])
    check("probe sees the branch", probe(tmp).branch === "feat/x")
    // A directory inside someone else's repository is not a clone of its own.
    const sub = path.join(tmp, "nested")
    fs.mkdirSync(sub)
    fs.writeFileSync(path.join(sub, "manifest.json"), '{\n  "version": "9.9.9"\n}\n')
    const nested = probe(sub)
    check("probe ignores an enclosing repository", nested.version === "9.9.9" && !nested.git, JSON.stringify(nested))
    const hostileDir = Model.pluginVersionProbeCommand("/x; rm -rf ~")
    check("probe takes the directory as an argument, never in the script",
      !hostileDir[2].includes("rm -rf") && hostileDir[4] === "/x; rm -rf ~")
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

// --- when to notify --------------------------------------------------------

const state = latest => ({ checkedAt: 1, latest })
check("a newer release is announced", Model.updateAvailable(release, state("1.14.0"), true) === "1.14.0")
check("a release is not announced when current or ahead",
  Model.updateAvailable(release, state("1.13.0"), true) === "" && Model.updateAvailable(release, state("1.12.0"), true) === "")
check("a dev build never gets the notice",
  Model.updateAvailable({ ...release, branch: "feat/x" }, state("9.0.0"), true) === ""
    && Model.updateAvailable({ ...release, dirty: true }, state("9.0.0"), true) === ""
    && Model.updateAvailable({ ...release, git: false }, state("9.0.0"), true) === "")
check("a version ahead of the latest release gets no notice",
  Model.updateAvailable({ ...release, version: "2.0.0-rc.1" }, state("1.14.0"), true) === "")
check("a prerelease install is offered the release it precedes",
  Model.updateAvailable({ ...release, version: "2.0.0-rc.1" }, state("2.0.0"), true) === "2.0.0")
check("switched off, nothing is announced", Model.updateAvailable(release, state("9.0.0"), false) === "")
check("malformed stored state announces nothing",
  [null, undefined, "x", 5, {}, state("junk"), state("1.14.0-rc.1")].every(v => Model.updateAvailable(release, v, true) === ""))
check("an unreadable installed version announces nothing",
  Model.updateAvailable({ ...release, version: "" }, state("9.0.0"), true) === "")

// --- once a day ------------------------------------------------------------

const DAY = 24 * 60 * 60 * 1000
const now = 1_800_000_000_000
check("never checked is due", Model.updateCheckDue(true, null, now) && Model.updateCheckDue(true, {}, now))
check("checked an hour ago is not due", !Model.updateCheckDue(true, { checkedAt: now - 3600_000 }, now))
check("checked a day ago is due",
  Model.updateCheckDue(true, { checkedAt: now - DAY }, now) && !Model.updateCheckDue(true, { checkedAt: now - DAY + 1 }, now))
check("a stored time in the future is due again", Model.updateCheckDue(true, { checkedAt: now + DAY }, now))
check("off is never due",
  !Model.updateCheckDue(false, null, now) && !Model.updateCheckDue("true", null, now) && !Model.updateCheckDue(undefined, null, now))
check("garbage state is treated as never checked",
  Model.updateCheckDue(true, { checkedAt: "soon" }, now) && Model.updateCheckDue(true, "x", now))
check("a result records the time and the release",
  JSON.stringify(Model.updateCheckRecord(null, "1.14.0", now)) === JSON.stringify({ checkedAt: now, latest: "1.14.0" }))
check("a failed check keeps the last known release and still records the time",
  JSON.stringify(Model.updateCheckRecord({ checkedAt: 5, latest: "1.14.0" }, "", now)) === JSON.stringify({ checkedAt: now, latest: "1.14.0" })
    && Model.updateCheckRecord({ latest: "evil" }, "", now).latest === "")

// --- the state file -------------------------------------------------------

check("stored state parses", JSON.stringify(Model.parseUpdateCheckState('{"checkedAt":5,"latest":"1.14.0"}')) === JSON.stringify({ checkedAt: 5, latest: "1.14.0" }))
check("a bad release in stored state is dropped, the time kept",
  Model.parseUpdateCheckState('{"checkedAt":5,"latest":"evil"}').latest === "")
for (const bad of ["", "nope", "[]", "null", '{"checkedAt":"x"}', '{"checkedAt":-1}', '{"latest":"1.0.0"}', "x".repeat(2000), null]) {
  check(`unusable stored state ${JSON.stringify(String(bad).slice(0, 20))} is null`, Model.parseUpdateCheckState(bad) === null)
}
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-state-"))
  const env = { ...process.env, XDG_STATE_HOME: tmp }
  try {
    const rd = () => { const a = Model.updateCheckReadCommand(); return execFileSync(a[0], a.slice(1), { env, encoding: "utf8" }) }
    check("reading with no state file gives nothing", Model.parseUpdateCheckState(rd()) === null)
    const w = Model.updateCheckWriteCommand()
    const rec = Model.updateCheckRecord(null, "1.14.0", 1234567)
    execFileSync(w[0], w.slice(1), { env, input: JSON.stringify(rec) })
    const file = path.join(tmp, "qs-bitwarden-cli", "update-check.json")
    check("the record round-trips through the state file", JSON.stringify(Model.parseUpdateCheckState(rd())) === JSON.stringify(rec))
    check("the state file is private", (fs.statSync(file).mode & 0o777) === 0o600 && (fs.statSync(path.dirname(file)).mode & 0o777) === 0o700)
    check("no temp file is left behind", fs.readdirSync(path.dirname(file)).join() === "update-check.json")
    fs.rmSync(file)
    fs.symlinkSync("/etc/hostname", file)
    check("a symlinked state file is not followed", rd() === "")
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

// --- the request and the action --------------------------------------------

const argv = Model.updateCheckCommand()
check("the check is curl with fixed argv, a timeout, a size cap and https only",
  argv[0] === "curl" && argv[1] === "-q" && argv.includes("--max-time") && argv.includes("--max-filesize")
    && argv.includes("=https")
    && argv[argv.length - 1] === "https://api.github.com/repos/Elevate08/qs-bitwarden-cli/releases/latest")
check("the User-Agent is generic", argv[argv.indexOf("-A") + 1] === "qs-bitwarden-cli-update-check")
check("the update command is the plugin's own id",
  Model.pluginUpdateCommandText() === "omarchy plugin update io.github.elevate08.qs-bitwarden-cli"
    && Model.PLUGIN_ID === JSON.parse(readRepo("manifest.json")).id)
check("the update runs in the floating terminal",
  Model.pluginUpdateLaunchCommand()[0] === "omarchy-launch-floating-terminal-with-presentation"
    && Model.pluginUpdateLaunchCommand()[1] === Model.pluginUpdateCommandText())

// --- the setting and its wiring -------------------------------------------

const manifest = JSON.parse(readRepo("manifest.json"))
const entry = Model.SETTINGS_SCHEMA.find(e => e.key === "checkForUpdates")
const inManifest = manifest.barWidget.schema.find(e => e.key === "checkForUpdates")
check("Check for updates is a General bool, on by default",
  !!entry && entry.group === "general" && entry.type === "bool" && entry.defaultValue === true && entry.label === "Check for updates")
check("it matches the manifest exactly",
  !!inManifest && inManifest.type === "boolean" && inManifest.defaultValue === true && inManifest.label === entry.label
    && inManifest.description === entry.description && manifest.barWidget.defaults.checkForUpdates === true)
check("it says what it discloses and that off sends nothing",
  /IP address/.test(entry.description) && /no request/.test(entry.description))
check("the stored check is not a setting, so storing it never reloads the shell",
  !("updateCheck" in manifest.barWidget.defaults) && !manifest.barWidget.schema.some(e => e.key === "updateCheck")
    && !/"updateCheck"/.test(readRepo("Service.qml")))

const service = readRepo("Service.qml")
check("the service reads the setting through boolSetting and settingValue",
  /readonly property bool checkForUpdates: Model\.boolSetting\("checkForUpdates", setting\("checkForUpdates", true\)\)/.test(service)
    && /case "checkForUpdates": return checkForUpdates/.test(service))
check("the check is stored in a state file, written from stdin",
  /Model\.updateCheckRecord\(updateCheckState, latest, Date\.now\(\)\)/.test(service)
    && /updateCheckWriteProc\.write\(JSON\.stringify\(updateCheckState\)\)/.test(service)
    && /property var updateCheckState: null/.test(service))
check("the state file is only read, and the request only made, while the setting is on",
  /if \(checkForUpdates && !updateCheckStateProc\.running/.test(service)
    && /Model\.updateCheckDue\(checkForUpdates, updateCheckState, Date\.now\(\)\)/.test(service)
    && (service.match(/updateCheckProc\.running = true/g) || []).length === 1)
check("opening settings refreshes the version", /currentScreen = "settings"\s*refreshVersionInfo\(\)/.test(service))
check("the plugin directory comes from the QML URL",
  /Model\.pluginDirFromUrl\(String\(Qt\.resolvedUrl\("\."\)\)\)/.test(service))

const panel = readPluginSource("Panel.qml")
check("the settings screen shows version, bw version and the notice",
  /text: "VERSION"/.test(panel) && /root\.pluginVersionLabel/.test(panel) && /dependencies\.bwVersion/.test(panel)
    && /"Update available: " \+ root\.updateAvailableVersion/.test(panel) && /runPluginUpdate\(\)/.test(panel))
check("with no terminal helper the command is shown instead",
  /!root\.pluginUpdateCanLaunch/.test(panel) && /"Run: " \+ root\.pluginUpdateCommandText/.test(panel))

done()
