#!/usr/bin/env node
// The release path: elevated permissions confined to one job, actions pinned,
// bytes re-checked before publishing, versions that agree. No release is run:
// the definition is checked, and the publishing steps' shell is run on fixtures.
//
//   node tests/release-provenance.test.js

const { createSuite, read } = require("./harness")
const path = require("path")


const { check, done } = createSuite("release-provenance")

const release = read(".github/workflows/release.yml")
const build = read(".github/workflows/agent-build.yml")
const owners = read(".github/CODEOWNERS")

// Split the file into its jobs, so a question like "which job can write" has
// a per-job answer rather than a whole-file one. Grepping the whole workflow
// for `id-token: write` would pass just as happily if every job had it.
const jobsBody = release.slice(release.indexOf("\njobs:"))
const jobs = new Map(
  [...jobsBody.matchAll(/^ {2}([a-z][a-z0-9-]*):\n([\s\S]*?)(?=^ {2}[a-z][a-z0-9-]*:\n|$(?![\s\S]))/gm)]
    .map(([, name, body]) => [name, body]))

const symbols = jobs.get("symbols") || ""

check("the workflow defines the three stages it describes",
  ["gates", "verify", "release"].every(j => jobs.has(j)),
  `jobs found: ${[...jobs.keys()].join(", ")}`)

// -------------------------------------------------------------------------
// What triggers it, and what cannot
// -------------------------------------------------------------------------

check("a release is a tag, not a branch push",
  /on:\n(?:.*\n)*?\s*push:\n\s*tags:\n\s*- 'v\*'/.test(release) && !/^\s*branches:/m.test(release),
  "the release workflow runs on something other than a version tag")
check("a dispatch run can rehearse the whole path",
  /workflow_dispatch:/.test(release),
  "verification cannot be run without creating a tag")
check("only a v* tag reaches the publishing job",
  /^ {4}if: github\.ref_type == 'tag' && startsWith\(github\.ref_name, 'v'\)$/m.test(jobs.get("release") || "")
    && /steps:\n {6}- name: [^\n]*\n(?: {8}#[^\n]*\n)* {8}env:\n {10}TAG: \$\{\{ github\.ref_name \}\}\n {8}run: \|\n {10}case "\$TAG" in\n {12}v\[0-9\]\*\) ;;\n {12}\*\)\n[^\n]*\n {14}exit 1/.test(jobs.get("release") || ""),
  "a dispatch run on a branch or another tag could publish a release or sign an attestation")
check("a release in flight is never cancelled",
  /concurrency:[\s\S]{0,200}?cancel-in-progress: false/.test(release),
  "a second tag could cancel a half-published release")

// -------------------------------------------------------------------------
// Least privilege, and where it stops
// -------------------------------------------------------------------------

const topLevel = release.slice(0, release.indexOf("\njobs:"))
check("the workflow is read-only by default",
  /^permissions:\n\s*contents: read\s*$/m.test(topLevel),
  "the default token carries more than read")

const elevated = ["contents: write", "id-token: write", "attestations: write"]
for (const grant of elevated) {
  const holders = [...jobs].filter(([, body]) => body.includes(grant)).map(([name]) => name)
  check(`only the release job holds ${grant}`,
    holders.length === 1 && holders[0] === "release",
    `held by: ${holders.join(", ") || "nobody"}`)
}
check("the gates and verify jobs state their read-only scope rather than inheriting it",
  /permissions:\n\s*contents: read/.test(jobs.get("gates") || "")
    && /permissions:\n\s*contents: read/.test(jobs.get("verify") || ""),
  "a later change to the default would silently widen these jobs")
check("the elevated job runs behind an environment",
  /environment:\n\s*name: release/.test(jobs.get("release") || ""),
  "elevated credentials come into existence with no approval step")
check("no secret is referenced",
  !/secrets\./.test(release),
  "a release should need nothing beyond the job's own token")

// A tag is a moving pointer, and this is the workflow that mints signing
// credentials. Same argument as pinning the build image by digest, applied to
// the code that runs the release.
const actionUses = [...release.matchAll(/uses:\s*([^\s@]+)@(\S+)/g)]
  .filter(([, name]) => !name.startsWith("./"))
check("every third-party action is pinned to a full commit SHA",
  actionUses.length > 0 && actionUses.every(([, , ref]) => /^[0-9a-f]{40}$/.test(ref)),
  actionUses.filter(([, , ref]) => !/^[0-9a-f]{40}$/.test(ref)).map(m => m[0]).join(", ") || "no actions used")
check("each pin says which release it is, for a human",
  (release.match(/@[0-9a-f]{40} # v\d/g) || []).length === actionUses.length,
  "a bare SHA tells a reviewer nothing about what version it is")

// -------------------------------------------------------------------------
// The gates are the branch's gates
// -------------------------------------------------------------------------

check("the release calls the branch's gates instead of copying them",
  /uses: \.\/\.github\/workflows\/agent-build\.yml/.test(jobs.get("gates") || ""),
  "the release re-implements the checks, so the two can drift apart")
check("the branch workflow is callable",
  /^\s*workflow_call:/m.test(build),
  "release.yml calls a workflow that does not accept being called")
// The gates run inside the release, so their concurrency group is scoped by
// workflow too; by ref alone a branch build and a release could cancel each
// other.
check("a branch build and a release cannot cancel each other",
  /group: agent-build-\$\{\{ github\.workflow \}\}/.test(build)
    && /cancel-in-progress: \$\{\{ github\.workflow != 'release' \}\}/.test(build),
  "the called workflow's concurrency group does not distinguish its callers")
// A bare branch cut skips the branch build (its tree already passed), but the
// skip must name this workflow: called from release.yml on a tag push, the
// event is also a `created` push with no new commits, and the gates must run.
const buildJobs = [...build.slice(build.indexOf("\njobs:"))
  .matchAll(/^ {2}([a-z][a-z0-9-]*):\n([\s\S]*?)(?=^ {2}[a-z][a-z0-9-]*:\n|$(?![\s\S]))/gm)]
const branchCutSkip = "if: ${{ !(github.workflow == 'agent build' && github.event_name == 'push' && github.event.created && github.event.commits[0] == null) }}"
const unskipped = buildJobs.filter(([, , body]) => !body.includes(branchCutSkip)).map(([, name]) => name)
check("only a bare branch cut skips the branch build, never the release's gates",
  buildJobs.length >= 5 && unskipped.length === 0,
  `jobs without the exact skip condition: ${unskipped.join(", ") || "(no jobs found)"}`)
// The reviewer path (REVIEWING.md): a plain runner, no container and no Rust,
// so build-agent.sh has to re-enter the pinned image itself.
const reviewerJob = (buildJobs.find(([, name]) => name === "reviewer-rebuild") || [])[2] || ""
check("CI runs the reviewers' rebuild through the container re-exec",
  /runs-on: ubuntu-24\.04\n/.test(reviewerJob) && !/container:/.test(reviewerJob)
    && /if: github\.event_name != 'pull_request'\n\s*run: scripts\/verify-helpers\.sh --rebuild --arch x86_64\n/.test(reviewerJob)
    && !/QSBW_PINNED_BUILD/.test(reviewerJob)
    && /permissions:\n\s*contents: read/.test(reviewerJob)
    && /persist-credentials: false/.test(reviewerJob) && /timeout-minutes: \d+/.test(reviewerJob),
  "nothing in CI exercises the rebuild path REVIEWING.md tells reviewers to run")
check("the end-to-end job retries a stalled Arch snapshot download",
  /for attempt in 1 2 3; do\s*\n\s*pacman -Syu --noconfirm --needed --disable-download-timeout/.test(build),
  "one slow response from archive.archlinux.org fails the whole gate")
check("the panel tests job retries a failed apt index update",
  /for attempt in 1 2 3; do\s*\n\s*sudo apt-get update -o APT::Update::Error-Mode=any -o Acquire::Retries=3 && break/.test(build),
  "one 429 from a runner mirror fails the whole gate")
check("nothing publishes before those gates pass",
  /needs: gates/.test(jobs.get("verify") || "") && /needs: gates/.test(symbols)
    && /needs: \[verify, symbols, host-run\]/.test(jobs.get("release") || ""),
  "the publishing job does not depend on verification")

// -------------------------------------------------------------------------
// What the release verifies about itself
// -------------------------------------------------------------------------

const verify = jobs.get("verify") || ""
check("the tag, the manifest and the changelog must agree",
  /manifest\.json says/.test(verify) && /CHANGELOG\.md has no/.test(verify),
  "a tag could name a version nothing else in the repository claims")
// The checksum file sits beside the binaries, so the publishing job first
// holds it to the digest verify recorded in its own checkout, carried as a
// job output; then the binaries to it.
check("the bytes to attest are checked against the digest verify recorded, then SHA256SUMS",
  /sha256sum -c SHA256SUMS/.test(verify)
    && /id: bytes\n[\s\S]*?sums="\$\(sha256sum bin\/SHA256SUMS\)"\n[\s\S]*?\[\[ "\$sums" =~ \^\[0-9a-f\]\{64\}\$ \]\] \|\| \{[\s\S]*?echo "sums_sha256=\$sums" >> "\$GITHUB_OUTPUT"/.test(verify)
    && /outputs:\n(?:\s*#[^\n]*\n)*\s*sums_sha256: \$\{\{ steps\.bytes\.outputs\.sums_sha256 \}\}/.test(verify)
    && /SUMS_SHA256: \$\{\{ needs\.verify\.outputs\.sums_sha256 \}\}\n[\s\S]*?\[\[ "\$SUMS_SHA256" =~ \^\[0-9a-f\]\{64\}\$ \]\] \|\|[\s\S]*?echo "\$SUMS_SHA256  bin\/SHA256SUMS" \| sha256sum -c -\n\s*\( cd bin && sha256sum -c SHA256SUMS \)/.test(jobs.get("release") || "")
    && (jobs.get("release") || "").indexOf("sha256sum -c -") < (jobs.get("release") || "").indexOf("attest-build-provenance@")
    && /path: \$\{\{ runner\.temp \}\}\/dist/.test(jobs.get("release") || ""),
  "what is attested is only compared with a file in the same checkout")
const hostRun = jobs.get("host-run") || ""
check("the helper's reported versions are checked against the panel's",
  /SSH_AGENT_CONTROL_VERSION/.test(hostRun) && /control protocol/.test(hostRun)
    && /UNLOCK_KEY_ENVELOPE_VERSION/.test(hostRun) && /VAULT_HELPER_PROTOCOL/.test(hostRun),
  "a protocol bump could ship to users and disable the feature at launch")
check("the shipped binary is executed, not merely compiled",
  /--self-test/.test(hostRun), "nothing runs the bytes being released")
check("every architecture's bytes run on a runner of that architecture",
  /- arch: x86_64\s*\n\s*runner: ubuntu-24\.04\s*\n/.test(hostRun) && /- arch: aarch64\s*\n\s*runner: ubuntu-24\.04-arm\s*\n/.test(hostRun)
    && /bin\/\$ARCH-linux\/qs-bitwarden-vault/.test(hostRun),
  "an architecture's helpers are published without ever being run")
check("verify checks every architecture's bytes, machine and checksum line",
  /"x86_64:x86-64" "aarch64:ARM aarch64"/.test(verify) && /has no line for/.test(verify),
  "an architecture's binaries are not checked against SHA256SUMS")
// A container job defaults to `sh`, which has no arrays.
check("the container job declares bash rather than taking the image's sh",
  /defaults:\n\s*run:\n(?:\s*#[^\n]*\n)*\s*shell: bash/.test(verify),
  "a bashism in a container step fails at the end of a long job")

const releaseJob = jobs.get("release") || ""
// The shipped bytes run in host-run: a plain runner, no container, no write
// token, so nothing a helper does can reach the release token.
const hostRunJob = jobs.get("host-run") || ""
check("the shipped bytes run on a plain runner outside the build container",
  !/container:/.test(hostRunJob) && /--self-test/.test(hostRunJob) && /needs: verify/.test(hostRunJob),
  "a binary that only works inside its own build image would still be published")
check("the job that runs the shipped bytes holds no write token",
  !/contents: write|id-token: write|attestations: write/.test(hostRunJob)
    && /persist-credentials: false/.test(hostRunJob),
  "a helper executed beside a write token could steal it")
check("the publishing job does not execute the bytes it attests",
  !/--self-test/.test(releaseJob),
  "the release token would sit beside code the helpers run")
// Every shipped binary is a subject. An attestation that covers one of two
// leaves the other with no provenance behind it -- and the README tells users
// to verify both.
const attestation = /attest-build-provenance@[0-9a-f]{40}[\s\S]{0,500}?subject-path: \|?([\s\S]*?)\n\s*\n/
  .exec(releaseJob)
for (const arch of ["x86_64", "aarch64"]) {
  for (const binary of ["qs-bitwarden-ssh-agent", "qs-bitwarden-unlock-key", "qs-bitwarden-vault"]) {
    check(`the attestation names ${arch}-linux/${binary} as a subject`,
      !!attestation && attestation[1].includes(`bin/${arch}-linux/${binary}`),
      "the provenance attestation does not bind these tracked bytes")
  }
}
check("the verification command is written down where a reviewer will find it",
  /gh attestation verify/.test(release),
  "users are given provenance with no documented way to check it")

// -------------------------------------------------------------------------
// What the release publishes
// -------------------------------------------------------------------------

check("an SBOM is published", /cyclonedx/.test(verify), "no SBOM is produced")
check("a dependency and licence report is published",
  /cargo deny[\s\S]{0,140}?\blist\b/.test(verify) && /cargo tree/.test(verify),
  "users cannot see what is in the binary or under what terms")
check("debug symbols are published separately from the shipped bytes",
  /only-keep-debug/.test(symbols) && /\.debug/.test(symbols)
    && /- arch: aarch64\s*\n\s*runner: ubuntu-24\.04-arm/.test(symbols),
  "a stripped binary ships with no way to debug it at all")
check("the symbols job holds no write token",
  !/write/.test(symbols), "the companion build runs beside a write token")
// The release profile strips symbols, and a debug build links differently --
// its entry point and code layout move. Publishing the file is fine.
// Implying it maps onto the shipped bytes would not be.
check("the debug symbols say plainly that they are not the shipped bytes",
  /DEBUG-SYMBOLS\.md/.test(symbols) && /not[\s\S]{0,80}split of the shipped binary/i.test(symbols),
  "the symbol file invites address-level conclusions it cannot support")
check("release artifacts are scanned for key material before publication",
  /PRIVATE KEY/.test(releaseJob) && /BW_SESSION/.test(releaseJob)
    && releaseJob.indexOf("Refuse to publish anything that looks like key material") < releaseJob.indexOf("gh release create"),
  "nothing checks that a report or symbol file is free of secrets")
// The published release is what a reviewer sees, so it says how to check the
// helpers: the gates run that rebuilt them, the attestation command, the
// local script. Written after the changelog section, with the run link and
// repository passed through env rather than expanded into the script.
const publishStep = releaseJob.slice(releaseJob.indexOf("- name: Publish the release"))
const notesSection = /section="\$\(cat <<'EOF'\n([\s\S]*?)\n\s*EOF\n/.exec(publishStep)
const notesText = notesSection ? notesSection[1] : ""
check("the release notes carry a section on verifying the helpers",
  /^\s*## Verifying the helpers$/m.test(notesText)
    && publishStep.indexOf("CHANGELOG.md > \"$dist/release-notes.md\"") < publishStep.indexOf("## Verifying the helpers")
    && /printf '\\n%s\\n' "\$section" >> "\$notes"/.test(publishStep)
    && publishStep.indexOf(">> \"$notes\"") < publishStep.indexOf("gh release create"),
  "a reviewer of the published release is not told how to check the bundled binaries")
check("the notes link the gates run that rebuilt the helpers on both architectures",
  /\[`gates` run\]\(@RUN_URL@\)/.test(notesText) && /x86_64/.test(notesText) && /aarch64/.test(notesText)
    && /RUN_URL: \$\{\{ github\.server_url \}\}\/\$\{\{ github\.repository \}\}\/actions\/runs\/\$\{\{ github\.run_id \}\}/.test(publishStep)
    && /section="\$\{section\/\/@RUN_URL@\/\$RUN_URL\}"/.test(publishStep),
  "the notes claim a reproducible rebuild without pointing at the run that did it")
check("the notes give the attestation command and the local verification script",
  /gh attestation verify bin\/<arch>-linux\/<name> --repo @REPO@/.test(notesText)
    && /REPO: \$\{\{ github\.repository \}\}/.test(publishStep)
    && /section="\$\{section\/\/@REPO@\/\$REPO\}"/.test(publishStep)
    && /scripts\/verify-helpers\.sh --attestations/.test(notesText)
    && /scripts\/verify-helpers\.sh --rebuild/.test(notesText)
    && /REVIEWING\.md/.test(notesText)
    && /SHA256SUMS/.test(notesText),
  "the notes do not say how to check the attestations or repeat the rebuild")
check("no expression is expanded inside the notes text",
  notesSection !== null && !/\$\{\{/.test(notesText),
  "a workflow expression in the script body is injected as shell source")

// -------------------------------------------------------------------------
// The publishing shell, run
// -------------------------------------------------------------------------
//
// The steps that decide what is uploaded and what goes public are taken out
// of the two workflows and run here, against fixture artifact directories, a
// scratch git remote and a stub `gh` that records its calls.

const fs = require("fs")
const os = require("os")
const { spawnSync } = require("child_process")

const publisher = read(".github/workflows/publish-on-master.yml")
// The `run: |` body of the step with that name.
function stepShell(workflow, name) {
  const lines = workflow.slice(workflow.indexOf(`      - name: ${name}\n`)).split("\n")
  const from = lines.indexOf("        run: |") + 1
  let to = from
  while (to < lines.length && (lines[to] === "" || lines[to].startsWith("          "))) to++
  return lines.slice(from, to).map(line => line.slice(10)).join("\n")
}
const listingShell = stepShell(release, "Only the files this workflow makes may be published")
const publishShell = stepShell(release, "Publish the release")
const publisherShell = stepShell(publisher, "Publish the release this merge brought in")

// What a release holds, written out here and not read from the workflows.
const HELPERS = ["qs-bitwarden-ssh-agent", "qs-bitwarden-unlock-key", "qs-bitwarden-vault"]
const ARCHES = ["x86_64", "aarch64"]
const PACKAGES = ["", "unlock-key-", "vault-"]
const artifacts = {
  "release-reports": [
    ...PACKAGES.map(p => `${p}dependency-licences.json`),
    ...ARCHES.flatMap(a => PACKAGES.map(p => `${p}dependency-tree-${a}-linux.txt`)),
    ...ARCHES.flatMap(a => HELPERS.map(h => `${h}-${a}-linux.cdx.json`))],
  "release-symbols-x86_64": ["DEBUG-SYMBOLS.md", ...HELPERS.map(h => `${h}-x86_64-linux.debug.gz`)],
  "release-symbols-aarch64": HELPERS.map(h => `${h}-aarch64-linux.debug.gz`),
}
const ASSETS = ["SHA256SUMS", ...ARCHES.flatMap(a => HELPERS.map(h => `${h}-${a}-linux`)),
  ...Object.values(artifacts).flat()].sort()

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-release-"))
const stubs = path.join(scratch, "stubs")
fs.mkdirSync(stubs)
fs.writeFileSync(path.join(stubs, "gh"), `#!/usr/bin/env node
const fs = require("fs"), args = process.argv.slice(2)
fs.appendFileSync(process.env.GH_LOG, JSON.stringify(args) + "\\n")
if (args[0] === "api") {
  if (!fs.existsSync(process.env.GH_RELEASES)) { console.error("gh: Server Error (HTTP 502)"); process.exit(1) }
  process.stdout.write(fs.readFileSync(process.env.GH_RELEASES))
} else if (args[0] !== "release") process.exit(3)
`, { mode: 0o755 })
const baseEnv = {
  PATH: `${stubs}:${process.env.PATH}`, HOME: scratch, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.invalid", GH_TOKEN: "x", REPO: "o/r", RUN_URL: "https://example.invalid/run",
  GH_LOG: path.join(scratch, "gh.log"), GH_RELEASES: path.join(scratch, "releases.json"),
}
const sh = (script, cwd, env = {}, flags = "-e") =>
  spawnSync("bash", ["--noprofile", "--norc", flags, "-c", script], { cwd, env: { ...baseEnv, ...env }, encoding: "utf8" })
const git = (cwd, ...args) => {
  const run = spawnSync("git", args, { cwd, env: baseEnv, encoding: "utf8" })
  if (run.status !== 0) throw new Error(`git ${args.join(" ")}: ${run.stderr}`)
  return run.stdout.trim()
}

// The tagged checkout: v9.9.9, annotated as this repository's tags are, on a
// commit that master then moves past with a different asset list, so a
// publisher that read the list from master and not from the built commit
// would refuse the draft.
const origin = path.join(scratch, "origin.git")
const checkout = path.join(scratch, "checkout")
git(scratch, "init", "-q", "--bare", "-b", "master", origin)
git(scratch, "init", "-q", "-b", "master", checkout)
fs.mkdirSync(path.join(checkout, ".github"))
fs.writeFileSync(path.join(checkout, ".github/release-assets.txt"), read(".github/release-assets.txt"))
for (const arch of ARCHES) {
  fs.mkdirSync(path.join(checkout, "bin", `${arch}-linux`), { recursive: true })
  for (const helper of HELPERS) fs.writeFileSync(path.join(checkout, "bin", `${arch}-linux`, helper), `${helper} ${arch}\n`)
}
fs.writeFileSync(path.join(checkout, "bin/SHA256SUMS"), "sums\n")
fs.writeFileSync(path.join(checkout, "CHANGELOG.md"), "# Changelog\n\n## [9.9.9] - today\n\n- This release.\n\n## [9.9.8]\n\n- The one before.\n")
git(checkout, "add", "-A")
git(checkout, "commit", "-q", "-m", "release")
const built = git(checkout, "rev-parse", "HEAD")
git(checkout, "tag", "-a", "v9.9.9", "-m", "v9.9.9")
// A commit on master with the built commit's files, which the tag does not name.
git(checkout, "commit", "-q", "--allow-empty", "-m", "same files")
const untagged = git(checkout, "rev-parse", "HEAD")
fs.writeFileSync(path.join(checkout, ".github/release-assets.txt"), "checkout SHA256SUMS\nrelease-reports next-release.json\n")
git(checkout, "commit", "-q", "-a", "-m", "the next release's list")
const later = git(checkout, "rev-parse", "HEAD")
git(checkout, "remote", "add", "origin", origin)
git(checkout, "push", "-q", "origin", "master", "v9.9.9")
git(checkout, "checkout", "-q", "--detach", "v9.9.9")

const runnerTemp = path.join(scratch, "temp")
// The run's artifacts as download-artifact leaves them, then the listing step.
function listing(change = () => {}) {
  fs.rmSync(runnerTemp, { recursive: true, force: true })
  for (const [artifact, files] of Object.entries(artifacts)) {
    fs.mkdirSync(path.join(runnerTemp, "dist", artifact), { recursive: true })
    for (const file of files) fs.writeFileSync(path.join(runnerTemp, "dist", artifact, file), `${file}\n`)
  }
  change(path.join(runnerTemp, "dist"))
  return sh(listingShell, runnerTemp, { GITHUB_WORKSPACE: checkout })
}
// The draft's body is the notes the publish step wrote, as the API would
// hand them back; `marked` is a body recording some other commit.
let draftBody = ""
const marked = sha => `Notes.\n\n<!-- built-from: ${sha} -->\n`
const releaseEntry = (fields = {}) => ({
  tag_name: "v9.9.9", draft: true, body: draftBody,
  assets: ASSETS.map(name => ({ name, state: "uploaded" })), ...fields })
// What `gh api` answers: one page per array, or a failed call for null.
function serverHolds(...pages) {
  fs.rmSync(baseEnv.GH_RELEASES, { force: true })
  if (pages[0] !== null) fs.writeFileSync(baseEnv.GH_RELEASES, pages.map(page => JSON.stringify(page)).join("\n"))
  fs.writeFileSync(baseEnv.GH_LOG, "")
}
const ghCalls = verb => fs.readFileSync(baseEnv.GH_LOG, "utf8").split("\n").filter(Boolean).map(line => JSON.parse(line))
  .filter(args => args[0] === "release" && verb.includes(args[1]))
const runPublish = (sha = built) =>
  sh(publishShell, checkout, { RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: checkout, TAG: "v9.9.9", GITHUB_SHA: sha })
const uploaded = call => call.filter((arg, at) => arg.startsWith(runnerTemp) && call[at - 1] !== "--notes-file")
  .map(arg => path.basename(arg)).sort()
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

const listed = listing()
serverHolds([{ tag_name: "v9.9.8", draft: false, body: marked(built), assets: [] }])
const first = runPublish()
const created = ghCalls(["create", "upload"])
const createArgs = created.length === 1 ? created[0] : []
const notesAt = createArgs[createArgs.indexOf("--notes-file") + 1] || "/nonexistent"
const notes = fs.existsSync(notesAt) ? fs.readFileSync(notesAt, "utf8") : ""
draftBody = notes
serverHolds([releaseEntry()])
const rerun = runPublish()
const refilled = ghCalls(["create", "upload"])
check("a tagged run makes a draft of exactly the 29 assets, and a re-run refills that draft",
  listed.status === 0 && first.status === 0 && ASSETS.length === 29
    && createArgs[1] === "create" && createArgs[2] === "v9.9.9" && same(uploaded(createArgs), ASSETS)
    && createArgs.includes("--draft") && createArgs.includes("--verify-tag")
    && !createArgs.includes("--target") && notes.endsWith(`\n<!-- built-from: ${built} -->\n`)
    && notes.split("built-from:").length === 2
    && ARCHES.every(a => HELPERS.every(h =>
      fs.readFileSync(path.join(runnerTemp, "dist", `${h}-${a}-linux`), "utf8") === `${h} ${a}\n`))
    && /- This release\./.test(notes) && !/The one before/.test(notes) && /## Verifying the helpers/.test(notes)
    && rerun.status === 0 && refilled.length === 1 && refilled[0][1] === "upload"
    && same(uploaded(refilled[0]), ASSETS) && refilled[0].includes("--clobber"),
  `listing ${listed.status}, publish ${first.status} ${first.stderr}, calls ${JSON.stringify(created.map(c => c.slice(0, 3)))}, re-run ${rerun.status} ${rerun.stderr}`)

const badListings = {
  "a file more": dist => fs.writeFileSync(path.join(dist, "release-reports", "install.txt"), "x"),
  "a file fewer": dist => fs.rmSync(path.join(dist, "release-symbols-aarch64", `${HELPERS[0]}-aarch64-linux.debug.gz`)),
  "an artifact more": dist => fs.mkdirSync(path.join(dist, "release-extra")),
  "a link for a file": dist => {
    fs.rmSync(path.join(dist, "release-reports", "dependency-licences.json"))
    fs.symlinkSync("/etc/hostname", path.join(dist, "release-reports", "dependency-licences.json"))
  },
  "one artifact's file in another": dist =>
    fs.renameSync(path.join(dist, "release-symbols-x86_64", "DEBUG-SYMBOLS.md"), path.join(dist, "release-symbols-aarch64", "DEBUG-SYMBOLS.md")),
}
const passedListings = Object.entries(badListings).filter(([, change]) => listing(change).status === 0).map(([name]) => name)
check("artifacts that are not exactly the workflow's own stop the release",
  passedListings.length === 0, `accepted: ${passedListings.join(", ")}`)

listing()
const refusals = {
  "a published release": [[releaseEntry({ draft: false })], built],
  "a tag that names another commit": [[], later],
  "a draft made for another commit": [[releaseEntry({ body: marked(later) })], built],
  "a draft whose notes name two commits": [[releaseEntry({ body: marked(built) + marked(built) })], built],
  "a draft holding another asset": [[releaseEntry({ assets: [{ name: "install.txt", state: "uploaded" }] })], built],
  "a draft whose assets cannot be read": [[releaseEntry({ assets: null })], built],
  "two releases for the tag": [[releaseEntry(), releaseEntry()], built],
  "a failed lookup": [null, built],
}
const wrote = Object.entries(refusals).filter(([, [page, sha]]) => {
  serverHolds(page)
  return runPublish(sha).status === 0 || ghCalls(["create", "upload", "edit"]).length > 0
}).map(([name]) => name)
check("the publish step uploads nothing to a release it should not touch",
  wrote.length === 0, `uploaded despite: ${wrote.join(", ")}`)

// master: a clone at the later commit, as actions/checkout leaves it.
const master = path.join(scratch, "master")
git(scratch, "clone", "-q", origin, master)
function publisherStep() {
  fs.writeFileSync(path.join(scratch, "output"), "")
  return sh(publisherShell, master, { RUNNER_TEMP: scratch, BEFORE: "", GITHUB_OUTPUT: path.join(scratch, "output") }, "-e")
}
serverHolds([releaseEntry()])
const goesPublic = publisherStep()
const edits = ghCalls(["edit"])
const announced = fs.readFileSync(path.join(scratch, "output"), "utf8")
serverHolds([releaseEntry({ draft: false })])
const alreadyPublic = publisherStep()
check("master takes a draft public when its tag, commit and assets are the built ones, and only then edits it",
  goesPublic.status === 0 && edits.length === 1 && same(edits[0], ["release", "edit", "v9.9.9", "--draft=false"])
    && /^tags=v9\.9\.9$/m.test(announced)
    && alreadyPublic.status === 0 && ghCalls(["edit"]).length === 0,
  `status ${goesPublic.status} ${goesPublic.stderr}, edits ${JSON.stringify(edits)}`)

const without = name => ASSETS.filter(asset => asset !== name).map(asset => ({ name: asset, state: "uploaded" }))
const unpublishable = {
  "an asset more": [releaseEntry({ assets: [...releaseEntry().assets, { name: "install.txt", state: "uploaded" }] })],
  "an asset fewer": [releaseEntry({ assets: without("SHA256SUMS") })],
  "an upload cut short": [releaseEntry({ assets: [...without("SHA256SUMS"), { name: "SHA256SUMS", state: "starter" }] })],
  "no recorded commit": [releaseEntry({ body: "Notes.\n" })],
  "two recorded commits": [releaseEntry({ body: draftBody + marked(later) })],
  "a tag that names another commit than the built one": [releaseEntry({ body: marked(untagged) })],
  "two drafts for the tag": [releaseEntry(), releaseEntry()],
  "a failed lookup": null,
}
const wentPublic = Object.entries(unpublishable).filter(([, page]) => {
  serverHolds(page)
  return publisherStep().status === 0 || ghCalls(["edit", "create", "upload"]).length > 0
}).map(([name]) => name)
check("master does not take a draft public when the server's state is not what was built",
  wentPublic.length === 0, `published despite: ${wentPublic.join(", ")}`)

fs.rmSync(scratch, { recursive: true, force: true })

// -------------------------------------------------------------------------
// Who has to look at it
// -------------------------------------------------------------------------

check("the release workflow requires code-owner review",
  /release\.yml/.test(owners) || /^\/\.github\/\s+@/m.test(owners),
  "the one workflow that can publish is not owned by anyone")
check("the binary, its build script and the agent source stay owned",
  /^\/bin\/\s+@/m.test(owners) && /build-agent\.sh\s+@/m.test(owners) && /^\/agent\/\s+@/m.test(owners),
  "a change to the trust path could merge without review")

done()
