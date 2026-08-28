#!/usr/bin/env node
// A release is where this repository's committed binary stops being an
// internal claim and becomes something other people install. These tests guard
// the parts of that path which fail quietly: an elevated permission that leaks
// out of the one job meant to hold it, an action pinned to a moving tag, a
// publication that never re-checked the bytes it publishes, or a release whose
// version agrees with nothing.
//
// They do not run a release. What can be checked here is that the definition
// grants the least it can, verifies before it publishes, and says out loud
// what its artifacts are and are not.
//
//   node tests/release-provenance.test.js

const fs = require("fs")
const path = require("path")

const repoRoot = path.join(__dirname, "..")
const read = p => fs.readFileSync(path.join(repoRoot, p), "utf8")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)

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
check("only a tag reaches the publishing job",
  /if: github\.ref_type == 'tag'/.test(jobs.get("release") || ""),
  "a dispatch run could publish a release or sign an attestation")
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
check("nothing publishes before those gates pass",
  /needs: gates/.test(jobs.get("verify") || "") && /needs: verify/.test(jobs.get("release") || ""),
  "the publishing job does not depend on verification")

// -------------------------------------------------------------------------
// What the release verifies about itself
// -------------------------------------------------------------------------

const verify = jobs.get("verify") || ""
check("the tag, the manifest and the changelog must agree",
  /manifest\.json says/.test(verify) && /CHANGELOG\.md has no/.test(verify),
  "a tag could name a version nothing else in the repository claims")
check("the committed checksum is re-checked against the committed bytes",
  (release.match(/sha256sum -c SHA256SUMS/g) || []).length >= 2,
  "the binary and the checksum shipped beside it are never compared at release time")
check("the helper's reported versions are checked against the panel's",
  /SSH_AGENT_CONTROL_VERSION/.test(verify) && /control protocol/.test(verify),
  "a protocol bump could ship to users and disable the feature at launch")
check("the shipped binary is executed, not merely compiled",
  /--self-test/.test(verify), "nothing runs the bytes being released")

const releaseJob = jobs.get("release") || ""
check("the release job runs the bytes outside the build container",
  !/container:/.test(releaseJob) && /--self-test/.test(releaseJob),
  "a binary that only works inside its own build image would still be published")
check("the attestation names the shipped binary as its subject",
  /attest-build-provenance@[0-9a-f]{40}[\s\S]{0,300}?subject-path: bin\/x86_64-linux\/qs-bitwarden-ssh-agent/
    .test(releaseJob),
  "the provenance attestation does not bind the tracked bytes")
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
  /only-keep-debug/.test(verify) && /\.debug/.test(verify),
  "a stripped binary ships with no way to debug it at all")
// The release profile strips symbols, and a debug build links differently --
// its entry point and code layout move. Publishing the file is fine.
// Implying it maps onto the shipped bytes would not be.
check("the debug symbols say plainly that they are not the shipped bytes",
  /DEBUG-SYMBOLS\.md/.test(verify) && /not[\s\S]{0,80}split of the shipped binary/i.test(verify),
  "the symbol file invites address-level conclusions it cannot support")
check("release artifacts are scanned for key material before publication",
  /PRIVATE KEY/.test(verify) && /BW_SESSION/.test(verify),
  "nothing checks that a report or symbol file is free of secrets")
check("the release notes are the changelog section for this version",
  /release-notes\.md/.test(releaseJob) && /no changelog section for/.test(releaseJob),
  "a release could publish empty notes or the entire changelog")

// -------------------------------------------------------------------------
// Who has to look at it
// -------------------------------------------------------------------------

check("the release workflow requires code-owner review",
  /release\.yml/.test(owners) || /^\/\.github\/\s+@/m.test(owners),
  "the one workflow that can publish is not owned by anyone")
check("the binary, its build script and the agent source stay owned",
  /^\/bin\/\s+@/m.test(owners) && /build-agent\.sh\s+@/m.test(owners) && /^\/agent\/\s+@/m.test(owners),
  "a change to the trust path could merge without review")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`release-provenance: ${pass} passed`)
