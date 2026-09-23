#!/usr/bin/env node
// Guards the reproducible-build definition of the committed helpers: pinned
// digests that agree, an image pinned by digest, no unsupported
// reproducibility claims, and an enforced toolchain pin. No build is run (it
// needs a container); only that the definition is coherent.
//
//   node tests/ssh-agent-artifact.test.js

const { createSuite, read, repoRoot } = require("./harness")
const path = require("path")
const { spawnSync } = require("child_process")


const { check, eq, done } = createSuite("ssh-agent-artifact")

const script = read("scripts/build-agent.sh")
const workflow = read(".github/workflows/agent-build.yml")
const cargoConfig = read("agent/.cargo/config.toml")
const toolchain = read("agent/rust-toolchain.toml")

// -------------------------------------------------------------------------
// The pinned environment is pinned, and pinned to the same thing everywhere
// -------------------------------------------------------------------------

const DIGEST_RE = /rust:([0-9.]+)-(\w+)@(sha256:[0-9a-f]{64})/g
const scriptPin = /PINNED_IMAGE="rust:([0-9.]+)-(\w+)@(sha256:[0-9a-f]{64})"/.exec(script)
check("the build script pins an image by digest", !!scriptPin,
  "no digest-pinned PINNED_IMAGE; a tag is a moving pointer")

const workflowPins = [...workflow.matchAll(DIGEST_RE)]
check("every workflow job pins its container by digest", workflowPins.length >= 1,
  "no digest-pinned container image in the workflow")

if (scriptPin && workflowPins.length) {
  const unique = new Set(workflowPins.map(m => m[3]))
  eq("the workflow pins exactly one image digest", unique.size, 1)
  // Drift between these two is the failure this file mainly exists to catch:
  // CI would keep passing while the documented local build produced other bytes.
  check("the script and the workflow pin the same digest",
    unique.has(scriptPin[3]),
    `script ${scriptPin[3]} vs workflow ${[...unique].join(", ")}`)
}

// An image referenced anywhere by tag alone defeats the point.
const looseTag = /image:\s*rust:[0-9.]+-\w+\s*$/m.test(workflow)
check("no workflow image is referenced by tag alone", !looseTag,
  "a tag-only image reference would drift underneath an unchanged repository")

// The container's Rust must be the Rust the repository pins.
const pinnedChannel = /channel\s*=\s*"([^"]+)"/.exec(toolchain)
check("the toolchain file pins an exact channel",
  !!pinnedChannel && /^\d+\.\d+\.\d+$/.test(pinnedChannel[1]),
  pinnedChannel ? pinnedChannel[1] : "no channel")
if (pinnedChannel && scriptPin) {
  eq("the pinned image carries the pinned Rust version", scriptPin[1], pinnedChannel[1])
}
check("CI verifies the container's Rust matches the pin at run time",
  /rust-toolchain\.toml[\s\S]{0,400}?rustc --version/.test(workflow)
    || /pinned="?\$\(grep[\s\S]{0,200}?rust-toolchain\.toml/.test(workflow),
  "nothing checks the container's Rust against rust-toolchain.toml")

// -------------------------------------------------------------------------
// The build inputs the design requires
// -------------------------------------------------------------------------

check("the build is locked to the committed dependency set",
  /cargo build[^\n]*--locked/.test(script), "the build does not pass --locked")
check("the target is fixed",
  /SUPPORTED_TARGET="x86_64-unknown-linux-gnu"/.test(script), "no fixed target")
check("the source path is remapped out of the binary",
  /--remap-path-prefix=%s=\/src/.test(script), "the source path is not remapped")
check("the registry path is remapped too",
  /--remap-path-prefix=%s\/registry=\/registry/.test(script),
  "the registry path is the one that usually leaks, and it is not remapped")
check("the release profile strips symbols",
  /strip\s*=\s*"symbols"/.test(read("agent/Cargo.toml")),
  "the release profile does not strip")

// rustc embeds no build timestamp and ignores SOURCE_DATE_EPOCH, so listing it
// as the mechanism would be cargo-culting rather than pinning.
check("SOURCE_DATE_EPOCH is not claimed as the mechanism",
  !/SOURCE_DATE_EPOCH=/.test(script), "SOURCE_DATE_EPOCH is set as though it mattered here")

// A binary tracked by the commit that names it cannot be rebuilt from that
// commit -- the SHA would have to be known before it exists.
check("no git commit is embedded in the artifact",
  !/GIT_(COMMIT|SHA)|git rev-parse/.test(script),
  "embedding the commit makes the artifact circular")

// An actual assignment, not the comment explaining why there isn't one:
// rustflags set here are silently replaced when RUSTFLAGS is in the
// environment, which would drop the path remaps without any error.
check("the cargo config sets no rustflags for the environment to replace",
  !/^\s*rustflags\s*=/m.test(cargoConfig),
  "config.toml assigns rustflags, which RUSTFLAGS in the environment would silently drop")

// -------------------------------------------------------------------------
// What the script refuses
// -------------------------------------------------------------------------

const run = (...args) => spawnSync("bash", [path.join(repoRoot, "scripts/build-agent.sh"), ...args],
  { encoding: "utf8", env: Object.assign({}, process.env, { PATH: process.env.PATH }) })

eq("--help succeeds", run("--help").status, 0)
eq("an unknown argument is refused", run("--bogus").status, 1)

const wrongTarget = spawnSync("bash", [path.join(repoRoot, "scripts/build-agent.sh")],
  { encoding: "utf8", env: Object.assign({}, process.env, { CARGO_BUILD_TARGET: "aarch64-unknown-linux-gnu" }) })
eq("an unsupported target is refused", wrongTarget.status, 1)
check("the refusal names the target", /aarch64/.test(wrongTarget.stderr), wrongTarget.stderr.slice(0, 160))

// CI runs the script inside the image (no container runtime), so "am I
// pinned" must not mean "can I start a container".
check("the script recognises being inside the pinned environment",
  /in_pinned_environment\(\)/.test(script) && /QSBW_PINNED_BUILD/.test(script),
  "the script cannot tell it is already in the pinned image")
check("the workflow tells the script it is in the pinned environment",
  /QSBW_PINNED_BUILD:\s*'1'/.test(workflow),
  "CI runs in the pinned image but never says so")
check("a claim of being pinned is verified, not trusted",
  /rust-toolchain\.toml[\s\S]{0,400}?fail /.test(script) && /debian[\s\S]{0,200}?bookworm/.test(script),
  "the environment claim is taken on trust")
check("a container runtime is used to enter the image, not required to be in it",
  /reexec_in_container/.test(script),
  "no path re-executes the build inside the pinned image")

// Via --explain, so no image is pulled and no build runs.
const explain = run("--explain")
eq("--explain reports without acting", explain.status, 0)
check("--explain names the environment it would build in",
  /^environment: /m.test(explain.stdout), explain.stdout.slice(0, 200))
check("--explain is honest about an unpinned environment",
  !/not pinned and no container runtime/.test(explain.stdout)
    || /would not be reproducible/.test(explain.stdout),
  explain.stdout.slice(0, 200))
check("--explain pulls nothing and builds nothing",
  explain.stdout.length < 500 && !/Compiling|Unable to find image/.test(explain.stdout + explain.stderr),
  explain.stdout.slice(0, 200))

// The refusal text itself is checked in the source, so that asserting it
// costs no build anywhere.
check("the refusal explains itself rather than failing opaquely",
  /not in the pinned build environment[\s\S]{0,300}?would not be reproducible/.test(script),
  "the refusal message does not say why")

check("an unpinned build is possible but must be asked for",
  /--allow-unpinned/.test(script) && /not reproducible/.test(script),
  "no way to build without a container, or no warning that it is not the release artifact")

// Only meaningful inside the pinned image; a host toolchain reports false
// drift.
check("--compare-tracked enters the pinned image like every other build mode",
  /compare_tracked\(\)[\s\S]{0,700}?in_pinned_environment[\s\S]{0,300}?reexec_in_container "\$runtime" --compare-tracked/.test(script),
  "the drift check builds with whatever toolchain the host happens to have")
check("and refuses rather than guessing when it cannot enter one",
  /compare_tracked\(\)[\s\S]{0,1100}?fail "not in the pinned build environment/.test(script),
  "an unpinned comparison reports a mismatch it cannot stand behind")

check("--compare-tracked reports drift without writing to the repository",
  /compare_tracked\(\)[\s\S]{0,1400}?mktemp -d/.test(script)
    && !/compare_tracked\(\)[\s\S]{0,1400}?install -m/.test(script),
  "the drift check writes into the repository")

// Every mode must use one builder (the target dir once differed between
// modes, and so did the bytes).
check("every build mode goes through one builder",
  (script.match(/build_clean_copy /g) || []).length >= 3,
  "the modes do not share a build procedure, so they can diverge again")
check("the target directory lives inside the remapped source root",
  /CARGO_TARGET_DIR="\$src\/target"/.test(script),
  "a target directory outside the remap embeds an unremapped path in the binary")
check("no mode passes its own target directory",
  !/build_into "[^"]*" "[^"]*"/.test(script),
  "a per-mode target directory is how the two paths diverged before")

// Paths and flag names the release process refers to.
check("the artifact is architecture-scoped",
  /OUTPUT_ARCH="x86_64-linux"/.test(script) && /OUTPUT_DIR="\$REPO_ROOT\/bin\/\$OUTPUT_ARCH"/.test(script),
  "a flat bin/ has to be restructured the day a second target appears")
check("checksums go to one SHA256SUMS, not a sidecar per binary",
  /SUMS_FILE="\$REPO_ROOT\/bin\/SHA256SUMS"/.test(script),
  "no bin/SHA256SUMS")
check("the checksum file is written relative to bin/ so sha256sum -c works there",
  /listed\+=\("\$OUTPUT_ARCH\/\$name"\)/.test(script)
    && /cd "\$REPO_ROOT\/bin" && sha256sum "\$\{listed\[@\]\}" > "\$SUMS_FILE"/.test(script),
  "absolute or checkout-relative paths in SHA256SUMS would only verify here")

// -------------------------------------------------------------------------
// More than one helper
// -------------------------------------------------------------------------

// Each helper is its own Cargo package. In one package, adding the unlock
// tool changed the SSH helper's bytes with no SSH source change -- which is
// exactly the unexplained bin/ change the trust path exists to flag.
check("every shipped helper is built, from its own package",
  /ARTIFACTS=\([\s\S]*?"agent:qs-bitwarden-ssh-agent"[\s\S]*?"unlock-key:qs-bitwarden-unlock-key"[\s\S]*?\)/.test(script),
  "the build script does not list both helpers")
check("every package is built with the same procedure",
  /for spec in "\$\{ARTIFACTS\[@\]\}"[\s\S]{0,200}?cd "\$src\/\$package"[\s\S]{0,200}?cargo build --locked --release/.test(script),
  "a helper is built some other way than the loop every mode shares")
const unlockToolchain = read("unlock-key/rust-toolchain.toml")
eq("both packages pin the same compiler",
  (/channel\s*=\s*"([^"]+)"/.exec(unlockToolchain) || [])[1], pinnedChannel && pinnedChannel[1])
check("and the script refuses packages that disagree",
  /every package must name the same one/.test(script),
  "the pinned image carries one rustc; a second channel would build with the wrong one")
check("the unlock tool's release profile strips and aborts too",
  /strip\s*=\s*"symbols"/.test(read("unlock-key/Cargo.toml"))
    && /panic\s*=\s*"abort"/.test(read("unlock-key/Cargo.toml")),
  "the unlock tool handles the master password and ships with symbols or unwinding")
check("the unlock tool's cargo config sets no rustflags either",
  !/^\s*rustflags\s*=/m.test(read("unlock-key/.cargo/config.toml")),
  "config.toml assigns rustflags, which RUSTFLAGS in the environment would silently drop")
check("a helper not yet tracked counts as drift, not as nothing to compare",
  /\(not tracked\)/.test(script),
  "a new helper could ship uncommitted with the comparison reporting success")
for (const step of [/cargo fmt --check/, /cargo clippy --locked --all-targets/]) {
  check(`CI runs ${step.source.replace(/\\/g, "")} for every package`,
    new RegExp(`for package in agent unlock-key;[\\s\\S]{0,120}?${step.source}`).test(workflow),
    "one package's gates do not cover the other")
}
check("CI tests the unlock tool",
  /working-directory: unlock-key\s*\n\s*run: cargo test --locked --all-targets/.test(workflow),
  "the unlock tool's tests never run in CI")
check("CI applies the dependency policy to both packages",
  /cargo deny --manifest-path agent\/Cargo\.toml --config deny\.toml check/.test(workflow)
    && /cargo deny --manifest-path unlock-key\/Cargo\.toml --config deny\.toml check/.test(workflow),
  "a package's dependencies are not checked against deny.toml")
check("the uploaded candidate carries both helpers and the checksum file",
  /bin\/x86_64-linux\/qs-bitwarden-ssh-agent\s*\n\s*bin\/x86_64-linux\/qs-bitwarden-unlock-key\s*\n\s*bin\/SHA256SUMS/.test(workflow),
  "a maintainer committing the candidate would commit a SHA256SUMS naming a binary not in it")
check("Dependabot watches the unlock tool's lockfile too",
  /directory: \/unlock-key/.test(read(".github/dependabot.yml")),
  "the unlock tool's dependencies would never be proposed for update")
check("the usage text lists the flags that exist",
  /--compare-tracked/.test(script.split("USAGE")[1] || "") && !/\[--check\]/.test(script),
  "usage advertises a flag the script does not accept")

// -------------------------------------------------------------------------
// CI shape
// -------------------------------------------------------------------------

check("CI compares the tracked binary against a clean rebuild",
  /--compare-tracked/.test(workflow),
  "nothing verifies that the committed bytes are what this source builds")
check("the comparison is skipped only when no binary is tracked",
  /if \[ ! -f bin\/x86_64-linux\/qs-bitwarden-ssh-agent \]/.test(workflow),
  "the comparison could pass by absence rather than by matching")
// The comparison must run before the no-flag build writes bin/, or it
// compares a build with itself.
const compareAt = workflow.indexOf("name: Compare the tracked binary")
const candidateAt = workflow.indexOf("name: Build the candidate artifact")
check("the comparison runs before anything overwrites bin/",
  compareAt > 0 && candidateAt > 0 && compareAt < candidateAt,
  `compare step at ${compareAt}, candidate build at ${candidateAt}`)
// A drifted binary is when the candidate matters most, so the upload has to
// happen before the job gives up on the run.
check("a drifted binary still uploads the candidate that fixes it",
  workflow.indexOf("name: Upload the candidate") < workflow.indexOf("name: Fail if the tracked binary drifted"),
  "the job fails before the bytes a maintainer needs are available")
check("drift is still fatal on a same-repository run",
  /steps\.compare\.outputs\.drift == 'yes'/.test(workflow)
    && /github\.event\.pull_request\.head\.repo\.fork != true/.test(workflow),
  "recording drift replaced failing on it")

// No paths filter (it once let panel changes merge unchecked), and master is
// deliberately not a trigger: it only receives up-to-date release branches
// that already passed. Pinned so reintroducing it is a decision.
check("master is deliberately not gated here; the release branch it comes from is",
  !/push:\s*\n\s*branches:\s*\[[^\]]*master/.test(workflow)
    && !/pull_request:\s*\n\s*branches:\s*\[[^\]]*master/.test(workflow),
  "master is back in these triggers -- if that is intended, this check and the "
    + "trigger comment both need updating, because it means the same tree is checked twice")
// Release branches, where releases are assembled, must be gated.
check("CI runs against release branches too, where a release is assembled",
  /push:\s*\n\s*branches:\s*\[[^\]]*'release\/\*\*'/.test(workflow)
    && /pull_request:\s*\n\s*branches:\s*\[[^\]]*'release\/\*\*'/.test(workflow),
  "the workflow does not run on release-branch pushes and PRs into them")
// Master's one job is publishing; if it starts building or testing, the
// reasoning above no longer holds.
const publish = read(".github/workflows/publish-on-master.yml")
check("something does run on a master push, and it is the publish",
  /push:\s*\n\s*branches:\s*\[master\]/.test(publish),
  "nothing runs on master at all now")
check("the publish only publishes -- it does not build or test",
  !/cargo (build|test|clippy)|npm |node |qmltestrunner|build-agent\.sh/.test(publish),
  "the master workflow has grown work that belongs on the release branch")
check("the build workflow stays read-only; publishing holds write",
  /permissions:\s*\n\s*contents:\s*write/.test(publish)
    && /permissions:\s*\n\s*contents:\s*read/.test(workflow)
    && !/contents:\s*write/.test(workflow),
  "write access is not where it was expected")

// helper-rebuild.yml commits rebuilt helpers to eligible PRs. The job that
// runs repository code has no write token; the one with it runs none, commits
// only bin/, and dependency or toolchain changes are never auto-committed.
const rebuild = read(".github/workflows/helper-rebuild.yml")
const eligible = read("scripts/helper-autocommit-eligible.sh")
const rebuildJobs = rebuild.split(/\n  (?=\w[\w-]*:\n)/)
const buildJob = rebuildJobs.find(j => /^build:/.test(j)) || ""
const commitJob = rebuildJobs.find(j => /^commit:/.test(j)) || ""
check("the helper rebuild is read-only by default",
  /^permissions:\n\s*contents: read\s*$/m.test(rebuild), "top-level permissions are not read-only")
check("the job that builds holds no write token",
  buildJob !== "" && !/write/.test(buildJob), buildJob.slice(0, 300))
check("the job that commits runs no repository code",
  commitJob !== "" && !/build-agent\.sh|cargo |scripts\//.test(commitJob), commitJob.slice(0, 300))
check("every action in the helper rebuild is pinned to a commit",
  [...rebuild.matchAll(/uses:\s*([^\s@]+)@(\S+)/g)].every(m => /^[0-9a-f]{40}$/.test(m[2])),
  "an action is referenced by a moving tag")
check("the rebuild uses the pinned image",
  rebuild.includes(scriptPin[0].slice("PINNED_IMAGE=\"".length, -1)), "helper-rebuild.yml builds outside the pinned image")
check("only bin/ is committed, after its checksums verify",
  /sha256sum -c SHA256SUMS/.test(commitJob) && /refusing to commit anything outside bin\//.test(commitJob),
  "the commit job could commit something other than the verified helpers")
check("a branch that moved after the build is not committed to",
  /git rev-parse HEAD\)" = "\$BUILT"/.test(commitJob), "stale bytes could land on a newer push")
check("the new commit is re-checked",
  /gh workflow run agent-build\.yml/.test(commitJob) && /workflow_dispatch:/.test(workflow),
  "a push with GITHUB_TOKEN starts no workflow, so the commit would go unchecked")
check("dependency and toolchain changes are rebuilt by a person",
  /Cargo\.lock/.test(eligible) && /Cargo\.toml/.test(eligible) && /rust-toolchain\.toml/.test(eligible)
    && /dependabot/.test(eligible) && /IS_FORK/.test(eligible),
  "a lockfile change could be rebuilt and committed with nobody reading it")
check("agent build tolerates drift only where helper-rebuild fixes it",
  /steps\.compare\.outputs\.autofix != 'yes'/.test(workflow)
    && /helper-autocommit-eligible\.sh/.test(workflow),
  "the drift gate and the auto-commit disagree about which PRs are fixed")
// Publishing from the tag announced a version before master contained it.
check("the tag build leaves the release as a draft for master to publish",
  /gh release create "\$TAG"[^\n]*--draft/.test(read(".github/workflows/release.yml")),
  "release.yml publishes at tag time again, so master's merge is no longer what releases")

check("no paths filter decides which changes are checked",
  !/^\s*paths:/m.test(workflow),
  "a paths filter is how the panel went unchecked; these gates are cheap enough to always run")
check("the workflow is read-only",
  /permissions:\s*\n\s*contents:\s*read/.test(workflow), "the workflow requests more than read access")
// Actions pinned by commit, like the image by digest.
const actionUses = [...workflow.matchAll(/uses:\s*([^\s@]+)@(\S+)/g)]
check("every third-party action is used at least once", actionUses.length > 0, "no actions used")
check("every action is pinned to a full commit SHA",
  actionUses.every(([, , ref]) => /^[0-9a-f]{40}$/.test(ref)),
  actionUses.filter(([, , ref]) => !/^[0-9a-f]{40}$/.test(ref)).map(m => m[0]).join(", "))
check("each pin says which release it is, for a human",
  (workflow.match(/@[0-9a-f]{40} # v\d/g) || []).length === actionUses.length,
  "a bare SHA tells a reviewer nothing about what version it is")

// The dependency tree of a key-holding binary was reviewed once in writing;
// this is what stops that review going stale.
const deny = read("deny.toml")
check("CI enforces the dependency policy", /cargo deny/.test(workflow), "nothing runs cargo-deny")
// cargo-deny discovers its config beside the manifest or in the working
// directory. Running it from agent/ made it fall back to built-in defaults
// and report success while reading none of this policy.
check("the policy file is named explicitly rather than discovered",
  /cargo deny[^\n]*--config deny\.toml/.test(workflow),
  "a discovered config can silently be the wrong one, or none at all")
// apt exits 0 on a failed index; Error-Mode=any makes the fetch fail where it
// happens.
check("a failed package index fails the step that fetched it",
  /apt-get update[^\n]*APT::Update::Error-Mode=any/.test(workflow),
  "apt warns and exits 0 on a failed index, so the real error surfaces later and misattributed")
check("apt packages are not pinned by version string",
  !/apt-get install[^\n]*=[0-9]/.test(workflow),
  "hard version pins break when Ubuntu drops the superseded package")
check("advisories are denied rather than warned about",
  /yanked = "deny"/.test(deny), "yanked crates are tolerated")
check("the one accepted advisory says why, next to the exception itself",
  /RUSTSEC-2023-0071[\s\S]{0,300}?Accepted for these reasons[\s\S]{0,1200}?id = "RUSTSEC-2023-0071", reason = "[^"]{40,}"/.test(deny),
  "an ignored advisory with no recorded reasoning is just a silenced alarm")
check("only permissive licences are allowed",
  /allow = \[[\s\S]*?"MIT"/.test(deny) && !/GPL/.test(deny.split("[bans]")[0]),
  "a copyleft dependency would change this plugin's own distribution terms")
check("only crates.io is permitted as a source",
  /unknown-git = "deny"/.test(deny) && /unknown-registry = "deny"/.test(deny),
  "a git dependency is a moving target no lockfile review covers")

// The panel's JavaScript runs in QML's engine, not Node's, and they differ.
check("the QML tests run in CI",
  /qmltestrunner/.test(workflow), "the QML suite passes locally and never runs in CI")
// --no-install-recommends drops what QtQuick only recommends, and
// QtQml.WorkerScript is one of them: importing QtQuick then fails with a
// module-not-installed error that reads like a broken test.
check("every QML module the tests import is installed explicitly",
  /qml6-module-qtqml-workerscript/.test(workflow),
  "QtQuick's recommended modules are dropped by --no-install-recommends")
// One QML test imports the Omarchy shell by absolute path, which a runner
// does not have. Skipping it is right; skipping it silently, or skipping
// everything and reporting success, is not.
check("a QML test is skipped only for a stated, detected reason",
  /\[ ! -d \/usr\/share\/omarchy\/shell\/Ui \]/.test(workflow),
  "the skip is unconditional rather than tied to the missing dependency")
check("the skipped files are named in the log",
  /::notice::Omarchy shell not installed; skipped/.test(workflow),
  "a silent skip looks identical to a passing test")
check("skipping every QML test fails the job",
  /every QML test was skipped, so this gate proved nothing/.test(workflow),
  "the gate could pass by running nothing at all")

// A fork cannot push CI's bytes into its own branch, so an unconditional
// match requirement would make every external agent-source PR unmergeable.
check("a fork pull request reports binary drift rather than blocking on it",
  /IS_FORK/.test(workflow) && /fork/.test(workflow),
  "a fork contributor could never satisfy the binary comparison")
check("a same-repository run still fails on drift",
  /::error::the tracked binary does not match/.test(workflow),
  "drift is never fatal, so the comparison decides nothing")

check("dependency updates are told the binary must be rebuilt",
  /needs-binary-rebuild/.test(read(".github/dependabot.yml")),
  "an accepted dependency bump would fail --compare-tracked with no explanation")

check("no secrets are referenced",
  !/secrets\./.test(workflow), "a build gate should need no secrets")
check("the panel tests get the tools they shell out to",
  /jq/.test(workflow) && /openssh-client/.test(workflow) && /apt-get install[^\n]*\bargon2\b/.test(workflow),
  "the pipeline, signing and envelope tests would fail without jq, ssh-keygen and argon2")

done()
