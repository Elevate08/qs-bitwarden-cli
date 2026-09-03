#!/usr/bin/env node
// The helper ships as committed bytes, which is only defensible if anyone can
// rebuild them from the committed source. These tests guard the parts of that
// promise which rot silently: a digest that drifts between the build script
// and the workflow, an image pinned by tag instead of digest, a build that
// would claim reproducibility it cannot support, or a toolchain pin nothing
// actually enforces.
//
// They deliberately do not run a build. The build needs a container this
// machine may not have; what can be checked here is that the definition is
// coherent and refuses the right things.
//
//   node tests/ssh-agent-artifact.test.js

const fs = require("fs")
const path = require("path")
const { spawnSync } = require("child_process")

const repoRoot = path.join(__dirname, "..")
const read = p => fs.readFileSync(path.join(repoRoot, p), "utf8")

let pass = 0
const failures = []
const check = (label, ok, detail) => ok ? pass++ : failures.push(`${label}\n    ${detail}`)
const eq = (label, actual, expected) =>
  check(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)

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

// The pinned environment is entered, not started: CI runs this script inside
// the image, where no container runtime exists. Conflating "am I pinned" with
// "can I start a container" made the script refuse in the one place it was
// written for, so both halves are pinned down here.
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

// Asked through --explain rather than by running it. Invoking
// --verify-reproducible here would pull a 700MB image and run two full
// release builds just to observe a decision -- which is what this file's
// header promises not to do, and what it was doing on any machine with a
// container runtime until CI pointed it out.
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

// The comparison is only meaningful from inside the pinned image: the tracked
// bytes were produced there, and it pins glibc and binutils as well as the
// compiler. Run against a host toolchain it reports drift that is not drift --
// which, for the mode that exists to be a PR gate, is the worst way to fail.
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

// Every mode must build the same way. They did not: the release build put its
// target directory outside the remapped source root while the comparison
// modes put it inside, so the bytes CI offered as the candidate differed from
// the bytes --verify-reproducible had just declared identical. Committing
// those would have made the first --compare-tracked fail, or passed by luck
// and shipped a binary nobody could reproduce.
check("every build mode goes through one builder",
  (script.match(/build_clean_copy /g) || []).length >= 3,
  "the modes do not share a build procedure, so they can diverge again")
check("the target directory lives inside the remapped source root",
  /CARGO_TARGET_DIR="\$src\/target"/.test(script),
  "a target directory outside the remap embeds an unremapped path in the binary")
check("no mode passes its own target directory",
  !/build_into "[^"]*" "[^"]*"/.test(script),
  "a per-mode target directory is how the two paths diverged before")

// The artifact paths and the flag name are what Task 18 and its verification
// step refer to. They were wrong once -- a flat bin/ and a --check flag the
// task list never mentions -- and the cost of that is only paid later, when
// the binary is committed and everything has to be moved.
check("the artifact is architecture-scoped",
  /OUTPUT_ARCH="x86_64-linux"/.test(script) && /OUTPUT_DIR="\$REPO_ROOT\/bin\/\$OUTPUT_ARCH"/.test(script),
  "a flat bin/ has to be restructured the day a second target appears")
check("checksums go to one SHA256SUMS, not a sidecar per binary",
  /SUMS_FILE="\$REPO_ROOT\/bin\/SHA256SUMS"/.test(script),
  "no bin/SHA256SUMS")
check("the checksum file is written relative to bin/ so sha256sum -c works there",
  /cd "\$REPO_ROOT\/bin" && sha256sum "\$OUTPUT_ARCH\/\$OUTPUT_NAME"/.test(script),
  "absolute or checkout-relative paths in SHA256SUMS would only verify here")
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
// `./scripts/build-agent.sh` with no flags writes bin/ and bin/SHA256SUMS.
// Run the comparison after it and the tracked binary it reads back is the
// candidate that step just wrote -- so it compares a build with itself and
// passes whatever the committed bytes are. That is not hypothetical: it is
// what this workflow did until a stale binary sailed through a green run.
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

// These gates ran on neither the branch nor the files that needed them: the
// trigger still named the SSH agent's feature branch after that work reached
// master, and a paths filter of agent/** kept the panel -- Panel.qml,
// BitwardenModel.js, tests/ -- entirely outside the workflow. PR #13 merged
// with `no checks reported`. Both halves are asserted, because fixing one
// leaves the hole open.
check("CI runs against master, where the code now lands",
  /push:\s*\n\s*branches:\s*\[master[,\]]/.test(workflow)
    && /pull_request:\s*\n\s*branches:\s*\[master[,\]]/.test(workflow),
  "the workflow does not run on master pushes and master PRs")
// A release is assembled on a release branch before it is tagged, so the same
// gates have to cover it. Listing master alone let a PR into `release/1.7.0`
// merge with `no checks reported` -- PR #13's hole reached through the base
// branch instead of through a paths filter.
check("CI runs against release branches too, where a release is assembled",
  /push:\s*\n\s*branches:\s*\[[^\]]*'release\/\*\*'/.test(workflow)
    && /pull_request:\s*\n\s*branches:\s*\[[^\]]*'release\/\*\*'/.test(workflow),
  "the workflow does not run on release-branch pushes and PRs into them")
check("no paths filter decides which changes are checked",
  !/^\s*paths:/m.test(workflow),
  "a paths filter is how the panel went unchecked; these gates are cheap enough to always run")
check("the workflow is read-only",
  /permissions:\s*\n\s*contents:\s*read/.test(workflow), "the workflow requests more than read access")
// A tag is a moving pointer. Pinning actions by commit is the same argument
// as pinning the build image by digest, applied to the code that runs the
// build -- and a workflow that establishes trust in bytes should not itself
// depend on a mutable reference.
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
// apt answers a failed index with a warning and exit 0. That is how a 502
// from the archive passed `apt-get update` and came back four minutes later
// as `Unable to locate package` on six Qt packages -- the wrong error, in the
// wrong step, about the wrong thing. Error-Mode=any is what makes a mirror
// outage report itself as one.
check("a failed package index fails the step that fetched it",
  /apt-get update[^\n]*APT::Update::Error-Mode=any/.test(workflow),
  "apt warns and exits 0 on a failed index, so the real error surfaces later and misattributed")
check("apt packages are not pinned by version string",
  !/apt-get install[^\n]*=[0-9]/.test(workflow),
  "hard version pins break when Ubuntu drops the superseded package")
check("advisories are denied rather than warned about",
  /yanked = "deny"/.test(deny), "yanked crates are tolerated")
check("the one accepted advisory says why and where it is argued",
  /RUSTSEC-2023-0071[\s\S]{0,400}?0001-ssh-agent-dependencies/.test(deny),
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
  /jq/.test(workflow) && /openssh-client/.test(workflow),
  "the pipeline and signing tests would fail without jq and ssh-keygen")

if (failures.length) {
  console.error(`\n${failures.length} failed, ${pass} passed\n`)
  failures.forEach(f => console.error(`  FAIL ${f}`))
  process.exit(1)
}
console.log(`ssh-agent-artifact: ${pass} passed`)
