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

check("--compare-tracked reports drift without writing to the repository",
  /compare_tracked\(\)[\s\S]{0,600}?mktemp -d/.test(script)
    && !/compare_tracked\(\)[\s\S]{0,600}?install -m/.test(script),
  "the drift check writes into the repository")

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

check("CI runs against the feature branch while the feature is unfinished",
  /branches:\s*\[feature\/ssh-agent\]/.test(workflow), "the workflow does not run on the feature branch")
check("the workflow is read-only",
  /permissions:\s*\n\s*contents:\s*read/.test(workflow), "the workflow requests more than read access")
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
