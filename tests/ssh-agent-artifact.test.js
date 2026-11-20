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

check("the target is fixed per architecture",
  /x86_64\) printf 'x86_64-unknown-linux-gnu'/.test(script)
    && /aarch64\) printf 'aarch64-unknown-linux-gnu'/.test(script),
  "no fixed target for each shipped architecture")
check("the script ships the architectures the panel knows",
  /SUPPORTED_ARCHES=\(x86_64 aarch64\)/.test(script)
    && Object.keys(require("./harness").loadModule().HELPER_ARCHITECTURES).join(" ") === "x86_64 aarch64",
  "build-agent.sh and HELPER_ARCHITECTURES disagree about what a release ships")
// The image has no cross-linker, and installing one would put an unpinned
// package into the bytes: each architecture builds natively.
check("inside the image a build is native, never cross-compiled",
  /require_native\(\)/.test(script) && (script.match(/^\s*require_native$/gm) || []).length >= 4,
  "a mode can build another architecture with the image's own linker")
check("a container build runs the requested architecture's image variant",
  /--platform "\$\(platform_for "\$ARCH"\)"/.test(script) && /build-agent\.sh --arch "\$ARCH"/.test(script),
  "the re-exec ignores --arch, so it builds the host's architecture under another's name")
check("the source path is remapped out of the binary",
  /--remap-path-prefix=%s=\/src/.test(script), "the source path is not remapped")
check("the registry path is remapped too",
  /--remap-path-prefix=%s\/registry=\/registry/.test(script),
  "the registry path is the one that usually leaks, and it is not remapped")
check("the release profile strips symbols",
  /strip\s*=\s*"symbols"/.test(read("agent/Cargo.toml")),
  "the release profile does not strip")

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
  { encoding: "utf8", env: Object.assign({}, process.env, { CARGO_BUILD_TARGET: "riscv64gc-unknown-linux-gnu" }) })
eq("an unsupported target is refused", wrongTarget.status, 1)
check("the refusal names the target", /riscv64/.test(wrongTarget.stderr), wrongTarget.stderr.slice(0, 160))
const wrongArch = run("--arch", "riscv64")
eq("an unshipped architecture is refused", wrongArch.status, 1)
check("the refusal lists what ships", /x86_64 aarch64/.test(wrongArch.stderr), wrongArch.stderr.slice(0, 160))
for (const arch of ["x86_64", "aarch64", "arm64"]) {
  const explained = run("--explain", "--arch", arch)
  eq(`--arch ${arch} is accepted`, explained.status, 0)
  check(`--arch ${arch} names its target and directory`,
    new RegExp(`${arch === "arm64" ? "aarch64" : arch}-unknown-linux-gnu, bin/${arch === "arm64" ? "aarch64" : arch}-linux/`).test(explained.stdout),
    explained.stdout.slice(0, 200))
}

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
  /OUTPUT_ARCH="\$ARCH-linux"/.test(script) && /OUTPUT_DIR="\$REPO_ROOT\/bin\/\$OUTPUT_ARCH"/.test(script),
  "each architecture's helpers need their own bin/<arch>-linux/")
check("checksums go to one SHA256SUMS, not a sidecar per binary",
  /SUMS_FILE="\$REPO_ROOT\/bin\/SHA256SUMS"/.test(script),
  "no bin/SHA256SUMS")
const writeSums = functionBodyOf(script, "write_sums")
check("the checksum file is written relative to bin/ so sha256sum -c works there",
  /listed\+=\("\$OUTPUT_ARCH\/\$name"\)/.test(script)
    && /cd "\$REPO_ROOT\/bin"/.test(writeSums) && /sha256sum "\$\{listed\[@\]\}"/.test(writeSums),
  "absolute or checkout-relative paths in SHA256SUMS would only verify here")
check("a build replaces only its own architecture's lines in SHA256SUMS",
  /grep -v "  \$OUTPUT_ARCH\/" "\$SUMS_FILE"/.test(writeSums) && /LC_ALL=C sort -k2/.test(writeSums)
    && (script.match(/write_sums "\$\{listed\[@\]\}"/g) || []).length === 2,
  "building one architecture would drop the other's checksums")
// write_sums, run for real against a scratch bin/.
{
  const fsx = require("fs"), osx = require("os")
  const dir = fsx.mkdtempSync(path.join(osx.tmpdir(), "qsbw-sums-"))
  try {
    fsx.mkdirSync(path.join(dir, "bin", "aarch64-linux"), { recursive: true })
    fsx.writeFileSync(path.join(dir, "bin", "aarch64-linux", "qs-bitwarden-vault"), "arm\n")
    fsx.writeFileSync(path.join(dir, "bin", "SHA256SUMS"),
      "1".repeat(64) + "  aarch64-linux/qs-bitwarden-vault\n" + "2".repeat(64) + "  x86_64-linux/qs-bitwarden-vault\n")
    const body = functionBodyOf(script, "write_sums") + "\n}\n"
    const out = spawnSync("bash", ["-c", `${body}\nwrite_sums aarch64-linux/qs-bitwarden-vault`],
      { encoding: "utf8", env: Object.assign({}, process.env,
        { REPO_ROOT: dir, SUMS_FILE: path.join(dir, "bin", "SHA256SUMS"), OUTPUT_ARCH: "aarch64-linux" }) })
    const written = fsx.readFileSync(path.join(dir, "bin", "SHA256SUMS"), "utf8")
    eq("write_sums succeeds", out.status, 0)
    check("write_sums keeps the other architecture's line", written.includes("2".repeat(64) + "  x86_64-linux/qs-bitwarden-vault"), written)
    check("and replaces its own", !written.includes("1".repeat(64)) && /^[0-9a-f]{64}  aarch64-linux\/qs-bitwarden-vault$/m.test(written), written)
  } finally { fsx.rmSync(dir, { recursive: true, force: true }) }
}

// -------------------------------------------------------------------------
// More than one helper
// -------------------------------------------------------------------------

// Each helper is its own Cargo package. In one package, adding the unlock
// tool changed the SSH helper's bytes with no SSH source change -- which is
// exactly the unexplained bin/ change the trust path exists to flag.
check("every shipped helper is built, from its own package",
  /ARTIFACTS=\([\s\S]*?"agent:qs-bitwarden-ssh-agent"[\s\S]*?"unlock-key:qs-bitwarden-unlock-key"[\s\S]*?"vault:qs-bitwarden-vault"[\s\S]*?\)/.test(script),
  "the build script does not list every helper")
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
function functionBodyOf(source, name) {
  const at = source.indexOf(name + "() {")
  if (at < 0) return ""
  return source.slice(at, source.indexOf("\n}\n", at))
}
check("the gates name every helper package",
  /HELPERS: agent unlock-key vault/.test(workflow), "a helper's package is left out of the gates")
for (const step of [/cargo fmt --check/, /cargo clippy --locked --all-targets/, /cargo test --locked --all-targets/]) {
  check(`CI runs ${step.source.replace(/\\/g, "")} for every package`,
    new RegExp(`for package in \\$HELPERS; do[\\s\\S]{0,120}?${step.source}`).test(workflow),
    "one package's gates do not cover another")
}
check("CI applies the dependency policy to every package",
  /for package in \$HELPERS; do\s*\n\s*cargo deny --manifest-path "\$package\/Cargo\.toml" --config deny\.toml check/.test(workflow),
  "a package's dependencies are not checked against deny.toml")
check("the uploaded candidate carries every helper and the checksum file",
  /bin\/\$\{\{ matrix\.arch \}\}-linux\/qs-bitwarden-ssh-agent\s*\n\s*bin\/\$\{\{ matrix\.arch \}\}-linux\/qs-bitwarden-unlock-key\s*\n\s*bin\/\$\{\{ matrix\.arch \}\}-linux\/qs-bitwarden-vault\s*\n\s*bin\/SHA256SUMS/.test(workflow),
  "a maintainer committing the candidate would commit a SHA256SUMS naming a binary not in it")
// Every shipped architecture is built, natively, on its own runner, in CI,
// both by the gates and by the rebuild that commits bytes.
for (const [file, text] of [["agent-build.yml", workflow], ["helper-rebuild.yml", read(".github/workflows/helper-rebuild.yml")]]) {
  check(`${file} builds x86_64 on an x86_64 runner and aarch64 on an arm64 runner`,
    /- arch: x86_64\s*\n\s*runner: ubuntu-24\.04\s*\n/.test(text) && /- arch: aarch64\s*\n\s*runner: ubuntu-24\.04-arm\s*\n/.test(text)
      && /runs-on: \$\{\{ matrix\.runner \}\}/.test(text),
    "an architecture is not built in CI, or not natively")
  check(`${file} passes the leg's architecture to the build`,
    /build-agent\.sh --(ci|compare-tracked) --arch "\$ARCH"/.test(text), "the build picks its own architecture")
}
check("the helpers' tests run on aarch64 too",
  /runs-on: ubuntu-24\.04-arm[\s\S]{0,800}?cargo test --locked --all-targets/.test(workflow),
  "the aarch64 helpers ship without their tests ever running on aarch64")
check("the dependency policy covers every shipped target",
  /targets = \["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"\]/.test(read("deny.toml")),
  "an aarch64-only dependency would escape cargo-deny")
check("Dependabot watches the unlock tool's lockfile too",
  /directory: \/unlock-key/.test(read(".github/dependabot.yml")),
  "the unlock tool's dependencies would never be proposed for update")

// -------------------------------------------------------------------------
// CI shape
// -------------------------------------------------------------------------

// One pass: two builds that must match, the first compared with the tracked
// bytes, then written as the candidate (four builds before).
check("CI builds twice, compares with the tracked helpers and writes the candidate in one pass",
  /\.\/scripts\/build-agent\.sh --ci/.test(workflow)
    && !/build-agent\.sh --verify-reproducible/.test(workflow) && !/build-agent\.sh --compare-tracked/.test(workflow),
  "nothing verifies that the committed bytes are what this source builds")
check("drift (exit 3) is recorded, and any other failure stops the job",
  /\[ "\$rc" -eq 3 \] \|\| exit "\$rc"/.test(workflow), "a failed build could read as drift")
// The comparison must read bin/ before the candidate is written there, or
// it compares a build with itself.
const ci = functionBodyOf(script, "ci_build")
check("the comparison runs before anything overwrites bin/",
  ci.indexOf("have=") > 0 && ci.indexOf("install -m 0755") > ci.indexOf("have="),
  ci)
check("the one pass still requires both builds to match before writing anything",
  ci.indexOf("the two builds differ") < ci.indexOf("install -m 0755"), ci)
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
const rebuildJobs = rebuild.split(/\n  (?=\w[\w-]*:\n)/)
const buildJob = rebuildJobs.find(j => /^build:/.test(j)) || ""
const commitJob = rebuildJobs.find(j => /^commit:/.test(j)) || ""
const gateJob = rebuildJobs.find(j => /^gate:/.test(j)) || ""
// The verdict is a job of its own that runs nothing of the pull request's,
// and it is the only place the gate runs: in the build job it ran after the
// PR's build had, where that build could have answered for it.
check("the commit gate is decided from the base branch's copy before any PR code runs",
  /set -o pipefail\n[\s\S]*git show "\$BASE_SHA:scripts\/helper-autocommit-eligible\.sh"\)/.test(gateJob)
    && /BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/.test(gateJob)
    && !/\.\/|build-agent|cargo |container:|write|needs:/.test(gateJob)
    && /outputs:\n\s*eligible: \$\{\{ steps\.verdict\.outputs\.eligible \}\}/.test(gateJob)
    && !/helper-autocommit-eligible/.test(buildJob + commitJob),
  gateJob.slice(0, 300))
const gated = "if: needs.gate.outputs.eligible == 'yes'"
check("nothing of the PR is checked out, built or committed unless that verdict is yes",
  /\n    needs: gate\n/.test(buildJob)
    && buildJob.split(/\n      - /).slice(1).filter(step => /uses: actions\/checkout|\.\/scripts\//.test(step))
      .every(step => step.includes(`\n        ${gated}\n`))
    && /\n    needs: \[gate, build\]\n/.test(commitJob)
    && commitJob.includes(`\n    ${gated} && needs.build.result == 'success'\n`),
  "the build or the commit no longer waits for the gate job's own output")
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
// The same script, given the same actor and the same two commits as the gate
// job, and asked before this workflow's first run of the PR's build script.
const gateInputs = text => ["IS_FORK", "ACTOR", "BASE_SHA", "HEAD_SHA"]
  .map(name => (text.match(new RegExp(`\\n\\s+${name}: (\\$\\{\\{[^\\n]+\\}\\})\\n`)) || [])[1])
const autofixStep = workflow.split(/\n      - /).find(step => /^name: [^\n]*\n\s+id: autofix\n/.test(step)) || ""
check("agent build tolerates drift only where helper-rebuild fixes it",
  /steps\.autofix\.outputs\.autofix != 'yes'/.test(workflow)
    && /git show "\$BASE_SHA:scripts\/helper-autocommit-eligible\.sh"\)/.test(autofixStep)
    && gateInputs(gateJob).every(Boolean) && gateInputs(autofixStep).join() === gateInputs(gateJob).join()
    && workflow.indexOf(autofixStep) < workflow.indexOf("./scripts/build-agent.sh"),
  "the drift gate and the auto-commit disagree about which PRs are fixed")
// That the tag build leaves a draft for master to publish is run, not read:
// tests/release-provenance.test.js.

check("no paths filter decides which changes are checked",
  !/^\s*paths:/m.test(workflow),
  "a paths filter is how the panel went unchecked; these gates are cheap enough to always run")
// Actions pinned by commit, like the image by digest.
const actionUses = [...workflow.matchAll(/uses:\s*([^\s@]+)@(\S+)/g)]
check("every third-party action is used at least once", actionUses.length > 0, "no actions used")
check("every action is pinned to a full commit SHA",
  actionUses.every(([, , ref]) => /^[0-9a-f]{40}$/.test(ref)),
  actionUses.filter(([, , ref]) => !/^[0-9a-f]{40}$/.test(ref)).map(m => m[0]).join(", "))

// The dependency tree of a key-holding binary was reviewed once in writing;
// this is what stops that review going stale.
const deny = read("deny.toml")
// apt exits 0 on a failed index; Error-Mode=any makes the fetch fail where it
// happens.
check("a failed package index fails the step that fetched it",
  /apt-get update[^\n]*APT::Update::Error-Mode=any/.test(workflow),
  "apt warns and exits 0 on a failed index, so the real error surfaces later and misattributed")
check("advisories are denied rather than warned about",
  /yanked = "deny"/.test(deny), "yanked crates are tolerated")
check("only permissive licences are allowed",
  /allow = \[[\s\S]*?"MIT"/.test(deny) && !/GPL/.test(deny.split("[bans]")[0]),
  "a copyleft dependency would change this plugin's own distribution terms")
check("only crates.io is permitted as a source",
  /unknown-git = "deny"/.test(deny) && /unknown-registry = "deny"/.test(deny),
  "a git dependency is a moving target no lockfile review covers")

// The panel's JavaScript runs in QML's engine, not Node's, and they differ.
check("the QML tests run in CI",
  /qmltestrunner/.test(workflow), "the QML suite passes locally and never runs in CI")
// One QML test imports the Omarchy shell by absolute path, which a runner
// does not have. Skipping it is right; skipping it silently, or skipping
// everything and reporting success, is not.
check("a QML test is skipped only for a stated, detected reason",
  /\[ ! -d \/usr\/share\/omarchy\/shell\/Ui \]/.test(workflow),
  "the skip is unconditional rather than tied to the missing dependency")
check("skipping every QML test fails the job",
  /every QML test was skipped, so this gate proved nothing/.test(workflow),
  "the gate could pass by running nothing at all")

check("a same-repository run still fails on drift",
  /::error::the tracked binary does not match/.test(workflow),
  "drift is never fatal, so the comparison decides nothing")

check("dependency updates are told the binary must be rebuilt",
  /needs-binary-rebuild/.test(read(".github/dependabot.yml")),
  "an accepted dependency bump would fail --compare-tracked with no explanation")

check("no secrets are referenced",
  !/secrets\./.test(workflow), "a build gate should need no secrets")

done()
