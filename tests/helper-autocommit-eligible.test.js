#!/usr/bin/env node
// Behaviour of scripts/helper-autocommit-eligible.sh, the gate that decides
// whether CI may rebuild and commit the helper binaries. Runs the real script
// (the way CI does, piped into bash) against throwaway git repositories.
//
//   node tests/helper-autocommit-eligible.test.js

const { createSuite, repoRoot } = require("./harness")
const fs = require("fs")
const os = require("os")
const path = require("path")
const { spawnSync } = require("child_process")

const { check, done } = createSuite("helper-autocommit-eligible")
const script = fs.readFileSync(path.join(repoRoot, "scripts/helper-autocommit-eligible.sh"), "utf8")
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qsbw-eligible-"))

const gitEnv = {
  ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.com",
  GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.com",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null",
}
const git = (cwd, ...args) => {
  const r = spawnSync("git", args, { cwd, env: gitEnv, encoding: "utf8" })
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`)
  return r.stdout
}

const BASE_FILES = {
  "Service.qml": "a\n", "README.md": "a\n", "tests/x.test.js": "a\n",
  "agent/Cargo.toml": "a\n", "agent/Cargo.lock": "a\n", "agent/rust-toolchain.toml": "a\n",
  "agent/src/main.rs": "a\n", "unlock-key/src/main.rs": "a\n", "vault/src/main.rs": "a\n",
  "scripts/build-agent.sh": "a\n", "agent/.cargo/config.toml": "a\n", "agent/build.rs": "a\n",
}

let n = 0
// Commits BASE_FILES to a fixture release branch, applies `changes` (path ->
// content, null to delete, {symlink} for a symlink) on a branch off it, then runs
// the gate there.
function gate(changes, env = {}) {
  const dir = path.join(tmp, `repo${n++}`)
  fs.mkdirSync(dir)
  git(dir, "init", "-q", "-b", "main")
  const put = (p, c) => {
    fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true })
    fs.writeFileSync(path.join(dir, p), c)
  }
  for (const [p, c] of Object.entries(BASE_FILES)) put(p, c)
  git(dir, "add", "-A")
  git(dir, "commit", "-q", "-m", "base")
  git(dir, "update-ref", "refs/remotes/origin/release/1.0", "HEAD")
  git(dir, "checkout", "-q", "-b", "pr")
  for (const [p, c] of Object.entries(changes)) {
    const full = path.join(dir, p)
    if (c === null) fs.rmSync(full)
    else if (c && c.symlink) {
      fs.mkdirSync(path.dirname(full), { recursive: true })
      fs.symlinkSync(c.symlink, full)
    } else put(p, c)
  }
  git(dir, "add", "-A")
  git(dir, "commit", "-q", "-m", "pr")
  const r = spawnSync("bash", [], {
    cwd: dir, input: script, encoding: "utf8",
    env: {
      ...gitEnv, GITHUB_EVENT_NAME: "pull_request", GITHUB_BASE_REF: "release/1.0",
      IS_FORK: "false", ACTOR: "someone", ...env,
    },
  })
  return { out: r.stdout.trim(), err: r.stderr.trim() }
}
const verdict = (name, changes, want, env) => {
  const { out, err } = gate(changes, env)
  check(name, out === want, `expected ${want}, got ${out}: ${err}`)
}

// Eligible: plain Rust source, with or without ordinary files beside it.
verdict("agent source alone is eligible", { "agent/src/main.rs": "b\n" }, "yes")
verdict("a new file under src/ is eligible", { "vault/src/deep/new.rs": "b\n" }, "yes")
verdict("source beside QML and docs is eligible",
  { "agent/src/foo.rs": "b\n", "Service.qml": "b\n", "CHANGELOG.md": "b\n" }, "yes")
verdict("all three packages' sources are eligible",
  { "agent/src/main.rs": "b\n", "unlock-key/src/main.rs": "b\n", "vault/src/main.rs": "b\n" }, "yes")
verdict("QML, JS and tests alone are eligible",
  { "Service.qml": "b\n", "tests/x.test.js": "b\n", "docs/new.md": "b\n" }, "yes")

// Never eligible: anything that changes what is compiled in, at any depth.
const denied = {
  "root Cargo.toml": { "Cargo.toml": "[patch.crates-io]\n" },
  "root Cargo.lock": { "Cargo.lock": "b\n" },
  "root rust-toolchain": { "rust-toolchain": "nightly\n" },
  "root rust-toolchain.toml": { "rust-toolchain.toml": "b\n" },
  "root .cargo/config.toml": { ".cargo/config.toml": "b\n" },
  "root .cargo/config": { ".cargo/config": "b\n" },
  "agent/rust-toolchain": { "agent/rust-toolchain": "nightly\n" },
  "agent/Cargo.toml": { "agent/Cargo.toml": "b\n" },
  "agent/Cargo.lock": { "agent/Cargo.lock": "b\n" },
  "unlock-key/Cargo.lock": { "unlock-key/Cargo.lock": "b\n" },
  "vault/rust-toolchain.toml": { "vault/rust-toolchain.toml": "b\n" },
  "agent/.cargo/config.toml": { "agent/.cargo/config.toml": "b\n" },
  "a new .cargo directory in a package": { "vault/.cargo/config.toml": "b\n" },
  "agent/build.rs": { "agent/build.rs": "b\n" },
  "a new vault/build.rs": { "vault/build.rs": "fn main(){}\n" },
  "a nested Cargo.toml": { "tools/x/Cargo.toml": "b\n" },
  "a nested rust-toolchain": { "tools/rust-toolchain": "b\n" },
  "a nested .cargo directory": { "tools/.cargo/config.toml": "b\n" },
  "the build script": { "scripts/build-agent.sh": "b\n" },
  ".gitattributes (alters git archive)": { ".gitattributes": "agent/src export-ignore\n" },
  "a package file outside src/": { "agent/tests/t.rs": "b\n" },
  "a package benches file": { "vault/benches/b.rs": "b\n" },
  "a package-level data file": { "unlock-key/notes.txt": "b\n" },
  "a symlink under src/": { "agent/src/link.rs": { symlink: "../../Cargo.toml" } },
  "a deleted lockfile": { "agent/Cargo.lock": null },
  "a lockfile change among valid source": { "agent/src/main.rs": "b\n", "Cargo.lock": "b\n" },
}
for (const [name, changes] of Object.entries(denied)) verdict(`${name} is not eligible`, changes, "no")

// The unchanged actor, fork and branch checks.
verdict("Dependabot is not eligible", { "agent/src/main.rs": "b\n" }, "no", { ACTOR: "dependabot[bot]" })
verdict("a fork is not eligible", { "agent/src/main.rs": "b\n" }, "no", { IS_FORK: "true" })
verdict("a push is not eligible", { "agent/src/main.rs": "b\n" }, "no", { GITHUB_EVENT_NAME: "push" })
verdict("a PR into master is not eligible", { "agent/src/main.rs": "b\n" }, "no", { GITHUB_BASE_REF: "master" })
verdict("an unfetched base is not eligible", { "agent/src/main.rs": "b\n" }, "no", { GITHUB_BASE_REF: "release/9.9" })

fs.rmSync(tmp, { recursive: true, force: true })
done()
