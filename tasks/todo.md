# Task List: Opt-in Bitwarden SSH Agent

Source design: `docs/ideas/ssh-agent.md`, revision 2 (2026-08-26).

Every task must satisfy its acceptance criteria plus the repository-wide
Definition of Done: focused and regression tests, runtime verification, lint
and formatting, scoped changes, documentation for user-visible behavior,
security review for sensitive paths, and human approval before merge/release.
Each task also ends with the live checkpoint protocol in `tasks/plan.md`: the
dev-linked plugin is restarted and opened for user testing before work begins
on the next task.

## Task 1: Introduce the sanitized vault-read contract

**Description:** Add an out-of-process, positive-allowlist `jq` transform for
the ordinary `bw list items` result without switching the live panel yet. It
must emit one bounded object containing intact types 1–4 and a public-only
projection of type 5, while excluding types 6+ and keeping SSH private keys out
of every QML-facing byte.

**Acceptance criteria:**

- [x] Fixture markers prove types 1–4 remain intact, type 5 exposes only the
      approved public fields, and no type-5 private marker or type-6+ marker
      reaches QML-facing output.
- [x] A type 1–4 object carrying a top-level `sshKey` subtree rejects the whole
      read rather than mutating an ordinary object or risking a private-key leak.
- [x] Raw input and QML output have producer-side caps; malformed, truncated,
      or filter-failing input returns an error rather than a partial model.
- [x] The filter is static, receives values only through safe `jq --arg`
      inputs, and preserves the repository's no-secret-in-argv policy.

**Verification:**

- [x] Tests pass: `node tests/ssh-items.test.js`
- [x] Regression suite passes: `for test_file in tests/*.test.js; do node "$test_file" || exit 1; done`
- [x] Manual check: run the command against marker fixtures and inspect both
      stdout and failure exit codes.

**Dependencies:** None

**Files likely touched:**

- `BitwardenModel.js`
- `tests/ssh-items.test.js`

**Estimated scope:** Small: 2 files

## Task 2: Deliver the public SSH-key panel slice

**Description:** Switch the panel's item load to the sanitized envelope and
add type-5 SSH keys as public-only, read-only items. They participate in All,
Favorites, global search, counts, and type filtering, but cannot fall through
to generic detail fetching, creation, editing, or cloning.

**Acceptance criteria:**

- [x] Existing types render from `items`, while public SSH keys render from
      `sshKeys` with name, public key, fingerprint, organization/folder,
      favorite, and re-prompt availability only.
- [x] SSH keys appear in normal list/search/count flows and contextual
      suggestions remain login-only.
- [x] Generic `bw get item`, create, edit, and clone paths reject type 5; a
      read-only detail view never displays or requests private material.

**Verification:**

- [x] Tests pass: `node tests/ssh-items.test.js && node tests/items.test.js`
- [x] QML tests pass: `QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml`
- [x] Manual check: open a fixture vault containing types 1–8 and inspect list,
      filters, search, counts, detail, and disabled actions.

**Dependencies:** Task 1

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-items.test.js`
- `tests/items.test.js`
- `tests/qml/tst_ssh_items.qml`

**Estimated scope:** Medium: 5 files

## Task 3: Enforce SSH support prerequisites

**Description:** Make `jq` a required dependency, establish the supported
Bitwarden CLI floor, and expose accurate diagnostics for old CLI versions,
unconfirmed server capability, and the pre-2026.8 malformed-SSH-item hazard.
Ordinary non-SSH vault behavior must remain usable whenever possible.

**Acceptance criteria:**

- [x] First-run dependency checks report missing `jq` as required without
      changing optional dependency semantics.
- [x] SSH UI/agent setup is unavailable below `bw` 2025.1.2 and reports
      unconfirmed capability separately from a confirmed empty key set.
- [x] A whole-list failure attributable to the known upstream SSH-item issue
      names the 2026.8.0 fix without exposing raw CLI output.

**Verification:**

- [x] Tests pass: `node tests/setup-settings.test.js && node tests/ssh-items.test.js`
- [x] Plugin validates: `omarchy plugin validate .`
- [x] Manual check: exercise missing `jq`, old `bw`, empty supported vault, and
      malformed-item fixture diagnostics.

**Dependencies:** Task 2

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `manifest.json`
- `tests/setup-settings.test.js`
- `tests/ssh-items.test.js`

**Estimated scope:** Medium: 5 files

## Checkpoint: Safe Panel Baseline (Tasks 1–3)

- [x] Full JavaScript and QML suites pass.
- [x] Qt6 lint remains at the documented baseline and the manifest validates.
- [x] Marker tests prove no SSH private key or unknown cipher reaches QML.
- [x] Human review approves the prerequisite boundary.

## Task 4: Pin the Rust security foundation

**Description:** Time-box the dependency spike, scaffold the Rust crate with an
exact toolchain and lockfile, and record the selected protocol, crypto,
zeroization, async, and Linux-runtime dependencies. The decision also fixes
public-key export ownership and documents rejected/deprecated alternatives.

**Acceptance criteria:**

- [x] Current primary sources confirm maintenance status, required Ed25519/RSA
      support, peer credentials, licenses, audit surface, and protocol hooks.
- [x] The decision identifies how parsed private components are zeroized or
      explicitly stops the project if credible lock-time erasure is impossible.
- [x] `cargo test --locked` builds a minimal headless crate on
      `x86_64-unknown-linux-gnu` with no vault/network dependency.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked`
- [x] Build succeeds: `cargo build --manifest-path agent/Cargo.toml --locked`
- [x] Manual check: security review the ADR, dependency tree, licenses, enabled
      features, and public-export ownership decision.

**Dependencies:** Task 3

**Files likely touched:**

- `agent/Cargo.toml`
- `agent/Cargo.lock`
- `agent/rust-toolchain.toml`
- `agent/src/lib.rs`
- `docs/decisions/0001-ssh-agent-dependencies.md`

**Estimated scope:** Medium: 5 files

## Task 5: Implement bounded SSH protocol signing

**Description:** Implement the allowlisted agent frame decoder and a signing
slice for request-identities and sign-request. Support Ed25519 and RSA
SHA-256/SHA-512 flags, reject all mutation/forwarding/unknown operations, and
check frame lengths before allocating.

**Acceptance criteria:**

- [x] OpenSSH-compatible vectors pass for identity listing, Ed25519, RSA
      SHA-256, and RSA SHA-512 signatures.
- [x] Frames over 256 KiB, truncation, invalid lengths/UTF-8, mutation requests,
      and unknown extensions fail with normal bounded agent failures.
- [x] No error or debug path emits private keys, payloads, signatures, or raw
      parser data.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test protocol`
- [x] Lint passes: `cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings`
- [x] Manual checkpoint approved: the existing panel remained functional after
      the protocol slice. The real `ssh-add -L` and disposable-key smoke test
      remains part of the Task 9 socket-harness checkpoint.

**Dependencies:** Task 4

**Files likely touched:**

- `agent/src/protocol.rs`
- `agent/src/signing.rs`
- `agent/src/lib.rs`
- `agent/tests/protocol.rs`

**Estimated scope:** Medium: 4 files

## Task 6: Implement the vault-epoch keystore

**Description:** Add the single-owner private keystore and explicit vault state
machine. Loads build a bounded candidate set, validate derived public material,
deduplicate identities, and swap atomically; lock first denies authorization,
then drops private material while retaining only the allowed public cache.

**Acceptance criteria:**

- [x] Candidate loads enforce 128 keys, 64 KiB per PEM, and 8 MiB total; one
      bad key is skipped, while framing/schema/limit failures reject the whole
      candidate without mixing old and new private keys.
- [x] Public blob and derived fingerprint must match vault metadata; duplicates
      advertise once and re-prompt items never enter the private keystore.
- [x] Lock/epoch tests prove no authorization crosses after the atomic deny
      point and secret containers are dropped/zeroized without long-lived
      clones.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test keystore`
- [x] Formatting passes: `cargo fmt --manifest-path agent/Cargo.toml --check`
- [x] Manual check: private owners have no clone/revealing-debug path; all seven
      load/lock/logout tests pass under Heaptrack and Valgrind. Both tools
      attribute their small exit-time retention only to Rust/loader test-runtime
      bookkeeping, with no project or crypto allocation leak path.

**Dependencies:** Task 5

**Files likely touched:**

- `agent/src/keystore.rs`
- `agent/src/state.rs`
- `agent/src/lib.rs`
- `agent/tests/keystore.rs`

**Estimated scope:** Medium: 4 files

## Checkpoint: Rust Primitives (Tasks 4–6)

- [x] Protocol, crypto, mismatch, limit, and lock tests pass.
- [x] Dependency and secret-memory findings support the stated lock semantics.
- [x] Human review approves continuing the headless implementation.

## Task 7: Implement nonce-framed FIFO loading

**Description:** Create the private runtime directory and key-load FIFO, keep
the FIFO open `O_RDWR`, and drain one nonce-framed candidate load into secret
buffers under hard size/time limits. Prove the intended `tee` backpressure and
exit-status behavior without letting the companion spawn production children.

**Acceptance criteria:**

- [x] Runtime directory/FIFO ownership, type, and modes are verified; stale,
      symlinked, wrong-owner, and wrong-type paths are refused safely.
- [x] Missing, stale, duplicate, truncated, malformed, or nonce-mismatched
      payloads fail the whole load and never publish a partial key set.
- [x] Stress tests prove bounded draining and document when the two-read
      fallback must replace the preferred `tee` design.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test load`
- [x] Build succeeds: `cargo build --manifest-path agent/Cargo.toml --locked`
- [x] Manual check: run FIFO/`tee` tests with slow readers, branch failure,
      duplicate writers, and the full 8 MiB limit.

**Dependencies:** Task 6

**Files likely touched:**

- `agent/src/load.rs`
- `agent/src/runtime.rs`
- `agent/src/lib.rs`
- `agent/tests/load.rs`
- `tests/ssh-agent-pipeline.test.js`

**Estimated scope:** Medium: 5 files

## Task 8: Authorize signatures with bounded grants

**Description:** Make the companion authoritative for request correlation,
peer context, approvals, and grants. Enforce peer UID, bounded queues/deadlines,
single-use approval, and process-scoped grants keyed by PID plus start time and
executable path, with a final epoch/state/key check immediately before signing.

**Acceptance criteria:**

- [x] At most four sign requests exist, each expires within 30 seconds and is
      cancelled on disconnect; late/duplicate/old-epoch approvals are rejected.
- [x] Grants are capped at 900 seconds, scoped to one key/live process, and
      revoked by every specified lifecycle event or identity mismatch.
- [x] Same-UID peer enforcement and PID-reuse/re-exec tests pass while prompt
      metadata remains explicitly non-authoritative.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test approvals`
- [x] Lint passes: `cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings`
- [x] Manual checkpoint approved with the existing panel intact. Headless
      approve-once, grant, expiry, re-exec, PID reuse,
      overflow, disconnect, and lock-at-final-check races.

**Dependencies:** Tasks 5 and 6

**Files likely touched:**

- `agent/src/approvals.rs`
- `agent/src/peer.rs`
- `agent/src/server.rs`
- `agent/src/lib.rs`
- `agent/tests/approvals.rs`

**Estimated scope:** Medium: 5 files

## Task 9: Complete the supervised companion lifecycle

**Description:** Assemble the headless binary around the stable socket,
versioned NDJSON control channel, keystore, and approvals. Enforce singleton
startup with `flock`, harden process dump behavior before secrets arrive, use
bounded concurrent tasks/channels, and close the signing gate on EOF or protocol
mismatch.

**Acceptance criteria:**

- [x] The helper creates a mode-0600 socket in the private runtime directory,
      holds the singleton lock, advertises a versioned `ready`, and rejects a
      concurrent stale-instance race.
- [x] Control lines over 64 KiB, wrong versions/types, full channels, slow
      clients, or stdin EOF fail closed without blocking lock processing.
- [x] The release process sets `RLIMIT_CORE=0`/`PR_SET_DUMPABLE=0`, spawns no
      children, needs no `PATH`/`HOME`/vault credential, and cleans runtime paths.

**Verification:**

- [x] Tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test lifecycle`
- [x] Build succeeds: `cargo build --manifest-path agent/Cargo.toml --locked`
- [x] Manual/real-client checkpoint: disposable-key signing with the real
      OpenSSH `ssh-keygen -Y sign` client, multiple clients, control EOF,
      singleton restart, and runtime cleanup pass; the existing panel remains
      intact after its live reload. Full panel-managed authentication begins
      after Task 10 adds supervision.

**Dependencies:** Tasks 7 and 8

**Files likely touched:**

- `agent/src/main.rs`
- `agent/src/control.rs`
- `agent/src/runtime.rs`
- `agent/src/server.rs`
- `agent/tests/lifecycle.rs`

**Estimated scope:** Medium: 5 files

## Checkpoint: Headless Companion (Tasks 7–9)

- [ ] All Rust tests, format, Clippy, and initial dependency audit pass.
- [ ] Real OpenSSH/Git smoke tests pass with disposable keys and a fake panel.
- [ ] No vault credential or production child process enters the helper.
- [ ] Human review approves the control protocol and threat boundary.

## Task 10: Establish companion supervision

**Description:** Add an inert-by-default Quickshell supervisor that launches a
development helper by absolute plugin-relative path, keeps stdin open, parses
NDJSON asynchronously from startup, performs the version handshake, applies
capped restart backoff, and isolates helper errors from the ordinary vault.

**Acceptance criteria:**

- [ ] Disabled mode starts nothing; enabled mode uses a tracked non-detached
      `Process`, minimal environment, absolute path, and compatible handshake.
- [ ] Quickshell never waits synchronously; overlong/malformed output, EOF,
      mismatch, or crash closes the signing gate and reaches a bounded error state.
- [ ] A crash loop stops restarts and leaves login, unlock, list, copy, sync,
      edit, Send, and generator flows usable.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-control.test.js`
- [ ] QML tests pass: `QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml`
- [ ] Manual check: use a fake helper to stream ready/errors, stall, emit bad
      lines, close stdin/stdout, crash repeatedly, and recover.

**Dependencies:** Tasks 3 and 9

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-agent-control.test.js`
- `tests/qml/tst_ssh_agent.qml`

**Estimated scope:** Medium: 4 files

## Task 11: Deliver opt-in session setup

**Description:** Add the three SSH-agent settings and explicit disabled,
enabled, and error states. Implement the user-confirmed UWSM environment
fragment lifecycle and report `SSH_AUTH_SOCK` only as advisory terminal-routing
diagnostics, never as a condition for running the helper.

**Acceptance criteria:**

- [ ] `sshAgentEnabled=false`, `sshAgentUnlockOnDemand=false`, and a clamped
      `sshAgentApprovalWindowSec=120` default are consistent across manifest,
      model schema, and settings UI.
- [ ] Managed UWSM setup/removal uses safe parent creation, atomic mode-safe
      writes, symlink refusal, unexpected-content refusal, conflict confirmation,
      and explicit logout/login guidance.
- [ ] Diagnostics distinguish matching, elsewhere, and unset client sockets and
      print the terminal check without gating companion startup.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-setup.test.js && node tests/setup-settings.test.js`
- [ ] Plugin validates: `omarchy plugin validate .`
- [ ] Manual check: test fresh setup, another agent, symlink, modified fragment,
      disable, unset runtime dir, and a new graphical login.

**Dependencies:** Task 10

**Files likely touched:**

- `manifest.json`
- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-agent-setup.test.js`

**Estimated scope:** Medium: 4 files

## Task 12: Feed the companion from the shared vault read

**Description:** Extend the single sanitized vault read with the optional
`tee`/FIFO branch. Coordinate `key_load_begin`/`key_load_end`, fresh load IDs,
process-group supervision, and a one-time retry without the agent branch so an
optional load can never break the ordinary item list.

**Acceptance criteria:**

- [ ] Enabled loads send only eligible type-5 key fields and matching nonce to
      the FIFO while QML stdout still contains neither private nor unrelated
      markers; disabled loads have no private branch at all.
- [ ] Whole-pipeline, branch, helper, timeout, cap, or validation failure leaves
      no partial private set and retries the core list once without the branch.
- [ ] Unlock/sync/startup use one successful `bw list items` read, and a lock can
      terminate/reap the entire `bw`/cap/`tee`/`jq` process group.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-pipeline.test.js && cargo test --manifest-path agent/Cargo.toml --locked --test load`
- [ ] Regression suite passes: `for test_file in tests/*.test.js; do node "$test_file" || exit 1; done`
- [ ] Manual check: use full-size fixtures, a stalled FIFO, wrong nonce, helper
      death, `jq` failure, and lock during fan-out while observing list recovery.

**Dependencies:** Tasks 1, 7, and 10

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-agent-pipeline.test.js`
- `agent/tests/load.rs`

**Estimated scope:** Medium: 4 files

## Checkpoint: Optional Data Plane (Tasks 10–12)

- [ ] Disabled mode is inert and core panel regressions pass.
- [ ] Enabled mode loads from one read with bounded fallback behavior.
- [ ] QML responsiveness is verified under blocked clients and failed helpers.
- [ ] Human review approves the opt-in and data-minimization behavior.

## Task 13: Enforce vault lifecycle transitions

**Description:** Wire the companion state machine into unlock, remembered-
session startup, sync, lock, logout, account change, screen lock, suspend,
disable, and panel shutdown. Lock must atomically deny first, cancel pending
work, clear grants/private keys, and enforce the two-second acknowledgment kill
fallback without delaying `bw lock`.

**Acceptance criteria:**

- [ ] Every lifecycle path advances the epoch and produces the specified public
      cache, private cache, grants, pending requests, and process state.
- [ ] No signature response from the previous epoch returns after lock
      acknowledgment; timeout kills/reaps the helper while the vault lock proceeds.
- [ ] Starting beside a remembered unlocked session performs an initial key
      load, while logout/account change/disable clear public projections too.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-lifecycle.test.js && node tests/lock-triggers.test.js && node tests/lock-state.test.js`
- [ ] Rust tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test lifecycle`
- [ ] Manual check: lock during load/approval/signing/grant, suspend, screen lock,
      restart unlocked, logout, account switch, disable, and failed acknowledgment.

**Dependencies:** Tasks 8, 9, 10, and 12

**Files likely touched:**

- `Panel.qml`
- `tests/ssh-agent-lifecycle.test.js`
- `tests/lock-triggers.test.js`
- `tests/lock-state.test.js`

**Estimated scope:** Medium: 4 files

## Task 14: Deliver signing authorization UX

**Description:** Add one-at-a-time approval UI, the opt-in unlock-on-demand
flow, sanitized process/key context, request cancellation, cooldown, live grant
status, individual/all revoke controls, and panel focus rules that never prompt
over screen lock.

**Acceptance criteria:**

- [ ] Prompts clearly offer deny, approve once, and process grant only when
      enabled; they show key/process/forwarding context without overstating PID
      authority.
- [ ] Locked cached keys prompt at sign time; no-cache identity listing prompts
      only when unlock-on-demand is enabled, with coalescing and denial cooldown.
- [ ] Four-request/deadline/disconnect behavior is visible and bounded, and live
      grants update/revoke without freezing or exposing secret control data.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-ui.test.js`
- [ ] QML tests pass: `QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml`
- [ ] Manual check: authentication, fetch/push, signing, rebase, denied unlock,
      timeout, disconnect, grant expiry/revoke, and screen-lock suppression.

**Dependencies:** Tasks 8, 10, and 13

**Files likely touched:**

- `Panel.qml`
- `tests/ssh-agent-ui.test.js`
- `tests/qml/tst_ssh_agent.qml`

**Estimated scope:** Medium: 3 files

The two-read fallback is required if the agent branch cannot drain and
acknowledge a complete nonce-matching payload within the panel pipeline's
deadline, if its FIFO write fails, or if process-substitution status cannot be
correlated with the candidate acknowledgment. In every fallback case the panel
read remains authoritative and the failed candidate is discarded before a
separate bounded agent-only read is attempted.

## Task 15: Project validated public-key files

**Description:** Export only the companion's validated public identities to a
private plugin data directory, using deterministic hostile-name handling and
collision-safe filenames. Keep the projection across vault lock, refresh it
atomically per epoch, and clear it on logout, account change, or disable.

The panel writes the files from the validated public set the companion reports;
the companion stays out of the filesystem. See
`docs/decisions/0001-ssh-agent-dependencies.md`.

**Acceptance criteria:**

- [ ] One mode-0600 `.pub` file per advertised key exists inside a mode-0700
      directory; symlinks, wrong owners/types, collisions, and unexpected files
      cannot redirect or overwrite output.
- [ ] Projection updates are atomic, survive lock, and clear on logout/account
      change/disable without ever writing private material.
- [ ] Real Git SSH signing and `IdentityFile`/`IdentitiesOnly` flows work from
      the exported paths using disposable keys.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-export.test.js`
- [ ] Manual check: inspect modes/content/lifecycle and sign/verify a commit with
      `gpg.format=ssh` and a generated allowed-signers file.

**Dependencies:** Tasks 4, 6, 9, and 13

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `agent/src/control.rs`
- `tests/ssh-agent-export.test.js`

**Estimated scope:** Medium: 4 files

## Checkpoint: End-to-End Feature (Tasks 13–15)

- [ ] Lifecycle, UI, export, full Rust, full JavaScript, and QML suites pass.
- [ ] Real authentication and signing work without a private key on disk.
- [ ] Security review confirms private material paths and final authorization.
- [ ] Human usability/security review approves packaging.

## Task 16: Make the release build reproducible

**Description:** Define a digest-pinned x86_64 GNU build environment and one
local/CI build entry point using the committed lockfile/toolchain, fixed release
features, path remapping, deterministic stripping, and a byte-comparison mode.
Produce separate debug symbols only as temporary artifacts.

**Acceptance criteria:**

- [ ] Two clean builds from distinct absolute work paths emit identical
      stripped helper bytes and stable checksums.
- [ ] Build inputs cover toolchain, container, linker/strip tools, target,
      flags, release profile, source path, and Cargo registry path.
- [ ] The script refuses unlocked dependencies or an unsupported target and
      reports source/binary drift without modifying the repository.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-artifact.test.js`
- [ ] Build succeeds: `scripts/build-agent.sh --verify-reproducible`
- [ ] Manual check: compare artifacts from two clean paths and inspect them with
      `file`, `readelf`, `ldd`, `sha256sum`, and helper `--self-test`.

**Dependencies:** Task 9

**Files likely touched:**

- `.github/agent-build.Dockerfile`
- `agent/.cargo/config.toml`
- `scripts/build-agent.sh`
- `tests/ssh-agent-artifact.test.js`

**Estimated scope:** Medium: 4 files

## Task 17: Add read-only pull-request gates

**Description:** Add least-privilege CI for existing tests, Rust quality,
dependency/license policy, native target execution, disposable-key end-to-end
tests, candidate artifacts, and conditional tracked-binary comparison. Fork PRs
must remain useful without receiving secrets or repository write permission.

**Acceptance criteria:**

- [ ] PR jobs default to `contents: read`, use no secrets/write token, pin every
      third-party action by full SHA, and upload but never commit candidates.
- [ ] CI runs JavaScript/QML, fmt, Clippy, Rust tests, native E2E, RustSec,
      license/source/duplicate policy, and reproducible build checks.
- [ ] Source-only fork PRs report candidate drift without impossible blocking;
      `bin/` changes and merges to `master` require exact clean-build bytes.

**Verification:**

- [ ] Policy passes: `cargo deny --manifest-path agent/Cargo.toml check`
- [ ] Workflow passes: open a same-repo branch run and a fork-style dry run with
      source-only and `bin/`-touching change matrices.
- [ ] Manual check: inspect effective workflow permissions, action SHAs,
      artifacts, logs, and absence of secret material.

**Dependencies:** Task 16

**Files likely touched:**

- `.github/workflows/ci.yml`
- `.github/dependabot.yml`
- `deny.toml`
- `.github/CODEOWNERS`

**Estimated scope:** Medium: 4 files

## Checkpoint: Candidate Artifact (Tasks 16–17)

- [ ] Reproducibility and every read-only PR gate pass.
- [ ] Fork contribution and tracked-byte policies are both workable.
- [ ] Human supply-chain review approves bundling the artifact.

## Task 18: Validate the bundled helper at launch

**Description:** Add the tracked x86_64 GNU helper and checksum, then make the
panel validate architecture/format, executable mode, checksum consistency,
self-test, semantic/control versions, and handshake before enabling SSH-agent
behavior. Failures must disable only this optional feature.

**Acceptance criteria:**

- [ ] The repository contains executable release bytes and a matching checksum
      produced by Task 16, without Git LFS or runtime download.
- [ ] Missing, corrupt, stale, wrong-architecture, non-executable, self-test-
      failing, or protocol-mismatched helpers reach clear bounded diagnostics.
- [ ] Every validation failure leaves the rest of the Bitwarden plugin usable
      and creates no agent socket/FIFO/private branch.

**Verification:**

- [ ] Tests pass: `node tests/ssh-agent-bundle.test.js`
- [ ] Artifact check passes: `scripts/build-agent.sh --compare-tracked`
- [ ] Manual check: replace the helper in a disposable checkout with each
      failure form and confirm isolated setup diagnostics.

**Dependencies:** Tasks 10 and 16

**Files likely touched:**

- `bin/x86_64-linux/qs-bitwarden-ssh-agent`
- `bin/SHA256SUMS`
- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-agent-bundle.test.js`

**Estimated scope:** Medium: 5 files

## Task 19: Protect release provenance

**Description:** Add a protected tag workflow that repeats all gates, verifies
tracked bytes/checksums, creates GitHub build-provenance attestations, and
publishes SBOM plus dependency/license reports. Restrict elevated permissions
to the final release job and require review for security-sensitive paths.

**Acceptance criteria:**

- [ ] Protected releases rebuild/compare final bytes, run them natively, verify
      checksum/mode/version/self-test, and fail before publication on drift.
- [ ] Only the reviewed release job receives `id-token: write` and
      `attestations: write`; all actions are SHA-pinned and source paths have
      required CODEOWNERS review.
- [ ] Release artifacts include provenance, SBOM, dependency/license report,
      and separate debug symbols but no vault/test secret material.

**Verification:**

- [ ] Workflow passes: execute a protected test tag/release in a staging target.
- [ ] Provenance verifies: `gh attestation verify bin/x86_64-linux/qs-bitwarden-ssh-agent --repo Elevate08/qs-bitwarden-cli`
- [ ] Manual check: audit permissions, environment protection, attestation
      subject/digest, SBOM, reports, and retention settings.

**Dependencies:** Tasks 17 and 18

**Files likely touched:**

- `.github/workflows/release.yml`
- `.github/CODEOWNERS`

**Estimated scope:** Small: 2 files

## Checkpoint: Shippable Artifact (Tasks 18–19)

- [ ] Tracked bytes equal the protected clean build and pass native validation.
- [ ] Provenance, checksum, SBOM, license, and permission checks pass.
- [ ] Human release-governance review approves the trust path.

## Task 20: Complete release documentation

**Description:** Update user, operator, and design documentation for setup,
socket routing, approvals, grants, export, Git authentication/signing, locking,
security limits, provenance, upgrades, troubleshooting, disable/uninstall
cleanup, and the feature's explicit threat boundary. Resolve the design draft's
public-export contradiction and mark validated assumptions with evidence.

**Acceptance criteria:**

- [ ] Documentation accurately covers UWSM re-login, terminal diagnostics,
      conflicts with other agents, configuration snippets, grants, public
      files, version floor, helper verification, and cleanup after removal.
- [ ] The threat model plainly distinguishes best-effort erasure, public cache,
      same-UID/root limits, `bw` exposure, checksum corruption checks, and CI
      provenance without overstating any guarantee.
- [ ] The complete manual matrix passes for login/unlock/sync/lock/logout,
      both unlock-on-demand modes, auth/sign/rebase, crash/reload/update,
      disable/uninstall, and normal non-vault SSH keys.

**Verification:**

- [ ] Full gates pass: JavaScript, QML, Qt6 lint baseline, manifest validation,
      Rust fmt/Clippy/tests, dependency policy, reproducible build, and E2E.
- [ ] Docs check: follow setup, signing, verification, troubleshooting, and
      uninstall instructions from a clean disposable user/session.
- [ ] Manual check: complete the release matrix and obtain human security,
      usability, documentation, and release approval.

**Dependencies:** Tasks 3, 11, 14, 15, and 19

**Files likely touched:**

- `README.md`
- `CHANGELOG.md`
- `manifest.json`
- `docs/ideas/ssh-agent.md`

**Estimated scope:** Medium: 4 files

## Checkpoint: Complete (Task 20)

- [ ] Every task's acceptance criteria pass.
- [ ] The full project Definition of Done passes.
- [ ] No task exceeded five files without being split and re-reviewed.
- [ ] Human approval is recorded before merge or release.
