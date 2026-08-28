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

- [x] Disabled mode starts nothing; enabled mode uses a tracked non-detached
      `Process`, minimal environment, absolute path, and compatible handshake.
- [x] Quickshell never waits synchronously; overlong/malformed output, EOF,
      mismatch, or crash closes the signing gate and reaches a bounded error state.
- [x] A crash loop stops restarts and leaves login, unlock, list, copy, sync,
      edit, Send, and generator flows usable.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-control.test.js`
- [x] QML tests pass: `QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml`
- [x] Manual check: `tests/ssh-agent-control.test.js` drives the real reducer
      against real child processes -- fake helpers that answer the handshake,
      stall silently, emit non-JSON, emit an oversized line, close stdin, and
      die at once -- plus the real helper binary, which completes the v1
      handshake with only `XDG_RUNTIME_DIR`, reports paths under that
      directory, and cleans up its socket when stdin closes. Live: the shell
      restarted, `omarchy-shell shell ping` answered, the panel opened, and
      `status` returned `locked` with no helper process, socket, or FIFO
      created in the default disabled mode.

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

- [x] `sshAgentEnabled=false`, `sshAgentUnlockOnDemand=false`, and a clamped
      `sshAgentApprovalWindowSec=120` default are consistent across manifest,
      model schema, and settings UI.
- [x] Managed UWSM setup/removal uses safe parent creation, atomic mode-safe
      writes, symlink refusal, unexpected-content refusal, conflict confirmation,
      and explicit logout/login guidance.
- [x] Diagnostics distinguish matching, elsewhere, and unset client sockets and
      print the terminal check without gating companion startup.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-setup.test.js && node tests/setup-settings.test.js`
- [x] Plugin validates: `omarchy plugin validate .`
- [x] Manual check: `tests/ssh-agent-setup.test.js` exercises the real scripts
      against real temporary homes -- fresh setup, an idempotent rewrite,
      removal, a hand-written fragment, a symlink over a real file, a
      directory at the path, and an unset HOME -- asserting in each case that
      foreign content and symlink targets are left byte-identical. Another
      agent, unset socket, and matching socket are covered by the diagnostic
      cases. Live: the shell restarted, `omarchy-shell shell ping` answered,
      the panel and its settings screen opened, and with the feature off no
      helper, socket, FIFO, or routing file exists. A new graphical login is
      the user's to exercise; nothing in this task writes the fragment
      without an explicit click.

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

- [x] Enabled loads send only eligible type-5 key fields and matching nonce to
      the FIFO while QML stdout still contains neither private nor unrelated
      markers; disabled loads have no private branch at all.
- [x] Whole-pipeline, branch, helper, timeout, cap, or validation failure leaves
      no partial private set and retries the core list once without the branch.
- [x] Unlock/sync/startup use one successful `bw list items` read, and a lock can
      terminate/reap the entire `bw`/cap/`tee`/`jq` process group.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-pipeline.test.js && cargo test --manifest-path agent/Cargo.toml --locked --test load`
- [x] Regression suite passes: `for test_file in tests/*.test.js; do node "$test_file" || exit 1; done`
- [x] Manual check: `tests/ssh-agent-pipeline.test.js` runs the real pipeline
      against a real FIFO for a missing FIFO, a regular file squatting the
      path, an undrained FIFO, an absent nonce, malformed/truncated/non-array
      input, and a `bw` that exits nonzero after a valid document -- the item
      list survives every one. Its end-to-end case drives the real companion
      with a disposable key and confirms `ssh-add -L` lists exactly the key
      the vault held. Helper death during a stop was found to leave the socket
      and FIFO behind and is now fixed; see the graceful-shutdown note below.

**Dependencies:** Tasks 1, 7, and 10

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `tests/ssh-agent-pipeline.test.js`
- `agent/tests/load.rs`

**Estimated scope:** Medium: 4 files

## Checkpoint: Optional Data Plane (Tasks 10–12)

- [x] Disabled mode is inert and core panel regressions pass.
- [x] Enabled mode loads from one read with bounded fallback behavior.
- [x] QML responsiveness is verified under blocked clients and failed helpers.
- [ ] Human review approves the opt-in and data-minimization behavior.

## Task 13: Enforce vault lifecycle transitions

**Description:** Wire the companion state machine into unlock, remembered-
session startup, sync, lock, logout, account change, screen lock, suspend,
disable, and panel shutdown. Lock must atomically deny first, cancel pending
work, clear grants/private keys, and enforce the two-second acknowledgment kill
fallback without delaying `bw lock`.

**Acceptance criteria:**

- [x] Every lifecycle path advances the epoch and produces the specified public
      cache, private cache, grants, pending requests, and process state.
- [x] No signature response from the previous epoch returns after lock
      acknowledgment; timeout kills/reaps the helper while the vault lock proceeds.
- [x] Starting beside a remembered unlocked session performs an initial key
      load, while logout/account change/disable clear public projections too.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-lifecycle.test.js && node tests/lock-triggers.test.js && node tests/lock-state.test.js`
- [x] Rust tests pass: `cargo test --manifest-path agent/Cargo.toml --locked --test lifecycle`
- [x] Manual check: live, with a real vault -- a shell restart into a
      keyring-remembered unlocked session loaded keys (found and fixed a race
      where the handshake and the first `bw status` could each be second), a
      lock dropped the private set while the helper survived its
      acknowledgment, and disabling stopped the helper and emptied the runtime
      directory. Screen lock and suspend route through the same lock path.
      Logout, account switch, and the locked-with-cache identity listing are
      covered end to end over the real socket by
      `agent/tests/lifecycle.rs::a_locked_vault_still_lists_identities_but_refuses_to_sign`.
      NOT yet confirmed live: the locked-with-cache listing needs an unlocked
      vault, and the approval/signing/grant lock races belong to Task 14.

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

- [x] Prompts clearly offer deny, approve once, and process grant only when
      enabled; they show key/process/forwarding context without overstating PID
      authority.
- [x] Locked cached keys prompt at sign time; no-cache identity listing prompts
      only when unlock-on-demand is enabled, with coalescing and denial cooldown.
- [x] Four-request/deadline/disconnect behavior is visible and bounded, and live
      grants update/revoke without freezing or exposing secret control data.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-ui.test.js`
- [x] QML tests pass: `QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml`
- [x] Manual check: live, against a real vault and real OpenSSH clients --
      `git push` authentication, `ssh-keygen -Y sign`, repeated signed commits
      riding one grant, approving during a load, a dismissed unlock, request
      timeout, and client disconnect. Found and fixed three defects no
      automated test caught: the prompt never rendered (opening the panel
      reset the screen after it was set), timeouts never fed the cooldown,
      and the cooldown failed silently. Two design deviations were recorded
      rather than made quietly: docs/decisions/0002-grant-scope.md and
      docs/decisions/0003-request-deadline.md.

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

- [x] One mode-0600 `.pub` file per advertised key exists inside a mode-0700
      directory; symlinks, wrong owners/types, collisions, and unexpected files
      cannot redirect or overwrite output.
- [x] Projection updates are atomic, survive lock, and clear on logout/account
      change/disable without ever writing private material.
- [x] Real Git SSH signing and `IdentityFile`/`IdentitiesOnly` flows work from
      the exported paths using disposable keys.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-export.test.js`
- [x] Manual check: live, against the real vault. The projection is a 0700
      directory holding one 0600 `.pub` per advertised key with correct
      OpenSSH content. A commit signed with `gpg.format=ssh`,
      `user.signingkey` pointing at an exported path, and a generated
      allowed-signers file verifies: `git verify-commit` reports a good
      ED25519 signature and `git log %G?` reports `G`. Commits made earlier
      through the locked-vault unlock-then-approve path verify the same way.

**Dependencies:** Tasks 4, 6, 9, and 13

**Files likely touched:**

- `BitwardenModel.js`
- `Panel.qml`
- `agent/src/control.rs`
- `tests/ssh-agent-export.test.js`

**Estimated scope:** Medium: 4 files

## Checkpoint: End-to-End Feature (Tasks 13–15)

- [x] Lifecycle, UI, export, full Rust, full JavaScript, and QML suites pass.
- [x] Real authentication and signing work without a private key on disk.
- [x] Security review confirms private material paths and final authorization.
- [ ] Human usability/security review approves packaging.

## Task 16: Make the release build reproducible

**Description:** Define a digest-pinned x86_64 GNU build environment and one
local/CI build entry point using the committed lockfile/toolchain, fixed release
features, path remapping, deterministic stripping, and a byte-comparison mode.
Produce separate debug symbols only as temporary artifacts.

**Acceptance criteria:**

- [x] Two clean builds from distinct absolute work paths emit identical
      stripped helper bytes and stable checksums.
- [x] Build inputs cover toolchain, container, linker/strip tools, target,
      flags, release profile, source path, and Cargo registry path.
- [x] The script refuses unlocked dependencies or an unsupported target and
      reports source/binary drift without modifying the repository.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-artifact.test.js`
- [x] Build succeeds: `scripts/build-agent.sh --verify-reproducible` -- green
      in CI, which runs it inside the pinned image. It refuses locally for want
      of that image, by design, and `--explain` says so without building.
- [x] Manual check: done in CI rather than locally, this machine having no
      usable container runtime. Two builds from `/tmp/*/path-one` and
      `/tmp/*/a-considerably-longer-second-path` produced identical bytes:
      sha256 7f4c38d405adf16504ea7029896365c4081b0e154a4fc1755cd624c12503e816.
      Built under rustc 1.98.0 and GNU ld 2.40 in the pinned Debian bookworm
      image -- the host's ld 2.47 would have produced different bytes, which
      is what the image exists to prevent. `readelf`/`ldd` inspection of the
      committed artifact belongs with Task 18, which is where a binary is
      first committed.

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

- [x] PR jobs default to `contents: read`, use no secrets/write token, pin every
      third-party action by full SHA, and upload but never commit candidates.
- [x] CI runs JavaScript/QML, fmt, Clippy, Rust tests, native E2E, RustSec,
      license/source/duplicate policy, and reproducible build checks.
- [x] Source-only fork PRs report candidate drift without impossible blocking;
      `bin/` changes and merges to `master` require exact clean-build bytes.

**Verification:**

- [x] Policy passes: `cargo deny --manifest-path agent/Cargo.toml check`
- [x] Workflow passes: green on the same-repository feature branch across all
      three jobs. The fork path is implemented and reviewed but NOT exercised
      -- it needs an actual fork PR, which cannot be raised against one's own
      repository. Worth running once before this reaches master.
- [x] Manual check: permissions are `contents: read` only, every action is
      pinned to a full commit SHA with its version in a trailing comment, no
      `secrets.` reference appears, the candidate is uploaded and never
      committed by CI, and the logs carry no key material. Asserted by
      `tests/ssh-agent-artifact.test.js` as well as read by eye.

**Dependencies:** Task 16

**Files likely touched:**

- `.github/workflows/ci.yml`
- `.github/dependabot.yml`
- `deny.toml`
- `.github/CODEOWNERS`

**Estimated scope:** Medium: 4 files

## Checkpoint: Candidate Artifact (Tasks 16–17)

- [x] Reproducibility and every read-only PR gate pass.
- [x] Fork contribution and tracked-byte policies are both workable.
- [ ] Human supply-chain review approves bundling the artifact.

## Task 18: Validate the bundled helper at launch

**Description:** Add the tracked x86_64 GNU helper and checksum, then make the
panel validate architecture/format, executable mode, checksum consistency,
self-test, semantic/control versions, and handshake before enabling SSH-agent
behavior. Failures must disable only this optional feature.

**Acceptance criteria:**

- [x] The repository contains executable release bytes and a matching checksum
      produced by Task 16, without Git LFS or runtime download.
- [x] Missing, corrupt, stale, wrong-architecture, non-executable, self-test-
      failing, or protocol-mismatched helpers reach clear bounded diagnostics.
- [x] Every validation failure leaves the rest of the Bitwarden plugin usable
      and creates no agent socket/FIFO/private branch.

**Verification:**

- [x] Tests pass: `node tests/ssh-agent-bundle.test.js`
- [x] Artifact check passes: `scripts/build-agent.sh --compare-tracked` --
      green in CI: tracked and freshly built both
      69245af23a45ac96ec5e5d84ca1b34918cc8f0807a4b0e2aea6a74bac6a72852.
- [x] Manual check: `tests/ssh-agent-bundle.test.js` does exactly this against
      real files in disposable directories -- missing, non-executable,
      truncated, a Git LFS placeholder, and a broken shipped binary beside a
      working development build -- asserting the feature stays off and the
      diagnostic names the cause. Live: the panel launches
      bin/x86_64-linux/qs-bitwarden-ssh-agent, reaches ready and serves both
      keys.

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

- [x] Protected releases rebuild/compare final bytes, run them natively, verify
      checksum/mode/version/self-test, and fail before publication on drift.
      The gates stage calls `agent-build.yml` rather than copying it, so the
      release runs the branch's own `--verify-reproducible` and
      `--compare-tracked` against the tagged commit; the verify stage re-checks
      `bin/SHA256SUMS`, the executable bit, the ELF class, and the helper's
      reported crate and control-protocol versions against `agent/Cargo.toml`
      and `BitwardenModel.js`; the release stage runs the shipped bytes on the
      bare runner, outside the build container, before it publishes anything.
- [x] Only the reviewed release job receives `id-token: write` and
      `attestations: write`; all actions are SHA-pinned and source paths have
      required CODEOWNERS review. The workflow defaults to `contents: read`,
      the gates and verify jobs restate it rather than inheriting it, and the
      release job sits behind the `release` environment.
- [x] Release artifacts include provenance, SBOM, dependency/license report,
      and separate debug symbols but no vault/test secret material. The debug
      symbols are a companion build and say so: the release profile strips
      symbols, and a build with debug information links differently, so its
      entry point and code layout are not the shipped binary's. That was
      measured, not assumed, and `dist/DEBUG-SYMBOLS.md` states the limit where
      whoever downloads the file will read it.

**Verification:**

- [x] Tests pass: `node tests/release-provenance.test.js`
- [x] Environment configured: `release`, required reviewer `@Elevate08`
      (self-review permitted -- single maintainer), deployments restricted to
      `v*` tags. Confirmed through the API after creation.
- [ ] Workflow passes: execute a protected test tag/release in a staging target.
      The publishing half is still unrun -- a tag publishes to a public
      repository, so it is the maintainer's to push. Everything before it has
      now run on real CI twice, via a temporary branch trigger that was
      reverted immediately afterwards (`e696fb1` and its revert):
      gates, tag/manifest/changelog agreement, checksum and ELF checks, the
      version cross-check, `--self-test`, the SBOM, the licence and dependency
      reports, the debug symbols, and the secret scan all pass, and the
      publishing job correctly skipped itself on a non-tag ref.

      The rehearsal earned its cost. It found two defects that reading the file
      had not: a container job's default shell is `sh`, which has no arrays, so
      the secret scan died after every expensive step had passed; and the gates
      stage shared `agent-build.yml`'s concurrency group, letting a branch
      build and a release cancel each other. Both are fixed and both now have
      a test.
- [ ] Provenance verifies: `gh attestation verify bin/x86_64-linux/qs-bitwarden-ssh-agent --repo Elevate08/qs-bitwarden-cli`
      Waits on the first protected tag run: nothing has been attested yet.
- [ ] Manual check: audit permissions, environment protection, attestation
      subject/digest, SBOM, reports, and retention settings. Permissions and
      environment protection are audited by the tests above; the attestation
      subject, digest and published assets can only be audited after a run.

**Dependencies:** Tasks 17 and 18

**Files likely touched:**

- `.github/workflows/release.yml`
- `.github/CODEOWNERS`
- `.github/workflows/agent-build.yml` (made callable, so the release reuses
  the branch's gates instead of duplicating them)
- `tests/release-provenance.test.js`

**Estimated scope:** Small: 4 files

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
