# Implementation Plan: Opt-in Bitwarden SSH Agent

## Overview

Build the SSH-agent design in `docs/ideas/ssh-agent.md` as an optional,
disabled-by-default feature. The existing Quickshell panel remains the only
component that invokes `bw` and owns `BW_SESSION`; a supervised Rust companion
implements the local SSH-agent protocol, holds private SSH keys only while the
vault is unlocked, and makes signing contingent on a live approval or bounded
process grant. Before any agent work, the ordinary vault read is sanitized
outside QML so unsupported cipher types and `sshKey.privateKey` cannot enter
the long-lived panel process.

Detailed tasks and checkpoints are tracked in `tasks/todo.md`. No feature code
should be written until this plan has human approval.

## Development Worktree and Live Checkpoints

- Develop on branch `feature/ssh-agent` in `.worktrees/ssh-agent`, based on the
  latest fetched `origin/master`. Keep the primary `master` checkout free of
  feature changes.
- The enabled Omarchy plugin path
  `~/.config/omarchy/plugins/io.github.elevate08.qs-bitwarden-cli` must resolve
  to this worktree before any live test.
- At the end of every task slice, run its focused tests plus the applicable
  regression/QML/lint/manifest gates, verify the plugin symlink target, run
  `omarchy restart shell`, confirm `omarchy-shell shell ping`, summon the
  Bitwarden panel, and call its non-secret `status` IPC method.
- Pause after that live reload so the user can exercise the plugin manually.
  Do not start the next task until the user confirms the checkpoint or reports
  issues to fix.

## Scope

The first release includes:

- a public-only, read-only SSH-key item experience in the panel;
- Ed25519 and RSA SHA-2 authentication/signing through a stable Unix socket;
- explicit per-signature approval and short per-process grants;
- opt-in unlock-on-demand, safe UWSM client routing, and advisory diagnostics;
- public-key file projection for normal Git SSH-signing configuration;
- an x86_64 GNU helper bundled with the plugin and verified by reproducible CI.

It does not include key creation/import, SSH item editing/cloning, master-
password re-prompt keys, forwarding, persistent grants, GPG-agent support,
item types 6–8, aarch64, or a Bitwarden SDK/direct service integration.

## Architecture Decisions

- Sanitize `bw list items` with static `jq` programs before QML parses it. QML
  receives intact types 1–4 and a public-only type-5 projection; all other
  types fail closed out of the display model.
- Keep one panel-owned `bw list items` read per unlock/sync. When the agent is
  enabled, a bounded `tee` branch sends only eligible type-5 private material
  to a nonce-framed FIFO. Failure of that optional branch must never prevent
  the panel list from loading.
- Use one Rust companion and one stable socket under `$XDG_RUNTIME_DIR`. The
  companion spawns no child processes, receives neither `BW_SESSION` nor
  unrelated vault data, and exits when its control channel closes.
- Make approval, epoch checks, request limits, and final allow/deny decisions
  authoritative in the companion. Process information is prompt context, not
  an authentication boundary.
- Treat public-key file export as v1 scope because normal Git SSH signing needs
  file paths. The planning assumption is that the companion owns this
  projection from its validated public keystore; Task 4 records or corrects
  that ownership before implementation proceeds.
- Ship only `x86_64-unknown-linux-gnu` initially. Commit the source, lockfile,
  pinned toolchain, release bytes, and checksum; compare clean CI output byte
  for byte before anything reaches `master` or a release.

## Dependency Graph

```text
Task 1 sanitized read contract
  └── Task 2 panel SSH-key slice
        └── Task 3 prerequisites and diagnostics

Task 4 Rust dependency/security decision
  └── Task 5 protocol and signing
        └── Task 6 epoch keystore
              ├── Task 7 nonce FIFO loading
              └── Task 8 approvals and grants (also depends on Task 5)
                    └── Task 9 companion lifecycle (also depends on Task 7)

Tasks 3 + 9
  └── Task 10 QML supervision
        ├── Task 11 opt-in setup
        └── Task 12 shared vault fan-out (also depends on Tasks 1 + 7)
              └── Task 13 vault lifecycle (also depends on Tasks 8 + 9)
                    ├── Task 14 approval UI
                    └── Task 15 public-key projection

Task 9
  └── Task 16 reproducible build
        └── Task 17 pull-request gates

Tasks 10 + 16
  └── Task 18 bundled-helper validation
        └── Task 19 protected release (also depends on Task 17)

Tasks 3 + 11 + 14 + 15 + 19
  └── Task 20 documentation and release validation
```

## Task List

### Phase 1: Remove the Existing Exposure

- [x] Task 1: Introduce the sanitized vault-read contract
- [x] Task 2: Deliver the public SSH-key panel slice
- [x] Task 3: Enforce SSH support prerequisites

### Checkpoint: Safe Panel Baseline

- [ ] QML-facing fixture output contains no SSH private-key marker or unknown
      cipher-type marker.
- [ ] SSH keys are public-only and cannot reach generic detail/edit paths.
- [ ] All current JavaScript and QML tests pass; the plugin validates and lints
      at its existing baseline.
- [ ] Human review approves the security boundary before Rust work continues.

### Phase 2: Prove the Headless Agent Core

- [x] Task 4: Pin the Rust security foundation
- [x] Task 5: Implement bounded SSH protocol signing
- [x] Task 6: Implement the vault-epoch keystore

### Checkpoint: Rust Primitives

- [x] Ed25519 and both RSA SHA-2 modes pass protocol-vector tests.
- [x] Lock, malformed input, mismatch, and limit paths fail closed.
- [x] The dependency/zeroization decision is recorded and reviewed.

- [x] Task 7: Implement nonce-framed FIFO loading
- [x] Task 8: Authorize signatures with bounded grants
- [x] Task 9: Complete the supervised companion lifecycle

### Checkpoint: Headless Companion

- [ ] Disposable-key tests cover identities, signing, multiple clients,
      approval, grants, lock races, and FIFO rejection.
- [ ] The helper serves only its private stable socket, has no vault credential,
      spawns no process, and exits on control EOF.
- [ ] Manual headless authentication and Git SSH-signing smoke tests pass.
- [ ] Human review approves proceeding to panel integration.

### Phase 3: Integrate the Optional Feature

- [x] Task 10: Establish companion supervision
- [x] Task 11: Deliver opt-in session setup
- [x] Task 12: Feed the companion from the shared vault read

### Checkpoint: Optional Data Plane

- [x] Disabled mode starts no helper and creates no socket, FIFO, or private-key
      branch.
- [x] Enabled mode loads keys from the same vault read without delaying or
      breaking the ordinary list on helper failure.
- [x] QML remains responsive during blocked SSH clients and helper events.

- [x] Task 13: Enforce vault lifecycle transitions
- [x] Task 14: Deliver signing authorization UX
- [x] Task 15: Project validated public-key files

### Checkpoint: End-to-End Feature

- [x] Lock, logout, account change, suspend, screen lock, disable, crash, and
      Quickshell reload all satisfy the state machine.
- [x] Authentication, commit signing, and multi-commit signing work with no
      private key on disk.
- [x] Public projections survive lock but clear on logout/account change/disable.
- [ ] Human security and usability review approves packaging.

### Phase 4: Establish the Artifact Trust Path

- [x] Task 16: Make the release build reproducible
- [ ] Task 17: Add read-only pull-request gates

### Checkpoint: Candidate Artifact

- [ ] Two clean pinned builds produce identical stripped bytes.
- [ ] Existing, Rust, audit, license, and end-to-end gates pass with no PR
      secrets or write token.

- [ ] Task 18: Validate the bundled helper at launch
- [ ] Task 19: Protect release provenance

### Checkpoint: Shippable Artifact

- [ ] The tracked helper is executable, native-tested, checksum-consistent,
      protocol-compatible, and byte-identical to the protected build.
- [ ] A release produces provenance attestation, SBOM, and dependency/license
      report with narrowly scoped permissions.

### Phase 5: Document and Release

- [ ] Task 20: Complete release documentation

### Checkpoint: Complete

- [ ] Every task's acceptance criteria and the project Definition of Done pass.
- [ ] Setup, conflict, logout/login, upgrade, verification, and uninstall paths
      are documented and manually exercised.
- [ ] No private key, session token, signed payload, or signature appears in
      QML state, argv, logs, files, CI artifacts, or test diagnostics.
- [ ] Human review approves merge and release.

## Verification Strategy

Use focused tests after each task and these full gates at checkpoints:

```bash
for test_file in tests/*.test.js; do node "$test_file" || exit 1; done
QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml
mkdir -p /tmp/qs-imports
ln -sfn /usr/share/omarchy/shell /tmp/qs-imports/qs
/usr/lib/qt6/bin/qmllint -I /tmp/qs-imports Panel.qml FormPickerRow.qml
omarchy plugin validate .

cargo fmt --manifest-path agent/Cargo.toml --check
cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path agent/Cargo.toml --locked --all-targets
cargo deny --manifest-path agent/Cargo.toml check
```

The final runtime matrix must include a disposable fixture vault, a fake panel
controller, real OpenSSH clients, Git authentication, Git SSH signing, lock
during every sensitive transition, helper crash/reload, and both unlock-on-
demand modes. CI must never use a real vault or credential.

## Parallelization Opportunities

- After Task 3, the panel baseline can remain stable while Tasks 4–9 build the
  headless Rust core; do not parallelize work that changes the sanitized read
  contract until Task 1 is merged.
- After Task 9, Task 16's reproducible-build work can run alongside Tasks
  10–11 because it consumes the frozen helper interface rather than QML state.
- After Task 13, Tasks 14 and 15 can proceed independently if Task 4 has fixed
  the public-export owner and the control protocol is frozen.
- Tasks 17 and 18 may proceed in parallel after Task 16, but Task 19 waits for
  both so release policy matches launch-time validation.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| QML receives private SSH material before sanitization | High | Make Tasks 1–3 a standalone prerequisite gate with marker-based real-pipeline tests. |
| Selected Rust key types retain secret clones after lock | High | Fail the Task 4/6 spike if parsed private components cannot be bounded and best-effort-zeroized. |
| A lock races a load, approval, grant, or signature | High | Use vault epochs, an atomic deny linearization point, candidate keystores, bounded acknowledgments, and kill-on-timeout. |
| Same-UID FIFO injection replaces the key set | High | Require a fresh 128-bit load nonce delivered only over the private control pipe and reject duplicate/stale payloads. |
| A slow or broken agent branch stalls the core vault list | High | Bound input/output/time, drain eagerly, supervise one process group, and retry the list once without the optional branch. |
| Process attribution creates false security confidence | Medium | Enforce peer UID; present PID/path/start-time as context only; scope grants narrowly and revalidate at sign time. |
| UWSM setup overwrites another agent configuration | High | Use one plugin-owned atomic file, refuse symlinks/unexpected contents, show conflicts, and require confirmation plus re-login. |
| Bundled binary drifts from source | High | Pin every build input and compare clean release bytes byte-for-byte before merge/release. |
| Fork PR artifact policy becomes impossible to satisfy | Medium | Upload read-only candidates for source-only fork PRs; require the matching bytes before merge to `master`, not inside the untrusted fork job. |
| Older/self-hosted servers expose partial SSH support | Medium | Enforce the CLI floor, report capability as unconfirmed when appropriate, and document the 2026.8.0 malformed-item fix. |
| Feature complexity degrades the ordinary vault | High | Keep disabled mode inert, isolate helper failure, checkpoint every 2–3 tasks, and run the full existing regression suite throughout. |

## Open Questions for Human Review

- **Public export scope:** Revision 2 says both that public-key export is
  required in v1 and that it remains later work. This plan follows the stronger
  end-to-end requirement and includes it in v1. Confirm that choice.
- **Public export owner:** This plan recommends the companion write the
  projection from its validated public keystore, using an absolute data path
  supplied at launch. Task 4 must record the final owner and its path/cleanup
  contract before implementation.
- **Dependency outcome:** The Rust crate set, Bitwarden v2 agent status, RFC
  status, zeroization behavior, and license/audit surface must be re-verified
  from current primary sources during Task 4; the design draft's review date is
  not sufficient evidence.
- **Release governance:** Protected environments, required reviewers, and
  CODEOWNERS identities must be filled with repository-specific values before
  Task 19 can be completed.
