# Changelog

## [1.4.0] - 2026-08-28

### Added

- **Opt-in SSH agent.** With `sshAgentEnabled` on, the panel serves your vault's SSH keys to `ssh`, Git and `ssh-keygen -Y sign` while the vault is unlocked. Private keys are held only by a separate helper process, never written to disk and never passed to QML, and are dropped when the vault locks, on logout, and when the helper exits.
- Per-signature approval in the panel, naming the key, its `SHA256:` fingerprint and the program asking. One approval can cover further signatures from the same program and key for `sshAgentApprovalWindowSec` seconds (default 120), so a twenty-commit rebase is one prompt rather than twenty. Live approvals are listed and revocable; two unanswered prompts start a five-minute cooldown instead of continuing to raise the panel.
- `sshAgentUnlockOnDemand` (off by default) lets a signing request against a locked vault open the unlock prompt.
- Public identities are projected to `~/.local/share/qs-bitwarden-cli/ssh/*.pub`, mode 600 in a 700 directory, so Git SSH signing has the file paths it requires. Public material only; removed on logout, account change, and when the feature is turned off.
- **Route SSH Clients Here** writes one plugin-owned UWSM fragment, `~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent`, taking effect at the next login. An existing agent is named and confirmed before it is replaced, and a file that is a symlink or holds anything else is reported rather than overwritten.
- The helper ships as a committed, reproducibly built x86_64 binary, validated at launch for architecture, format, mode, checksum, self-test and control-protocol version. Any failure disables this feature alone and leaves the rest of the plugin working.
- Releases now publish a GitHub build-provenance attestation, an SBOM, and a dependency/licence report, produced by a protected release workflow whose publishing job is the only one holding write, OIDC or attestation permission. Verify with `gh attestation verify bin/x86_64-linux/qs-bitwarden-ssh-agent --repo Elevate08/qs-bitwarden-cli`.

### Security

- The vault read is split before it reaches the panel: SSH private material goes to the helper over a private FIFO carrying a 128-bit per-load nonce, and QML receives a sanitized list from which it has been removed.
- A signature is refused unless the vault is unlocked at the epoch the key was loaded under, so a lock racing a load, an approval or a signature cannot leave a key usable.
- Agent forwarding is not supported in this release; a forwarded request is labelled as such in the prompt, because the process it names is not the one that would use the signature.

## [1.3.1] - 2026-08-26

### Fixed

- Fixes #2: ask for a verification code only after Bitwarden requires one, including Bitwarden CLI 2026.2.0's standalone `Code is required.` challenge.

## [1.3.0] - 2026-08-24

### Added

- Authentication prewarming for substantially quicker locked-vault unlocks and logged-out sign-ins.
- Deterministic vault fixture tiers and performance regression coverage from 100 to 5,000 items.
- Visible, compact sync progress while fresh vault data is loading.

### Changed

- Render vault items before deferred folder, organization, and status metadata work.
- Coalesce generator, TOTP, and learned-association work to keep rapid interaction responsive and correct.
- Refresh the fixture screenshots and marketplace preview under the title “Bitwarden Vault Plugin.”

### Security

- Keep authentication secrets out of command arguments and deliver passwords through private runtime FIFOs.
- Scrub process collectors and transient plaintext after use, lock, logout, or cancellation.
- Cancel attachment and generator subprocess groups safely when their owning vault or screen closes.
- Serialize logout with credential writers and verify that session, PIN, and fingerprint credentials are absent from the OS keyring before allowing another login.
- Harden custom-server validation, session handoff, bounded subprocess output, and attachment destination handling.

### Fixed

- Prevent stale asynchronous results from crossing vault generations or mutating a newer session.
- Preserve folder and organization filtering during the faster initial-load sequence.
- Keep generator and TOTP requests correct across rapid option changes, cancellation, scrubbing, and reopen cycles.
