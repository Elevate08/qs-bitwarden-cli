# Changelog

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
