# Changelog

## [1.5.0] - 2026-08-28

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
## [1.4.1] - 2026-08-31

### Fixed

- The password generator, both Copy password buttons, the generator's Password type and the field-level **Generate...** shortcut wear a key icon again. 1.4.0 replaced all five with the refresh icon: a bulk glyph edit meant to correct one new button rewrote every other use of the same codepoint. Cosmetic only -- no button changed what it does -- and now pinned per button by test rather than by count, since a count moves with exactly this kind of mistake.

## [1.4.0] - 2026-08-30

### Added

- **Two-step method selection.** An account is asked which two-step method it uses before any code is collected, because a code sent without its method is a code the server will reject. The choice goes to Bitwarden on its own first, so a method the account does not have costs a round trip rather than a typed code -- and choosing **Email** is what makes Bitwarden send the email, since `bw` posts it only for a request carrying no token yet. It is asked once per account, not once per login.
- The method that worked is remembered per login address in `twoFactorMethods`, so the question is asked once per account rather than once per login, and two vaults on one machine each keep their own answer. **Change method** on the code screen asks again. A remembered method the account rejects is dropped for that account alone and retried without one.

### Fixed

- Fixes #4: a login on a machine Bitwarden has not seen before now completes in the panel. It used to ask for the emailed code over and over, because `bw login` has no flag for it -- `--code` carries the two-step token, which the device-verification step never reads. The challenge is told apart from a rejected two-step code by the attempt it answers: both say `Code is required.`, but only device verification says it again to a login that already sent a code. The panel then answers bw's prompt directly, on stdin, and a terminal is offered only if that login meets something it cannot answer.
- Two-step login now asks which method an account uses before collecting any code, and never sends a code without it. `bw` only puts the token on the wire when a provider came with it, so `--code` alone makes the request a bare password grant -- and an email provider answers that by issuing a *fresh* code, invalidating the one being submitted. Measured against `bw` 2026.2.0: the same login succeeds with `--method` and returns `Two-step token is invalid.` without it. Authenticator codes survived the omission because the server does not issue them; emailed ones never could.
- An account with more than one two-step method can log in again. The panel never sent `--method`, which `bw` needs as soon as an account has a choice to make; without it the login failed with `Login failed. No provider selected.` and no way forward.
- A login waiting on an emailed code survives the panel closing. It could not before: closing dropped the master password and the login stage, so going to read the code meant coming back to a blank form. That made both email two-step and new-device verification impossible to complete in the panel -- neither code can be read without leaving it. The login is now held for five minutes, on the wall clock so a suspend counts against it, and reopening lands on the field that was waiting.
- A `bw status` check no longer cancels the login it lands in the middle of. That check takes seconds and answers about the world as it was when it started -- a world where the login had not happened yet -- so it reported `unauthenticated` and the panel acted on it, sending SIGTERM to the login the user had just submitted and clearing the progress indicator on the way past. The button dropped out of "Verifying..." and nothing was shown, which is why a second press was needed. A submitted login is now the newer news, and a status result that raced it is discarded.
- A verification code typed into the panel is no longer discarded on the way out. Typing into a field assigns to its own `text`, which breaks the binding back to the state behind it -- so clearing that state left the field showing the code while the login read an empty value, sent no `--code` at all, and reported back that the code had been rejected. Retyping it repaired the state, which is why a second attempt worked and why the first code had expired by then. Fields and the state behind them are now cleared together, everywhere.
- A login no longer has to be submitted twice. Pressing the submit button while the panel was scrubbing the login process's output buffer queued the login against that scrub's exit, and the exit handler returned early for a scrub -- so the queued login was dropped and the click did nothing at all. The next click worked because by then nothing held the process. Both ways the process can end now dispatch whatever was queued, and a scrub is no longer started over a submit that is already waiting.
- A login no longer has to be submitted twice when handing the password to `bw` misses its window. The writer polls for `bw`'s FIFO and gives up if `bw` has not opened it in time, which a cold start after the panel has been closed can outrun; unlock has always re-armed itself there, while login left the button for you to press again. It now retries once on its own, and still reports if the second attempt fails too.
- A vault that has never synced is no longer shown as an empty vault. `bw login` calls its full sync without `allowThrowOnError`, so a sync that fails is swallowed: login still exits 0 and prints a working session, onto a local vault holding no ciphers. The panel now notices `lastSync` is unset on an unlocked vault and syncs once to repair it, which also covers the terminal handoff and a session restored from the keyring.
- An account whose only two-step methods are ones the CLI cannot perform -- a passkey, or Duo -- now says so and points at API key login, instead of reporting a bare `No providers available for this client.`

### Changed

- Every login result is logged with the branch it took, the exit code, and how many bytes came back -- lengths and flags only, never a session, never a code, and stderr through the same sanitiser the panel shows. Read it with `quickshell log -f | grep qs-bitwarden`. A failed login happens on someone else's machine against someone else's account, and this is the difference between a bug report and a guess.
- Email login is three stages where it was two: credentials, the two-step method, then the code. The method is asked once per account and remembered, so only a first login on an account sees the middle stage.

### Security

- A closed panel now holds one thing it did not before: a login stopped on a second factor keeps the master password and its stage for five minutes. That is a deliberate exception to the panel dropping everything on close, and it is what makes an emailed code answerable at all. It is bounded on the wall clock rather than a monotonic timer, so a machine suspended mid-login wakes past it rather than into it; it expires while the panel is closed rather than at the next open; and locking, logging out, and a successful login all end it early.
- The one login that runs with bw's prompts enabled -- new-device verification, the only challenge bw accepts from no flag -- keeps the guarantee `BW_NOINTERACTION` was there for, by answering on a pipe rather than a pty. A pipe ends: measured against the inquirer 8.2.6 bw bundles, a prompt with nothing left to read exits rather than blocking, so an unexpected prompt still ends the login instead of hanging it with the master password loaded. `timeout` covers a bw that never prompts at all. The code is read from the environment by the command's own `printf`, so unlike `--code` it reaches no argv, and bw's prompt echo is stripped of escape sequences and redacted of the code before any of it is shown.
- Logging out no longer takes the cursor out of the master password field a few seconds later. A logout sets the status itself and then confirms it with `bw status`; that confirmation re-focused the login screen mid-typing, so the rest of the master password was typed into the unmasked email field, which the next submit would have sent as an email address. Focus now moves only onto a screen that does not already hold it. The same fix covers the API key form's client secret and master password.

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
