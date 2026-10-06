# Local desktop and keyring tests

These desktop checks use `io.github.elevate08.qs-bitwarden-cli` already loaded
in the current Omarchy session. They do not launch a second shell or compositor.
Install the candidate's `Service.qml` and `Panel.qml`, then reload the plugin.
If rescanning retains the old compiled IPC methods, restart the Omarchy shell.

Run unattended checks:

```sh
tests/desktop/run.sh
```

This runs the production PAM/FIDO lifecycle regression suite, safe diagnostics
checks, real libsecret integration on a private D-Bus with a disposable keyring,
and the loaded plugin's close/reopen/focus checks. It briefly opens the panel.
It leaves active prompts and editing screens alone. Missing desktop or hardware
coverage is explicitly reported as SKIP, rather than counted as a pass.
Keyring dependencies (`dbus`, `gnome-keyring`, `libsecret`, `gdbus`) are required
by this runner and the CI integration gate. No user keyring is accessed.

For the real authentication paths, run:

```sh
tests/desktop/run.sh --interactive
```

This locks the real vault. Follow the printed actions: open a password/PIN
prompt and cancel it, then unlock with password, PIN, fingerprint and FIDO2
as available. Leave the cancellation prompt open briefly so the runner can
check compositor focus. Enter credentials only into the plugin's own UI.
The runner observes readiness, method, focus, scanning, busy and lock state;
it never receives passwords, PINs, vault contents or keyring values.
Unlock steps time out after three minutes. The panel's original open/closed
state is restored, while the vault remains in the state reached by the test.
A failed attempt can leave it locked; unlock normally afterward.

Add `--require` to fail when any requested desktop/hardware coverage is skipped.
A complete physical run needs configured PIN/fingerprint/FIDO2 methods and an
attached authenticator. CI cannot prove physical presence or compositor focus;
its lifecycle tests simulate the device boundary, while this local runner
uses the loaded plugin and real hardware. Actual destructive account cleanup
and method re-enrolment should use a disposable account and remain separate
from this runner.

Logs contain check summaries only. `desktopState` is a read-only diagnostic
IPC method: it returns no account identifiers, field contents, item names,
device identifiers, or authentication error strings.

To retry one live step without repeating every unlock:

```sh
node tests/desktop/focus.integration.js --cancel-only
node tests/desktop/focus.integration.js --method=pin
node tests/desktop/focus.integration.js --method=fingerprint
```

Single-method tests skip cancellation and exercise only the requested unlock.
