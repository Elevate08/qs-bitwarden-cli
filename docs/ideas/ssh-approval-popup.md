# Spec: Centered SSH Approval Popup

Status: implementation approved by the feature request

## Objective

Add an opt-in SSH authorization surface that appears in the center of the
active bar output instead of opening the Bitwarden panel. A locked vault first
shows a clear unlock-required state and the configured unlock controls; after
unlocking, the same transient surface changes to the existing SSH signing
approval. The surface disappears as soon as the request is answered,
cancelled, or expires.

## Tech Stack

- QML/Qt 6 with Quickshell 0.3.1 and Omarchy 4.0.2.
- The existing `Panel` root remains the owner of vault, SSH-helper, request,
  deadline, cooldown, and unlock state.
- A Quickshell `PanelWindow` on the Wayland overlay layer presents the centered
  surface on the bar widget's output.
- No new dependency or helper protocol message is introduced.

## Commands

```bash
node tests/ssh-agent-setup.test.js
node tests/ssh-agent-ui.test.js
for test_file in tests/*.test.js; do node "$test_file" || exit 1; done
env -u DISPLAY -u WAYLAND_DISPLAY -u QT_QPA_PLATFORMTHEME \
  QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/qml
mkdir -p /tmp/qs-imports
ln -sfn /usr/share/omarchy/shell /tmp/qs-imports/qs
/usr/lib/qt6/bin/qmllint -I /tmp/qs-imports Panel.qml SshApprovalPopup.qml SshApprovalScreen.qml SshUnlockScreen.qml
omarchy plugin validate .
```

## Project Structure

- `Panel.qml`: owns request routing, vault state, unlock actions, and setting
  values.
- `SshApprovalPopup.qml`: owns only the centered window, focus, and dismissal.
- `SshApprovalScreen.qml`: reusable authorization content for panel and popup.
- `SshUnlockScreen.qml`: popup unlock-required status and unlock controls.
- `BitwardenModel.js` / `manifest.json`: setting contract and safe default.
- `tests/`: static integration and pure model tests; `tests/qml/`: QML tests.

## Code Style

Keep presentation declarative and authorization imperative in `Panel.qml`:

```qml
SshApprovalPopup {
  panel: root
  anchorItem: button
}
```

All request-derived text uses `Text.PlainText`. Use Omarchy spacing, color,
border, typography, input, and button components rather than custom values.

## Testing Strategy

- Add failing contract tests for the new setting in both manifest and model.
- Add failing wiring tests proving popup mode does not call `root.open()`, the
  legacy mode still does, and unlock transitions reuse the same pending
  request.
- Lint every new QML component against the installed Omarchy imports.
- Run the full JavaScript and QML suites before handoff.
- Runtime acceptance requires an enabled development plugin, a locked vault,
  and a real SSH signing request; no real credentials belong in tests or logs.

## Boundaries

- Always: keep the setting false by default; deny on Escape, outside click,
  cancellation, and timeout; render request metadata as plain text; clear
  transient unlock input when the popup closes.
- Ask first: changing helper authorization, request deadlines, cooldown rules,
  credential storage, or the SSH control protocol.
- Never: put session tokens, passwords, private keys, payloads, or signatures
  in popup-local persistent state, command arguments, logs, or fixtures.

## Threat Model

- Request key/process labels cross from a same-UID client through the helper
  and are untrusted display data. Plain-text rendering prevents markup from
  becoming UI.
- The overlay is presentation, not an authorization boundary. Existing helper
  request IDs, epochs, deadlines, peer checks, and final authorization checks
  remain authoritative.
- The desktop lock-state gate remains ahead of both panel and popup prompts.
- The master password and recovered PIN/fingerprint password continue through
  the existing bounded private-FIFO path and are scrubbed by existing process
  cleanup.
- A popup must never approve from a bare Enter key; denial is the default
  focused action.

## Success Criteria

- `sshAgentApprovalPopup` is a boolean setting, disabled by default.
- With it disabled, SSH unlock and approval requests behave exactly as before.
- With it enabled, an SSH request does not open or navigate the anchored panel.
- A locked vault shows why it must be unlocked and offers configured PIN,
  fingerprint, and master-password paths without duplicating auth logic.
- A successful unlock changes the same centered surface to the signing prompt,
  including key, fingerprint, requesting program, deadline, and grant option.
- Deny, approve, cancellation, timeout, and outside click remove the surface;
  a panel the user already opened remains where it was.
- The centered window uses the bar widget's output, stays within the output at
  narrow sizes, follows the Omarchy theme, and is fully keyboard operable.

## Open Questions

None for implementation. Full account login remains a panel workflow; the
popup is intentionally limited to a signed-in but locked vault and SSH signing
authorization.
