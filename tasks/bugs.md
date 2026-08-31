# Known Defects

Found outside a task's own verification, during the Task 20 manual matrix.
Each entry records what was observed, what the code actually does, and how it
was resolved.

## 1. README described `sshAgentUnlockOnDemand` as gating signing

**Status:** fixed in the same commit. Found 2026-08-31 on `feature/ssh-agent`.

**Observed:** With **Unlock on demand** switched off and the vault locked,
`ssh-add -T` against a projected public key still opened the panel's unlock
prompt. Dismissing it returned "agent refused operation" for both the Ed25519
and the RSA key.

**Verdict: the code is correct and the documentation was wrong.** The setting
governs the identity listing on a cold cache, not signing. A locked signing
request for a key the helper already holds in its public cache always raises
the unlock prompt and parks the request; dismissing the prompt is what refuses
it, and it refuses immediately rather than at the deadline.

**Where that is settled:**

- `docs/ideas/ssh-agent.md:178` -- the state table row for "Locked, cache
  available" reads "List public identities; signing asks panel to unlock",
  with no condition attached.
- `docs/ideas/ssh-agent.md:310` -- "When it is on, unlock-on-demand must begin
  at `SSH_AGENTC_REQUEST_IDENTITIES` rather than at the sign request: with no
  cache there are no identities to offer, so no sign request will ever
  arrive."
- `agent/src/main.rs:475` consults `unlock_on_demand` in the `Identities` arm;
  the `Sign` arm at `main.rs:511` deliberately does not.
- `agent/tests/lifecycle.rs:320` and `:444` both assert the locked-sign
  behavior without ever setting the option, so the default already covers it.

**Fixed by** rewriting README "While the vault is locked" to separate the two
moments, and rewriting the `sshAgentUnlockOnDemand` row in the configuration
reference. No code change; the helper binary is unaffected and needs no
rebuild.

**Consequence for the Task 20 matrix:** the "off -> refused, no panel" row as
originally written cannot pass, because it describes behavior the design does
not have. Signing refusal while locked is tested by dismissing the prompt, and
by asking for a key the public cache does not know.

## 2. A grant's remaining time never counted down

**Status:** fixed. Found 2026-08-31 on `feature/ssh-agent`, during the Task 20
manual matrix.

**Observed:** With one live grant, the ACTIVE APPROVALS row on the SSH agent
settings screen read "1m 59s left" for the whole two minutes and then the row
disappeared, having never counted down. `sshAgentStatus` reported
`"grants":1` throughout.

**Cause:** `sshAgentGrantViews` computed `remainingLabel` from the companion's
`expiresInSec` at the instant of the announcement, and the companion announces
a grant once and says nothing further until the set changes. The view was a
snapshot rendered for the life of the grant; nothing re-derived it, and
nothing dropped a lapsed grant until the next announcement arrived.

**Fixed by** stamping each announced grant with `expiresAtMs` -- when it runs
out rather than how long it had left -- and adding `sshAgentGrantsAt(views,
nowMs)`, which re-derives the remaining time for a given moment and drops what
has lapsed. `Panel.sshGrants` became a derived property over
`sshGrantsAnnounced` and a `sshGrantTick` driven by a 1s timer that runs only
while grants exist, matching the cooldown countdown. Both fallbacks are
deliberate: an unstamped view, or any view before the first tick, is shown as
announced rather than dropped, because a grant must never disappear merely
because a timer has not run yet.

**Also worth knowing:** the same staleness would have hidden a grant that had
genuinely expired, since `sshAgentStatus` reported the announced count rather
than the live one. It now reports the live one.

## 3. The helper leaks its runtime files when the plugin is removed

**Status:** open, low severity. Found 2026-08-31 during the Task 20 manual
matrix.

**Observed:** After `omarchy plugin remove` with the SSH agent still enabled,
`/run/user/1000/qs-bitwarden-cli/` still held `ssh-agent.sock`,
`ssh-agent.lock` and `ssh-keys.fifo`, with no helper process running.

**Cause:** `ServiceRuntime` and `Runtime` in `agent/src/runtime.rs:264` and
`:320` unlink those files from `Drop`, which runs on a graceful shutdown --
which is why turning the agent off leaves nothing behind. Tearing the plugin
down kills the helper rather than shutting it down, so `Drop` never runs.

**Impact:** Small. The files are on a tmpfs and go with the login session, and
`omarchy plugin remove` has no uninstall hook, so nothing of ours can run at
that moment anyway. Until the next login, a client routed at that path finds a
socket that answers nothing rather than no socket at all.

**Possible fix:** A SIGTERM handler in the helper that runs the same cleanup,
if the shell terminates rather than kills the process. `Drop` cannot help
against SIGKILL and nothing can. Worth checking which signal the shell
actually sends before writing the handler.

**Documented meanwhile** in the README's Uninstall section: turn the agent off
before removing the plugin, and what the three files are if you did not.

## 4. The uninstall instructions destroyed a stow-managed shell.json

**Status:** fixed. Found 2026-08-31 during the Task 20 manual matrix, on the
maintainer's own machine.

**Observed:** Following the Uninstall section, the step "delete the
`io.github.elevate08.qs-bitwarden-cli` key under `plugins`" was carried out by
removing `~/.config/omarchy/shell.json`. Every configured plugin disappeared
from the bar, not only this one, and the shell came up on its built-in
defaults.

**Cause:** That path was a `stow` symlink into `~/projects/dotfiles`. Deleting
it removed the link, not the configuration; the shell then found no user
config at all. The real file was intact in the repository throughout, and
restoring the symlink restored everything.

The instruction was also redundant: `omarchy plugin remove` already calls
`omarchy-shell shell setPluginEnabled <id> false`, which removes the bar entry
and its settings before the directory goes.

**Fixed by** deleting the hand-edit step, naming `omarchy plugin disable` for
the stale-entry case, and warning plainly that `shell.json` is often a symlink
and must be changed through the shell rather than edited. Nothing in the
Uninstall section now tells a user to touch a file the shell owns.

**Worth remembering:** every other path in that section is under this plugin's
own directories, where a mistake costs the user only this plugin's data. This
one step reached into a file shared by every plugin on the system, and that is
what made a documentation error destructive.
