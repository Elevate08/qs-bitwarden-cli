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
