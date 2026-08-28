# 2. Approval grants are scoped to a program, not a process

Date: 2026-08-27

## Status

Accepted. Supersedes the grant-scoping rule in `docs/ideas/ssh-agent.md`
("Bounded approval grants"), which this decision deliberately relaxes.

## Context

The design specified that an approval grant is "scoped to **one key and one
live client process**", keyed on the peer PID together with that PID's start
time and the executable path captured at grant time. PID reuse therefore
cannot inherit a grant, and a re-`exec` invalidates it.

That rule was justified by a usability argument:

> Approval strictly per signature is unusable for the workflows this feature
> exists to serve. A `git rebase` over twenty commits with `gpg.format=ssh` is
> twenty modal prompts; a fetch followed by a push is two.

Live testing against a real vault showed the rule does not achieve that. Git
does not hold a connection to the agent across commits: it spawns a **fresh
`ssh-keygen -Y sign` process for every commit it signs**. Every one of those
has a different PID and a different start time, so a PID-scoped grant never
matches. Approving "for this process" and then making a second signed commit
prompted again, and a twenty-commit rebase would prompt twenty times whether a
grant was taken or not.

So the grant, as specified, was close to inert: it helped only a single
long-lived process making repeated signature requests, which is not a workflow
this feature was built for. The button existed and did nothing useful.

## Decision

A grant is scoped to **one key and one program, for one user**: it matches on
the peer UID, the executable path captured at grant time, and the public key.
PID and process start time are still captured and shown in the prompt, but no
longer participate in matching.

The approval button says "Approve for this program", not "for this process",
because that is what it now does.

Unchanged:

- The peer UID must equal the companion's effective UID. That is the one
  property the companion actually verifies, and it is not relaxed here.
- The window is still bounded by `sshAgentApprovalWindowSec` (default 120s,
  maximum 900s, `0` disables grants entirely).
- Grants still live only in the companion's memory, never touch disk, and
  never survive a restart.
- Every lifecycle event that dropped a grant before still drops it: expiry,
  lock, logout, account change, epoch change, disabling the feature, screen
  lock, suspend, `revoke_grants`, and per-grant revocation.
- A grant still replaces the prompt, not the final check. Epoch, lock state
  and key identity are rechecked immediately before the signing primitive.

## Consequences

**What this accepts.** During an open window, *any* process running the same
executable path, as the same user, can obtain a signature with that key
without a prompt. Under PID scoping that was limited to one process.

**Why that is tolerable here.** The threat model this feature works within
already states it "does not claim to protect an unlocked desktop from
arbitrary code already running as the same user". A hostile same-UID process
that wanted a signature under the old rule could simply execute
`/usr/bin/ssh-keygen` itself and request one in its own right — it would face
a prompt, but so would any first request under either rule. The scope change
does not hand an attacker a capability they could not otherwise reach; it
removes a distinction that cost the user twenty prompts and bought a boundary
that a same-UID attacker was never obstructed by.

**What genuinely widens.** The window is now shared. If the user approves
`/usr/bin/ssh-keygen` for two minutes to sign a rebase, a concurrent hostile
invocation of that same binary during those two minutes signs without asking.
Under PID scoping it would have prompted. This is a real reduction, and it is
the price of the feature working at all.

**Mitigations retained.** The window defaults to 120 seconds rather than the
900-second maximum; grants are visible in the panel with their remaining time
and revocable individually or all at once; and every live grant is destroyed
by a lock, a screen lock, or a suspend.

**If this proves too wide**, the narrower option is to keep program scoping but
additionally require that the requesting process's parent match the one that
was approved — which would cover Git's per-commit children while excluding
unrelated invocations. That was not done here because parent PIDs are as
forgeable as any other `/proc` metadata and would add a check that reads as a
security boundary without being one.

## Alternatives considered

- **Key-only grants for the window.** Simplest, and matches what `ssh-agent`'s
  own confirm timeout does. Rejected as wider than necessary: the program is
  cheap to match on and excludes unrelated binaries.
- **Keep PID scoping and document the limit.** Honest, but leaves a button in
  the UI that almost never does anything, which is its own kind of dishonesty.
- **Drop grants from v1.** Removes the machinery, but returns the twenty-prompt
  rebase the design explicitly called unusable.
