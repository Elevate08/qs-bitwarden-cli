# 3. A signing request gives the user two minutes, not thirty seconds

Date: 2026-08-27

## Status

Accepted. Adjusts the request-deadline figure in `docs/ideas/ssh-agent.md`
("Panel-to-Companion Contract"), which specified thirty seconds.

## Context

The control contract said:

> Reject overflow, give each request a 30-second deadline, and cancel it when
> its client disconnects.

Thirty seconds is ample for a machine and short for a person. A signing
request has to travel further than the socket: the panel opens or takes focus,
the user notices it, reads a key name and a `SHA256:` fingerprint, considers
which program is asking, and decides. During live testing against a real vault
that budget expired twice under a user who was doing nothing more unusual than
reading the prompt he had been asked to read. Both expiries were recorded as
refusals, which then fed the denial cooldown and suppressed further prompts —
so a deadline that was merely tight cascaded into signing being disabled.

A second problem was found at the same time and is the more serious of the
two. The socket server bounded its wait for the state loop's answer with the
same `CLIENT_IO_TIMEOUT` it used for reading a frame and writing a reply:

```rust
let bytes = match timeout(CLIENT_IO_TIMEOUT, response).await { .. };
```

Both were thirty seconds, so the two clocks expired together by coincidence
rather than by design. Raising only the approval deadline would have left the
client giving up first and the new deadline doing nothing — the human bound
would have been decorative. The two values were coupled without ever being
related.

## Decision

Three separate bounds, each sized for what it actually waits on.

| Bound | Value | Waits on |
|---|---:|---|
| `approvals::REQUEST_LIFETIME_MS` | 120s | a person deciding |
| `server::RESPONSE_TIMEOUT` | 150s | the state loop's answer, on behalf of a blocked client |
| `server::CLIENT_IO_TIMEOUT` | 30s | a socket read or write |

`RESPONSE_TIMEOUT` deliberately exceeds `REQUEST_LIFETIME_MS`, so the
companion's deadline is always what fires first and there is one authority on
when a request is over. A test asserts that ordering, and asserts the
literal 120s figure so that changing it stays a deliberate act rather than a
side effect.

The held-request deadline used while a vault unlock is pending is derived from
`REQUEST_LIFETIME_MS` rather than repeated, because unlocking asks more of the
user than approving does and certainly needs no less time.

## Consequences

**A blocked client may now wait up to two minutes.** In practice it will not:
the mechanism that actually reclaims a request promptly is the client
disconnect, which the server watches for while a request is pending. Pressing
Ctrl-C on a `git push` ends the request immediately, and the panel's prompt is
withdrawn with it. The deadline is the backstop for a client that neither
answers nor leaves.

**The four-request bound is unchanged**, so at most four requests can be
waiting at once regardless of how long each may wait. A same-UID process can
still occupy those slots with junk requests and delay a legitimate one; that
was already inside the threat model this feature does not defend against, and
a longer deadline widens the window without changing the conclusion.

**Two minutes is still a deadline.** A request that nobody answers is refused,
the client is told, and the prompt comes down. Removing the bound entirely
would leave prompts and blocked clients accumulating with nothing to clear
them.

## Alternatives considered

- **Keep 30s and make the panel more attention-grabbing.** Rejected: the
  design explicitly forbids desktop notifications in v1, and the remaining
  levers (opening and focusing the panel) are already used.
- **Restart the clock when the prompt is first displayed.** Fairer in
  principle, since the wait should start when the user could first act. It
  needs the panel to report display state back to the companion, which adds a
  control message and a way for a wrong answer to extend a deadline. Not worth
  the surface for the benefit.
- **Make it configurable.** Another setting for something almost nobody would
  tune, and a badly chosen value degrades either usability or the bound. The
  figure is documented here instead.
- **Remove the deadline while the panel is open and focused.** Attractive, but
  it makes the bound depend on window state the companion cannot verify.
