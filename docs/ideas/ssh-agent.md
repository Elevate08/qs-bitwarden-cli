# SSH Agent Support

Status: refined design proposal, ready for prerequisite spikes

Last reviewed: 2026-08-26 (revision 2)

## Problem Statement

**How might we let a Quickshell user use SSH keys stored in Bitwarden without
running Bitwarden Desktop, while ensuring that locking the vault immediately
stops new signatures and removes the plugin's usable private-key material?**

The desired experience is:

- `ssh`, Git authentication, and Git SSH signing use a stable `SSH_AUTH_SOCK`.
- SSH-agent support is disabled by default and runs no companion process until
  the user explicitly opts in.
- When the agent is enabled, unlocking the existing panel makes eligible vault
  SSH keys available to SSH clients.
- SSH keys appear in the panel as a public-only item type whether or not the
  agent is enabled, and cost no extra vault read.
- Locking the panel immediately denies signing and drops private keys from the
  agent.
- A sign request made while locked can raise the panel's unlock UI.
- Every signature is approved in the panel, or covered by a short bounded grant
  the user opened deliberately, and identifies the requesting process as
  accurately as Linux permits.
- The plugin continues to use `bw` as its Bitwarden integration. It does not
  become another Bitwarden client.

## Decision

Build an **optional Rust companion binary** that implements the SSH agent and
is supervised by Quickshell. Do not build the earlier Python proxy plus an
inner OpenSSH agent.

The agent is opt-in and disabled by default. While disabled, the companion is
not started, no socket or FIFO exists, and the list pipeline carries no agent
branch, so no private SSH-key material is projected at all. Public-only SSH-key
browsing remains available and does not enable the agent implicitly.

Both its source and its compiled Linux artifact live in this repository. The
artifact accepted into the plugin must be reproducibly built and compared
byte-for-byte by CI, then attested by a protected release workflow. Installing
the plugin therefore installs the helper with it; users do not need a Rust
toolchain, an AUR package, or a runtime download.

Rust is justified here because this process would own a security boundary:
untrusted binary protocol parsing, caller inspection, request correlation,
approval enforcement, and private-key signing. It is not justified by speed.
All ordinary vault operations remain in QML/JavaScript and continue to use the
Bitwarden CLI.

The companion spawns nothing. It does not run `bw`, it never receives
`BW_SESSION`, and it does not use the Bitwarden SDK, call the Bitwarden service
directly, implement vault decryption, or persist its own vault state. The panel
remains the only component that runs the CLI.

One `bw list items` per unlock or sync feeds every consumer. The panel's
existing pipeline gains `jq` stages that split the decrypted list in the shell,
before any of it reaches a long-lived process:

- **to QML, on stdout**: `{"items": [...], "sshKeys": [...]}` -- supported
  non-SSH types as complete objects, plus a public-only projection of type 5
  (item ID, name, organization, folder, favorite, re-prompt state, public key,
  fingerprint). `sshKey.privateKey` is never in this stream.
- **to the companion, over a private FIFO**, only while the agent is enabled:
  the eligible type-5 items projected to item ID, name, private key, public
  key, and fingerprint. Items requiring master-password re-prompt are excluded
  here.

This is downstream data minimization, not a claim that `bw` decrypts only one
item type. The short-lived `bw` and `jq` processes still handle the full list;
the security boundary is that private key material never enters QML and
unrelated vault items never enter the long-lived companion.

This follows the boundary used by Bitwarden Desktop—a native Rust agent with
public-key metadata retained and private keys removed on lock—without copying
its implementation blindly. Bitwarden's current v1 agent and its
`bitwarden-russh` fork are deprecated while a v2 implementation is being
developed, so dependency selection is a prerequisite spike.

## Architecture

```text
ssh / git / ssh-keygen -Y sign
    │ SSH agent protocol
    ▼
$XDG_RUNTIME_DIR/qs-bitwarden-cli/ssh-agent.sock      (0600, in a 0700 dir)
    │
    ▼
Rust companion -- spawns no child processes
    ├── parses an allowlisted subset of the agent protocol
    ├── owns public metadata and unlocked private keys
    ├── signs only after panel approval or a live bounded grant
    ├── inspects the Unix peer PID/UID
    ├── control NDJSON on stdin/stdout  ◀──▶  Quickshell panel
    └── key loads on ssh-keys.fifo (0600)  ◀──  the agent branch below

Quickshell panel
    ├── owns login, unlock, lock, sync, and logout UX
    ├── owns BW_SESSION; it never leaves QML and the shell
    ├── supervises the companion as a non-detached Process
    ├── renders unlock, approval, and grant UI
    └── runs ONE pipeline per unlock or sync:

            bw list items
                 │
              16 MiB cap
                 │
                tee ──┬──▶ jq agent filter ───▶ ssh-keys.fifo   (agent enabled)
                      │
                      └──▶ jq public split ───▶ stdout ──▶ QML
                                                 {"items":[…],"sshKeys":[…]}
```

There is one agent socket and one signing authority. Eliminating the inner
`ssh-agent` removes the most serious flaw in the proxy design: another process
running as the same user could connect directly to the inner socket and bypass
the proxy's approval UI.

The companion starts whenever the feature is enabled, including while the vault
is locked, and regardless of what `SSH_AUTH_SOCK` currently points at. Client
routing is a separate, advisory concern; see "Opt-in and Session Setup".
Quickshell's `Process` can keep stdin open, write control messages, parse
newline-delimited stdout, terminate the child on configuration reload, and clear
most of its inherited environment. The companion must also exit and clear keys
when it sees stdin EOF.

Because the companion spawns nothing, it has exactly three inputs -- control
NDJSON on stdin, nonce-framed key loads on its FIFO, and agent protocol on its
socket -- and all three are bounded. It needs no `PATH`, no `HOME`, and no vault
credentials of any kind.

## Responsibility Boundary

| Concern | Owner |
|---|---|
| Login, unlock, lock, logout, sync | Panel using existing `bw` flows |
| Vault session lifetime | Panel |
| Types 1–4 list and detail UI | Panel; only types 1–4 pass the allowlist |
| SSH key list/detail UI | Panel, public-only type-5 projection from the same read |
| One `bw list items` read per unlock/sync | Panel |
| Splitting that read into QML and agent streams | `jq` stages inside the panel's own pipeline |
| Receiving eligible private SSH keys when enabled | Companion, over its FIFO |
| Agent socket and protocol | Companion |
| Private-key parsing and signing | Companion |
| Caller PID/UID/process display | Companion |
| Approval and unlock UI | Panel |
| Bounded approval grants | Companion, surfaced and revocable in the panel |
| Request timeout and final allow/deny | Companion |

The panel never sends the session token to the companion, and QML never holds a
private key. The token stays in QML and in the `bw` child's environment, exactly
where it lives today; private-key text goes from `jq` straight into the
companion's FIFO without passing through QML or an environment variable. This is
a strict improvement on the previous draft, which handed a long-lived process
`BW_SESSION` for the life of the session.

The session token and private-key text still exist transiently in process
memory. “Vault only” therefore means **never intentionally persisted at rest**,
not that the bytes exist nowhere outside Bitwarden. Swap, hibernation, core
dumps, a compromised same-UID process, root, and the kernel are separate threat
boundaries. The widest of those windows is the `bw` child itself, which holds
the entire decrypted vault; see "Security Requirements".

## Vault and Agent State

Use an explicit state machine instead of deriving behavior from whether a
socket or key happens to exist.

| State | Public identities | Private keys | Agent behavior |
|---|---:|---:|---|
| Logged out / account changed | None | None | Return no identities; tell panel login is required |
| Locked, no cache yet | None | None | Return no identities; with unlock-on-demand enabled, ask the panel to unlock first, with a timeout |
| Loading | Previous safe cache only | None until complete | Coalesce requests; fail closed if load fails |
| Unlocked | Present | Present | List identities; every sign needs an approval or a live grant |
| Locked, cache available | Present | None | List public identities; signing asks panel to unlock |
| Disabled / companion stopped | Socket absent | None | Normal “no agent” failure |

Loading is **eager once per unlock or explicit refresh**, not per signing
request, and it rides the panel's existing list read rather than adding one of
its own. Per-key `bw get item` calls are slow and introduce races. A vault sync
remains owned by the panel; after a successful sync the same single pipeline
refreshes the panel list and, when the agent is enabled, the companion's keys.

Lock processing is ordered:

1. Atomically enter a deny-signing state.
2. Cancel all pending approvals and in-flight loads.
3. Have the panel terminate and reap any in-flight `bw`/`jq` load process group
   and close its pipes; the companion independently abandons the current load
   nonce, so bytes still arriving on the FIFO are discarded.
4. Wait for any signature operation that already crossed its final authorization
   point; no new operation may cross that point after step 1.
5. Drop every approval grant, then drop and best-effort-zeroize private keys and
   filtered JSON. (The companion holds no session token to drop.)
6. Retain only public key, fingerprint, item ID, and display name.
7. Acknowledge the lock to the panel. After this acknowledgment, no signature
   response from the previous epoch may be returned.

This defines the unavoidable race honestly. A cryptographic primitive that
started immediately before the lock cannot reliably be interrupted halfway
through. The lock linearization point is the atomic deny transition in step 1.

The panel's own lock is never blocked by the companion. It drops its session,
runs `bw lock`, and reports the vault locked on its own schedule. It waits at
most two seconds for the companion's `locked` acknowledgment, then kills the
child outright -- a companion that cannot confirm a lock is a companion that
must not keep running. The acknowledgment is what lets the panel say "keys
cleared" as well as "vault locked"; it is not a precondition for locking.

Account changes and logout clear both private and public caches, and drop every
grant. Disabling the feature terminates the companion and removes its socket and
FIFO.

One transition the previous revision left out: the panel can start into an
already-unlocked vault, because `rememberSession` restores a session key from
the keyring. A freshly started companion is in "locked, no cache yet" while the
panel is unlocked, so the panel must run a key load as part of its first item
read in that case, exactly as it would after an interactive unlock. Startup is
not evidence that the vault is locked.

## Opt-in and Session Setup

Add an `sshAgentEnabled` boolean setting with a default of `false`, alongside
`sshAgentUnlockOnDemand` (default `false`) and `sshAgentApprovalWindowSec`
(default `120`). Treat setup as an explicit state machine rather than assuming
that a checked box means the agent is usable:

| Setup state | Companion | Meaning |
|---|---|---|
| Disabled | Stopped | No socket, no FIFO, no agent branch in the list pipeline |
| Enabled | Running | The helper passed its handshake and is serving its socket |
| Error | Stopped or backing off | Missing/incompatible helper or bounded crash loop; ordinary vault UI remains usable |

Client routing is deliberately **not** a setup state. The previous draft had a
"setup required" state that kept the companion stopped until `SSH_AUTH_SOCK`
looked right, which is both unnecessary and wrong.

The companion always binds the deterministic path
`$XDG_RUNTIME_DIR/qs-bitwarden-cli/ssh-agent.sock`; it does not depend on
`SSH_AUTH_SOCK` to discover its own endpoint. If `XDG_RUNTIME_DIR` is unset the
feature refuses to start rather than falling back to a path another user could
have prepared, matching how the existing session handoff already behaves.

`SSH_AUTH_SOCK` matters only to *clients*: `ssh`, `scp`, `sftp`, `ssh-add`,
`ssh-keygen -Y sign`, Git through `ssh`, and anything that spawns them --
editors, IDEs, Ansible, build scripts. Neither the panel nor the companion ever
reads it. That is why it cannot gate startup, and why the panel's own reading of
it is a hint rather than a verdict: the panel sees the *graphical session's*
environment, while a `~/.bashrc` export, a `systemd --user` unit, a TTY login,
or an incoming SSH session can each differ and are all invisible to it.

So report it as advisory diagnostics with three outcomes -- *matches*, *points
elsewhere* (naming the apparent owner), or *unset* -- and also print the check
the user can run in the terminal they actually use:

```sh
echo "$SSH_AUTH_SOCK"; ssh-add -L
```

Omarchy runs the graphical session through UWSM, so the assisted setup should
offer to create exactly one plugin-owned file:

```sh
# ~/.config/uwsm/env.d/50-qs-bitwarden-ssh-agent
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR}/qs-bitwarden-cli/ssh-agent.sock"
```

The normal plugin installer only clones and enables plugins; it does not run
install hooks. The setup action therefore happens only after an explicit user
choice in the panel. It must create the parent safely, write atomically, refuse
to follow a symlink, and refuse to replace unexpected contents at the managed
path. If the current session points at Bitwarden Desktop, 1Password, GPG Agent,
OpenSSH, or another socket, show the conflict and require confirmation rather
than silently changing the primary agent.

UWSM applies the fragment at the next graphical login, and only to the graphical
session: a TTY login, a `systemd --user` unit that started earlier, and an
incoming SSH session do not inherit it. After writing it, show that
logout/login is required; do not claim that restarting only Quickshell can
change the environment of applications that are already running. Once the new
session starts, the panel reports whether the inherited value matches -- as a
diagnostic, never as a gate on starting the companion.

Turning the setting off immediately performs the same deny/cancel/zeroize
shutdown discipline as a lock, closes and unlinks the socket, and terminates
the companion. If the plugin created the exact managed fragment, disabling
removes it; unexpected or manually managed configuration is left untouched
with cleanup instructions. Existing processes retain their old environment
until logout, but the agent itself is already stopped. Removing the plugin
cannot run an uninstall hook, so the documentation must also explain manual
fragment removal.

### Unlock on demand is opt-in, and must start at identity listing

`ssh` asks the agent for identities on **every** connection, including ones that
will authenticate with an on-disk key and have nothing to do with the vault. If
identity listing could raise the unlock UI, the first `ssh` after every login
would open the panel whether or not a vault key was involved.

The default is therefore: while locked with no cache, return an empty identity
list and record a non-secret "vault locked" status. The user unlocks the panel
once, the public-key cache is populated, and from then on identity listing
answers while locked and only a *sign* request raises the unlock UI -- which is
the right moment, because by then a specific vault key has been selected.

`sshAgentUnlockOnDemand` (default `false`) restores the eager behavior for users
who want it. When it is on, unlock-on-demand must begin at
`SSH_AGENTC_REQUEST_IDENTITIES` rather than at the sign request: with no cache
there are no identities to offer, so no sign request will ever arrive. That
asymmetry is exactly why this is a setting and not the default. The request
emits `unlock_required`, waits for one bounded unlock attempt, loads keys, and
then answers the original request; repeated denials or timeouts enter the
cooldown described under "Quickshell responsiveness and lifecycle".

After at least one successful load, public identities are returned while locked
in both modes. Public keys are not secret, and this avoids unnecessary unlock
prompts. The subsequent sign request is still denied until unlock and explicit
approval or a live grant.

## Panel-to-Companion Contract

Use one JSON object per line over stdin/stdout. Every message includes
`"v": 1` and `"type"`. The protocol is private to this plugin but versioned so
an old bundled binary fails clearly after a plugin update.

Panel to companion:

```json
{"v":1,"type":"hello"}
{"v":1,"type":"key_load_begin","epoch":7,"loadId":"<128-bit random hex>"}
{"v":1,"type":"key_load_end","epoch":7,"status":"ok"}
{"v":1,"type":"vault_locked","epoch":7}
{"v":1,"type":"vault_logged_out"}
{"v":1,"type":"approve","requestId":42,"grantSeconds":0}
{"v":1,"type":"deny","requestId":42}
{"v":1,"type":"unlock_cancelled","requestId":41,"reason":"user-cancelled"}
{"v":1,"type":"revoke_grants"}
{"v":1,"type":"shutdown"}
```

No message carries a session token, because the companion never runs `bw`.
`unlock_cancelled` exists because the previous draft had no way to tell the
companion that the user dismissed the unlock dialog: the pending request simply
burned its timeout.

Companion to panel, with no secret fields:

```json
{"v":1,"type":"ready","socketPath":"...","fifoPath":"...","agentVersion":"..."}
{"v":1,"type":"unlock_required","requestId":41,"reason":"list-identities"}
{"v":1,"type":"approval_required","requestId":42,"keyId":"...","keyName":"Work","fingerprint":"SHA256:...","pid":1234,"processName":"ssh","processPath":"/usr/bin/ssh","operation":"ssh-sign","namespace":null,"forwarded":false,"grantOffered":true}
{"v":1,"type":"keys_loaded","epoch":7,"keyCount":2,"skipped":[{"itemId":"...","code":"UNSUPPORTED_KEY_TYPE"}]}
{"v":1,"type":"locked","epoch":7}
{"v":1,"type":"grants_changed","grants":[{"grantId":9,"keyId":"...","keyName":"Work","pid":1234,"processName":"ssh","expiresInSec":95}]}
{"v":1,"type":"state_changed","state":"locked-cached","keyCount":2}
{"v":1,"type":"error","code":"KEY_LOAD_FAILED","message":"Could not load SSH keys","recoverable":true}
```

`keys_loaded` and `locked` are the two acknowledgments the panel may wait on,
each with its own bounded wait. `locked` is the one described in "Vault and
Agent State": two seconds, then the child is killed. `keys_loaded` is what
releases an SSH request that triggered the unlock; the panel does not need it to
render its own list.

Contract rules:

- No control message carries a session token or private key material. The only
  path for private keys is the FIFO, framed by `key_load_begin` and
  `key_load_end` for one epoch.
- `loadId` is a fresh 128-bit random value per load, generated by the panel,
  never logged, and delivered only over the companion's private stdin pipe. The
  FIFO payload must open with the matching `loadId` or the load fails closed.
  That nonce is what stops another same-UID process from writing its own key set
  into the FIFO during an open window -- it cannot guess a value it cannot read.
- A second payload inside one window, a payload with a stale or absent
  `loadId`, or a `key_load_end` whose `status` is not `ok` invalidates the whole
  candidate load.
- `approve` may carry `grantSeconds`. `0` approves exactly one signature; a
  non-zero value, capped by `sshAgentApprovalWindowSec`, additionally opens a
  grant. See "Bounded approval grants".
- Unknown versions, message types, fields with wrong types, and overlong lines
  fail closed. Start with a 64 KiB control-message ceiling.
- Agent frames have a separate hard ceiling, initially 256 KiB, checked before
  allocation.
- Request IDs are unique for the process lifetime. Late approvals, duplicate
  responses, and approvals after lock are rejected.
- Only one unlock flow runs at a time. Show one approval prompt at a time and
  allow at most four pending sign requests including the visible request.
  Reject overflow, give each request a deadline, and cancel it when its client
  disconnects. **The deadline is 120 seconds, not the 30 originally specified
  here** -- see `docs/decisions/0003-request-deadline.md`. Thirty seconds
  expired under a user who was doing no more than reading the prompt, and each
  expiry counted as a refusal, so a tight deadline escalated into the denial
  cooldown switching signing off entirely.
- A timeout returns only the normal SSH-agent failure and leaves a non-secret
  status in the panel. Do not create a desktop notification in v1; repeated
  local requests must not create notification spam or persistent history.
- Errors exposed to QML are stable codes plus sanitized user-facing messages.
  Raw key parser errors and CLI output stay out of stdout and normal logs.

### Bounded approval grants

Approval strictly per signature is unusable for the workflows this feature
exists to serve. A `git rebase` over twenty commits with `gpg.format=ssh` is
twenty modal prompts; a fetch followed by a push is two. Deferring grants until
"real workflows make this unusable" defers past the first day of real use, so
they are in v1.

> **Superseded by `docs/decisions/0002-grant-scope.md`.** The process scoping
> described in the next paragraph was implemented and then relaxed to *program*
> scoping, because live testing showed it did not achieve the very thing this
> section opens by arguing for. Git spawns a fresh `ssh-keygen -Y sign` for
> every commit it signs, so each has a different PID and start time and no
> PID-scoped grant ever matched: a twenty-commit rebase prompted twenty times
> whether a grant had been taken or not. Grants now match on the peer UID, the
> executable path, and the key. The ADR records what that widens and why it was
> judged acceptable. The paragraph below is kept as the original reasoning.

A grant is scoped to **one key and one live client process**. It is keyed on the
peer PID *together with* that PID's start time from `/proc/<pid>/stat`, so PID
reuse cannot inherit a grant, and on the executable path captured at grant time,
so a re-`exec` invalidates it.

- The approval prompt offers *Approve once* and *Approve for this program*
  (originally *for this process*; see the note above).
  `sshAgentApprovalWindowSec` (default `120`, maximum `900`, `0` to disable
  grants and always ask) sets the window.
- Grants live only in the companion's memory. They are never written to disk and
  never survive a companion restart.
- A grant is dropped on: expiry, lock, logout, account change, epoch change,
  disabling the feature, screen lock, suspend, client process exit,
  `revoke_grants`, and any mismatch of key identity or executable path. (PID
  start time no longer participates; see the note above.)
- Every live grant is visible in the panel with its key, process, and remaining
  time, and is revocable individually or all at once.
- A grant does not bypass the final authorization point. Epoch, lock state, and
  key identity are still rechecked immediately before the signing primitive. A
  grant replaces the prompt, not the check.
- Grants count against the same four-request bound as prompted requests.

## SSH Agent Protocol Scope

Initially accept only what is needed for local authentication and SSH signing:

- request identities;
- sign request;
- the RSA SHA-2 signature flags required by OpenSSH;
- Ed25519 and RSA keys supported by Bitwarden SSH items;
- enough OpenSSH extension/session-bind parsing to recognize and reject
  unsupported forwarding safely.

Explicitly reject agent mutation operations such as add, remove, remove-all,
lock/unlock, smartcard, and unknown extensions. Do not blindly forward opaque
messages.

Agent forwarding is out of the first release. A forwarded connection changes
what the peer PID means and expands the threat model. If it is later enabled,
session-bind and forwarding state must be tracked and shown in the approval UI.

The companion should derive fingerprints from the parsed public key and use the
vault fingerprint only for comparison. A mismatch is an error, not a loose
lookup fallback.

Build each refresh into a separate candidate keystore. For every item, parse
the private key, derive its public blob and fingerprint, and compare both with
the vault metadata. Skip an individual malformed, encrypted, unsupported, or
mismatched key with a sanitized item-level reason while continuing to validate
the rest. Coalesce duplicate public blobs into one advertised identity rather
than returning indistinguishable duplicates. Only after validation completes
does one atomic swap publish the complete accepted set; no old private key is
combined with a new partial refresh.

Transport, filter, schema, truncation, or global-limit failure is different
from one invalid item: it invalidates the whole candidate load and leaves no
private-key set available. Master-password re-prompt items are visible in the
public-only panel list with an unavailable explanation, but their private keys
are filtered out before Rust and they are not advertised by the agent in v1.

## Public Key File Export

Git commit signing needs files, so this is v1 scope rather than later polish.
`ssh-keygen -Y sign` takes `user.signingkey` as a path (the inline
`key::ssh-ed25519 AAAA…` form works, but is not how anyone configures this), and
`gpg.ssh.allowedSignersFile` has no inline equivalent at all. Without exported
files, the `gpg.format=ssh` acceptance test below cannot be satisfied the way a
user would actually set it up. `IdentitiesOnly=yes` users need the same thing.

Public keys are not secret, so this does not cross the private boundary.

- Export to `${XDG_DATA_HOME:-$HOME/.local/share}/qs-bitwarden-cli/ssh/`, one
  `.pub` file per advertised key, mode `0600` inside a `0700` directory. Do not
  write into `~/.ssh`; that directory belongs to the user and to OpenSSH.
- Derive filenames with the hostile-filename sanitizer the attachment path
  already uses. An item name is decrypted vault content about to become a path.
  Resolve collisions with the item ID rather than overwriting.
- The directory is a projection of the current vault epoch: rewritten on load,
  and cleared on logout, account change, or disabling the feature. A lock does
  not clear it, because public identities stay advertised while locked.
- Never write private keys to disk under any circumstance. That is key export,
  and it stays out of scope.
- Document the resulting `user.signingkey`, `allowed_signers`, and
  `IdentityFile`/`IdentitiesOnly` snippets in setup.

## Security Requirements

The feature protects against accidental signing, stale key residency after
lock, malformed local agent clients, and private keys leaking through argv,
QML state, logs, or files. It does not claim to protect an unlocked desktop
from arbitrary code already running as the same user.

- Create a `0700` runtime directory and a `0600` Unix socket under
  `$XDG_RUNTIME_DIR`; verify owner and file type before replacing a stale path.
- Require the peer UID from `SO_PEERCRED` to equal the companion's effective
  UID. Treat PID/executable information as prompt context, not authentication.
- Make approval authoritative in the companion. The panel can request allow or
  deny, but no sign path exists without a matching live request.
- Give every load, approval, and sign operation a vault epoch. Recheck the
  epoch, approval, lock state, and key identity at the final authorization
  point immediately before invoking the signing primitive.
- Set `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` for the companion before it reads
  anything secret, and be precise about what that buys. `RLIMIT_CORE` is
  inherited across `execve`; `PR_SET_DUMPABLE` is **reset to 1 by `execve`**, so
  it protects the companion's key store and nothing else. The companion spawns
  no children, so it has nothing else to protect -- but the panel's `bw` child
  is dumpable and holds the entire decrypted vault plus `BW_SESSION` in its
  environment. That process, not the agent, is the widest same-UID exposure
  window in the design; it is bounded only by being short-lived and by
  `/proc/<pid>/environ` being owner-readable. Do not describe the agent's
  hardening as though it covered the load path.
- The companion needs no `PATH`, no `HOME`, and no vault credentials of any
  kind. Give it a minimal environment and keep it that way.
- Hold an exclusive `flock` on a lock file in the runtime directory before
  unlinking or binding the socket, and refuse to start while it is held. A
  Quickshell reload otherwise starts the replacement companion while the
  outgoing one is still draining toward stdin EOF, leaving it serving an
  unlinked socket with a dead control channel.
- Use secret/zeroizing wrappers for the session, raw item JSON, and PEM buffers.
  Audit whether the selected key types clone or zeroize their backing memory;
  Rust does not make secret erasure automatic.
- Put `bw`, the raw-output cap, `tee`, and both `jq` stages in one supervised
  process group owned by the panel. A lock, logout, timeout, or helper shutdown
  kills and reaps the whole group before the state transition is acknowledged.
- Give `BW_SESSION` only to the `bw` child, as the panel already does. Invoke
  every `jq` stage with static program text and `--arg` inputs, never a
  shell-interpolated filter.
- Create the key-load FIFO with `mkfifo` at mode `0600` inside the `0700`
  runtime directory, and have the companion hold it open `O_RDWR` for its
  lifetime so it never observes EOF and writers never take `SIGPIPE` from a
  momentarily busy reader.
- Start with explicit vault-load limits: 16 MiB of raw CLI JSON (the panel's
  existing `MAX_ITEMS_BYTES`), 128 SSH keys, 64 KiB per PEM, and 8 MiB of
  filtered SSH-key JSON on the FIFO. Treat hitting any limit as a failed load,
  never a partial key set.
- Bound all inputs, queues, and waits. Test truncated frames, length overflow,
  slow clients, disconnects, invalid UTF-8, and request floods.
- Never log environment values, control input, private keys, signed payloads,
  signatures, or raw `bw` stdout/stderr.
- Run `bw` non-interactively with `BW_NOINTERACTION=true`. Pass `BW_SESSION` in
  its environment, consistent with the repository's existing no-secrets-in-
  argv policy.

## Remaining Concerns and Acceptance Criteria

### Private-key memory and zeroization

Rust prevents many memory-corruption bugs; it does not guarantee that secrets
are never copied, swapped, or left behind by a dependency. Lock semantics are
credible only if the chosen representation supports them.

- Filtered JSON and PEM input must use `Zeroizing<Vec<u8>>` or an equivalent
  secret container from the first byte read off the FIFO. Avoid conversion
  through ordinary `String`, `format!`, debug output, or cloned request
  structures. The companion holds no session token to protect.
- Review the actual private components of every supported parsed key type. If
  RSA big integers or Ed25519 secret material do not implement reliable
  zeroization on drop, that dependency fails the spike; wrapping only the PEM
  text is not enough after it has been parsed.
- Keep private keys in one keystore owned by the signing worker. Other tasks use
  public identifiers and request IDs, not cloned private-key objects or `Arc`s
  that can outlive a lock.
- Locked memory may be added for the small PEM buffers if it works under
  normal Omarchy memory-lock limits. Failure to `mlock` cannot silently weaken a
  documented guarantee, and parsed third-party key objects may still live in
  ordinary heap pages.
- Release execution disables debugging/core dumps. CI keeps separate debug
  symbols as artifacts if needed; they are not bundled in the plugin.
- Tests prove state and drop behavior, while the documentation remains candid:
  best-effort erasure protects against later accidental reads, not root, the
  kernel, or a process that already stole the key while the vault was unlocked.

### Quickshell responsiveness and lifecycle

The SSH client is allowed to block on a response; Quickshell's event loop is
not. The panel/agent integration passes only if all of these hold:

- QML starts the helper as a tracked, non-detached `Process` with
  `stdinEnabled`, an attached line parser from startup, a cleared/allowlisted
  environment, and an absolute path resolved inside the plugin directory.
- QML never waits synchronously for the helper or for SSH. It reacts to one
  bounded event at a time and lets the existing asynchronous unlock flow run.
- The helper uses independent asynchronous socket tasks plus bounded internal
  channels. A slow SSH client, a full control pipe, or one pending approval
  cannot stall other clients or the lock command.
- EOF, protocol mismatch, or loss of the panel control channel immediately
  closes the signing gate and exits. Unexpected exits use capped restart
  backoff; a crash loop disables the feature and leaves the rest of the plugin
  usable.
- Identity requests are answered from the public cache without any panel
  interaction. Only when `sshAgentUnlockOnDemand` is on can they raise the
  unlock UI, and then they are coalesced; repeated denied or timed-out requests
  enter a cooldown so a same-UID process cannot keep opening the panel. Sign
  requests use the four-request bound and 30-second deadline defined by the
  control contract.
- A same-UID process can still occupy the four request slots with junk sign
  requests and delay a legitimate one. That is inside the threat model this
  feature explicitly does not defend against, but the bound, the deadline, and
  the client-disconnect cancellation keep it from becoming permanent.
- Screen lock and suspend always deny and dismiss pending prompts; the agent
  never opens an approval UI over the lock screen. A normal unlocked desktop
  may open/focus the panel for an SSH-triggered request.
- Integration tests cover the panel being closed, a concurrent vault sync, lock
  during load, lock during approval, lock while a grant is live, helper
  crash/restart, Quickshell reload (including the `flock` that prevents two
  companions binding one socket), the panel restarting while the vault is
  already unlocked from the keyring, screen lock, and a client disconnecting
  while the UI is open.

### Bitwarden CLI coordination

The previous draft had three separate `bw list items` reads -- panel list,
public-only SSH list, agent private list -- and then had to serialize them
against Bitwarden's data-file locking. On a real vault each read costs seconds,
so that design tripled unlock latency to buy a boundary that one read provides
just as well.

There is now **one read per unlock or sync**, split in the shell:

```sh
set -o pipefail
bw list items \
  | head -c 16777216 \
  | tee >( jq -c --arg loadId "$QSBW_LOAD_ID" "$AGENT_FILTER" > "$FIFO" ) \
  | jq -c "$PANEL_FILTER" \
  | head -c "$PANEL_CAP"
```

The `tee` branch exists only while the agent is enabled; with the feature off,
the command is the panel pipeline alone. Both filters are static programs with
`--arg` inputs, never interpolated text.

Rules this has to satisfy:

- **The optional feature can never break the core list.** If the pipeline fails
  while the agent branch is present, the panel retries once without it and
  reports the agent load as failed. The item list is not allowed to depend on
  the companion being healthy.
- **Backpressure is bounded.** The companion drains the FIFO eagerly into its
  bounded candidate buffer. Because it holds the FIFO `O_RDWR`, a busy reader
  blocks the writer rather than breaking it, and the block is bounded by the
  8 MiB filtered cap and the pipeline's own timeout.
- **`pipefail` does not observe process substitution.** A failure inside the
  `tee` branch will not fail the pipeline, so the companion must detect a short,
  malformed, or nonce-mismatched payload itself and fail that load closed.
  `key_load_end` reports the panel's view of the pipeline; the companion's own
  validation is what is authoritative.
- **Ordering stops being a concurrency problem.** One `bw` invocation means
  there is nothing to serialize. The panel renders from stdout while the
  companion validates its candidate keystore in parallel, and an SSH-triggered
  unlock is released by `keys_loaded` without waiting for the panel to finish
  rendering.
- A lock cancels the running pipeline and abandons the current `loadId`. A
  whole-pipeline failure leaves the previous private-key set unavailable.
  Individual invalid keys follow the skip-and-report policy above; re-prompt
  private keys never leave the `jq` stage.

If the spike shows the `tee` fan-out cannot be made robust, the fallback is two
panel-owned reads -- one for QML, one piped straight into the FIFO -- never
three, and never one that hands the companion a session token. Folding the
public-only SSH projection into the panel's own stdout is independently correct
and removes the third read either way.

## Prerequisite: Sanitize the Vault Read Before QML

Today `bw list items` returns decrypted type-5 `sshKey.privateKey` values and
`parseItems()` retains the entire cipher as `rawObject`. Removing the field
after `JSON.parse()` is too late: an immutable JavaScript string and parsed QML
object have already held it. The current model also recognizes only item types
1–4 and falls back to treating an unknown type as a login, so a type-5 cipher
can be both exposed and misrepresented -- as can types 6–8, which already
exist.

Before adding the agent, put an out-of-process split in front of QML. One
command, one stdout document:

```json
{"items": [ ...types 1-4, unchanged... ],
 "sshKeys": [ ...type 5, public fields only... ]}
```

- `items` is a positive allowlist of supported types 1–4, each item's object
  intact so `rawObject` can still round-trip through `bw edit item`. A positive
  allowlist fails closed when Bitwarden adds another sensitive type -- and it
  already has: `CipherType` now defines `6 BankAccount`, `7 DriversLicense`, and
  `8 Passport`, all present in the shipped CLI 2026.2.0. `itemTypeName()`
  currently falls back to `"login"`, so the plugin mislabels every one of them
  today, exactly as it does type 5. The allowlist fixes a live bug, not a
  hypothetical one. Types 6–8 need their own follow-up before they can be shown.
- `sshKeys` projects only item ID, name, type, organization ID, folder ID,
  favorite state, re-prompt state, public key, and fingerprint.
  `sshKey.privateKey` is never part of this stream.

Because both arrive on the same read, “SSH Keys” needs no lazy load, no second
collector, no freshness timestamp, and no separate vault-epoch guard -- and
there is no longer any reason to hide SSH keys from All, Favorites, global
search, or item counts. They participate like any other type. Contextual
suggestions stay login-only, because an SSH key has no URI to match.

SSH key detail is public-only and read-only in v1. It renders from the sanitized
type-5 object and must never fall through to the generic `bw get item` command,
which would return the private key to QML. Generic create, edit, and clone paths
reject type 5. Deletion can be considered separately because it is ID-based,
but it is not required for the first release. Supporting SSH metadata edits
later requires an opaque `bw get item` → allowlisted `jq` patch → `bw encode` →
`bw edit item` pipeline so QML never has to round-trip the private key.

The pipeline keeps a raw-input cap before the filters and a second QML-facing
output cap after them. It uses `pipefail` and makes filter errors or truncated
input fail the read rather than returning a partial array. Fixture
tests place unique markers in an SSH private key and in unrelated vault types,
execute the real pipelines, and prove:

- the `items` array contains no type-5 item and no private-key marker;
- the `sshKeys` array contains only type-5 public fields and no private-key
  marker;
- with the agent branch enabled, the FIFO payload carries the private-key marker
  and no unrelated-item marker, while QML-facing stdout still carries neither;
- a payload written to the FIFO with a wrong or absent `loadId` is rejected;
- neither marker survives in collector or model state; and
- no type-5 item can reach the generic detail fallback.

The companion receives private SSH material only from the FIFO branch of that
same read. It is the only long-lived plugin component allowed to hold private
keys, and it obtains them without running a command, without holding a session
token, and without costing a second vault decryption.

## Dependencies and Version Floor

`jq` is already a hard dependency of the `omarchy` package itself -- `pacman -Qi
omarchy` lists it alongside `git`, `perl`, `gum`, `quickshell`, and `uwsm` -- so
it is present on every Omarchy install and the split filter adds no new install
step. It still belongs in the existing dependency probe as a *required* tool, so
a non-Omarchy Arch install fails with a clear message instead of an empty vault
list. `jq` is also the only guaranteed JSON tool: `gojq`, `dasel`, `yq`,
`python`, and `node` are not Omarchy dependencies (`/usr/bin/node` exists only
because `bitwarden-cli` depends on `nodejs-lts-jod`). `bw` continues to be
resolved through `PATH` by the panel, as it is today; the pacman
`bitwarden-cli` package is the supported install.

The SSH key item type has a real version floor:

| Version | What changed |
|---|---|
| `bw` 2024.12.0 | First CLI release whose export model carries `sshKey` (`PM-10393 SSH keys`, bitwarden/clients#10825, merged 2024-11-08, first contained in tag `cli-v2024.12.0`) |
| 2025.1.0 / 2025.1.1 | SSH key creation and import ship in the web vault and browser extension, so items can actually exist |
| 2026.3.0 | SSH key storage and SSH Agent feature flags are removed; the feature is unconditionally on |
| 2026.8.0 | `PM-40201`: SSH key items with a null public key or fingerprint no longer fail to decrypt and break the vault |

**Floor: `bw` 2025.1.0.** Below it, hide the feature behind a clear message
rather than showing an empty key list. 2024.12.0 is the version where the field
exists but no client could yet create an item to put in it, which is not a
useful floor.

The version check is necessary but not sufficient. Self-hosted Bitwarden and
Vaultwarden gained type 5 on their own schedules, and the flag removal only
landed in 2026.3.0, so the panel should treat "the read returned no type-5 items
at all" as an *unconfirmed capability* rather than a confirmed empty set.

Record the 2026.8.0 fix as a known upstream hazard: on an older CLI a single
malformed SSH key item can fail the whole `bw list items` call, which breaks the
ordinary panel list too. That failure is not the plugin's, and the diagnostic
should say so and name the fix version.

## Rust Dependency Spike

Do not start the UI implementation until a small headless spike proves the
agent core. Evaluate maintained crates against these requirements:

1. Correct OpenSSH agent framing and bounded decoding.
2. Ed25519 signing and RSA SHA-256/SHA-512 flag handling.
3. A hook before every identity-list and sign operation.
4. Unix peer credentials and concurrent clients.
5. Explicit handling of unknown messages and OpenSSH extensions.
6. Secret-memory behavior, dependency health, license compatibility, and audit
   surface.
7. The FIFO transport: `O_RDWR` retention, nonce framing, bounded draining, and
   rejection of an unframed or duplicated payload.

Re-verify the dependency claims at spike time rather than trusting this
document's review date: the `bitwarden-russh` deprecation, the state of
Bitwarden's v2 agent, and RFC 9987's status can all have moved.

RustCrypto's `ssh-key` is a reasonable candidate for key parsing/signing, but
its surrounding agent protocol support still needs evaluation. Do not depend
on the deprecated `bitwarden-russh` repository. Reusing code from Bitwarden's
eventual v2 implementation is possible only after its stability, licensing,
and fit are reviewed.

The spike passes only after automated tests cover Ed25519 and RSA, both RSA
SHA-2 flags, malformed frames, key/public/fingerprint mismatch, duplicate keys,
per-item skips, whole-load failure, lock-during-approval, multiple clients, the
`tee` fan-out's exit-status and backpressure behavior, FIFO nonce rejection, and
grant expiry plus PID-reuse rejection, plus manual end-to-end tests for:

- `ssh -T` or a real Git authentication flow with no private key on disk;
- a Git commit signed with `gpg.format=ssh`, configured through an exported
  public key file the way a user would actually set it up;
- a `git rebase` over several commits, once with grants off and once with a
  grant, to confirm the prompt volume is tolerable;
- `ssh-add -L` while unlocked and after lock;
- an SSH request made before the first vault unlock, in both unlock-on-demand
  modes;
- `ssh` to a host that uses an on-disk key, to confirm the default mode does not
  raise the panel;
- Quickshell reload while a terminal retains the stable socket path.

## Repository Binary and CI Trust

The repository is the distribution unit for an Omarchy plugin, so keep both
the Rust source and supported release binaries in it:

```text
agent/
    Cargo.toml
    Cargo.lock
    rust-toolchain.toml
    src/
bin/
    x86_64-linux/qs-bitwarden-ssh-agent
    SHA256SUMS
```

The v1 target is `x86_64-unknown-linux-gnu`, built and executed on x86_64 CI.
Do not advertise or publish aarch64 until Omarchy supports it as a normal target
and CI can execute the final artifact natively. A GNU-linked binary matches the
initial Omarchy runtime; reconsider static PIE/musl only in a later portability
decision backed by compatibility tests.

Do not use Git LFS for the executable; a normal plugin checkout must contain
the exact bytes it will execute. Preserve executable mode in Git. Quickshell
launches the target for the current architecture by a canonical path relative
to the plugin, never by searching PATH.

### Pull-request gates

**Decision:** use the read-only candidate workflow. Pull-request CI builds and
uploads the candidate binary; a maintainer adds those bytes to the PR; CI then
rebuilds and compares them before merge. Do not give PR jobs a write token and
do not add a bot-authored binary-update PR flow in the initial implementation.

Every PR runs with read-only repository permissions and no secrets:

1. Run all existing JavaScript/QML tests.
2. Run `cargo fmt --check`, Clippy with warnings denied, and Rust unit,
   integration, and protocol-vector tests.
3. Audit `Cargo.lock` for RustSec advisories and enforce allowed licenses,
   registries, Git sources, and duplicate dependency policy with `cargo-deny`.
4. Build with the committed lockfile and exact pinned toolchain.
5. Execute each produced target natively, on an architecture runner, or under a
   deliberate emulator; never publish an architecture that CI only compiled.
6. Run end-to-end tests against disposable keys, a fixture `bw`, Unix sockets,
   and a fake approval controller. CI never receives a real vault session.
7. Rebuild the release binary in the pinned release environment. Compare it
   byte-for-byte with the binary checked into `bin/` **when the PR touches
   `bin/`, and unconditionally on merge to `master` and on a release tag.** On a
   fork PR that only changes `agent/`, upload the candidate and report the diff
   without blocking: a fork contributor usually cannot push CI's bytes into
   their own branch, so an unconditional match requirement would make every
   external agent-source PR unmergeable. The bytes still cannot reach `master`
   without a clean rebuild-and-compare.

This avoids giving untrusted pull-request code a write token. Whether the
candidate was first compiled locally or downloaded from the read-only CI job,
the required clean rebuild proves that CI produces the same bytes before they
can merge.

### Reproducible build inputs

- Commit `Cargo.lock` and an exact `rust-toolchain.toml`; use `cargo --locked`.
- Build inside a container image pinned by digest, with pinned target packages,
  linker, strip tool, feature flags, and release profile.
- Remove build-path variance with `--remap-path-prefix`, covering both the
  source root and `$CARGO_HOME/registry` -- the registry path is the one that
  usually leaks. Note that `rustc` does not consume `SOURCE_DATE_EPOCH` and does
  not embed build timestamps: set it for the surrounding tooling if that helps,
  but do not list it as the mechanism that makes the Rust build reproducible.
  Do not embed the Git commit SHA in a binary tracked by that same commit; doing
  so creates a circular artifact. Embed semantic and control-protocol versions
  instead.
- Prefer pure-Rust crypto dependencies and keep the v1 binary GNU-linked.
- Keep stripped release bytes in `bin/` and upload separate debug symbols as
  short-lived CI/release artifacts.
- Any change to Rust source, `Cargo.lock`, toolchain, build container, flags, or
  release profile requires a regenerated binary and checksum.

### Release provenance and local validation

On a protected release tag, CI repeats every gate against the final commit,
verifies the tracked bytes, and then:

- recomputes and verifies the committed `bin/SHA256SUMS` before packaging;
- creates GitHub build-provenance attestation for each binary, binding its
  digest to this repository, workflow, and commit;
- publishes an SBOM and dependency/license report;
- exposes a documented `gh attestation verify` command for users who want to
  validate provenance;
- confirms the helper's `--version`, protocol version, target architecture,
  executable mode, dynamic-library requirements, and built-in self-test.

Be honest about what the launch-time checksum does. `bin/SHA256SUMS` lives in
the same directory as the binary *and* as the QML that checks it, so anyone able
to replace the binary can replace both. It is not tamper detection. What it does
catch is real and worth keeping: a corrupt or partial clone, an LFS-smudged
placeholder, an architecture or format mismatch, and -- most usefully -- a stale
binary after a `git pull` that updated the source but left an old artifact
behind.

Tamper and provenance are a different mechanism with a different root of trust:

- CI attests each binary's digest to this repository, workflow, and commit.
- Setup diagnostics show a one-command verification, and run it on request when
  `gh` is available (it is not an Omarchy dependency, so it cannot be assumed):

  ```sh
  gh attestation verify bin/x86_64-linux/qs-bitwarden-ssh-agent \
     --repo Elevate08/qs-bitwarden-cli
  ```

- Re-offer that check after a plugin update, when the binary has changed.

Then state the limit plainly: anyone who can write to the plugin directory can
also rewrite the QML that performs any of these checks. The plugin cannot defend
itself against a same-UID attacker, and filesystem permissions own that
boundary. This is the same threat line the rest of the plugin already draws.

Pin every third-party GitHub Action to a full commit SHA. Protect changes to
workflow files, `agent/`, `Cargo.lock`, and `bin/` with required review and
CODEOWNERS. Default workflow permissions to `contents: read`; grant
`id-token: write` and `attestations: write` only to the protected release job.
Attestation proves origin and build instructions, not that the source is safe,
so review, tests, and dependency gates remain mandatory.

At runtime, the panel and companion perform a protocol/version handshake. A
missing binary, unsupported architecture, checksum mismatch, failed self-test,
or version mismatch disables SSH-agent support with a clear diagnostic; it
does not prevent the rest of the Bitwarden plugin from loading.

## Delivery Plan

### 0. Remove the existing QML exposure

- Split the item-list pipeline out of process into one stdout document with
  `items` (allowlisted types 1–4) and `sshKeys` (public-only type 5).
- Add the SSH Keys type, public-only parser, and read-only detail view with no
  generic `bw get item` fallback.
- Add type 5, public key, fingerprint, and re-prompt-unavailable presentation;
  SSH keys participate in All, Favorites, search, and counts like any other
  type.
- Add `jq` to the dependency probe as required, and the `bw` 2025.1.0 floor with
  its diagnostic.
- Add tests independently of agent work.

### 1. Prove the Rust agent core

- Select maintained crypto/protocol crates.
- Implement an in-memory test keystore and socket.
- Validate algorithms, flags, limits, key-type zeroization, lock
  linearization, approvals, and peer context.
- Prove the `tee` fan-out, both `jq` filters, and the nonce-framed FIFO
  transport against fixture vaults, including agent-branch failure leaving the
  panel list intact.
- Record the dependency and threat-model decision before building UI around it.

### 2. Integrate the CLI and panel

- Add versioned stdio control messages and Quickshell supervision.
- Add the disabled-by-default settings and the assisted UWSM setup/removal flow,
  with `SSH_AUTH_SOCK` reported as advisory diagnostics only.
- Add the `tee` agent branch and FIFO transport to the existing single read.
- Add the state machine, opt-in unlock-on-demand, one-at-a-time approval modal,
  bounded grants with their revoke UI, four-request bound, 30-second timeout,
  and lock/logout/disable handling.
- Keep the rest of the plugin functional when the optional helper is absent.

### 3. Package and document

- Add the repo-tracked binary, reproducible CI build/compare gate, checksum,
  SBOM, and protected release attestation. Users do not need a Rust toolchain.
- Ship and test the x86_64 GNU target only.
- Ship public-key file export; it is required by the signing flow, not optional
  polish.
- Add setup diagnostics, managed `SSH_AUTH_SOCK` lifecycle instructions, the
  `gh attestation verify` provenance check, authentication and signing examples,
  uninstall cleanup, and an upgrade/version-mismatch path.

## Not Doing Initially

- **Python proxy plus inner `ssh-agent`**: two sockets create a bypass path and
  split approval, lifetime, and error handling across processes.
- **A Bitwarden SDK or direct cloud API**: the CLI remains the vault boundary.
- **Key generation or import**: those write private material and need a separate
  design and security review.
- **SSH item creation, editing, or cloning in QML**: the CLI edit contract
  round-trips the complete cipher, so these need an opaque metadata-patch design
  that never exposes the existing private key to QML.
- **Master-password re-prompt for agent keys**: show affected items in the
  public list but do not load or advertise them until a dedicated re-prompt
  authorization flow exists.
- **GPG agent support**: Bitwarden has no corresponding vault key type; SSH
  signing covers the commit-signing use case.
- **Agent forwarding**: peer attribution and session binding require a later,
  explicit threat-model expansion.
- **Host selection inside the plugin**: the agent does not reliably know the
  destination. OpenSSH config, `IdentityFile`, and `IdentitiesOnly` own this.
- **Per-key custom policy stored in vault fields**: do not require users to
  mutate vault items for plugin-specific metadata.
- **Persistent private-key or session caches**: no encrypted side database and
  no “remember until reboot” mode.
- **Unbounded or persistent approval**: grants are per key and per program (see
  `docs/decisions/0002-grant-scope.md`, which relaxed this from per live
  process), memory-only, and time-limited. There is no "always allow", no
  per-key policy stored in the vault, and nothing that survives a lock, a
  logout, or a companion restart.
- **Item types 6–8** (bank account, driver's licence, passport): the allowlist
  excludes them along with type 5. Presenting them needs its own design; today
  they are silently mislabelled as logins.
- **aarch64 and static/musl binaries**: v1 targets the normal x86_64 GNU Omarchy
  environment and adds platforms only when they can be executed and verified
  in CI.

## Nice to Have (Deferred)

Ideas worth doing that are deliberately outside the first release.

- **Choice of approval presentation.** The approval prompt currently takes over
  the panel. Offer a user preference between a genuinely full-screen prompt --
  drawn over the desktop the way a lock screen is, so a signing request cannot
  be missed while working in another window -- and the present in-panel one for
  users who would rather it stayed small.

  If the in-panel presentation is chosen, the panel should close itself once
  the answer has been given, rather than leaving the user on whatever screen
  was behind the prompt. Today the panel stays open after an approval, which is
  fine when the user opened it themselves and wrong when a signing request
  opened it on their behalf.

  Neither variant may prompt over a locked screen; that rule is unchanged.

## Assumptions to Validate

The design is settled, but these spike assumptions must be true before the
feature proceeds past its prerequisite/headless stages:

- [ ] A maintained Rust dependency set can correctly implement the required
      agent protocol and RSA signature flags without adopting deprecated code.
- [ ] Quickshell remains responsive and can complete unlock/approval while the
      requesting SSH client is blocked on the socket.
- [ ] `bw list items` reliably returns all supported SSH keys in a format the
      selected Rust key library can parse, including imported RSA keys.
- [ ] Private key buffers can be bounded and best-effort-zeroized without
      hidden long-lived clones in selected dependencies.
- [ ] One `bw list items` read can be fanned out with `tee` into a QML stream
      and a FIFO without the agent branch ever truncating or failing the panel
      list, and without unacceptable backpressure.
- [ ] `bw` 2025.1.0 is a workable floor on the servers this plugin supports,
      including self-hosted Bitwarden and Vaultwarden.
- [ ] A pinned x86_64 GNU build environment can reproducibly emit the exact
      bytes tracked in the repository and run them on the target Omarchy
      environment.

Public-key export remains a later feature. Its filename, permission, conflict,
removal, and account-change semantics require a separate design before it is
implemented.

## Corrections from Revision 1

- The design performed up to three full `bw list items` decryptions per unlock
  and then had to serialize them against CLI data-file locking. One read now
  feeds both QML and the agent, and the public-only SSH projection rides the
  panel's own stdout.
- The companion no longer runs `bw` and no longer receives `BW_SESSION`. It
  spawns no child processes at all, so it needs no `PATH`, no `HOME`, and no
  load process group.
- `PR_SET_DUMPABLE=0` is reset by `execve`. It protects the companion's key
  store and never the `bw` child that holds the whole decrypted vault.
- Unlock-on-demand at identity listing is now opt-in. `ssh` lists identities on
  every connection, so making it the default opened the panel on the first `ssh`
  after login even when only on-disk keys were involved.
- `SSH_AUTH_SOCK` is client routing only; nothing in the plugin reads it. It is
  now advisory diagnostics, and the "setup required" state that gated the
  companion's startup on it is gone.
- Bounded approval grants moved into v1. Per-signature-only approval is
  unusable for `git rebase` with `gpg.format=ssh`.
- Public-key file export moved into v1. `gpg.ssh.allowedSignersFile` has no
  inline form, so commit signing could not be configured normally without it.
- The control contract had no way to report a cancelled unlock and no
  acknowledgment for a completed lock, yet the prose depended on both.
- The launch-time checksum is a corruption and staleness check, not tamper
  detection; `SHA256SUMS` sits in the same directory as the binary it describes
  and the QML that reads it.
- `CipherType` already defines types 6–8 upstream and they ship in CLI 2026.2.0.
  The current fallback mislabels all of them as logins today, which makes the
  positive allowlist a fix rather than a precaution.
- The PR gate required a byte-for-byte match on every PR, which no fork
  contributor could satisfy.

## Corrections from the Original Draft

- Bitwarden Desktop does **not** use a Python-like proxy around OpenSSH's
  `ssh-agent`; it implements a native Rust agent.
- A fresh local test did not reproduce the claim that daemonized `ssh-agent`
  bypasses `-c` confirmation. Foreground `-D` is still useful for supervision,
  but the prior security claim was incorrect.
- Unlock-on-demand must begin at the identity-list request, not only at a sign
  request. (Revision 2 keeps this true but makes the behavior opt-in; see
  above.)
- Removing `sshKey` from `rawObject` after parsing does not keep it out of QML;
  sanitization must happen before QML receives the JSON.
- The ordinary panel list must not carry `sshKey.privateKey`. A public-only
  type-5 projection never uses the generic detail fallback. (Revision 2 folds
  that projection into the same read instead of loading it lazily.)
- The previous design simultaneously proposed per-request lazy fetch and eager
  preload. This revision chooses one bounded CLI load per unlock/refresh.
- The inner-agent socket created an approval bypass and made the outer proxy's
  caller attribution unreliable. The single native agent removes that split.
- `bw list items` has no type filter. A bounded, allowlisting filter must sit
  in front of every consumer or each one receives unrelated vault secrets.
  (Revision 2 moves that filter into the panel's own pipeline; the companion no
  longer runs a CLI command of its own.)
- The agent is disabled by default. Omarchy session routing is configured only
  through an explicit assisted UWSM setup, and opting out stops the companion
  immediately.

## References

- [Bitwarden Desktop native SSH agent source](https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/core/src/ssh_agent/mod.rs)
- [Deprecated `bitwarden-russh` repository](https://github.com/bitwarden/bitwarden-russh)
- [Bitwarden SSH agent behavior](https://bitwarden.com/help/ssh-agent/)
- [Bitwarden CLI reference](https://bitwarden.com/help/cli/)
- [Bitwarden CLI vault command implementation](https://github.com/bitwarden/clients/blob/main/apps/cli/src/vault.program.ts)
- [Quickshell `Process` supervision and stdio](https://quickshell.org/docs/v0.3.0/types/Quickshell.Io/Process/)
- [Omarchy UWSM environment defaults](https://github.com/basecamp/omarchy/blob/quattro/default/uwsm/env.d/10-omarchy)
- [UWSM environment and shell-profile guidance](https://github.com/Vladimir-csp/uwsm/blob/master/README.md#4-environments-and-shell-profile)
- [SSH Agent Protocol, RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)
- [RustCrypto SSH crates](https://github.com/RustCrypto/SSH)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub Actions secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [Cargo deterministic lockfile options](https://doc.rust-lang.org/cargo/commands/cargo.html#manifest-options)
- [RustSec audit tooling](https://rustsec.org/)
