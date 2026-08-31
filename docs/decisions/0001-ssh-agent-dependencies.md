# 0001: Rust dependencies for the SSH-agent companion

- Status: accepted
- Date: 2026-08-27
- Task: 4 of `tasks/todo.md`
- Supersedes: the dependency assumptions in `docs/ideas/ssh-agent.md`

## Context

The companion holds decrypted SSH private keys for as long as the vault is
unlocked and signs with them on request. Every crate in its dependency tree is
therefore in the blast radius of a private-key compromise, and the crate set is
also what the reproducible build (Task 16) pins byte for byte.

`docs/ideas/ssh-agent.md` named RustCrypto's `ssh-key` as a candidate and told
this task to re-verify every claim at spike time rather than trust the idea
document's review date. That was the right instruction: two of its assumptions
did not survive contact with the released crates.

Sources were checked on 2026-08-27 against crates.io, the published crate
sources in the local registry, the projects' own repositories, and the RustSec
advisory database.

## Decision

The companion is built from the following crates, all pinned in
`agent/Cargo.lock` and all MIT or Apache-2.0 except where noted.

| Crate | Version | Role | Why this one |
| --- | --- | --- | --- |
| `ssh-key` | 0.6.7 | Key parsing, public blobs, fingerprints, Ed25519 signing | Maintained by RustCrypto, ~4M recent downloads, no advisories. Default features off, so ECDSA, DSA, and OpenSSH key encryption never compile in. |
| `ssh-encoding` | 0.2 | Wire primitives for the frame decoder | Same project, the version `ssh-key` already uses. |
| `ed25519-dalek` | 2.2 | Ed25519 backend | Not called directly. Declared to enable its `zeroize` feature — see below. BSD-3-Clause. |
| `rsa` | 0.9.10 | RSA private keys and PKCS#1 v1.5 signing | Required directly for both RSA SHA-2 algorithms — see below. |
| `sha2` | 0.10 | SHA-256/512 for the two RSA algorithms | Already in the tree via `ssh-key`. |
| `signature` | 2 | `Signer`/`Verifier` traits | The traits `ssh-key` and `rsa` sign through. |
| `zeroize` | 1.9 | `Zeroizing<Vec<u8>>` for PEM text and FIFO payloads | The standard, and what every crypto crate here already zeroizes through. |
| `tokio` | 1.53 | Current-thread runtime, `UnixListener`, timers, bounded channels | `net` also carries `peer_cred()`, which is how the same-UID check is made — no separate crate needed for `SO_PEERCRED`. |
| `rustix` | 1.1 | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` | Maintained, no advisories, and avoids a bare `libc` unsafe block for the two calls that must happen before the first secret is read. |
| `serde`, `serde_json` | 1 | The NDJSON control channel on stdin/stdout | The format the panel already speaks. |

That is 63 crates in the runtime graph. `cargo test --locked`, `cargo build
--locked`, `cargo fmt --check`, and `cargo clippy --all-targets -D warnings`
all pass on `x86_64-unknown-linux-gnu` with no vault, no network, and no
socket involved.

### Ed25519 secret memory needs a feature `ssh-key` does not ask for

The spike's pass/fail criterion was whether private components can be erased
on drop. For the representations `ssh-key` owns, they are: `Ed25519PrivateKey`
and `RsaPrivateKey` both zeroize their fields in `Drop`, and `Mpint` zeroizes
its backing `Vec`.

The gap is one level down. `ssh-key` builds a transient
`ed25519_dalek::SigningKey` for each Ed25519 signature, and it depends on
`ed25519-dalek` with `default-features = false` without requesting `zeroize`.
Dalek implements `ZeroizeOnDrop` for `SigningKey` only behind that feature, so
as `ssh-key` configures it, each signature leaves 32 secret bytes in freed
memory.

This crate therefore names `ed25519-dalek` as a direct dependency for that
feature alone. Cargo's feature unification turns the impl on for every copy in
the graph, including the ones `ssh-key` constructs. `rsa` needs no equivalent:
its `RsaPrivateKey` zeroizes unconditionally, and it enables `num-bigint-dig`'s
`zeroize` feature itself.

Because this property comes from feature resolution rather than from anything
visible in this crate's source, it is asserted at compile time —
`assert_zeroize_on_drop::<T>()` in `src/lib.rs`, called on both types in a
test. Removing the dalek dependency does not weaken the build quietly; it
stops it.

Declaring a dependency to enable one of its features is a normal use of Cargo's
feature unification: it changes configuration, not code. Bitwarden's desktop
agent solves the same problem far more heavily, with a `secure_memory` crate
that keeps key material in `memsec` locked allocations, encrypted under AES-GCM
with the key held in the Linux kernel keyring (DPAPI on Windows) and decrypted
only for use. That is a stronger guarantee and a much larger surface; it is
worth revisiting at Task 6 if the keystore review finds zeroize-on-drop
insufficient, not before.

### `ssh-key` 0.6.7 cannot sign with RSA at all

`ssh-key` 0.6.7's `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` passes
`key.private.p` twice where `from_components` expects `p` and `q`
(`ssh-key-0.6.7/src/private/rsa.rs:192`). The resulting key fails validation,
so every RSA signature through `ssh-key` returns an opaque error. The fix is on
the project's master branch; it is not in any release. 0.6.7 is from October
2024 and the 0.7 line has been in release candidates since 2025 — rc.11 landed
in June 2026 — so there is no stable release with a working RSA path.

Three options: ship a release candidate of a security dependency, drop RSA from
v1, or construct the private key here. This crate constructs it here
(`rsa_keys::private_key`): a dozen lines against `rsa`'s stable API, no fork
and no `[patch]` section, deleted the day a fixed release exists. A test
asserts that `ssh-key`'s own RSA signing still fails, so the workaround cannot
outlive its reason without someone noticing.

The same module owns SHA-2 algorithm selection, which is needed regardless of
that bug: `ssh-key`'s `Signer` impl for RSA hardcodes SHA-512, while
`rsa-sha2-256` and `rsa-sha2-512` are distinct signature algorithms chosen by
flags on the sign request. Answering with the wrong one is a failed
authentication, not a fallback.

Nothing here is a modified, forked, vendored, or pre-release dependency. Both
crates are current stable releases from crates.io, and `rsa_keys::private_key`
is ordinary code in this crate calling `rsa::RsaPrivateKey::from_components` —
the same public API `ssh-key` calls internally, with `q` where `ssh-key`
repeats `p`.

#### Why not let ssh-key build the key, as Bitwarden does

Bitwarden's own desktop agent (`apps/desktop/desktop_native/ssh_agent`, the v2
rebuild that replaced the deprecated `bitwarden-russh` fork) reaches the same
two conclusions this decision does: it pins `ssh-key` at exactly 0.6.7 with no
`[patch]` section, implements the agent protocol itself rather than taking a
protocol crate, and depends on `rsa` directly to build the SHA-256 signing key
`ssh-key` cannot produce.

Where it differs is that it lets `ssh-key` perform the keypair conversion, and
that works only because its lockfile pins `rsa` **0.9.6**. In 0.9.6,
`from_components` validates only when it had to recover the primes itself, so a
key with `p` supplied twice is accepted. Verified against both releases: on
0.9.6 the resulting key holds two identical primes, CRT precomputation fails
silently, `validate()` returns `InvalidModulus`, and signatures still verify
because signing falls back to the plain `d`/`n` path. From 0.9.7 onward
validation is unconditional and the same call returns an error — which in
Bitwarden's `sign_rsa` is an `.expect()`.

So the alternative to `rsa_keys` is to pin an older `rsa` and sign with a
private key that fails its own `validate()`. This crate would rather hold a
correct key on the current release.

### The agent protocol is implemented here, not taken from a crate

`ssh-agent-lib` 0.6.0 (May 2026) is maintained and well used, and it was the
obvious candidate. Its framing codec does not bound the frame length: it reads
a `u32` and waits for that many bytes, returning `Ok(None)` until they arrive
(`ssh-agent-lib-0.6.0/src/codec.rs`). A same-UID client can therefore make the
agent buffer toward 4 GiB, which is the opposite of this design's requirement
that frames over 256 KiB be rejected outright.

Its `Session` trait also spans the whole message set, while this agent
answers exactly two requests and refuses everything else, and it wraps the
listener in a way that puts `SO_PEERCRED` and the approval gate further from
the accept path than a security review wants them.

So Task 5 implements an allowlisted decoder directly on `ssh-encoding`, as
`tasks/todo.md` already assumed. RFC 9987 (Standards Track, May 2026) is now
the normative reference for the wire format, which is a better position than
this project would have been in a year ago. `ssh-agent-lib` remains a useful
cross-check for message encoding during Task 5.

`bitwarden-russh` is confirmed deprecated by its own README, and Bitwarden's
v2 agent is an in-progress rebuild that has itself moved to upstream crates
plus a hand-written protocol layer. Neither is a dependency here, and nothing
in this decision depends on when v2 lands.

### RSA timing: RUSTSEC-2023-0071 is present and unpatched

`rsa` 0.9.10 is affected by the Marvin attack advisory (medium, no patched
version, constant-time work still in progress upstream). It is the only
advisory that applies to this tree; `curve25519-dalek` (RUSTSEC-2024-0344),
`ed25519-dalek` (RUSTSEC-2022-0093), `tokio` (RUSTSEC-2025-0023), and `sha2`
(RUSTSEC-2021-0100) are all patched at the pinned versions.

It is accepted for v1, for reasons that should be stated plainly rather than
waved through:

- The advisory describes key recovery from timing measurements of many private
  key operations. The attacker in this design is a local process running as the
  same UID, which the threat model already treats as able to read the panel's
  `bw` child and its decrypted vault directly. It does not need a timing oracle.
- Every signature requires a live human approval or an unexpired process grant,
  and at most four sign requests exist at a time. That is not a rate an
  adaptive timing attack can work with.
- The alternative backends are worse trades: `rsa` 0.10 is a release candidate,
  and binding OpenSSL or `ring` for RSA-only signing adds a native build and a
  larger attack surface than the advisory it would retire.

This is recorded so it is reviewed again rather than inherited silently: if
`rsa` publishes a constant-time release, take it. Ed25519 keys — what most
Bitwarden SSH items will be — are not affected either way.

### Public-key file export moves to the panel

`docs/ideas/ssh-agent.md` planned for the companion to own the `.pub` file
projection from its validated keystore, and the plan asked this task to
confirm or correct that. It is corrected: the **panel** writes the files, from
the validated public set the companion reports over the control channel.

The companion is deliberately a process with no `PATH`, no `HOME`, no vault
credentials, and no children. Giving it a writable directory adds filesystem
surface to the one process holding private keys, to write data that is not
secret. The panel, by contrast, already writes files, already knows
`XDG_DATA_HOME`, and already has the hostile-filename sanitizer the attachment
path uses — which is the part of this that is actually delicate, since an item
name is decrypted vault content about to become a path. Duplicating that
sanitizer in Rust to serve a non-secret projection is the wrong division of
labour.

The companion stays authoritative about *which* keys are valid; the panel only
writes down what it is told. Task 15 implements it on that basis.

## Consequences

- `agent/rust-toolchain.toml` pins 1.98.0 with `rustfmt` and `clippy`. A distro
  cargo ignores that file, so the reproducible build (Task 16) must run under
  rustup in a pinned container and compare bytes — the toolchain is part of the
  artifact, not a local preference.
- `panic = "abort"` and `strip = "symbols"` in the release profile: a
  key-holding process should not unwind through arbitrary `Drop` impls or ship
  symbols. CI keeps debug symbols as a separate artifact if they are ever
  needed.
- Two workarounds are load-bearing and both are pinned by tests: the dalek
  `zeroize` feature and `rsa_keys`. Neither can be removed silently.
- The licence set is MIT/Apache-2.0 plus BSD-3-Clause (`ed25519-dalek`,
  `curve25519-dalek`, `subtle`) and BSD-2-Clause/Unlicense options elsewhere.
  All are compatible with this plugin's MIT licence; the release must ship the
  attribution notices (Task 19).
- `cargo-deny` (Task 16) gets an explicit allowlist for those licences and an
  exception entry for RUSTSEC-2023-0071 with a link back to this decision, so
  the advisory has to be re-approved rather than ignored.

## Verification

```bash
cargo test  --manifest-path agent/Cargo.toml --locked
cargo build --manifest-path agent/Cargo.toml --locked
cargo fmt   --manifest-path agent/Cargo.toml --check
cargo clippy --manifest-path agent/Cargo.toml --locked --all-targets -- -D warnings
```

## Sources

- [crates.io: ssh-key](https://crates.io/crates/ssh-key), [ssh-agent-lib](https://crates.io/crates/ssh-agent-lib), [rsa](https://crates.io/crates/rsa), [tokio](https://crates.io/crates/tokio), [rustix](https://crates.io/crates/rustix)
- [RustCrypto/SSH `ssh-key/src/private/rsa.rs` on master](https://github.com/RustCrypto/SSH/blob/master/ssh-key/src/private/rsa.rs) — the released 0.6.7 source in the local registry is the other half of that comparison
- [wiktor-k/ssh-agent-lib `src/codec.rs`](https://github.com/wiktor-k/ssh-agent-lib/blob/main/src/codec.rs)
- [RFC 9987: Secure Shell (SSH) Agent Protocol](https://www.rfc-editor.org/rfc/rfc9987.html)
- [bitwarden/bitwarden-russh](https://github.com/bitwarden/bitwarden-russh) — deprecation notice
- [bitwarden/clients `apps/desktop/desktop_native/ssh_agent`](https://github.com/bitwarden/clients/tree/main/apps/desktop/desktop_native/ssh_agent), and the `rsa` 0.9.6 pin in its `Cargo.lock`
- [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html), [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html), [RUSTSEC-2025-0023](https://rustsec.org/advisories/RUSTSEC-2025-0023.html)
