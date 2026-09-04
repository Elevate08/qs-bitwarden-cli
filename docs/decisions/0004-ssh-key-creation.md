# 4. SSH key creation stays out of the plugin, on private-key grounds

Date: 2026-09-03

## Status

Accepted. Confirms two entries in `docs/ideas/ssh-agent.md` ("Not Doing
Initially") — *Key generation or import* and *SSH item creation, editing, or
cloning in QML* — and replaces the reason recorded for one of them.

## Context

The question keeps coming back: the panel lists SSH keys, serves them to `ssh`
and Git, and can create every other item type. Why not create one?

The design deferred it twice, and the second entry gives a reason that is worth
re-reading:

> **SSH item creation, editing, or cloning in QML**: the CLI edit contract
> round-trips the complete cipher, so these need an opaque metadata-patch design
> that never exposes the existing private key to QML.

That reason is correct about **editing** and does not apply to **creation**.
`buildEditPayload` starts from a deep clone of `rawObject`, so editing a type-5
item would put the stored private key in QML. A key being created has no stored
private material to expose — whatever it holds, this plugin generated a moment
ago. The two cases were filed together and are not the same case.

So creation was re-examined on its own.

### What the CLI can actually do

The obvious first question was whether the vault boundary this plugin refuses to
cross can write a type-5 item at all. The first evidence said no:

```
$ bw get template item.sshKey
Unknown template object.
```

and the CLI's own template switch (`@bitwarden/cli` 2026.2.0, `build/bw.js`)
confirms the gap is deliberate — it has cases for `item.card`, `item.field`,
`item.identity`, `item.login`, `item.login.uri` and `item.securenote`, and no
case for `item.sshKey`.

That reading was wrong, and it is recorded here because it is the wrong
conclusion a reader is most likely to reach independently. The base item
template carries the field:

```
$ bw get template item
{... "card":null,"identity":null,"sshKey":null,"reprompt":0}
```

and the encrypt path — the one a create actually goes through — handles the
type in full:

```js
case CipherType.SshKey:
    cipher.sshKey = new SshKey();
    yield this.encryptObjProperty(model.sshKey, cipher.sshKey,
        { privateKey: null, publicKey: null, keyFingerprint: null }, key);
    return;
```

**The CLI can encrypt and create a type-5 item.** The missing template is a
convenience gap, not a capability gap, and a hand-built payload carrying
`privateKey`, `publicKey` and `keyFingerprint` is very likely to be accepted.
This decision therefore cannot rest on "the CLI will not let us", because it
will.

## Decision

The plugin does not create SSH keys. The reason is private-key custody, not CLI
capability.

Every design that puts a new key in the vault has to answer where the private
key is generated and what it touches on the way. There are two candidates and
each one gives up a property the SSH work was built around.

**Generate in the helper.** It already holds private keys, in memory, never on
disk — that is the entire point of it being a separate process. But it has no
random-number generator, and that is deliberate. `rand_core` is a
dev-dependency, commented *"Test-only key generation, so no private key material
is committed"*, and `selftest.rs` explains the refusal directly:

> the only honest ways to get one are to generate it — which would put a
> random-number generator into a key-holding binary's dependency tree for the
> sake of a smoke test — or to embed one, which is exactly what this project
> refuses to do anywhere else.

Reversing that means a new release dependency in the audited supply chain, a
rebuilt binary, new committed bytes, a new `SHA256SUMS`, and a fresh provenance
attestation. `/agent/` and `/bin/` are CODEOWNERS-flagged for precisely this
class of change. It is not prohibitive — but it is a supply-chain decision, not
a feature decision, and it should be taken as one.

**Generate with `ssh-keygen`.** No helper change, no new dependency. It writes
the private key to disk, and "never on disk" is a property this feature states
plainly. A FIFO does not rescue it: `ssh-keygen` wants to write two real files.

**And either way**, the private key must reach `bw` through the panel's
`QSBW_ITEM` environment payload. That route is already trusted with passwords,
so it is not new machinery — but it is new for SSH private keys, which this
design has kept exclusively inside the helper, and it would mean QML briefly
holds the one class of secret it has never held.

None of that is unsolvable. It is a security design with a threat model to
revisit, and it does not belong in a release that is about card items and a
settings screen.

## Consequences

**Users create SSH keys in the web vault or the browser extension**, where the
feature shipped in 2025.1.0. The panel lists, serves and signs with them the
moment they exist. This is a gap in convenience, not in function.

**The type-5 read-only guards stay.** `createItemCommand`, `editItemCommand`,
`deleteItemCommand`, `buildCreatePayload`, `buildEditPayload` and
`startEditItem` all refuse type 5, and the sanitizing filter continues to reduce
type-5 items to public metadata before QML sees them. Those guards now have a
decision behind them rather than an unexamined default.

**A hazard for anyone tempted to test this quickly.** Confirming the create path
empirically means writing a real type-5 item, and the failure mode is not
symmetric. Bitwarden CLI below `2026.8.0` fails to decrypt SSH key items with a
null public key or fingerprint, and *one such item breaks the entire vault
list* — in this plugin and in every other client on that CLI, until the item is
removed. A malformed write is therefore not a harmless experiment on a vault
someone depends on. Test against a throwaway account or a local Vaultwarden.

**If this is revisited**, helper-side generation is the design to start from.
The dependency cost is real and reviewable; the alternative trades away two
properties — private keys never on disk, private keys never in QML — that are
harder to win back than a line in `Cargo.toml`.

## Alternatives considered

- **Import an existing key rather than generate one.** Avoids the RNG question
  entirely, and the user already has the private key in a file. It still routes
  private material through QML and `bw`, so it clears the smaller obstacle and
  leaves the larger one, and it is a strictly less useful feature.
- **Create the item with only public material and fill the private key in
  later.** This is the malformed-item shape named above. It would break vault
  listing for every client on a CLI below 2026.8.0.
- **Have the helper write the item to `bw` itself**, keeping the private key out
  of QML entirely. The most promising variant, and the one worth designing if
  this is picked up: it would need the helper to hold a session token, which is
  a widening of its role from "signs with keys it was given" to "acts on the
  vault", and that deserves its own review.
- **Wait for a CLI template.** The absence of `item.sshKey` suggests Bitwarden
  does not consider CLI creation a supported path yet. Waiting costs nothing and
  may produce a supported shape to build against.
