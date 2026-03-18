# Envisible [envi]

[![CI](https://github.com/bloccooo/envisible/actions/workflows/ci.yml/badge.svg)](https://github.com/bloccooo/envisible/actions/workflows/ci.yml)

A serverless secret manager for teams. Secrets are stored encrypted in a storage backend of your choice (S3, R2, WebDAV, or local) and synced across team members using a [CRDT](https://automerge.org) — no central server, no shared master password, no trust in the storage provider.

Also designed for the agentic era: credentials are scoped per terminal session, injected only into explicitly declared processes, and never accessible to tools running in other terminals — protecting against prompt injection attacks and curious agents.

## Install

```sh
curl -fsSL https://blocco.studio/envi/install.sh | bash
```

Supports macOS (Apple Silicon & Intel) and Linux (x64). Installs to `/usr/local/bin/envi`.

## Encryption

Secrets are encrypted with AES-256-GCM using a shared workspace key (DEK). Each member holds their own copy of the DEK, wrapped with a personal X25519 key pair derived from their passphrase, workspace ID, and a random member ID via Argon2id. The passphrase never leaves the device.

Each member maintains their own Automerge document, signed with an Ed25519 key before upload. Peers reject unsigned or tampered files before merging. Member keys are authenticated with an HMAC-SHA256 keyed by the DEK, so any DEK holder can detect if a member's keys were replaced at the storage layer.

### Invite flow

**Generating the token (inviter)**

A random 16-byte nonce is used to deterministically derive an ephemeral X25519 keypair via HKDF from the inviter's private key:

```
invite_priv = HKDF(inviter_x25519_priv, salt=nonce, info="bkey-invite-v1")
invite_pub  = X25519_pubkey(invite_priv)
```

The token contains `invite_pub`, the inviter's member ID, the nonce, and the inviter's Ed25519 verifying key. The entire payload is then signed with the inviter's Ed25519 private key:

```
token_signature = Ed25519_sign(inviter_signing_priv, JSON(payload))
```

Nothing is stored locally — the invite private key can always be re-derived from the inviter's session key and the nonce.

**Joining (invitee)**

On receiving the token, the invitee first verifies `token_signature` against `inviter_signing_key`. This proves the token was produced by the holder of that key and has not been tampered with.

The invitee then fetches the workspace document and checks that `members[inviter_id].signing_key` matches `inviter_signing_key` from the token. This proves the key belongs to a real, existing member of the workspace — an attacker controlling rogue storage cannot satisfy this check without holding the inviter's private key.

Finally, the invitee derives their own keypair from their passphrase, performs an X25519 key exchange with `invite_pub` to derive a shared secret, and computes:

```
invite_mac = HMAC-SHA256(shared_secret, member_id || ":" || public_key || ":" || signing_key)
```

This MAC and the nonce are stored in their pending member record.

**Granting access (inviter)**

When the inviter reviews the pending request, they re-derive `invite_priv` from the nonce (using their session key — nothing was stored locally), recompute the shared secret via ECDH, and verify the MAC — confirming that the public key in the record is exactly the one the invitee registered, and was not swapped in storage by an attacker.

## Commands

### `envi setup`

Create a new workspace or join an existing one via an invite link.

```sh
envi setup                     # create workspace
envi setup envi-invite:<token> # join workspace
```

### `envi`

Open the terminal UI to manage secrets, namespaces, and members.

```sh
envi
```

**Key bindings:**

| Key   | Action                                     |
| ----- | ------------------------------------------ |
| `n`   | New item                                   |
| `e`   | Edit selected                              |
| `d`   | Delete selected                            |
| `s`   | Manage namespace secrets (namespaces pane) |
| `g`   | Grant access to member (members pane)      |
| `i`   | Generate invite link (members pane)        |
| `v`   | Toggle value visibility                    |
| `Tab` | Switch pane                                |
| `q`   | Quit                                       |

### `envi exec`

Inject secrets as environment variables into a command.

```sh
envi exec -- node server.js
envi exec --namespace myapp -- node server.js
envi exec --namespace myapp --dry-run
```

A `.envi` file in the project root can specify the default namespace:

```
namespace = "myapp"
```

### `envi sync`

Pull the latest state from the storage backend and push local changes.

```sh
envi sync
```

### `envi logout`

Stop the key agent and clear cached credentials from RAM. The next command will prompt for the passphrase again.

Credentials are scoped per terminal session (TTY), so logging out in one terminal only affects that terminal. Other open terminals retain their cached credentials. TTY scoping also limits the blast radius of prompt injection attacks — a process running in a different terminal (e.g. an AI agent) cannot reuse credentials unlocked in your interactive session.

```sh
envi logout
```

### `envi clear`

Remove all local data: stop the agent, delete the local cache, and remove the config from the OS keychain. Use this to fully reset the installation.

```sh
envi clear
```

## Security roadmap

The current implementation uses sound cryptographic primitives (AES-256-GCM, X25519/ECIES, Argon2id) but currently has known limitations.

**Known bugs:**

- **Member name impersonation** — member names are self-declared and not verified. Nothing prevents two members from registering with the same display name, or a malicious joiner from choosing a name that mimics a legitimate member. Fixed by requiring the inviting member to countersign new members (see below).

**Planned hardening, roughly in priority order:**

- ~~**Remove passphrase persistence**~~ — done. The passphrase is never written to disk; the derived key is held only in RAM by a short-lived background agent and cleared on `envi logout`.
- ~~**Password reuse across members**~~ — fixed. Private keys are now derived from `(passphrase, workspace_id, member_id)` where `member_id` is a random UUID generated at setup. Key material is bound to a specific member identity, so knowing another member's passphrase is not sufficient to derive their key.
- ~~**Authenticated CRDT documents**~~ — done. Each member's Automerge document is signed with an Ed25519 key before being pushed to storage. All files must be signed — unsigned files are rejected. Pending members are excluded from the canonical bytes so a new member registering their public key does not invalidate the existing signature. Member public and signing keys are protected by a per-member HMAC-SHA256 keyed by the shared DEK, so key substitution is detectable by any DEK holder.
- ~~**Genesis trust anchor**~~ — done. The invite token now embeds the inviter's Ed25519 verifying key. On first pull, the invitee checks that the inviter's entry in the fetched document carries the same signing key as the token. Since the token is shared over a trusted channel, this pins the inviter's identity and detects a forged or swapped document before the invitee registers.
- ~~**Member identity verification**~~ — done. The invite flow now uses an X25519 key exchange between the inviter's derived ephemeral key and the invitee's public key to produce a shared secret that neither party needs to transmit. The invitee computes an HMAC over their own public and signing keys; the inviter re-derives the shared secret on review and verifies the MAC, detecting any key substitution at the storage layer.
- **Single-use, expiring invite links** — invite links currently have no expiry and can be reused indefinitely. Each link already carries a unique nonce (binding it to a specific ephemeral key), but a future version will add explicit expiry and enforce single-use so that replayed or leaked links cannot register new members.
- **Scoped secret injection** — `envi exec` will require secrets to be explicitly declared (e.g. in the `.envi` file) rather than injecting the full workspace vault, limiting the blast radius of prompt-injection attacks against AI agents.

## Building from source

Requires Rust (stable).

```sh
cargo build --release
```
