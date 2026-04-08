# Security Audit TODO

Findings from internal security audit. Ordered by severity.

---

## Critical

- [ ] **Non-constant-time MAC/token comparison** — replace `==` on `String` with `subtle::ConstantTimeEq` in `verify_invite_mac`, `verify_key_mac` (`lib/src/crypto.rs:269,303`) and the agent token check (`cli/src/agent.rs:358`)

- [ ] **Key material not zeroized or mlock'd** — wrap all `[u8; 32]` DEKs and private keys in `secrecy::Secret` or `zeroize::Zeroizing`; call `mlock` on sensitive buffers in the agent's in-memory store (`cli/src/agent.rs:297`) and the `Session` struct (`lib/src/store.rs:172`)

---

## High

- [ ] **Invite token embeds storage credentials in cleartext** — the `InvitePayload` JSON (base64-encoded, trivially decodable) carries full S3/GitHub/R2 credentials (`lib/src/invite.rs:26`); consider separating the storage credential grant from the invite token or encrypting the credential section

- [ ] **Manual join: no key integrity guarantee** — joining via "configure storage manually" (action == 2 in `cli/src/commands/setup.rs:111`) produces no invite MAC and no nonce; a storage-level adversary can swap the pending member's public key before it is granted; add a side-channel verification step (e.g., display a key fingerprint the joiner must confirm out-of-band)

- [ ] **Old-format token downgrade** — tokens without `token_signature` / `inviter_signing_key` silently bypass both signature verification and the genesis trust anchor check (`lib/src/invite.rs:122`, `lib/src/invite.rs:99`); enforce a minimum token version or reject unsigned tokens with an explicit error

- [ ] **Pending members excluded from signed document** — `canonical_document_bytes` filters out pending members (`lib/src/crypto.rs:348`), so their public keys have no cryptographic binding to the signed document; an adversary with storage write access can tamper with pending member records without invalidating any signature

---

## Medium

- [ ] **Private key sent as hex string over TCP** — the agent protocol sends the 32-byte private key as a JSON hex string over a TCP socket (`cli/src/agent.rs:200`); replace with a Unix domain socket (with restrictive file permissions) to reduce attack surface and eliminate the risk of the key passing through kernel TCP buffers

- [ ] **Storage credentials in plaintext config JSON** — `write_config` stores S3/GitHub/R2 keys in a 0o600 JSON file (`lib/src/config.rs:36`); prefer the OS keychain (macOS Keychain, libsecret, Windows Credential Manager) for credential storage

- [ ] **`--dry-run` leaks secret values to stdout** — `envi exec --dry-run` prints plaintext secret values (`cli/src/commands/exec.rs:97`), which get captured in CI logs; redact values by default and add a `--reveal` flag to opt into showing them

---

## Low

- [ ] **`ttyname(3)` not thread-safe** — `get_tty()` calls `libc::ttyname()` which returns a pointer to a static buffer; replace with `ttyname_r` (reentrant variant) to avoid data races in a multi-threaded Tokio runtime (`cli/src/agent.rs:18`)

- [ ] **Weak passphrase strength check** — the 12-char + character-class check (`cli/src/passphrase.rs:49`) allows low-entropy passphrases like `Password1!`; replace with an entropy estimator (e.g., `zxcvbn`) and set a minimum entropy threshold
