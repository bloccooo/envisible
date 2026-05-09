# Security Review: `envisible`

**Reviewer role:** Senior Rust / applied cryptography  
**Codebase version:** 0.0.39  
**Date:** 2026-05-09  
**Scope:** Full codebase — cryptographic design, protocol correctness, key management, secrets handling, inter-process communication, and operational security

---

## Methodology

This review examines every layer where secrets or keys are handled: key derivation, encryption, signing, the invite protocol, the agent IPC protocol, secret injection into subprocesses, and storage of credentials on disk. Findings are classified by exploitability and impact, not theoretical severity alone.

---

## Severity Scale

| Rating | Meaning |
|--------|---------|
| **Critical** | Directly enables an attacker to recover plaintext secrets or private keys with no prior access |
| **High** | Enables a realistic attack under a defined threat model (e.g., local user, network attacker, compromised storage backend) |
| **Medium** | Weakens a defense-in-depth assumption or requires user interaction/coincidence to exploit |
| **Low** | Best-practice deviation; no known practical exploit path |
| **Info** | Design note; awareness only |

---

## Finding 1 — Invite Token Embeds Storage Credentials in Cleartext

**Severity: Critical**  
**File:** `lib/src/invite.rs:70–88`, `lib/src/storage.rs:9–57`

### Description

`generate_invite` serializes the full `StorageConfig` into the invite payload before base64-encoding it:

```rust
// invite.rs:70–78
let payload = InvitePayload {
    vault,
    storage: storage.clone(),   // <── S3/R2 keys, GitHub PATs, WebDAV passwords
    invite_pub: Some(B64.encode(invite_pub)),
    inviter_id: Some(inviter_id.to_string()),
    nonce: Some(B64.encode(nonce_bytes)),
    inviter_signing_key: Some(inviter_signing_key),
    token_signature: None,
};
let unsigned_json = serde_json::to_string(&payload)?;
// ...
let b64 = B64URL.encode(json.as_bytes());
Ok(format!("{INVITE_PREFIX}{b64}"))
```

The output is a base64 string that any reader can decode to recover the exact S3/R2 access keys, GitHub personal access token, or WebDAV password embedded verbatim in the JSON.

**`StorageConfig` fields exposed verbatim:**

| Backend | Fields in token |
|---------|----------------|
| S3 | `access_key_id`, `secret_access_key`, `bucket`, `region` |
| R2 | `account_id`, `access_key_id`, `secret_access_key`, `bucket` |
| GitHub | `token` (PAT with repo write scope) |
| WebDAV | `username`, `password`, `endpoint` |

The invite token is typically shared via chat, email, or QR code — all channels that may be logged, cached, or visible to third parties. Anyone who intercepts or reads the token gains:

1. Full read/write access to the storage backend (they can download all vault files or upload corrupted ones)
2. Persistence: the storage credentials do not rotate when a new invite is generated; the leaked credentials remain valid indefinitely until manually rotated in the storage backend

**Note:** The cryptographic security of secrets (AES-256-GCM + per-member DEK) means intercepting the storage files alone is not sufficient to read secrets — the passphrase is still required. However, storage write access allows an attacker to:
- Delete vault files (denial of service)
- Upload a forged document — though document signatures would catch tampering if the invitee re-verifies after joining
- Enumerate all vaults and members in the account
- Exhaust storage quotas

### Fix

Remove storage credentials from invite tokens entirely. The invitee should configure storage credentials separately. The invite token needs to carry only the data required to complete the join protocol:

```rust
// Reduced InvitePayload — no storage credentials
pub struct InvitePayload {
    pub vault: VaultPayload,              // id + name only
    pub invite_pub: Option<String>,       // ephemeral pub key for MAC
    pub inviter_id: Option<String>,
    pub nonce: Option<String>,
    pub inviter_signing_key: Option<String>,
    pub token_signature: Option<String>,
}
```

The join flow would then prompt the new member to configure their own storage credentials (the existing "Join via manual storage config" path already does this). Alternatively, encrypt the storage credential block asymmetrically to the invitee's public key — but that requires a prior key exchange, so the cleaner path is to separate them.

---

## Finding 2 — Private Key Transmitted in Cleartext Over TCP

**Severity: High**  
**File:** `cli/src/agent.rs:200–207`, `cli/src/agent.rs:380–395`

### Description

The key agent stores the raw X25519 private key (32 bytes) in memory and transfers it between client and server as a hex string over a plain TCP connection:

```rust
// agent.rs:200–207 (client: store)
pub fn store_key(&self, vault_id: &str, key: &[u8; 32]) {
    let _ = self.request(&Request::StoreKey {
        token: self.token.clone(),
        vault_id: vault_id.to_string(),
        session_id: get_tty(),
        key: hex::encode(key),   // ← raw private key as hex in JSON over TCP
    });
}

// agent.rs:187–197 (client: get)
pub fn get_key(&self, vault_id: &str) -> Option<[u8; 32]> {
    let resp = self.request(&Request::GetKey { ... })?;
    let bytes = hex::decode(resp.key?).ok()?;
    bytes.try_into().ok()
}
```

The key is the root of all security: from it, `derive_signing_key` (Ed25519) and the X25519 scalar (for DEK unwrapping) are both derived. Any process able to observe the TCP stream between client and agent recovers the complete private key.

Although the server binds only to `127.0.0.1`, on Linux loopback traffic is accessible to root and to any process using raw sockets with `CAP_NET_RAW`. On macOS, local TCP connections are also visible to system-level monitoring (Activity Monitor, `tcpdump lo0`, DTrace, etc.). The `agent.json` token at mode `0o600` limits who can initiate a connection, but it does not protect the key in transit.

Additionally, the private key passes through several unprotected memory regions: the tokio async read buffer, the `String` returned by `serde_json`, the `hex::decode` output `Vec<u8>`, and the `TcpStream` kernel buffer — none of which use locked (`mlock`) or zeroized memory.

### Fix

Replace TCP with a Unix domain socket. A Unix socket file at mode `0o600` in a directory only the user can traverse (`~/.cache/envi/`, which is already 0o700 on most systems) provides kernel-enforced access control without any network stack:

```rust
// Use tokio::net::UnixListener instead of TcpListener
use tokio::net::UnixListener;
let socket_path = cache_dir().join("agent.sock");
let listener = UnixListener::bind(&socket_path)?;
std::fs::set_permissions(&socket_path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
```

The `agent.json` file would then store the socket path instead of a TCP address and token:

```json
{ "socket": "/Users/you/Library/Caches/envi/agent.sock" }
```

The socket file's `0o600` permission IS the authentication — no token is needed. This also eliminates the port-scanning attack surface entirely. On Windows, use a named pipe.

---

## Finding 3 — MAC Comparisons Are Not Constant-Time

**Severity: High**  
**Files:** `lib/src/crypto.rs:298–308`, `lib/src/crypto.rs:259–270`

### Description

Both MAC verification functions use Rust's `==` operator to compare Base64 strings:

```rust
// crypto.rs:298–308
pub fn verify_key_mac(..., mac_b64: &str) -> Result<()> {
    let expected = compute_key_mac(...);
    if expected == mac_b64 {   // ← not constant-time
        Ok(())
    } else {
        Err(Error::InvalidKeyMac(member_id.to_string()))
    }
}

// crypto.rs:259–270
pub fn verify_invite_mac(...) -> Result<()> {
    let expected = compute_invite_mac(...)?;
    if expected == mac_b64 {   // ← not constant-time
        Ok(())
    } else {
        Err(Error::InvalidInviteMac(member_id.to_string()))
    }
}
```

`str::eq` in Rust compares byte by byte and returns `false` on the first mismatch. A sufficiently precise timing adversary can brute-force the expected MAC one character at a time by measuring response latency.

**Exploitability note:** `verify_key_mac` takes the DEK as input, so an attacker must already hold the DEK to mount a timing attack. This makes it self-defeating for `key_mac`. However, `verify_invite_mac` is called during the grant flow with the invite ECDH shared secret — if an attacker can submit crafted `invite_mac` values and measure whether verification passes or fails fast/slow, they could theoretically recover the shared secret one byte at a time. The attack is mitigated in practice by the fact that the ECDH shared secret is unknown to the attacker, and the latency jitter in a TUI app is orders of magnitude larger than a single byte comparison — but this should still be fixed.

### Fix

Use `subtle::ConstantTimeEq` for all MAC comparisons:

```toml
# lib/Cargo.toml
subtle = "2"
```

```rust
use subtle::ConstantTimeEq;

// In verify_key_mac and verify_invite_mac:
if expected.as_bytes().ct_eq(mac_b64.as_bytes()).into() {
    Ok(())
} else {
    Err(...)
}
```

Alternatively, use `hmac`'s built-in `verify_slice` method, which is already constant-time:

```rust
let mut mac = HmacSha256::new_from_slice(dek)?;
mac.update(...);
mac.verify_slice(&B64.decode(mac_b64)?)
    .map_err(|_| Error::InvalidKeyMac(...))?;
```

---

## Finding 4 — Manual Join Path Bypasses Invite MAC Verification

**Severity: High**  
**File:** `cli/src/commands/setup.rs:216–234`

### Description

The codebase provides two join paths. The invite token path (action 1) computes an `invite_mac` that cryptographically binds the joiner's public key to the specific invite token, preventing key substitution attacks. The manual storage configuration path (action 2) sets no invite MAC at all:

```rust
// setup.rs:217–229
state.members.insert(
    config.member_id.clone(),
    lib::types::Member {
        id: config.member_id.clone(),
        email: config.member_name.clone(),
        public_key: public_key_b64,
        signing_key: signing_public_key,
        key_mac: String::new(),
        wrapped_dek: String::new(),
        invite_mac: String::new(),    // ← no binding
        invite_nonce: String::new(),  // ← no binding
    },
);
```

Any actor with read/write access to the storage backend (e.g., via the leaked credentials in Finding 1, or via a rogue employee with storage access) can inject a pending member record with an arbitrary public key. A legitimate member reviewing their TUI will see the pending member and has no cryptographic way to distinguish a legitimate joiner from an injected one. If they grant access, the attacker receives a wrapped DEK.

This attack requires:
1. Write access to the vault's storage prefix
2. Knowledge of the vault ID and member ID format (both predictable from the storage layout)
3. A legitimate member granting access to the injected pending record

The invite MAC flow was specifically designed to prevent this. The manual path re-opens the hole.

### Fix

Either remove the manual join path entirely (force all joins through invite tokens), or add an out-of-band fingerprint step. For the manual path, after a pending member is created, display the SHA-256 fingerprint of their public key and require a legitimate member to verbally confirm the fingerprint before granting access (similar to SSH host key verification). This can be implemented as a UI hint without protocol changes:

```rust
// In the grant UI: show the fingerprint of the pending member's public key
let pub_key_bytes = B64.decode(&pending_member.public_key)?;
let fingerprint = hex::encode(&sha2::Sha256::digest(&pub_key_bytes)[..8]);
// Display: "Pending member fingerprint: ab:cd:ef:01:23:45:67:89 — verify out-of-band before granting"
```

---

## Finding 5 — Agent Key Persists for 8 Hours With No Active Lock

**Severity: Medium**  
**File:** `cli/src/agent.rs:28`, `cli/src/agent.rs:303–313`

### Description

The agent caches the private key in memory for up to 8 hours of inactivity:

```rust
// agent.rs:28
const DEFAULT_TTL_SECS: u64 = 8 * 3600;
```

The TTL watchdog checks every 5 minutes, so the actual worst case is 8 hours and 5 minutes. The key is scoped to `(vault_id, tty_name)`, which prevents cross-terminal leakage — but if a user leaves their terminal session open and walks away, anyone with physical or remote access to that terminal can invoke `envi exec` or open the TUI and decrypt all secrets without entering a passphrase. This is the "unlocked laptop" threat model.

Additionally, the TTL resets on every agent interaction, meaning the key can persist indefinitely on a machine that is actively used — far beyond the 8-hour stated limit.

### Fix — Two Changes

**1. Honour a configurable timeout that does not reset on activity:**

```rust
// Track creation time, not last activity, for TTL enforcement
let created_at: Arc<Mutex<std::time::Instant>> =
    Arc::new(Mutex::new(std::time::Instant::now()));
```

**2. Expose a `lock` command:**

```sh
envi agent lock         # evict all cached keys immediately
envi agent lock --vault my-vault   # evict a specific vault's key
```

The recommended default TTL for a secrets manager is 15–30 minutes. Many users tolerate being prompted for a passphrase every half hour. 8 hours is in line with SSH agent defaults, which is an acceptable baseline, but the TTL should be prominently documented and user-configurable rather than hardcoded.

---

## Finding 6 — Argon2id Parameters Are Minimum-Viable for a Secrets Manager

**Severity: Medium**  
**File:** `lib/src/crypto.rs:25–36`

### Description

```rust
let params = Params::new(65536, 3, 1, Some(32))
//                       ^m=64MB  ^t=3  ^p=1
```

These parameters meet OWASP's 2023 baseline (m ≥ 19 MB, t ≥ 1 for Argon2id with 64 MB). However, for a secrets manager where key derivation happens only once at unlock time and there is no UX cost beyond ~1 second, the parameters should be at the upper end of what the target hardware can sustain, not at the lower bound of acceptability.

Adversary context: an attacker who steals the config file and a vault file sees the `member_id` (salt component) and the member's public key (the target). They can verify a passphrase guess by checking whether `derive_private_key(guess, vault_id, member_id)` produces the known public key. With current parameters on a modern GPU (A100), Argon2id at m=65536, t=3 achieves roughly 100–200 hashes/second per GPU. At m=262144 (256 MB), this drops to ~20–30 hashes/second per GPU.

For a team secrets manager where vaults contain credentials with high business value, an attacker is likely to invest GPU resources in offline cracking.

### Fix

Increase parameters to a level appropriate for a secrets manager while remaining sub-second on typical hardware:

```rust
// m = 256 MB, t = 4, p = 1 — approximately 600–800 ms on a modern laptop
let params = Params::new(262144, 4, 1, Some(32))
    .map_err(|e| Error::Other(e.to_string()))?;
```

Alternatively, expose the parameters in the vault config so they can be updated when devices improve. Adding a `kdf_version` field to `EnviDocument` would allow backward-compatible parameter upgrades.

---

## Finding 7 — No Passphrase Pepper

**Severity: Medium**  
**File:** `lib/src/crypto.rs:25–36`

### Description

The Argon2id key derivation uses no pepper — a secret value known only to the specific device that would need to be compromised in addition to the passphrase:

```rust
pub fn derive_private_key(passphrase: &str, vault_id: &str, member_id: &str) -> Result<[u8; 32]> {
    // salt = vault_id:member_id  (both stored in config.json — not secret)
    argon2.hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut output)?;
}
```

An attacker who steals `config.json` (for the salt) and any vault file (for the public key to verify guesses) can begin offline cracking immediately with no further local access required. Adding a pepper stored in the OS keychain (Keychain on macOS, Secret Service on Linux, DPAPI on Windows) would require the attacker to also compromise the device locally to begin cracking.

### Fix

Derive the pepper from the OS keychain, not from a file:

```rust
// lib/src/crypto.rs
pub fn derive_private_key_peppered(
    passphrase: &str,
    vault_id: &str,
    member_id: &str,
    pepper: &[u8],       // retrieved from OS keychain
) -> Result<[u8; 32]> {
    // Combined salt: hash(vault_id:member_id || pepper)
    let mut combined_salt = Vec::new();
    combined_salt.extend_from_slice(salt.as_bytes());
    combined_salt.extend_from_slice(pepper);
    argon2.hash_password_into(passphrase.as_bytes(), &combined_salt, &mut output)?;
}
```

On first vault creation/join, generate 32 random bytes and store them in the OS keychain under a key like `envi.pepper.<member_id>`. On subsequent unlocks, retrieve the pepper before calling Argon2id. This reduces the offline cracking surface to only attackers who have both the config/vault files AND local keychain access (which typically requires authentication anyway).

Recommended crate: `keyring = "2"`.

---

## Finding 8 — Passphrase Strength Validation Is Character-Class Based, Not Entropy-Based

**Severity: Medium**  
**File:** `cli/src/passphrase.rs:49–67`

### Description

```rust
fn check_strength(passphrase: &str) -> std::result::Result<(), &'static str> {
    if passphrase.len() < 12 {
        return Err("must be at least 12 characters");
    }
    let score = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();
    if score < 3 {
        return Err("must contain at least 3 of: lowercase, uppercase, digits, special characters");
    }
    Ok(())
}
```

`Password1!` passes this check (12 chars, lower + upper + digit + special = score 4) despite having approximately 40 bits of entropy. `correct horse battery staple` fails (no uppercase, no digit, no special) despite having ~44 bits of entropy and being significantly more memorable. The check actively discourages the highest-entropy passphrase format (long random words).

Given that the passphrase is the last defense against offline cracking (Finding 6), weak passphrases accepted by this check represent a meaningful risk.

### Fix

Use an entropy estimator (e.g., the `zxcvbn` crate, the Rust port of Dropbox's passphrase strength library):

```toml
# cli/Cargo.toml
zxcvbn = "3"
```

```rust
fn check_strength(passphrase: &str) -> Result<(), &'static str> {
    let estimate = zxcvbn::zxcvbn(passphrase, &[]);
    if estimate.score() < zxcvbn::Score::Three {
        return Err("passphrase is too weak — try a longer phrase or more randomness");
    }
    Ok(())
}
```

`zxcvbn` scores 0–4 and accounts for common patterns, dictionary words, keyboard walks, and repetition. Score 3 corresponds to approximately 10^10 guesses (sufficient for Argon2id with good parameters), score 4 to 10^14.

---

## Finding 9 — `exec` Exposes Secrets as Environment Variables

**Severity: Medium**  
**File:** `cli/src/commands/exec.rs:111–117`

### Description

```rust
let status = std::process::Command::new(&cmd[0])
    .args(&cmd[1..])
    .envs(std::env::vars())   // inherit ALL parent environment variables
    .envs(env_vars)           // then inject vault secrets
    .status()?;
```

Secrets injected as environment variables are:

1. **Visible in `/proc/<PID>/environ`** on Linux to any process running as the same user (and to root)
2. **Visible in `ps auxe`** on some systems
3. **Inherited by all child processes** of the invoked command — if the child calls a shell or spawns subprocesses, all secrets propagate further
4. **Not cleaned up on crash** — core dumps may contain environment variables
5. **Potentially logged** by process supervisors (systemd, launchd, Docker) that capture process metadata

Additionally, `.envs(std::env::vars())` passes the entire current environment to the child, including any secrets already in the parent's environment (e.g., `AWS_SECRET_ACCESS_KEY` from a prior `export`). This could cause unintended secrets to propagate.

This is the standard approach for secret injection (Docker, Heroku, AWS Lambda all use it) and has no clean alternative — but the risks should be documented and mitigated where possible.

### Fix

1. **Do not inherit the full parent environment unless necessary:**

```rust
// Only pass explicitly requested variables, not all parent env vars
let status = std::process::Command::new(&cmd[0])
    .args(&cmd[1..])
    .env_clear()              // start from empty environment
    .envs(minimal_env())      // add PATH, HOME, USER, etc. — not everything
    .envs(env_vars)           // inject vault secrets
    .status()?;

fn minimal_env() -> Vec<(&'static str, String)> {
    ["PATH", "HOME", "USER", "SHELL", "TERM", "LANG"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v)))
        .collect()
}
```

2. **On Linux, set the environment on the child process after fork and before exec using `/proc/self/fd` tricks or `prctl(PR_SET_DUMPABLE, 0)` to suppress core dumps.**

3. **Document in the README** that `envi exec` uses environment variables and link to the security implications.

---

## Finding 10 — `unsafe` TTY Name Lookup Is Not Thread-Safe

**Severity: Low**  
**File:** `cli/src/agent.rs:18–26`

### Description

```rust
fn get_tty() -> String {
    unsafe {
        let ptr = libc::ttyname(libc::STDIN_FILENO);
        if ptr.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}
```

`libc::ttyname()` is not thread-safe: it returns a pointer to a static internal buffer that may be overwritten by a concurrent call from another thread. In a multi-threaded async runtime (tokio), if two tasks call `get_tty()` concurrently, the second call may overwrite the buffer while the first is reading it — a data race that is undefined behavior in Rust.

In practice, `get_tty()` is only called from the main thread during `get_key` and `store_key` (before the TUI starts), so concurrent calls are unlikely today. But this is a latent unsafe that could trigger if the call sites move into async tasks.

### Fix

Use `libc::ttyname_r` (the thread-safe reentrant variant):

```rust
fn get_tty() -> String {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::ttyname_r(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut i8, buf.len()) };
    if ret != 0 {
        return String::new();
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8) };
    cstr.to_string_lossy().into_owned()
}
```

---

## Finding 11 — Agent Bearer Token Has No Replay Protection

**Severity: Low**  
**File:** `cli/src/agent.rs:287–295`, `cli/src/agent.rs:351–363`

### Description

Every agent request sends the same static bearer token in the JSON body:

```rust
Request::StoreKey { token: self.token.clone(), ... }
```

The token is generated once at agent start and never rotates. An attacker who observes a single request (e.g., via a loopback sniffer, process memory read, or log leak) has permanent access to the agent until it restarts. There is no nonce, timestamp, or HMAC over the request payload to prevent replay.

Combined with Finding 2 (plaintext TCP), a captured token + address allows an attacker to issue their own `GetKey` request and extract the cached private key.

### Fix (short-term)

If switching to Unix sockets (Finding 2), the socket permissions replace the need for a token entirely. The bearer token can be removed.

If TCP is kept for any reason, use HMAC-based request authentication with a per-request nonce:

```rust
struct AuthRequest {
    nonce: String,     // random, single-use
    timestamp: u64,    // Unix seconds
    hmac: String,      // HMAC-SHA256(shared_token, nonce || timestamp || request_body)
}
```

Reject requests with a timestamp older than 30 seconds and track seen nonces to prevent replay.

---

## Finding 12 — Config File Not Protected on Non-Unix Platforms

**Severity: Low**  
**Files:** `lib/src/config.rs:43–58`, `cli/src/agent.rs:52–64`

### Description

On Unix, both the config file and the agent file are created with mode `0o600`:

```rust
#[cfg(unix)]
{
    std::fs::OpenOptions::new()
        .mode(0o600)
        .open(&path)?
        .write_all(json.as_bytes())?;
}
#[cfg(not(unix))]
std::fs::write(&path, json)?;  // ← no permission restriction on Windows
```

On Windows, `std::fs::write` creates a file inheriting the parent directory's ACL, which may be readable by other users or processes depending on the system configuration. The config file contains storage credentials (S3 keys, GitHub tokens, etc.), making it a high-value target.

### Fix

On Windows, use the `windows-acl` or `winapi` crate to set a DACL restricting the file to the current user:

```rust
#[cfg(windows)]
fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_ATTRIBUTE_NORMAL + no inherit = user-only by default
    // Then set explicit DACL via windows-acl
    windows_acl::helper::grant_access(path, current_user_sid(), ...).ok();
    std::fs::write(path, data)
}
```

---

## Finding 13 — Dry-Run Mode Prints Secret Values to Terminal

**Severity: Low**  
**File:** `cli/src/commands/exec.rs:96–102`

### Description

```rust
if dry_run {
    for (k, v) in &env_vars {
        println!("  {k}={v}");   // plaintext values
    }
    return Ok(());
}
```

Secret values are printed to stdout in plaintext with no masking. These values:
- Remain in terminal scroll-back buffers indefinitely
- May be captured by terminal logging tools (`script`, `tmux` logging, IDE terminal history)
- May appear in CI/CD logs if `--dry-run` is used in a pipeline
- Are visible to shoulder-surfers

### Fix

Mask values by default and add a `--reveal` flag:

```rust
if dry_run {
    for (k, v) in &env_vars {
        if reveal {
            println!("  {k}={v}");
        } else {
            println!("  {k}=<hidden> ({} chars)", v.len());
        }
    }
}
```

---

## Finding 14 — `doc_version` Is Unused But Could Enable Downgrade Attacks

**Severity: Info**  
**File:** `lib/src/types.rs:13`

### Description

```rust
pub struct EnviDocument {
    pub doc_version: u64,  // currently unused in code
    ...
}
```

The field exists but is never read or incremented. If future code uses `doc_version` to gate features (e.g., "only verify signatures if doc_version >= 2"), an attacker who can write to storage could supply a document with `doc_version = 0` to downgrade the document to a lower-security protocol version.

### Fix

When `doc_version` is put into use: always treat it as a minimum floor — accept documents with a version equal to or higher than the expected version, never lower. Never branch on "version < X → skip security check."

---

## Finding 15 — Old Invite Tokens (Without Signature) Are Still Accepted

**Severity: Info**  
**File:** `lib/src/invite.rs:122–151`

### Description

```rust
// parse_invite — token_signature is optional
if let (Some(sig_b64), Some(verifying_key_b64)) =
    (&payload.token_signature, &payload.inviter_signing_key)
{
    // verify...
}
// If no token_signature: silently succeed
```

Invite tokens without a signature field are accepted without any cryptographic verification. The only protection for old-style tokens is the `verify_genesis_anchor` check (does the inviter's key in the token match the document?), but there is no proof the token was generated by the inviter rather than crafted by anyone with knowledge of the vault.

Additionally, `verify_genesis_anchor` itself silently skips if `inviter_signing_key` is absent:
```rust
let (Some(expected_key), Some(inviter_id)) =
    (&payload.inviter_signing_key, &payload.inviter_id)
else {
    return Ok(()); // old token — skip
};
```

This means old tokens bypass both checks entirely.

### Fix

If old token support is no longer needed, require `token_signature` and `inviter_signing_key` to be present:

```rust
let (sig_b64, verifying_key_b64) = match (&payload.token_signature, &payload.inviter_signing_key) {
    (Some(s), Some(k)) => (s, k),
    _ => return Err(Error::InvalidInviteLink),  // reject unsigned tokens
};
```

If backward compatibility must be maintained, at minimum log a prominent warning when an unsigned token is accepted.

---

## Positive Security Findings

The following aspects of the security design are well-implemented and worth preserving:

### Cryptographic Primitives Are Sound

All selected primitives are modern and appropriately sized:
- **X25519 + HKDF-SHA256 + AES-256-GCM** for DEK wrapping (ECIES construction)
- **Argon2id** for passphrase-to-key derivation (correct algorithm for this use case)
- **Ed25519** for document signing with `verify_strict` (prevents malleability)
- **HMAC-SHA256** for key MACs and invite MACs
- AES-256-GCM provides authenticated encryption — any ciphertext tampering is detected

### Signature Coverage Is Comprehensive

The `canonical_document_bytes` function (`crypto.rs:347`) uses a `BTreeMap` for both members and secrets, guaranteeing alphabetical key ordering and thus a fully deterministic serialization. The signed payload covers the full vault state (all active members, all secrets), so any modification to any field invalidates the signature.

Pending members (empty `wrapped_dek`) are correctly excluded from canonical bytes, preventing new member registration from invalidating existing signatures.

### Key Separation Is Correct

The X25519 encryption key and Ed25519 signing key are derived via separate HKDF operations with distinct `info` strings (`bkey-sign-v1` vs the implicit X25519 derivation path), ensuring cryptographic domain separation.

### Invite MAC Prevents Key Substitution

The v2 invite flow ECDH-MAC correctly binds the new member's public key to the specific invite token. The ECDH shared secret (`ECDH(invitee_priv, invite_pub)`) can only be computed by the legitimate invitee (holder of `invitee_priv`) and verified by the legitimate inviter (who can re-derive `invite_priv` from `inviter_priv + nonce`). A MITM who substitutes their own public key in storage cannot produce the correct MAC.

### ECIES Nonce Handling Is Correct

The DEK wrapping uses a fresh ephemeral X25519 keypair per wrap operation (`EphemeralSecret::random_from_rng`), ensuring that re-wrapping the same DEK for the same recipient produces a different ciphertext each time. The AES-256-GCM nonce is independently randomized. There is no nonce reuse risk.

### DEK Rotation on Member Removal Is Complete

`rotate_dek_in_state` (`members.rs:41`) correctly decrypts all secrets with the old DEK, generates a new random DEK, re-encrypts all secrets, and re-wraps the new DEK for every active member. Pending members are left pending and must be re-granted. The old DEK is not persisted anywhere after rotation.

---

## Summary Table

| # | Finding | Severity | File | Effort to Fix |
|---|---------|----------|------|---------------|
| 1 | Invite token embeds storage credentials in cleartext | **Critical** | `invite.rs:70` | Medium |
| 2 | Private key sent as hex over plaintext TCP | **High** | `agent.rs:200` | Medium |
| 3 | MAC comparisons are not constant-time | **High** | `crypto.rs:298, 259` | Low |
| 4 | Manual join path bypasses invite MAC | **High** | `setup.rs:216` | Low |
| 5 | Agent key persists 8 hours with no lock command | **Medium** | `agent.rs:28` | Low |
| 6 | Argon2id parameters are minimum-viable | **Medium** | `crypto.rs:25` | Trivial |
| 7 | No passphrase pepper | **Medium** | `crypto.rs:25` | Medium |
| 8 | Passphrase strength check is character-class based | **Medium** | `passphrase.rs:49` | Low |
| 9 | `exec` exposes secrets as environment variables | **Medium** | `exec.rs:111` | Low |
| 10 | `ttyname()` is not thread-safe | **Low** | `agent.rs:18` | Trivial |
| 11 | Agent bearer token has no replay protection | **Low** | `agent.rs:358` | Low (fixed by #2) |
| 12 | Config file not restricted on Windows | **Low** | `config.rs:55` | Low |
| 13 | Dry-run prints secret values to terminal | **Low** | `exec.rs:96` | Trivial |
| 14 | `doc_version` unused — future downgrade risk | **Info** | `types.rs:13` | — |
| 15 | Old unsigned invite tokens silently accepted | **Info** | `invite.rs:122` | Low |

### Recommended Fix Order

1. **Finding 1** — Remove storage credentials from invite tokens (eliminates a class of credential leak)
2. **Finding 3** — Constant-time MAC comparison (one-line fix, eliminates a crypto correctness issue)
3. **Finding 2** — Migrate agent to Unix socket (eliminates plaintext key-over-TCP)
4. **Finding 4** — Add fingerprint verification to manual join (closes the key-substitution gap)
5. **Finding 6** — Increase Argon2id parameters (one-line fix, significantly hardens offline cracking)
6. **Finding 8** — Replace character-class check with `zxcvbn` (better usability + security)
7. **Finding 7** — Add OS keychain pepper (meaningful defense-in-depth improvement)
8. **Findings 5, 9–15** — Operational hardening (lower urgency, schedule for next cycle)
