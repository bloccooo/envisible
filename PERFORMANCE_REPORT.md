# Performance Analysis: `envisible` — Sync Latency & File Size

**Reviewer role:** Claude Code
**Codebase version:** 0.0.39  
**Date:** 2026-05-09

---

## Executive Summary

There are two distinct but interrelated problems. Both trace back to a single root cause: **every call to `reconcile()` generates SET operations for every field of every secret**, regardless of what actually changed. After 3–4 months of daily use with 150 secrets, the Automerge operation log inside each `.envi.enc` file has ballooned to the point where parsing and merging it becomes the dominant cost at startup. The large file sizes are a symptom of this same explosion.

---

## How Automerge Stores Data (and Why Your Files Are 5–6 MB)

Automerge is an operation-log CRDT. Internally, `AutoCommit` maintains an **append-only journal of every mutation** ever applied to the document. When you call `doc.save()` (`store.rs:78`), that full journal is serialized — not just the current state. Automerge uses a columnar binary encoding with RLE compression, but the underlying operations never disappear unless you create a fresh document.

Every call to `reconcile(doc, &envi)` diffs the new Rust struct against the current document and appends SET operations for every field that looks different. The critical path is in `doc.rs:92–95`:

```rust
let envi = state_to_envi_doc(doc, &effective, &session.dek)?;
reconcile(doc, &envi)?;
```

Inside `state_to_envi_doc`:

```rust
// doc.rs:104–117
envi.secrets.clear();          // wipe all secrets
for s in &state.secrets {
    envi.secrets.insert(s.id.clone(), Secret {
        name:        encrypt_field(&s.name, dek)?,   // ← random nonce every call
        value:       encrypt_field(&s.value, dek)?,  // ← random nonce every call
        description: encrypt_field(&s.description, dek)?,
        tags:        encrypt_field(&tags_json, dek)?,
    });
}
```

`encrypt_field` (`crypto.rs:119`) generates a fresh 12-byte random nonce on every invocation:

```rust
rand::thread_rng().fill_bytes(&mut nonce_bytes);
```

Because the nonce changes, the ciphertext changes, so the string value changes. Autosurgeon's `reconcile` compares new values against what's in the document and issues a SET for every field that differs. Since **every encrypted field always differs**, every reconcile generates `150 secrets × 4 fields = 600 SET operations`, even when only one character in one secret changed.

**Rough math:** if you open the TUI daily over 120 days and go through ~5 reconcile cycles per session:

```
120 days × 5 reconciles × 600 ops × ~100 bytes/op ≈ 36 MB raw ops
```

Automerge's columnar compression helps but cannot eliminate this. 5–6 MB for a 150-secret vault over that period is entirely consistent with this model.

---

## Issue 1 — The `reconcile` Explosion

**Severity: Critical**  
**Files:** `cli/src/tui/doc.rs:101–136`, `lib/src/secrets.rs:47–60`, `lib/src/members.rs:41–89`

### Problem

`state_to_envi_doc` always clears and re-inserts every secret. Because `encrypt_field` always uses a fresh nonce, every field of every secret looks changed to `autosurgeon::reconcile`. The result is O(N × fields) new operations per save, regardless of what actually changed. Over months this creates thousands of operations that accumulate permanently in the document journal.

### Fix

Only re-encrypt fields that actually changed in plaintext. Compare each secret in the new `State` against the old `State` (already passed as `old` to `apply_set_state`). For unchanged fields, preserve the existing ciphertext from the Automerge document.

```rust
// cli/src/tui/doc.rs — replace state_to_envi_doc signature and body
pub fn state_to_envi_doc(
    doc: &AutoCommit,
    old_state: &State,
    new_state: &State,
    dek: &[u8; 32],
) -> Result<EnviDocument> {
    let mut envi: EnviDocument = hydrate(doc).map_err(|e| Error::Other(e.to_string()))?;

    // Index old plaintext secrets for O(1) lookup
    let old_map: HashMap<&str, &Secret> = old_state.secrets
        .iter()
        .map(|s| (s.id.as_str(), s))
        .collect();

    // Remove deleted secrets
    let new_ids: HashSet<&str> = new_state.secrets.iter().map(|s| s.id.as_str()).collect();
    envi.secrets.retain(|id, _| new_ids.contains(id.as_str()));

    for s in &new_state.secrets {
        let tags_json = serde_json::to_string(&s.tags)?;

        match old_map.get(s.id.as_str()) {
            Some(old) => {
                // Secret existed before — only re-encrypt changed fields
                let enc = envi.secrets.entry(s.id.clone()).or_default();
                if old.name != s.name {
                    enc.name = encrypt_field(&s.name, dek)?;
                }
                if old.value != s.value {
                    enc.value = encrypt_field(&s.value, dek)?;
                }
                if old.description != s.description {
                    enc.description = encrypt_field(&s.description, dek)?;
                }
                let old_tags_json = serde_json::to_string(&old.tags)?;
                if old_tags_json != tags_json {
                    enc.tags = encrypt_field(&tags_json, dek)?;
                }
            }
            None => {
                // New secret — encrypt all fields
                envi.secrets.insert(s.id.clone(), lib::types::Secret {
                    id: s.id.clone(),
                    name: encrypt_field(&s.name, dek)?,
                    value: encrypt_field(&s.value, dek)?,
                    description: encrypt_field(&s.description, dek)?,
                    tags: encrypt_field(&tags_json, dek)?,
                });
            }
        }
    }

    // Members: same pattern — preserve unchanged encrypted fields
    let old_member_map: HashMap<&str, &super::state::Member> = old_state.members
        .iter()
        .map(|m| (m.id.as_str(), m))
        .collect();

    let new_member_ids: HashSet<&str> = new_state.members.iter().map(|m| m.id.as_str()).collect();
    envi.members.retain(|id, _| new_member_ids.contains(id.as_str()));

    for m in &new_state.members {
        if old_member_map.contains_key(m.id.as_str()) {
            // Only overwrite fields that are explicitly being changed
            let enc = envi.members.entry(m.id.clone()).or_default();
            enc.wrapped_dek = m.wrapped_dek.clone();
            enc.key_mac = m.key_mac.clone();
        } else {
            envi.members.insert(m.id.clone(), lib::types::Member {
                id: m.id.clone(),
                email: m.email.clone(),
                public_key: m.public_key.clone(),
                wrapped_dek: m.wrapped_dek.clone(),
                signing_key: m.signing_key.clone(),
                key_mac: m.key_mac.clone(),
                invite_mac: m.invite_mac.clone(),
                invite_nonce: m.invite_nonce.clone(),
            });
        }
    }

    Ok(envi)
}
```

Update the call site in `apply_set_state` to pass `old`:

```rust
// doc.rs:92
let envi = state_to_envi_doc(doc, old, &effective, &session.dek)?;
```

**Impact:** Reduces new operations per edit from ~600 to only the fields actually changed (typically 1–4). Stops future history growth immediately. Does not shrink existing accumulated history — see Issue 2 for that.

---

## Issue 2 — Automerge History Never Compacted

**Severity: High**  
**File:** `lib/src/store.rs:78`

### How Automerge Stores History Internally

Each `reconcile()` call produces a "change" — a batch of operations with a lamport timestamp and actor ID. Automerge stores all changes in a columnar format sorted by actor. The current value for any key is determined by replaying all changes. Even if secret X was updated 200 times, all 200 change entries are retained. `doc.save()` (`store.rs:78`) serializes this entire log, not just the final state.

### The Compaction Challenge

Because Automerge is an operation-log CRDT, dropping history requires coordination: if member A compacts their file but member B still has the old history, the merge of A's compact doc + B's old doc will re-introduce B's history into the result. Full compaction is only achievable once all members have uploaded compact versions.

There is also a **delete-correctness hazard**: a compact document that doesn't contain secret X cannot tell other members "X was deleted" vs "X was never there." Without explicit tombstones, deletions would be silently resurrected after compaction when merged with a peer that still has the old insert operation.

### Fix — Two-Phase Approach

**Phase A: Add tombstones** (prerequisite for safe compaction)

```rust
// lib/src/types.rs
#[derive(Debug, Clone, Reconcile, Hydrate, Default)]
pub struct EnviDocument {
    pub id: String,
    pub name: String,
    pub doc_version: u64,
    pub members: HashMap<String, Member>,
    pub secrets: HashMap<String, Secret>,
    pub deleted_secret_ids: Vec<String>,   // tombstones — survive compaction
    pub deleted_member_ids: Vec<String>,
    pub document_signature: String,
}
```

When removing a secret, push its ID to `deleted_secret_ids` instead of only removing it from the map. When loading secrets in `list_secrets` and `derive_state`, filter out any ID present in `deleted_secret_ids`. A compact document can now communicate "this was deleted" even without the original delete operation in its history.

**Phase B: Compact on persist**

After signing, create a fresh `AutoCommit` with only the current state and save that instead of the full document:

```rust
// lib/src/store.rs — persist()
pub async fn persist(
    &self,
    doc: &mut AutoCommit,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let mut state: EnviDocument = hydrate(doc as &AutoCommit)?;
    let canonical = canonical_document_bytes(&state);
    state.document_signature = sign_document(&canonical, &self.member_id, signing_key);

    // Compact: fresh document with no operation history
    let mut compact = AutoCommit::new();
    reconcile(&mut compact, &state)?;

    let data = compact.save();
    let push = push_path(&self.vault_id, &self.member_id);

    self.local.push(&push, data.clone()).await?;
    let _ = timeout(REMOTE_TIMEOUT, self.remote.push(&push, data)).await;

    // Replace in-place so the in-session document stays consistent
    *doc = compact;
    Ok(())
}
```

Over one sync cycle per member, each uploaded file becomes compact. The local merged document (which initially may still contain old history from other members' files) will also shrink as all members upload compact versions and the old bloated files are replaced.

**Expected result:** Files shrink from 5–6 MB to ~50–200 KB (actual data size of your encrypted secrets plus Automerge's columnar header), after all members have saved once.

---

## Issue 3 — Full Re-Download on Every Startup

**Severity: High**  
**File:** `lib/src/storage.rs:128–158`

### Problem

`StorageBackend::pull()` lists all member files and downloads them unconditionally on every startup. With 5–6 MB files and multiple members, this is substantial I/O even before parsing begins. The existing local cache is used only as a merge fallback, not to skip unchanged remote files.

```rust
// storage.rs:142 — downloads ALL files every time
let results = futures::stream::iter(doc_entries)
    .map(|e| { ... self.op.read(&path).await ... })
    .buffer_unordered(MAX_CONCURRENT)
    ...
```

### Fix — ETag / Hash-Based Conditional Download

Most storage backends (S3, R2, WebDAV) support `ETag` or `Last-Modified` headers. `opendal` exposes `Metadata` for each entry via `stat()`. Cache the last-known ETag per member file path alongside the local document:

```rust
// lib/src/storage.rs — add to StorageBackend
pub async fn pull_if_changed(
    &self,
    prefix: &str,
    known_etags: &HashMap<String, String>,
) -> Result<(Vec<Vec<u8>>, HashMap<String, String>)> {
    let entries = match self.op.list(prefix).await {
        Ok(e) => e,
        Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok((vec![], HashMap::new())),
        Err(e) => return Err(Error::Storage(e)),
    };

    let doc_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().ends_with(&format!(".{DOC_EXTENSION}")))
        .collect();

    let mut new_etags = known_etags.clone();
    let mut changed_paths = vec![];

    for entry in &doc_entries {
        let path = entry.path().to_owned();
        if let Ok(meta) = self.op.stat(&path).await {
            let etag = meta.etag().map(str::to_owned)
                .or_else(|| meta.last_modified().map(|t| t.to_rfc3339()));
            match (etag.as_deref(), known_etags.get(&path)) {
                (Some(e), Some(k)) if e == k => continue, // unchanged
                _ => {}
            }
            if let Some(e) = etag {
                new_etags.insert(path.clone(), e);
            }
            changed_paths.push(path);
        }
    }

    const MAX_CONCURRENT: usize = 8;
    let results = futures::stream::iter(changed_paths)
        .map(|path| async move { self.op.read(&path).await.ok().map(|b| b.to_bytes().to_vec()) })
        .buffer_unordered(MAX_CONCURRENT)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    Ok((results, new_etags))
}
```

Persist the `etag_map` alongside the local cache (a small JSON sidecar file). For backends that support neither ETags nor `Last-Modified` (the `Fs` backend in tests), fall back to a content hash stored on first download.

**Impact:** On startup after an idle period with no remote changes, zero bytes downloaded. Only changed member files are re-fetched and re-merged. This is likely the single most impactful change for perceived startup latency.

---

## Issue 4 — Sequential Signature Verification and Merge

**Severity: Medium**  
**File:** `lib/src/store.rs:100–148`

### Problem

The verification loop and the merge are both sequential:

```rust
// store.rs:105–148
let docs: Vec<AutoCommit> = files
    .into_iter()
    .filter_map(|bytes| {
        let doc = AutoCommit::load(&bytes).ok()?;       // expensive — parses full binary
        let state: EnviDocument = hydrate(&doc).ok()?;  // expensive — replays ops
        let canonical = canonical_document_bytes(&state); // alloc + BTreeMap + JSON
        verify_document_signature(...)?;
        Some(doc)
    })
    .collect();

docs.into_iter().reduce(|mut a, mut b| {
    let _ = a.merge(&mut b);
    a
})
```

`AutoCommit::load` parses the full columnar binary format. `hydrate` traverses the operation graph to reconstruct the Rust struct. `canonical_document_bytes` allocates two `BTreeMap`s and serializes to JSON. These three steps run once per member file, back-to-back, on a potentially multi-megabyte file.

### Fix — Parallelize Verification with `spawn_blocking`

CPU-bound work should move off the async executor onto a dedicated thread pool:

```rust
// lib/src/store.rs
use tokio::task;

async fn load_and_verify_files(files: Vec<Vec<u8>>) -> Option<AutoCommit> {
    if files.is_empty() {
        return None;
    }

    // Verify all files in parallel on the blocking thread pool
    let handles: Vec<_> = files
        .into_iter()
        .map(|bytes| task::spawn_blocking(move || verify_file(bytes)))
        .collect();

    let docs: Vec<AutoCommit> = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter_map(|r| r.ok().flatten())
        .collect();

    if docs.is_empty() {
        return None;
    }

    // Sequential reduction is fine for small teams;
    // a tree reduction would parallelize further for large member counts
    docs.into_iter().reduce(|mut a, mut b| {
        let _ = a.merge(&mut b);
        a
    })
}

fn verify_file(bytes: Vec<u8>) -> Option<AutoCommit> {
    let doc = AutoCommit::load(&bytes).ok()?;
    let state: EnviDocument = hydrate(&doc).ok()?;

    if state.document_signature.is_empty() {
        eprintln!("warning: skipping unsigned member file");
        return None;
    }

    let member_id = state.document_signature.splitn(2, ':').next()?;
    let member = state.members.get(member_id)?;

    if member.signing_key.is_empty() {
        eprintln!("warning: skipping file with no signing key for member {member_id}");
        return None;
    }

    let canonical = canonical_document_bytes(&state);
    match verify_document_signature(&canonical, &state.document_signature, &member.signing_key) {
        Ok(()) => Some(doc),
        Err(_) => {
            eprintln!("warning: invalid signature for member {member_id}");
            None
        }
    }
}
```

**Impact:** Verification time scales with the number of CPU cores available rather than member count × file size. On a quad-core machine with 4 members, this is a ~4× speedup for the verification phase.

---

## Issue 5 — `derive_state` Decrypts All Secrets on Every Action

**Severity: Medium**  
**File:** `cli/src/tui/doc.rs:142–188`

### Problem

`derive_state` is called after every `apply_set_state`. Inside, `list_secrets` performs 150 × 4 = 600 AES-GCM decrypt operations:

```rust
// doc.rs:145
let mut secrets: Vec<Secret> = list_secrets(doc, &session.dek)
    .unwrap_or_default()
    ...
```

```rust
// secrets.rs:93–100
pub fn list_secrets(doc: &AutoCommit, dek: &[u8; 32]) -> Result<Vec<PlaintextSecret>> {
    let state: EnviDocument = hydrate(doc)?;
    state.secrets.values()
        .map(|s| decrypt_secret(s, dek))  // AES-GCM per field, every time
        .collect()
}
```

This runs on every user action that triggers a doc change, blocking the 16 ms TUI render cycle for potentially hundreds of crypto operations.

### Fix — Ciphertext-Keyed Decryption Cache

Cache plaintext by its ciphertext string. Since ciphertext is stable for any given (plaintext, nonce) pair, a cache miss only happens when a field actually changed:

```rust
// lib/src/store.rs — add to Session
pub struct Session {
    pub member_id: String,
    pub dek: [u8; 32],
    pub signing_key: ed25519_dalek::SigningKey,
    pub private_key: [u8; 32],
    pub decrypt_cache: HashMap<String, String>, // ciphertext → plaintext
}
```

```rust
// lib/src/secrets.rs — cache-aware variant
pub fn list_secrets_cached(
    doc: &AutoCommit,
    dek: &[u8; 32],
    cache: &mut HashMap<String, String>,
) -> Result<Vec<PlaintextSecret>> {
    let state: EnviDocument = hydrate(doc)?;
    state.secrets.values()
        .map(|s| {
            let decrypt_cached = |ct: &str| -> Result<String> {
                if let Some(pt) = cache.get(ct) {
                    return Ok(pt.clone());
                }
                let pt = decrypt_field(ct, dek)?;
                cache.insert(ct.to_string(), pt.clone());
                Ok(pt)
            };
            let tags_json = decrypt_cached(&s.tags)?;
            Ok(PlaintextSecret {
                id: s.id.clone(),
                name: decrypt_cached(&s.name)?,
                value: decrypt_cached(&s.value)?,
                description: decrypt_cached(&s.description)?,
                tags: serde_json::from_str(&tags_json)?,
            })
        })
        .collect()
}
```

Clear the cache only on DEK rotation or vault unlock (when the DEK changes). Invalidate individual entries on secret update (the ciphertext will be different after a new nonce is generated).

**Impact:** For typical edits (1 secret changes at a time), reduces decrypt operations from 150 × 4 → 1 × 4 per `derive_state`. TUI feels noticeably more responsive on large vaults.

---

## Issue 6 — `opt-level = "z"` Trades CPU for Binary Size

**Severity: Low**  
**File:** `Cargo.toml:17`

```toml
opt-level = "z"   # optimize for size
```

`opt-level = "z"` minimizes binary size by disabling loop unrolling, SIMD vectorization, and aggressive inlining. This is appropriate for embedded systems or extremely size-constrained deployments, but for a desktop CLI tool it trades measurable CPU throughput for marginal size savings. AES-GCM, HKDF, and Argon2 are all on the hot path at startup.

`opt-level = "s"` retains size discipline but re-enables profitable inlining:

```toml
[profile.release]
opt-level     = "s"   # size-aware but keeps inlining
lto           = true
codegen-units = 1
panic         = "abort"
strip         = true
```

**Impact:** ~10–20% faster on crypto-heavy paths (AES-GCM decrypt of 150 secrets, HKDF chains) at the cost of a slightly larger binary (~5–10% binary size increase). Given the other fixes, the binary size difference is not meaningful.

---

## Issue 7 — `canonical_document_bytes` Allocates on Every Signature Verify

**Severity: Low**  
**File:** `lib/src/crypto.rs:347–393`, `lib/src/store.rs:127`

### Problem

For each member file loaded, `canonical_document_bytes` allocates two `BTreeMap`s (one for members, one for secrets), populates them with references, and runs a full `serde_json::to_vec`. For 150 secrets, that is 150 `BTreeMap` insertions + JSON serialization per file.

```rust
// crypto.rs:348–392
let members: BTreeMap<_, _> = state.members.iter()
    .filter(|(_, m)| !m.wrapped_dek.is_empty())
    .map(...).collect();

let secrets: BTreeMap<_, _> = state.secrets.iter()
    .map(...).collect();

serde_json::to_vec(&SigDocument { members, secrets, ... })?
```

This is called once during `load_and_verify_files` per file and once during `persist`. With the parallel verification fix (Issue 4), this work is distributed across threads. With compaction (Issue 2), the document is far smaller. This issue is not a priority unless verification remains a bottleneck after the higher-priority fixes.

A minor improvement is to pre-size the `BTreeMap` with `BTreeMap::new()` and insert in sorted order to avoid re-sorting, but `BTreeMap` does not support pre-allocation. A more impactful change would be to replace `BTreeMap`-based canonical serialization with a manually ordered `serde_json::Value` builder that iterates the `HashMap` once, sorts the keys in-place, and writes directly — eliminating the intermediate allocation.

---

## Priority Order and Expected Outcomes

| # | Issue | Impact | Effort | Expected Outcome |
|---|-------|--------|--------|-----------------|
| 1 | Reconcile explosion — re-encrypt only changed fields | Critical | Medium | Stops history growth cold; future files stay small |
| 2 | History compaction on persist + tombstones | High | Medium | Files shrink to ~50–200 KB after one sync cycle per member |
| 3 | ETag-based conditional download | High | Medium | Eliminates network I/O for unchanged files; startup near-instant on idle vaults |
| 4 | Parallel signature verification | Medium | Low | Linear speedup proportional to CPU cores × member count |
| 5 | Decryption cache in `derive_state` | Medium | Low | TUI edits feel instant on large vaults |
| 6 | `opt-level = "s"` | Low | Trivial | ~10–20% crypto speedup for free |
| 7 | `canonical_document_bytes` allocation | Low | Low | Minor; deprioritize until others land |

---

## Root Cause Summary

**Why is sync slow?**  
The `.envi.enc` files are large because every `reconcile` has been writing ~600 SET operations per save for months. `AutoCommit::load` + `hydrate` + signature verification on a 5–6 MB file is expensive CPU work, and it runs for every member's file on every startup with no caching of unchanged files. The storage backend is irrelevant — the bottleneck is CPU-side parsing of an over-grown document.

**Why are the files huge?**  
`encrypt_field` generates a new random nonce on every call, making all 150 × 4 ciphertext values look changed to autosurgeon on every `reconcile`. Each reconcile appends a batch of ~600 operations to the Automerge journal. Four months of daily use across multiple sync events per session results in millions of accumulated operations stored in each member's file.

**How does Automerge store data?**  
As an append-only columnar log of operations, each tagged with an actor ID and lamport timestamp. `doc.save()` serializes this entire log. The current value for any key is determined by replaying all operations — only the latest wins for reads, but all are retained for merge correctness. History is never trimmed automatically.

**Can history be compressed?**  
Yes. Creating a fresh `AutoCommit`, reconciling the current state into it, and saving that produces a compact document containing only the current state with no historical operations. The prerequisite is tombstones for deleted items (Issue 2, Phase A), which ensure delete semantics are preserved after compaction when merging with peers that haven't seen the compaction yet. With both fixes in place, files shrink to reflect the actual data size after one sync cycle per member.
