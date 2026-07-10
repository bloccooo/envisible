# Report: Intermittent `error: not a member of this vault` on login

**Date:** 2026-07-10
**Symptom:** Login (`envi ui`, `envi exec`) intermittently fails with `not a member of this vault`; on other runs the same vault unlocks fine (sometimes without a passphrase prompt).
**Status:** Root cause fixed (Fix 1); reproduced live in the field and confirmed by warning logs, see section 2. Fixes 2–6 still open.

## Fix tracking

- [x] **Fix 1 — `pull()`: never let a failed remote pull erase the local vault** (critical) — pool local + remote candidates before computing max compaction date, `lib/src/vault_repo.rs::pull()`. Verified against the actual failure log; regression tests `pull_uses_local_cache_when_remote_unreachable` and `pull_prefers_local_when_local_compaction_newer_than_remote` added.
- [ ] **Fix 2 — distinguish "remote unavailable" from "remote empty" and surface it** (high) — warning logs added (this session), but `pull()` still silently falls back to `init_vault()` if truly nothing is found anywhere; no dedicated error/UI surfacing yet.
- [ ] **Fix 3 — fall back to a passphrase prompt when the agent's cached key fails** (high) — not yet implemented; `ui.rs`/`exec.rs` still error out on a stale cached key instead of re-prompting.
- [ ] **Fix 4 — make the `NotAMember` message actionable** (medium) — partially: a diagnostic warning was added at the throw site (`lib/src/crypto.rs::unlock_document`), but the user-facing error text is unchanged.
- [ ] **Fix 5 — refresh the local cache on successful remote pull** (medium) — not yet implemented.
- [ ] **Fix 6 — make silent drops observable** (low) — done for the paths covered by this incident (see warning logs added throughout `vault_repo.rs` and `crypto.rs`); not audited beyond that.

---

## 1. Where the error comes from

The string is produced by a single variant, `Error::NotAMember` (`lib/src/error.rs:5`), constructed in exactly **one** place — `unlock_document()` in `lib/src/crypto.rs:426-430`:

```rust
let member = vault_doc
    .members
    .values()
    .find(|m| m.public_key == pub_key_b64)
    .ok_or(Error::NotAMember)?;
```

It fires when the X25519 public key derived from the caller's private key matches **no member** in the vault document being unlocked. Since the private key is `derive_private_key(passphrase, vault_id, member_id)` (`lib/src/crypto.rs:26`), every occurrence is one of two things:

- **Key-side:** the derived key is wrong (bad passphrase, wrong `member_id`/`vault_id` in config, stale agent key).
- **Document-side:** the key is right but the document handed to `unlock_document` doesn't contain the member record.

The intermittency points at the document side, and there is a concrete bug there.

---

## 2. Root cause of the intermittent failure (primary bug)

### `VaultRepo::pull()` silently returns an **empty vault** when the remote is unreachable and the vault has ever been compacted

`lib/src/vault_repo.rs:58-112`. The chain:

1. The remote pull runs under a 5-second timeout, and **both timeout and any storage error are swallowed into an empty list** (`vault_repo.rs:47-53`):

   ```rust
   Some(max_timeout) => match timeout(max_timeout, storage.pull(&prefix)).await {
       Ok(Ok(documents)) => documents,
       _ => vec![],   // timeout OR error → pretend remote is empty
   },
   ```

2. With zero remote docs, `max_remote_compaction_date` computes to `0` (`vault_repo.rs:77-81`).

3. The local cached document is only included if its compaction date **equals** `max_remote_compaction_date` (`vault_repo.rs:93-101`). Compaction (`cli/src/tui/mod.rs:213-241`, `Actions::Compact`) stamps `compaction_date = Some(now)`, so once anyone compacts the vault, the local cache carries a nonzero date. `nonzero != 0` → **the local doc is discarded**.

4. `all` is now empty, so `pull()` falls back to `init_vault()` (`vault_repo.rs:109`, defined at `vault_repo.rs:187-200`) — a freshly initialized document with an **empty members map**.

5. `unlock_document` finds no member matching any key → `NotAMember`.

**Net behavior:** on a compacted vault, login succeeds when the remote answers within 5s and fails with `not a member of this vault` whenever the remote is slow, offline, or erroring. That is exactly "randomly fails."

Note the compaction-date equality filter itself is *intentional and must stay*: compaction creates a fresh `AutoCommit` with no shared Automerge history (`tui/mod.rs:224-226`), so pre- and post-compaction docs must never be merged together. The bug is only in what happens when the remote side is missing.

### Secondary variant of the same bug: local ahead of remote

`persist()` pushes to remote best-effort with the same swallowed timeout (`vault_repo.rs:132-133`). If a **compaction's remote push fails**, the local cache holds `compaction_date = D2` while remote still has `D1 < D2`. On the next pull, `max_remote_compaction_date = D1`, the local doc (`D2 != D1`) is discarded, and the user unlocks against pre-compaction remote state. Usually that still contains the member (works), but it silently resurrects pre-compaction data — and if membership/keys changed at compaction time, it can also produce `NotAMember` or `InvalidKeyMac`. Either way the local/remote split never heals because the compacted doc only exists locally.

---

## 3. Contributing cause of "randomly unlocks without asking" (agent behavior)

`cli/src/agent.rs`. The agent daemon caches derived keys in memory, keyed by `(vault_id, tty)` (`agent.rs:187-198`, `session_id` = controlling TTY from `get_tty()`, `agent.rs:18-26`), with an 8-hour idle TTL enforced by a watchdog that checks every 5 minutes (`agent.rs:28`, `302-313`).

Consequences:

- Whether you get a passphrase prompt depends on the agent being alive, the TTL, **and which terminal tab you're in** (per-TTY keying). This fully explains the "randomly unlocks the vault" half of the symptom — it's not random, it's cache state.
- With no TTY (scripts/CI), `session_id` is `""` and all headless sessions share one cache slot.
- Keys are only stored **after** a successful unlock (`ui.rs:56-58`, `exec.rs:163-165`), so a mistyped passphrase is never cached. Good. **But** a key cached before a membership change (e.g. you re-joined the vault and your member record's `public_key` changed) stays valid in the agent for up to 8h, and both callers use it **without any fallback**: if the cached key produces `NotAMember`, the command errors out instead of prompting (`ui.rs:47-55`, `exec.rs:154-162`).

---

## 4. Complete list of paths to `NotAMember`

| # | Path | Location | Random? |
|---|------|----------|---------|
| 1 | Remote pull timeout/error + compacted local cache → `init_vault()` empty doc | `vault_repo.rs:47-53, 93-109` | **Yes — primary suspect** |
| 2 | Local compaction newer than remote (failed push) → local doc dropped, stale remote state used | `vault_repo.rs:93-101, 132-133` | Yes |
| 3 | Stale agent key after membership/passphrase change, no prompt fallback | `agent.rs:187`, `ui.rs:47`, `exec.rs:154` | Yes (depends on agent/TTY state) |
| 4 | Partial remote listing (eventual consistency): the per-member file containing your grant not returned | `storage.rs:128` via `vault_repo.rs:64` | Yes |
| 5 | `verify_documents` silently drops the doc containing your membership (unsigned / signer not in file / signer has no signing key / bad signature) — prints `warning:` to stderr | `vault_repo.rs:140-178` | Possible |
| 6 | Remote doc fails hydration (`VaultDocument::try_from` → `None`) and is dropped by the compaction filter's `unwrap_or(false)` | `vault_repo.rs:69-91` | Possible |
| 7 | Wrong passphrase — surfaces as `NotAMember`, not "wrong password" | `crypto.rs:26, 420-430` | User-dependent |
| 8 | `member_id` or `vault.id` in local config differs from what was used at join (key derivation input) | `ui.rs:51`, `exec.rs:158`, `setup.rs` | Deterministic |
| 9 | Genuinely removed / re-invited with a new `public_key` on the member record | vault document | Deterministic |

(A member record that exists but has an empty `wrapped_dek` produces the distinct `AccessPending` error, `crypto.rs:432-434` — not this bug.)

---

## 5. Fixes

### Fix 1 — `pull()`: never let a failed remote pull erase the local vault  **(critical)**

`lib/src/vault_repo.rs`.

**Rule change:** compute the max compaction date over **all** candidate docs (local **and** remote), then keep every doc whose date equals that max. This one change fixes both path 1 and path 2:

- Remote unreachable → candidates = {local}, max = local's date → local doc used. Login works offline.
- Local compacted ahead of remote → max = local's D2 → local wins instead of being dropped; the next `persist()` pushes it and heals the split.
- Normal case (remote ≥ local) → identical behavior to today.

Sketch:

```rust
pub async fn pull(&self) -> Result<AutoCommit> {
    let local_documents = self.pull_verified_documents(&self.local_storage, None).await?;
    let remote_documents = self
        .pull_verified_documents(&self.remote_storage, Some(REMOTE_TIMEOUT))
        .await?;

    // Hydrate every candidate once; docs that fail hydration are dropped (warn).
    let candidates: Vec<(AutoCommit, u64)> = local_documents
        .into_iter()
        .chain(remote_documents)
        .filter_map(|d| {
            let date = VaultDocument::try_from(&d)
                .ok()
                .map(|s| s.compaction_date.unwrap_or(0))?;
            Some((d, date))
        })
        .collect();

    let max_date = candidates.iter().map(|(_, d)| *d).max().unwrap_or(0);

    let merged = candidates
        .into_iter()
        .filter(|(_, d)| *d == max_date)
        .map(|(d, _)| d)
        .reduce(|mut a, mut b| { let _ = a.merge(&mut b); a });

    Ok(merged.unwrap_or_else(|| init_vault(&self.vault_id)))
}
```

Notes:
- `merge_documents` for the local side becomes unnecessary (locals join the same candidate pool). Keep the compaction-equality semantics — do **not** merge across different compaction generations.
- Local cache may legitimately hold multiple files if `cache_dir()` is shared; the pool handles that.

### Fix 2 — distinguish "remote unavailable" from "remote empty" and surface it  **(high)**

`pull_verified_documents` (`vault_repo.rs:40-56`) currently collapses timeout/error into `vec![]`. Return something like `(Vec<AutoCommit>, bool /* remote_ok */)` (or a small enum) so `pull()` can report degraded state. Then:

- In `ui.rs` / `exec.rs`, print a one-line notice when operating from cache only: `warning: could not reach remote storage — using local cache`.
- If **both** local and remote yield nothing, `pull()` should not silently hand back `init_vault()` to a login flow. Either return a dedicated error (`Error::VaultUnavailable`) or let callers detect `members.is_empty()` before prompting for a passphrase. `init_vault` is only legitimately needed by the setup flow — consider moving the fallback out of `pull()` and into setup (`cli/src/commands/setup.rs`), making `pull()` return `Result<Option<AutoCommit>>`.

### Fix 3 — fall back to a passphrase prompt when the agent key fails  **(high)**

`cli/src/commands/ui.rs:47-58` and `cli/src/commands/exec.rs:154-166` (identical logic — extract a shared helper, e.g. `fn unlock_with_agent(...)` in a common module):

```rust
// pseudo-structure for the shared helper
let session = match agent_key {
    Some(key) => match unlock_document(&doc, &key) {
        Ok(s) => Ok(s),
        // stale cached key: re-prompt instead of failing
        Err(Error::NotAMember) => {
            let key = derive_private_key(&prompt_passphrase()?, &vault.id, &config.member_id)?;
            unlock_document(&doc, &key)
        }
        Err(e) => Err(e),
    },
    None => { /* prompt as today */ }
};
```

Only store the key in the agent after the successful unlock (as today). Optionally, drop the stale entry via a new `DeleteKey` agent request, but re-storing on success already overwrites it.

### Fix 4 — make the `NotAMember` message actionable  **(medium)**

A wrong passphrase is indistinguishable from a missing membership at the crypto layer, but callers can disambiguate by inspecting the doc they just pulled:

- `vault_doc.members.is_empty()` → the document is empty; almost certainly a sync problem, not an auth problem. Message: `vault document is empty — could not sync from storage; check your connection and try again`.
- Members exist but none match → `wrong passphrase, or you are not a member of this vault`. Consider a bounded retry loop (2–3 attempts) on the prompt path.

Cheapest version: change the error text in `lib/src/error.rs:5` to mention the passphrase. Better version: do the check in `ui.rs`/`exec.rs` (or in `unlock_document` itself, by adding an `Error::EmptyVaultDocument` variant when `members.is_empty()`).

### Fix 5 — refresh the local cache on successful remote pull  **(medium)**

`persist()` writes to the local cache, but `pull()` never does (`vault_repo.rs:58-112`), so a read-mostly user's cache goes stale and widens the window for paths 1/2. After a successful remote pull, mirror the fetched files (or the merged doc) into `local_storage`. Mirroring raw files verbatim under the same names is simplest and avoids re-signing (the merged doc can't be written via `persist()` without a signing key, which `pull()` doesn't have).

### Fix 6 — make silent drops observable  **(low)**

- `verify_documents` warnings (`vault_repo.rs:148, 156-159, 170-173`) already go to stderr; also count them and include the count in the degraded-state notice from Fix 2.
- Log (behind a `--verbose` flag or `RUST_LOG`) which docs were excluded by the compaction filter and why — this is the information that was missing when debugging this very issue.

---

## 6. Tests to add

In `lib/src/vault_repo.rs` (extend the existing `#[cfg(test)]` suite, which already covers compaction merging):

1. **`pull_uses_local_cache_when_remote_unreachable`** — local storage has a signed, compacted doc (`compaction_date = Some(n)`); remote storage backend errors (or points at an unroutable target). `pull()` must return the local doc with its members intact. *This test fails today — it reproduces the primary bug.*
2. **`pull_prefers_local_when_local_compaction_newer`** — local has `compaction_date = 2000`, remote has `1000`. `pull()` returns the local doc.
3. **`pull_returns_error_or_none_when_no_documents_anywhere`** — both storages empty → whatever contract Fix 2 chooses (not a silently-empty unlockable doc).
4. **`pull_remote_only_still_works`** — regression guard: empty local cache + healthy remote behaves as today.
5. Keep all five existing compaction tests green (`pull_adopts_compacted_remote_doc`, `pull_merges_multiple_compacted_docs_with_same_date`, `pull_excludes_uncompacted_docs_when_newer_compaction_exists`, `pull_normal_merge_when_no_compaction`, `pull_loads_old_doc_without_compaction_date_field`).

In `cli` (or as an integration test):

6. **Stale agent key falls back to prompt** — unlock with a wrong cached key must trigger the passphrase path, not exit with `NotAMember` (Fix 3). May need the shared unlock helper to be testable without a live agent.

Manual reproduction of the primary bug (pre-fix):

```sh
# on a vault that has been compacted at least once:
networksetup -setairportpower en0 off   # or unplug / firewall the remote
envi ui                                  # → "error: not a member of this vault"
networksetup -setairportpower en0 on
envi ui                                  # → unlocks fine
```

---

## 7. Suggested order of implementation

1. Fix 1 + test 1/2/3/4 (removes the failure).
2. Fix 3 (removes the stale-agent variant; small, self-contained).
3. Fix 2 + Fix 4 (turns any residual occurrence into a diagnosable message).
4. Fix 5 + Fix 6 (hardening / observability).

Fixes 1–4 are independent of each other except that Fix 2 slightly reshapes `pull_verified_documents`, so land Fix 1 and Fix 2 together in one pass over `vault_repo.rs`.
