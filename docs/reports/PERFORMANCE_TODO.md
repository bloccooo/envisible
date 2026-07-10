# Performance TODO

Tracks fixes for [`PERFORMANCE_REPORT.md`](./PERFORMANCE_REPORT.md). Ordered by priority as listed in the report's "Priority Order" section.
Check an item off and note the commit when it's applied.

---

- [x] **Issue 2 — Automerge history never compacted** — implemented as manual compaction (`Actions::Compact` in `cli/src/tui/mod.rs:213`, `compaction_date` field in `lib/src/vault_document.rs`, filtering logic in `lib/src/vault_repo.rs`)

- [ ] **Issue 1 — The `reconcile` explosion** — `state_to_envi_doc` still clears and rewrites all secrets on every action (`doc.rs`); needs diff-based reconcile instead of clear-and-rebuild

- [ ] **Issue 3 — Full re-download on every startup** — no ETag / conditional-download support found in `lib/src/storage.rs`

- [ ] **Issue 4 — Sequential signature verification and merge** — no `spawn_blocking` usage found; verification in `verify_documents` (`lib/src/vault_repo.rs`) is still sequential

- [ ] **Issue 5 — `derive_state` decrypts all secrets on every action** — no decryption cache found

- [ ] **Issue 6 — `opt-level = "z"` trades CPU for binary size** — `Cargo.toml` still sets `opt-level = "z"`; revisit if startup CPU cost matters more than binary size

- [ ] **Issue 7 — `canonical_document_bytes` allocates on every signature verify** — not yet verified whether this was addressed
