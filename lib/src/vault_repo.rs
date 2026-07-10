use crate::{
    crypto::{canonical_document_bytes, sign_document, verify_document_signature},
    error::Result,
    storage::{pull_prefix, push_path, StorageBackend, StorageConfig},
    vault_document::VaultDocument,
};
use automerge::AutoCommit;
use autosurgeon::reconcile;
use directories::ProjectDirs;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};

const REMOTE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct VaultRepo {
    vault_id: String,
    member_id: String,
    remote_storage: StorageBackend,
    local_storage: StorageBackend,
}

pub struct PullOutcome {
    pub doc: AutoCommit,
    /// True if the remote pull errored or timed out during this call, meaning
    /// `doc` may be based on the local cache alone rather than the latest remote state.
    pub remote_unreachable: bool,
}

impl VaultRepo {
    pub fn new(vault_id: &str, member_id: &str, storage: &StorageConfig) -> Result<Self> {
        let remote_storage = StorageBackend::new(storage)?;

        let cache_root = cache_dir();
        let local_config = crate::storage::StorageConfig::Fs(crate::storage::FsConfig {
            root: cache_root.to_string_lossy().into_owned(),
        });
        let local_storage = StorageBackend::new(&local_config)?;

        Ok(Self {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote_storage,
            local_storage,
        })
    }

    async fn pull_verified_documents(
        &self,
        storage: &StorageBackend,
        label: &str,
        max_timeout: Option<Duration>,
    ) -> Result<(Vec<AutoCommit>, bool)> {
        let prefix = pull_prefix(&self.vault_id);

        let (unverified_documents, reachable) = match max_timeout {
            Some(max_timeout) => match timeout(max_timeout, storage.pull(&prefix)).await {
                Ok(Ok(documents)) => (documents, true),
                Ok(Err(e)) => {
                    crate::warn_log!(
                        "warning: {label} pull for vault {} failed ({e}) — treating as empty",
                        self.vault_id
                    );
                    (vec![], false)
                }
                Err(_) => {
                    crate::warn_log!(
                        "warning: {label} pull for vault {} timed out after {}s — treating as empty",
                        self.vault_id,
                        max_timeout.as_secs()
                    );
                    (vec![], false)
                }
            },
            None => (storage.pull(&prefix).await?, true),
        };

        Ok((verify_documents(unverified_documents), reachable))
    }

    pub async fn pull(&self) -> Result<PullOutcome> {
        let (local_documents, _) = self
            .pull_verified_documents(&self.local_storage, "local", None)
            .await?;
        let (remote_documents, remote_reachable) = self
            .pull_verified_documents(&self.remote_storage, "remote", Some(REMOTE_TIMEOUT))
            .await?;
        let remote_unreachable = !remote_reachable;

        // Hydrate every candidate (local and remote) once, pairing each with its
        // state so the max compaction date reflects both sources — otherwise an
        // unreachable remote (empty candidate list) forces the max down to 0 and
        // discards an already-compacted local cache. See vault_repo tests below.
        let docs_with_state: Vec<(AutoCommit, Option<VaultDocument>)> = local_documents
            .into_iter()
            .chain(remote_documents)
            .map(|d| {
                let s = VaultDocument::try_from(&d).ok();
                (d, s)
            })
            .collect();

        let max_compaction_date = docs_with_state
            .iter()
            .filter_map(|(_, s)| s.as_ref().map(|s| s.compaction_date.unwrap_or(0)))
            .max()
            .unwrap_or(0);

        let all: Vec<AutoCommit> = docs_with_state
            .into_iter()
            .filter_map(|(d, s)| match s {
                Some(s) if s.compaction_date.unwrap_or(0) == max_compaction_date => Some(d),
                Some(s) => {
                    crate::warn_log!(
                        "warning: discarding a document for vault {} — its compaction date ({:?}) does not match the newest known compaction date ({})",
                        self.vault_id, s.compaction_date, max_compaction_date
                    );
                    None
                }
                None => None,
            })
            .collect();

        let merged = all.into_iter().reduce(|mut a, mut b| {
            let _ = a.merge(&mut b);
            a
        });

        if merged.is_none() {
            crate::warn_log!(
                "warning: no usable document found locally or remotely for vault {} — initializing an empty vault; unlocking against it will fail with 'not a member of this vault'",
                self.vault_id
            );
        }

        Ok(PullOutcome {
            doc: merged.unwrap_or_else(|| init_vault(&self.vault_id)),
            remote_unreachable,
        })
    }

    /// Sign the document then push to local cache and remote storage.
    pub async fn persist(
        &self,
        doc: &mut AutoCommit,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<()> {
        // Sign: compute canonical bytes, produce signature, store in document
        let mut vault_doc = VaultDocument::try_from(doc as &AutoCommit)?;
        let canonical = canonical_document_bytes(&vault_doc);
        vault_doc.document_signature = sign_document(&canonical, &self.member_id, signing_key);
        reconcile(doc, &vault_doc)?;

        let data = doc.save();
        let push = push_path(&self.vault_id, &self.member_id);

        // Always write to local cache
        self.local_storage.push(&push, data.clone()).await?;

        // Best-effort remote push with timeout
        match timeout(REMOTE_TIMEOUT, self.remote_storage.push(&push, data)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => crate::warn_log!(
                "warning: remote push for vault {} failed ({e}) — local cache is ahead of remote until the next successful sync",
                self.vault_id
            ),
            Err(_) => crate::warn_log!(
                "warning: remote push for vault {} timed out after {}s — local cache is ahead of remote until the next successful sync",
                self.vault_id,
                REMOTE_TIMEOUT.as_secs()
            ),
        }

        Ok(())
    }
}

/// Verify signatures on each file and return the valid docs, skipping bad ones.
fn verify_documents(files: Vec<Vec<u8>>) -> Vec<AutoCommit> {
    files
        .into_iter()
        .filter_map(|bytes| {
            let doc = AutoCommit::load(&bytes).ok()?;
            let vault_doc = VaultDocument::try_from(&doc).ok()?;

            if vault_doc.document_signature.is_empty() {
                crate::warn_log!("warning: skipping unsigned member file");
                return None;
            }

            let member_id = vault_doc.document_signature.splitn(2, ':').next()?;
            let member = vault_doc.members.get(member_id)?;

            if member.signing_key.is_empty() {
                crate::warn_log!(
                    "warning: skipping file signed by member {member_id} with no registered signing key"
                );
                return None;
            }

            let canonical = canonical_document_bytes(&vault_doc);
            match verify_document_signature(
                &canonical,
                &vault_doc.document_signature,
                &member.signing_key,
            ) {
                Ok(()) => Some(doc),
                Err(_) => {
                    crate::warn_log!(
                        "warning: skipping member file with invalid signature (member {member_id})"
                    );
                    None
                }
            }
        })
        .collect()
}

fn init_vault(vault_id: &str) -> AutoCommit {
    let mut doc = AutoCommit::new();
    let vault_doc = VaultDocument {
        id: vault_id.to_string(),
        name: String::new(),
        doc_version: 0,
        members: Default::default(),
        secrets: Default::default(),
        document_signature: String::new(),
        compaction_date: None,
    };
    reconcile(&mut doc, &vault_doc).expect("init_doc reconcile failed");
    doc
}

pub fn cache_dir() -> PathBuf {
    ProjectDirs::from("", "", "envi")
        .map(|d| d.cache_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".envi-cache"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{canonical_document_bytes, derive_signing_key, sign_document},
        storage::{push_path, FsConfig, StorageConfig},
        vault_document::{Member, VaultDocument},
    };
    use autosurgeon::reconcile;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use std::collections::HashMap;
    use tempfile::TempDir;

    // Deterministic test private key from a single seed byte.
    fn test_private_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // A Member entry whose signing_key will pass verify_files.
    fn test_member(member_id: &str, seed: u8) -> Member {
        let sk = derive_signing_key(&test_private_key(seed));
        Member {
            id: member_id.to_string(),
            email: format!("{member_id}@test.com"),
            public_key: String::new(),
            wrapped_dek: String::new(),
            signing_key: B64.encode(sk.verifying_key().to_bytes()),
            key_mac: String::new(),
            invite_mac: String::new(),
            invite_nonce: String::new(),
        }
    }

    // Build a signed, serialised AutoCommit for (vault_id, member_id) with one member.
    fn make_doc_bytes(
        vault_id: &str,
        member_id: &str,
        seed: u8,
        compaction_date: Option<u64>,
    ) -> Vec<u8> {
        make_vault_doc_bytes(
            vault_id,
            &[(member_id, seed)],
            member_id,
            seed,
            compaction_date,
        )
    }

    // Build a fresh signed doc containing all listed members, signed by signer_id.
    // `members_info` is a slice of (member_id, seed) pairs — every member in the vault.
    fn make_vault_doc_bytes(
        vault_id: &str,
        members_info: &[(&str, u8)],
        signer_id: &str,
        signer_seed: u8,
        compaction_date: Option<u64>,
    ) -> Vec<u8> {
        let sk = derive_signing_key(&test_private_key(signer_seed));
        let mut members = HashMap::new();
        for &(mid, seed) in members_info {
            members.insert(mid.to_string(), test_member(mid, seed));
        }

        let mut vault_doc = VaultDocument {
            id: vault_id.to_string(),
            name: "Test Vault".to_string(),
            doc_version: 0,
            members,
            secrets: Default::default(),
            document_signature: String::new(),
            compaction_date,
        };

        let canonical = canonical_document_bytes(&vault_doc);
        vault_doc.document_signature = sign_document(&canonical, signer_id, &sk);

        let mut doc = AutoCommit::new();
        reconcile(&mut doc, &vault_doc).unwrap();
        doc.save()
    }

    // Load existing doc bytes, optionally update compaction_date, and re-sign as signer_id.
    // Docs produced this way share Automerge ancestry with the source bytes.
    fn fork_and_sign(
        source_bytes: &[u8],
        signer_id: &str,
        signer_seed: u8,
        compaction_date: Option<u64>,
    ) -> Vec<u8> {
        let sk = derive_signing_key(&test_private_key(signer_seed));
        let mut doc = AutoCommit::load(source_bytes).unwrap();
        let mut vault_doc = VaultDocument::try_from(&doc).unwrap();
        vault_doc.compaction_date = compaction_date;
        vault_doc.document_signature = String::new();
        let canonical = canonical_document_bytes(&vault_doc);
        vault_doc.document_signature = sign_document(&canonical, signer_id, &sk);
        reconcile(&mut doc, &vault_doc).unwrap();
        doc.save()
    }

    fn fs_backend(dir: &std::path::Path) -> StorageBackend {
        StorageBackend::new(&StorageConfig::Fs(FsConfig {
            root: dir.to_string_lossy().into_owned(),
        }))
        .unwrap()
    }

    async fn write_to_remote(
        remote: &StorageBackend,
        vault_id: &str,
        member_id: &str,
        bytes: Vec<u8>,
    ) {
        remote
            .push(&push_path(vault_id, member_id), bytes)
            .await
            .unwrap();
    }

    // ── compaction_date field ─────────────────────────────────────────────────

    #[test]
    fn compaction_date_none_treated_as_zero() {
        let bytes = make_doc_bytes("v1", "m1", 1, None);
        let doc = AutoCommit::load(&bytes).unwrap();
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert_eq!(vault_doc.compaction_date.unwrap_or(0), 0);
    }

    #[test]
    fn compaction_date_some_roundtrips() {
        let bytes = make_doc_bytes("v1", "m1", 1, Some(42_000));
        let doc = AutoCommit::load(&bytes).unwrap();
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert_eq!(vault_doc.compaction_date, Some(42_000));
    }

    // ── pull() compaction logic ───────────────────────────────────────────────

    #[tokio::test]
    async fn pull_adopts_compacted_remote_doc() {
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-adopt";
        let member_id = "m1";

        write_to_remote(
            &fs_backend(remote.path()),
            vault_id,
            member_id,
            make_doc_bytes(vault_id, member_id, 1, Some(1000)),
        )
        .await;

        // Local has an older, uncompacted doc.
        fs_backend(local.path())
            .push(
                &push_path(vault_id, member_id),
                make_doc_bytes(vault_id, member_id, 1, None),
            )
            .await
            .unwrap();

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert_eq!(
            vault_doc.compaction_date,
            Some(1000),
            "should adopt compacted remote"
        );
    }

    #[tokio::test]
    async fn pull_merges_multiple_compacted_docs_with_same_date() {
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-multi";
        let remote_be = fs_backend(remote.path());
        let both = &[("m1", 1u8), ("m2", 2u8)];

        // Two peers both compacted at the same timestamp.
        // Crucially each compacted doc contains ALL members (realistic: you compact the
        // whole vault state). When Automerge resolves the conflict between the two fresh
        // `members` map objects, whichever wins still has both members inside it.
        write_to_remote(
            &remote_be,
            vault_id,
            "m1",
            make_vault_doc_bytes(vault_id, both, "m1", 1, Some(2000)),
        )
        .await;
        write_to_remote(
            &remote_be,
            vault_id,
            "m2",
            make_vault_doc_bytes(vault_id, both, "m2", 2, Some(2000)),
        )
        .await;

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: "m1".to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        // Both members' data should appear after merging the two compacted docs.
        assert!(vault_doc.members.contains_key("m1"));
        assert!(vault_doc.members.contains_key("m2"));
        assert_eq!(vault_doc.compaction_date, Some(2000));
    }

    #[tokio::test]
    async fn pull_excludes_uncompacted_docs_when_newer_compaction_exists() {
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-exclude";
        let remote_be = fs_backend(remote.path());

        // m1 compacted, m2 did not.
        write_to_remote(
            &remote_be,
            vault_id,
            "m1",
            make_doc_bytes(vault_id, "m1", 1, Some(3000)),
        )
        .await;
        write_to_remote(
            &remote_be,
            vault_id,
            "m2",
            make_doc_bytes(vault_id, "m2", 2, None),
        )
        .await;

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: "m1".to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        // Only m1's compacted doc should be used; m2's is excluded.
        assert_eq!(vault_doc.compaction_date, Some(3000));
        assert!(vault_doc.members.contains_key("m1"));
        assert!(
            !vault_doc.members.contains_key("m2"),
            "uncompacted peer should be excluded"
        );
    }

    #[tokio::test]
    async fn pull_uses_local_cache_when_remote_unreachable() {
        // Regression test: the remote yields nothing (unreachable, timed out, or
        // simply empty) while the local cache holds an already-compacted doc.
        // Before the fix, max_remote_compaction_date was computed only from the
        // (empty) remote set, so it came out as 0; the local doc's nonzero
        // compaction date then failed the equality check and was discarded,
        // and pull() fell back to init_vault() — an empty, memberless doc that
        // makes every subsequent unlock_document() call fail with NotAMember.
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-offline";
        let member_id = "m1";

        fs_backend(local.path())
            .push(
                &push_path(vault_id, member_id),
                make_doc_bytes(vault_id, member_id, 1, Some(1_778_420_931)),
            )
            .await
            .unwrap();

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote_storage: fs_backend(remote.path()), // empty: nothing ever pushed
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert_eq!(vault_doc.compaction_date, Some(1_778_420_931));
        assert!(
            vault_doc.members.contains_key(member_id),
            "local cached membership must survive an unreachable remote"
        );
    }

    #[tokio::test]
    async fn pull_prefers_local_when_local_compaction_newer_than_remote() {
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-local-ahead";
        let member_id = "m1";

        // Remote still has the pre-compaction state (e.g. the compaction's
        // best-effort remote push failed or hasn't landed yet).
        write_to_remote(
            &fs_backend(remote.path()),
            vault_id,
            member_id,
            make_doc_bytes(vault_id, member_id, 1, Some(1000)),
        )
        .await;

        // Local already compacted again, more recently.
        fs_backend(local.path())
            .push(
                &push_path(vault_id, member_id),
                make_doc_bytes(vault_id, member_id, 1, Some(2000)),
            )
            .await
            .unwrap();

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert_eq!(
            vault_doc.compaction_date,
            Some(2000),
            "should prefer the newer local compaction over stale remote"
        );
    }

    #[tokio::test]
    async fn pull_normal_merge_when_no_compaction() {
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-normal";
        let remote_be = fs_backend(remote.path());

        // Build a shared genesis with both members so the two files share Automerge
        // ancestry. Each member then forks and re-signs it. Without shared ancestry
        // Automerge would conflict on the `members` map object and only one member's
        // entry would survive.
        let genesis = make_vault_doc_bytes(vault_id, &[("m1", 1), ("m2", 2)], "m1", 1, None);

        // Neither peer has compacted; each just re-signs the shared genesis.
        write_to_remote(
            &remote_be,
            vault_id,
            "m1",
            fork_and_sign(&genesis, "m1", 1, None),
        )
        .await;
        write_to_remote(
            &remote_be,
            vault_id,
            "m2",
            fork_and_sign(&genesis, "m2", 2, None),
        )
        .await;

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: "m1".to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        // Normal CRDT merge: both members should appear.
        assert!(vault_doc.members.contains_key("m1"));
        assert!(vault_doc.members.contains_key("m2"));
        assert_eq!(vault_doc.compaction_date.unwrap_or(0), 0);
    }

    // ── Backwards compatibility ───────────────────────────────────────────────

    #[tokio::test]
    async fn pull_loads_old_doc_without_compaction_date_field() {
        // Simulate a vault file written by an old version of envi that has no
        // `compaction_date` key in the Automerge document. The new code must still
        // be able to hydrate it; without `#[autosurgeon(missing = "Default::default")]`
        // on that field, autosurgeon would error and verify_files would reject the file.
        let remote = TempDir::new().unwrap();
        let local = TempDir::new().unwrap();
        let vault_id = "vault-old";
        let member_id = "m1";
        let seed: u8 = 1;

        // Build a doc that deliberately omits compaction_date (old format).
        // We do this by reconciling an old-style struct that has no compaction_date.
        #[derive(autosurgeon::Reconcile, autosurgeon::Hydrate, Default)]
        struct OldEnviDocument {
            id: String,
            name: String,
            doc_version: u64,
            members: HashMap<String, Member>,
            secrets: std::collections::HashMap<String, crate::vault_document::Secret>,
            document_signature: String,
        }
        let sk = derive_signing_key(&test_private_key(seed));
        let mut members = HashMap::new();
        members.insert(member_id.to_string(), test_member(member_id, seed));
        let old_state = OldEnviDocument {
            id: vault_id.to_string(),
            name: "Old Vault".to_string(),
            doc_version: 0,
            members,
            secrets: Default::default(),
            document_signature: String::new(),
        };
        let mut doc = AutoCommit::new();
        reconcile(&mut doc, &old_state).unwrap();
        // Sign it (using the new canonical bytes which still exclude compaction_date)
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        let canonical = crate::crypto::canonical_document_bytes(&vault_doc);
        let sig = crate::crypto::sign_document(&canonical, member_id, &sk);
        let mut signed_state = vault_doc;
        signed_state.document_signature = sig;
        reconcile(&mut doc, &signed_state).unwrap();
        let old_bytes = doc.save();

        write_to_remote(&fs_backend(remote.path()), vault_id, member_id, old_bytes).await;

        let repo = VaultRepo {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote_storage: fs_backend(remote.path()),
            local_storage: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap().doc;
        let vault_doc = VaultDocument::try_from(&doc).unwrap();
        assert!(
            vault_doc.members.contains_key(member_id),
            "old vault file should survive verify_files"
        );
        assert_eq!(
            vault_doc.compaction_date, None,
            "missing field hydrates as None"
        );
    }

    // ── Compact action logic ──────────────────────────────────────────────────

    #[test]
    fn compact_produces_smaller_doc_with_timestamp() {
        let vault_id = "vault-compact";
        let member_id = "m1";

        // Build a doc with accumulated history.
        let mut doc = AutoCommit::load(&make_doc_bytes(vault_id, member_id, 1, None)).unwrap();
        for i in 0..100u64 {
            let mut vault_doc = VaultDocument::try_from(&doc).unwrap();
            vault_doc.doc_version = i;
            reconcile(&mut doc, &vault_doc).unwrap();
        }
        let size_before = doc.save().len();

        // Simulate Actions::Compact: reconcile current state into a fresh doc.
        let now = 99_999u64;
        let mut vault_doc = VaultDocument::try_from(&doc).unwrap();
        vault_doc.document_signature = String::new();
        vault_doc.compaction_date = Some(now);

        let mut fresh = AutoCommit::new();
        reconcile(&mut fresh, &vault_doc).unwrap();
        let size_after = fresh.save().len();

        assert!(
            size_after < size_before,
            "compacted doc ({size_after} B) should be smaller than doc with 100 ops ({size_before} B)",
        );

        let vault_doc = VaultDocument::try_from(&fresh).unwrap();
        assert_eq!(vault_doc.doc_version, 99);
        assert_eq!(vault_doc.compaction_date, Some(99_999));
        assert!(vault_doc.document_signature.is_empty());
    }
}
