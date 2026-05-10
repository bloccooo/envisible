use crate::{
    crypto::{
        canonical_document_bytes, derive_signing_key, get_public_key, sign_document, unwrap_dek,
        verify_document_signature, verify_key_mac,
    },
    error::{Error, Result},
    storage::{pull_prefix, push_path, StorageBackend, StorageConfig},
    types::VaultDocument,
};
use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use directories::ProjectDirs;
use std::path::PathBuf;
use tokio::time::{timeout, Duration};

const REMOTE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct VaultRepo {
    vault_id: String,
    member_id: String,
    remote: StorageBackend,
    local: StorageBackend,
}

impl VaultRepo {
    pub fn new(vault_id: &str, member_id: &str, storage: &StorageConfig) -> Result<Self> {
        let remote = StorageBackend::new(storage)?;

        let cache_root = cache_dir();
        let local_config = crate::storage::StorageConfig::Fs(crate::storage::FsConfig {
            root: cache_root.to_string_lossy().into_owned(),
        });
        let local = StorageBackend::new(&local_config)?;

        Ok(Self {
            vault_id: vault_id.to_string(),
            member_id: member_id.to_string(),
            remote,
            local,
        })
    }

    pub async fn pull(&self) -> Result<AutoCommit> {
        let prefix = pull_prefix(&self.vault_id);

        let local_doc = self.load_local(&prefix).await;

        let remote_docs: Vec<AutoCommit> =
            match timeout(REMOTE_TIMEOUT, self.remote.pull(&prefix)).await {
                Ok(Ok(files)) => verify_files(files),
                _ => vec![],
            };

        // Hydrate each remote doc once, pair with its state, reuse for both passes.
        let remote_docs_with_state: Vec<(AutoCommit, Option<VaultDocument>)> = remote_docs
            .into_iter()
            .map(|d| {
                let s: Option<VaultDocument> = hydrate(&d).ok();
                (d, s)
            })
            .collect();

        let max_remote_compaction_date = remote_docs_with_state
            .iter()
            .filter_map(|(_, s)| s.as_ref().map(|s| s.compaction_date.unwrap_or(0)))
            .max()
            .unwrap_or(0);

        let mut all: Vec<AutoCommit> = remote_docs_with_state
            .into_iter()
            .filter(|(_, s)| {
                s.as_ref()
                    .map(|s| s.compaction_date.unwrap_or(0) == max_remote_compaction_date)
                    .unwrap_or(false)
            })
            .map(|(d, _)| d)
            .collect();

        if let Some(local) = local_doc {
            let s: Option<VaultDocument> = hydrate(&local).ok();

            if s.map(|s| s.compaction_date.unwrap_or(0) == max_remote_compaction_date)
                .unwrap_or(false)
            {
                all.push(local);
            }
        }

        let merged = all
            .into_iter()
            .reduce(|mut a, mut b| {
                let _ = a.merge(&mut b);
                a
            })
            .unwrap_or_else(|| init_vault(&self.vault_id));

        Ok(merged)
    }

    /// Sign the document then push to local cache and remote storage.
    pub async fn persist(
        &self,
        doc: &mut AutoCommit,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<()> {
        // Sign: compute canonical bytes, produce signature, store in document
        let mut vault_doc: VaultDocument = hydrate(doc as &AutoCommit)?;
        let canonical = canonical_document_bytes(&vault_doc);
        vault_doc.document_signature = sign_document(&canonical, &self.member_id, signing_key);
        reconcile(doc, &vault_doc)?;

        let data = doc.save();
        let push = push_path(&self.vault_id, &self.member_id);

        // Always write to local cache
        self.local.push(&push, data.clone()).await?;

        // Best-effort remote push with timeout
        let _ = timeout(REMOTE_TIMEOUT, self.remote.push(&push, data)).await;

        Ok(())
    }

    async fn load_local(&self, prefix: &str) -> Option<AutoCommit> {
        let files = self.local.pull(prefix).await.ok()?;
        let docs = verify_files(files);
        docs.into_iter().reduce(|mut a, mut b| {
            let _ = a.merge(&mut b);
            a
        })
    }
}

/// Verify signatures on each file and return the valid docs, skipping bad ones.
fn verify_files(files: Vec<Vec<u8>>) -> Vec<AutoCommit> {
    files
        .into_iter()
        .filter_map(|bytes| {
            let doc = AutoCommit::load(&bytes).ok()?;
            let vault_doc: VaultDocument = hydrate(&doc).ok()?;

            if vault_doc.document_signature.is_empty() {
                eprintln!("warning: skipping unsigned member file");
                return None;
            }

            let member_id = vault_doc.document_signature.splitn(2, ':').next()?;
            let member = vault_doc.members.get(member_id)?;

            if member.signing_key.is_empty() {
                eprintln!(
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
                    eprintln!(
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

// --- Session ---

pub struct Session {
    pub member_id: String,
    pub dek: [u8; 32],
    pub signing_key: ed25519_dalek::SigningKey,
    /// X25519 private key seed — kept in session so the invite flow can re-derive
    /// invite keypairs on demand without any local storage.
    pub private_key: [u8; 32],
}

/// Unlock the document for the given private key.
/// Verifies all member key MACs using the decrypted DEK.
pub fn unlock(doc: &AutoCommit, private_key: &[u8; 32]) -> Result<Session> {
    let vault_doc: VaultDocument = hydrate(doc)?;

    let public_key = get_public_key(private_key);
    let pub_key_b64 = B64.encode(public_key);

    let member = vault_doc
        .members
        .values()
        .find(|m| m.public_key == pub_key_b64)
        .ok_or(Error::NotAMember)?;

    if member.wrapped_dek.is_empty() {
        return Err(Error::AccessPending);
    }

    let dek = unwrap_dek(&member.wrapped_dek, private_key)?;

    // Verify key MACs for all members that have one
    for m in vault_doc.members.values() {
        if m.key_mac.is_empty() {
            continue; // pending member or old client — skip
        }
        verify_key_mac(&dek, &m.id, &m.public_key, &m.signing_key, &m.key_mac)
            .map_err(|_| Error::InvalidKeyMac(m.id.clone()))?;
    }

    let signing_key = derive_signing_key(private_key);

    Ok(Session {
        member_id: member.id.clone(),
        dek,
        signing_key,
        private_key: *private_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{canonical_document_bytes, derive_signing_key, sign_document},
        storage::{push_path, FsConfig, StorageConfig},
        types::{Member, VaultDocument},
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
        let mut vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
        assert_eq!(vault_doc.compaction_date.unwrap_or(0), 0);
    }

    #[test]
    fn compaction_date_some_roundtrips() {
        let bytes = make_doc_bytes("v1", "m1", 1, Some(42_000));
        let doc = AutoCommit::load(&bytes).unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            remote: fs_backend(remote.path()),
            local: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            remote: fs_backend(remote.path()),
            local: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            remote: fs_backend(remote.path()),
            local: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
        // Only m1's compacted doc should be used; m2's is excluded.
        assert_eq!(vault_doc.compaction_date, Some(3000));
        assert!(vault_doc.members.contains_key("m1"));
        assert!(
            !vault_doc.members.contains_key("m2"),
            "uncompacted peer should be excluded"
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
            remote: fs_backend(remote.path()),
            local: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            secrets: std::collections::HashMap<String, crate::types::Secret>,
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
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            remote: fs_backend(remote.path()),
            local: fs_backend(local.path()),
        };

        let doc = repo.pull().await.unwrap();
        let vault_doc: VaultDocument = hydrate(&doc).unwrap();
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
            let mut vault_doc: VaultDocument = hydrate(&doc).unwrap();
            vault_doc.doc_version = i;
            reconcile(&mut doc, &vault_doc).unwrap();
        }
        let size_before = doc.save().len();

        // Simulate Actions::Compact: reconcile current state into a fresh doc.
        let now = 99_999u64;
        let mut vault_doc: VaultDocument = hydrate(&doc).unwrap();
        vault_doc.document_signature = String::new();
        vault_doc.compaction_date = Some(now);

        let mut fresh = AutoCommit::new();
        reconcile(&mut fresh, &vault_doc).unwrap();
        let size_after = fresh.save().len();

        assert!(
            size_after < size_before,
            "compacted doc ({size_after} B) should be smaller than doc with 100 ops ({size_before} B)",
        );

        let vault_doc: VaultDocument = hydrate(&fresh).unwrap();
        assert_eq!(vault_doc.doc_version, 99);
        assert_eq!(vault_doc.compaction_date, Some(99_999));
        assert!(vault_doc.document_signature.is_empty());
    }
}
