use std::collections::{HashMap, HashSet};

use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{compute_key_mac, derive_invite_key, encrypt_field, verify_invite_mac, wrap_dek},
    error::{Error, Result},
    members::{remove_member, rotate_dek},
    secrets::list_secrets,
    store::Session,
    types::EnviDocument,
};

use super::state::{Member, Secret, State};

/// Returns true if new_state requires a doc mutation (vs a footer-only update).
pub fn is_doc_change(old: &State, new: &State) -> bool {
    new.rotate_dek
        || !new.pending_grants.is_empty()
        || old.secrets != new.secrets
        || old.members.len() != new.members.len()
        || old
            .members
            .iter()
            .zip(new.members.iter())
            .any(|(o, n)| o.id != n.id)
}

/// Apply the doc changes implied by new_state and return the re-derived canonical State.
/// The caller is responsible for restoring the footer from new_state.
pub fn apply_set_state(
    doc: &mut AutoCommit,
    session: &mut Session,
    old: &State,
    new: &State,
) -> Result<State> {
    // ── DEK rotation (lib handles full re-encryption internally) ──────────────
    if new.rotate_dek {
        let new_dek = rotate_dek(doc, &session.dek)?;
        session.dek = new_dek;
        return Ok(derive_state(doc, session, new));
    }

    // ── Member removal (triggers internal DEK rotation) ───────────────────────
    let removed: Vec<String> = old
        .members
        .iter()
        .filter(|m| !new.members.iter().any(|nm| nm.id == m.id))
        .map(|m| m.id.clone())
        .collect();
    if !removed.is_empty() {
        for id in &removed {
            let new_dek = remove_member(doc, &session.dek, id)?;
            session.dek = new_dek;
        }
        return Ok(derive_state(doc, session, new));
    }

    // ── Grant + secret/tag changes: build EnviDocument and reconcile ──────────
    let mut effective = new.clone();

    for id in &new.pending_grants {
        if let Some(m) = effective.members.iter_mut().find(|m| m.id == *id) {
            let pub_key_bytes = B64
                .decode(&m.public_key)
                .map_err(|_| Error::DecryptionFailed)?;
            let pub_key: [u8; 32] = pub_key_bytes
                .try_into()
                .map_err(|_| Error::DecryptionFailed)?;

            // Verify invite MAC if this member registered with a v2 invite token.
            if !m.invite_mac.is_empty() && !m.invite_nonce.is_empty() {
                let nonce_bytes = B64
                    .decode(&m.invite_nonce)
                    .map_err(|_| Error::InvalidInviteLink)?;
                let invite_priv = derive_invite_key(&session.private_key, &nonce_bytes)?;
                verify_invite_mac(
                    &invite_priv,
                    &pub_key,
                    &m.id,
                    &m.public_key,
                    &m.signing_key,
                    &m.invite_mac,
                )?;
            }

            m.wrapped_dek = wrap_dek(&session.dek, &pub_key)?;
            m.key_mac = compute_key_mac(&session.dek, &m.id, &m.public_key, &m.signing_key);
        }
    }
    effective.pending_grants.clear();

    let envi = state_to_envi_doc(doc, &effective, &old, &session.dek)?;
    reconcile(doc, &envi).map_err(|e| Error::Other(e.to_string()))?;

    Ok(derive_state(doc, session, &effective))
}

/// Build an EnviDocument from State by encrypting all plaintext secrets.
/// Starts from the current doc (preserves doc_version, document_signature, etc.)
/// then overwrites secrets and members but only those that changed.
pub fn state_to_envi_doc(
    doc: &AutoCommit,
    new_state: &State,
    old_state: &State,
    dek: &[u8; 32],
) -> Result<EnviDocument> {
    let mut envi: EnviDocument = hydrate(doc).map_err(|e| Error::Other(e.to_string()))?;

    // Index old plaintext secrets for O(1) lookup
    let old_map: HashMap<&str, &Secret> = old_state
        .secrets
        .iter()
        .map(|s| (s.id.as_str(), s))
        .collect();

    // Remove deleted secrets
    let new_ids: HashSet<&str> = new_state.secrets.iter().map(|s| s.id.as_str()).collect();
    envi.secrets.retain(|id, _| new_ids.contains(id.as_str()));

    for secret in &new_state.secrets {
        let tags_json = serde_json::to_string(&secret.tags)?;

        match old_map.get(secret.id.as_str()) {
            Some(old) => {
                // Secret existed before — only re-encrypt changed fields
                let enc = envi.secrets.entry(secret.id.clone()).or_default();
                if old.name != secret.name {
                    enc.name = encrypt_field(&secret.name, dek)?;
                }
                if old.value != secret.value {
                    enc.value = encrypt_field(&secret.value, dek)?;
                }
                if old.description != secret.description {
                    enc.description = encrypt_field(&secret.description, dek)?;
                }
                let old_tags_json = serde_json::to_string(&old.tags)?;
                if old_tags_json != tags_json {
                    enc.tags = encrypt_field(&tags_json, dek)?;
                }
            }
            None => {
                // New secret — encrypt all fields
                envi.secrets.insert(
                    secret.id.clone(),
                    lib::types::Secret {
                        id: secret.id.clone(),
                        name: encrypt_field(&secret.name, dek)?,
                        value: encrypt_field(&secret.value, dek)?,
                        description: encrypt_field(&secret.description, dek)?,
                        tags: encrypt_field(&tags_json, dek)?,
                    },
                );
            }
        }
    }

    // Members: same pattern — preserve unchanged encrypted fields
    let old_member_map: HashMap<&str, &super::state::Member> = old_state
        .members
        .iter()
        .map(|member| (member.id.as_str(), member))
        .collect();

    let new_member_ids: HashSet<&str> = new_state
        .members
        .iter()
        .map(|member| member.id.as_str())
        .collect();

    envi.members
        .retain(|id, _| new_member_ids.contains(id.as_str()));

    for member in &new_state.members {
        if old_member_map.contains_key(member.id.as_str()) {
            // Only overwrite fields that are explicitly being changed
            let enc = envi.members.entry(member.id.clone()).or_default();
            enc.wrapped_dek = member.wrapped_dek.clone();
            enc.key_mac = member.key_mac.clone();
        } else {
            envi.members.insert(
                member.id.clone(),
                lib::types::Member {
                    id: member.id.clone(),
                    email: member.email.clone(),
                    public_key: member.public_key.clone(),
                    wrapped_dek: member.wrapped_dek.clone(),
                    signing_key: member.signing_key.clone(),
                    key_mac: member.key_mac.clone(),
                    invite_mac: member.invite_mac.clone(),
                    invite_nonce: member.invite_nonce.clone(),
                },
            );
        }
    }

    Ok(envi)
}

/// Re-derive the in-memory State from the automerge document.
/// Copies footer from `current` so hints and status are preserved.
/// Always resets rotate_dek and pending_grants.
pub fn derive_state(doc: &AutoCommit, session: &Session, current: &State) -> State {
    let envi: EnviDocument = hydrate(doc).unwrap_or_default();

    let mut secrets: Vec<Secret> = list_secrets(doc, &session.dek)
        .unwrap_or_default()
        .into_iter()
        .map(|s| Secret {
            id: s.id,
            name: s.name,
            value: s.value,
            description: s.description,
            tags: s.tags,
        })
        .collect();
    secrets.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let mut members: Vec<Member> = envi
        .members
        .values()
        .map(|m| Member {
            id: m.id.clone(),
            email: m.email.clone(),
            public_key: m.public_key.clone(),
            wrapped_dek: m.wrapped_dek.clone(),
            signing_key: m.signing_key.clone(),
            key_mac: m.key_mac.clone(),
            invite_mac: m.invite_mac.clone(),
            invite_nonce: m.invite_nonce.clone(),
            is_me: m.id == session.member_id,
        })
        .collect();
    members.sort_by(|a, b| a.email.cmp(&b.email));

    State {
        device_name: current.device_name.clone(),
        vault_id: current.vault_id.clone(),
        vault_name: current.vault_name.clone(),
        storage_config: current.storage_config.clone(),
        footer: current.footer.clone(),
        secrets,
        members,
        pending_grants: vec![],
        rotate_dek: false,
        private_key: current.private_key,
        selected_tags: current.selected_tags.clone(),
    }
}
