use std::collections::HashSet;
use std::sync::Arc;

use lib::storage::StorageConfig;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub value: String,
    pub description: String,
    pub tags: Vec<String>,
}

/// Mirrors lib::types::Member but with plaintext fields — lossless representation of the doc.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub id: String,
    pub email: String,
    // Crypto fields from the doc (preserved as-is; empty wrapped_dek = pending)
    pub public_key: String,
    pub wrapped_dek: String,
    pub signing_key: String,
    pub key_mac: String,
    pub invite_mac: String,
    pub invite_nonce: String,
    // Runtime: not in doc
    pub is_me: bool,
}

impl Member {
    pub fn is_pending(&self) -> bool {
        self.wrapped_dek.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FooterStatus {
    Idle,
    Syncing,
    Ok(String),
    Error(String),
}

#[derive(Debug, Clone)]
pub struct FooterState {
    pub hint: String,
    pub hint_is_warning: bool,
    pub status: FooterStatus,
}

impl Default for FooterState {
    fn default() -> Self {
        Self {
            hint: String::new(),
            hint_is_warning: false,
            status: FooterStatus::Idle,
        }
    }
}

#[derive(Debug, Clone)]
pub struct State {
    pub device_name: String,
    pub vault_id: String,
    pub vault_name: String,
    pub storage_config: StorageConfig,
    pub footer: FooterState,
    pub secrets: Vec<Secret>,
    pub members: Vec<Member>,
    /// Member IDs to grant access to (main loop fills wrapped_dek using DEK).
    /// Always empty after derive_state.
    pub pending_grants: Vec<String>,
    /// Signal the main loop to rotate the DEK. Always false after derive_state.
    pub rotate_dek: bool,
    /// X25519 private key — in-memory only, never written to disk.
    /// Used to generate invite tokens and verify invite MACs.
    pub private_key: [u8; 32],
}

impl State {
    /// Clone the inner State out of an Arc.
    pub fn cloned(arc: &Arc<Self>) -> Self {
        (**arc).clone()
    }

    /// Derive sorted unique tags from all secrets.
    pub fn tags(&self) -> Vec<String> {
        let mut tag_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for s in &self.secrets {
            for t in &s.tags {
                tag_set.insert(t.clone());
            }
        }
        tag_set.into_iter().collect()
    }

    pub fn with_footer_hint(mut self, hint: impl Into<String>) -> Self {
        self.footer.hint = hint.into();
        self.footer.hint_is_warning = false;
        self
    }

    pub fn with_footer_warning(mut self, hint: impl Into<String>) -> Self {
        self.footer.hint = hint.into();
        self.footer.hint_is_warning = true;
        self
    }

    pub fn with_footer_status(mut self, status: FooterStatus) -> Self {
        self.footer.status = status;
        self
    }

    /// Append a new secret with a fresh UUID.
    pub fn with_secret_added(
        mut self,
        name: String,
        value: String,
        description: String,
        tags: Vec<String>,
    ) -> Self {
        self.secrets.push(Secret {
            id: Uuid::now_v7().to_string(),
            name,
            value,
            description,
            tags,
        });
        self.secrets
            .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self
    }

    /// Replace the fields of an existing secret in-place.
    pub fn with_secret_updated(
        mut self,
        id: String,
        name: String,
        value: String,
        description: String,
        tags: Vec<String>,
    ) -> Self {
        if let Some(s) = self.secrets.iter_mut().find(|s| s.id == id) {
            s.name = name;
            s.value = value;
            s.description = description;
            s.tags = tags;
        }
        self.secrets
            .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self
    }

    /// Remove the secret with the given id.
    pub fn with_secret_deleted(mut self, id: &str) -> Self {
        self.secrets.retain(|s| s.id != id);
        self
    }

    /// Rename a tag across all secrets.
    pub fn with_tag_renamed(mut self, old: &str, new_name: String) -> Self {
        for s in &mut self.secrets {
            for t in &mut s.tags {
                if t == old {
                    *t = new_name.clone();
                }
            }
        }
        self
    }

    /// Remove a tag from all secrets.
    pub fn with_tag_deleted(mut self, tag: &str) -> Self {
        for s in &mut self.secrets {
            s.tags.retain(|t| t != tag);
        }
        self
    }

    /// Update tag assignments: add the tag to selected secrets, remove from others.
    pub fn with_tag_assignments(mut self, tag: &str, selected_ids: &HashSet<String>) -> Self {
        for s in &mut self.secrets {
            let has = selected_ids.contains(&s.id);
            let had = s.tags.iter().any(|t| t == tag);
            if has && !had {
                s.tags.push(tag.to_string());
            } else if !has && had {
                s.tags.retain(|t| t != tag);
            }
        }
        self
    }

    /// Remove the member with the given id.
    pub fn with_member_removed(mut self, id: &str) -> Self {
        self.members.retain(|m| m.id != id);
        self
    }

    /// Signal the main loop to grant access to this member (fill wrapped_dek using DEK).
    pub fn with_member_granted(mut self, id: &str) -> Self {
        if self.members.iter().any(|m| m.id == id) {
            self.pending_grants.push(id.to_string());
        }
        self
    }

    /// Signal the main loop to rotate the DEK.
    pub fn with_dek_rotated(mut self) -> Self {
        self.rotate_dek = true;
        self
    }
}
