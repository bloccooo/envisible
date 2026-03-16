#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub value: String,
    pub description: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub email: String,
    pub is_me: bool,
    pub is_pending: bool,
}

use lib::storage::{FsConfig, StorageConfig};

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
        Self { hint: String::new(), hint_is_warning: false, status: FooterStatus::Idle }
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
}

impl State {
    pub fn mock() -> Self {
        Self {
            device_name: "MacBook Pro".to_string(),
            vault_id: "mock-vault-id".to_string(),
            vault_name: "my-vault".to_string(),
            storage_config: StorageConfig::Fs(FsConfig { root: "~/.envi/mock-vault".to_string() }),
            footer: FooterState::default(),
            secrets: vec![
                Secret {
                    id: "1".to_string(),
                    name: "AWS Access Key".to_string(),
                    value: "AKIAIOSFODNN7EXAMPLE".to_string(),
                    description: "AWS production credentials".to_string(),
                    tags: vec!["aws".to_string(), "prod".to_string()],
                },
                Secret {
                    id: "2".to_string(),
                    name: "Database URL".to_string(),
                    value: "postgres://user:pass@localhost:5432/db".to_string(),
                    description: "Production database".to_string(),
                    tags: vec!["db".to_string(), "prod".to_string()],
                },
                Secret {
                    id: "3".to_string(),
                    name: "GitHub Token".to_string(),
                    value: "ghp_xxxxxxxxxxxxxxxxxxxx".to_string(),
                    description: "Personal access token".to_string(),
                    tags: vec!["dev".to_string(), "github".to_string()],
                },
                Secret {
                    id: "4".to_string(),
                    name: "Stripe Secret Key".to_string(),
                    value: "sk_live_xxxxxxxxxxxx".to_string(),
                    description: "Stripe payment API key".to_string(),
                    tags: vec!["payments".to_string(), "prod".to_string()],
                },
            ],
            members: vec![
                Member {
                    id: "me".to_string(),
                    email: "you@example.com".to_string(),
                    is_me: true,
                    is_pending: false,
                },
                Member {
                    id: "alice".to_string(),
                    email: "alice@example.com".to_string(),
                    is_me: false,
                    is_pending: false,
                },
                Member {
                    id: "bob".to_string(),
                    email: "bob@example.com".to_string(),
                    is_me: false,
                    is_pending: true,
                },
            ],
        }
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

    pub fn with_secret_added(mut self, name: String, value: String, description: String, tags: Vec<String>) -> Self {
        let id = (self.secrets.len() + 1).to_string();
        self.secrets.push(Secret { id, name, value, description, tags });
        self.secrets.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self
    }

    pub fn with_secret_updated(mut self, id: &str, name: String, value: String, description: String, tags: Vec<String>) -> Self {
        if let Some(s) = self.secrets.iter_mut().find(|s| s.id == id) {
            s.name = name;
            s.value = value;
            s.description = description;
            s.tags = tags;
        }
        self.secrets.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        self
    }

    pub fn with_secret_deleted(mut self, id: &str) -> Self {
        self.secrets.retain(|s| s.id != id);
        self
    }

    pub fn with_tag_renamed(mut self, old: &str, new_name: &str) -> Self {
        for s in &mut self.secrets {
            for t in &mut s.tags {
                if t == old {
                    *t = new_name.to_string();
                }
            }
        }
        self
    }

    pub fn with_tag_deleted(mut self, tag: &str) -> Self {
        for s in &mut self.secrets {
            s.tags.retain(|t| t != tag);
        }
        self
    }

    /// Returns a new state with the footer hint set (normal DarkGray style).
    pub fn with_footer_hint(mut self, hint: impl Into<String>) -> Self {
        self.footer.hint = hint.into();
        self.footer.hint_is_warning = false;
        self
    }

    /// Returns a new state with the footer hint set in warning/yellow style (e.g. confirmations).
    pub fn with_footer_warning(mut self, hint: impl Into<String>) -> Self {
        self.footer.hint = hint.into();
        self.footer.hint_is_warning = true;
        self
    }
}
