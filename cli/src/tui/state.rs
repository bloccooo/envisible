use lib::storage::StorageConfig;

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
}

impl State {
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
}
