use envi::commands::exec::{filter_by_tag, find_vault};
use lib::{
    config::VaultConfig,
    error::Error,
    storage::{FsConfig, StorageConfig},
    types::PlaintextSecret,
};

fn make_vault(name: &str) -> VaultConfig {
    VaultConfig {
        id: format!("id-{name}"),
        name: name.to_string(),
        storage: StorageConfig::Fs(FsConfig { root: "/tmp".to_string() }),
    }
}

fn make_secret(name: &str, value: &str, tags: &[&str]) -> PlaintextSecret {
    PlaintextSecret {
        id: name.to_string(),
        name: name.to_string(),
        value: value.to_string(),
        description: String::new(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
    }
}

// --- find_vault ---

#[test]
fn find_vault_returns_matching_vault() {
    let vaults = vec![make_vault("prod"), make_vault("staging")];
    let v = find_vault(vaults, "prod").unwrap();
    assert_eq!(v.name, "prod");
}

#[test]
fn find_vault_is_case_insensitive() {
    let vaults = vec![make_vault("Production")];
    let v = find_vault(vaults, "production").unwrap();
    assert_eq!(v.name, "Production");
}

#[test]
fn find_vault_returns_error_when_not_found() {
    let vaults = vec![make_vault("prod")];
    let err = find_vault(vaults, "missing").unwrap_err();
    assert!(matches!(err, Error::Other(_)));
}

#[test]
fn find_vault_error_message_contains_vault_name() {
    let vaults = vec![make_vault("prod")];
    let err = find_vault(vaults, "missing").unwrap_err();
    assert!(err.to_string().contains("missing"));
}

// --- filter_by_tag ---

#[test]
fn filter_by_tag_none_returns_all() {
    let secrets = vec![make_secret("A", "1", &["x"]), make_secret("B", "2", &[])];
    let result = filter_by_tag(secrets, None);
    assert_eq!(result.len(), 2);
}

#[test]
fn filter_by_tag_keeps_only_matching() {
    let secrets = vec![
        make_secret("A", "1", &["prod"]),
        make_secret("B", "2", &["dev"]),
        make_secret("C", "3", &["prod", "dev"]),
    ];
    let result = filter_by_tag(secrets, Some("prod"));
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|s| s.tags.iter().any(|t| t == "prod")));
}

#[test]
fn filter_by_tag_returns_empty_when_no_match() {
    let secrets = vec![make_secret("A", "1", &["dev"])];
    let result = filter_by_tag(secrets, Some("prod"));
    assert!(result.is_empty());
}

#[test]
fn filter_by_tag_excludes_untagged_secrets() {
    let secrets = vec![make_secret("A", "1", &[]), make_secret("B", "2", &["prod"])];
    let result = filter_by_tag(secrets, Some("prod"));
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "B");
}
