mod common;

use lib::{
    invite::{generate_invite, parse_invite, VaultPayload},
    storage::{FsConfig, StorageConfig},
};

fn fs_storage() -> StorageConfig {
    StorageConfig::Fs(FsConfig { root: "/tmp/test".to_string() })
}

#[test]
fn generate_and_parse_invite_roundtrip() {
    let storage = fs_storage();
    let vault = VaultPayload {
        id: "ws-123".to_string(),
        name: "My Vault".to_string(),
    };
    let link = generate_invite(&storage, vault).unwrap();
    let payload = parse_invite(&link).unwrap();
    assert_eq!(payload.vault.id, "ws-123");
    assert_eq!(payload.vault.name, "My Vault");
}

#[test]
fn invite_link_starts_with_prefix() {
    let link = generate_invite(
        &fs_storage(),
        VaultPayload { id: "id".to_string(), name: "name".to_string() },
    )
    .unwrap();
    assert!(link.starts_with("envi-invite:"));
}

#[test]
fn parse_invalid_link_returns_error() {
    assert!(parse_invite("not-an-invite-link").is_err());
    assert!(parse_invite("envi-invite:!!!invalid_base64!!!").is_err());
    assert!(parse_invite("envi-invite:bm90anNvbg==").is_err()); // valid b64, not valid JSON
}
