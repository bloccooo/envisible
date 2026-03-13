mod common;

use envilib::{
    crypto::generate_dek,
    secrets::{add_secret, list_secrets, remove_secret, update_secret, PlaintextSecretFields},
};

fn fields(name: &str, value: &str) -> PlaintextSecretFields {
    PlaintextSecretFields {
        name: name.to_string(),
        value: value.to_string(),
        description: String::new(),
        tags: vec![],
    }
}

#[test]
fn add_and_list_secret() {
    let mut ws = common::setup();
    add_secret(&mut ws.doc, &ws.dek, fields("API_KEY", "secret123")).unwrap();
    let secrets = list_secrets(&ws.doc, &ws.dek).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "API_KEY");
    assert_eq!(secrets[0].value, "secret123");
}

#[test]
fn add_multiple_secrets() {
    let mut ws = common::setup();
    add_secret(&mut ws.doc, &ws.dek, fields("KEY_A", "val_a")).unwrap();
    add_secret(&mut ws.doc, &ws.dek, fields("KEY_B", "val_b")).unwrap();
    let secrets = list_secrets(&ws.doc, &ws.dek).unwrap();
    assert_eq!(secrets.len(), 2);
}

#[test]
fn update_secret_changes_value() {
    let mut ws = common::setup();
    add_secret(&mut ws.doc, &ws.dek, fields("TOKEN", "old-value")).unwrap();
    let id = list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();
    update_secret(&mut ws.doc, &ws.dek, &id, fields("TOKEN", "new-value")).unwrap();
    let secrets = list_secrets(&ws.doc, &ws.dek).unwrap();
    assert_eq!(secrets[0].value, "new-value");
}

#[test]
fn remove_secret_deletes_it() {
    let mut ws = common::setup();
    add_secret(&mut ws.doc, &ws.dek, fields("TO_DELETE", "v")).unwrap();
    let id = list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();
    remove_secret(&mut ws.doc, &id).unwrap();
    assert!(list_secrets(&ws.doc, &ws.dek).unwrap().is_empty());
}

#[test]
fn secret_with_tags_roundtrips() {
    let mut ws = common::setup();
    add_secret(
        &mut ws.doc,
        &ws.dek,
        PlaintextSecretFields {
            name: "KEY".to_string(),
            value: "val".to_string(),
            description: "desc".to_string(),
            tags: vec!["prod".to_string(), "api".to_string()],
        },
    )
    .unwrap();
    let secrets = list_secrets(&ws.doc, &ws.dek).unwrap();
    assert_eq!(secrets[0].description, "desc");
    assert_eq!(secrets[0].tags, vec!["prod", "api"]);
}

#[test]
fn list_secrets_fails_with_wrong_dek() {
    let mut ws = common::setup();
    add_secret(&mut ws.doc, &ws.dek, fields("KEY", "value")).unwrap();
    let wrong_dek = generate_dek();
    assert!(list_secrets(&ws.doc, &wrong_dek).is_err());
}

#[test]
fn update_nonexistent_secret_returns_error() {
    let mut ws = common::setup();
    let err = update_secret(&mut ws.doc, &ws.dek, "nonexistent-id", fields("K", "v"));
    assert!(err.is_err());
}
