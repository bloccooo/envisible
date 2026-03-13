mod common;

use lib::{
    namespaces::{add_namespace, list_namespaces, remove_namespace, set_namespace_secrets, update_namespace},
    secrets::{add_secret, PlaintextSecretFields},
};

#[test]
fn add_and_list_namespace() {
    let mut ws = common::setup();
    add_namespace(&mut ws.doc, "backend").unwrap();
    let namespaces = list_namespaces(&ws.doc).unwrap();
    assert_eq!(namespaces.len(), 1);
    assert_eq!(namespaces[0].name, "backend");
}

#[test]
fn update_namespace_name() {
    let mut ws = common::setup();
    add_namespace(&mut ws.doc, "old-name").unwrap();
    let id = list_namespaces(&ws.doc).unwrap()[0].id.clone();
    update_namespace(&mut ws.doc, &id, "new-name").unwrap();
    let namespaces = list_namespaces(&ws.doc).unwrap();
    assert_eq!(namespaces[0].name, "new-name");
}

#[test]
fn test_remove_namespace() {
    let mut ws = common::setup();
    add_namespace(&mut ws.doc, "to-delete").unwrap();
    let id = list_namespaces(&ws.doc).unwrap()[0].id.clone();
    remove_namespace(&mut ws.doc, &id).unwrap();
    assert!(list_namespaces(&ws.doc).unwrap().is_empty());
}

#[test]
fn set_namespace_secrets_associates_secret_ids() {
    let mut ws = common::setup();
    add_namespace(&mut ws.doc, "myapp").unwrap();
    let namespace_id = list_namespaces(&ws.doc).unwrap()[0].id.clone();

    add_secret(
        &mut ws.doc,
        &ws.dek,
        PlaintextSecretFields {
            name: "DB_URL".to_string(),
            value: "postgres://...".to_string(),
            description: String::new(),
            tags: vec![],
        },
    )
    .unwrap();
    let secret_id = lib::secrets::list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();

    set_namespace_secrets(&mut ws.doc, &namespace_id, vec![secret_id.clone()]).unwrap();

    let namespaces = list_namespaces(&ws.doc).unwrap();
    assert_eq!(namespaces[0].secret_ids, vec![secret_id]);
}

#[test]
fn remove_secret_also_removes_it_from_namespaces() {
    let mut ws = common::setup();
    add_namespace(&mut ws.doc, "myapp").unwrap();
    let namespace_id = list_namespaces(&ws.doc).unwrap()[0].id.clone();

    add_secret(
        &mut ws.doc,
        &ws.dek,
        PlaintextSecretFields {
            name: "KEY".to_string(),
            value: "val".to_string(),
            description: String::new(),
            tags: vec![],
        },
    )
    .unwrap();
    let secret_id = lib::secrets::list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();
    set_namespace_secrets(&mut ws.doc, &namespace_id, vec![secret_id.clone()]).unwrap();

    lib::secrets::remove_secret(&mut ws.doc, &secret_id).unwrap();

    let namespaces = list_namespaces(&ws.doc).unwrap();
    assert!(namespaces[0].secret_ids.is_empty(), "secret should be removed from namespace");
}

#[test]
fn update_nonexistent_namespace_returns_error() {
    let mut ws = common::setup();
    assert!(update_namespace(&mut ws.doc, "nonexistent-id", "name").is_err());
}
