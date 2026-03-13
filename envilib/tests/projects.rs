mod common;

use envilib::{
    projects::{add_project, list_projects, remove_project, set_project_secrets, update_project},
    secrets::{add_secret, PlaintextSecretFields},
};

#[test]
fn add_and_list_project() {
    let mut ws = common::setup();
    add_project(&mut ws.doc, "backend").unwrap();
    let projects = list_projects(&ws.doc).unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "backend");
}

#[test]
fn update_project_name() {
    let mut ws = common::setup();
    add_project(&mut ws.doc, "old-name").unwrap();
    let id = list_projects(&ws.doc).unwrap()[0].id.clone();
    update_project(&mut ws.doc, &id, "new-name").unwrap();
    let projects = list_projects(&ws.doc).unwrap();
    assert_eq!(projects[0].name, "new-name");
}

#[test]
fn test_remove_project() {
    let mut ws = common::setup();
    add_project(&mut ws.doc, "to-delete").unwrap();
    let id = list_projects(&ws.doc).unwrap()[0].id.clone();
    remove_project(&mut ws.doc, &id).unwrap();
    assert!(list_projects(&ws.doc).unwrap().is_empty());
}

#[test]
fn set_project_secrets_associates_secret_ids() {
    let mut ws = common::setup();
    add_project(&mut ws.doc, "myapp").unwrap();
    let project_id = list_projects(&ws.doc).unwrap()[0].id.clone();

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
    let secret_id = envilib::secrets::list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();

    set_project_secrets(&mut ws.doc, &project_id, vec![secret_id.clone()]).unwrap();

    let projects = list_projects(&ws.doc).unwrap();
    assert_eq!(projects[0].secret_ids, vec![secret_id]);
}

#[test]
fn remove_secret_also_removes_it_from_projects() {
    let mut ws = common::setup();
    add_project(&mut ws.doc, "myapp").unwrap();
    let project_id = list_projects(&ws.doc).unwrap()[0].id.clone();

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
    let secret_id = envilib::secrets::list_secrets(&ws.doc, &ws.dek).unwrap()[0].id.clone();
    set_project_secrets(&mut ws.doc, &project_id, vec![secret_id.clone()]).unwrap();

    envilib::secrets::remove_secret(&mut ws.doc, &secret_id).unwrap();

    let projects = list_projects(&ws.doc).unwrap();
    assert!(projects[0].secret_ids.is_empty(), "secret should be removed from project");
}

#[test]
fn update_nonexistent_project_returns_error() {
    let mut ws = common::setup();
    assert!(update_project(&mut ws.doc, "nonexistent-id", "name").is_err());
}
