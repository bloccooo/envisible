mod common;

use automerge::AutoCommit;
use autosurgeon::reconcile;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{
        compute_key_mac, derive_private_key, derive_signing_key, generate_dek, get_public_key,
        wrap_dek,
    },
    members::{remove_member, rotate_dek},
    secrets::{add_secret, list_secrets, PlaintextSecretFields},
    store::unlock,
    types::{EnviDocument, Member},
};
use std::collections::HashMap;

fn make_member(id: &str, passphrase: &str, vault_id: &str, dek: &[u8; 32]) -> Member {
    let private_key = derive_private_key(passphrase, vault_id, id).unwrap();
    let public_key = get_public_key(&private_key);
    let public_key_b64 = B64.encode(public_key);
    let signing_key = derive_signing_key(&private_key);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().as_bytes());
    let wrapped_dek = wrap_dek(dek, &public_key).unwrap();
    let key_mac = compute_key_mac(dek, id, &public_key_b64, &verifying_key_b64);
    Member {
        id: id.to_string(),
        email: format!("{id}@example.com"),
        public_key: public_key_b64,
        wrapped_dek,
        signing_key: verifying_key_b64,
        key_mac,
    }
}

const WS_ID: &str = "test-vault-id";

/// Build a two-member vault.
fn two_member_vault() -> (AutoCommit, [u8; 32]) {
    let dek = generate_dek();
    let m1 = make_member("member-one-id", "pass-m1", WS_ID, &dek);
    let m2 = make_member("member-two-id", "pass-m2", WS_ID, &dek);

    let mut members = HashMap::new();
    members.insert("member-one-id".to_string(), m1);
    members.insert("member-two-id".to_string(), m2);

    let state = EnviDocument {
        id: WS_ID.to_string(),
        name: "Two Member Vault".to_string(),
        doc_version: 1,
        members,

        secrets: HashMap::new(),
        document_signature: String::new(),
    };
    let mut doc = AutoCommit::new();
    reconcile(&mut doc, &state).unwrap();
    (doc, dek)
}

#[test]
fn rotate_dek_secrets_still_decryptable() {
    let mut ws = common::setup();
    add_secret(
        &mut ws.doc,
        &ws.dek,
        PlaintextSecretFields {
            name: "KEY".to_string(),
            value: "original-value".to_string(),
            description: String::new(),
            tags: vec![],
        },
    )
    .unwrap();

    let new_dek = rotate_dek(&mut ws.doc, &ws.dek).unwrap();
    assert_ne!(ws.dek, new_dek, "DEK should change after rotation");

    let secrets = list_secrets(&ws.doc, &new_dek).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].value, "original-value");
}

#[test]
fn rotate_dek_old_dek_can_no_longer_decrypt() {
    let mut ws = common::setup();
    add_secret(
        &mut ws.doc,
        &ws.dek,
        PlaintextSecretFields {
            name: "KEY".to_string(),
            value: "value".to_string(),
            description: String::new(),
            tags: vec![],
        },
    )
    .unwrap();

    let old_dek = ws.dek;
    rotate_dek(&mut ws.doc, &ws.dek).unwrap();

    assert!(
        list_secrets(&ws.doc, &old_dek).is_err(),
        "old DEK should not decrypt after rotation"
    );
}

#[test]
fn rotate_dek_member_can_still_unlock() {
    let mut ws = common::setup();
    let new_dek = rotate_dek(&mut ws.doc, &ws.dek).unwrap();
    let session = unlock(&ws.doc, &ws.private_key).unwrap();
    assert_eq!(session.dek, new_dek);
}

#[test]
fn remove_member_removes_them_from_document() {
    let (mut doc, dek) = two_member_vault();
    remove_member(&mut doc, &dek, "member-two-id").unwrap();

    let private_key = derive_private_key("pass-m2", WS_ID, "member-two-id").unwrap();
    let err = unlock(&doc, &private_key)
        .err()
        .expect("should return an error");
    assert!(matches!(err, lib::error::Error::NotAMember));
}

#[test]
fn remove_member_rotates_dek_so_removed_member_loses_access() {
    let (mut doc, old_dek) = two_member_vault();
    add_secret(
        &mut doc,
        &old_dek,
        PlaintextSecretFields {
            name: "KEY".to_string(),
            value: "secret".to_string(),
            description: String::new(),
            tags: vec![],
        },
    )
    .unwrap();

    let new_dek = remove_member(&mut doc, &old_dek, "member-two-id").unwrap();
    assert_ne!(old_dek, new_dek, "DEK should be rotated after removal");

    // Remaining member can still decrypt with their private key
    let private_key_m1 = derive_private_key("pass-m1", WS_ID, "member-one-id").unwrap();
    let session = unlock(&doc, &private_key_m1).unwrap();
    let secrets = list_secrets(&doc, &session.dek).unwrap();
    assert_eq!(secrets[0].value, "secret");
}
