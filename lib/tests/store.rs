mod common;

use autosurgeon::reconcile;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{derive_private_key, get_public_key, wrap_dek},
    store::unlock,
    types::{EnviDocument, Member},
};
use std::collections::HashMap;

#[test]
fn unlock_with_valid_key_succeeds() {
    let ws = common::setup();
    let session = unlock(&ws.doc, &ws.private_key).unwrap();
    assert_eq!(session.member_id, ws.member_id);
}

#[test]
fn unlock_returns_correct_dek() {
    let ws = common::setup();
    let session = unlock(&ws.doc, &ws.private_key).unwrap();
    assert_eq!(session.dek, ws.dek);
}

#[test]
fn unlock_with_wrong_passphrase_returns_not_a_member() {
    let ws = common::setup();
    let wrong_key = derive_private_key("wrong-passphrase", common::WORKSPACE_ID, common::MEMBER_ID).unwrap();
    let err = unlock(&ws.doc, &wrong_key).err().expect("should return an error");
    assert!(matches!(err, lib::error::Error::NotAMember));
}

#[test]
fn unlock_with_wrong_member_id_returns_not_a_member() {
    let ws = common::setup();
    let wrong_key = derive_private_key(common::PASSPHRASE, common::WORKSPACE_ID, "other-member-id").unwrap();
    let err = unlock(&ws.doc, &wrong_key).err().expect("should return an error");
    assert!(matches!(err, lib::error::Error::NotAMember));
}

#[test]
fn unlock_pending_member_returns_access_pending() {
    use automerge::AutoCommit;

    let private_key = derive_private_key("pending-pass", "ws", "pending-member").unwrap();
    let public_key = get_public_key(&private_key);
    let public_key_b64 = B64.encode(public_key);

    let mut members = HashMap::new();
    members.insert(
        "pending-member".to_string(),
        Member {
            id: "pending-member".to_string(),
            email: "p@example.com".to_string(),
            public_key: public_key_b64,
            wrapped_dek: String::new(), // pending — no DEK access yet
            signing_key: String::new(),
            key_mac: String::new(),
        },
    );

    let state = EnviDocument {
        id: "ws".to_string(),
        name: "ws".to_string(),
        doc_version: 1,
        members,
        namespaces: HashMap::new(),
        secrets: HashMap::new(),
        document_signature: String::new(),
    };
    let mut doc = AutoCommit::new();
    reconcile(&mut doc, &state).unwrap();

    let err = unlock(&doc, &private_key).err().expect("should return an error");
    assert!(matches!(err, lib::error::Error::AccessPending));
}

#[test]
fn unlock_detects_tampered_key_mac() {
    use automerge::AutoCommit;
    use lib::crypto::{compute_key_mac, derive_signing_key, generate_dek};

    // Set up a member with a valid key MAC ...
    let private_key = derive_private_key("passphrase", "workspace-id", "member-one-id").unwrap();
    let public_key = get_public_key(&private_key);
    let public_key_b64 = B64.encode(public_key);
    let signing_key = derive_signing_key(&private_key);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().as_bytes());

    let dek = generate_dek();
    let wrapped_dek = wrap_dek(&dek, &public_key).unwrap();
    let key_mac = compute_key_mac(&dek, "member-one-id", &public_key_b64, &verifying_key_b64);

    // ... but another member with a tampered (wrong) key MAC
    let private_key2 = derive_private_key("passphrase", "workspace-id", "member-two-id").unwrap();
    let public_key2 = get_public_key(&private_key2);
    let public_key2_b64 = B64.encode(public_key2);
    let signing_key2 = derive_signing_key(&private_key2);
    let verifying_key2_b64 = B64.encode(signing_key2.verifying_key().as_bytes());
    let wrapped_dek2 = wrap_dek(&dek, &public_key2).unwrap();
    let bad_mac = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();

    let mut members = HashMap::new();
    members.insert(
        "member-one-id".to_string(),
        Member {
            id: "member-one-id".to_string(),
            email: "m1@example.com".to_string(),
            public_key: public_key_b64,
            wrapped_dek,
            signing_key: verifying_key_b64,
            key_mac,
        },
    );
    members.insert(
        "member-two-id".to_string(),
        Member {
            id: "member-two-id".to_string(),
            email: "m2@example.com".to_string(),
            public_key: public_key2_b64,
            wrapped_dek: wrapped_dek2,
            signing_key: verifying_key2_b64,
            key_mac: bad_mac,
        },
    );

    let state = EnviDocument {
        id: "workspace-id".to_string(),
        name: "Workspace".to_string(),
        doc_version: 1,
        members,
        namespaces: HashMap::new(),
        secrets: HashMap::new(),
        document_signature: String::new(),
    };
    let mut doc = AutoCommit::new();
    reconcile(&mut doc, &state).unwrap();

    let err = unlock(&doc, &private_key).err().expect("should return an error");
    assert!(matches!(err, lib::error::Error::InvalidKeyMac(_)));
}
