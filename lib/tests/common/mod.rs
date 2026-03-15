#![allow(dead_code)]

use automerge::AutoCommit;
use autosurgeon::reconcile;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{
        compute_key_mac, derive_private_key, derive_signing_key, generate_dek, get_public_key,
        wrap_dek,
    },
    types::{EnviDocument, Member},
};
use std::collections::HashMap;

pub const PASSPHRASE: &str = "test-passphrase";
pub const VAULT_ID: &str = "test-vault-id";
pub const MEMBER_ID: &str = "test-member-id";

pub struct Vault {
    pub doc: AutoCommit,
    pub dek: [u8; 32],
    pub private_key: [u8; 32],
    pub signing_key: ed25519_dalek::SigningKey,
    pub member_id: String,
}

/// Build an in-memory vault with one fully-active member.
pub fn setup() -> Vault {
    let private_key = derive_private_key(PASSPHRASE, VAULT_ID, MEMBER_ID).unwrap();
    let public_key = get_public_key(&private_key);
    let public_key_b64 = B64.encode(public_key);
    let signing_key = derive_signing_key(&private_key);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().as_bytes());

    let dek = generate_dek();
    let wrapped_dek = wrap_dek(&dek, &public_key).unwrap();
    let key_mac = compute_key_mac(&dek, MEMBER_ID, &public_key_b64, &verifying_key_b64);

    let mut members = HashMap::new();
    members.insert(
        MEMBER_ID.to_string(),
        Member {
            id: MEMBER_ID.to_string(),
            email: "test@example.com".to_string(),
            public_key: public_key_b64,
            wrapped_dek,
            signing_key: verifying_key_b64,
            key_mac,
        },
    );

    let state = EnviDocument {
        id: VAULT_ID.to_string(),
        name: "Test Vault".to_string(),
        doc_version: 1,
        members,
        secrets: HashMap::new(),
        document_signature: String::new(),
    };

    let mut doc = AutoCommit::new();
    reconcile(&mut doc, &state).unwrap();

    Vault {
        doc,
        dek,
        private_key,
        signing_key,
        member_id: MEMBER_ID.to_string(),
    }
}
