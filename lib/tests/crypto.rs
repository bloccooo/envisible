mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{
        canonical_document_bytes, compute_key_mac, decrypt_field, derive_private_key,
        derive_signing_key, encrypt_field, generate_dek, get_public_key, sign_document,
        unwrap_dek, verify_document_signature, verify_key_mac, wrap_dek,
    },
    types::{EnviDocument, Member},
};
use std::collections::HashMap;

// --- Key derivation ---

#[test]
fn derive_private_key_is_deterministic() {
    let k1 = derive_private_key("pass", "ws", "member").unwrap();
    let k2 = derive_private_key("pass", "ws", "member").unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn derive_private_key_differs_by_passphrase() {
    let k1 = derive_private_key("passA", "ws", "member").unwrap();
    let k2 = derive_private_key("passB", "ws", "member").unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn derive_private_key_differs_by_workspace_id() {
    let k1 = derive_private_key("pass", "ws1", "member").unwrap();
    let k2 = derive_private_key("pass", "ws2", "member").unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn derive_private_key_differs_by_member_id() {
    let k1 = derive_private_key("pass", "ws", "member-1").unwrap();
    let k2 = derive_private_key("pass", "ws", "member-2").unwrap();
    assert_ne!(k1, k2);
}

// --- DEK wrap / unwrap ---

#[test]
fn wrap_unwrap_dek_roundtrip() {
    let private_key = derive_private_key("passphrase", "workspace-id", "member-id").unwrap();
    let public_key = get_public_key(&private_key);
    let dek = generate_dek();
    let wrapped = wrap_dek(&dek, &public_key).unwrap();
    let recovered = unwrap_dek(&wrapped, &private_key).unwrap();
    assert_eq!(dek, recovered);
}

#[test]
fn unwrap_dek_fails_with_wrong_private_key() {
    let private_key = derive_private_key("passphrase", "workspace-id", "member-id").unwrap();
    let public_key = get_public_key(&private_key);
    let dek = generate_dek();
    let wrapped = wrap_dek(&dek, &public_key).unwrap();

    let wrong_key = derive_private_key("other-pass", "workspace-id", "member-id").unwrap();
    assert!(unwrap_dek(&wrapped, &wrong_key).is_err());
}

// --- Field encrypt / decrypt ---

#[test]
fn encrypt_decrypt_field_roundtrip() {
    let dek = generate_dek();
    let plaintext = "my secret value";
    let encrypted = encrypt_field(plaintext, &dek).unwrap();
    let decrypted = decrypt_field(&encrypted, &dek).unwrap();
    assert_eq!(plaintext, decrypted);
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    let dek = generate_dek();
    let c1 = encrypt_field("value", &dek).unwrap();
    let c2 = encrypt_field("value", &dek).unwrap();
    assert_ne!(c1, c2, "each encryption should use a fresh random nonce");
}

#[test]
fn decrypt_field_fails_with_wrong_dek() {
    let dek = generate_dek();
    let encrypted = encrypt_field("secret", &dek).unwrap();
    let wrong_dek = generate_dek();
    assert!(decrypt_field(&encrypted, &wrong_dek).is_err());
}

// --- Document signing ---

#[test]
fn sign_verify_document_roundtrip() {
    let seed = [7u8; 32];
    let signing_key = derive_signing_key(&seed);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().as_bytes());
    let canonical = b"canonical document content";
    let sig = sign_document(canonical, "member-1", &signing_key);
    assert!(verify_document_signature(canonical, &sig, &verifying_key_b64).is_ok());
}

#[test]
fn verify_fails_on_tampered_content() {
    let seed = [7u8; 32];
    let signing_key = derive_signing_key(&seed);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().as_bytes());
    let sig = sign_document(b"original content", "member-1", &signing_key);
    assert!(verify_document_signature(b"tampered content", &sig, &verifying_key_b64).is_err());
}

#[test]
fn verify_fails_with_wrong_verifying_key() {
    let signing_key = derive_signing_key(&[7u8; 32]);
    let other_key = derive_signing_key(&[8u8; 32]);
    let wrong_verifying_b64 = B64.encode(other_key.verifying_key().as_bytes());
    let sig = sign_document(b"content", "member-1", &signing_key);
    assert!(verify_document_signature(b"content", &sig, &wrong_verifying_b64).is_err());
}

// --- Key MAC ---

#[test]
fn key_mac_roundtrip() {
    let dek = [1u8; 32];
    let mac = compute_key_mac(&dek, "m1", "pubkey_b64", "signkey_b64");
    assert!(verify_key_mac(&dek, "m1", "pubkey_b64", "signkey_b64", &mac).is_ok());
}

#[test]
fn key_mac_fails_with_wrong_dek() {
    let dek = [1u8; 32];
    let mac = compute_key_mac(&dek, "m1", "pubkey_b64", "signkey_b64");
    let wrong_dek = [2u8; 32];
    assert!(verify_key_mac(&wrong_dek, "m1", "pubkey_b64", "signkey_b64", &mac).is_err());
}

#[test]
fn key_mac_fails_with_wrong_member_id() {
    let dek = [1u8; 32];
    let mac = compute_key_mac(&dek, "m1", "pubkey_b64", "signkey_b64");
    assert!(verify_key_mac(&dek, "m2", "pubkey_b64", "signkey_b64", &mac).is_err());
}

#[test]
fn key_mac_fails_with_tampered_public_key() {
    let dek = [1u8; 32];
    let mac = compute_key_mac(&dek, "m1", "original_pubkey", "signkey_b64");
    assert!(verify_key_mac(&dek, "m1", "replaced_pubkey", "signkey_b64", &mac).is_err());
}

// --- Canonical document bytes ---

fn empty_doc(id: &str) -> EnviDocument {
    EnviDocument {
        id: id.to_string(),
        name: "ws".to_string(),
        doc_version: 1,
        members: HashMap::new(),
        namespaces: HashMap::new(),
        secrets: HashMap::new(),
        document_signature: String::new(),
    }
}

fn active_member(id: &str) -> Member {
    Member {
        id: id.to_string(),
        email: "a@b.com".to_string(),
        public_key: "pubkey".to_string(),
        wrapped_dek: "wrapped".to_string(), // non-empty = active
        signing_key: "signkey".to_string(),
        key_mac: "mac".to_string(),
    }
}

fn pending_member(id: &str) -> Member {
    Member {
        id: id.to_string(),
        email: "p@b.com".to_string(),
        public_key: "pending_pubkey".to_string(),
        wrapped_dek: String::new(), // empty = pending
        signing_key: "pending_signkey".to_string(),
        key_mac: String::new(),
    }
}

#[test]
fn canonical_bytes_are_deterministic() {
    let mut doc = empty_doc("ws-id");
    doc.members.insert("m1".to_string(), active_member("m1"));
    let b1 = canonical_document_bytes(&doc);
    let b2 = canonical_document_bytes(&doc);
    assert_eq!(b1, b2);
}

#[test]
fn canonical_bytes_exclude_document_signature() {
    let mut doc = empty_doc("ws-id");
    doc.members.insert("m1".to_string(), active_member("m1"));
    let b1 = canonical_document_bytes(&doc);
    doc.document_signature = "member-1:somesig".to_string();
    let b2 = canonical_document_bytes(&doc);
    assert_eq!(b1, b2, "document_signature must not affect canonical bytes");
}

#[test]
fn canonical_bytes_exclude_pending_members() {
    let mut doc_without = empty_doc("ws-id");
    doc_without.members.insert("m1".to_string(), active_member("m1"));

    let mut doc_with = doc_without.clone();
    doc_with.members.insert("pending".to_string(), pending_member("pending"));

    assert_eq!(
        canonical_document_bytes(&doc_without),
        canonical_document_bytes(&doc_with),
        "pending members (empty wrapped_dek) must not affect canonical bytes",
    );
}

#[test]
fn canonical_bytes_change_when_active_member_added() {
    let mut doc1 = empty_doc("ws-id");
    doc1.members.insert("m1".to_string(), active_member("m1"));

    let mut doc2 = doc1.clone();
    doc2.members.insert("m2".to_string(), active_member("m2"));

    assert_ne!(canonical_document_bytes(&doc1), canonical_document_bytes(&doc2));
}
