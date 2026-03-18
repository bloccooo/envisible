mod common;

use base64::{engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use lib::{
    crypto::{derive_invite_key, derive_private_key, derive_signing_key, get_public_key},
    invite::{generate_invite, parse_invite, verify_genesis_anchor, VaultPayload},
    storage::{FsConfig, StorageConfig},
    types::Member,
};
use std::collections::HashMap;

fn fs_storage() -> StorageConfig {
    StorageConfig::Fs(FsConfig { root: "/tmp/test".to_string() })
}

fn vault() -> VaultPayload {
    VaultPayload { id: "ws-123".to_string(), name: "My Vault".to_string() }
}

fn inviter_key() -> [u8; 32] {
    derive_private_key("test-pass", "test-vault", "inviter-id").unwrap()
}

// --- Basic roundtrip ---

#[test]
fn generate_and_parse_invite_roundtrip() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();
    assert_eq!(payload.vault.id, "ws-123");
    assert_eq!(payload.vault.name, "My Vault");
    assert_eq!(payload.inviter_id.as_deref(), Some("inviter-id"));
    assert!(payload.invite_pub.is_some());
    assert!(payload.nonce.is_some());
}

#[test]
fn invite_link_starts_with_prefix() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    assert!(link.starts_with("envi-invite:"));
}

#[test]
fn parse_invalid_link_returns_error() {
    assert!(parse_invite("not-an-invite-link").is_err());
    assert!(parse_invite("envi-invite:!!!invalid_base64!!!").is_err());
    assert!(parse_invite("envi-invite:bm90anNvbg==").is_err()); // valid b64, not valid JSON
}

#[test]
fn invite_pub_is_valid_x25519_key() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();
    let pub_bytes = B64.decode(payload.invite_pub.unwrap()).unwrap();
    assert_eq!(pub_bytes.len(), 32, "invite_pub must be a 32-byte X25519 key");
}

#[test]
fn each_invite_has_unique_nonce_and_pub() {
    let key = inviter_key();
    let l1 = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let l2 = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let p1 = parse_invite(&l1).unwrap();
    let p2 = parse_invite(&l2).unwrap();
    assert_ne!(p1.nonce, p2.nonce, "each invite must use a fresh nonce");
    assert_ne!(p1.invite_pub, p2.invite_pub, "each invite must derive a unique pub key");
}

// --- Token signature ---

#[test]
fn token_contains_signature_and_signing_key() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();
    assert!(payload.token_signature.is_some(), "token must carry a signature");
    assert!(payload.inviter_signing_key.is_some(), "token must carry the inviter's verifying key");
}

#[test]
fn inviter_signing_key_in_token_matches_derived_key() {
    let key = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();
    let expected = B64.encode(derive_signing_key(&key).verifying_key().to_bytes());
    assert_eq!(payload.inviter_signing_key.as_deref(), Some(expected.as_str()));
}

#[test]
fn tampered_payload_fails_parse() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    let b64 = link.strip_prefix("envi-invite:").unwrap();
    let mut json = String::from_utf8(B64URL.decode(b64).unwrap()).unwrap();
    // Change the vault name — this invalidates the signature
    json = json.replace("\"My Vault\"", "\"Tampered Vault\"");
    let tampered = format!("envi-invite:{}", B64URL.encode(json.as_bytes()));
    assert!(parse_invite(&tampered).is_err(), "tampered payload must be rejected");
}

#[test]
fn tampered_signing_key_fails_parse() {
    let link = generate_invite(&fs_storage(), vault(), &inviter_key(), "inviter-id").unwrap();
    let b64 = link.strip_prefix("envi-invite:").unwrap();
    let json = String::from_utf8(B64URL.decode(b64).unwrap()).unwrap();
    // Replace inviter_signing_key with a different member's key
    let other_key = derive_private_key("other-pass", "test-vault", "other-id").unwrap();
    let other_signing_key = B64.encode(derive_signing_key(&other_key).verifying_key().to_bytes());
    // Extract original signing key from token and replace it
    let payload: serde_json::Value = serde_json::from_str(&json).unwrap();
    let original_key = payload["inviter_signing_key"].as_str().unwrap();
    let json = json.replace(original_key, &other_signing_key);
    let tampered = format!("envi-invite:{}", B64URL.encode(json.as_bytes()));
    assert!(parse_invite(&tampered).is_err(), "swapped signing key must be rejected");
}

// --- Genesis anchor ---

fn make_members(member_id: &str, signing_key_b64: &str) -> HashMap<String, Member> {
    let mut m = HashMap::new();
    m.insert(
        member_id.to_string(),
        Member {
            id: member_id.to_string(),
            email: "test@example.com".to_string(),
            public_key: String::new(),
            wrapped_dek: "wrapped".to_string(),
            signing_key: signing_key_b64.to_string(),
            key_mac: String::new(),
            invite_mac: String::new(),
            invite_nonce: String::new(),
        },
    );
    m
}

#[test]
fn genesis_anchor_passes_when_key_matches() {
    let key = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    let expected_key = payload.inviter_signing_key.clone().unwrap();
    let members = make_members("inviter-id", &expected_key);

    assert!(verify_genesis_anchor(&payload, &members).is_ok());
}

#[test]
fn genesis_anchor_fails_when_key_differs() {
    let key = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    // Document has a different signing key for the inviter
    let attacker_key = derive_private_key("attacker", "vault", "attacker-id").unwrap();
    let attacker_signing = B64.encode(derive_signing_key(&attacker_key).verifying_key().to_bytes());
    let members = make_members("inviter-id", &attacker_signing);

    assert!(verify_genesis_anchor(&payload, &members).is_err());
}

#[test]
fn genesis_anchor_fails_when_inviter_absent_from_document() {
    let key = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &key, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    // Document does not contain the inviter at all
    let members = HashMap::new();

    assert!(verify_genesis_anchor(&payload, &members).is_err());
}

#[test]
fn genesis_anchor_skips_for_old_token_without_signing_key() {
    // Simulate a pre-v3 token with no inviter_signing_key
    let payload = lib::invite::InvitePayload {
        vault: vault(),
        storage: fs_storage(),
        invite_pub: None,
        inviter_id: Some("inviter-id".to_string()),
        nonce: None,
        inviter_signing_key: None,
        token_signature: None,
    };
    // Should silently pass regardless of document contents
    assert!(verify_genesis_anchor(&payload, &HashMap::new()).is_ok());
}

// --- Invite MAC ---

#[test]
fn invite_mac_roundtrip() {
    use lib::crypto::{compute_invite_mac, verify_invite_mac};

    let inviter_priv = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &inviter_priv, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    let invite_pub: [u8; 32] = B64.decode(payload.invite_pub.unwrap()).unwrap().try_into().unwrap();
    let nonce_bytes = B64.decode(payload.nonce.unwrap()).unwrap();

    let invitee_priv = derive_private_key("invitee-pass", "vault", "invitee-id").unwrap();
    let invitee_pub = get_public_key(&invitee_priv);
    let invitee_pub_b64 = B64.encode(invitee_pub);

    let mac = compute_invite_mac(&invitee_priv, &invite_pub, "invitee-id", &invitee_pub_b64, "signkey").unwrap();

    let invite_priv = derive_invite_key(&inviter_priv, &nonce_bytes).unwrap();
    assert!(verify_invite_mac(&invite_priv, &invitee_pub, "invitee-id", &invitee_pub_b64, "signkey", &mac).is_ok());
}

#[test]
fn invite_mac_fails_with_swapped_public_key() {
    use lib::crypto::{compute_invite_mac, derive_invite_key, verify_invite_mac};

    let inviter_priv = inviter_key();
    let link = generate_invite(&fs_storage(), vault(), &inviter_priv, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    let invite_pub: [u8; 32] = B64.decode(payload.invite_pub.unwrap()).unwrap().try_into().unwrap();
    let nonce_bytes = B64.decode(payload.nonce.unwrap()).unwrap();

    let invitee_priv = derive_private_key("invitee-pass", "vault", "invitee-id").unwrap();
    let invitee_pub = get_public_key(&invitee_priv);
    let invitee_pub_b64 = B64.encode(invitee_pub);

    let mac = compute_invite_mac(&invitee_priv, &invite_pub, "invitee-id", &invitee_pub_b64, "signkey").unwrap();

    // Attacker swaps the public key in storage
    let attacker_priv = derive_private_key("attacker-pass", "vault", "attacker-id").unwrap();
    let attacker_pub = get_public_key(&attacker_priv);
    let attacker_pub_b64 = B64.encode(attacker_pub);

    let invite_priv = derive_invite_key(&inviter_priv, &nonce_bytes).unwrap();
    assert!(verify_invite_mac(&invite_priv, &attacker_pub, "invitee-id", &attacker_pub_b64, "signkey", &mac).is_err());
}
