mod common;

use lib::{
    crypto::{derive_private_key, get_public_key},
    invite::{generate_invite, parse_invite, VaultPayload},
    storage::{FsConfig, StorageConfig},
};

fn fs_storage() -> StorageConfig {
    StorageConfig::Fs(FsConfig { root: "/tmp/test".to_string() })
}

fn inviter_key() -> [u8; 32] {
    derive_private_key("test-pass", "test-vault", "inviter-id").unwrap()
}

#[test]
fn generate_and_parse_invite_roundtrip() {
    let storage = fs_storage();
    let vault = VaultPayload {
        id: "ws-123".to_string(),
        name: "My Vault".to_string(),
    };
    let link = generate_invite(&storage, vault, &inviter_key(), "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();
    assert_eq!(payload.vault.id, "ws-123");
    assert_eq!(payload.vault.name, "My Vault");
    assert_eq!(payload.inviter_id.as_deref(), Some("inviter-id"));
    assert!(payload.invite_pub.is_some());
    assert!(payload.nonce.is_some());
}

#[test]
fn invite_link_starts_with_prefix() {
    let link = generate_invite(
        &fs_storage(),
        VaultPayload { id: "id".to_string(), name: "name".to_string() },
        &inviter_key(),
        "inviter-id",
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

#[test]
fn invite_pub_is_valid_x25519_key() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let link = generate_invite(
        &fs_storage(),
        VaultPayload { id: "id".to_string(), name: "name".to_string() },
        &inviter_key(),
        "inviter-id",
    )
    .unwrap();
    let payload = parse_invite(&link).unwrap();
    let pub_bytes = B64.decode(payload.invite_pub.unwrap()).unwrap();
    assert_eq!(pub_bytes.len(), 32, "invite_pub must be a 32-byte X25519 key");
}

#[test]
fn each_invite_has_unique_nonce_and_pub() {
    let storage = fs_storage();
    let vault = VaultPayload { id: "id".to_string(), name: "name".to_string() };
    let key = inviter_key();
    let l1 = generate_invite(&storage, vault.clone(), &key, "inviter-id").unwrap();
    let l2 = generate_invite(&storage, vault, &key, "inviter-id").unwrap();
    let p1 = parse_invite(&l1).unwrap();
    let p2 = parse_invite(&l2).unwrap();
    assert_ne!(p1.nonce, p2.nonce, "each invite must use a fresh nonce");
    assert_ne!(p1.invite_pub, p2.invite_pub, "each invite must derive a unique pub key");
}

#[test]
fn invite_mac_roundtrip() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use lib::crypto::{compute_invite_mac, derive_invite_key, verify_invite_mac};

    // Simulate: inviter generates an invite
    let inviter_priv = inviter_key();
    let storage = fs_storage();
    let vault = VaultPayload { id: "vault".to_string(), name: "V".to_string() };
    let link = generate_invite(&storage, vault, &inviter_priv, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    let invite_pub_bytes = B64.decode(payload.invite_pub.unwrap()).unwrap();
    let invite_pub: [u8; 32] = invite_pub_bytes.try_into().unwrap();
    let nonce_bytes = B64.decode(payload.nonce.unwrap()).unwrap();

    // Simulate: invitee derives their keys and computes MAC
    let invitee_priv = derive_private_key("invitee-pass", "vault", "invitee-id").unwrap();
    let invitee_pub = get_public_key(&invitee_priv);
    let invitee_pub_b64 = B64.encode(invitee_pub);
    let invitee_signing_b64 = "signkey_b64";

    let mac = compute_invite_mac(
        &invitee_priv,
        &invite_pub,
        "invitee-id",
        &invitee_pub_b64,
        invitee_signing_b64,
    )
    .unwrap();

    // Simulate: inviter re-derives invite_priv and verifies MAC
    let invite_priv = derive_invite_key(&inviter_priv, &nonce_bytes).unwrap();
    assert!(verify_invite_mac(
        &invite_priv,
        &invitee_pub,
        "invitee-id",
        &invitee_pub_b64,
        invitee_signing_b64,
        &mac,
    )
    .is_ok());
}

#[test]
fn invite_mac_fails_with_swapped_public_key() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use lib::crypto::{compute_invite_mac, derive_invite_key, verify_invite_mac};

    let inviter_priv = inviter_key();
    let storage = fs_storage();
    let vault = VaultPayload { id: "vault".to_string(), name: "V".to_string() };
    let link = generate_invite(&storage, vault, &inviter_priv, "inviter-id").unwrap();
    let payload = parse_invite(&link).unwrap();

    let invite_pub_bytes = B64.decode(payload.invite_pub.unwrap()).unwrap();
    let invite_pub: [u8; 32] = invite_pub_bytes.try_into().unwrap();
    let nonce_bytes = B64.decode(payload.nonce.unwrap()).unwrap();

    // Legit invitee computes MAC over their real key
    let invitee_priv = derive_private_key("invitee-pass", "vault", "invitee-id").unwrap();
    let invitee_pub = get_public_key(&invitee_priv);
    let invitee_pub_b64 = B64.encode(invitee_pub);

    let mac = compute_invite_mac(
        &invitee_priv, &invite_pub, "invitee-id", &invitee_pub_b64, "signkey",
    )
    .unwrap();

    // Attacker swaps the public key in storage
    let attacker_priv = derive_private_key("attacker-pass", "vault", "attacker-id").unwrap();
    let attacker_pub = get_public_key(&attacker_priv);
    let attacker_pub_b64 = B64.encode(attacker_pub);

    // Inviter re-derives invite_priv and tries to verify against the swapped key
    let invite_priv = derive_invite_key(&inviter_priv, &nonce_bytes).unwrap();
    assert!(verify_invite_mac(
        &invite_priv,
        &attacker_pub, // swapped!
        "invitee-id",
        &attacker_pub_b64,
        "signkey",
        &mac,
    )
    .is_err());
}
