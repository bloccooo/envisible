use crate::{
    crypto::{derive_invite_key, derive_signing_key},
    error::{Error, Result},
    storage::StorageConfig,
};
use base64::{
    engine::general_purpose::STANDARD as B64,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
    Engine,
};
use ed25519_dalek::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

const INVITE_PREFIX: &str = "envi-invite:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePayload {
    pub vault: VaultPayload,
    pub storage: StorageConfig,
    /// Base64(X25519 public key deterministically derived from inviter_priv + nonce).
    /// Present in v2+ tokens; None in old tokens.
    #[serde(default)]
    pub invite_pub: Option<String>,
    /// Inviter's member ID.
    #[serde(default)]
    pub inviter_id: Option<String>,
    /// Base64(random 16-byte nonce). Stored by invitee in their member record so
    /// the inviter can re-derive the invite key later without storing anything locally.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Base64(Ed25519 verifying key of the inviter). The invitee uses this to verify
    /// the token signature and to pin the inviter's identity against the workspace document.
    #[serde(default)]
    pub inviter_signing_key: Option<String>,
    /// Base64(Ed25519 signature over the token payload bytes, excluding this field).
    /// Proves the token was produced by the holder of `inviter_signing_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_signature: Option<String>,
}

/// Generate a signed invite token embedding an ephemeral invite public key.
/// The token is signed with the inviter's Ed25519 key so the invitee can verify
/// it was produced by a legitimate workspace member.
/// The invite private key is deterministically re-derivable from `inviter_private_key` + nonce,
/// so nothing needs to be stored locally.
pub fn generate_invite(
    storage: &StorageConfig,
    vault: VaultPayload,
    inviter_private_key: &[u8; 32],
    inviter_id: &str,
) -> Result<String> {
    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let invite_priv = derive_invite_key(inviter_private_key, &nonce_bytes)?;
    let invite_pub = *PublicKey::from(&StaticSecret::from(invite_priv)).as_bytes();

    let signing_key = derive_signing_key(inviter_private_key);
    let inviter_signing_key = B64.encode(signing_key.verifying_key().to_bytes());

    // Build payload without signature first, serialize, then sign.
    let payload = InvitePayload {
        vault,
        storage: storage.clone(),
        invite_pub: Some(B64.encode(invite_pub)),
        inviter_id: Some(inviter_id.to_string()),
        nonce: Some(B64.encode(nonce_bytes)),
        inviter_signing_key: Some(inviter_signing_key),
        token_signature: None,
    };
    let unsigned_json = serde_json::to_string(&payload)?;
    let signature = signing_key.sign(unsigned_json.as_bytes());

    let signed = InvitePayload {
        token_signature: Some(B64.encode(signature.to_bytes())),
        ..payload
    };
    let json = serde_json::to_string(&signed)?;
    let b64 = B64URL.encode(json.as_bytes());
    Ok(format!("{INVITE_PREFIX}{b64}"))
}

pub fn parse_invite(link: &str) -> Result<InvitePayload> {
    let b64 = link
        .strip_prefix(INVITE_PREFIX)
        .ok_or(Error::InvalidInviteLink)?;
    let bytes = B64URL.decode(b64).map_err(|_| Error::InvalidInviteLink)?;
    let json = String::from_utf8(bytes).map_err(|_| Error::InvalidInviteLink)?;
    let payload: InvitePayload =
        serde_json::from_str(&json).map_err(|_| Error::InvalidInviteLink)?;

    // Verify the token signature if present.
    if let (Some(sig_b64), Some(verifying_key_b64)) =
        (&payload.token_signature, &payload.inviter_signing_key)
    {
        let sig_bytes = B64.decode(sig_b64).map_err(|_| Error::InvalidInviteLink)?;
        let sig_bytes: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| Error::InvalidInviteLink)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let key_bytes = B64
            .decode(verifying_key_b64)
            .map_err(|_| Error::InvalidInviteLink)?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| Error::InvalidInviteLink)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| Error::InvalidInviteLink)?;

        // Reconstruct the unsigned payload bytes (token_signature field absent).
        let unsigned = InvitePayload {
            token_signature: None,
            ..payload.clone()
        };
        let unsigned_json = serde_json::to_string(&unsigned).map_err(|_| Error::InvalidInviteLink)?;

        verifying_key
            .verify_strict(unsigned_json.as_bytes(), &sig)
            .map_err(|_| Error::InvalidInviteLink)?;
    }

    Ok(payload)
}
