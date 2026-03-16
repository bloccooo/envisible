use crate::{
    crypto::derive_invite_key,
    error::{Error, Result},
    storage::StorageConfig,
};
use base64::{
    engine::general_purpose::STANDARD as B64,
    engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
    Engine,
};
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
    /// Inviter's member ID (informational, for display).
    #[serde(default)]
    pub inviter_id: Option<String>,
    /// Base64(random 16-byte nonce). Stored by invitee in their member record so
    /// the inviter can re-derive the invite key later without storing anything locally.
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Generate an invite token embedding an ephemeral invite public key.
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

    let payload = InvitePayload {
        vault,
        storage: storage.clone(),
        invite_pub: Some(B64.encode(invite_pub)),
        inviter_id: Some(inviter_id.to_string()),
        nonce: Some(B64.encode(nonce_bytes)),
    };
    let json = serde_json::to_string(&payload)?;
    let b64 = B64URL.encode(json.as_bytes());
    Ok(format!("{INVITE_PREFIX}{b64}"))
}

pub fn parse_invite(link: &str) -> Result<InvitePayload> {
    let b64 = link
        .strip_prefix(INVITE_PREFIX)
        .ok_or(Error::InvalidInviteLink)?;
    let bytes = B64URL.decode(b64).map_err(|_| Error::InvalidInviteLink)?;
    let json = String::from_utf8(bytes).map_err(|_| Error::InvalidInviteLink)?;
    serde_json::from_str(&json).map_err(|_| Error::InvalidInviteLink)
}
