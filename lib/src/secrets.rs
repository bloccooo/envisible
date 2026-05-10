use crate::{
    crypto::{decrypt_field, encrypt_field},
    error::Result,
    vault_document::{PlaintextSecret, Secret, VaultDocument},
};
use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use uuid::Uuid;

fn encrypt_secret(
    fields: &PlaintextSecretFields,
    dek: &[u8; 32],
) -> Result<(String, String, String, String)> {
    Ok((
        encrypt_field(&fields.name, dek)?,
        encrypt_field(&fields.value, dek)?,
        encrypt_field(&fields.description, dek)?,
        encrypt_field(&serde_json::to_string(&fields.tags)?, dek)?,
    ))
}

fn decrypt_secret(s: &Secret, dek: &[u8; 32]) -> Result<PlaintextSecret> {
    let tags_json = decrypt_field(&s.tags, dek)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json)?;
    Ok(PlaintextSecret {
        id: s.id.clone(),
        name: decrypt_field(&s.name, dek)?,
        value: decrypt_field(&s.value, dek)?,
        description: decrypt_field(&s.description, dek)?,
        tags,
    })
}

pub struct PlaintextSecretFields {
    pub name: String,
    pub value: String,
    pub description: String,
    pub tags: Vec<String>,
}

pub fn add_secret(
    doc: &mut AutoCommit,
    dek: &[u8; 32],
    fields: PlaintextSecretFields,
) -> Result<()> {
    let id = Uuid::now_v7().to_string();
    let (enc_name, enc_value, enc_desc, enc_tags) = encrypt_secret(&fields, dek)?;

    let mut vault_doc: VaultDocument = hydrate(doc)?;
    vault_doc.secrets.insert(
        id.clone(),
        Secret {
            id,
            name: enc_name,
            value: enc_value,
            description: enc_desc,
            tags: enc_tags,
        },
    );
    reconcile(doc, &vault_doc)?;
    Ok(())
}

pub fn remove_secret(doc: &mut AutoCommit, id: &str) -> Result<()> {
    let mut vault_doc: VaultDocument = hydrate(doc)?;
    vault_doc.secrets.remove(id);
    reconcile(doc, &vault_doc)?;
    Ok(())
}

pub fn update_secret(
    doc: &mut AutoCommit,
    dek: &[u8; 32],
    id: &str,
    fields: PlaintextSecretFields,
) -> Result<()> {
    let (enc_name, enc_value, enc_desc, enc_tags) = encrypt_secret(&fields, dek)?;
    let mut vault_doc: VaultDocument = hydrate(doc)?;

    let secret = vault_doc
        .secrets
        .get_mut(id)
        .ok_or_else(|| crate::error::Error::SecretNotFound(id.to_string()))?;
    secret.name = enc_name;
    secret.value = enc_value;
    secret.description = enc_desc;
    secret.tags = enc_tags;

    reconcile(doc, &vault_doc)?;
    Ok(())
}

pub fn list_secrets(doc: &AutoCommit, dek: &[u8; 32]) -> Result<Vec<PlaintextSecret>> {
    let vault_doc: VaultDocument = hydrate(doc)?;
    vault_doc
        .secrets
        .values()
        .map(|s| decrypt_secret(s, dek))
        .collect()
}
