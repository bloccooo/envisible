use std::{error::Error, time::Instant};

use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lib::{
    crypto::{
        compute_key_mac, derive_private_key, derive_signing_key, generate_dek, get_public_key,
        wrap_dek,
    },
    secrets::{add_secret, add_secret_from_state, PlaintextSecretFields},
    storage::{FsConfig, StorageConfig},
    store::Store,
    types::{EnviDocument, Member},
};
use uuid::Uuid;

const SECRETS_COUNT: usize = 1000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let vault_name: String = "Test Vault".into();

    let member_name = "Test".to_string();
    let passphrase = "test";
    let vault_id = Uuid::now_v7().to_string();
    let member_id = Uuid::now_v7().to_string();

    let storage_config = StorageConfig::Fs(FsConfig { root: "./".into() });

    let store = Store::new(&vault_id, &member_id, &storage_config)?;

    let mut doc = store.pull().await?;

    let private_key = derive_private_key(passphrase, &vault_id, &member_id)?;
    let public_key = get_public_key(&private_key);
    let signing_key = derive_signing_key(&private_key);
    let signing_public_key = B64.encode(signing_key.verifying_key().to_bytes());
    let dek = generate_dek();
    let wrapped_dek = wrap_dek(&dek, &public_key)?;
    let public_key_b64 = B64.encode(public_key);
    let key_mac = compute_key_mac(&dek, &member_id, &public_key_b64, &signing_public_key);

    let mut state: EnviDocument = hydrate(&doc)?;
    state.id = vault_id;
    state.name = vault_name.clone();
    state.members.insert(
        member_id.clone(),
        Member {
            id: member_id.clone(),
            email: member_name.clone(),
            public_key: public_key_b64,
            signing_key: signing_public_key,
            key_mac,
            wrapped_dek,
            invite_mac: String::new(),
            invite_nonce: String::new(),
        },
    );

    let start = Instant::now();

    let sample_values = [
        |i: usize| format!("secret-value-{i}"),
        |i: usize| format!("postgres://user:password-{i}@db.internal:5432/mydb"),
        |i: usize| format!(
            "app:\n  name: service-{i}\n  port: {}\n  debug: false\ndb:\n  host: db.internal\n  password: secret-{i}\n",
            8000 + i
        ),
        |i: usize| format!(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA{i:064}placeholder\n-----END RSA PRIVATE KEY-----"
        ),
        |i: usize| format!(
            "{{\"api_key\":\"{i:032}\",\"endpoint\":\"https://api.service-{i}.internal\",\"timeout\":30,\"retries\":3}}"
        ),
    ];

    for i in 0..SECRETS_COUNT {
        let value = sample_values[i % sample_values.len()](i);
        add_secret_from_state(
            &mut state,
            &dek,
            PlaintextSecretFields {
                description: "".into(),
                name: format!("SECRET_{i}"),
                tags: vec![],
                value,
            },
        )?;
    }
    println!("add_secret loop: {:?}", start.elapsed());

    let start = Instant::now();

    reconcile(&mut doc, &state)?;

    println!("Reconciling: {:?}", start.elapsed());

    let start = Instant::now();

    store.persist(&mut doc, &signing_key).await?;

    println!("persisting: {:?}", start.elapsed());

    Ok(())
}
