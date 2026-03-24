use std::{
    collections::HashMap,
    error::Error,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::{stream, StreamExt};
use lib::{
    crypto::{
        compute_key_mac, derive_private_key, derive_signing_key, generate_dek, get_public_key,
        wrap_dek,
    },
    secrets::{add_secret_from_state, PlaintextSecretFields},
    storage::StorageConfig,
    store::Store,
    types::{EnviDocument, Member},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tokio::task::spawn_blocking;
use uuid::Uuid;

const MEMBERS_COUNT: usize = 20;
const SECRETS_COUNT: usize = 500;

fn create_member(
    vault_id: String,
    member_index: usize,
    dek: &[u8; 32],
) -> Result<Member, Box<dyn Error + Send + Sync>> {
    let member_id = Uuid::now_v7().to_string();
    let member_name = format!("Member {member_index}");

    let passphrase = member_id.clone();
    let private_key = derive_private_key(&passphrase, &vault_id, &member_id)?;
    let public_key = get_public_key(&private_key);
    let signing_key = derive_signing_key(&private_key);
    let signing_public_key = B64.encode(signing_key.verifying_key().to_bytes());

    let wrapped_dek = wrap_dek(&dek, &public_key)?;
    let public_key_b64 = B64.encode(public_key);
    let key_mac = compute_key_mac(&dek, &member_id, &public_key_b64, &signing_public_key);

    let member = Member {
        id: member_id.clone(),
        email: member_name.clone(),
        public_key: public_key_b64,
        signing_key: signing_public_key,
        key_mac,
        wrapped_dek,
        invite_mac: String::new(),
        invite_nonce: String::new(),
    };

    Ok(member)
}

async fn persist(
    member: &Member,
    store: &Store,
    doc: &mut AutoCommit,
    state: &EnviDocument,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    reconcile(doc, state)?;

    // Passphrase is equal to member id for testing
    let private_key = derive_private_key(&member.id, &state.id, &member.id)?;
    let signing_key = derive_signing_key(&private_key);
    store.persist(doc, &signing_key).await?;

    Ok(())
}

fn sample_secret(i: usize) -> (String, String) {
    match i % 6 {
        0 => (
            format!("STRIPE_SECRET_KEY_{i}"),
            format!("sk_live_{:064x}", i as u128 * 0xdeadbeef),
        ),
        1 => (
            format!("DATABASE_URL_{i}"),
            format!("postgres://app_user:p4ssw0rd-{i:04}@db-prod-{i}.internal:5432/appdb"),
        ),
        2 => (
            format!("SSH_PRIVATE_KEY_{i}"),
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                 b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
                 QyNTUxOQAAACB{i:>042}AAAAA\n\
                 benchmark-key-{i:016}\n\
                 -----END OPENSSH PRIVATE KEY-----"
            ),
        ),
        3 => (
            format!("KUBECONFIG_{i}"),
            format!(
                "apiVersion: v1\n\
                 clusters:\n\
                 - cluster:\n\
                     certificate-authority-data: {ca}\n\
                     server: https://k8s-cluster-{i}.internal:6443\n\
                   name: prod-cluster-{i}\n\
                 contexts:\n\
                 - context:\n\
                     cluster: prod-cluster-{i}\n\
                     user: svc-account-{i}\n\
                   name: prod-{i}\n\
                 current-context: prod-{i}\n\
                 kind: Config\n\
                 users:\n\
                 - name: svc-account-{i}\n\
                   user:\n\
                     token: eyJhbGciOiJSUzI1NiJ9.bench-token-{i:016}.sig\n",
                ca = format!("{:>076}", i),
                i = i,
            ),
        ),
        4 => (
            format!("AWS_SECRET_ACCESS_KEY_{i}"),
            format!("{:>040}", format!("bench{i}Key")),
        ),
        _ => (
            format!("GENERIC_TOKEN_{i}"),
            format!("ghp_{:064x}", i as u128 * 0xcafebabe),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Sync + Send>> {
    let dek = generate_dek();
    let vault_id = Uuid::now_v7().to_string();

    println!("Initializing document");

    // Create members
    let start = Instant::now();
    let members: Vec<Member> = (0..MEMBERS_COUNT)
        .into_par_iter()
        .map(|i| create_member(vault_id.clone(), i, &dek))
        .collect::<Result<Vec<_>, _>>()?;

    let storage_config = StorageConfig::from_env()?;
    let mut stores: HashMap<String, Arc<Mutex<Store>>> = HashMap::new();

    for member in members.iter() {
        let store = Store::new(&vault_id, &member.id, &storage_config)?;
        stores.insert(member.id.clone(), Arc::new(Mutex::new(store)));
    }

    // Initialize document

    if let Some(member) = members.get(0) {
        if let Some(store) = stores.get(&member.id) {
            let store = store.lock().await;
            let mut doc = store.pull().await?;
            let mut state: EnviDocument = hydrate(&doc)?;
            state.id = vault_id.clone();
            state.name = "Vault Test".into();

            for member in members.iter() {
                state.members.insert(member.id.clone(), member.clone());
            }

            for i in 0..SECRETS_COUNT {
                let (name, value) = sample_secret(i);
                add_secret_from_state(
                    &mut state,
                    &dek,
                    PlaintextSecretFields {
                        description: "".into(),
                        name,
                        tags: vec![],
                        value,
                    },
                )
                .unwrap();
            }

            persist(member, &store, &mut doc, &state).await?;
        } else {
            eprintln!("Unable to initialize document")
        }
    } else {
        eprintln!("Unable to initialize document")
    }

    println!("Document initialized in: {:?}", start.elapsed());

    let members = Arc::new(members);
    let stores = Arc::new(stores);

    // Persist each member document

    println!();
    println!("Persisting each member's document");
    stream::iter(0..MEMBERS_COUNT)
        .for_each_concurrent(8, |i| {
            let members = Arc::clone(&members);
            let stores = Arc::clone(&stores);
            async move {
                let member = members[i].clone();
                let store = Arc::clone(stores.get(&member.id).unwrap());
                let store = store.lock().await;

                let doc = store.pull().await.unwrap();

                let (mut doc, state) = spawn_blocking(move || {
                    let state: EnviDocument = hydrate(&doc).unwrap();
                    (doc, state)
                })
                .await
                .unwrap();

                persist(&member, &store, &mut doc, &state).await.unwrap();
            }
        })
        .await;

    let now = Instant::now();

    let count = Arc::new(AtomicU64::new(0));
    let pull_ns = Arc::new(AtomicU64::new(0));
    let persist_ns = Arc::new(AtomicU64::new(0));

    // Test pull and persist

    println!();
    println!("*** Test pull and persist ***");
    stream::iter(0..MEMBERS_COUNT)
        .for_each_concurrent(1, |i| {
            let members = Arc::clone(&members);
            let stores = Arc::clone(&stores);
            let pull_ns = Arc::clone(&pull_ns);
            let persist_ns = Arc::clone(&persist_ns);
            let count = Arc::clone(&count);

            println!();
            println!("Member {i}");

            async move {
                let member = members[i].clone();
                let store = Arc::clone(stores.get(&member.id).unwrap());
                let store = store.lock().await;

                let t = Instant::now();
                let doc = store
                    .pull_with_progress(|progress| println!("p: {progress}%"))
                    .await
                    .unwrap();
                pull_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);

                let (mut doc, state) = spawn_blocking(move || {
                    let state: EnviDocument = hydrate(&doc).unwrap();
                    (doc, state)
                })
                .await
                .unwrap();

                let t = Instant::now();
                persist(&member, &store, &mut doc, &state).await.unwrap();
                persist_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                count.fetch_add(1, Ordering::Relaxed);
            }
        })
        .await;

    let count = count.load(Ordering::Relaxed);
    let total = now.elapsed();
    let avg_pull = Duration::from_nanos(pull_ns.load(Ordering::Relaxed) / count);
    let avg_persist = Duration::from_nanos(persist_ns.load(Ordering::Relaxed) / count);

    println!();
    println!("=== Benchmark Summary ===");
    println!("  secrets  : {}", SECRETS_COUNT);
    println!("  members  : {}", MEMBERS_COUNT);
    println!("  total    : {:?}", total);
    println!("  pull avg : {:?}", avg_pull);
    println!("  persist avg: {:?}", avg_persist);

    Ok(())
}
