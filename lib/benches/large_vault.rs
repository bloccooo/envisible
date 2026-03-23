/// Benchmarks for a realistic vault: 50 members, 300 secrets.
///
/// Covers the hot paths that run on every sync and unlock:
///   - unlock (50 key-MAC verifications)
///   - list_secrets (300 AES-256-GCM decryptions)
///   - add_secret / update_secret / remove_secret
///   - canonical_document_bytes (JSON serialisation for signing)
///   - sign_document / verify_document_signature (Ed25519)
///   - doc.save() / AutoCommit::load (Automerge serialisation round-trip)
///   - CRDT merge of 50 member documents
use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use lib::{
    crypto::{
        canonical_document_bytes, compute_key_mac, derive_signing_key, encrypt_field, generate_dek,
        get_public_key, sign_document, verify_document_signature, wrap_dek,
    },
    secrets::{add_secret, list_secrets, remove_secret, update_secret, PlaintextSecretFields},
    store::unlock,
    types::{EnviDocument, Member, Secret},
};
use rand::RngCore;

const N_MEMBERS: usize = 50;
const N_SECRETS: usize = 300;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

struct MemberKeys {
    id: String,
    private_key: [u8; 32],
}

/// Build an AutoCommit with N_MEMBERS full members and N_SECRETS encrypted secrets.
/// Returns (doc, dek, private_key_of_member_0).
fn build_vault() -> (AutoCommit, [u8; 32], [u8; 32]) {
    let dek = generate_dek();

    let mut state = EnviDocument {
        id: "bench-vault-id".to_string(),
        name: "Bench Vault".to_string(),
        doc_version: 1,
        ..Default::default()
    };

    let mut member_keys: Vec<MemberKeys> = Vec::with_capacity(N_MEMBERS);

    for i in 0..N_MEMBERS {
        let mut private_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut private_key);

        let public_key = get_public_key(&private_key);
        let pub_key_b64 = B64.encode(public_key);
        let signing_key = derive_signing_key(&private_key);
        let sign_key_b64 = B64.encode(signing_key.verifying_key().to_bytes());
        let wrapped_dek = wrap_dek(&dek, &public_key).unwrap();
        let member_id = format!("member-{i:04}");
        let key_mac = compute_key_mac(&dek, &member_id, &pub_key_b64, &sign_key_b64);

        state.members.insert(
            member_id.clone(),
            Member {
                id: member_id.clone(),
                email: format!("member{i}@example.com"),
                public_key: pub_key_b64,
                wrapped_dek,
                signing_key: sign_key_b64,
                key_mac,
                invite_mac: String::new(),
                invite_nonce: String::new(),
            },
        );

        member_keys.push(MemberKeys {
            id: member_id,
            private_key,
        });
    }

    // Pre-populate secrets directly into state before the first reconcile so we
    // avoid running N_SECRETS individual reconcile calls during setup.
    for i in 0..N_SECRETS {
        let id = format!("secret-{i:04}");
        state.secrets.insert(
            id.clone(),
            Secret {
                id: id.clone(),
                name: encrypt_field(&format!("SECRET_{i:04}"), &dek).unwrap(),
                value: encrypt_field(&format!("super-secret-value-{i}"), &dek).unwrap(),
                description: encrypt_field(&format!("Description for secret {i}"), &dek).unwrap(),
                tags: encrypt_field(
                    &serde_json::to_string(&vec!["bench", &format!("tag-{}", i % 10)]).unwrap(),
                    &dek,
                )
                .unwrap(),
            },
        );
    }

    let mut doc = AutoCommit::new();
    reconcile(&mut doc, &state).unwrap();

    // Sign with member-0's key.
    let signing_key_0 = derive_signing_key(&member_keys[0].private_key);
    let canonical = canonical_document_bytes(&state);
    state.document_signature = sign_document(&canonical, &member_keys[0].id, &signing_key_0);
    reconcile(&mut doc, &state).unwrap();

    let first_private_key = member_keys[0].private_key;
    (doc, dek, first_private_key)
}

/// Clone `base` and add `n` extra secrets so it looks like a peer's document.
fn fork_with_secrets(base: &mut AutoCommit, dek: &[u8; 32], n: usize, tag: &str) -> AutoCommit {
    let mut doc = base.fork();
    for i in 0..n {
        add_secret(
            &mut doc,
            dek,
            PlaintextSecretFields {
                name: format!("{tag}-secret-{i}"),
                value: format!("{tag}-value-{i}"),
                description: String::new(),
                tags: vec![tag.to_string()],
            },
        )
        .unwrap();
    }
    doc
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_unlock(c: &mut Criterion) {
    let (doc, _dek, private_key) = build_vault();

    c.bench_function("unlock (50 members, 300 secrets)", |b| {
        b.iter(|| unlock(black_box(&doc), black_box(&private_key)).unwrap())
    });
}

fn bench_list_secrets(c: &mut Criterion) {
    let (doc, dek, _key) = build_vault();

    c.bench_function("list_secrets (300 secrets)", |b| {
        b.iter(|| list_secrets(black_box(&doc), black_box(&dek)).unwrap())
    });
}

fn bench_add_secret(c: &mut Criterion) {
    let (mut doc, dek, _key) = build_vault();

    c.bench_function("add_secret (300-secret doc)", |b| {
        b.iter_batched(
            || doc.fork(),
            |mut d| {
                add_secret(
                    black_box(&mut d),
                    black_box(&dek),
                    PlaintextSecretFields {
                        name: "NEW_SECRET".into(),
                        value: "new-value".into(),
                        description: "new description".into(),
                        tags: vec!["bench".into()],
                    },
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_update_secret(c: &mut Criterion) {
    let (mut doc, dek, _key) = build_vault();
    let state: EnviDocument = hydrate(&doc).unwrap();
    let first_id = state.secrets.keys().next().unwrap().clone();

    c.bench_function("update_secret (300-secret doc)", |b| {
        b.iter_batched(
            || doc.fork(),
            |mut d| {
                update_secret(
                    black_box(&mut d),
                    black_box(&dek),
                    black_box(&first_id),
                    PlaintextSecretFields {
                        name: "UPDATED".into(),
                        value: "updated-value".into(),
                        description: "updated".into(),
                        tags: vec!["bench".into()],
                    },
                )
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_remove_secret(c: &mut Criterion) {
    let (mut doc, _dek, _key) = build_vault();
    let state: EnviDocument = hydrate(&doc).unwrap();
    let first_id = state.secrets.keys().next().unwrap().clone();

    c.bench_function("remove_secret (300-secret doc)", |b| {
        b.iter_batched(
            || doc.fork(),
            |mut d| remove_secret(black_box(&mut d), black_box(&first_id)).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_canonical_bytes(c: &mut Criterion) {
    let (doc, _dek, _key) = build_vault();
    let state: EnviDocument = hydrate(&doc).unwrap();

    c.bench_function("canonical_document_bytes (50 members, 300 secrets)", |b| {
        b.iter(|| canonical_document_bytes(black_box(&state)))
    });
}

fn bench_sign_verify(c: &mut Criterion) {
    let (doc, _dek, private_key) = build_vault();
    let state: EnviDocument = hydrate(&doc).unwrap();
    let canonical = canonical_document_bytes(&state);
    let signing_key = derive_signing_key(&private_key);
    let verifying_key_b64 = B64.encode(signing_key.verifying_key().to_bytes());
    let sig_field = sign_document(&canonical, "member-0000", &signing_key);

    let mut group = c.benchmark_group("signing");

    group.bench_function("sign_document", |b| {
        b.iter(|| {
            sign_document(
                black_box(&canonical),
                "member-0000",
                black_box(&signing_key),
            )
        })
    });

    group.bench_function("verify_document_signature", |b| {
        b.iter(|| {
            verify_document_signature(
                black_box(&canonical),
                black_box(&sig_field),
                black_box(&verifying_key_b64),
            )
            .unwrap()
        })
    });

    group.finish();
}

fn bench_automerge_save_load(c: &mut Criterion) {
    let (mut doc, _dek, _key) = build_vault();

    let mut group = c.benchmark_group("automerge");

    group.bench_function("doc.save() (50 members, 300 secrets)", |b| {
        b.iter(|| doc.save())
    });

    let saved = doc.save();
    group.bench_function("AutoCommit::load (50 members, 300 secrets)", |b| {
        b.iter(|| AutoCommit::load(black_box(&saved)).unwrap())
    });

    group.finish();
}

fn bench_crdt_merge(c: &mut Criterion) {
    let (mut base, dek, _key) = build_vault();

    // Pre-build 50 peer documents (each with 2 unique secrets) outside the timed loop.
    let mut peers: Vec<AutoCommit> = (0..N_MEMBERS)
        .map(|i| fork_with_secrets(&mut base, &dek, 2, &format!("peer-{i}")))
        .collect();

    c.bench_function("crdt merge 50 peer docs", |b| {
        b.iter_batched(
            || {
                // Clone all peer docs for each iteration.
                peers.iter_mut().map(|p| p.fork()).collect::<Vec<_>>()
            },
            |mut docs| {
                let mut merged = docs.remove(0);
                for mut peer in docs {
                    merged.merge(&mut peer).unwrap();
                }
                merged
            },
            BatchSize::LargeInput,
        )
    });
}

criterion_group!(
    benches,
    bench_unlock,
    bench_list_secrets,
    bench_add_secret,
    bench_update_secret,
    bench_remove_secret,
    bench_canonical_bytes,
    bench_sign_verify,
    bench_automerge_save_load,
    bench_crdt_merge,
);
criterion_main!(benches);
