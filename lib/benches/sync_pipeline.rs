/// Benchmarks for the store-level pull/verify/merge pipeline.
///
/// Mirrors the private `load_and_verify_files` logic in store.rs and breaks it
/// into per-step timings so we can see exactly where the time goes when syncing
/// a vault with 50 members and 300 secrets.
///
/// Also measures raw document size (bytes) as the secret count grows, showing
/// how much data each member file carries and how the storage footprint scales.
use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use rayon::prelude::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use lib::{
    crypto::{
        canonical_document_bytes, compute_key_mac, derive_signing_key, encrypt_field, generate_dek,
        get_public_key, sign_document, verify_document_signature, wrap_dek,
    },
    types::{EnviDocument, Member, Secret},
};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct MemberKey {
    id: String,
    private_key: [u8; 32],
}

/// Build an EnviDocument state in RAM: `n_members` full members, `n_secrets` encrypted secrets.
/// Uses a single `reconcile` call (not N `add_secret` calls) so setup stays fast.
fn build_state(n_members: usize, n_secrets: usize) -> (EnviDocument, [u8; 32], Vec<MemberKey>) {
    let dek = generate_dek();
    let mut state = EnviDocument {
        id: "bench-vault-id".to_string(),
        name: "Bench Vault".to_string(),
        doc_version: 1,
        ..Default::default()
    };

    let mut member_keys: Vec<MemberKey> = Vec::with_capacity(n_members);

    for i in 0..n_members {
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
        member_keys.push(MemberKey {
            id: member_id,
            private_key,
        });
    }

    for i in 0..n_secrets {
        let id = format!("secret-{i:04}");
        state.secrets.insert(
            id.clone(),
            Secret {
                id: id.clone(),
                name: encrypt_field(&format!("SECRET_{i:04}"), &dek).unwrap(),
                value: encrypt_field(&format!("super-secret-value-{i}"), &dek).unwrap(),
                description: encrypt_field(&format!("Description for secret {i}"), &dek).unwrap(),
                tags: encrypt_field(
                    &serde_json::to_string(&["bench", &format!("tag-{}", i % 10)]).unwrap(),
                    &dek,
                )
                .unwrap(),
            },
        );
    }

    (state, dek, member_keys)
}

/// Build the Automerge doc from a pre-built state (one reconcile call).
fn state_to_doc(state: &EnviDocument) -> AutoCommit {
    let mut doc = AutoCommit::new();
    reconcile(&mut doc, state).unwrap();
    doc
}

/// Produce one signed, saved member file per member.
/// Each file contains the full vault state signed with that member's own key.
fn build_member_files(n_members: usize, n_secrets: usize) -> Vec<Vec<u8>> {
    let (base_state, _dek, member_keys) = build_state(n_members, n_secrets);
    let canonical = canonical_document_bytes(&base_state);
    let mut base_doc = state_to_doc(&base_state);

    member_keys
        .iter()
        .map(|mk| {
            let signing_key = derive_signing_key(&mk.private_key);
            let sig = sign_document(&canonical, &mk.id, &signing_key);
            let mut doc = base_doc.fork();
            let mut state = base_state.clone();
            state.document_signature = sig;
            reconcile(&mut doc, &state).unwrap();
            doc.save()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Replicate the private `load_and_verify_files` from store.rs
// ---------------------------------------------------------------------------

fn load_and_verify_merge(files: &[Vec<u8>]) -> Option<AutoCommit> {
    let docs: Vec<AutoCommit> = files
        .par_iter()
        .filter_map(|bytes| {
            let doc = AutoCommit::load(bytes).ok()?;
            let state: EnviDocument = hydrate(&doc).ok()?;

            if state.document_signature.is_empty() {
                return None;
            }
            let member_id = state.document_signature.splitn(2, ':').next()?;
            let member = state.members.get(member_id)?;
            if member.signing_key.is_empty() {
                return None;
            }

            let canonical = canonical_document_bytes(&state);
            verify_document_signature(&canonical, &state.document_signature, &member.signing_key)
                .ok()?;
            Some(doc)
        })
        .collect();

    docs.into_iter().reduce(|mut a, mut b| {
        let _ = a.merge(&mut b);
        a
    })
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Full pipeline: load + verify + merge all 50 member files.
/// This is what `Store::pull` does on every sync.
fn bench_full_pipeline(c: &mut Criterion) {
    let files = build_member_files(50, 300);

    let total_bytes: usize = files.iter().map(|f| f.len()).sum();
    let avg_bytes = total_bytes / files.len();
    println!(
        "\n  [sync_pipeline] 50 member files @ 300 secrets: avg {avg_bytes} B/file, {:.1} KB total on wire",
        total_bytes as f64 / 1024.0
    );

    c.bench_function("pull: load+verify+merge 50 files (300 secrets)", |b| {
        b.iter(|| load_and_verify_merge(black_box(&files)))
    });
}

/// Break the pipeline into individual steps for a single member file.
/// Shows where time is spent per file before the merge.
fn bench_pipeline_steps(c: &mut Criterion) {
    let files = build_member_files(50, 300);
    let one_file = &files[0];

    let mut group = c.benchmark_group("sync_step (single file, 300 secrets)");

    // Step 1 – deserialise Automerge binary
    group.bench_function("1. AutoCommit::load", |b| {
        b.iter(|| AutoCommit::load(black_box(one_file)).unwrap())
    });

    // Step 2 – hydrate into EnviDocument
    let doc = AutoCommit::load(one_file).unwrap();
    group.bench_function("2. hydrate (EnviDocument)", |b| {
        b.iter(|| {
            let _: EnviDocument = hydrate(black_box(&doc)).unwrap();
        })
    });

    // Step 3 – compute canonical bytes for signing
    let state: EnviDocument = hydrate(&doc).unwrap();
    group.bench_function("3. canonical_document_bytes", |b| {
        b.iter(|| canonical_document_bytes(black_box(&state)))
    });

    // Step 4 – Ed25519 signature verification
    let canonical = canonical_document_bytes(&state);
    let member_id = state.document_signature.splitn(2, ':').next().unwrap();
    let member = state.members.get(member_id).unwrap();
    let signing_key_b64 = member.signing_key.clone();
    let sig_field = state.document_signature.clone();
    group.bench_function("4. verify_document_signature", |b| {
        b.iter(|| {
            verify_document_signature(
                black_box(&canonical),
                black_box(&sig_field),
                black_box(&signing_key_b64),
            )
            .unwrap()
        })
    });

    // Step 5 – merge two already-loaded docs
    let mut doc_a = AutoCommit::load(one_file).unwrap();
    let mut doc_b = AutoCommit::load(&files[1]).unwrap();
    group.bench_function("5. merge two docs", |b| {
        b.iter_batched(
            || (doc_a.fork(), doc_b.fork()),
            |(mut a, mut b)| a.merge(&mut b).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Document byte size and save/load time as the secret count grows.
/// Prints the raw byte sizes and benchmarks save() at each scale point.
fn bench_doc_size_growth(c: &mut Criterion) {
    let secret_counts: &[usize] = &[50, 100, 200, 300, 500, 1000];

    println!("\n  [doc_size] serialised document size (50 members):");
    println!("  {:>10}  {:>12}  {:>10}", "secrets", "bytes", "KB");

    // Collect sizes without rebuilding during the bench iterations
    let mut docs: Vec<(usize, AutoCommit)> = Vec::new();
    for &n in secret_counts {
        let (state, _, _) = build_state(50, n);
        let mut doc = state_to_doc(&state);
        let saved = doc.save();
        println!(
            "  {:>10}  {:>12}  {:>9.1}",
            n,
            saved.len(),
            saved.len() as f64 / 1024.0
        );
        docs.push((n, doc));
    }

    let mut group = c.benchmark_group("doc_save_at_scale (50 members)");
    for (n, doc) in &mut docs {
        group.bench_with_input(BenchmarkId::from_parameter(*n), n, |b, _| {
            b.iter(|| doc.save())
        });
    }
    group.finish();

    // Also show how file count (members) affects merge time at fixed 300 secrets
    let member_counts: &[usize] = &[5, 10, 25, 50];
    println!("\n  [doc_size] serialised document size (300 secrets):");
    println!("  {:>10}  {:>12}  {:>10}", "members", "bytes", "KB");

    for &m in member_counts {
        let (state, _, _) = build_state(m, 300);
        let mut doc = state_to_doc(&state);
        let saved = doc.save();
        println!(
            "  {:>10}  {:>12}  {:>9.1}",
            m,
            saved.len(),
            saved.len() as f64 / 1024.0
        );
    }
}

/// Show how the full pipeline time scales with member count at 300 secrets.
fn bench_pipeline_member_scaling(c: &mut Criterion) {
    let member_counts: &[usize] = &[5, 10, 25, 50];

    let mut group = c.benchmark_group("pull pipeline scaling (300 secrets)");
    for &m in member_counts {
        let files = build_member_files(m, 300);
        group.bench_with_input(BenchmarkId::new("members", m), &m, |b, _| {
            b.iter(|| load_and_verify_merge(black_box(&files)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_pipeline_steps,
    bench_doc_size_growth,
    bench_pipeline_member_scaling,
);
criterion_main!(benches);
