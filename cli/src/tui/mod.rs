mod actions;
mod component;
mod components;
mod pages;
mod router;
mod state;

use std::io;
use std::sync::Arc;

use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use lib::{
    crypto::{compute_key_mac, encrypt_field, wrap_dek},
    error::{Error, Result},
    members::{remove_member, rotate_dek},
    secrets::list_secrets,
    storage::StorageConfig,
    store::{Session, Store},
    types::EnviDocument,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;

use actions::Actions;
use component::Component;
use router::Router;
use state::{FooterState, FooterStatus, Member, Secret, State};

pub async fn run(
    doc: AutoCommit,
    store: Store,
    session: Session,
    _invite_token: String,
    device_name: String,
    vault_name: String,
    storage_config: StorageConfig,
) -> Result<()> {
    enable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| Error::Other(e.to_string()))?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| Error::Other(e.to_string()))?;

    let result = run_app(
        &mut terminal,
        doc,
        store,
        session,
        device_name,
        vault_name,
        storage_config,
    )
    .await;

    disable_raw_mode().map_err(|e| Error::Other(e.to_string()))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .map_err(|e| Error::Other(e.to_string()))?;
    terminal
        .show_cursor()
        .map_err(|e| Error::Other(e.to_string()))?;

    result
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut doc: AutoCommit,
    store: Store,
    mut session: Session,
    device_name: String,
    vault_name: String,
    storage_config: StorageConfig,
) -> Result<()> {
    let store = Arc::new(store);
    let vault_id = {
        let envi: EnviDocument = hydrate(&doc).map_err(|e| Error::Other(e.to_string()))?;
        envi.id.clone()
    };

    let initial_state = Arc::new(derive_state(
        &doc,
        &session,
        &State {
            device_name,
            vault_id,
            vault_name,
            storage_config,
            footer: FooterState::default(),
            secrets: vec![],
            members: vec![],
            pending_grants: vec![],
            rotate_dek: false,
        },
    ));

    let (tx, mut rx) = mpsc::channel::<Actions>(64);
    let mut state = initial_state;
    let mut router = Router::new(tx.clone(), state.clone());
    let mut persist_task: Option<JoinHandle<bool>> = None;

    loop {
        // Check if the background persist task has completed.
        if let Some(handle) = &persist_task {
            if handle.is_finished() {
                let success = persist_task.take().unwrap().await.unwrap_or(false);
                let status = if success {
                    FooterStatus::Ok("✓ saved".to_string())
                } else {
                    FooterStatus::Error("save failed".to_string())
                };
                state = Arc::new((*state).clone().with_footer_status(status));
                router.update(state.clone()).await;
            }
        }

        // Drain all pending actions (non-blocking).
        while let Ok(action) = rx.try_recv() {
            match action {
                Actions::Exit => {
                    return Ok(());
                }
                Actions::SetState(new_state) => {
                    if !is_doc_change(&state, &new_state) {
                        // Footer/hint only — no doc mutation needed.
                        state = new_state;
                        router.update(state.clone()).await;
                        continue;
                    }

                    match apply_set_state(&mut doc, &mut session, &state, &new_state) {
                        Ok(mut canonical) => {
                            canonical.footer = new_state.footer.clone();
                            canonical.footer.status = FooterStatus::Syncing;
                            state = Arc::new(canonical);
                            router.update(state.clone()).await;

                            let doc_bytes = doc.save();
                            let store_clone = Arc::clone(&store);
                            let signing_key = session.signing_key.clone();
                            persist_task = Some(tokio::spawn(async move {
                                match AutoCommit::load(&doc_bytes) {
                                    Ok(mut d) => {
                                        store_clone.persist(&mut d, &signing_key).await.is_ok()
                                    }
                                    Err(_) => false,
                                }
                            }));
                        }
                        Err(e) => {
                            state = Arc::new(
                                (*new_state)
                                    .clone()
                                    .with_footer_status(FooterStatus::Error(e.to_string())),
                            );
                            router.update(state.clone()).await;
                        }
                    }
                }
                Actions::NavigateTo(route) => {
                    router.navigate(route);
                }
            }
        }

        // Draw current state.
        terminal
            .draw(|frame| {
                let area = frame.area();
                router.render(frame, area);
            })
            .map_err(|e| Error::Other(e.to_string()))?;

        // Wait for the next terminal event (blocks up to 16ms, ~60fps).
        if event::poll(Duration::from_millis(16)).map_err(|e| Error::Other(e.to_string()))? {
            let ev = event::read().map_err(|e| Error::Other(e.to_string()))?;
            if let Event::Key(key) = &ev {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }
            }
            router.handle_event(ev).await;
        }
    }
}

/// Returns true if new_state requires a doc mutation (vs a footer-only update).
fn is_doc_change(old: &State, new: &State) -> bool {
    new.rotate_dek
        || !new.pending_grants.is_empty()
        || old.secrets != new.secrets
        || old.members.len() != new.members.len()
        || old
            .members
            .iter()
            .zip(new.members.iter())
            .any(|(o, n)| o.id != n.id)
}

/// Apply the doc changes implied by new_state and return the re-derived canonical State.
/// The caller is responsible for restoring the footer from new_state.
fn apply_set_state(
    doc: &mut AutoCommit,
    session: &mut Session,
    old: &State,
    new: &State,
) -> Result<State> {
    // ── DEK rotation (lib handles full re-encryption internally) ──────────────
    if new.rotate_dek {
        let new_dek = rotate_dek(doc, &session.dek)?;
        session.dek = new_dek;
        return Ok(derive_state(doc, session, new));
    }

    // ── Member removal (triggers internal DEK rotation) ───────────────────────
    let removed: Vec<String> = old
        .members
        .iter()
        .filter(|m| !new.members.iter().any(|nm| nm.id == m.id))
        .map(|m| m.id.clone())
        .collect();
    if !removed.is_empty() {
        for id in &removed {
            let new_dek = remove_member(doc, &session.dek, id)?;
            session.dek = new_dek;
        }
        return Ok(derive_state(doc, session, new));
    }

    // ── Grant + secret/tag changes: build EnviDocument and reconcile ──────────
    let mut effective = new.clone();

    for id in &new.pending_grants {
        if let Some(m) = effective.members.iter_mut().find(|m| m.id == *id) {
            let pub_key_bytes = B64
                .decode(&m.public_key)
                .map_err(|_| Error::DecryptionFailed)?;
            let pub_key: [u8; 32] = pub_key_bytes
                .try_into()
                .map_err(|_| Error::DecryptionFailed)?;
            m.wrapped_dek = wrap_dek(&session.dek, &pub_key)?;
            m.key_mac =
                compute_key_mac(&session.dek, &m.id, &m.public_key, &m.signing_key);
        }
    }
    effective.pending_grants.clear();

    let envi = state_to_envi_doc(doc, &effective, &session.dek)?;
    reconcile(doc, &envi).map_err(|e| Error::Other(e.to_string()))?;

    Ok(derive_state(doc, session, &effective))
}

/// Build an EnviDocument from State by encrypting all plaintext secrets.
/// Starts from the current doc (preserves doc_version, document_signature, etc.)
/// then overwrites secrets and members entirely from State.
fn state_to_envi_doc(doc: &AutoCommit, state: &State, dek: &[u8; 32]) -> Result<EnviDocument> {
    let mut envi: EnviDocument = hydrate(doc).map_err(|e| Error::Other(e.to_string()))?;

    envi.secrets.clear();
    for s in &state.secrets {
        let tags_json = serde_json::to_string(&s.tags)?;
        envi.secrets.insert(
            s.id.clone(),
            lib::types::Secret {
                id: s.id.clone(),
                name: encrypt_field(&s.name, dek)?,
                value: encrypt_field(&s.value, dek)?,
                description: encrypt_field(&s.description, dek)?,
                tags: encrypt_field(&tags_json, dek)?,
            },
        );
    }

    envi.members.clear();
    for m in &state.members {
        envi.members.insert(
            m.id.clone(),
            lib::types::Member {
                id: m.id.clone(),
                email: m.email.clone(),
                public_key: m.public_key.clone(),
                wrapped_dek: m.wrapped_dek.clone(),
                signing_key: m.signing_key.clone(),
                key_mac: m.key_mac.clone(),
            },
        );
    }

    Ok(envi)
}

/// Re-derive the in-memory State from the automerge document.
/// Copies footer from `current` so hints and status are preserved.
/// Always resets rotate_dek and pending_grants.
fn derive_state(doc: &AutoCommit, session: &Session, current: &State) -> State {
    let envi: EnviDocument = hydrate(doc).unwrap_or_default();

    let mut secrets: Vec<Secret> = list_secrets(doc, &session.dek)
        .unwrap_or_default()
        .into_iter()
        .map(|s| Secret {
            id: s.id,
            name: s.name,
            value: s.value,
            description: s.description,
            tags: s.tags,
        })
        .collect();
    secrets.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    let mut members: Vec<Member> = envi
        .members
        .values()
        .map(|m| Member {
            id: m.id.clone(),
            email: m.email.clone(),
            public_key: m.public_key.clone(),
            wrapped_dek: m.wrapped_dek.clone(),
            signing_key: m.signing_key.clone(),
            key_mac: m.key_mac.clone(),
            is_me: m.id == session.member_id,
        })
        .collect();
    members.sort_by(|a, b| a.email.cmp(&b.email));

    State {
        device_name: current.device_name.clone(),
        vault_id: current.vault_id.clone(),
        vault_name: current.vault_name.clone(),
        storage_config: current.storage_config.clone(),
        footer: current.footer.clone(),
        secrets,
        members,
        pending_grants: vec![],
        rotate_dek: false,
    }
}
