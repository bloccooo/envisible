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
    crypto::{compute_key_mac, wrap_dek},
    error::{Error, Result},
    members::{remove_member, rotate_dek},
    secrets::{add_secret, list_secrets, update_secret, PlaintextSecretFields},
    storage::StorageConfig,
    store::{Session, Store},
    types::EnviDocument,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Duration;

use actions::{Actions, DocMutation};
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

    // Build initial state from the real document.
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
                    state = new_state;
                    router.update(state.clone()).await;
                }
                Actions::ApplyMutation(mutation, hint) => {
                    match apply_mutation(&mut doc, &mut session, &state, mutation) {
                        Ok(()) => {
                            let mut new_state = derive_state(&doc, &session, &state);
                            if let Some(h) = hint {
                                new_state = new_state.with_footer_hint(h);
                            }
                            new_state.footer.status = FooterStatus::Syncing;
                            state = Arc::new(new_state);
                            router.update(state.clone()).await;

                            // Spawn background persist task.
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
                                (*state)
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
            // Ctrl+C exits unconditionally.
            if let Event::Key(key) = &ev {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }
            }
            router.handle_event(ev).await;
        }
    }
}

/// Re-derive the in-memory State from the automerge document.
/// Copies footer from `current` so hints and status are preserved.
fn derive_state(doc: &AutoCommit, session: &Session, current: &State) -> State {
    let envi_state: EnviDocument = hydrate(doc).unwrap_or_default();

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

    let mut members: Vec<Member> = envi_state
        .members
        .values()
        .map(|m| Member {
            id: m.id.clone(),
            email: m.email.clone(),
            is_me: m.id == session.member_id,
            is_pending: m.wrapped_dek.is_empty(),
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
    }
}

/// Apply a document mutation. Mutates `doc` and/or `session` in-place.
fn apply_mutation(
    doc: &mut AutoCommit,
    session: &mut Session,
    current_state: &State,
    mutation: DocMutation,
) -> Result<()> {
    match mutation {
        DocMutation::AddSecret {
            name,
            value,
            description,
            tags,
        } => {
            add_secret(
                doc,
                &session.dek,
                PlaintextSecretFields {
                    name,
                    value,
                    description,
                    tags,
                },
            )?;
        }
        DocMutation::UpdateSecret {
            id,
            name,
            value,
            description,
            tags,
        } => {
            update_secret(
                doc,
                &session.dek,
                &id,
                PlaintextSecretFields {
                    name,
                    value,
                    description,
                    tags,
                },
            )?;
        }
        DocMutation::DeleteSecret { id } => {
            lib::secrets::remove_secret(doc, &id)?;
        }
        DocMutation::RenameTag { old, new_name } => {
            for secret in &current_state.secrets {
                if secret.tags.contains(&old) {
                    let tags = secret
                        .tags
                        .iter()
                        .map(|t| {
                            if t == &old {
                                new_name.clone()
                            } else {
                                t.clone()
                            }
                        })
                        .collect();
                    update_secret(
                        doc,
                        &session.dek,
                        &secret.id,
                        PlaintextSecretFields {
                            name: secret.name.clone(),
                            value: secret.value.clone(),
                            description: secret.description.clone(),
                            tags,
                        },
                    )?;
                }
            }
        }
        DocMutation::DeleteTag { tag } => {
            for secret in &current_state.secrets {
                if secret.tags.contains(&tag) {
                    let tags = secret.tags.iter().filter(|t| *t != &tag).cloned().collect();
                    update_secret(
                        doc,
                        &session.dek,
                        &secret.id,
                        PlaintextSecretFields {
                            name: secret.name.clone(),
                            value: secret.value.clone(),
                            description: secret.description.clone(),
                            tags,
                        },
                    )?;
                }
            }
        }
        DocMutation::SaveTagAssignments { tag, selected_ids } => {
            for secret in &current_state.secrets {
                let has = selected_ids.contains(&secret.id);
                let had = secret.tags.contains(&tag);
                if has != had {
                    let mut tags = secret.tags.clone();
                    if has {
                        tags.push(tag.clone());
                    } else {
                        tags.retain(|t| t != &tag);
                    }
                    update_secret(
                        doc,
                        &session.dek,
                        &secret.id,
                        PlaintextSecretFields {
                            name: secret.name.clone(),
                            value: secret.value.clone(),
                            description: secret.description.clone(),
                            tags,
                        },
                    )?;
                }
            }
        }
        DocMutation::GrantMember { id } => {
            let envi_state: EnviDocument =
                hydrate(doc as &AutoCommit).map_err(|e| Error::Other(e.to_string()))?;
            if let Some(m) = envi_state.members.get(&id) {
                let pub_key_bytes = B64
                    .decode(&m.public_key)
                    .map_err(|_| Error::DecryptionFailed)?;
                let pub_key: [u8; 32] = pub_key_bytes
                    .try_into()
                    .map_err(|_| Error::DecryptionFailed)?;
                let wrapped = wrap_dek(&session.dek, &pub_key)?;
                let key_mac = compute_key_mac(&session.dek, &m.id, &m.public_key, &m.signing_key);
                let mut new_envi = envi_state;
                if let Some(m) = new_envi.members.get_mut(&id) {
                    m.wrapped_dek = wrapped;
                    m.key_mac = key_mac;
                }
                reconcile(doc, &new_envi).map_err(|e| Error::Other(e.to_string()))?;
            }
        }
        DocMutation::RemoveMember { id } => {
            let new_dek = remove_member(doc, &session.dek, &id)?;
            session.dek = new_dek;
        }
        DocMutation::RotateDek => {
            let new_dek = rotate_dek(doc, &session.dek)?;
            session.dek = new_dek;
        }
    }
    Ok(())
}
