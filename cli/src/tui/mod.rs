mod actions;
mod component;
mod components;
mod doc;
mod pages;
mod router;
mod state;

use std::io;
use std::sync::Arc;

use automerge::AutoCommit;
use autosurgeon::hydrate;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use lib::{
    error::{Error, Result},
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
use doc::{apply_set_state, derive_state, is_doc_change};
use router::Router;
use state::{FooterState, FooterStatus, State};

pub async fn run(
    doc: AutoCommit,
    store: Store,
    session: Session,
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
            private_key: session.private_key,
        },
    ));

    let (tx, mut rx) = mpsc::channel::<Actions>(64);
    let mut state = initial_state;
    let mut router = Router::new(tx.clone(), state.clone());
    let mut persist_task: Option<JoinHandle<bool>> = None;
    let mut sync_task: Option<JoinHandle<Option<Vec<u8>>>> = None;

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
                state = Arc::new(State::cloned(&state).with_footer_status(status));
                router.update(state.clone()).await;
            }
        }

        // Check if the background sync task has completed.
        if let Some(handle) = &sync_task {
            if handle.is_finished() {
                let result = sync_task.take().unwrap().await.unwrap_or(None);
                let status = match result {
                    Some(bytes) => match AutoCommit::load(&bytes) {
                        Ok(mut pulled) => {
                            let _ = doc.merge(&mut pulled);
                            let new_state = derive_state(&doc, &session, &state);
                            state = Arc::new(new_state.with_footer_status(FooterStatus::Ok("✓ synced".to_string())));
                            router.update(state.clone()).await;
                            continue;
                        }
                        Err(_) => FooterStatus::Error("sync failed".to_string()),
                    },
                    None => FooterStatus::Error("sync failed".to_string()),
                };
                state = Arc::new(State::cloned(&state).with_footer_status(status));
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
                Actions::Sync => {
                    if sync_task.is_none() {
                        state = Arc::new(State::cloned(&state).with_footer_status(FooterStatus::Syncing));
                        router.update(state.clone()).await;
                        let store_clone = Arc::clone(&store);
                        sync_task = Some(tokio::spawn(async move {
                            store_clone.pull().await.ok().map(|mut d| d.save())
                        }));
                    }
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
