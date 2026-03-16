use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::prelude::*;
use tokio::sync::mpsc::Sender;

use crate::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    components::{header::HeaderComponent, secrets::SecretsComponent},
    state::State,
};

pub struct HomePage {
    actions_tx: Sender<Actions>,
    header: HeaderComponent,
    secrets: SecretsComponent,
}

impl HomePage {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            header: HeaderComponent::new(state.clone()),
            secrets: SecretsComponent::new(state.clone()),
            actions_tx,
        }
    }
}

#[async_trait]
impl Component for HomePage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(HeaderComponent::HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        self.header.render(frame, chunks[0]);
        self.secrets.render(frame, chunks[1]);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.header.update(state.clone()).await;
        self.secrets.update(state).await;
        let _ = self.actions_tx.send(Actions::Render).await;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if self.secrets.handle_event(event.clone()).await == EventResult::Consumed {
            return EventResult::Consumed;
        }

        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Char('q') => {
                    let _ = self.actions_tx.send(Actions::Exit).await;
                    return EventResult::Consumed;
                }
                KeyCode::Char('n') => {
                    let _ = self
                        .actions_tx
                        .send(Actions::NavigateTo(Route::NewSecret))
                        .await;
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }
        EventResult::Ignored
    }
}
