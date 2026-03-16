use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::layout::{Constraint, Direction, Layout};
use tokio::sync::mpsc::Sender;

use crate::tui::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    components::footer::FooterComponent,
    pages::{
        home::HomePage, invite::InvitePage, secret_form::SecretFormPage, tag_form::TagFormPage,
    },
    state::State,
};

pub struct Router {
    state: Arc<State>,
    actions_tx: Sender<Actions>,
    current_page: Box<dyn Component>,
}

impl Router {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        let state = Arc::new((*state).clone().with_footer_hint(HomePage::DEFAULT_HINT));
        Self {
            current_page: Box::new(HomePage::new(actions_tx.clone(), state.clone())),
            actions_tx,
            state,
        }
    }

    pub fn navigate(&mut self, route: Route) {
        let hint = match &route {
            Route::Home | Route::HomeWithTagAssignment(_) => HomePage::DEFAULT_HINT,
            Route::NewSecret | Route::EditSecret(_) => {
                "[Tab] Next field  [Enter] Submit  [Esc] Cancel"
            }
            Route::NewTag | Route::EditTag(_) => "[Enter] Submit  [Esc] Cancel",
            Route::Invite => InvitePage::DEFAULT_HINT,
        };
        self.state = Arc::new((*self.state).clone().with_footer_hint(hint));
        let _ = self
            .actions_tx
            .try_send(Actions::SetState(self.state.clone()));

        self.current_page = match route {
            Route::Home => Box::new(HomePage::new(self.actions_tx.clone(), self.state.clone())),
            Route::NewSecret => Box::new(SecretFormPage::new(
                self.actions_tx.clone(),
                self.state.clone(),
            )),
            Route::EditSecret(id) => {
                let values = self
                    .state
                    .secrets
                    .iter()
                    .find(|s| s.id == id)
                    .map(|s| {
                        vec![
                            s.name.clone(),
                            s.value.clone(),
                            s.description.clone(),
                            s.tags.join(", "),
                        ]
                    })
                    .unwrap_or_default();
                Box::new(SecretFormPage::new_edit(
                    self.actions_tx.clone(),
                    self.state.clone(),
                    id,
                    values,
                ))
            }
            Route::NewTag => Box::new(TagFormPage::new(
                self.actions_tx.clone(),
                self.state.clone(),
            )),
            Route::EditTag(tag) => Box::new(TagFormPage::new_edit(
                self.actions_tx.clone(),
                self.state.clone(),
                tag,
            )),
            Route::HomeWithTagAssignment(tag) => Box::new(HomePage::new_with_tag_assignment(
                self.actions_tx.clone(),
                self.state.clone(),
                tag,
            )),
            Route::Invite => Box::new(InvitePage::new(self.actions_tx.clone(), self.state.clone())),
        };
    }
}

#[async_trait]
impl Component for Router {
    fn render(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(area);

        self.current_page.render(frame, chunks[0]);
        FooterComponent::render(frame, chunks[1], &self.state.footer);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state.clone();
        self.current_page.update(state).await;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        self.current_page.handle_event(event).await
    }
}
