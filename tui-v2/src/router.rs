use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use tokio::sync::mpsc::Sender;

use crate::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    pages::{home::HomePage, new_secret::NewSecretPage},
    state::State,
};

pub struct Router {
    state: Arc<State>,
    actions_tx: Sender<Actions>,
    current_page: Box<dyn Component>,
}

impl Router {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            current_page: Box::new(HomePage::new(actions_tx.clone(), state.clone())),
            actions_tx,
            state,
        }
    }

    pub fn navigate(&mut self, route: Route) {
        self.current_page = match route {
            Route::Home => Box::new(HomePage::new(self.actions_tx.clone(), self.state.clone())),
            Route::NewSecret => {
                Box::new(NewSecretPage::new(self.actions_tx.clone(), self.state.clone()))
            }
        };
    }
}

#[async_trait]
impl Component for Router {
    async fn handle_event(&mut self, event: Event) -> EventResult {
        self.current_page.handle_event(event).await
    }

    fn render(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.current_page.render(frame, area);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state.clone();
        self.current_page.update(state).await;
    }
}
