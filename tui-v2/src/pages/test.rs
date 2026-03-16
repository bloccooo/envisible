use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::{
    prelude::*,
    widgets::{Block, Paragraph},
};
use tokio::sync::mpsc::Sender;

use crate::{actions::Actions, component::{Component, EventResult}, state::State};

pub struct TestPage {
    actions_tx: Sender<Actions>,
}

impl TestPage {
    pub fn new(actions_tx: Sender<Actions>) -> Self {
        Self { actions_tx }
    }
}

#[async_trait]
impl Component for TestPage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new("This is the test page").block(Block::bordered().title("tui-v2")),
            area,
        );
    }

    async fn update(&mut self, _state: Arc<State>) {
        let _ = self.actions_tx.send(Actions::Render).await;
    }

    async fn handle_event(&mut self, _event: Event) -> EventResult {
        EventResult::Ignored
    }
}
