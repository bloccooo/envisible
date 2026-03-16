use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::{layout::Rect, Frame};

use crate::tui::state::State;

#[derive(Debug, PartialEq, Eq)]
pub enum EventResult {
    Consumed,
    Ignored,
}

#[async_trait]
pub trait Component: Send {
    fn render(&self, frame: &mut Frame, area: Rect);
    async fn update(&mut self, state: Arc<State>);
    async fn handle_event(&mut self, event: Event) -> EventResult;
}
