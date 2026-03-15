use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::Frame;

use crate::state::State;

/// Returned by [`Component::handle_event`] to indicate whether the event was consumed.
/// A `Consumed` result stops propagation — the parent will not handle the event.
#[derive(Debug, PartialEq, Eq)]
pub enum EventResult {
    /// The event was handled. Parent should not process it further.
    Consumed,
    /// The event was not handled. Parent may handle it.
    Ignored,
}

#[async_trait]
pub trait Component: Send {
    fn render(&self, frame: &mut Frame);
    async fn update(&mut self, state: Arc<State>);
    async fn handle_event(&mut self, event: Event) -> EventResult;
}
