use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::{component::{Component, EventResult}, state::State};

pub struct HeaderComponent {
    state: Arc<State>,
}

impl HeaderComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self { state }
    }

    pub const HEIGHT: u16 = 5;
}

#[async_trait]
impl Component for HeaderComponent {
    fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(Self::HEIGHT), Constraint::Min(0)])
            .split(area);
        self.render_area(frame, chunks[0]);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, _event: Event) -> EventResult {
        EventResult::Ignored
    }
}

impl HeaderComponent {
    pub fn render_area(&self, frame: &mut Frame, area: Rect) {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        let lines = vec![
            Line::from(Span::styled(
                format!("bKey · v{VERSION}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::raw(self.state.device_name.clone())),
            Line::from(Span::raw(format!(
                "{} · {}",
                self.state.vault_name, self.state.storage_backend
            ))),
        ];

        let block = Block::default()
            .title(" bKey ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        frame.render_widget(Paragraph::new(lines).block(block), area);
    }
}
