use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph},
    Frame,
};

use lib::storage::StorageConfig;

use crate::tui::{
    component::{Component, EventResult},
    state::State,
};

fn storage_backend_label(config: &StorageConfig) -> &'static str {
    match config {
        StorageConfig::Fs(_) => "Local FS",
        StorageConfig::S3(_) => "S3",
        StorageConfig::R2(_) => "R2",
        StorageConfig::Webdav(_) => "WebDAV",
        StorageConfig::Github(_) => "GitHub",
    }
}

pub struct HeaderComponent {
    state: Arc<State>,
}

impl HeaderComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self { state }
    }

    pub const HEIGHT: u16 = 6;
}

#[async_trait]
impl Component for HeaderComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        let lines = vec![
            Line::from(
                Span::raw(self.state.device_name.clone()).style(Style::default().fg(Color::White)),
            ),
            Line::from(
                Span::raw(format!(
                    "{} • {}",
                    self.state.vault_name,
                    storage_backend_label(&self.state.storage_config),
                ))
                .style(Style::default().fg(Color::DarkGray)),
            ),
        ];

        let block = Block::default()
            .title(format!(" Envisible • v{VERSION} "))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .padding(Padding::new(1, 1, 1, 1));

        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, _event: Event) -> EventResult {
        EventResult::Ignored
    }
}
