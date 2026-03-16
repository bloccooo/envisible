use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::Event;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use lib::storage::StorageConfig;

use crate::{component::{Component, EventResult}, state::State};

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

    pub const HEIGHT: u16 = 5;
}

#[async_trait]
impl Component for HeaderComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        let lines = vec![
            Line::from(Span::styled(
                format!("Envisible · v{VERSION}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::raw(self.state.device_name.clone())),
            Line::from(Span::raw(format!(
                "{} · {}",
                self.state.vault_name,
                storage_backend_label(&self.state.storage_config),
            ))),
        ];

        let block = Block::default()
            .title(" Envisible ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, _event: Event) -> EventResult {
        EventResult::Ignored
    }
}
