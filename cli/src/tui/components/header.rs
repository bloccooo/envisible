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

        let mut vault_line = vec![Span::raw(format!(
            "{} • {}",
            self.state.vault_name,
            storage_backend_label(&self.state.storage_config),
        ))
        .style(Style::default().fg(Color::DarkGray))];

        if self.state.offline {
            vault_line.push(Span::raw("  "));
            vault_line.push(
                Span::raw("⚠ OFFLINE — showing cached data")
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            );
        }

        let lines = vec![
            Line::from(
                Span::raw(self.state.device_name.clone()).style(Style::default().fg(Color::White)),
            ),
            Line::from(vault_line),
        ];

        let border_color = if self.state.offline {
            Color::Yellow
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .title(format!(" Envisible • v{VERSION} "))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
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

#[cfg(test)]
mod tests {
    use super::*;
    use lib::storage::FsConfig;
    use ratatui::{backend::TestBackend, Terminal};
    use std::collections::HashSet;

    fn test_state(offline: bool) -> Arc<State> {
        Arc::new(State {
            device_name: "my-device".to_string(),
            vault_id: "vault-1".to_string(),
            vault_name: "Test Vault".to_string(),
            storage_config: StorageConfig::Fs(FsConfig {
                root: "/tmp".to_string(),
            }),
            footer: Default::default(),
            secrets: vec![],
            members: vec![],
            pending_grants: vec![],
            rotate_dek: false,
            private_key: [0u8; 32],
            selected_tags: HashSet::new(),
            offline,
        })
    }

    fn render_to_string(state: Arc<State>) -> String {
        let backend = TestBackend::new(60, HeaderComponent::HEIGHT);
        let mut terminal = Terminal::new(backend).unwrap();
        let component = HeaderComponent::new(state);
        terminal
            .draw(|frame| component.render(frame, frame.area()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn shows_offline_indicator_when_state_is_offline() {
        let out = render_to_string(test_state(true));
        assert!(out.contains("OFFLINE"), "expected OFFLINE indicator, got: {out}");
    }

    #[test]
    fn hides_offline_indicator_when_state_is_online() {
        let out = render_to_string(test_state(false));
        assert!(!out.contains("OFFLINE"), "did not expect OFFLINE indicator, got: {out}");
    }
}
