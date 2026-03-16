use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use tokio::sync::mpsc::Sender;

use lib::invite::{generate_invite, VaultPayload};

use crate::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    state::State,
};

pub struct InvitePage {
    actions_tx: Sender<Actions>,
    invite_token: String,
}

impl InvitePage {
    pub const DEFAULT_HINT: &'static str = "[Esc] Close";

    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        let invite_token = generate_invite(
            &state.storage_config,
            VaultPayload { id: state.vault_id.clone(), name: state.vault_name.clone() },
        )
        .unwrap_or_else(|_| "(error generating token)".to_string());
        Self { actions_tx, invite_token }
    }
}

#[async_trait]
impl Component for InvitePage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "Invite Token",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Share this with the person you want to invite.",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(vec![Span::styled(
                "It contains your storage config (no credentials).",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(""),
            Line::from(self.invite_token.clone()),
            Line::from(""),
            Line::from(vec![
                Span::styled("They should run:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("envi setup {}", self.invite_token),
                    Style::default().fg(Color::White),
                ),
            ]),
        ];

        let block = Block::default()
            .title(" Invite ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        frame.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
            area,
        );
    }

    async fn update(&mut self, _state: Arc<State>) {}

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            if key.code == KeyCode::Esc {
                let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
                return EventResult::Consumed;
            }
        }
        EventResult::Ignored
    }
}
