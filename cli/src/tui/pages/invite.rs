use std::sync::Arc;

use arboard::Clipboard;
use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Padding, Paragraph, Wrap},
    Frame,
};
use tokio::sync::mpsc::Sender;
use tokio::time::Duration;

use lib::invite::{generate_invite, VaultPayload};

use crate::tui::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    state::{FooterStatus, State},
};

pub struct InvitePage {
    actions_tx: Sender<Actions>,
    invite_token: String,
    state: Arc<State>,
}

impl InvitePage {
    pub const DEFAULT_HINT: &'static str = "[c] Copy  [Esc] Close";

    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        let inviter_id = state
            .members
            .iter()
            .find(|m| m.is_me)
            .map(|m| m.id.as_str())
            .unwrap_or("");
        let invite_token = generate_invite(
            &state.storage_config,
            VaultPayload {
                id: state.vault_id.clone(),
                name: state.vault_name.clone(),
            },
            &state.private_key,
            inviter_id,
        )
        .unwrap_or_else(|_| "(error generating token)".to_string());
        Self {
            actions_tx,
            invite_token,
            state,
        }
    }
}

#[async_trait]
impl Component for InvitePage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(vec![Span::styled(
                "Token",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
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
        ];

        let block = Block::default()
            .title(" Invite ")
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .padding(Padding::uniform(1));

        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Char('c') => {
                    if let Ok(mut clipboard) = Clipboard::new() {
                        let _ = clipboard.set_text(self.invite_token.clone());
                    }
                    let tx = self.actions_tx.clone();
                    let copied_state = Arc::new(
                        State::cloned(&self.state).with_footer_status(FooterStatus::Ok(
                            "copied to clipboard".to_string(),
                        )),
                    );
                    let reset_state =
                        Arc::new(State::cloned(&self.state).with_footer_status(FooterStatus::Idle));
                    let _ = tx.send(Actions::SetState(copied_state)).await;
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let _ = tx.send(Actions::SetState(reset_state)).await;
                    });
                    return EventResult::Consumed;
                }
                KeyCode::Esc => {
                    let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }
        EventResult::Ignored
    }
}
