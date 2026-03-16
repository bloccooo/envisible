use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use tokio::sync::mpsc::Sender;

use crate::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    state::State,
};

pub struct TagFormPage {
    actions_tx: Sender<Actions>,
    state: Arc<State>,
    /// `None` = new tag, `Some(old_name)` = editing an existing tag.
    editing_tag: Option<String>,
    field_input: String,
    cursor: usize,
    title: &'static str,
}

impl TagFormPage {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            actions_tx,
            state,
            editing_tag: None,
            field_input: String::new(),
            cursor: 0,
            title: " New Tag ",
        }
    }

    pub fn new_edit(actions_tx: Sender<Actions>, state: Arc<State>, old_name: String) -> Self {
        let cursor = old_name.chars().count();
        Self {
            actions_tx,
            state,
            editing_tag: Some(old_name.clone()),
            field_input: old_name,
            cursor,
            title: " Edit Tag ",
        }
    }

    async fn submit(&mut self) {
        let new_name = self.field_input.trim().to_string();
        if new_name.is_empty() {
            let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
            return;
        }
        if let Some(old) = self.editing_tag.clone() {
            // Rename: update all secrets that carry the old tag name.
            if new_name != old {
                let new_state = Arc::new((*self.state).clone().with_tag_renamed(&old, &new_name));
                let _ = self.actions_tx.send(Actions::SetState(new_state)).await;
            }
            let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
        } else {
            // New tag: open home in tag-assignment mode so the user can attach it to secrets.
            let _ = self.actions_tx.send(Actions::NavigateTo(Route::HomeWithTagAssignment(new_name))).await;
        }
    }
}

#[async_trait]
impl Component for TagFormPage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(self.title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let input = &self.field_input;
        let cursor_pos = self.cursor;
        let before: String = input.chars().take(cursor_pos).collect();
        let at = input.chars().nth(cursor_pos).map(|c| c.to_string()).unwrap_or_else(|| " ".to_string());
        let after: String = input.chars().skip(cursor_pos + 1).collect();

        let lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "▶ Name ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::raw("  "),
                Span::raw(before),
                Span::styled(at, Style::default().bg(Color::White).fg(Color::Black)),
                Span::raw(after),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "  [Enter] Submit  [Esc] Cancel",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Esc => {
                    let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
                    return EventResult::Consumed;
                }
                KeyCode::Enter => {
                    self.submit().await;
                    return EventResult::Consumed;
                }
                KeyCode::Left => { if self.cursor > 0 { self.cursor -= 1; } }
                KeyCode::Right => { if self.cursor < self.field_input.chars().count() { self.cursor += 1; } }
                KeyCode::Home => self.cursor = 0,
                KeyCode::End => self.cursor = self.field_input.chars().count(),
                KeyCode::Backspace => {
                    if self.cursor > 0 {
                        let mut chars: Vec<char> = self.field_input.chars().collect();
                        chars.remove(self.cursor - 1);
                        self.field_input = chars.into_iter().collect();
                        self.cursor -= 1;
                    }
                }
                KeyCode::Delete => {
                    let len = self.field_input.chars().count();
                    if self.cursor < len {
                        let mut chars: Vec<char> = self.field_input.chars().collect();
                        chars.remove(self.cursor);
                        self.field_input = chars.into_iter().collect();
                    }
                }
                KeyCode::Char(c) => {
                    let mut chars: Vec<char> = self.field_input.chars().collect();
                    chars.insert(self.cursor, c);
                    self.field_input = chars.into_iter().collect();
                    self.cursor += 1;
                }
                _ => {}
            }
        }
        let _ = self.actions_tx.send(Actions::Render).await;
        EventResult::Consumed
    }
}
