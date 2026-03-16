use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use tokio::sync::mpsc::Sender;

use crate::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    components::textarea::{TextAreaComponent, TextAreaEvent},
    state::{Secret, State},
};

const SECRET_FIELDS: &[(&str, bool)] = &[
    ("Name", false),
    ("Value", true),
    ("Description", false),
    ("Tags (comma-separated)", false),
];

pub struct NewSecretPage {
    actions_tx: Sender<Actions>,
    state: Arc<State>,
    field_idx: usize,
    field_input: String,
    cursor: usize,
    collected_values: Vec<String>,
    textarea: TextAreaComponent,
}

impl NewSecretPage {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            actions_tx,
            state,
            field_idx: 0,
            field_input: String::new(),
            cursor: 0,
            collected_values: vec![],
            textarea: TextAreaComponent::new(),
        }
    }

    fn is_textarea_field(&self) -> bool {
        self.field_idx == 1
    }

    fn advance_field(&mut self) {
        let value = if self.is_textarea_field() {
            self.textarea.value()
        } else {
            self.field_input.clone()
        };
        self.collected_values.push(value);
        self.field_idx += 1;
        self.field_input = String::new();
        self.cursor = 0;
        self.textarea.reset();
    }

    fn go_back_field(&mut self) {
        if self.field_idx == 0 {
            return;
        }
        let prev_value = self.collected_values.pop().unwrap_or_default();
        self.field_idx -= 1;

        if self.field_idx == 1 {
            self.textarea.set_value(&prev_value);
        } else {
            self.field_input = prev_value;
            self.cursor = self.field_input.chars().count();
        }
    }

    async fn submit(&mut self) {
        let mut all = self.collected_values.clone();
        all.push(self.field_input.clone());

        let mut new_state = (*self.state).clone();
        let id = (new_state.secrets.len() + 1).to_string();
        new_state.secrets.push(Secret {
            id,
            name: all.get(0).cloned().unwrap_or_default(),
            value: all.get(1).cloned().unwrap_or_default(),
            description: all.get(2).cloned().unwrap_or_default(),
            tags: all
                .get(3)
                .cloned()
                .unwrap_or_default()
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
        });

        let _ = self
            .actions_tx
            .send(Actions::SetState(Arc::new(new_state)))
            .await;
        let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
    }

    fn handle_text_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }
            KeyCode::Right => {
                if self.cursor < self.field_input.chars().count() {
                    self.cursor += 1;
                }
            }
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
                if self.cursor < self.field_input.chars().count() {
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

    fn render_form(&self, frame: &mut Frame, area: Rect) {

        let block = Block::default()
            .title(" New Secret ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        if self.is_textarea_field() {
            let inner = block.inner(area);
            frame.render_widget(block, area);
            self.render_textarea_form(frame, inner);
            return;
        }

        let mut lines: Vec<Line> = vec![Line::from("")];

        for (i, (label, is_secret)) in SECRET_FIELDS.iter().enumerate() {
            if i < self.field_idx {
                let value = self.collected_values.get(i).cloned().unwrap_or_default();
                let display = if *is_secret {
                    "••••••••".to_string()
                } else {
                    value
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {} ", label),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(display, Style::default().fg(Color::Green)),
                ]));
            } else if i == self.field_idx {
                lines.push(Line::from(vec![Span::styled(
                    format!("▶ {} ", label),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )]));

                let input = &self.field_input;
                let display = if *is_secret {
                    "•".repeat(input.chars().count())
                } else {
                    input.clone()
                };
                let cursor_pos = self.cursor;
                let before = if *is_secret {
                    "•".repeat(cursor_pos)
                } else {
                    input.chars().take(cursor_pos).collect::<String>()
                };
                let at = display
                    .chars()
                    .nth(cursor_pos)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| " ".to_string());
                let after = if *is_secret {
                    "•".repeat(input.chars().count().saturating_sub(cursor_pos + 1))
                } else {
                    input.chars().skip(cursor_pos + 1).collect::<String>()
                };

                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::raw(before),
                    Span::styled(at, Style::default().bg(Color::White).fg(Color::Black)),
                    Span::raw(after),
                ]));
            } else {
                lines.push(Line::from(vec![Span::styled(
                    format!("  {} ", label),
                    Style::default().fg(Color::DarkGray),
                )]));
            }
            lines.push(Line::from(""));
        }

        lines.push(Line::from(vec![Span::styled(
            "  [Enter] Next/Submit  [Up] Back  [Esc] Cancel",
            Style::default().fg(Color::DarkGray),
        )]));

        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_textarea_form(&self, frame: &mut Frame, area: Rect) {
        let header_height = (1 + self.field_idx * 2 + 1) as u16;

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(header_height),
                Constraint::Length(6),
                Constraint::Min(0),
            ])
            .split(area);

        let mut header_lines: Vec<Line> = vec![Line::from("")];
        for i in 0..self.field_idx {
            let (label, is_secret) = SECRET_FIELDS[i];
            let value = self.collected_values.get(i).cloned().unwrap_or_default();
            let display = if is_secret {
                "••••••••".to_string()
            } else {
                value
            };
            header_lines.push(Line::from(vec![
                Span::styled(
                    format!("  {} ", label),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(display, Style::default().fg(Color::Green)),
            ]));
            header_lines.push(Line::from(""));
        }
        header_lines.push(Line::from(vec![Span::styled(
            format!("▶ {} ", SECRET_FIELDS[self.field_idx].0),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]));
        frame.render_widget(Paragraph::new(header_lines), chunks[0]);

        self.textarea.render_area(frame, chunks[1], "Value");

        let mut footer_lines: Vec<Line> = vec![];
        for i in (self.field_idx + 1)..SECRET_FIELDS.len() {
            footer_lines.push(Line::from(vec![Span::styled(
                format!("  {} ", SECRET_FIELDS[i].0),
                Style::default().fg(Color::DarkGray),
            )]));
        }
        footer_lines.push(Line::from(""));
        footer_lines.push(Line::from(vec![Span::styled(
            "  [Enter] Newline  [Tab] Next  [Up] Back  [Esc] Cancel",
            Style::default().fg(Color::DarkGray),
        )]));
        frame.render_widget(Paragraph::new(footer_lines), chunks[2]);
    }
}

#[async_trait]
impl Component for NewSecretPage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        self.render_form(frame, area);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            if key.code == KeyCode::Esc {
                let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
                return EventResult::Consumed;
            }

            if self.is_textarea_field() {
                match self.textarea.handle_key(key) {
                    TextAreaEvent::NavigatePrev => self.go_back_field(),
                    TextAreaEvent::NavigateNext => self.advance_field(),
                    TextAreaEvent::Changed => {}
                }
            } else {
                match key.code {
                    KeyCode::Up => self.go_back_field(),
                    KeyCode::Down | KeyCode::Enter => {
                        if self.field_idx < SECRET_FIELDS.len() - 1 {
                            self.advance_field();
                        } else if key.code == KeyCode::Enter {
                            self.submit().await;
                            return EventResult::Consumed;
                        }
                    }
                    _ => self.handle_text_input(key),
                }
            }
        }
        let _ = self.actions_tx.send(Actions::Render).await;
        EventResult::Consumed
    }
}
