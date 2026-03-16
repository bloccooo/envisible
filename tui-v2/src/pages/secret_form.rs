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
    state::State,
};

const SECRET_FIELDS: &[(&str, bool)] = &[
    ("Name", false),
    ("Value", true),
    ("Description", false),
    ("Tags (comma-separated)", false),
];

pub struct SecretFormPage {
    actions_tx: Sender<Actions>,
    state: Arc<State>,
    editing_id: Option<String>,
    initial_values: Vec<String>,
    field_idx: usize,
    field_input: String,
    cursor: usize,
    collected_values: Vec<String>,
    tag_ac_matches: Vec<String>,
    tag_ac_idx: Option<usize>,
    textarea: TextAreaComponent,
    title: &'static str,
}

impl SecretFormPage {
    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            actions_tx,
            state,
            editing_id: None,
            initial_values: vec![],
            field_idx: 0,
            field_input: String::new(),
            cursor: 0,
            collected_values: vec![],
            tag_ac_matches: vec![],
            tag_ac_idx: None,
            textarea: TextAreaComponent::new(),
            title: " New Secret ",
        }
    }

    pub fn new_edit(actions_tx: Sender<Actions>, state: Arc<State>, id: String, initial_values: Vec<String>) -> Self {
        let first = initial_values.first().cloned().unwrap_or_default();
        let cursor = first.chars().count();
        let mut textarea = TextAreaComponent::new();
        let value_str = initial_values.get(1).cloned().unwrap_or_default();
        if !value_str.is_empty() {
            textarea.set_value(&value_str);
        }
        let mut page = Self {
            actions_tx,
            state,
            editing_id: Some(id),
            initial_values: initial_values.clone(),
            field_idx: 0,
            field_input: first,
            cursor,
            collected_values: vec![],
            tag_ac_matches: vec![],
            tag_ac_idx: None,
            textarea,
            title: " Edit Secret ",
        };
        page.update_tag_ac();
        page
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
        let next_idx = self.field_idx + 1;
        let next_initial = self.initial_values.get(next_idx).cloned().unwrap_or_default();
        self.collected_values.push(value);
        self.field_idx = next_idx;
        self.field_input = next_initial.clone();
        self.cursor = next_initial.chars().count();
        self.update_tag_ac();
    }

    fn go_back_field(&mut self) {
        if self.field_idx == 0 { return; }
        let prev_idx = self.field_idx - 1;
        let prev_value = self.collected_values.pop().unwrap_or_default();
        self.field_idx = prev_idx;
        if prev_idx == 1 {
            self.textarea.set_value(&prev_value);
        } else {
            self.field_input = prev_value;
            self.cursor = self.field_input.chars().count();
        }
        self.update_tag_ac();
    }

    async fn submit(&mut self) {
        let mut all = self.collected_values.clone();
        all.push(self.field_input.clone());
        let name = all.first().cloned().unwrap_or_default();
        let value = all.get(1).cloned().unwrap_or_default();
        let description = all.get(2).cloned().unwrap_or_default();
        let tags = split_tags(all.get(3).cloned().unwrap_or_default().as_str());
        let new_state = if let Some(id) = &self.editing_id.clone() {
            (*self.state).clone().with_secret_updated(id, name, value, description, tags)
        } else {
            (*self.state).clone().with_secret_added(name, value, description, tags)
        };
        let _ = self.actions_tx.send(Actions::SetState(Arc::new(new_state))).await;
        let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
    }

    fn update_tag_ac(&mut self) {
        if self.field_idx != 3 {
            self.tag_ac_matches.clear();
            self.tag_ac_idx = None;
            return;
        }
        let current_token = self.field_input
            .split(',')
            .last()
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        let entered: std::collections::HashSet<String> = self.field_input
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        self.tag_ac_matches = self.state.tags().iter()
            .filter(|t| {
                let tl = t.to_lowercase();
                !entered.contains(&tl) && (current_token.is_empty() || tl.starts_with(&current_token))
            })
            .cloned()
            .collect();
        if self.tag_ac_matches.is_empty() {
            self.tag_ac_idx = None;
        } else if let Some(idx) = self.tag_ac_idx {
            self.tag_ac_idx = Some(idx.min(self.tag_ac_matches.len() - 1));
        }
    }

    fn insert_ac_tag(&mut self, selected: &str) {
        let new_input = if let Some(comma_pos) = self.field_input.rfind(',') {
            let prefix = self.field_input[..comma_pos].trim_end();
            if prefix.is_empty() {
                format!("{selected}, ")
            } else {
                format!("{prefix}, {selected}, ")
            }
        } else {
            format!("{selected}, ")
        };
        self.field_input = new_input;
        self.cursor = self.field_input.chars().count();
    }

    fn handle_text_input(&mut self, key: KeyEvent) {
        match key.code {
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

    fn render_form(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(self.title)
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
                let display = if *is_secret { "••••••••".to_string() } else { value };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {} ", label), Style::default().fg(Color::DarkGray)),
                    Span::styled(display, Style::default().fg(Color::Green)),
                ]));
            } else if i == self.field_idx {
                lines.push(Line::from(vec![Span::styled(
                    format!("▶ {} ", label),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )]));

                let input = &self.field_input;
                let display = if *is_secret { "•".repeat(input.chars().count()) } else { input.clone() };
                let cursor_pos = self.cursor;
                let before: String = if *is_secret {
                    "•".repeat(cursor_pos)
                } else {
                    input.chars().take(cursor_pos).collect()
                };
                let at = display.chars().nth(cursor_pos).map(|c| c.to_string()).unwrap_or_else(|| " ".to_string());
                let after: String = if *is_secret {
                    "•".repeat(input.chars().count().saturating_sub(cursor_pos + 1))
                } else {
                    input.chars().skip(cursor_pos + 1).collect()
                };

                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::raw(before),
                    Span::styled(at, Style::default().bg(Color::White).fg(Color::Black)),
                    Span::raw(after),
                ]));

                // Tag autocomplete dropdown (tags field only).
                if i == 3 && !self.tag_ac_matches.is_empty() {
                    const MAX_VISIBLE: usize = 5;
                    for (j, tag) in self.tag_ac_matches.iter().take(MAX_VISIBLE).enumerate() {
                        if self.tag_ac_idx == Some(j) {
                            lines.push(Line::from(vec![
                                Span::raw("  "),
                                Span::styled(format!("▶ {tag}"), Style::default().bg(Color::Cyan).fg(Color::Black)),
                            ]));
                        } else {
                            lines.push(Line::from(vec![
                                Span::raw("  "),
                                Span::styled(format!("  {tag}"), Style::default().fg(Color::DarkGray)),
                            ]));
                        }
                    }
                    if self.tag_ac_matches.len() > MAX_VISIBLE {
                        lines.push(Line::from(Span::styled(
                            format!("  … {} more", self.tag_ac_matches.len() - MAX_VISIBLE),
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
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
            let display = if is_secret { "••••••••".to_string() } else { value };
            header_lines.push(Line::from(vec![
                Span::styled(format!("  {} ", label), Style::default().fg(Color::DarkGray)),
                Span::styled(display, Style::default().fg(Color::Green)),
            ]));
            header_lines.push(Line::from(""));
        }
        header_lines.push(Line::from(vec![Span::styled(
            format!("▶ {} ", SECRET_FIELDS[self.field_idx].0),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
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
impl Component for SecretFormPage {
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
                // Tag autocomplete intercept on the tags field.
                let on_tags_field = self.field_idx == 3;
                if on_tags_field && !self.tag_ac_matches.is_empty() {
                    match key.code {
                        KeyCode::Down => {
                            self.tag_ac_idx = Some(
                                self.tag_ac_idx.map_or(0, |i| (i + 1).min(self.tag_ac_matches.len() - 1)),
                            );
                            let _ = self.actions_tx.send(Actions::Render).await;
                            return EventResult::Consumed;
                        }
                        KeyCode::Up if self.tag_ac_idx.is_some() => {
                            self.tag_ac_idx = self.tag_ac_idx.and_then(|i| if i == 0 { None } else { Some(i - 1) });
                            let _ = self.actions_tx.send(Actions::Render).await;
                            return EventResult::Consumed;
                        }
                        KeyCode::Enter if self.tag_ac_idx.is_some() => {
                            let selected = self.tag_ac_matches[self.tag_ac_idx.unwrap()].clone();
                            self.insert_ac_tag(&selected);
                            self.tag_ac_idx = None;
                            self.update_tag_ac();
                            let _ = self.actions_tx.send(Actions::Render).await;
                            return EventResult::Consumed;
                        }
                        _ => { self.tag_ac_idx = None; }
                    }
                }

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
                    _ => {
                        self.handle_text_input(key);
                        self.update_tag_ac();
                    }
                }
            }
        }
        let _ = self.actions_tx.send(Actions::Render).await;
        EventResult::Consumed
    }
}

fn split_tags(s: &str) -> Vec<String> {
    s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()
}
