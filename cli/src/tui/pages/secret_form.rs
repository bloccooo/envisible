use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use tokio::sync::mpsc::Sender;

use crate::tui::{
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

/// Column width reserved for labels in completed rows.
const LABEL_WIDTH: usize = 14;
/// Max autocomplete suggestions shown at once.
const AC_MAX: usize = 5;
/// Height of the textarea input box (borders + content rows).
const TEXTAREA_HEIGHT: u16 = 6;

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
    pub const DEFAULT_HINT: &'static str = "[↑↓ Tab] Navigate  [Enter] Submit  [Esc] Cancel";

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
            title: "New Secret",
        }
    }

    pub fn new_edit(
        actions_tx: Sender<Actions>,
        state: Arc<State>,
        id: String,
        initial_values: Vec<String>,
    ) -> Self {
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
            title: "Edit Secret",
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
        let next_initial = self
            .initial_values
            .get(next_idx)
            .cloned()
            .unwrap_or_default();
        self.collected_values.push(value);
        self.field_idx = next_idx;
        self.field_input = next_initial.clone();
        self.cursor = next_initial.chars().count();
        self.update_tag_ac();
    }

    fn go_back_field(&mut self) {
        if self.field_idx == 0 {
            return;
        }
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

        let new_state = if let Some(id) = self.editing_id.clone() {
            State::cloned(&self.state).with_secret_updated(id, name, value, description, tags)
        } else {
            State::cloned(&self.state).with_secret_added(name, value, description, tags)
        };
        let _ = self
            .actions_tx
            .send(Actions::SetState(Arc::new(new_state)))
            .await;
        let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
    }

    fn update_tag_ac(&mut self) {
        if self.field_idx != 3 {
            self.tag_ac_matches.clear();
            self.tag_ac_idx = None;
            return;
        }
        let current_token = self
            .field_input
            .split(',')
            .last()
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        let entered: std::collections::HashSet<String> = self
            .field_input
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        self.tag_ac_matches = self
            .state
            .tags()
            .iter()
            .filter(|t| {
                let tl = t.to_lowercase();
                !entered.contains(&tl)
                    && (current_token.is_empty() || tl.starts_with(&current_token))
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

    // ── Rendering ─────────────────────────────────────────────────────────────

    fn render_form(&self, frame: &mut Frame, area: Rect) {
        let form_area = area;

        let step = self.field_idx + 1;
        let total = SECRET_FIELDS.len();
        let title = format!(" {} • {} of {} ", self.title, step, total);

        let outer = Block::default()
            .title(title)
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = outer.inner(form_area);
        frame.render_widget(outer, form_area);

        // Autocomplete height (tags field only).
        let ac_count = if self.field_idx == 3 && !self.tag_ac_matches.is_empty() {
            self.tag_ac_matches.len().min(AC_MAX) as u16
                + if self.tag_ac_matches.len() > AC_MAX {
                    1
                } else {
                    0
                }
        } else {
            0
        };

        // pre  = top padding (1) + completed fields (field_idx × 2)
        let pre_h = 1 + self.field_idx as u16 * 2;
        let input_h = if self.is_textarea_field() {
            TEXTAREA_HEIGHT
        } else {
            1
        };
        let post_h = (SECRET_FIELDS.len() - self.field_idx - 1) as u16;

        let v_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(pre_h),    // completed fields + top padding
                Constraint::Length(1),        // active field label
                Constraint::Length(1),        // spacing between label and input
                Constraint::Length(input_h),                          // active input
                Constraint::Length(if ac_count > 0 { 1 } else { 0 }), // spacing before autocomplete
                Constraint::Length(ac_count),                          // tag autocomplete
                Constraint::Length(1),                                 // gap before pending
                Constraint::Length(post_h),   // pending field labels
                Constraint::Min(0),
            ])
            .split(inner);

        self.render_completed(frame, v_chunks[0]);
        self.render_active_label(frame, v_chunks[1]);

        if self.is_textarea_field() {
            self.textarea
                .render_area(frame, inset(v_chunks[3], 1, 0), "");
        } else {
            self.render_active_input(frame, v_chunks[3]);
        }

        if ac_count > 0 {
            self.render_autocomplete(frame, v_chunks[5]);
        }

        self.render_pending(frame, v_chunks[7]);
    }

    fn render_completed(&self, frame: &mut Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        // First line is always blank (top padding inside the card).
        let mut lines: Vec<Line> = vec![Line::from("")];
        for i in 0..self.field_idx {
            let (label, is_secret) = SECRET_FIELDS[i];
            let raw = self.collected_values.get(i).cloned().unwrap_or_default();
            let display = if is_secret && !raw.is_empty() {
                "••••••••".to_string()
            } else {
                raw
            };

            lines.push(Line::from(vec![
                Span::styled(" ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{label:<LABEL_WIDTH$}"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(display, Style::default().fg(Color::White)),
            ]));

            lines.push(Line::from(""));
        }
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn render_active_label(&self, frame: &mut Frame, area: Rect) {
        let label = SECRET_FIELDS[self.field_idx].0;
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    label,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ])),
            area,
        );
    }

    fn render_active_input(&self, frame: &mut Frame, area: Rect) {
        let (_, is_secret) = SECRET_FIELDS[self.field_idx];
        let input = &self.field_input;
        let char_count = input.chars().count();
        let cursor_pos = self.cursor;

        let before: String = if is_secret {
            "•".repeat(cursor_pos)
        } else {
            input.chars().take(cursor_pos).collect()
        };
        let at = if is_secret {
            if cursor_pos < char_count {
                "•".to_string()
            } else {
                " ".to_string()
            }
        } else {
            input
                .chars()
                .nth(cursor_pos)
                .map(|c| c.to_string())
                .unwrap_or_else(|| " ".to_string())
        };
        let after: String = if is_secret {
            "•".repeat(char_count.saturating_sub(cursor_pos + 1))
        } else {
            input.chars().skip(cursor_pos + 1).collect()
        };

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw(" "),
                Span::raw(before),
                Span::styled(at, Style::default().bg(Color::White).fg(Color::Black)),
                Span::raw(after),
            ])),
            area,
        );
    }

    fn render_autocomplete(&self, frame: &mut Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        let ac_area = inset(area, 1, 0);
        let mut lines: Vec<Line> = vec![];
        for (j, tag) in self.tag_ac_matches.iter().take(AC_MAX).enumerate() {
            if self.tag_ac_idx == Some(j) {
                lines.push(Line::from(vec![Span::styled(
                    tag.as_str(),
                    Style::default().fg(Color::White),
                )]));
            } else {
                lines.push(Line::from(vec![Span::styled(
                    tag.as_str(),
                    Style::default().fg(Color::DarkGray),
                )]));
            }
        }
        if self.tag_ac_matches.len() > AC_MAX {
            lines.push(Line::from(Span::styled(
                format!("   +{} more", self.tag_ac_matches.len() - AC_MAX),
                Style::default().fg(Color::DarkGray),
            )));
        }
        frame.render_widget(Paragraph::new(lines), ac_area);
    }

    fn render_pending(&self, frame: &mut Frame, area: Rect) {
        let count = SECRET_FIELDS.len() - self.field_idx - 1;
        if count == 0 || area.height == 0 {
            return;
        }
        let mut lines: Vec<Line> = vec![];
        for i in (self.field_idx + 1)..SECRET_FIELDS.len() {
            let (label, _) = SECRET_FIELDS[i];
            lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(label, Style::default().fg(Color::DarkGray)),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), area);
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
                let on_tags = self.field_idx == 3;
                if on_tags && !self.tag_ac_matches.is_empty() {
                    match key.code {
                        KeyCode::Down => {
                            self.tag_ac_idx = Some(
                                self.tag_ac_idx
                                    .map_or(0, |i| (i + 1).min(self.tag_ac_matches.len() - 1)),
                            );
                            return EventResult::Consumed;
                        }
                        KeyCode::Up if self.tag_ac_idx.is_some() => {
                            self.tag_ac_idx =
                                self.tag_ac_idx
                                    .and_then(|i| if i == 0 { None } else { Some(i - 1) });
                            return EventResult::Consumed;
                        }
                        KeyCode::Enter if self.tag_ac_idx.is_some() => {
                            let selected = self.tag_ac_matches[self.tag_ac_idx.unwrap()].clone();
                            self.insert_ac_tag(&selected);
                            self.tag_ac_idx = None;
                            self.update_tag_ac();
                            return EventResult::Consumed;
                        }
                        _ => {
                            self.tag_ac_idx = None;
                        }
                    }
                }

                match key.code {
                    KeyCode::Up => self.go_back_field(),
                    KeyCode::Down | KeyCode::Enter | KeyCode::Tab => {
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

        EventResult::Consumed
    }
}

fn split_tags(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Shrinks `area` by `left` columns on the left and `right` on the right.
fn inset(area: Rect, left: u16, right: u16) -> Rect {
    let shrink = left.saturating_add(right).min(area.width);
    Rect {
        x: area.x + left.min(area.width),
        y: area.y,
        width: area.width.saturating_sub(shrink),
        height: area.height,
    }
}
