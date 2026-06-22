use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};
use tokio::sync::mpsc::Sender;

use crate::tui::{
    actions::{Actions, Route},
    component::{Component, EventResult},
    components::textarea::TextAreaComponent,
    state::State,
};

const SECRET_FIELDS: &[(&str, bool)] = &[
    ("Name", false),
    ("Value", true),
    ("Description", false),
    ("Tags (comma-separated)", false),
];

const AC_MAX: usize = 5;
const TEXTAREA_BOX_HEIGHT: u16 = 5;

#[derive(PartialEq)]
enum FormMode {
    Normal,
    Edit,
    Confirm,
}

pub struct SecretFormPage {
    actions_tx: Sender<Actions>,
    state: Arc<State>,
    editing_id: Option<String>,
    initial_values: Vec<String>,
    focused: usize,
    mode: FormMode,
    values: [String; 4],
    cursors: [usize; 4],
    textarea: TextAreaComponent,
    title: &'static str,
    tag_ac_matches: Vec<String>,
    tag_ac_idx: Option<usize>,
}

impl SecretFormPage {
    pub const DEFAULT_HINT: &'static str =
        "[↑↓] Navigate  [Enter] Edit  [d] Clear  [s] Save  [Esc] Cancel";
    const EDIT_HINT: &'static str = "[Esc] Stop editing";

    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        Self {
            actions_tx,
            state,
            editing_id: None,
            initial_values: vec![],
            focused: 0,
            mode: FormMode::Normal,
            values: [String::new(), String::new(), String::new(), String::new()],
            cursors: [0; 4],
            textarea: TextAreaComponent::new(),
            title: "New Secret",
            tag_ac_matches: vec![],
            tag_ac_idx: None,
        }
    }

    pub fn new_edit(
        actions_tx: Sender<Actions>,
        state: Arc<State>,
        id: String,
        initial_values: Vec<String>,
    ) -> Self {
        let name = initial_values.get(0).cloned().unwrap_or_default();
        let value_str = initial_values.get(1).cloned().unwrap_or_default();
        let desc = initial_values.get(2).cloned().unwrap_or_default();
        let tags = initial_values.get(3).cloned().unwrap_or_default();

        let mut textarea = TextAreaComponent::new();
        if !value_str.is_empty() {
            textarea.set_value(&value_str);
        }

        let cursors = [
            name.chars().count(),
            0,
            desc.chars().count(),
            tags.chars().count(),
        ];

        Self {
            actions_tx,
            state,
            editing_id: Some(id),
            initial_values,
            focused: 0,
            mode: FormMode::Normal,
            values: [name, String::new(), desc, tags],
            cursors,
            textarea,
            title: "Edit Secret",
            tag_ac_matches: vec![],
            tag_ac_idx: None,
        }
    }

    fn is_dirty(&self) -> bool {
        self.values[0] != self.initial_values.get(0).cloned().unwrap_or_default()
            || self.textarea.value() != self.initial_values.get(1).cloned().unwrap_or_default()
            || self.values[2] != self.initial_values.get(2).cloned().unwrap_or_default()
            || self.values[3] != self.initial_values.get(3).cloned().unwrap_or_default()
    }

    async fn enter_edit_mode(&mut self) {
        self.mode = FormMode::Edit;
        let new_state = Arc::new(State::cloned(&self.state).with_footer_hint(Self::EDIT_HINT));
        self.state = new_state.clone();
        let _ = self.actions_tx.send(Actions::SetState(new_state)).await;
    }

    async fn exit_edit_mode(&mut self) {
        self.mode = FormMode::Normal;
        self.tag_ac_idx = None;
        let new_state = Arc::new(State::cloned(&self.state).with_footer_hint(Self::DEFAULT_HINT));
        self.state = new_state.clone();
        let _ = self.actions_tx.send(Actions::SetState(new_state)).await;
    }

    async fn submit(&mut self) {
        let name = self.values[0].clone();
        let value = self.textarea.value();
        let description = self.values[2].clone();
        let tags = split_tags(&self.values[3]);

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

    // ── Event handlers ────────────────────────────────────────────────────────

    async fn handle_normal(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.focused > 0 {
                    self.focused -= 1;
                    self.update_tag_ac();
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                if self.focused < SECRET_FIELDS.len() - 1 {
                    self.focused += 1;
                    self.update_tag_ac();
                }
            }
            KeyCode::Enter | KeyCode::Char('i') => {
                self.enter_edit_mode().await;
            }
            KeyCode::Char('d') => {
                if self.focused == 1 {
                    self.textarea.set_value("");
                } else {
                    self.values[self.focused] = String::new();
                    self.cursors[self.focused] = 0;
                }
                self.update_tag_ac();
            }
            KeyCode::Char('s') | KeyCode::Esc => {
                self.mode = FormMode::Confirm;
            }
            _ => {}
        }
    }

    async fn handle_edit(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.exit_edit_mode().await;
            return;
        }

        if self.focused == 1 {
            self.textarea.handle_key(key);
            return;
        }

        // Tags autocomplete takes priority for navigation/select keys
        if self.focused == 3 && !self.tag_ac_matches.is_empty() {
            match key.code {
                KeyCode::Down => {
                    self.tag_ac_idx = Some(
                        self.tag_ac_idx
                            .map_or(0, |i| (i + 1).min(self.tag_ac_matches.len() - 1)),
                    );
                    return;
                }
                KeyCode::Up if self.tag_ac_idx.is_some() => {
                    self.tag_ac_idx =
                        self.tag_ac_idx
                            .and_then(|i| if i == 0 { None } else { Some(i - 1) });
                    return;
                }
                KeyCode::Enter if self.tag_ac_idx.is_some() => {
                    let selected = self.tag_ac_matches[self.tag_ac_idx.unwrap()].clone();
                    self.insert_ac_tag(&selected);
                    self.tag_ac_idx = None;
                    self.update_tag_ac();
                    return;
                }
                _ => {
                    self.tag_ac_idx = None;
                }
            }
        }

        // Enter confirms and exits edit mode for single-line fields
        if key.code == KeyCode::Enter {
            self.exit_edit_mode().await;
            return;
        }

        let idx = self.focused;
        self.handle_text_input(key, idx);
        self.update_tag_ac();
    }

    async fn handle_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => self.submit().await,
            KeyCode::Char('n') => {
                let _ = self.actions_tx.send(Actions::NavigateTo(Route::Home)).await;
            }
            KeyCode::Esc => self.mode = FormMode::Normal,
            _ => {}
        }
    }

    fn handle_text_input(&mut self, key: KeyEvent, idx: usize) {
        match key.code {
            KeyCode::Left => {
                if self.cursors[idx] > 0 {
                    self.cursors[idx] -= 1;
                }
            }
            KeyCode::Right => {
                if self.cursors[idx] < self.values[idx].chars().count() {
                    self.cursors[idx] += 1;
                }
            }
            KeyCode::Home => self.cursors[idx] = 0,
            KeyCode::End => self.cursors[idx] = self.values[idx].chars().count(),
            KeyCode::Backspace => {
                if self.cursors[idx] > 0 {
                    let mut chars: Vec<char> = self.values[idx].chars().collect();
                    chars.remove(self.cursors[idx] - 1);
                    self.values[idx] = chars.into_iter().collect();
                    self.cursors[idx] -= 1;
                }
            }
            KeyCode::Delete => {
                let len = self.values[idx].chars().count();
                if self.cursors[idx] < len {
                    let mut chars: Vec<char> = self.values[idx].chars().collect();
                    chars.remove(self.cursors[idx]);
                    self.values[idx] = chars.into_iter().collect();
                }
            }
            KeyCode::Char(c) => {
                let mut chars: Vec<char> = self.values[idx].chars().collect();
                chars.insert(self.cursors[idx], c);
                self.values[idx] = chars.into_iter().collect();
                self.cursors[idx] += 1;
            }
            _ => {}
        }
    }

    fn update_tag_ac(&mut self) {
        if self.focused != 3 || self.mode != FormMode::Edit {
            self.tag_ac_matches.clear();
            self.tag_ac_idx = None;
            return;
        }
        let input = self.values[3].clone();
        let current_token = input
            .split(',')
            .last()
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        let entered: std::collections::HashSet<String> = input
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
        let input = &self.values[3];
        let new_input = if let Some(comma_pos) = input.rfind(',') {
            let prefix = input[..comma_pos].trim_end();
            if prefix.is_empty() {
                format!("{selected}, ")
            } else {
                format!("{prefix}, {selected}, ")
            }
        } else {
            format!("{selected}, ")
        };
        self.values[3] = new_input;
        self.cursors[3] = self.values[3].chars().count();
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    fn render_form(&self, frame: &mut Frame, area: Rect) {
        let outer = Block::default()
            .title(format!(" {} ", self.title))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = outer.inner(area);
        frame.render_widget(outer, area);

        let ac_rows = if self.focused == 3
            && self.mode == FormMode::Edit
            && !self.tag_ac_matches.is_empty()
        {
            self.tag_ac_matches.len().min(AC_MAX) as u16
                + if self.tag_ac_matches.len() > AC_MAX {
                    1
                } else {
                    0
                }
        } else {
            0
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),                               // top padding
                Constraint::Length(1),                               // label 0
                Constraint::Length(1),                               // box 0
                Constraint::Length(1),                               // gap
                Constraint::Length(1),                               // label 1
                Constraint::Length(TEXTAREA_BOX_HEIGHT),             // box 1
                Constraint::Length(1),                               // gap
                Constraint::Length(1),                               // label 2
                Constraint::Length(1),                               // box 2
                Constraint::Length(1),                               // gap
                Constraint::Length(1),                               // label 3
                Constraint::Length(1),                               // box 3
                Constraint::Length(if ac_rows > 0 { 1 } else { 0 }), // gap before ac
                Constraint::Length(ac_rows),                         // autocomplete
                Constraint::Min(0),
            ])
            .split(inner);

        let field_layout = [
            (chunks[1], chunks[2]),
            (chunks[4], chunks[5]),
            (chunks[7], chunks[8]),
            (chunks[10], chunks[11]),
        ];

        for (i, (label_area, box_area)) in field_layout.iter().enumerate() {
            let is_focused = i == self.focused;
            let in_edit = is_focused && self.mode == FormMode::Edit;

            let label_color = if is_focused {
                if in_edit {
                    Color::Cyan
                } else {
                    Color::White
                }
            } else {
                Color::DarkGray
            };
            let border_color = label_color;

            // Label row: field name left, mode badge right
            let label_cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(0), Constraint::Length(8)])
                .split(*label_area);

            let label_style = if is_focused {
                Style::default()
                    .fg(label_color)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(label_color)
            };
            frame.render_widget(
                Paragraph::new(Span::styled(
                    format!("  {}", SECRET_FIELDS[i].0),
                    label_style,
                )),
                label_cols[0],
            );

            if is_focused {
                let badge = if in_edit { "INSERT" } else { "NORMAL" };
                frame.render_widget(
                    Paragraph::new(Span::styled(badge, Style::default().fg(label_color)))
                        .alignment(Alignment::Right),
                    label_cols[1],
                );
            }

            // Left-bar indicator for the focused field; unfocused fields just indent.
            let content_area = if is_focused {
                let block = Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::default().fg(border_color));
                let inner = block.inner(*box_area);
                frame.render_widget(block, *box_area);
                inner
            } else {
                Rect {
                    x: box_area.x + 1,
                    width: box_area.width.saturating_sub(1),
                    ..*box_area
                }
            };

            if i == 1 {
                self.textarea
                    .render_area(frame, inset(content_area, 1, 0), in_edit);
            } else {
                self.render_single_line_field(frame, content_area, i, in_edit);
            }
        }

        if ac_rows > 0 {
            self.render_autocomplete(frame, chunks[13]);
        }
    }

    fn render_single_line_field(
        &self,
        frame: &mut Frame,
        area: Rect,
        idx: usize,
        show_cursor: bool,
    ) {
        let (_, is_secret) = SECRET_FIELDS[idx];
        let input = &self.values[idx];
        let char_count = input.chars().count();

        if !show_cursor {
            let display = if is_secret && char_count > 0 {
                "•".repeat(char_count)
            } else {
                input.clone()
            };
            let text_color = if char_count > 0 {
                Color::White
            } else {
                Color::DarkGray
            };
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw(" "),
                    Span::styled(display, Style::default().fg(text_color)),
                ])),
                area,
            );
            return;
        }

        let cursor_pos = self.cursors[idx];
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
        let ac_area = inset(area, 3, 0);
        let mut lines: Vec<Line> = vec![];
        for (j, tag) in self.tag_ac_matches.iter().take(AC_MAX).enumerate() {
            let style = if self.tag_ac_idx == Some(j) {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            lines.push(Line::from(Span::styled(tag.as_str(), style)));
        }
        if self.tag_ac_matches.len() > AC_MAX {
            lines.push(Line::from(Span::styled(
                format!("   +{} more", self.tag_ac_matches.len() - AC_MAX),
                Style::default().fg(Color::DarkGray),
            )));
        }
        frame.render_widget(Paragraph::new(lines), ac_area);
    }

    fn render_confirm(&self, frame: &mut Frame, area: Rect, title: &str, hint: &str) {
        const W: u16 = 46;
        const H: u16 = 5;
        let x = area.x + area.width.saturating_sub(W) / 2;
        let y = area.y + area.height.saturating_sub(H) / 2;
        let popup = Rect {
            x,
            y,
            width: W.min(area.width),
            height: H.min(area.height),
        };

        frame.render_widget(Clear, popup);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::White));
        let popup_inner = block.inner(popup);
        frame.render_widget(block, popup);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .split(popup_inner);

        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("  {title}"),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("  {hint}"),
                Style::default().fg(Color::DarkGray),
            )),
            rows[1],
        );
    }
}

#[async_trait]
impl Component for SecretFormPage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        self.render_form(frame, area);
        if self.mode == FormMode::Confirm {
            self.render_confirm(
                frame,
                area,
                "Would you like to save?",
                "[y/Enter] Save  [n] Discard  [Esc] Cancel",
            );
        }
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            match self.mode {
                FormMode::Normal => self.handle_normal(key).await,
                FormMode::Edit => self.handle_edit(key).await,
                FormMode::Confirm => self.handle_confirm(key).await,
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

fn inset(area: Rect, left: u16, right: u16) -> Rect {
    let shrink = left.saturating_add(right).min(area.width);
    Rect {
        x: area.x + left.min(area.width),
        y: area.y,
        width: area.width.saturating_sub(shrink),
        height: area.height,
    }
}
