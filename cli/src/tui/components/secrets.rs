use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Padding, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::tui::{
    component::{Component, EventResult},
    state::State,
};

pub struct SecretsComponent {
    state: Arc<State>,
    pub sec_idx: usize,
    pub show_values: bool,
    pub focused: bool,
    pub editing_tag: Option<String>,
    pub ts_selected_ids: HashSet<String>,
}

impl SecretsComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            sec_idx: 0,
            show_values: false,
            focused: true,
            editing_tag: None,
            ts_selected_ids: HashSet::new(),
        }
    }
}

#[async_trait]
impl Component for SecretsComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let focused = self.focused;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let secrets = self.state.filtered_secrets();
        let assigning = self.editing_tag.is_some();
        let value_col_width = (area.width.saturating_sub(4) as usize) * 40 / 100 - 2;

        let header = Row::new(["Name", "Value", "Tags"].iter().map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD),
            )
        }))
        .height(1);

        let rows: Vec<Row> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let is_selected = i == self.sec_idx && focused;

                let value_display = if self.show_values {
                    if s.value.chars().count() > value_col_width {
                        let truncated: String = s.value.chars().take(value_col_width).collect();
                        format!("{truncated}…")
                    } else {
                        s.value.clone()
                    }
                } else {
                    "••••••••".to_string()
                };

                let name_cell = if assigning {
                    let checked = self.ts_selected_ids.contains(&s.id);
                    let checkbox = if checked { "[x] " } else { "[ ] " };
                    Cell::from(format!("{checkbox}{}", s.name))
                } else {
                    Cell::from(s.name.clone())
                };

                let style = if is_selected {
                    Style::default().bg(Color::Cyan).fg(Color::Black)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    name_cell,
                    Cell::from(value_display),
                    Cell::from(s.tags.join(", ")),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ];

        let scroll = scroll_indicators(self.sec_idx, secrets.len(), area.height as usize, 3);
        let title = if let Some(tag) = &self.editing_tag {
            format!(" Secrets — assigning '{tag}' {scroll} ")
        } else {
            format!(" Secrets ({}) {scroll} ", secrets.len())
        };

        let block = Block::default()
            .title(title)
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .padding(Padding::uniform(1));

        if secrets.is_empty() {
            let placeholder = Paragraph::new("press n to add a new secret")
                .style(Style::default().fg(Color::DarkGray))
                .block(block);
            frame.render_widget(placeholder, area);
            return;
        }

        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(Style::default().bg(Color::Cyan).fg(Color::Black));

        let mut table_state = TableState::default();
        if focused && !secrets.is_empty() {
            table_state.select(Some(self.sec_idx));
        }

        frame.render_stateful_widget(table, area, &mut table_state);
    }

    async fn update(&mut self, state: Arc<State>) {
        let filtered_len = state.filtered_secrets().len();
        if filtered_len > 0 {
            self.sec_idx = self.sec_idx.min(filtered_len - 1);
        } else {
            self.sec_idx = 0;
        }
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if !self.focused {
            return EventResult::Ignored;
        }
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Up => {
                    if self.sec_idx > 0 {
                        self.sec_idx -= 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Down => {
                    if self.sec_idx + 1 < self.state.filtered_secrets().len() {
                        self.sec_idx += 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Char('v') => {
                    self.show_values = !self.show_values;
                    return EventResult::Consumed;
                }
                KeyCode::Char(' ') if self.editing_tag.is_some() => {
                    if let Some(secret) = self.state.filtered_secrets().get(self.sec_idx).copied() {
                        let id = secret.id.clone();
                        if self.ts_selected_ids.contains(&id) {
                            self.ts_selected_ids.remove(&id);
                        } else {
                            self.ts_selected_ids.insert(id);
                        }
                    }
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }
        EventResult::Ignored
    }
}

fn scroll_indicators(
    selected: usize,
    total: usize,
    area_height: usize,
    overhead: usize,
) -> &'static str {
    let visible = area_height.saturating_sub(overhead);
    if total <= visible {
        return "";
    }
    match (selected > 0, selected + 1 < total) {
        (true, true) => "▲▼",
        (true, false) => "▲",
        (false, true) => "▼",
        (false, false) => "",
    }
}
