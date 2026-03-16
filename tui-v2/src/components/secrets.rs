use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::{component::{Component, EventResult}, state::State};

pub struct SecretsComponent {
    state: Arc<State>,
    pub sec_idx: usize,
    pub show_values: bool,
    pub focused: bool,
}

impl SecretsComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            sec_idx: 0,
            show_values: false,
            focused: true,
        }
    }

    fn render_area(&self, frame: &mut Frame, area: Rect) {
        let focused = self.focused;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let secrets = &self.state.secrets;

        let value_col_width = (area.width.saturating_sub(4) as usize) * 40 / 100 - 2;

        let header = Row::new(
            ["Name", "Value", "Tags"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD))),
        )
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

                let style = if is_selected {
                    Style::default().bg(Color::Cyan).fg(Color::Black)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Cell::from(s.name.clone()),
                    Cell::from(value_display),
                    Cell::from(s.tags.join(", ")),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Percentage(30),
            ratatui::layout::Constraint::Percentage(40),
            ratatui::layout::Constraint::Percentage(30),
        ];

        let scroll = scroll_indicators(self.sec_idx, secrets.len(), area.height as usize, 3);
        let block = Block::default()
            .title(format!(" Secrets ({}) {} ", secrets.len(), scroll))
            .borders(Borders::ALL)
            .border_style(border_style);

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
}

#[async_trait]
impl Component for SecretsComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        self.render_area(frame, area);
    }

    async fn update(&mut self, state: Arc<State>) {
        if !state.secrets.is_empty() {
            self.sec_idx = self.sec_idx.min(state.secrets.len() - 1);
        }
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if let Event::Key(key) = event {
            match key.code {
                KeyCode::Up => {
                    if self.sec_idx > 0 {
                        self.sec_idx -= 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Down => {
                    if self.sec_idx + 1 < self.state.secrets.len() {
                        self.sec_idx += 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Char('v') => {
                    self.show_values = !self.show_values;
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }
        EventResult::Ignored
    }
}

fn scroll_indicators(selected: usize, total: usize, area_height: usize, overhead: usize) -> &'static str {
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
