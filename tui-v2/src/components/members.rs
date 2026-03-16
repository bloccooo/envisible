use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use crate::{
    component::{Component, EventResult},
    state::State,
};

pub struct MembersComponent {
    state: Arc<State>,
    pub member_idx: usize,
    pub focused: bool,
}

impl MembersComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self { state, member_idx: 0, focused: false }
    }
}

#[async_trait]
impl Component for MembersComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let members = &self.state.members;
        let focused = self.focused;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let items: Vec<ListItem> = members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let is_selected = i == self.member_idx && focused;
                let label = if m.is_me {
                    format!("{} (you)", m.email)
                } else if m.is_pending {
                    format!("{} [pending]", m.email)
                } else {
                    m.email.clone()
                };
                let style = if is_selected {
                    Style::default().bg(Color::Cyan).fg(Color::Black)
                } else if m.is_pending {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                ListItem::new(label).style(style)
            })
            .collect();

        let scroll = scroll_indicators(self.member_idx, members.len(), area.height as usize, 2);
        let block = Block::default()
            .title(format!(" Members ({}) {} ", members.len(), scroll))
            .borders(Borders::ALL)
            .border_style(border_style);

        let mut list_state = ListState::default();
        if focused && !members.is_empty() {
            list_state.select(Some(self.member_idx));
        }

        frame.render_stateful_widget(List::new(items).block(block), area, &mut list_state);
    }

    async fn update(&mut self, state: Arc<State>) {
        if !state.members.is_empty() {
            self.member_idx = self.member_idx.min(state.members.len() - 1);
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
                    if self.member_idx > 0 {
                        self.member_idx -= 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Down => {
                    if self.member_idx + 1 < self.state.members.len() {
                        self.member_idx += 1;
                    }
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
