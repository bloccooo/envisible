use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use crate::tui::{
    component::{Component, EventResult},
    state::State,
};

pub struct TagsComponent {
    state: Arc<State>,
    pub tag_idx: usize,
    pub focused: bool,
}

impl TagsComponent {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            tag_idx: 0,
            focused: false,
        }
    }
}

#[async_trait]
impl Component for TagsComponent {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let tags = self.state.tags();
        let focused = self.focused;
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let items: Vec<ListItem> = tags
            .iter()
            .enumerate()
            .map(|(i, tag)| {
                let is_selected = i == self.tag_idx && focused;
                let count = self
                    .state
                    .secrets
                    .iter()
                    .filter(|s| s.tags.contains(tag))
                    .count();
                let style = if is_selected {
                    Style::default().bg(Color::Cyan).fg(Color::Black)
                } else {
                    Style::default()
                };
                ListItem::new(format!("{tag} ({count})")).style(style)
            })
            .collect();

        let scroll = scroll_indicators(self.tag_idx, tags.len(), area.height as usize, 2);
        let block = Block::default()
            .title(format!(" Tags ({}) {} ", tags.len(), scroll))
            .borders(Borders::ALL)
            .border_style(border_style);

        let mut list_state = ListState::default();
        if focused && !tags.is_empty() {
            list_state.select(Some(self.tag_idx));
        }

        frame.render_stateful_widget(List::new(items).block(block), area, &mut list_state);
    }

    async fn update(&mut self, state: Arc<State>) {
        let tags = state.tags();
        if !tags.is_empty() {
            self.tag_idx = self.tag_idx.min(tags.len() - 1);
        }
        self.state = state;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        if !self.focused {
            return EventResult::Ignored;
        }
        if let Event::Key(key) = event {
            let tags = self.state.tags();
            match key.code {
                KeyCode::Up => {
                    if self.tag_idx > 0 {
                        self.tag_idx -= 1;
                    }
                    return EventResult::Consumed;
                }
                KeyCode::Down => {
                    if self.tag_idx + 1 < tags.len() {
                        self.tag_idx += 1;
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
