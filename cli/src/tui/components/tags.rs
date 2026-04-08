use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Padding},
    Frame,
};

use crate::tui::{
    component::{Component, EventResult},
    state::State,
};

pub struct TagsComponent {
    state: Arc<State>,
    pub tag_idx: usize, // 0 = "All", 1+ = real tags (offset by 1)
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

    /// Returns the real tag at the current cursor position, or None if "All" is selected.
    pub fn current_real_tag<'a>(&self, tags: &'a [String]) -> Option<&'a String> {
        if self.tag_idx == 0 {
            None
        } else {
            tags.get(self.tag_idx - 1)
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

        // "All" pseudo-tag at index 0.
        let all_cursor = self.tag_idx == 0 && focused;
        let all_filtered = self.state.selected_tags.is_empty();
        let all_item = ListItem::new(format!("{} All", if all_filtered { "●" } else { " " }))
            .style(if all_cursor {
                Style::default().bg(Color::Cyan).fg(Color::Black)
            } else {
                Style::default()
            });

        let real_items = tags.iter().enumerate().map(|(i, tag)| {
            let display_idx = i + 1; // offset by 1 for "All"
            let cursor_here = display_idx == self.tag_idx && focused;
            let is_filter_on = self.state.selected_tags.contains(tag);
            let count = self
                .state
                .secrets
                .iter()
                .filter(|s| s.tags.contains(tag))
                .count();
            let check = if is_filter_on { "●" } else { " " };
            let style = if cursor_here {
                Style::default().bg(Color::Cyan).fg(Color::Black)
            } else if is_filter_on {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(format!("{check} {tag} ({count})")).style(style)
        });

        let items: Vec<ListItem> = std::iter::once(all_item).chain(real_items).collect();
        let total = tags.len() + 1; // includes "All"

        let scroll = scroll_indicators(self.tag_idx, total, area.height as usize, 2);
        let block = Block::default()
            .title(format!(" Tags ({}) {} ", tags.len(), scroll))
            .title_style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .padding(Padding::uniform(1));

        let mut list_state = ListState::default();
        if focused {
            list_state.select(Some(self.tag_idx));
        }

        frame.render_stateful_widget(List::new(items).block(block), area, &mut list_state);
    }

    async fn update(&mut self, state: Arc<State>) {
        let tags = state.tags();
        // valid range: 0 (All) … tags.len() (last real tag)
        self.tag_idx = self.tag_idx.min(tags.len());
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
                    if self.tag_idx < tags.len() {
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
