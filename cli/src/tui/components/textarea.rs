use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub enum TextAreaEvent {
    Changed,
    NavigatePrev,
    NavigateNext,
}

pub struct TextAreaComponent {
    lines: Vec<String>,
    row: usize,
    col: usize,
    scroll: usize,
}

impl TextAreaComponent {
    pub fn new() -> Self {
        Self {
            lines: vec![String::new()],
            row: 0,
            col: 0,
            scroll: 0,
        }
    }

    pub fn value(&self) -> String {
        self.lines.join("\n")
    }

    pub fn set_value(&mut self, s: &str) {
        self.lines = if s.is_empty() {
            vec![String::new()]
        } else {
            s.split('\n').map(|l| l.to_string()).collect()
        };
        self.row = self.lines.len().saturating_sub(1);
        self.col = self.lines[self.row].chars().count();
        self.scroll = 0;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> TextAreaEvent {
        match key.code {
            KeyCode::Up => {
                if self.row > 0 {
                    self.row -= 1;
                    self.col = self.col.min(self.lines[self.row].chars().count());
                    self.update_scroll();
                    return TextAreaEvent::Changed;
                } else {
                    return TextAreaEvent::NavigatePrev;
                }
            }
            KeyCode::Down => {
                if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = self.col.min(self.lines[self.row].chars().count());
                    self.update_scroll();
                    return TextAreaEvent::Changed;
                } else {
                    return TextAreaEvent::NavigateNext;
                }
            }
            KeyCode::Tab => return TextAreaEvent::NavigateNext,
            KeyCode::Enter => {
                let chars: Vec<char> = self.lines[self.row].chars().collect();
                let before: String = chars[..self.col].iter().collect();
                let after: String = chars[self.col..].iter().collect();
                self.lines[self.row] = before;
                self.lines.insert(self.row + 1, after);
                self.row += 1;
                self.col = 0;
            }
            KeyCode::Backspace => {
                if self.col > 0 {
                    let mut chars: Vec<char> = self.lines[self.row].chars().collect();
                    chars.remove(self.col - 1);
                    self.lines[self.row] = chars.into_iter().collect();
                    self.col -= 1;
                } else if self.row > 0 {
                    let current = self.lines.remove(self.row);
                    let prev_len = self.lines[self.row - 1].chars().count();
                    self.lines[self.row - 1].push_str(&current);
                    self.row -= 1;
                    self.col = prev_len;
                }
            }
            KeyCode::Delete => {
                let line_len = self.lines[self.row].chars().count();
                if self.col < line_len {
                    let mut chars: Vec<char> = self.lines[self.row].chars().collect();
                    chars.remove(self.col);
                    self.lines[self.row] = chars.into_iter().collect();
                } else if self.row + 1 < self.lines.len() {
                    let next = self.lines.remove(self.row + 1);
                    self.lines[self.row].push_str(&next);
                }
            }
            KeyCode::Left => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.lines[self.row].chars().count();
                }
            }
            KeyCode::Right => {
                let line_len = self.lines[self.row].chars().count();
                if self.col < line_len {
                    self.col += 1;
                } else if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = 0;
                }
            }
            KeyCode::Home => self.col = 0,
            KeyCode::End => self.col = self.lines[self.row].chars().count(),
            KeyCode::Char(c) => {
                let mut chars: Vec<char> = self.lines[self.row].chars().collect();
                chars.insert(self.col, c);
                self.lines[self.row] = chars.into_iter().collect();
                self.col += 1;
            }
            _ => {}
        }
        self.update_scroll();
        TextAreaEvent::Changed
    }

    pub fn render_area(&self, frame: &mut Frame, area: Rect, title: &str) {
        let viewport = area.height.saturating_sub(2) as usize;

        let scroll_indicator = match (self.scroll > 0, self.scroll + viewport < self.lines.len()) {
            (true, true) => " ▲▼",
            (true, false) => " ▲",
            (false, true) => " ▼",
            (false, false) => "",
        };

        let block = Block::default()
            .title(format!(" {title}{scroll_indicator} "))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let visible: Vec<Line> = (self.scroll..self.scroll + viewport)
            .map(|r| {
                if r >= self.lines.len() {
                    return Line::from("");
                }
                let text = &self.lines[r];
                if r != self.row {
                    return Line::from(text.clone());
                }
                let before: String = text.chars().take(self.col).collect();
                let at = text
                    .chars()
                    .nth(self.col)
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| " ".to_string());
                let after: String = text.chars().skip(self.col + 1).collect();
                Line::from(vec![
                    Span::raw(before),
                    Span::styled(at, Style::default().bg(Color::White).fg(Color::Black)),
                    Span::raw(after),
                ])
            })
            .collect();

        frame.render_widget(Paragraph::new(visible), inner);
    }

    fn update_scroll(&mut self) {
        const VIEWPORT: usize = 4;
        if self.row < self.scroll {
            self.scroll = self.row;
        } else if self.row >= self.scroll + VIEWPORT {
            self.scroll = self.row + 1 - VIEWPORT;
        }
    }
}
