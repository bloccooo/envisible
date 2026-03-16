use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::Paragraph,
    Frame,
};

use crate::state::{FooterState, FooterStatus};

pub struct FooterComponent;

impl FooterComponent {
    pub fn render(frame: &mut Frame, area: Rect, footer: &FooterState) {
        let hint_color = if footer.hint_is_warning { Color::Yellow } else { Color::DarkGray };

        let (status_text, status_color) = match &footer.status {
            FooterStatus::Idle => ("✓ saved".to_string(), Color::DarkGray),
            FooterStatus::Syncing => ("↑ syncing…".to_string(), Color::Yellow),
            FooterStatus::Ok(msg) => (msg.clone(), Color::Green),
            FooterStatus::Error(msg) => (msg.clone(), Color::Red),
        };

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(12)])
            .split(area);

        frame.render_widget(
            Paragraph::new(footer.hint.as_str()).style(Style::default().fg(hint_color)),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(status_text)
                .style(Style::default().fg(status_color))
                .alignment(Alignment::Right),
            chunks[1],
        );
    }
}
