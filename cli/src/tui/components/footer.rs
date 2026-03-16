use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Span,
    widgets::Paragraph,
    Frame,
};

use crate::tui::state::{FooterState, FooterStatus};

pub struct FooterComponent;

impl FooterComponent {
    pub fn render(frame: &mut Frame, area: Rect, footer: &FooterState) {
        let hint_color = if footer.hint_is_warning {
            Color::Yellow
        } else {
            Color::DarkGray
        };
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
            Paragraph::new(Span::styled(
                footer.hint.as_str(),
                Style::default().fg(hint_color),
            )),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(Span::styled(status_text, Style::default().fg(status_color)))
                .alignment(ratatui::layout::Alignment::Right),
            chunks[1],
        );
    }
}
