use crossterm::{
    event::EventStream,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use futures::StreamExt;
mod actions;
mod component;
mod components;
mod pages;
mod router;
mod state;
use ratatui::prelude::*;
use std::io::{self, stdout};

use std::sync::Arc;

use crate::{actions::Actions, component::Component, router::Router, state::State};

#[tokio::main]
async fn main() -> io::Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = Arc::new(State::mock());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Actions>(32);
    let mut events = EventStream::new();
    let mut router = Router::new(tx.clone(), state.clone());

    // Render initial frame
    let _ = tx.send(Actions::Render).await;

    loop {
        // Drain all pending actions first (non-blocking)
        while let Ok(action) = rx.try_recv() {
            match action {
                Actions::Exit => {
                    disable_raw_mode()?;
                    stdout().execute(LeaveAlternateScreen)?;
                    return Ok(());
                }
                Actions::Render => {
                    
                }
                Actions::SetState(new_state) => {
                    state = new_state;
                    router.update(state.clone()).await;
                }
                Actions::NavigateTo(route) => {
                    router.navigate(route);
                    
                }

            }

            terminal.draw(|frame| { let area = frame.area(); router.render(frame, area); })?;
        }

        // Then block on the next terminal event
        if let Some(Ok(event)) = events.next().await {
            router.handle_event(event).await;
            terminal.draw(|frame| { let area = frame.area(); router.render(frame, area); })?;
        }
    }
}
