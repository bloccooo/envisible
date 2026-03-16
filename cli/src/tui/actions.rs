use std::sync::Arc;

use crate::tui::state::State;

#[derive(Debug, Clone)]
pub enum Route {
    Home,
    NewSecret,
    EditSecret(String),
    NewTag,
    EditTag(String),
    HomeWithTagAssignment(String),
    Invite,
}

pub enum Actions {
    Exit,
    SetState(Arc<State>),
    NavigateTo(Route),
}
