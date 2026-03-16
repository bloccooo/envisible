use std::sync::Arc;

use crate::state::State;

#[derive(Debug, Clone)]
pub enum Route {
    Home,
    NewSecret,
    EditSecret(String),
    NewTag,
    EditTag(String),
    /// Returns home and immediately enters tag-assignment mode for `tag`.
    HomeWithTagAssignment(String),
    Invite,
}

pub enum Actions {
    Exit,
    Render,
    SetState(Arc<State>),
    NavigateTo(Route),
}
