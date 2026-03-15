use std::sync::Arc;

use crate::state::State;

pub enum Route {
    Home,
    NewSecret,
}

pub enum Actions {
    Exit,
    Render,
    SetState(Arc<State>),
    NavigateTo(Route),
}
