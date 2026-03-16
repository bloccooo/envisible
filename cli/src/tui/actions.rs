use std::collections::HashSet;
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

/// A typed mutation to apply to the automerge document.
/// Pages send this instead of SetState for data-changing operations,
/// so the main loop can call the correct lib function and re-derive state from the doc.
///
/// The `Option<String>` is an optional footer hint to display after the mutation completes.
/// When None, the current hint is preserved.
pub enum DocMutation {
    AddSecret {
        name: String,
        value: String,
        description: String,
        tags: Vec<String>,
    },
    UpdateSecret {
        id: String,
        name: String,
        value: String,
        description: String,
        tags: Vec<String>,
    },
    DeleteSecret {
        id: String,
    },
    RenameTag {
        old: String,
        new_name: String,
    },
    DeleteTag {
        tag: String,
    },
    SaveTagAssignments {
        tag: String,
        selected_ids: HashSet<String>,
    },
    GrantMember {
        id: String,
    },
    RemoveMember {
        id: String,
    },
    RotateDek,
}

pub enum Actions {
    Exit,
    SetState(Arc<State>),
    /// Apply a document mutation and optionally set a footer hint afterwards.
    ApplyMutation(DocMutation, Option<String>),
    NavigateTo(Route),
}
