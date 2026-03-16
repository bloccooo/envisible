use std::sync::Arc;

use async_trait::async_trait;
use crossterm::event::{Event, KeyCode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
};
use tokio::sync::mpsc::Sender;

use crate::tui::{
    actions::{Actions, DocMutation, Route},
    component::{Component, EventResult},
    components::{
        header::HeaderComponent, members::MembersComponent, secrets::SecretsComponent,
        tags::TagsComponent,
    },
    state::State,
};

#[derive(Debug, Clone, PartialEq)]
pub enum Focus {
    Secrets,
    Tags,
    Members,
}

pub struct HomePage {
    actions_tx: Sender<Actions>,
    state: Arc<State>,
    pub focus: Focus,
    header: HeaderComponent,
    pub secrets: SecretsComponent,
    pub tags: TagsComponent,
    pub members: MembersComponent,
    // Confirmation dialogs
    secret_to_delete: Option<String>,
    tag_to_delete: Option<String>,
    member_to_delete: Option<String>,
    member_to_grant: Option<String>,
    confirming_rotate: bool,
    // Clipboard
    clipboard: Option<arboard::Clipboard>,
}

impl HomePage {
    pub const DEFAULT_HINT: &'static str =
        "[n] New  [e] Edit  [d] Delete  [c] Copy  [v] Reveal  [Tab] Switch  [q] Quit";

    pub fn new(actions_tx: Sender<Actions>, state: Arc<State>) -> Self {
        let mut page = Self {
            header: HeaderComponent::new(state.clone()),
            secrets: SecretsComponent::new(state.clone()),
            tags: TagsComponent::new(state.clone()),
            members: MembersComponent::new(state.clone()),
            state,
            actions_tx,
            focus: Focus::Secrets,
            secret_to_delete: None,
            tag_to_delete: None,
            member_to_delete: None,
            member_to_grant: None,
            confirming_rotate: false,
            clipboard: arboard::Clipboard::new().ok(),
        };
        page.sync_focus();
        page
    }

    pub fn new_with_tag_assignment(
        actions_tx: Sender<Actions>,
        state: Arc<State>,
        tag: String,
    ) -> Self {
        let mut page = Self::new(actions_tx, state.clone());
        page.secrets.ts_selected_ids = state
            .secrets
            .iter()
            .filter(|s| s.tags.contains(&tag))
            .map(|s| s.id.clone())
            .collect();
        page.secrets.editing_tag = Some(tag);
        page.set_focus(Focus::Secrets);
        page
    }

    fn sync_focus(&mut self) {
        self.secrets.focused = self.focus == Focus::Secrets;
        self.tags.focused = self.focus == Focus::Tags;
        self.members.focused = self.focus == Focus::Members;
    }

    fn set_focus(&mut self, focus: Focus) {
        self.focus = focus;
        self.sync_focus();
    }

    fn normal_hint(&self) -> &'static str {
        match &self.focus {
            Focus::Secrets => {
                if self.secrets.editing_tag.is_some() {
                    "[Space] Toggle  [Enter] Save  [Esc] Cancel"
                } else {
                    Self::DEFAULT_HINT
                }
            }
            Focus::Tags => "[n] New  [e] Rename  [s] Assign  [d] Delete  [Tab] Switch  [q] Quit",
            Focus::Members => {
                let pending = self
                    .state
                    .members
                    .get(self.members.member_idx)
                    .map(|m| m.is_pending)
                    .unwrap_or(false);
                if pending {
                    "[g] Grant  [d] Remove  [i] Invite  [Tab] Switch  [q] Quit"
                } else {
                    "[d] Remove  [i] Invite  [r] Rotate DEK  [Tab] Switch  [q] Quit"
                }
            }
        }
    }

    async fn send_hint(&self, hint: impl Into<String>) {
        let new_state = Arc::new((*self.state).clone().with_footer_hint(hint));
        let _ = self.actions_tx.send(Actions::SetState(new_state)).await;
    }

    async fn send_warning(&self, hint: impl Into<String>) {
        let new_state = Arc::new((*self.state).clone().with_footer_warning(hint));
        let _ = self.actions_tx.send(Actions::SetState(new_state)).await;
    }

    async fn save_tag_assignments(&mut self) {
        let tag = match self.secrets.editing_tag.clone() {
            Some(t) => t,
            None => return,
        };
        let selected_ids = self.secrets.ts_selected_ids.clone();
        let _ = self
            .actions_tx
            .send(Actions::ApplyMutation(
                DocMutation::SaveTagAssignments { tag, selected_ids },
                Some(
                    "[n] New  [e] Rename  [s] Assign  [d] Delete  [Tab] Switch  [q] Quit"
                        .to_string(),
                ),
            ))
            .await;
    }
}

#[async_trait]
impl Component for HomePage {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(HeaderComponent::HEIGHT),
                Constraint::Min(0),
            ])
            .split(area);

        self.header.render(frame, main_chunks[0]);

        let body_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(8)])
            .split(main_chunks[1]);

        let pane_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if self.state.secrets.is_empty() {
                vec![Constraint::Percentage(100), Constraint::Percentage(0)]
            } else {
                vec![Constraint::Percentage(75), Constraint::Percentage(25)]
            })
            .split(body_chunks[0]);

        self.secrets.render(frame, pane_chunks[0]);
        if !self.state.secrets.is_empty() {
            self.tags.render(frame, pane_chunks[1]);
        }
        self.members.render(frame, body_chunks[1]);
    }

    async fn update(&mut self, state: Arc<State>) {
        self.state = state.clone();
        self.header.update(state.clone()).await;
        self.secrets.update(state.clone()).await;
        self.tags.update(state.clone()).await;
        self.members.update(state).await;
    }

    async fn handle_event(&mut self, event: Event) -> EventResult {
        let Event::Key(key) = event else {
            return EventResult::Ignored;
        };

        // Tag-assignment mode intercepts Enter/Esc before confirmations.
        if self.secrets.editing_tag.is_some() && self.focus == Focus::Secrets {
            match key.code {
                KeyCode::Enter => {
                    self.save_tag_assignments().await;
                    self.secrets.editing_tag = None;
                    self.secrets.ts_selected_ids.clear();
                    self.set_focus(Focus::Tags);
                    return EventResult::Consumed;
                }
                KeyCode::Esc => {
                    self.secrets.editing_tag = None;
                    self.secrets.ts_selected_ids.clear();
                    self.set_focus(Focus::Tags);
                    self.send_hint(
                        "[n] New  [e] Rename  [s] Assign  [d] Delete  [Tab] Switch  [q] Quit",
                    )
                    .await;
                    return EventResult::Consumed;
                }
                _ => {}
            }
        }

        // Confirmation: tag delete.
        if self.tag_to_delete.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(tag) = self.tag_to_delete.take() {
                        if self.tags.tag_idx > 0 {
                            self.tags.tag_idx -= 1;
                        }
                        let _ = self
                            .actions_tx
                            .send(Actions::ApplyMutation(
                                DocMutation::DeleteTag { tag },
                                Some(self.normal_hint().to_string()),
                            ))
                            .await;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.tag_to_delete = None;
                    self.send_hint(self.normal_hint()).await;
                }
                _ => {}
            }
            return EventResult::Consumed;
        }

        // Confirmation: secret delete.
        if self.secret_to_delete.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(id) = self.secret_to_delete.take() {
                        if self.secrets.sec_idx > 0 {
                            self.secrets.sec_idx -= 1;
                        }
                        let _ = self
                            .actions_tx
                            .send(Actions::ApplyMutation(
                                DocMutation::DeleteSecret { id },
                                Some(self.normal_hint().to_string()),
                            ))
                            .await;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.secret_to_delete = None;
                    self.send_hint(self.normal_hint()).await;
                }
                _ => {}
            }
            return EventResult::Consumed;
        }

        // Confirmation: member delete.
        if self.member_to_delete.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(id) = self.member_to_delete.take() {
                        if self.members.member_idx > 0 {
                            self.members.member_idx -= 1;
                        }
                        let _ = self
                            .actions_tx
                            .send(Actions::ApplyMutation(
                                DocMutation::RemoveMember { id },
                                Some(self.normal_hint().to_string()),
                            ))
                            .await;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.member_to_delete = None;
                    self.send_hint(self.normal_hint()).await;
                }
                _ => {}
            }
            return EventResult::Consumed;
        }

        // Confirmation: DEK rotate.
        if self.confirming_rotate {
            match key.code {
                KeyCode::Char('y') => {
                    self.confirming_rotate = false;
                    let _ = self
                        .actions_tx
                        .send(Actions::ApplyMutation(
                            DocMutation::RotateDek,
                            Some(self.normal_hint().to_string()),
                        ))
                        .await;
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.confirming_rotate = false;
                    self.send_hint(self.normal_hint()).await;
                }
                _ => {}
            }
            return EventResult::Consumed;
        }

        // Confirmation: member grant.
        if self.member_to_grant.is_some() {
            match key.code {
                KeyCode::Char('y') => {
                    if let Some(id) = self.member_to_grant.take() {
                        let _ = self
                            .actions_tx
                            .send(Actions::ApplyMutation(
                                DocMutation::GrantMember { id },
                                Some(self.normal_hint().to_string()),
                            ))
                            .await;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.member_to_grant = None;
                    self.send_hint(self.normal_hint()).await;
                }
                _ => {}
            }
            return EventResult::Consumed;
        }

        // Delegate Up/Down/'v'/Space to the focused child component.
        let delegated = match self.focus {
            Focus::Secrets => self.secrets.handle_event(Event::Key(key)).await,
            Focus::Tags => self.tags.handle_event(Event::Key(key)).await,
            Focus::Members => self.members.handle_event(Event::Key(key)).await,
        };
        if delegated == EventResult::Consumed {
            return EventResult::Consumed;
        }

        // Page-level keys.
        match key.code {
            KeyCode::Char('q') => {
                let _ = self.actions_tx.send(Actions::Exit).await;
            }
            KeyCode::Tab => {
                if self.secrets.editing_tag.is_none() {
                    let next = match self.focus {
                        Focus::Secrets => Focus::Tags,
                        Focus::Tags => Focus::Members,
                        Focus::Members => Focus::Secrets,
                    };
                    self.set_focus(next);
                    self.send_hint(self.normal_hint()).await;
                }
            }
            KeyCode::Char('n') => match self.focus {
                Focus::Secrets => {
                    let _ = self
                        .actions_tx
                        .send(Actions::NavigateTo(Route::NewSecret))
                        .await;
                }
                Focus::Tags => {
                    let _ = self
                        .actions_tx
                        .send(Actions::NavigateTo(Route::NewTag))
                        .await;
                }
                Focus::Members => {}
            },
            KeyCode::Char('e') => match self.focus {
                Focus::Secrets => {
                    if let Some(sec) = self.state.secrets.get(self.secrets.sec_idx) {
                        let _ = self
                            .actions_tx
                            .send(Actions::NavigateTo(Route::EditSecret(sec.id.clone())))
                            .await;
                    }
                }
                Focus::Tags => {
                    let tags = self.state.tags();
                    if let Some(tag) = tags.get(self.tags.tag_idx).cloned() {
                        let _ = self
                            .actions_tx
                            .send(Actions::NavigateTo(Route::EditTag(tag)))
                            .await;
                    }
                }
                Focus::Members => {}
            },
            KeyCode::Char('d') => match self.focus {
                Focus::Secrets => {
                    if let Some(sec) = self.state.secrets.get(self.secrets.sec_idx) {
                        let msg = format!("Delete secret '{}'? [y] Yes  [n] No", sec.name);
                        self.secret_to_delete = Some(sec.id.clone());
                        self.send_warning(msg).await;
                    }
                }
                Focus::Tags => {
                    let tags = self.state.tags();
                    if let Some(tag) = tags.get(self.tags.tag_idx).cloned() {
                        let msg = format!("Delete tag '{tag}'? [y] Yes  [n] No");
                        self.tag_to_delete = Some(tag);
                        self.send_warning(msg).await;
                    }
                }
                Focus::Members => {
                    if let Some(m) = self.state.members.get(self.members.member_idx) {
                        if !m.is_me {
                            let msg = format!("Remove {}? [y] Yes  [n] No", m.email);
                            self.member_to_delete = Some(m.id.clone());
                            self.send_warning(msg).await;
                        }
                    }
                }
            },
            KeyCode::Char('c') => {
                if self.focus == Focus::Secrets {
                    if let Some(sec) = self.state.secrets.get(self.secrets.sec_idx) {
                        let value = sec.value.clone();
                        if let Some(cb) = &mut self.clipboard {
                            let _ = cb.set_text(value);
                        }
                    }
                }
            }
            KeyCode::Char('s') => {
                if self.focus == Focus::Tags {
                    let tags = self.state.tags();
                    if let Some(tag) = tags.get(self.tags.tag_idx).cloned() {
                        self.secrets.ts_selected_ids = self
                            .state
                            .secrets
                            .iter()
                            .filter(|s| s.tags.contains(&tag))
                            .map(|s| s.id.clone())
                            .collect();
                        self.secrets.editing_tag = Some(tag);
                        self.set_focus(Focus::Secrets);
                        self.send_hint("[Space] Toggle  [Enter] Save  [Esc] Cancel")
                            .await;
                    }
                }
            }
            KeyCode::Char('g') => {
                if self.focus == Focus::Members {
                    if let Some(m) = self.state.members.get(self.members.member_idx) {
                        if m.is_pending {
                            let msg = format!("Grant access to {}? [y] Yes  [n] No", m.email);
                            self.member_to_grant = Some(m.id.clone());
                            self.send_warning(msg).await;
                        }
                    }
                }
            }
            KeyCode::Char('r') => {
                if self.focus == Focus::Members {
                    self.confirming_rotate = true;
                    self.send_warning(
                        "Rotate DEK? All secrets will be re-encrypted. [y] Yes  [n] No",
                    )
                    .await;
                }
            }
            KeyCode::Char('i') => {
                if self.focus == Focus::Members {
                    let _ = self
                        .actions_tx
                        .send(Actions::NavigateTo(Route::Invite))
                        .await;
                }
            }
            _ => return EventResult::Ignored,
        }

        EventResult::Consumed
    }
}
