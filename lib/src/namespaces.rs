use crate::{
    error::{Error, Result},
    types::{EnviDocument, Namespace},
};
use automerge::AutoCommit;
use autosurgeon::{hydrate, reconcile};
use uuid::Uuid;

pub fn add_namespace(doc: &mut AutoCommit, name: &str) -> Result<()> {
    let id = Uuid::now_v7().to_string();
    let mut state: EnviDocument = hydrate(doc)?;
    state.namespaces.insert(
        id.clone(),
        Namespace {
            id,
            name: name.to_string(),
            secret_ids: vec![],
        },
    );
    reconcile(doc, &state)?;
    Ok(())
}

pub fn remove_namespace(doc: &mut AutoCommit, id: &str) -> Result<()> {
    let mut state: EnviDocument = hydrate(doc)?;
    state.namespaces.remove(id);
    reconcile(doc, &state)?;
    Ok(())
}

pub fn update_namespace(doc: &mut AutoCommit, id: &str, name: &str) -> Result<()> {
    let mut state: EnviDocument = hydrate(doc)?;
    let namespace = state
        .namespaces
        .get_mut(id)
        .ok_or_else(|| Error::NamespaceNotFound(id.to_string()))?;
    namespace.name = name.to_string();
    reconcile(doc, &state)?;
    Ok(())
}

pub fn set_namespace_secrets(
    doc: &mut AutoCommit,
    namespace_id: &str,
    secret_ids: Vec<String>,
) -> Result<()> {
    let mut state: EnviDocument = hydrate(doc)?;
    let namespace = state
        .namespaces
        .get_mut(namespace_id)
        .ok_or_else(|| Error::NamespaceNotFound(namespace_id.to_string()))?;
    namespace.secret_ids = secret_ids;
    reconcile(doc, &state)?;
    Ok(())
}

pub fn list_namespaces(doc: &AutoCommit) -> Result<Vec<Namespace>> {
    let state: EnviDocument = hydrate(doc)?;
    Ok(state.namespaces.into_values().collect())
}
