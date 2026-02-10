use std::collections::HashSet;

use async_graphql::{Context, ID, Object, Result};
use review_database::{Indexable, Iterable, Store, event::Direction};

use super::{Role, Tag};
use crate::graphql::RoleGuard;
use crate::graphql::customer_access::{
    hostname_customer_id_map, is_member, sensor_from_key, users_customers,
};

/// Collects the set of event-tag IDs referenced by `TriageResponse`s that
/// the current user is allowed to see.
///
/// Returns `None` for administrators (no filtering needed), or
/// `Some(HashSet)` for scoped users.
fn accessible_tag_ids(store: &Store, users_cids: Option<&[u32]>) -> Result<Option<HashSet<u32>>> {
    if users_cids.is_none() {
        return Ok(None); // Admin: all tags are accessible
    }

    let hostname_map = hostname_customer_id_map(store)?;
    let map = store.triage_response_map();
    let mut tag_ids = HashSet::new();

    for entry in map.iter(Direction::Forward, None) {
        let tr = entry.map_err(|e| {
            async_graphql::Error::new(format!("failed to iterate triage responses: {e}"))
        })?;
        let key_bytes = tr.key();
        let Ok(sensor) = sensor_from_key(&key_bytes) else {
            continue;
        };
        match hostname_map.get(&sensor).copied() {
            Some(c) if is_member(users_cids, c) => {
                tag_ids.extend(tr.tag_ids().iter().copied());
            }
            _ => {}
        }
    }

    Ok(Some(tag_ids))
}

/// Checks that the user has access to **all** `TriageResponse`s that
/// reference the given `tag_id`.
///
/// Returns `Ok(())` for administrators or when every referencing response
/// belongs to an accessible customer. Returns `Err("Forbidden")` if any
/// referencing response belongs to an inaccessible customer.
fn check_tag_access(store: &Store, users_cids: Option<&[u32]>, tag_id: u32) -> Result<()> {
    if users_cids.is_none() {
        return Ok(()); // Admin bypass
    }

    let hostname_map = hostname_customer_id_map(store)?;
    let map = store.triage_response_map();

    for entry in map.iter(Direction::Forward, None) {
        let tr = entry.map_err(|e| {
            async_graphql::Error::new(format!("failed to iterate triage responses: {e}"))
        })?;
        if !tr.tag_ids().contains(&tag_id) {
            continue;
        }
        let key_bytes = tr.key();
        let Ok(sensor) = sensor_from_key(&key_bytes) else {
            return Err("Forbidden".into());
        };
        match hostname_map.get(&sensor).copied() {
            Some(c) if is_member(users_cids, c) => {}
            _ => return Err("Forbidden".into()),
        }
    }

    Ok(())
}

#[derive(Default)]
pub(in crate::graphql) struct EventTagQuery;

#[Object]
impl EventTagQuery {
    /// A list of event tags.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let allowed = accessible_tag_ids(&store, users_cids.as_deref())?;
        let set = store.event_tag_set()?;

        Ok(set
            .tags()
            .filter(|tag| match &allowed {
                None => true, // Admin: all tags visible
                Some(ids) => ids.contains(&tag.id),
            })
            .map(|tag| Tag {
                id: tag.id,
                name: tag.name.clone(),
            })
            .collect())
    }
}

#[derive(Default)]
pub(in crate::graphql) struct EventTagMutation;

#[Object]
impl EventTagMutation {
    /// Inserts a new event tag, returning the ID of the new tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_event_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let mut set = store.event_tag_set()?;
        let id = set.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes an event tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_event_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;
        check_tag_access(&store, users_cids.as_deref(), id_num)?;

        let mut set = store.event_tag_set()?;
        let triage_response_map = store.triage_response_map();
        let name = set.remove_event_tag(id_num, &triage_response_map)?;
        Ok(Some(name))
    }

    /// Updates the name of an event tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_event_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;
        check_tag_access(&store, users_cids.as_deref(), id_num)?;

        let mut set = store.event_tag_set()?;
        Ok(set.update(id_num, &old, &new)?)
    }
}
