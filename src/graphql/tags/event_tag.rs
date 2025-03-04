use async_graphql::{Context, ID, Object, Result};

use super::{Role, Tag};
use crate::graphql::RoleGuard;

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
        let store = crate::graphql::get_store(ctx).await?;
        let set = store.event_tag_set()?;
        Ok(set
            .tags()
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
        let store = crate::graphql::get_store(ctx).await?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let mut set = store.event_tag_set()?;
        let triage_response_map = store.triage_response_map();
        let id = id.0.parse::<u32>()?;
        let name = set.remove_event_tag(id, &triage_response_map)?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let mut set = store.event_tag_set()?;
        Ok(set.update(id.0.parse()?, &old, &new)?)
    }
}
