use async_graphql::{Context, ID, Object, Result};

use super::{Role, Tag};
use crate::graphql::RoleGuard;

#[derive(Default)]
pub(in crate::graphql) struct NetworkTagQuery;

#[Object]
impl NetworkTagQuery {
    /// A list of network tags.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let store = crate::graphql::get_store(ctx).await?;
        let tags = store.network_tag_set()?;
        Ok(tags
            .tags()
            .map(|tag| Tag {
                id: tag.id,
                name: tag.name.clone(),
            })
            .collect())
    }
}

#[derive(Default)]
pub(in crate::graphql) struct NetworkTagMutation;

#[Object]
impl NetworkTagMutation {
    /// Inserts a new network tag, returning the ID of the new tag.
    ///
    /// # Errors
    ///
    /// Returns an error if a tag with the same name already exists.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_network_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
        let mut tags = store.network_tag_set()?;

        // Check if a tag with the same name already exists
        if tags.tags().any(|tag| tag.name == name) {
            return Err(format!("Network tag with name '{name}' already exists").into());
        }

        let id = tags.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes a network tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_network_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let mut tags = store.network_tag_set()?;
        let networks = store.network_map();
        let id = id.0.parse::<u32>()?;
        let name = tags.remove_network_tag(id, &networks)?;
        Ok(Some(name))
    }

    /// Updates the name of a network tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_network_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let mut tags = store.network_tag_set()?;
        Ok(tags.update(id.0.parse()?, &old, &new)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn network_tag() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r"{networkTagList{name}}").await;
        assert_eq!(res.data.to_string(), r"{networkTagList: []}");

        let res = schema
            .execute(r#"mutation {insertNetworkTag(name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema.execute(r"{networkTagList{name}}").await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "foo"}]}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [0])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema.execute(r#"{network(id: "0") {tagIds}}"#).await;
        assert_eq!(res.data.to_string(), r#"{network: {tagIds: ["0"]}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    removeNetworkTag(id: "0")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworkTag: "foo"}"#);

        let res = schema.execute(r#"{network(id: "0") {tagIds}}"#).await;
        assert_eq!(res.data.to_string(), r"{network: {tagIds: []}}");
    }

    #[tokio::test]
    async fn insert_duplicate_network_tag_fails() {
        let schema = TestSchema::new().await;

        // Insert the first tag
        let res = schema
            .execute(r#"mutation {insertNetworkTag(name: "duplicate")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        // Attempt to insert a tag with the same name
        let res = schema
            .execute(r#"mutation {insertNetworkTag(name: "duplicate")}"#)
            .await;

        // Verify the operation failed with an error
        assert!(!res.errors.is_empty());
        assert!(
            res.errors[0]
                .message
                .contains("Network tag with name 'duplicate' already exists")
        );

        // Verify only one tag exists
        let res = schema.execute(r"{networkTagList{name}}").await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{name: "duplicate"}]}"#
        );
    }
}
