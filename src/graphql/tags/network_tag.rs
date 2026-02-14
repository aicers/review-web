use async_graphql::{Context, ID, Object, Result};

use super::{Role, Tag};
use crate::graphql::RoleGuard;

#[derive(Default)]
pub(in crate::graphql) struct NetworkTagQuery;

#[Object]
impl NetworkTagQuery {
    /// A list of network tags for a specific customer.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network_tag_list(&self, ctx: &Context<'_>, customer_id: ID) -> Result<Vec<Tag>> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer id")?;
        let store = crate::graphql::get_store(ctx)?;
        let tags = store.network_tag_set(customer_id)?;
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
    /// Inserts a new network tag for a specific customer, returning the ID of
    /// the new tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_network_tag(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        name: String,
    ) -> Result<ID> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer id")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set(customer_id)?;
        let id = tags.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes a network tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_network_tag(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        id: ID,
    ) -> Result<Option<String>> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer id")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set(customer_id)?;
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
        customer_id: ID,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer id")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set(customer_id)?;
        Ok(tags.update(id.0.parse()?, &old, &new)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn network_tag() {
        let schema = TestSchema::new().await;

        // First create a customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertCustomer(name: "test_customer", description: "", networks: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"{networkTagList(customerId: "0"){name}}"#)
            .await;
        assert_eq!(res.data.to_string(), r"{networkTagList: []}");

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: "0", name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"{networkTagList(customerId: "0"){name}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "foo"}]}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeNetworkTag(customerId: "0", id: "0")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworkTag: "foo"}"#);

        let res = schema
            .execute_as_system_admin(r#"{networkTagList(customerId: "0"){name}}"#)
            .await;
        assert_eq!(res.data.to_string(), r"{networkTagList: []}");
    }
}
