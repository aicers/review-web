use async_graphql::{Context, ID, Object, Result};
use review_database::{Iterable, Role, Store, event::Direction};

use super::Tag;
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
    async fn network_tag_list(
        &self,
        ctx: &Context<'_>,
        customer_id: Option<ID>,
    ) -> Result<Vec<Tag>> {
        let store = crate::graphql::get_store(ctx)?;
        let role = match ctx.data_opt::<RoleGuard>() {
            Some(RoleGuard::Role(role)) => *role,
            _ => return Err("Forbidden".into()),
        };

        if role == Role::SystemAdministrator {
            return load_all_network_tags(&store);
        }

        let customer_id = customer_id
            .ok_or("customer ID is required")?
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer ID")?;
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
    /// Inserts a new network tag, returning the ID of the new tag.
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
            .map_err(|_| "invalid customer ID")?;
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
            .map_err(|_| "invalid customer ID")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set(customer_id)?;
        let networks = store.network_map();
        let id = id.as_str().parse::<u32>()?;
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
            .map_err(|_| "invalid customer ID")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set(customer_id)?;
        let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        Ok(tags.update(id, &old, &new)?)
    }
}

fn load_all_network_tags(store: &Store) -> Result<Vec<Tag>> {
    let customer_map = store.customer_map();
    let mut tags = Vec::new();

    for customer in customer_map.iter(Direction::Forward, None) {
        let customer = customer?;
        let tag_set = store.network_tag_set(customer.id)?;
        tags.extend(tag_set.tags().map(|tag| Tag {
            id: tag.id,
            name: tag.name.clone(),
        }));
    }

    tags.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id).then_with(|| lhs.name.cmp(&rhs.name)));
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use crate::graphql::{Role, RoleGuard, TestSchema};

    #[tokio::test]
    async fn network_tag_list_returns_empty_for_system_admin() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(r"{networkTagList{name}}")
            .await;
        assert_eq!(res.data.to_string(), r"{networkTagList: []}");
    }

    #[tokio::test]
    async fn network_tag_list_requires_customer_id_for_non_admin() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_with_guard(
                r"{networkTagList{name}}",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "customer ID is required");
    }

    #[tokio::test]
    async fn network_tag_list_returns_customer_scoped_tags_for_non_admin() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_with_guard(
                r"{networkTagList(customerId: 0){name}}",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "foo"}]}"#);
    }

    #[tokio::test]
    async fn insert_network_tag_returns_id() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);
    }

    #[tokio::test]
    async fn remove_network_tag_returns_removed_name() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeNetworkTag(customerId: 0, id: "0")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworkTag: "foo"}"#);
    }

    #[tokio::test]
    async fn update_network_tag_returns_true() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNetworkTag(customerId: 0, id: "0", old: "foo", new: "bar")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r"{updateNetworkTag: true}");
    }

    #[tokio::test]
    async fn removing_network_tag_clears_network_tag_ids() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "foo")}"#)
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [0])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {tagIds}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{network: {tagIds: ["0"]}}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeNetworkTag(customerId: 0, id: "0")
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {tagIds}}"#)
            .await;
        assert_eq!(res.data.to_string(), r"{network: {tagIds: []}}");
    }

    #[tokio::test]
    async fn network_tags_are_scoped_by_customer() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "alpha")}"#)
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 1, name: "alpha")}"#)
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(customerId: 0, name: "beta")}"#)
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(r"{networkTagList(customerId: 0){id name}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{id: "0", name: "alpha"}, {id: "1", name: "alpha"}, {id: "2", name: "beta"}]}"#
        );

        let res = schema
            .execute_as_system_admin(r"{networkTagList(customerId: 1){id name}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{id: "0", name: "alpha"}, {id: "1", name: "alpha"}, {id: "2", name: "beta"}]}"#
        );

        let res = schema
            .execute_as_system_admin(r"{networkTagList{id name}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{id: "0", name: "alpha"}, {id: "1", name: "alpha"}, {id: "2", name: "beta"}]}"#
        );

        let res = schema
            .execute_with_guard(
                r"{networkTagList(customerId: 0){id name}}",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{id: "0", name: "alpha"}, {id: "2", name: "beta"}]}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNetworkTag(customerId: 0, id: "0", old: "alpha", new: "zero-alpha")
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_system_admin(r"{networkTagList{name}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{name: "zero-alpha"}, {name: "alpha"}, {name: "beta"}]}"#
        );

        let res = schema
            .execute_with_guard(
                r"{networkTagList(customerId: 1){name}}",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkTagList: [{name: "alpha"}]}"#
        );
    }
}
