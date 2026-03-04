use std::collections::HashSet;

use async_graphql::{Context, ID, Object, Result};
use review_database::{Iterable, event::Direction};

use super::{Role, Tag};
use crate::graphql::{
    RoleGuard,
    customer_access::{has_any_membership, users_customers},
};

fn accessible_network_tag_ids(ctx: &Context<'_>, users_customers: &[u32]) -> Result<HashSet<u32>> {
    let store = crate::graphql::get_store(ctx)?;
    let networks = store.network_map();
    let mut visible_tag_ids = HashSet::new();

    for entry in networks.iter(Direction::Forward, None) {
        let network = entry.map_err(|_| async_graphql::Error::new("database error"))?;
        if has_any_membership(Some(users_customers), &network.customer_ids) {
            visible_tag_ids.extend(network.tag_ids().iter().copied());
        }
    }
    Ok(visible_tag_ids)
}

/// Checks whether a scoped user can access a network tag for mutation.
///
/// Returns:
/// 1. `Err("Forbidden")` if any referenced network belongs to an inaccessible customer.
/// 2. `Err("Forbidden")` if the tag is not referenced by any network.
/// 3. `Ok(())` if the tag is referenced and all referenced networks are accessible.
fn check_network_tag_access(ctx: &Context<'_>, tag_id: u32, users_customers: &[u32]) -> Result<()> {
    let store = crate::graphql::get_store(ctx)?;
    let networks = store.network_map();
    let mut is_referenced = false;

    for entry in networks.iter(Direction::Forward, None) {
        let network = entry.map_err(|_| async_graphql::Error::new("database error"))?;
        if network.tag_ids().contains(&tag_id) {
            is_referenced = true;
            if !has_any_membership(Some(users_customers), &network.customer_ids) {
                return Err("Forbidden".into());
            }
        }
    }

    if is_referenced {
        Ok(())
    } else {
        Err("Forbidden".into())
    }
}

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
        let users_customers = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let tags = store.network_tag_set()?;

        let tags = if let Some(users_customers) = users_customers.as_deref() {
            let visible_tag_ids = accessible_network_tag_ids(ctx, users_customers)?;
            tags.tags()
                .filter(|tag| visible_tag_ids.contains(&tag.id))
                .map(|tag| Tag {
                    id: tag.id,
                    name: tag.name.clone(),
                })
                .collect()
        } else {
            tags.tags()
                .map(|tag| Tag {
                    id: tag.id,
                    name: tag.name.clone(),
                })
                .collect()
        };

        Ok(tags)
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
    async fn insert_network_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set()?;
        let id = tags.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes a network tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_network_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let id = id.0.parse::<u32>()?;
        if let Some(users_customers) = users_customers(ctx)?.as_deref() {
            check_network_tag_access(ctx, id, users_customers)?;
        }

        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set()?;
        let networks = store.network_map();
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
        let id = id.0.parse::<u32>()?;
        if let Some(users_customers) = users_customers(ctx)?.as_deref() {
            check_network_tag_access(ctx, id, users_customers)?;
        }

        let store = crate::graphql::get_store(ctx)?;
        let mut tags = store.network_tag_set()?;
        Ok(tags.update(id, &old, &new)?)
    }
}

#[cfg(test)]
mod tests {
    use review_database::Role;

    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn network_tag() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(r"{networkTagList{name}}")
            .await;
        assert_eq!(res.data.to_string(), r"{networkTagList: []}");

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(r"{networkTagList{name}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "foo"}]}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [0])
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
                    removeNetworkTag(id: "0")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworkTag: "foo"}"#);

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {tagIds}}"#)
            .await;
        assert_eq!(res.data.to_string(), r"{network: {tagIds: []}}");
    }

    #[tokio::test]
    async fn network_tag_list_scoped_by_customer() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(name: "t1")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(name: "t2")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n2", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["1"], tagIds: ["1"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "1"}"#);

        let res = schema
            .execute_as_scoped_user(
                r"{networkTagList{name}}",
                Role::SecurityMonitor,
                Some(vec![0]),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "t1"}]}"#);
    }

    #[tokio::test]
    async fn network_tag_insert_allowed_for_scoped_user() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_scoped_user(
                r#"mutation {insertNetworkTag(name: "new-tag")}"#,
                Role::SecurityManager,
                Some(vec![0]),
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);
    }

    #[tokio::test]
    async fn network_tag_update_remove_require_full_reference_access() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(name: "shared")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n2", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["1"], tagIds: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "1"}"#);

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { updateNetworkTag(id: "0", old: "shared", new: "renamed") }"#,
                Role::SecurityManager,
                Some(vec![0]),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { removeNetworkTag(id: "0") }"#,
                Role::SecurityManager,
                Some(vec![0]),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn network_tag_update_remove_denied_when_unreferenced() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"mutation {insertNetworkTag(name: "orphan")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { updateNetworkTag(id: "0", old: "orphan", new: "renamed") }"#,
                Role::SecurityManager,
                Some(vec![0]),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { removeNetworkTag(id: "0") }"#,
                Role::SecurityManager,
                Some(vec![0]),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");
    }
}
