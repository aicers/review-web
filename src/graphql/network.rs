use std::convert::TryInto;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result, StringNumber,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{self as database};
use tracing::info;

use super::{
    Role, RoleGuard,
    customer::{HostNetworkGroup, HostNetworkGroupInput},
};
use crate::graphql::query_with_constraints;
use crate::info_with_username;

#[derive(Default)]
pub(super) struct NetworkQuery;

#[Object]
impl NetworkQuery {
    /// A list of networks.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Network, NetworkTotalCount, EmptyFields>> {
        info_with_username!(ctx, "Network configuration list retrieved");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// A network for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network(&self, ctx: &Context<'_>, id: ID) -> Result<Network> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such network".into());
        };
        info_with_username!(ctx, "Network configuration for {} retrieved", inner.name);
        Ok(Network { inner })
    }
}

#[derive(Default)]
pub(super) struct NetworkMutation;

#[Object]
impl NetworkMutation {
    /// Inserts a new network, returning the ID of the network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_network(
        &self,
        ctx: &Context<'_>,
        name: String,
        description: String,
        networks: HostNetworkGroupInput,
    ) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        let entry =
            review_database::Network::new(name.clone(), description, networks.try_into()?, vec![]);
        let id = map.insert(entry)?;
        info_with_username!(ctx, "Network {name} has been registered");
        Ok(ID(id.to_string()))
    }

    /// Removes networks, returning the networks names that no longer exist.
    ///
    /// On error, some networks may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn remove_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let key = map.remove(i)?;
            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            info_with_username!(ctx, "Network {name} has been deleted");
            removed.push(name);
        }
        Ok(removed)
    }

    /// Updates the given network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_network(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NetworkUpdateInput,
        new: NetworkUpdateInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let old_name = old.name.clone();
        let new_name = new.name.clone();
        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.network_map();
        map.update(i, &old.try_into()?, &new.try_into()?)?;
        info_with_username!(
            ctx,
            "Network {:?} has been updated to {:?}",
            old_name,
            new_name
        );
        Ok(id)
    }
}

#[derive(InputObject)]
struct NetworkUpdateInput {
    name: Option<String>,
    description: Option<String>,
    networks: Option<HostNetworkGroupInput>,
}

impl TryFrom<NetworkUpdateInput> for review_database::NetworkUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: NetworkUpdateInput) -> Result<Self, Self::Error> {
        Ok(Self::new(
            input.name,
            input.description,
            input.networks.and_then(|v| v.try_into().ok()),
            None,
        ))
    }
}

pub(super) struct Network {
    inner: database::Network,
}

#[Object]
impl Network {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn networks(&self) -> HostNetworkGroup<'_> {
        (&self.inner.networks).into()
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }
}

impl From<database::Network> for Network {
    fn from(inner: database::Network) -> Self {
        Self { inner }
    }
}

pub(super) fn id_args_into_uints(ids: &[ID]) -> Result<Vec<u32>> {
    ids.iter()
        .map(|id| {
            let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            Ok::<_, async_graphql::Error>(id)
        })
        .collect::<Result<Vec<_>, _>>()
}

struct NetworkTotalCount;

#[Object]
impl NetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;

        Ok(StringNumber(store.network_map().count()?))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Network, NetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.network_map();
    super::load_edges(&map, after, before, first, last, NetworkTotalCount)
}

#[cfg(test)]
mod tests {
    use crate::graphql::{Role, RoleGuard, TestSchema};

    #[tokio::test]
    async fn network_list_returns_empty() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r"{networkList{edges{node{name}}totalCount}}")
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [], totalCount: "0"}}"#
        );
    }

    #[tokio::test]
    async fn network_list_returns_inserted_entry() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "desc", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r"{networkList{edges{node{name description}}totalCount}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1", description: "desc"}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn network_returns_error_for_missing_id() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {name}}"#)
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "no such network");
    }

    #[tokio::test]
    async fn network_returns_inserted_entry() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "desc", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {name description}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{network: {name: "n1", description: "desc"}}"#
        );
    }

    #[tokio::test]
    async fn network_customer_list_field_is_removed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"{network(id: "0") {customerList{name}}}"#)
            .await;

        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("customerList"));
    }

    #[tokio::test]
    async fn remove_networks() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [], totalCount: "0"}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1"}}], totalCount: "1"}}"#
        );

        let res = schema
            .execute_as_system_admin(r#"mutation { removeNetworks(ids: ["0"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworks: ["n1"]}"#);

        let res = schema
            .execute_as_system_admin(r"{networkList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [], totalCount: "0"}}"#
        );
    }

    #[tokio::test]
    async fn update_network() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(r"{networkList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{networkList: {totalCount: "0"}}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n0", description: "", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNetwork(
                    id: "0",
                    old: {
                        name: "n0",
                        networks: {
                            hosts: ["1.1.1.1"],
                            networks: [],
                            ranges: []
                        }
                    },
                    new: {
                        name: "n0",
                        networks: {
                            hosts: ["2.2.2.2"],
                            networks: [],
                            ranges: []
                        }
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn select_networks() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [0, 1, 2])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
        let res = schema
            .execute_as_system_admin(r"{networkList{edges{node{name tagIds}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1", tagIds: ["0", "1", "2"]}}], totalCount: "1"}}"#
        );
    }

    async fn assert_forbidden(schema: &TestSchema, role: Role, query: &str) {
        let res = schema
            .execute_with_guard(query, RoleGuard::Role(role))
            .await;
        assert!(
            !res.errors.is_empty(),
            "Role {role:?} should be forbidden for query: {query}"
        );
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    // --- Regression tests: SystemAdministrator can still use all mutations ---

    #[tokio::test]
    async fn system_admin_can_insert_network() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "d", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn system_admin_can_update_network() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n0", description: "", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNetwork(
                        id: "0",
                        old: { name: "n0", networks: {
                            hosts: ["1.1.1.1"], networks: [], ranges: []
                        }, tagIds: [] },
                        new: { name: "n0-updated", networks: {
                            hosts: ["2.2.2.2"], networks: [], ranges: []
                        }, tagIds: [] }
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());
        assert_eq!(res.data.to_string(), r#"{updateNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn system_admin_can_remove_networks() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let res = schema
            .execute_as_system_admin(r#"mutation { removeNetworks(ids: ["0"]) }"#)
            .await;
        assert!(res.errors.is_empty());
        assert_eq!(res.data.to_string(), r#"{removeNetworks: ["n1"]}"#);
    }

    // --- Regression: insertNetwork still works for non-admin roles ---

    #[tokio::test]
    async fn security_administrator_can_insert_network() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertNetwork(name: "n1", description: "d", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(res.errors.is_empty());
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn security_manager_can_insert_network() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertNetwork(name: "n1", description: "d", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
                RoleGuard::Role(Role::SecurityManager),
            )
            .await;
        assert!(res.errors.is_empty());
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
    }

    // --- Regression: networkList and network(id) still work for all roles ---

    #[tokio::test]
    async fn all_roles_can_query_network_list() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "d", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let expected = r#"{networkList: {edges: [{node: {name: "n1"}}], totalCount: "1"}}"#;
        for role in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_with_guard(
                    r"{networkList{edges{node{name}}totalCount}}",
                    RoleGuard::Role(role),
                )
                .await;
            assert!(
                res.errors.is_empty(),
                "Role {role:?} should be allowed to query networkList"
            );
            assert_eq!(
                res.data.to_string(),
                expected,
                "Role {role:?} should see the same networkList result"
            );
        }
    }

    #[tokio::test]
    async fn all_roles_can_query_network_by_id() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "d", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let expected = r#"{network: {name: "n1"}}"#;
        for role in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_with_guard(r#"{network(id: "0") {name}}"#, RoleGuard::Role(role))
                .await;
            assert!(
                res.errors.is_empty(),
                "Role {role:?} should be allowed to query network(id)"
            );
            assert_eq!(
                res.data.to_string(),
                expected,
                "Role {role:?} should see the same network(id) result"
            );
        }
    }

    // --- Failure tests: non-admin roles cannot updateNetwork ---

    #[tokio::test]
    async fn non_admin_roles_cannot_update_network() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n0", description: "orig", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let update_mutation = r#"mutation {
            updateNetwork(
                id: "0",
                old: { name: "n0", description: "orig", networks: {
                    hosts: ["1.1.1.1"], networks: [], ranges: []
                }, tagIds: [] },
                new: { name: "hacked", description: "modified", networks: {
                    hosts: ["9.9.9.9"], networks: [], ranges: []
                }, tagIds: [] }
            )
        }"#;

        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            assert_forbidden(&schema, role, update_mutation).await;

            // Verify data unchanged
            let res = schema
                .execute_as_system_admin(r#"{network(id: "0") {name description}}"#)
                .await;
            assert_eq!(
                res.data.to_string(),
                r#"{network: {name: "n0", description: "orig"}}"#,
                "Network should be unchanged after forbidden {role:?} updateNetwork"
            );
        }
    }

    // --- Failure tests: non-admin roles cannot removeNetworks ---

    #[tokio::test]
    async fn non_admin_roles_cannot_remove_networks() {
        let schema = TestSchema::new().await;
        schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, tagIds: [])
                }"#,
            )
            .await;

        let remove_mutation = r#"mutation { removeNetworks(ids: ["0"]) }"#;

        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            assert_forbidden(&schema, role, remove_mutation).await;

            // Verify network still exists
            let res = schema
                .execute_as_system_admin(r"{networkList{totalCount}}")
                .await;
            assert_eq!(
                res.data.to_string(),
                r#"{networkList: {totalCount: "1"}}"#,
                "Network should still exist after forbidden {role:?} removeNetworks"
            );
        }
    }

    // --- Preserve-current-behavior: insertNetwork with tagIds: [] ---

    #[tokio::test]
    async fn insert_network_with_empty_tag_ids_for_permitted_roles() {
        let schema = TestSchema::new().await;

        for (i, role) in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
        ]
        .iter()
        .enumerate()
        {
            let name = format!("net{i}");
            let query = format!(
                r#"mutation {{
                    insertNetwork(name: "{name}", description: "", networks: {{
                        hosts: [], networks: [], ranges: []
                    }}, tagIds: [])
                }}"#
            );
            let res = schema
                .execute_with_guard(&query, RoleGuard::Role(*role))
                .await;
            assert!(
                res.errors.is_empty(),
                "Role {role:?} should be allowed to insertNetwork with empty tagIds"
            );
        }

        let res = schema
            .execute_as_system_admin(r"{networkList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{networkList: {totalCount: "3"}}"#);
    }
}
