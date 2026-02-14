use std::convert::TryInto;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result, StringNumber,
    connection::{Connection, Edge, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{self as database, Iterable, UniqueKey, event::Direction};
use tracing::info;

use super::{
    Role, RoleGuard,
    cluster::try_id_args_into_ints,
    customer::{Customer, HostNetworkGroup, HostNetworkGroupInput},
    customer_access::{has_membership, users_customers},
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
        let user_customers = users_customers(ctx)?;
        info_with_username!(ctx, "Network configuration list retrieved");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, after, before, first, last, user_customers).await
            },
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

        let user_customers = users_customers(ctx)?;
        if !has_membership(user_customers.as_deref(), &inner.customer_ids) {
            return Err("Forbidden: access denied".into());
        }

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
        customer_ids: Vec<ID>,
        tag_ids: Vec<ID>,
    ) -> Result<ID> {
        let customer_ids = id_args_into_uints(&customer_ids)?;
        let tag_ids = id_args_into_uints(&tag_ids)?;

        let user_customers = users_customers(ctx)?;
        if !has_membership(user_customers.as_deref(), &customer_ids) {
            return Err("Forbidden: access denied".into());
        }

        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        let entry = review_database::Network::new(
            name.clone(),
            description,
            networks.try_into()?,
            customer_ids,
            tag_ids,
        );
        let id = map.insert(entry)?;
        info_with_username!(ctx, "Network {name} has been registered");
        Ok(ID(id.to_string()))
    }

    /// Removes networks, returning the networks names that no longer exist.
    ///
    /// On error, some networks may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let user_customers = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

            let Some(network) = map.get_by_id(i)? else {
                return Err("no such network".into());
            };
            if !has_membership(user_customers.as_deref(), &network.customer_ids) {
                return Err("Forbidden: access denied".into());
            }

            let name = network.name.clone();
            let _ = map.remove(i)?;

            info_with_username!(ctx, "Network {name} has been deleted");
            removed.push(name);
        }
        Ok(removed)
    }

    /// Updates the given network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_network(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NetworkUpdateInput,
        new: NetworkUpdateInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let user_customers = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        let Some(network) = map.get_by_id(i)? else {
            return Err("no such network".into());
        };
        if !has_membership(user_customers.as_deref(), &network.customer_ids) {
            return Err("Forbidden: access denied".into());
        }

        if let Some(new_customer_ids) = &new.customer_ids {
            let new_customer_ids = id_args_into_uints(new_customer_ids)?;
            if !has_membership(user_customers.as_deref(), &new_customer_ids) {
                return Err("Forbidden: access denied".into());
            }
        }

        let old_name = old.name.clone();
        let new_name = new.name.clone();
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
    customer_ids: Option<Vec<ID>>,
    tag_ids: Option<Vec<ID>>,
}

impl TryFrom<NetworkUpdateInput> for review_database::NetworkUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: NetworkUpdateInput) -> Result<Self, Self::Error> {
        let customer_ids = try_id_args_into_ints::<u32>(input.customer_ids)?;
        let tag_ids = try_id_args_into_ints::<u32>(input.tag_ids)?;
        Ok(Self::new(
            input.name,
            input.description,
            input.networks.and_then(|v| v.try_into().ok()),
            customer_ids,
            tag_ids,
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

    #[graphql(name = "customerList")]
    async fn customer_ids(&self, ctx: &Context<'_>) -> Result<Vec<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        let mut customers = Vec::new();

        for &id in &self.inner.customer_ids {
            #[allow(clippy::cast_sign_loss)] // u32 stored as i32 in database
            let Some(customer) = map.get_by_id(id)? else {
                continue;
            };
            customers.push(customer.into());
        }
        Ok(customers)
    }

    async fn tag_ids(&self) -> Vec<ID> {
        self.inner
            .tag_ids()
            .iter()
            .map(|&id| ID(id.to_string()))
            .collect()
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

struct NetworkTotalCount {
    user_customers: Option<Vec<u32>>,
}

#[Object]
impl NetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();

        if self.user_customers.is_none() {
            return Ok(StringNumber(map.count()?));
        }

        let count = map
            .iter(Direction::Forward, None)
            .filter(|res| match res {
                Ok(network) => {
                    has_membership(self.user_customers.as_deref(), &network.customer_ids)
                }
                Err(_) => true,
            })
            .count();
        Ok(StringNumber(count))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    user_customers: Option<Vec<u32>>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Network, NetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.network_map();

    if user_customers.is_none() {
        return super::load_edges(
            &map,
            after,
            before,
            first,
            last,
            NetworkTotalCount { user_customers },
        );
    }

    let user_customers_ref = user_customers.as_deref();
    let predicate = |network: &database::Network| -> bool {
        has_membership(user_customers_ref, &network.customer_ids)
    };

    let (nodes, has_previous, has_next) =
        super::process_load_edges_filtered(&map, after, before, first, last, None, predicate);

    for node in &nodes {
        if let Err(e) = node {
            tracing::warn!("Failed to load from DB: {}", e);
            return Err("database error".into());
        }
    }

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        NetworkTotalCount {
            user_customers: user_customers.clone(),
        },
    );
    connection.edges.extend(nodes.into_iter().map(|node| {
        let Ok(node) = node else { unreachable!() };
        let key_ref: &[u8] = node.unique_key();
        let key = key_ref.to_vec();
        Edge::new(OpaqueCursor(key), node.into())
    }));
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use review_database::Role;

    use crate::graphql::TestSchema;

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
                    }, customerIds: [], tagIds: [])
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
                    }, customerIds: [], tagIds: [])
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
                        customerIds: [],
                        tagIds: []
                    },
                    new: {
                        name: "n0",
                        networks: {
                            hosts: ["2.2.2.2"],
                            networks: [],
                            ranges: []
                        }
                        customerIds: [],
                        tagIds: []
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
                    }, customerIds: [], tagIds: [0, 1, 2])
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

    #[tokio::test]
    async fn network_customer_scoping_admin_sees_all() {
        let schema = TestSchema::new().await;

        // Create two customers
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

        // Create networks with different customer associations
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c2", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["1"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "1"}"#);

        // Create admin user (customer_ids = None)
        schema.create_user_account("admin_user", Role::SecurityAdministrator, None);

        // Admin should see all networks
        let res = schema
            .execute_as_user(
                r"{networkList{edges{node{name}}totalCount}}",
                "admin_user",
                Role::SecurityAdministrator,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "net_c1"}}, {node: {name: "net_c2"}}], totalCount: "2"}}"#
        );
    }

    #[tokio::test]
    async fn network_customer_scoping_user_sees_own_networks() {
        let schema = TestSchema::new().await;

        // Create two customers
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

        // Create networks with different customer associations
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c2", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["1"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "1"}"#);

        // Create user with access to customer 0 only
        schema.create_user_account("scoped_user", Role::SecurityMonitor, Some(vec![0]));

        // Scoped user should only see network belonging to customer 0
        let res = schema
            .execute_as_user(
                r"{networkList{edges{node{name}}totalCount}}",
                "scoped_user",
                Role::SecurityMonitor,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "net_c1"}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn network_customer_scoping_read_denied() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to different customer
        schema.create_user_account("other_user", Role::SecurityMonitor, Some(vec![99]));

        // User should be denied access to network
        let res = schema
            .execute_as_user(
                r#"{network(id: "0") {name}}"#,
                "other_user",
                Role::SecurityMonitor,
            )
            .await;
        assert!(!res.errors.is_empty());
        assert!(res.errors[0].message.contains("access denied"));
    }

    #[tokio::test]
    async fn network_customer_scoping_update_denied() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to different customer
        schema.create_user_account("other_user", Role::SecurityManager, Some(vec![99]));

        // User should be denied update access to network
        let res = schema
            .execute_as_user(
                r#"mutation {
                    updateNetwork(
                        id: "0",
                        old: {
                            name: "net_c1",
                            customerIds: ["0"]
                        },
                        new: {
                            name: "modified"
                        }
                    )
                }"#,
                "other_user",
                Role::SecurityManager,
            )
            .await;
        assert!(!res.errors.is_empty());
        assert!(res.errors[0].message.contains("access denied"));
    }

    #[tokio::test]
    async fn network_customer_scoping_delete_denied() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to different customer
        schema.create_user_account("other_user", Role::SecurityManager, Some(vec![99]));

        // User should be denied delete access to network
        let res = schema
            .execute_as_user(
                r#"mutation { removeNetworks(ids: ["0"]) }"#,
                "other_user",
                Role::SecurityManager,
            )
            .await;
        assert!(!res.errors.is_empty());
        assert!(res.errors[0].message.contains("access denied"));
    }

    #[tokio::test]
    async fn network_customer_scoping_insert_denied() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create user with access to different customer
        schema.create_user_account("other_user", Role::SecurityManager, Some(vec![99]));

        // User should be denied insert with customer they don't have access to
        let res = schema
            .execute_as_user(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
                "other_user",
                Role::SecurityManager,
            )
            .await;
        assert!(!res.errors.is_empty());
        assert!(res.errors[0].message.contains("access denied"));
    }

    #[tokio::test]
    async fn network_customer_scoping_insert_allowed() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create user with access to customer 0
        schema.create_user_account("scoped_user", Role::SecurityManager, Some(vec![0]));

        // User should be allowed to insert with their own customer
        let res = schema
            .execute_as_user(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
                "scoped_user",
                Role::SecurityManager,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn network_customer_scoping_allowed_access() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to customer 0
        schema.create_user_account("scoped_user", Role::SecurityMonitor, Some(vec![0]));

        // User should be allowed to read network
        let res = schema
            .execute_as_user(
                r#"{network(id: "0") {name}}"#,
                "scoped_user",
                Role::SecurityMonitor,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{network: {name: "net_c1"}}"#);
    }

    #[tokio::test]
    async fn network_customer_scoping_update_allowed() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to customer 0
        schema.create_user_account("scoped_user", Role::SecurityManager, Some(vec![0]));

        // User should be allowed to update network
        let res = schema
            .execute_as_user(
                r#"mutation {
                    updateNetwork(
                        id: "0",
                        old: {
                            name: "net_c1",
                            customerIds: ["0"]
                        },
                        new: {
                            name: "modified_net"
                        }
                    )
                }"#,
                "scoped_user",
                Role::SecurityManager,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateNetwork: "0"}"#);
    }

    #[tokio::test]
    async fn network_customer_scoping_delete_allowed() {
        let schema = TestSchema::new().await;

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create network
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(name: "net_c1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: ["0"], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        // Create user with access to customer 0
        schema.create_user_account("scoped_user", Role::SecurityManager, Some(vec![0]));

        // User should be allowed to delete network
        let res = schema
            .execute_as_user(
                r#"mutation { removeNetworks(ids: ["0"]) }"#,
                "scoped_user",
                Role::SecurityManager,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{removeNetworks: ["net_c1"]}"#);
    }
}
