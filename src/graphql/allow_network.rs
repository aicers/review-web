use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, ID, InputObject, Object, Result,
    connection::{Connection, EmptyFields},
};
use database::event::Direction;
use review_database::Iterable;
use review_database::{self as database, Store};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use super::{
    BoxedAgentManager, Role, RoleGuard,
    customer::{HostNetworkGroup, HostNetworkGroupInput, NetworksTargetAgentKeysPair},
};
use crate::graphql::node::SEMI_SUPERVISED_AGENT;
use crate::graphql::{parse_allow_block_list_key, query_with_constraints};
use crate::{error_with_username, info_with_username};

#[derive(Default)]
pub(super) struct AllowNetworkQuery;

#[Object]
impl AllowNetworkQuery {
    /// A list of allowed networks.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn allow_network_list(
        &self,
        ctx: &Context<'_>,
        customer_id: Option<u32>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, AllowNetwork, AllowNetworkTotalCount, EmptyFields>>
    {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, customer_id, after, before, first, last).await
            },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct AllowNetworkMutation;

#[Object]
impl AllowNetworkMutation {
    /// Inserts a new allowed network, returning the ID of the new allowed network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_allow_network(
        &self,
        ctx: &Context<'_>,
        customer_id: u32,
        name: String,
        networks: HostNetworkGroupInput,
        description: String,
    ) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.allow_network_map();
        let networks: database::HostNetworkGroup =
            networks.try_into().map_err(|_| "invalid network")?;
        let value = review_database::AllowNetwork {
            id: u32::MAX,
            name: name.clone(),
            customer_id,
            networks,
            description,
        };
        let id = map.put(value)?;
        info_with_username!(ctx, "Allowlist {name} has been registered");

        if let Ok(networks) = get_allow_networks(&store, customer_id) {
            let agent_keys = crate::graphql::agent_keys_by_customer_id(&store)?;
            if let Some(agent_keys) = agent_keys.get(&customer_id) {
                let network_list = NetworksTargetAgentKeysPair::new(
                    networks,
                    agent_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                );
                if let Err(e) = apply_allow_networks(ctx, &[network_list]).await {
                    error_with_username!(ctx, "Failed to broadcast allow networks: {e:?}");
                }
            }
        }
        Ok(ID(id.to_string()))
    }

    /// Removes allowed networks, returning the names of successfully removed networks.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_allow_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.allow_network_map();

        let ids: Vec<u32> = ids
            .iter()
            .map(|id| id.as_str().parse::<u32>().map_err(|_| "invalid ID"))
            .collect::<Result<_, _>>()?;
        let count = ids.len();
        let mut affected_customers = std::collections::HashSet::new();
        let removed = ids
            .into_iter()
            .try_fold(Vec::with_capacity(count), |mut removed, id| {
                if let Ok(key) = map.remove(id)
                    && let Ok((customer_id, name)) = parse_allow_block_list_key(&key)
                {
                    info_with_username!(ctx, "Allowlist {name} has been deleted");
                    removed.push(name);
                    affected_customers.insert(customer_id);
                    Ok(removed)
                } else {
                    Err(removed)
                }
            })
            .unwrap_or_else(|r| r);

        if removed.is_empty() {
            return Err("None of the specified allowed networks was removed.".into());
        }

        let agent_keys_map = crate::graphql::agent_keys_by_customer_id(&store)?;
        let mut network_lists = Vec::new();

        for customer_id in affected_customers {
            if let Ok(networks) = get_allow_networks(&store, customer_id)
                && let Some(agent_keys) = agent_keys_map.get(&customer_id)
            {
                network_lists.push(NetworksTargetAgentKeysPair::new(
                    networks,
                    agent_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                ));
            }
        }

        if !network_lists.is_empty()
            && let Err(e) = apply_allow_networks(ctx, &network_lists).await
        {
            error_with_username!(ctx, "Failed to broadcast allow networks: {e:?}");
        }

        if removed.len() < count {
            return Err("Some allowed networks were removed, but not all.".into());
        }

        Ok(removed)
    }

    /// Updates the given allowed network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_allow_network(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: AllowNetworkInput,
        new: AllowNetworkInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.allow_network_map();
        let current_allow_network = map
            .get_by_id(i)?
            .ok_or_else(|| anyhow::anyhow!("no such allow network"))?;
        let old: review_database::AllowNetworkUpdate = old.try_into()?;
        let new: review_database::AllowNetworkUpdate = new.try_into()?;
        map.update(i, &old, &new)?;
        info_with_username!(
            ctx,
            "Allowlist {:?} has been updated to {:?}",
            old.name,
            new.name
        );

        if let Ok(networks) = get_allow_networks(&store, current_allow_network.customer_id) {
            let agent_keys = crate::graphql::agent_keys_by_customer_id(&store)?;
            if let Some(agent_keys) = agent_keys.get(&current_allow_network.customer_id) {
                let network_list = NetworksTargetAgentKeysPair::new(
                    networks,
                    agent_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                );
                if let Err(e) = apply_allow_networks(ctx, &[network_list]).await {
                    error_with_username!(ctx, "Failed to broadcast allow networks: {e:?}");
                }
            }
        }
        Ok(id)
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct AllowNetwork {
    inner: review_database::AllowNetwork,
}

impl From<review_database::AllowNetwork> for AllowNetwork {
    fn from(inner: review_database::AllowNetwork) -> Self {
        Self { inner }
    }
}

#[Object]
impl AllowNetwork {
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
}

#[derive(InputObject)]
struct AllowNetworkInput {
    name: Option<String>,
    customer_id: Option<u32>,
    networks: Option<HostNetworkGroupInput>,
    description: Option<String>,
}

impl TryFrom<AllowNetworkInput> for review_database::AllowNetworkUpdate {
    type Error = anyhow::Error;

    fn try_from(input: AllowNetworkInput) -> Result<Self, Self::Error> {
        let networks = input.networks.map(TryInto::try_into).transpose()?;
        Ok(Self {
            name: input.name,
            customer_id: input.customer_id,
            networks,
            description: input.description,
        })
    }
}

struct AllowNetworkTotalCount {
    customer_id: Option<u32>,
}

#[Object]
impl AllowNetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.allow_network_map();
        if let Some(customer_id) = self.customer_id {
            let key = customer_id.to_be_bytes().to_vec();
            Ok(map.prefix_iter(Direction::Forward, None, &key).count())
        } else {
            Ok(map.count()?)
        }
    }
}

async fn load(
    ctx: &Context<'_>,
    customer_id: Option<u32>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, AllowNetwork, AllowNetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.allow_network_map();
    let prefix = customer_id.map(|id| id.to_be_bytes().to_vec());
    super::load_edges_with_prefix(
        &map,
        after,
        before,
        first,
        last,
        prefix.as_deref(),
        AllowNetworkTotalCount { customer_id },
    )
}

/// Returns the allow network list.
///
/// # Errors
///
/// Returns an error if the allow network database could not be retrieved.
pub fn get_allow_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    use review_database::Iterable;

    let map = db.allow_network_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    let key = customer_id.to_be_bytes();

    for res in map.prefix_iter(Direction::Forward, None, &key) {
        let allow_network = res?;
        hosts.extend(allow_network.networks.hosts());
        networks.extend(allow_network.networks.networks());
        ip_ranges.extend(allow_network.networks.ip_ranges().to_vec());
    }
    Ok(database::HostNetworkGroup::new(hosts, networks, ip_ranges))
}

async fn apply_allow_networks(
    ctx: &Context<'_>,
    networks: &[NetworksTargetAgentKeysPair],
) -> Result<()> {
    let agent_manager = ctx.data::<BoxedAgentManager>()?;
    agent_manager
        .send_agent_specific_allow_networks(networks)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_allow_network() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(r"{allowNetworkList(customerId: 0){totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r"{allowNetworkList: {totalCount: 0}}");

        let res = schema
            .execute(
                r#"
                mutation {
                    insertAllowNetwork(
                        name: "Name 1"
                        customerId: 0
                        networks: {
                            hosts: ["1.1.1.1"]
                            networks: []
                            ranges: []
                        }
                        description: "Description 1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAllowNetwork: "0"}"#);

        let res = schema
            .execute(
                r#"
                mutation {
                    updateAllowNetwork(
                        id: "0"
                        old: {
                            name: "Name 1"
                            customerId: 0
                            networks: {
                                hosts: ["1.1.1.1"]
                                networks: []
                                ranges: []
                            }
                            description: "Description 1"
                        }
                        new: {
                            name: "Name 2"
                            customerId: 0
                            networks: {
                                hosts: ["1.1.1.1"]
                                networks: []
                                ranges: []
                            }
                            description: "Description 1"
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateAllowNetwork: "0"}"#);

        let res = schema
            .execute(
                r"
                query {
                    allowNetworkList(customerId: 0, first: 10) {
                        nodes {
                            name
                        }
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{allowNetworkList: {nodes: [{name: "Name 2"}]}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    removeAllowNetworks(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAllowNetworks: ["Name 2"]}"#);
    }
}
