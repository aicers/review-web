use std::sync::Arc;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    connection::{Connection, EmptyFields},
    Context, InputObject, Object, Result, ID,
};
use database::Direction;
use review_database::{self as database, Store};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{
    customer::{HostNetworkGroup, HostNetworkGroupInput},
    BoxedAgentManager, Role, RoleGuard,
};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct BlockNetworkQuery;

#[Object]
impl BlockNetworkQuery {
    /// A list of blocked networks.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn block_network_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, BlockNetwork, BlockNetworkTotalCount, EmptyFields>>
    {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct BlockNetworkMutation;

#[Object]
impl BlockNetworkMutation {
    /// Inserts a new blocked network, returning the ID of the new black point.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_block_network(
        &self,
        ctx: &Context<'_>,
        name: String,
        networks: HostNetworkGroupInput,
        description: String,
    ) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.block_network_map();
        let networks: database::HostNetworkGroup =
            networks.try_into().map_err(|_| "invalid network")?;
        let value = review_database::BlockNetwork {
            id: u32::MAX,
            name,
            networks,
            description,
        };
        let id = map.put(value)?;
        Ok(ID(id.to_string()))
    }

    /// Removes blocked networks, returning the IDs that no longer exist.
    ///
    /// On error, some blocked networks may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_block_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.block_network_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let key = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            removed.push(name);
        }

        Ok(removed)
    }

    /// Updates the given blocked network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_block_network(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: BlockNetworkInput,
        new: BlockNetworkInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let db = super::get_store(ctx).await?;
        let mut map = db.block_network_map();
        let old: review_database::BlockNetworkUpdate = old.try_into()?;
        let new: review_database::BlockNetworkUpdate = new.try_into()?;
        map.update(i, &old, &new)?;
        Ok(id)
    }

    /// Broadcast the block networks to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_block_networks(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let db = super::get_store(ctx).await?;
        let networks = get_block_networks(&db)?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        let r = agent_manager.broadcast_block_networks(&networks).await;
        r.map_err(Into::into)
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct BlockNetwork {
    inner: review_database::BlockNetwork,
}

impl From<review_database::BlockNetwork> for BlockNetwork {
    fn from(inner: review_database::BlockNetwork) -> Self {
        Self { inner }
    }
}

#[Object]
impl BlockNetwork {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn networks(&self) -> HostNetworkGroup {
        (&self.inner.networks).into()
    }
}

#[derive(InputObject)]
struct BlockNetworkInput {
    name: Option<String>,
    networks: Option<HostNetworkGroupInput>,
    description: Option<String>,
}

impl TryFrom<BlockNetworkInput> for review_database::BlockNetworkUpdate {
    type Error = anyhow::Error;

    fn try_from(input: BlockNetworkInput) -> Result<Self, Self::Error> {
        let networks = input.networks.map(TryInto::try_into).transpose()?;
        Ok(Self {
            name: input.name,
            networks,
            description: input.description,
        })
    }
}

struct BlockNetworkTotalCount;

#[Object]
impl BlockNetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        Ok(db.block_network_map().count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, BlockNetwork, BlockNetworkTotalCount, EmptyFields>> {
    let db = super::get_store(ctx).await?;
    let map = db.block_network_map();
    super::load_edges(&map, after, before, first, last, BlockNetworkTotalCount)
}

/// Returns the block network list.
///
/// # Errors
///
/// Returns an error if the block network database could not be retrieved.
pub fn get_block_networks(db: &Store) -> Result<database::HostNetworkGroup> {
    use review_database::Iterable;

    let map = db.block_network_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    for res in map.iter(Direction::Forward, None) {
        let block_network = res?;
        hosts.extend(block_network.networks.hosts());
        networks.extend(block_network.networks.networks());
        ip_ranges.extend(block_network.networks.ip_ranges().to_vec());
    }
    Ok(database::HostNetworkGroup::new(hosts, networks, ip_ranges))
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_block_network() {
        let schema = TestSchema::new().await;

        let res = schema.execute(r"{blockNetworkList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{blockNetworkList: {totalCount: 0}}");

        let res = schema
            .execute(
                r#"
                mutation {
                    insertBlockNetwork(
                        name: "Name 1"
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
        assert_eq!(res.data.to_string(), r#"{insertBlockNetwork: "0"}"#);

        let res = schema
            .execute(
                r#"
                mutation {
                    updateBlockNetwork(
                        id: "0"
                        old: {
                            name: "Name 1"
                            networks: {
                                hosts: ["1.1.1.1"]
                                networks: []
                                ranges: []
                            }
                            description: "Description 1"
                        }
                        new: {
                            name: "Name 2"
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
        assert_eq!(res.data.to_string(), r#"{updateBlockNetwork: "0"}"#);

        let res = schema
            .execute(
                r"
                query {
                    blockNetworkList(first: 10) {
                        nodes {
                            name
                        }
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{blockNetworkList: {nodes: [{name: "Name 2"}]}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    removeBlockNetworks(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeBlockNetworks: ["Name 2"]}"#);
    }
}
