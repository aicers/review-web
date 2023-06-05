use super::{
    customer::{HostNetworkGroup, HostNetworkGroupInput},
    BoxedAgentManager, Role, RoleGuard,
};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, InputObject, Object, Result, ID,
};
use bincode::Options;
use review_database::{self as database, Indexable, Indexed, IndexedMapUpdate, IterableMap, Store};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    ) -> Result<Connection<String, BlockNetwork, BlockNetworkTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last) },
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
        let db = ctx.data::<Arc<Store>>()?;
        let map = db.block_network_map();
        let networks: database::HostNetworkGroup =
            networks.try_into().map_err(|_| "invalid network")?;
        let value = BlockNetwork {
            id: u32::MAX,
            name,
            networks,
            description,
        };
        let id = map.insert(value)?;
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
        let map = ctx.data::<Arc<Store>>()?.block_network_map();

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

        let db = ctx.data::<Arc<Store>>()?;
        let map = db.block_network_map();
        map.update(i, &old, &new)?;
        Ok(id)
    }

    /// Broadcast the block networks to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_block_networks(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let db = ctx.data::<Arc<Store>>()?;
        let serialized_networks =
            bincode::DefaultOptions::new().serialize(&get_block_networks(db)?)?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager
            .broadcast_block_networks(&serialized_networks)
            .await
            .map_err(Into::into)
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct BlockNetwork {
    id: u32,
    name: String,
    networks: database::HostNetworkGroup,
    description: String,
}

#[Object]
impl BlockNetwork {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.name
    }

    async fn description(&self) -> &str {
        &self.description
    }

    async fn networks(&self) -> HostNetworkGroup {
        (&self.networks).into()
    }
}

impl Indexable for BlockNetwork {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(InputObject)]
struct BlockNetworkInput {
    name: Option<String>,
    networks: Option<HostNetworkGroupInput>,
    description: Option<String>,
}

impl IndexedMapUpdate for BlockNetworkInput {
    type Entry = BlockNetwork;

    fn key(&self) -> Option<&[u8]> {
        self.name.as_deref().map(str::as_bytes)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(name);
        }
        if let Some(networks) = self.networks.as_ref() {
            value.networks = networks.try_into()?;
        }
        if let Some(description) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(description);
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref() {
            if v != value.name {
                return false;
            }
        }
        if let Some(v) = self.networks.as_ref() {
            let Ok(v) = database::HostNetworkGroup::try_from(v) else {
                return false;
            };
            if v != value.networks {
                return false;
            }
        }
        if let Some(v) = self.description.as_deref() {
            if v != value.description {
                return false;
            }
        }
        true
    }
}

struct BlockNetworkTotalCount;

#[Object]
impl BlockNetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let db = ctx.data::<Arc<Store>>()?;
        Ok(db.block_network_map().count()?)
    }
}

fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, BlockNetwork, BlockNetworkTotalCount, EmptyFields>> {
    let map = ctx.data::<Arc<Store>>()?.block_network_map();
    super::load(&map, after, before, first, last, BlockNetworkTotalCount)
}

/// Returns the block network list.
///
/// # Errors
///
/// Returns an error if the block network database could not be retrieved.
pub fn get_block_networks(db: &Arc<Store>) -> Result<database::HostNetworkGroup> {
    let map = db.block_network_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    for (_key, value) in map.iter_forward()? {
        let block_network = bincode::DefaultOptions::new()
            .deserialize::<BlockNetwork>(value.as_ref())
            .map_err(|_| "invalid value in database")?;
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

        let res = schema.execute(r#"{blockNetworkList{totalCount}}"#).await;
        assert_eq!(
            res.data.to_string(),
            r#"{blockNetworkList: {totalCount: 0}}"#
        );

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
                r#"
                query {
                    blockNetworkList(first: 10) {
                        nodes {
                            name
                        }
                    }
                }"#,
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
