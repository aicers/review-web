use super::{
    customer::{HostNetworkGroup, HostNetworkGroupInput},
    BoxedAgentManager, Role, RoleGuard,
};
use crate::graphql::validate_and_process_pagination_params;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, InputObject, Object, Result, ID,
};
use bincode::Options;
use database::Direction;
use review_database::{self as database, Store};
use serde::{Deserialize, Serialize};

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
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, AllowNetwork, AllowNetworkTotalCount, EmptyFields>> {
        let (after, before, first, last) =
            validate_and_process_pagination_params(after, before, first, last)?;

        query(
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
pub(super) struct AllowNetworkMutation;

#[Object]
impl AllowNetworkMutation {
    /// Inserts a new allowed network, returning the ID of the new allowed network.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_allow_network(
        &self,
        ctx: &Context<'_>,
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
            name,
            networks,
            description,
        };
        let id = map.put(value)?;
        Ok(ID(id.to_string()))
    }

    /// Removes allowed networks, returning the IDs that no longer exist.
    ///
    /// On error, some allowed networks may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_allow_networks(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.allow_network_map();

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
        let old: review_database::AllowNetworkUpdate = old.try_into()?;
        let new: review_database::AllowNetworkUpdate = new.try_into()?;
        map.update(i, &old, &new)?;
        Ok(id)
    }

    /// Broadcast the allowed networks to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_allow_networks(&self, ctx: &Context<'_>) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;

        let serialized_networks =
            bincode::DefaultOptions::new().serialize(&get_allow_networks(&store)?)?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager
            .broadcast_allow_networks(&serialized_networks)
            .await
            .map_err(Into::into)
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

    async fn networks(&self) -> HostNetworkGroup {
        (&self.inner.networks).into()
    }
}

#[derive(InputObject)]
struct AllowNetworkInput {
    name: Option<String>,
    networks: Option<HostNetworkGroupInput>,
    description: Option<String>,
}

impl TryFrom<AllowNetworkInput> for review_database::AllowNetworkUpdate {
    type Error = anyhow::Error;

    fn try_from(input: AllowNetworkInput) -> Result<Self, Self::Error> {
        let networks = input.networks.map(TryInto::try_into).transpose()?;
        Ok(Self {
            name: input.name,
            networks,
            description: input.description,
        })
    }
}

struct AllowNetworkTotalCount;

#[Object]
impl AllowNetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;

        Ok(store.allow_network_map().count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, AllowNetwork, AllowNetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.allow_network_map();
    super::load_edges(&map, after, before, first, last, AllowNetworkTotalCount)
}

/// Returns the allow network list.
///
/// # Errors
///
/// Returns an error if the allow network database could not be retrieved.
pub fn get_allow_networks(db: &Store) -> Result<database::HostNetworkGroup> {
    use review_database::Iterable;

    let map = db.allow_network_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    for res in map.iter(Direction::Forward, None) {
        let allow_network = res?;
        hosts.extend(allow_network.networks.hosts());
        networks.extend(allow_network.networks.networks());
        ip_ranges.extend(allow_network.networks.ip_ranges().to_vec());
    }
    Ok(database::HostNetworkGroup::new(hosts, networks, ip_ranges))
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_allow_network() {
        let schema = TestSchema::new().await;

        let res = schema.execute(r#"{allowNetworkList{totalCount}}"#).await;
        assert_eq!(
            res.data.to_string(),
            r#"{allowNetworkList: {totalCount: 0}}"#
        );

        let res = schema
            .execute(
                r#"
                mutation {
                    insertAllowNetwork(
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
        assert_eq!(res.data.to_string(), r#"{insertAllowNetwork: "0"}"#);

        let res = schema
            .execute(
                r#"
                mutation {
                    updateAllowNetwork(
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
        assert_eq!(res.data.to_string(), r#"{updateAllowNetwork: "0"}"#);

        let res = schema
            .execute(
                r#"
                query {
                    allowNetworkList(first: 10) {
                        nodes {
                            name
                        }
                    }
                }"#,
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
