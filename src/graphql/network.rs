use super::{
    customer::{Customer, HostNetworkGroup, HostNetworkGroupInput},
    Role, RoleGuard,
};
use anyhow::Context as AnyhowContext;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, InputObject, Object, Result,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use review_database::{
    self as database, types::FromKeyValue, Indexed, IndexedMapIterator, IndexedMapUpdate,
    IndexedMultimap, IterableMap,
};
use std::{convert::TryInto, mem::size_of};

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
    ) -> Result<Connection<String, Network, NetworkTotalCount, EmptyFields>> {
        query(
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

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        let Some((key, value)) = map.get_kv_by_id(i)? else {
            return Err("no such network".into());
        };
        Ok(Network {
            inner: database::Network::from_key_value(key.as_ref(), value.as_ref())?,
        })
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
        customer_ids: Vec<u32>,
        mut tag_ids: Vec<u32>,
    ) -> Result<ID> {
        tag_ids.sort_unstable();
        tag_ids.dedup();

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        let mut key = Vec::with_capacity(name.len());
        key.extend_from_slice(name.as_bytes());
        key.resize(name.len() + size_of::<u32>(), 0);
        let entry = database::NetworkEntry {
            key,
            value: database::NetworkEntryValue {
                description,
                networks: networks
                    .try_into()
                    .map_err(|_| "invalid IP or network address")?,
                customer_ids,
                tag_ids,
                creation_time: Utc::now(),
            },
        };
        let id = map.insert(entry)?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let mut key = map.remove(i)?;

            let len = key.len();
            let name = if len > size_of::<u32>() {
                key.truncate(len - size_of::<u32>());
                match String::from_utf8(key) {
                    Ok(key) => key,
                    Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
                }
            } else {
                String::from_utf8_lossy(&key).into()
            };
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

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        map.update(i, &old, &new)?;
        Ok(id)
    }
}

#[derive(InputObject)]
struct NetworkUpdateInput {
    name: Option<String>,
    description: Option<String>,
    networks: Option<HostNetworkGroupInput>,
    customer_ids: Option<Vec<u32>>,
    tag_ids: Option<Vec<u32>>,
}

impl IndexedMapUpdate for NetworkUpdateInput {
    type Entry = database::NetworkEntry;

    fn key(&self) -> Option<&[u8]> {
        self.name.as_deref().map(str::as_bytes)
    }

    fn apply(&self, mut entry: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(name) = self.name.as_deref() {
            let len = entry.key.len();
            let mut index = [0_u8; size_of::<u32>()];
            index.copy_from_slice(&entry.key[len - size_of::<u32>()..len]);
            entry.key.clear();
            entry.key.reserve(name.len() + size_of::<u32>());
            entry.key.extend(name.as_bytes());
            entry.key.extend(index);
        }
        if let Some(description) = self.description.as_deref() {
            entry.value.description.clear();
            entry.value.description.push_str(description);
        }
        if let Some(ref networks) = self.networks {
            entry.value.networks = networks.clone().try_into().context("invalid network")?;
        }
        if let Some(customer_ids) = self.customer_ids.as_deref() {
            entry.value.customer_ids.clear();
            entry.value.customer_ids.extend(customer_ids.iter());
        }
        if let Some(tag_ids) = self.tag_ids.as_deref() {
            entry.value.tag_ids.clear();
            entry.value.tag_ids.extend(tag_ids.iter());
        }
        Ok(entry)
    }

    fn verify(&self, entry: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref() {
            if v.len() + size_of::<u32>() != entry.key.len() {
                return false;
            }
            if v.as_bytes() != &entry.key[..v.len()] {
                return false;
            }
        }
        if let Some(v) = self.description.as_deref() {
            if v != entry.value.description {
                return false;
            }
        }
        if let Some(ref v) = self.networks {
            if *v != entry.value.networks {
                return false;
            }
        }
        if let Some(v) = self.customer_ids.as_deref() {
            if v != entry.value.customer_ids {
                return false;
            }
        }
        if let Some(v) = self.tag_ids.as_deref() {
            if v != entry.value.tag_ids {
                return false;
            }
        }
        true
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

    async fn networks(&self) -> HostNetworkGroup {
        (&self.inner.networks).into()
    }

    #[graphql(name = "customerList")]
    async fn customer_ids(&self, ctx: &Context<'_>) -> Result<Vec<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = Vec::new();
        let codec = bincode::DefaultOptions::new();
        for &id in &self.inner.customer_ids {
            #[allow(clippy::cast_sign_loss)] // u32 stored as i32 in database
            let Some(value) = map.get_by_id(id)?
            else {
                continue;
            };
            let customer = codec
                .deserialize::<database::Customer>(value.as_ref())
                .map_err(|_| "invalid value in database")?;
            customers.push(customer.into());
        }
        Ok(customers)
    }

    async fn tag_ids(&self) -> &[u32] {
        &self.inner.tag_ids
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

struct NetworkTotalCount;

#[Object]
impl NetworkTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;

        Ok(store.network_map().count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Network, NetworkTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.network_map();
    super::load::<
        '_,
        IndexedMultimap,
        IndexedMapIterator,
        Network,
        database::Network,
        NetworkTotalCount,
    >(&map, after, before, first, last, NetworkTotalCount)
}

pub(super) async fn remove_tag(ctx: &Context<'_>, tag_id: u32) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.network_map();
    let mut updates = Vec::new();
    for (key, value) in map.iter_forward()? {
        let network = database::Network::from_key_value(key.as_ref(), value.as_ref())
            .context("invalid network entry in database")?;
        if !network.has_tag(tag_id) {
            continue;
        }

        let old_tag_ids = network.tag_ids;
        let mut new_tag_ids = old_tag_ids.clone();
        new_tag_ids.retain(|&id| id != tag_id);
        updates.push((network.id, old_tag_ids, new_tag_ids));
    }

    for (id, old_tag_ids, new_tag_ids) in updates {
        let old = NetworkUpdateInput {
            name: None,
            description: None,
            networks: None,
            customer_ids: None,
            tag_ids: Some(old_tag_ids),
        };
        let new = NetworkUpdateInput {
            name: None,
            description: None,
            networks: None,
            customer_ids: None,
            tag_ids: Some(new_tag_ids),
        };
        map.update(id, &old, &new)
            .map_err(|e| format!("failed to update network: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn remove_networks() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"{networkList{edges{node{name}}totalCount}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [],totalCount: 0}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute(r#"{networkList{edges{node{name}}totalCount}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [{node: {name: "n1"}}],totalCount: 1}}"#
        );

        let res = schema
            .execute(r#"mutation { removeNetworks(ids: ["0"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworks: ["n1"]}"#);

        let res = schema
            .execute(r#"{networkList{edges{node{name}}totalCount}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{networkList: {edges: [],totalCount: 0}}"#
        );
    }

    #[tokio::test]
    async fn update_network() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{networkList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{networkList: {totalCount: 0}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n0", description: "", networks: {
                        hosts: ["1.1.1.1"], networks: [], ranges: []
                    }, customerIds: [], tagIds: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute(
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
}
