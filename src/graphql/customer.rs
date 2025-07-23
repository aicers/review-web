use std::convert::{TryFrom, TryInto};

use anyhow::Context as AnyhowContext;
use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, SimpleObject,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{self as database, Direction, Iterable, Store};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::node::SEMI_SUPERVISED_AGENT;
use super::{BoxedAgentManager, Role, RoleGuard, agent_keys_by_customer_id};
use crate::graphql::query_with_constraints;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworksTargetAgentKeysPair {
    networks: database::HostNetworkGroup,
    target_agent_keys: Vec<String>,
}

impl NetworksTargetAgentKeysPair {
    #[must_use]
    pub fn new(
        networks: database::HostNetworkGroup,
        agent_keys: Vec<String>,
        target_agent: &str,
    ) -> Self {
        Self {
            networks,
            target_agent_keys: agent_keys
                .into_iter()
                .filter(|s| s.starts_with(target_agent))
                .collect(),
        }
    }

    #[must_use]
    pub fn target_agent_keys(&self) -> &[String] {
        &self.target_agent_keys
    }

    #[must_use]
    pub fn networks(&self) -> &database::HostNetworkGroup {
        &self.networks
    }
}

#[derive(Default)]
pub(super) struct CustomerQuery;

#[Object]
impl CustomerQuery {
    /// A list of customers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn customer_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Customer, CustomerTotalCount, EmptyFields>> {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// A customer for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn customer(&self, ctx: &Context<'_>, id: ID) -> Result<Customer> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such customer".into());
        };
        Ok(Customer { inner })
    }
}

#[derive(Default)]
pub(super) struct CustomerMutation;

#[Object]
impl CustomerMutation {
    /// Inserts a new customer, returning the ID of the new customer.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn insert_customer(
        &self,
        ctx: &Context<'_>,
        name: String,
        description: String,
        networks: Vec<CustomerNetworkInput>,
    ) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut networks: Vec<review_database::CustomerNetwork> = networks
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>>>()?;
        networks.sort_by(|a, b| a.name.cmp(&b.name));
        let original_count = networks.len();
        networks.dedup_by(|a, b| a.name == b.name);
        if networks.len() != original_count {
            return Err("duplicate network name".into());
        }
        let value = database::Customer {
            id: u32::MAX,
            name,
            description,
            networks,
            creation_time: Utc::now(),
        };
        let id = map.put(value)?;
        Ok(ID(id.to_string()))
    }

    /// Removes customers, returning the customer names that no longer exist.
    ///
    /// Returns an error if any accounts or nodes still reference the customers to be removed.
    /// On error, no customers will be removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn remove_customers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let network_map = store.network_map();

        // Parse customer IDs before validation to catch invalid IDs early
        let customer_ids = ids
            .iter()
            .map(|id| id.as_str().parse::<u32>().map_err(|_| "invalid ID"))
            .collect::<Result<Vec<u32>, _>>()?;

        // Validate that no accounts or nodes reference these customers
        validate_customer_removal(&store, &customer_ids)?;

        let customer_id_hash = agent_keys_by_customer_id(&store)?;
        let mut removed_customer_networks = Vec::new();
        let mut removed = Vec::<String>::with_capacity(customer_ids.len());
        for i in customer_ids {
            let key = map.remove(i)?;
            network_map.remove_customer(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            removed.push(name);

            if let Some(agent_keys) = customer_id_hash.get(&i) {
                let network_list = NetworksTargetAgentKeysPair::new(
                    database::HostNetworkGroup::new(vec![], vec![], vec![]),
                    agent_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                );
                removed_customer_networks.push(network_list);
            }
        }

        if !removed_customer_networks.is_empty() {
            if let Err(e) =
                send_agent_specific_customer_networks(ctx, &removed_customer_networks).await
            {
                error!("failed to broadcast internal networks. {e:?}");
            }
        }

        Ok(removed)
    }

    /// Updates the given customer.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_customer(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: CustomerUpdateInput,
        new: CustomerUpdateInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let old = old.try_into()?;
        let new = new.try_into()?;

        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.customer_map();
        map.update(i, &old, &new)?;

        if let Some(new_networks) = new.networks {
            let customer_id_hash = agent_keys_by_customer_id(&store)?;
            if let Some(agent_keys) = customer_id_hash.get(&i) {
                let (hosts, networks, ip_ranges) = new_networks.iter().fold(
                    (vec![], vec![], vec![]),
                    |(mut hosts, mut networks, mut ip_ranges), nn| {
                        hosts.extend(nn.network_group.hosts());
                        networks.extend(nn.network_group.networks());
                        ip_ranges.extend(nn.network_group.ip_ranges().to_vec());
                        (hosts, networks, ip_ranges)
                    },
                );

                let network_list = NetworksTargetAgentKeysPair::new(
                    database::HostNetworkGroup::new(hosts, networks, ip_ranges),
                    agent_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                );

                if let Err(e) = send_agent_specific_customer_networks(ctx, &[network_list]).await {
                    error!("failed to broadcast internal networks. {e:?}");
                }
            }
        }

        Ok(id)
    }
}

/// Validates that customers can be safely removed by checking for references in accounts and nodes.
///
/// # Errors
///
/// Returns an error if any accounts or nodes still reference the customers to be removed.
fn validate_customer_removal(store: &Store, customer_ids: &[u32]) -> Result<()> {
    let account_map = store.account_map();
    let node_map = store.node_map();

    // Check for account references
    for entry in account_map.iter(Direction::Forward, None) {
        let account = entry.map_err(|_| "failed to iterate accounts")?;
        if let Some(account_customer_ids) = &account.customer_ids {
            for customer_id in customer_ids {
                if account_customer_ids.contains(customer_id) {
                    return Err(format!(
                        "Cannot remove customer {}: still referenced by account {}",
                        customer_id, account.username
                    )
                    .into());
                }
            }
        }
    }

    // Check for node references
    for entry in node_map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "failed to iterate nodes")?;
        for customer_id in customer_ids {
            // Check current profile
            if let Some(profile) = &node.profile {
                if profile.customer_id == *customer_id {
                    return Err(format!(
                        "Cannot remove customer {}: still referenced by node {}",
                        customer_id, node.name
                    )
                    .into());
                }
            }
            // Check draft profile
            if let Some(profile_draft) = &node.profile_draft {
                if profile_draft.customer_id == *customer_id {
                    return Err(format!(
                        "Cannot remove customer {}: still referenced by node {} (draft profile)",
                        customer_id, node.name
                    )
                    .into());
                }
            }
        }
    }

    Ok(())
}

pub(super) struct Customer {
    inner: database::Customer,
}

#[Object]
impl Customer {
    /// The ID of the customer.
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    /// The name of the customer.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The description of the customer.
    async fn description(&self) -> &str {
        &self.inner.description
    }

    /// The networks this customer owns.
    async fn networks(&self) -> Vec<CustomerNetwork> {
        self.inner.networks.iter().map(Into::into).collect()
    }

    /// The time when this customer was created.
    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }
}

impl From<database::Customer> for Customer {
    fn from(inner: database::Customer) -> Self {
        Self { inner }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
struct CustomerNetworkInput {
    pub name: String,
    pub description: String,
    pub network_type: NetworkType,
    pub network_group: HostNetworkGroupInput,
}

impl TryFrom<CustomerNetworkInput> for database::CustomerNetwork {
    type Error = async_graphql::Error;

    fn try_from(input: CustomerNetworkInput) -> Result<Self, Self::Error> {
        Ok(database::CustomerNetwork {
            name: input.name,
            description: input.description,
            network_type: input.network_type.into(),
            network_group: input.network_group.try_into()?,
        })
    }
}

struct CustomerNetwork<'a> {
    inner: &'a database::CustomerNetwork,
}

#[Object]
impl CustomerNetwork<'_> {
    /// The name of the network.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The description of the network.
    async fn description(&self) -> &str {
        &self.inner.description
    }

    /// The type of the network.
    async fn network_type(&self) -> NetworkType {
        self.inner.network_type.into()
    }

    /// The network group of the network.
    async fn network_group(&self) -> HostNetworkGroup {
        (&self.inner.network_group).into()
    }
}

impl<'a> From<&'a database::CustomerNetwork> for CustomerNetwork<'a> {
    fn from(inner: &'a database::CustomerNetwork) -> Self {
        Self { inner }
    }
}

#[derive(Clone, InputObject)]
pub struct HostNetworkGroupInput {
    pub hosts: Vec<String>,
    pub networks: Vec<String>,
    pub ranges: Vec<IpRangeInput>,
}

impl PartialEq<database::HostNetworkGroup> for HostNetworkGroupInput {
    fn eq(&self, rhs: &database::HostNetworkGroup) -> bool {
        if self.hosts.len() != rhs.hosts().len()
            || self.networks.len() != rhs.networks().len()
            || self.ranges.len() != rhs.ip_ranges().len()
        {
            return false;
        }

        for h in &self.hosts {
            let Ok(addr) = h.parse() else {
                return false;
            };
            if !rhs.contains_host(addr) {
                return false;
            }
        }
        for n in &self.networks {
            let Ok(net) = n.parse() else {
                return false;
            };
            if !rhs.contains_network(&net) {
                return false;
            }
        }
        for r in &self.ranges {
            let Ok(start) = r.start.parse() else {
                return false;
            };
            let Ok(end) = r.end.parse() else {
                return false;
            };
            if !rhs.contains_ip_range(&(start..=end)) {
                return false;
            }
        }
        true
    }
}

impl TryFrom<HostNetworkGroupInput> for database::HostNetworkGroup {
    type Error = anyhow::Error;

    fn try_from(input: HostNetworkGroupInput) -> Result<Self, Self::Error> {
        (&input).try_into()
    }
}

impl TryFrom<&HostNetworkGroupInput> for database::HostNetworkGroup {
    type Error = anyhow::Error;

    fn try_from(input: &HostNetworkGroupInput) -> Result<Self, Self::Error> {
        let mut hosts = Vec::with_capacity(input.hosts.len());
        for h in &input.hosts {
            hosts.push(h.parse().context("invalid host address")?);
        }

        let mut networks = Vec::with_capacity(input.networks.len());
        for n in &input.networks {
            networks.push(n.parse().context("invalid network address")?);
        }

        let mut ip_ranges = Vec::with_capacity(input.ranges.len());
        for r in &input.ranges {
            let start = r.start.parse().context("invalid start address")?;
            let end = r.end.parse().context("invalid end address")?;
            ip_ranges.push(start..=end);
        }

        Ok(Self::new(hosts, networks, ip_ranges))
    }
}

#[derive(Clone, InputObject)]
pub struct IpRangeInput {
    pub start: String,
    pub end: String,
}

#[derive(InputObject)]
struct CustomerUpdateInput {
    name: Option<String>,
    description: Option<String>,
    networks: Option<Vec<CustomerNetworkInput>>,
}

impl TryFrom<CustomerUpdateInput> for review_database::CustomerUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: CustomerUpdateInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: input.name,
            description: input.description,
            networks: input
                .networks
                .map(|n| {
                    n.into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
        })
    }
}

pub(super) struct HostNetworkGroup<'a> {
    inner: &'a database::HostNetworkGroup,
}

#[Object]
impl HostNetworkGroup<'_> {
    #[graphql(name = "hosts")]
    async fn hosts_as_strings(&self) -> Vec<String> {
        self.inner.hosts().iter().map(ToString::to_string).collect()
    }

    #[graphql(name = "networks")]
    async fn networks_as_strings(&self) -> Vec<String> {
        self.inner
            .networks()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    async fn ranges(&self) -> Vec<IpRange> {
        self.inner
            .ip_ranges()
            .iter()
            .map(|r| IpRange {
                start: r.start().to_string(),
                end: r.end().to_string(),
            })
            .collect()
    }
}

impl<'a> From<&'a database::HostNetworkGroup> for HostNetworkGroup<'a> {
    fn from(inner: &'a database::HostNetworkGroup) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
struct IpRange {
    start: String,
    end: String,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::NetworkType")]
enum NetworkType {
    Intranet,
    Extranet,
    Gateway,
}

struct CustomerTotalCount;

#[Object]
impl CustomerTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        Ok(store.customer_map().count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Customer, CustomerTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.customer_map();
    super::load_edges(&map, after, before, first, last, CustomerTotalCount)
}

/// Returns the customer network list.
///
/// # Errors
///
/// Returns an error if the customer database could not be retrieved.
pub fn get_customer_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    let map = db.customer_map();
    let mut hosts = vec![];
    let mut networks = vec![];
    let mut ip_ranges = vec![];
    if let Some(customer) = map.get_by_id(customer_id)? {
        customer.networks.iter().for_each(|net| {
            hosts.extend(net.network_group.hosts());
            networks.extend(net.network_group.networks());
            ip_ranges.extend(net.network_group.ip_ranges().to_vec());
        });
    }
    Ok(database::HostNetworkGroup::new(hosts, networks, ip_ranges))
}

/// Returns a list of agents that received the internal networks.
///
/// # Errors
///
/// Returns an error if the broadcast fail.
pub async fn send_agent_specific_customer_networks(
    ctx: &Context<'_>,
    networks: &[NetworksTargetAgentKeysPair],
) -> Result<Vec<String>> {
    let agent_manager = ctx.data::<BoxedAgentManager>()?;
    agent_manager
        .send_agent_specific_internal_networks(networks)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn check_customer_ordering() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r"{customerList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{customerList: {edges: [], totalCount: 0}}"
        );

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t1", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t2", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t3", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "2"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t4", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "3"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t5", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "4"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t6", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "5"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t7", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "6"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t8", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "7"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t9", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "8"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertCustomer(name: "t10", description: "", networks: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "9"}"#);

        let res = schema
            .execute(r"{customerList(last: 10){edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "t1"}}, {node: {name: "t10"}}, {node: {name: "t2"}}, {node: {name: "t3"}}, {node: {name: "t4"}}, {node: {name: "t5"}}, {node: {name: "t6"}}, {node: {name: "t7"}}, {node: {name: "t8"}}, {node: {name: "t9"}}], totalCount: 10}}"#
        );

        let res = schema
            .execute(r#"{customerList(last: 10, before: "WzExNiw1Nl0"){edges{node{name}}totalCount,pageInfo{startCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "t1"}}, {node: {name: "t10"}}, {node: {name: "t2"}}, {node: {name: "t3"}}, {node: {name: "t4"}}, {node: {name: "t5"}}, {node: {name: "t6"}}, {node: {name: "t7"}}], totalCount: 10, pageInfo: {startCursor: "WzExNiw0OV0"}}}"#
        );

        let res = schema
            .execute(
                r#"{customerList(last: 10, after: "dDc="){edges{node{name}}totalCount,pageInfo{startCursor}}}"#,
            )
            .await;
        assert!(res.is_err());

        let res = schema
            .execute(
                r#"{customerList(first:10 after:"WzExNiw1NV0" ){edges{node{name}}totalCount,pageInfo{endCursor}}}"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "t8"}}, {node: {name: "t9"}}], totalCount: 10, pageInfo: {endCursor: "WzExNiw1N10"}}}"#
        );

        let res = schema
        .execute(
            r#"{customerList(first:10 before:"WzExNiw1NV0" ){edges{node{name}}totalCount,pageInfo{endCursor}}}"#,
        )
        .await;
        assert!(res.is_err());

        let res = schema
            .execute(r"{customerList(first:10){edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "t1"}}, {node: {name: "t10"}}, {node: {name: "t2"}}, {node: {name: "t3"}}, {node: {name: "t4"}}, {node: {name: "t5"}}, {node: {name: "t6"}}, {node: {name: "t7"}}, {node: {name: "t8"}}, {node: {name: "t9"}}], totalCount: 10}}"#
        );

        let res = schema
            .execute(
                r#"mutation { removeCustomers(ids: ["0","1","2","3","4","5","6","7","8","9"]) }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeCustomers: ["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"]}"#
        );

        let res = schema
            .execute(r"{customerList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{customerList: {edges: [], totalCount: 0}}"
        );
    }

    #[tokio::test]
    async fn remove_customers() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r"{customerList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{customerList: {edges: [], totalCount: 0}}"
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertCustomer(name: "c1", description: "", networks: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute(r"{customerList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "c1"}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                insertNetwork(name: "n1", description: "", networks: {
                    hosts: [], networks: [], ranges: []
                }, customerIds: [0], tagIds: [])
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema
            .execute(r#"mutation { removeCustomers(ids: ["0"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeCustomers: ["c1"]}"#);

        let res = schema
            .execute(r"{networkList{edges{node{customerList{name}}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r"{networkList: {edges: [{node: {customerList: []}}], totalCount: 1}}"
        );
    }

    #[tokio::test]
    async fn remove_customers_with_account_reference() {
        let schema = TestSchema::new().await;

        // Create a customer
        let res = schema
            .execute(
                r#"mutation {
                    insertCustomer(name: "test_customer", description: "", networks: [])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        // Create an account that references this customer
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "test_user",
                        password: "test_password",
                        role: "SECURITY_MONITOR",
                        name: "Test User",
                        department: "IT",
                        maxParallelSessions: 1,
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());

        // Try to remove the customer - should fail
        let res = schema
            .execute(r#"mutation { removeCustomers(ids: ["0"]) }"#)
            .await;
        assert!(!res.errors.is_empty());
        assert!(
            res.errors[0]
                .message
                .contains("still referenced by account")
        );

        // Verify customer is still there
        let res = schema
            .execute(r"{customerList{edges{node{name}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{customerList: {edges: [{node: {name: "test_customer"}}], totalCount: 1}}"#
        );
    }
}
