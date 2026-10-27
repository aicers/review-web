use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, StringNumber,
    connection::{Connection, Edge, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{Iterable, Store, UniqueKey, event::Direction};
use serde::{Deserialize, Serialize};

use super::{IpAddress, Role, RoleGuard, SharedAgentManager};
use crate::graphql::customer_access::{
    event_sensor_customer_id_map, hostname_customer_id_map, is_member, users_customers,
};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct SamplingPolicyQuery;

#[derive(Default)]
pub(super) struct SamplingPolicyMutation;

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
#[derive(Default)]
pub enum Interval {
    FiveMinutes = 0,
    TenMinutes = 1,
    #[default]
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

impl From<review_database::SamplingInterval> for Interval {
    fn from(input: review_database::SamplingInterval) -> Self {
        match input {
            review_database::SamplingInterval::FiveMinutes => Self::FiveMinutes,
            review_database::SamplingInterval::TenMinutes => Self::TenMinutes,
            review_database::SamplingInterval::FifteenMinutes => Self::FifteenMinutes,
            review_database::SamplingInterval::ThirtyMinutes => Self::ThirtyMinutes,
            review_database::SamplingInterval::OneHour => Self::OneHour,
        }
    }
}
impl From<Interval> for review_database::SamplingInterval {
    fn from(input: Interval) -> Self {
        match input {
            Interval::FiveMinutes => Self::FiveMinutes,
            Interval::TenMinutes => Self::TenMinutes,
            Interval::FifteenMinutes => Self::FifteenMinutes,
            Interval::ThirtyMinutes => Self::ThirtyMinutes,
            Interval::OneHour => Self::OneHour,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
#[derive(Default)]
pub enum Period {
    SixHours = 0,
    TwelveHours = 1,
    #[default]
    OneDay = 2,
}

impl From<review_database::SamplingPeriod> for Period {
    fn from(input: review_database::SamplingPeriod) -> Self {
        match input {
            review_database::SamplingPeriod::SixHours => Self::SixHours,
            review_database::SamplingPeriod::TwelveHours => Self::TwelveHours,
            review_database::SamplingPeriod::OneDay => Self::OneDay,
        }
    }
}

impl From<Period> for review_database::SamplingPeriod {
    fn from(input: Period) -> Self {
        match input {
            Period::SixHours => Self::SixHours,
            Period::TwelveHours => Self::TwelveHours,
            Period::OneDay => Self::OneDay,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
#[derive(Default)]
pub enum Kind {
    #[default]
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

impl From<review_database::SamplingKind> for Kind {
    fn from(input: review_database::SamplingKind) -> Self {
        match input {
            review_database::SamplingKind::Conn => Self::Conn,
            review_database::SamplingKind::Dns => Self::Dns,
            review_database::SamplingKind::Http => Self::Http,
            review_database::SamplingKind::Rdp => Self::Rdp,
        }
    }
}

impl From<Kind> for review_database::SamplingKind {
    fn from(input: Kind) -> Self {
        match input {
            Kind::Conn => Self::Conn,
            Kind::Dns => Self::Dns,
            Kind::Http => Self::Http,
            Kind::Rdp => Self::Rdp,
        }
    }
}
pub(super) struct SamplingPolicy {
    inner: review_database::SamplingPolicy,
}

#[Object]
impl SamplingPolicy {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn kind(&self) -> Kind {
        self.inner.kind.into()
    }

    async fn interval(&self) -> Interval {
        self.inner.interval.into()
    }

    async fn period(&self) -> Period {
        self.inner.period.into()
    }

    async fn offset(&self) -> i32 {
        self.inner.offset
    }

    async fn src_ip(&self) -> Option<String> {
        self.inner.src_ip.as_ref().map(ToString::to_string)
    }

    async fn dst_ip(&self) -> Option<String> {
        self.inner.dst_ip.as_ref().map(ToString::to_string)
    }

    async fn node(&self) -> Option<String> {
        self.inner.node.clone()
    }

    async fn column(&self) -> Option<StringNumber<u32>> {
        self.inner.column.map(StringNumber)
    }

    async fn immutable(&self) -> bool {
        self.inner.immutable
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }
}

impl From<review_database::SamplingPolicy> for SamplingPolicy {
    fn from(inner: review_database::SamplingPolicy) -> Self {
        Self { inner }
    }
}

/// The customer lookups that resolve a sampling policy's `node`.
struct PolicyCustomers {
    sensors: HashMap<String, u32>,
    hostnames: HashMap<String, u32>,
}

impl PolicyCustomers {
    fn load(store: &Store) -> Result<Self> {
        Ok(Self {
            sensors: event_sensor_customer_id_map(store)?,
            hostnames: hostname_customer_id_map(store)?,
        })
    }

    /// Returns the customer of `policy`.
    ///
    /// `node` is resolved as a sensor name, and only failing that as a node
    /// hostname, which is what policies written before sensor names were
    /// required store. A policy without `node` has no customer.
    fn customer_of(&self, policy: &review_database::SamplingPolicy) -> Option<u32> {
        let node = policy.node.as_deref()?;
        self.sensors
            .get(node)
            .or_else(|| self.hostnames.get(node))
            .copied()
    }

    /// Returns whether a caller scoped to `scope` may access `policy`.
    ///
    /// A policy whose customer cannot be resolved is out of every scope.
    fn in_scope(&self, policy: &review_database::SamplingPolicy, scope: &[u32]) -> bool {
        self.customer_of(policy)
            .is_some_and(|customer_id| is_member(Some(scope), customer_id))
    }

    /// Checks that `node` is a sensor name whose customer is in `scope`.
    ///
    /// `None` for `scope` is an unscoped caller, for whom any sensor name
    /// passes.
    fn check_node(&self, node: Option<&str>, scope: Option<&[u32]>) -> Result<()> {
        let Some(node) = node else {
            return Err("node is required".into());
        };
        let Some(&customer_id) = self.sensors.get(node) else {
            return Err(format!("{node:?} is not a sensor name").into());
        };
        if is_member(scope, customer_id) {
            Ok(())
        } else {
            Err("Forbidden".into())
        }
    }
}

struct SamplingPolicyTotalCount;

#[Object]
impl SamplingPolicyTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.sampling_policy_map();

        let Some(scope) = users_cids else {
            return Ok(StringNumber(map.count()?));
        };
        let customers = PolicyCustomers::load(&store)?;
        let mut count = 0;
        for entry in map.iter(Direction::Forward, None) {
            if customers.in_scope(&entry?, &scope) {
                count += 1;
            }
        }
        Ok(StringNumber(count))
    }
}

#[derive(Clone, InputObject)]
pub(super) struct SamplingPolicyInput {
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddress>,
    pub dst_ip: Option<IpAddress>,
    pub node: Option<String>, // sensor name
    pub column: Option<u32>,
    pub immutable: bool,
}

impl TryFrom<SamplingPolicyInput> for review_database::SamplingPolicyUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: SamplingPolicyInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: input.name,
            kind: input.kind.into(),
            interval: input.interval.into(),
            period: input.period.into(),
            offset: input.offset,
            src_ip: input.src_ip.map(|ip| ip.0),
            dst_ip: input.dst_ip.map(|ip| ip.0),
            node: input.node,
            column: input.column,
            immutable: input.immutable,
        })
    }
}

#[Object]
impl SamplingPolicyQuery {
    /// A list of sampling policies.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn sampling_policy_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, SamplingPolicy, SamplingPolicyTotalCount, EmptyFields>,
    > {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// Looks up a sampling policy by the given id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn sampling_policy(&self, ctx: &Context<'_>, id: ID) -> Result<SamplingPolicy> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.sampling_policy_map();
        let Some(policy) = map.get_by_id(i)? else {
            return Err("no such sampling policy".into());
        };
        if let Some(scope) = users_cids
            && !PolicyCustomers::load(&store)?.in_scope(&policy, &scope)
        {
            return Err("Forbidden".into());
        }
        Ok(policy.into())
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, SamplingPolicy, SamplingPolicyTotalCount, EmptyFields>>
{
    let users_cids = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.sampling_policy_map();
    let Some(scope) = users_cids else {
        return super::load_edges(&map, after, before, first, last, SamplingPolicyTotalCount);
    };

    let customers = PolicyCustomers::load(&store)?;
    let (nodes, has_previous, has_next) =
        super::process_load_edges_filtered(&map, after, before, first, last, None, |policy| {
            customers.in_scope(policy, &scope)
        });

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, SamplingPolicyTotalCount);
    let edges = nodes
        .into_iter()
        .map(|node| -> Result<_> {
            let node = node.map_err(|e| {
                tracing::warn!("Failed to load from DB: {}", e);
                async_graphql::Error::new("database error")
            })?;
            let key: Vec<u8> = node.unique_key().to_vec();
            Ok(Edge::new(OpaqueCursor(key), node.into()))
        })
        .collect::<Result<Vec<_>>>()?;
    connection.edges.extend(edges);
    Ok(connection)
}

#[derive(Serialize)]
pub struct Policy {
    pub id: u32,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub node: Option<String>,
    pub column: Option<u32>,
}

impl From<review_database::SamplingPolicy> for Policy {
    fn from(input: review_database::SamplingPolicy) -> Self {
        Self {
            id: input.id,
            kind: input.kind.into(),
            interval: input.interval.into(),
            period: input.period.into(),
            offset: input.offset,
            src_ip: input.src_ip,
            dst_ip: input.dst_ip,
            node: input.node,
            column: input.column,
        }
    }
}

async fn load_immutable(ctx: &Context<'_>) -> Result<Vec<Policy>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.sampling_policy_map();

    let mut rtn: Vec<Policy> = Vec::new();

    for entry in map.iter(Direction::Forward, None) {
        let pol = entry?;
        if pol.immutable {
            rtn.push(pol.into());
        }
    }

    Ok(rtn)
}

/// Returns the sampling policies a Time Series Generator of the given
/// customer pulls.
///
/// A policy is included if and only if it is immutable and its `node` is a
/// sensor name (see `event_sensor_names`) of a node whose applied profile
/// belongs to `customer_id`. The Data Store keys events by sensor name, so
/// that is the only `node` that can produce data:
/// - A mutable policy can still be edited, and a generator keeps the first
///   definition it received for an ID, so pulling one would mix the series
///   of two definitions under one ID.
/// - A policy whose `node` is a node hostname never matches Data Store data.
/// - A policy without `node` has no sensor, which the Data Store refuses.
///
/// Immutable policies whose `node` is not a sensor name are skipped with a
/// warning.
///
/// # Errors
///
/// Returns an error if the sampling policy or node database could not
/// be read.
pub fn get_sampling_policies(db: &Store, customer_id: u32) -> Result<Vec<Policy>> {
    let policy_map = db.sampling_policy_map();
    let sensor_customer = event_sensor_customer_id_map(db)?;

    let mut policies = vec![];
    for res in policy_map.iter(Direction::Forward, None) {
        let policy = res?;
        if !policy.immutable {
            continue;
        }
        match policy.node.as_deref().map(|node| sensor_customer.get(node)) {
            Some(Some(&cid)) => {
                if cid == customer_id {
                    policies.push(policy.into());
                }
            }
            Some(None) => {
                tracing::warn!(
                    "sampling policy {:?} references {:?}, which is not a sensor name; skipping",
                    policy.name,
                    policy.node,
                );
            }
            None => {
                tracing::warn!(
                    "sampling policy {:?} has no sensor name; skipping",
                    policy.name
                );
            }
        }
    }
    Ok(policies)
}

#[Object]
impl SamplingPolicyMutation {
    /// Inserts a new sampling policy, returning its ID.
    ///
    /// `node` must be a sensor name, such as `piglet.sensor.example.com`, and
    /// for a caller scoped to customers, one of a customer in scope.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_sampling_policy(
        &self,
        ctx: &Context<'_>,
        name: String,
        kind: Kind,
        interval: Interval,
        period: Period,
        offset: i32,
        src_ip: Option<IpAddress>,
        dst_ip: Option<IpAddress>,
        node: Option<String>,
        column: Option<u32>,
        immutable: bool,
    ) -> Result<ID> {
        {
            let users_cids = users_customers(ctx)?;
            let store = crate::graphql::get_store(ctx)?;
            PolicyCustomers::load(&store)?.check_node(node.as_deref(), users_cids.as_deref())?;
        }

        let pol = review_database::SamplingPolicy {
            id: u32::MAX,
            name,
            kind: kind.into(),
            interval: interval.into(),
            period: period.into(),
            offset,
            src_ip: src_ip.map(|ip| ip.0),
            dst_ip: dst_ip.map(|ip| ip.0),
            node,
            column,
            immutable,
            creation_time: chrono::Utc::now(),
        };

        let id = {
            let store = crate::graphql::get_store(ctx)?;
            let map = store.sampling_policy_map();
            map.put(pol.clone())?
        };

        if immutable {
            let agents = ctx.data::<SharedAgentManager>()?;
            let policies = load_immutable(ctx).await?;
            if let Err(e) = agents.broadcast_crusher_sampling_policy(&policies).await {
                // Change policy to mutable so that user can retry
                let old: review_database::SamplingPolicyUpdate = pol.into();
                let mut new = old.clone();
                new.immutable = false;
                let store = crate::graphql::get_store(ctx)?;
                let mut map = store.sampling_policy_map();
                map.update(id, &old, &new)?;
                return Err(e.into());
            }
        }

        Ok(ID(id.to_string()))
    }

    /// Removes sampling policies, returning the IDs that no longer exist.
    ///
    /// Every ID is checked before any policy is removed, so a refused ID
    /// leaves every policy in place. A repeated ID is removed once.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_sampling_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let mut ids = ids
            .iter()
            .map(|id| id.as_str().parse::<u32>().map_err(|_| "invalid ID".into()))
            .collect::<Result<Vec<_>>>()?;
        // A repeated ID would pass every check and then fail its second
        // removal, after the first had already taken effect.
        let mut seen = HashSet::new();
        ids.retain(|&i| seen.insert(i));

        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.sampling_policy_map();
        let customers = users_cids
            .is_some()
            .then(|| PolicyCustomers::load(&store))
            .transpose()?;
        for &i in &ids {
            let Some(policy) = map.get_by_id(i)? else {
                return Err("no such sampling policy".into());
            };
            if let (Some(scope), Some(customers)) = (users_cids.as_deref(), customers.as_ref())
                && !customers.in_scope(&policy, scope)
            {
                return Err("Forbidden".into());
            }
        }

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for i in ids {
            let key = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            removed.push(name);
        }

        Ok(removed)
    }

    /// Updates an existing sampling policy.
    ///
    /// The new `node` must be a sensor name. A caller scoped to customers may
    /// update only a policy of a customer in scope, and only to a sensor name
    /// of a customer in scope.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_sampling_policy(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: SamplingPolicyInput,
        new: SamplingPolicyInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        if old.immutable {
            return Err("immutable set by user".into());
        }

        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.sampling_policy_map();
        let customers = PolicyCustomers::load(&store)?;
        if let Some(scope) = users_cids.as_deref() {
            let Some(stored) = map.get_by_id(i)? else {
                return Err("no such sampling policy".into());
            };
            if !customers.in_scope(&stored, scope) {
                return Err("Forbidden".into());
            }
        }
        customers.check_node(new.node.as_deref(), users_cids.as_deref())?;

        let old = old.try_into()?;
        let new = new.try_into()?;
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use chrono::Utc;
    use review_database::{Agent, AgentKind, AgentStatus, Lifecycle, Role, Store};
    use serde_json::json;

    use crate::graphql::TestSchema;

    const SENSOR_A: &str = "piglet.a.example.com";
    const SENSOR_B: &str = "piglet.b.example.com";

    fn sensor_agent() -> Agent {
        Agent {
            node_id: u32::MAX,
            key: "001.piglet".to_string(),
            kind: AgentKind::Sensor,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance: None,
        }
    }

    /// Inserts a node with an applied profile, carrying a Sensor agent when
    /// `with_sensor` is set, so that it emits `piglet.<hostname>`.
    fn insert_node(store: &Store, name: &str, hostname: &str, customer_id: u32, with_sensor: bool) {
        let node = review_database::Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents: if with_sensor {
                vec![sensor_agent()]
            } else {
                vec![]
            },
            external_services: vec![],
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node");
    }

    fn insert_policy(store: &Store, name: &str, node: Option<&str>, immutable: bool) -> u32 {
        let policy = review_database::SamplingPolicy {
            id: u32::MAX,
            name: name.to_string(),
            kind: review_database::SamplingKind::Conn,
            interval: review_database::SamplingInterval::FifteenMinutes,
            period: review_database::SamplingPeriod::OneDay,
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: node.map(ToString::to_string),
            column: None,
            immutable,
            creation_time: Utc::now(),
        };
        store
            .sampling_policy_map()
            .put(policy)
            .expect("insert policy")
    }

    fn insert_mutation(name: &str, node: Option<&str>) -> String {
        let node = node.map_or_else(|| "null".to_string(), |node| format!("{node:?}"));
        format!(
            r#"mutation {{
                insertSamplingPolicy(
                    name: "{name}",
                    kind: CONN,
                    interval: FIFTEEN_MINUTES,
                    period: ONE_DAY,
                    offset: 0,
                    node: {node},
                    immutable: false
                )
            }}"#
        )
    }

    fn policy_input(name: &str, node: Option<&str>) -> String {
        let node = node.map_or_else(|| "null".to_string(), |node| format!("{node:?}"));
        format!(
            r#"{{
                name: "{name}",
                kind: CONN,
                interval: FIFTEEN_MINUTES,
                period: ONE_DAY,
                offset: 0,
                node: {node},
                immutable: false
            }}"#
        )
    }

    fn update_mutation(id: u32, old: (&str, Option<&str>), new: (&str, Option<&str>)) -> String {
        format!(
            r#"mutation {{
                updateSamplingPolicy(id: "{id}", old: {}, new: {})
            }}"#,
            policy_input(old.0, old.1),
            policy_input(new.0, new.1),
        )
    }

    /// Lists policies, which come in name order.
    const LIST_QUERY: &str = r"{
        samplingPolicyList(first: 10) {
            totalCount
            nodes { name }
        }
    }";

    fn listed_names(res: async_graphql::Response) -> (Vec<String>, String) {
        assert!(res.errors.is_empty(), "list: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let list = &data["samplingPolicyList"];
        let names = list["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["name"].as_str().unwrap().to_string())
            .collect();
        (names, list["totalCount"].as_str().unwrap().to_string())
    }

    fn error_message(res: &async_graphql::Response) -> &str {
        &res.errors.first().expect("an error").message
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_sampling_policy() {
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "sensor", "sensor.example.com", 0, true);
        insert_node(&schema.store(), "manager", "manager.example.com", 0, true);

        let res = schema
            .execute_as_system_admin(r"{samplingPolicyList{totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{samplingPolicyList: {totalCount: "0"}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertSamplingPolicy(
                        name: "Policy 1",
                        kind: CONN,
                        interval: FIFTEEN_MINUTES,
                        period: ONE_DAY,
                        offset: 0,
                        node: "piglet.sensor.example.com",
                        immutable: false,
                        srcIp: "127.0.0.1",
                        dstIp: "127.0.0.2"
                    )
                }
            "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertSamplingPolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertSamplingPolicy(
                        name: "Policy 2",
                        kind: CONN,
                        interval: FIFTEEN_MINUTES,
                        period: ONE_DAY,
                        offset: 0,
                        node: "piglet.sensor.example.com",
                        immutable: false,
                        srcIp: "127.0.0.1",
                        dstIp: "127.0.0.x"
                    )
                }
            "#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message.clone(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x".to_string()
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateSamplingPolicy(
                        id: "0",
                        old: {
                            name: "Policy 1",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            node: "piglet.sensor.example.com",
                            immutable: false,
                            srcIp: "127.0.0.1",
                            dstIp: "127.0.0.2"
                        },
                        new:{
                            name: "Policy 2",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            node: "piglet.manager.example.com",
                            immutable: true,
                            srcIp: "127.0.0.1",
                            dstIp: "127.0.0.2"
                        }
                      )
                }
            "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateSamplingPolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r"query {
                    samplingPolicyList(first: 10) {
                        nodes {
                            name
                            kind
                            interval
                            period
                            offset
                            node
                            immutable
                            srcIp
                            dstIp
                        }
                    }
                }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "samplingPolicyList": {
                    "nodes": [{
                        "name": "Policy 2",
                        "kind": "CONN",
                        "interval": "FIFTEEN_MINUTES",
                        "period": "ONE_DAY",
                        "offset": 0,
                        "node": "piglet.manager.example.com",
                        "immutable": true,
                        "srcIp": "127.0.0.1",
                        "dstIp": "127.0.0.2",
                    }]
                }
            })
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateSamplingPolicy(
                        id: "0",
                        old: {
                            name: "Policy 2",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            node: "piglet.manager.example.com",
                            immutable: true,
                            srcIp: "127.0.0.1",
                            dstIp: "127.0.0.2"
                        },
                        new:{
                            name: "Policy 3",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            node: "piglet.manager.example.com",
                            immutable: true,
                            srcIp: "127.0.0.x",
                            dstIp: "127.0.0.2"
                        }
                      )
                }
            "#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message.clone(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x \
            (occurred while parsing \"SamplingPolicyInput\")"
                .to_string()
        );

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeSamplingPolicies(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeSamplingPolicies: ["Policy 2"]}"#
        );
    }

    /// Sets up customer 1 and customer 2, each with a sensor node, and four
    /// policies: one per customer's sensor name, a legacy one whose `node` is
    /// customer 2's hostname, and a node-less one.
    ///
    /// Returns the IDs of customer 1's policy, customer 2's policy, the legacy
    /// policy and the node-less policy.
    fn setup_two_customers(schema: &TestSchema) -> (u32, u32, u32, u32) {
        let store = schema.store();
        insert_node(&store, "node_a", "a.example.com", 1, true);
        insert_node(&store, "node_b", "b.example.com", 2, true);
        (
            insert_policy(&store, "policy_a", Some(SENSOR_A), false),
            insert_policy(&store, "policy_b", Some(SENSOR_B), false),
            insert_policy(&store, "legacy_b", Some("b.example.com"), false),
            insert_policy(&store, "global", None, false),
        )
    }

    #[tokio::test]
    async fn scoped_caller_lists_only_own_policies() {
        let schema = TestSchema::new().await;
        setup_two_customers(&schema);

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, Some(vec![2]))
            .await;
        let (names, total) = listed_names(res);
        assert_eq!(names, ["legacy_b", "policy_b"]);
        assert_eq!(total, "2");

        let res = schema
            .execute_as_scoped_user(
                r"{ samplingPolicyList(first: 1) { totalCount pageInfo { hasNextPage } nodes { name } } }",
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "samplingPolicyList": {
                    "totalCount": "2",
                    "pageInfo": { "hasNextPage": true },
                    "nodes": [{ "name": "legacy_b" }],
                }
            })
        );

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, Some(vec![999]))
            .await;
        let (names, total) = listed_names(res);
        assert!(names.is_empty(), "{names:?}");
        assert_eq!(total, "0");

        // Unscoped callers see every policy, including the node-less one.
        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, total) = listed_names(res);
        assert_eq!(names, ["global", "legacy_b", "policy_a", "policy_b"]);
        assert_eq!(total, "4");

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, None)
            .await;
        let (_, total) = listed_names(res);
        assert_eq!(total, "4");
    }

    #[tokio::test]
    async fn scoped_caller_reads_only_own_policy() {
        let schema = TestSchema::new().await;
        let (policy_a, policy_b, legacy_b, global) = setup_two_customers(&schema);
        let query = |id: u32| format!(r#"{{ samplingPolicy(id: "{id}") {{ name }} }}"#);

        let res = schema
            .execute_as_scoped_user(&query(policy_a), Role::SecurityAdministrator, Some(vec![2]))
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_scoped_user(&query(global), Role::SecurityAdministrator, Some(vec![2]))
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        for (id, name) in [(policy_b, "policy_b"), (legacy_b, "legacy_b")] {
            let res = schema
                .execute_as_scoped_user(&query(id), Role::SecurityAdministrator, Some(vec![2]))
                .await;
            assert!(res.errors.is_empty(), "{:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap(),
                json!({ "samplingPolicy": { "name": name } })
            );
        }

        let res = schema.execute_as_system_admin(&query(global)).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn insert_requires_sensor_name_in_scope() {
        let schema = TestSchema::new().await;
        setup_two_customers(&schema);

        let res = schema
            .execute_as_scoped_user(
                &insert_mutation("other", Some(SENSOR_A)),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_scoped_user(
                &insert_mutation("forged", Some(SENSOR_A)),
                Role::SecurityAdministrator,
                Some(vec![999]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_scoped_user(
                &insert_mutation("own", Some(SENSOR_B)),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let callers = [
            (Role::SystemAdministrator, None),
            (Role::SecurityAdministrator, None),
            (Role::SecurityAdministrator, Some(vec![2])),
        ];
        for (role, scope) in callers {
            let res = schema
                .execute_as_scoped_user(&insert_mutation("no node", None), role, scope.clone())
                .await;
            assert_eq!(error_message(&res), "node is required");

            let res = schema
                .execute_as_scoped_user(
                    &insert_mutation("hostname", Some("b.example.com")),
                    role,
                    scope,
                )
                .await;
            assert_eq!(
                error_message(&res),
                r#""b.example.com" is not a sensor name"#
            );
        }

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, _) = listed_names(res);
        assert_eq!(names, ["global", "legacy_b", "own", "policy_a", "policy_b"]);
    }

    #[tokio::test]
    async fn update_checks_stored_and_new_customer() {
        let schema = TestSchema::new().await;
        let (policy_a, policy_b, legacy_b, global) = setup_two_customers(&schema);

        let res = schema
            .execute_as_scoped_user(
                &update_mutation(
                    policy_a,
                    ("policy_a", Some(SENSOR_A)),
                    ("policy_a", Some(SENSOR_B)),
                ),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_scoped_user(
                &update_mutation(
                    policy_b,
                    ("policy_b", Some(SENSOR_B)),
                    ("policy_b", Some(SENSOR_A)),
                ),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        // A node-less policy has no customer, so a scoped caller cannot claim
        // it even with a sensor name in scope.
        let res = schema
            .execute_as_scoped_user(
                &update_mutation(global, ("global", None), ("global", Some(SENSOR_B))),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_system_admin(&update_mutation(
                global,
                ("global", None),
                ("global", Some("a.example.com")),
            ))
            .await;
        assert_eq!(
            error_message(&res),
            r#""a.example.com" is not a sensor name"#
        );

        let res = schema
            .execute_as_system_admin(&update_mutation(
                policy_a,
                ("policy_a", Some(SENSOR_A)),
                ("policy_a", None),
            ))
            .await;
        assert_eq!(error_message(&res), "node is required");

        // A legacy policy resolves to its customer through the hostname, and
        // can be moved onto a sensor name in scope.
        let res = schema
            .execute_as_scoped_user(
                &update_mutation(
                    legacy_b,
                    ("legacy_b", Some("b.example.com")),
                    ("legacy_b", Some(SENSOR_B)),
                ),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let res = schema
            .execute_as_scoped_user(
                &update_mutation(
                    policy_b,
                    ("policy_b", Some(SENSOR_B)),
                    ("renamed_b", Some(SENSOR_B)),
                ),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // An unscoped caller can give a node-less policy a sensor name.
        let res = schema
            .execute_as_system_admin(&update_mutation(
                global,
                ("global", None),
                ("global", Some(SENSOR_A)),
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, _) = listed_names(res);
        assert_eq!(names, ["global", "legacy_b", "policy_a", "renamed_b"]);
    }

    #[tokio::test]
    async fn remove_is_all_or_nothing() {
        let schema = TestSchema::new().await;
        let (policy_a, policy_b, _, _) = setup_two_customers(&schema);
        let mutation = |ids: &[u32]| {
            let ids = ids
                .iter()
                .map(|id| format!("\"{id}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!("mutation {{ removeSamplingPolicies(ids: [{ids}]) }}")
        };

        let res = schema
            .execute_as_scoped_user(
                &mutation(&[policy_b, policy_a]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_system_admin(&mutation(&[policy_b, 9999]))
            .await;
        assert_eq!(error_message(&res), "no such sampling policy");

        let res = schema
            .execute_as_scoped_user(
                &mutation(&[999_999]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "no such sampling policy");

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (_, total) = listed_names(res);
        assert_eq!(total, "4");

        let res = schema
            .execute_as_scoped_user(
                &mutation(&[policy_b, policy_b]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "removeSamplingPolicies": ["policy_b"] })
        );

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, _) = listed_names(res);
        assert_eq!(names, ["global", "legacy_b", "policy_a"]);
    }

    #[test]
    fn get_sampling_policies_filters_by_customer() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();

        insert_node(&store, "node_a", "a.example.com", 1, true);
        insert_node(&store, "node_b", "b.example.com", 2, true);
        insert_node(&store, "node_c", "c.example.com", 1, false);

        // Only an immutable policy whose `node` is a sensor name of the
        // customer is pulled:
        //  - customer 1's and customer 2's sensor names -> their customer only
        //  - a mutable policy on customer 1's sensor    -> skipped
        //  - customer 1's node hostname                 -> skipped
        //  - a hostname of a node without a sensor      -> skipped
        //  - no node                                    -> skipped
        //  - a name no node emits                       -> skipped
        insert_policy(&store, "policy_a", Some(SENSOR_A), true);
        insert_policy(&store, "policy_b", Some(SENSOR_B), true);
        insert_policy(&store, "mutable_a", Some(SENSOR_A), false);
        insert_policy(&store, "hostname_a", Some("a.example.com"), true);
        insert_policy(&store, "hostname_c", Some("c.example.com"), true);
        insert_policy(&store, "global", None, true);
        insert_policy(&store, "orphan", Some("piglet.missing.example.com"), true);

        let ids = |customer_id| {
            super::get_sampling_policies(&store, customer_id)
                .unwrap()
                .into_iter()
                .map(|p| (p.id, p.node))
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(1), [(0, Some(SENSOR_A.to_string()))]);
        assert_eq!(ids(2), [(1, Some(SENSOR_B.to_string()))]);
        assert_eq!(ids(99), Vec::new());
    }
}
