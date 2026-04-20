use std::net::IpAddr;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, StringNumber,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{Iterable, Store, event::Direction};
use serde::{Deserialize, Serialize};

use super::{BoxedAgentManager, IpAddress, Role, RoleGuard};
use crate::graphql::customer_access::hostname_customer_id_map;
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

struct SamplingPolicyTotalCount;

#[Object]
impl SamplingPolicyTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;

        Ok(StringNumber(store.sampling_policy_map().count()?))
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
    pub node: Option<String>, // hostname
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

        let store = crate::graphql::get_store(ctx)?;
        let map = store.sampling_policy_map();
        let Some(policy) = map.get_by_id(i)? else {
            return Err("no such sampling policy".into());
        };
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
    let store = crate::graphql::get_store(ctx)?;
    let map = store.sampling_policy_map();
    super::load_edges(&map, after, before, first, last, SamplingPolicyTotalCount)
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

/// Returns sampling policies that belong to the given customer.
///
/// A policy is included if:
/// - Its `node` field is `None` (treated as a shared/global policy), or
/// - Its `node` (a hostname) matches a node whose `profile.customer_id`
///   equals the requested `customer_id`.
///
/// `SamplingPolicy.node` stores a hostname (see `SamplingPolicyInput.node`),
/// so the join key is `NodeProfile.hostname`, not `Node.name`.
///
/// Policies whose `node` hostname does not map to any node with a
/// profile are skipped with a warning.
///
/// # Errors
///
/// Returns an error if the sampling policy or node database could not
/// be read.
pub fn get_sampling_policies(db: &Store, customer_id: u32) -> Result<Vec<Policy>> {
    let policy_map = db.sampling_policy_map();
    let hostname_customer = hostname_customer_id_map(db)?;

    let mut policies = vec![];
    for res in policy_map.iter(Direction::Forward, None) {
        let policy = res?;
        match &policy.node {
            None => {
                policies.push(policy.into());
            }
            Some(hostname) => match hostname_customer.get(hostname) {
                Some(&cid) if cid == customer_id => {
                    policies.push(policy.into());
                }
                Some(_) => {}
                None => {
                    tracing::warn!(
                        "sampling policy {:?} references hostname {:?} \
                         that does not map to any node with a profile; skipping",
                        policy.name,
                        hostname,
                    );
                }
            },
        }
    }
    Ok(policies)
}

#[Object]
impl SamplingPolicyMutation {
    /// Inserts a new sampling policy, returning the ID of the new node.
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
            let agents = ctx.data::<BoxedAgentManager>()?;
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
    /// On error, some sampling policies may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_sampling_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.sampling_policy_map();

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

    /// Updates an existing sampling policy.
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
        let old = old.try_into()?;
        let new = new.try_into()?;

        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.sampling_policy_map();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use chrono::Utc;
    use review_database::Store;
    use serde_json::json;

    use crate::graphql::TestSchema;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_sampling_policy() {
        let schema = TestSchema::new().await;

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
                        node: "sensor",
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
                        node: "sensor",
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
                            node: "sensor",
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
                            node: "manager",
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
                        "node": "manager",
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
                            node: "manager",
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
                            node: "manager",
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

    fn insert_node(store: &Store, name: &str, hostname: &str, customer_id: u32) {
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
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node");
    }

    fn insert_policy(store: &Store, name: &str, node: Option<&str>) {
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
            immutable: false,
            creation_time: Utc::now(),
        };
        store
            .sampling_policy_map()
            .put(policy)
            .expect("insert policy");
    }

    #[test]
    fn get_sampling_policies_filters_by_customer() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();

        // Nodes use distinct `name` and `hostname` values so the test
        // distinguishes which field the join key is — `SamplingPolicy.node`
        // is a hostname, not a node name.
        insert_node(&store, "node_a", "host_a", 1);
        insert_node(&store, "node_b", "host_b", 2);

        // Create policies (policy.node stores the target hostname):
        //  - global (node = None)       -> returned for every customer
        //  - assigned to host_a (cust 1) -> returned only for customer 1
        //  - assigned to host_b (cust 2) -> returned only for customer 2
        //  - referencing a missing host  -> skipped
        //  - referencing a node's *name* (not hostname) -> skipped
        insert_policy(&store, "global_policy", None);
        insert_policy(&store, "policy_a", Some("host_a"));
        insert_policy(&store, "policy_b", Some("host_b"));
        insert_policy(&store, "orphan_policy", Some("no_such_host"));
        insert_policy(&store, "by_node_name_policy", Some("node_a"));

        // Customer 1 should see global + policy_a.
        let result = super::get_sampling_policies(&store, 1).unwrap();
        let names: Vec<&str> = result
            .iter()
            .map(|p| p.node.as_deref().unwrap_or("(none)"))
            .collect();
        assert_eq!(result.len(), 2, "customer 1 policies: {names:?}");
        assert!(
            result.iter().any(|p| p.node.is_none()),
            "global policy missing"
        );
        assert!(
            result.iter().any(|p| p.node.as_deref() == Some("host_a")),
            "policy_a missing"
        );

        // Customer 2 should see global + policy_b.
        let result = super::get_sampling_policies(&store, 2).unwrap();
        let names: Vec<&str> = result
            .iter()
            .map(|p| p.node.as_deref().unwrap_or("(none)"))
            .collect();
        assert_eq!(result.len(), 2, "customer 2 policies: {names:?}");
        assert!(
            result.iter().any(|p| p.node.is_none()),
            "global policy missing"
        );
        assert!(
            result.iter().any(|p| p.node.as_deref() == Some("host_b")),
            "policy_b missing"
        );

        // Customer 99 (no nodes) should see only the global policy.
        let result = super::get_sampling_policies(&store, 99).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].node.is_none());
    }
}
