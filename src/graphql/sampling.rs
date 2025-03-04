use std::net::IpAddr;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, StringNumber,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{Direction, Iterable};
use serde::{Deserialize, Serialize};

use super::{BoxedAgentManager, IpAddress, Role, RoleGuard};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct SamplingPolicyQuery;

#[derive(Default)]
pub(super) struct SamplingPolicyMutation;

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
pub enum Interval {
    FiveMinutes = 0,
    TenMinutes = 1,
    FifteenMinutes = 2,
    ThirtyMinutes = 3,
    OneHour = 4,
}

impl Default for Interval {
    fn default() -> Self {
        Self::FifteenMinutes
    }
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
pub enum Period {
    SixHours = 0,
    TwelveHours = 1,
    OneDay = 2,
}

impl Default for Period {
    fn default() -> Self {
        Self::OneDay
    }
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
pub enum Kind {
    Conn = 0,
    Dns = 1,
    Http = 2,
    Rdp = 3,
}

impl Default for Kind {
    fn default() -> Self {
        Self::Conn
    }
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
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;

        Ok(store.sampling_policy_map().count()?)
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

        let store = crate::graphql::get_store(ctx).await?;
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
    let store = crate::graphql::get_store(ctx).await?;
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
    let store = crate::graphql::get_store(ctx).await?;
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
            let store = crate::graphql::get_store(ctx).await?;
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
                let store = crate::graphql::get_store(ctx).await?;
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
        let store = crate::graphql::get_store(ctx).await?;
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

        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.sampling_policy_map();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::graphql::TestSchema;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_sampling_policy() {
        let schema = TestSchema::new().await;

        let res = schema.execute(r"{samplingPolicyList{totalCount}}").await;
        assert_eq!(
            res.data.to_string(),
            r"{samplingPolicyList: {totalCount: 0}}"
        );

        let res = schema
            .execute(
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
            .execute(
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
            res.errors.first().unwrap().message.to_string(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x".to_string()
        );

        let res = schema
            .execute(
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
            .execute(
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
            .execute(
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
            res.errors.first().unwrap().message.to_string(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x \
            (occurred while parsing \"SamplingPolicyInput\")"
                .to_string()
        );

        let res = schema
            .execute(
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
}
