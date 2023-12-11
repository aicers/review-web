use super::{BoxedAgentManager, Role, RoleGuard};
use anyhow::Context as AnyhowContext;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    ComplexObject, Context, Enum, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use oinq::RequestCode;
use review_database::{
    Indexable, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate, IterableMap,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Default)]
pub(super) struct SamplingPolicyQuery;

#[derive(Default)]
pub(super) struct SamplingPolicyMutation;

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
pub(super) enum Interval {
    FifteenSeconds = 0,
    ThirtySeconds = 1,
    OneMinutes = 2,
    FiveMinutes = 3,
    TenMinutes = 4,
    FifteenMinutes = 5,
    ThirtyMinutes = 6,
    OneHour = 7,
}

impl Default for Interval {
    fn default() -> Self {
        Self::FifteenMinutes
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
pub(super) enum Period {
    SixHours = 0,
    TwelveHours = 1,
    OneDay = 2,
    OneMonth = 3,
    ThreeMonth = 4,
    SixMonth = 5,
    OneYear = 6,
}

impl Default for Period {
    fn default() -> Self {
        Self::OneDay
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Enum, Deserialize, Serialize)]
#[repr(u32)]
pub(super) enum Kind {
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

#[derive(Clone, Deserialize, Serialize, SimpleObject)]
#[graphql(complex)]
pub(super) struct SamplingPolicy {
    #[graphql(skip)]
    id: u32,
    name: String,
    kind: Kind,
    interval: Interval,
    period: Period,
    offset: i32,
    #[graphql(skip)]
    src_ip: Option<IpAddr>,
    #[graphql(skip)]
    dst_ip: Option<IpAddr>,
    node: Option<String>,
    column: Option<u32>,
    immutable: bool,
    creation_time: DateTime<Utc>,
}

#[ComplexObject]
impl SamplingPolicy {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn src_ip(&self) -> Option<String> {
        self.src_ip.as_ref().map(ToString::to_string)
    }

    async fn dst_ip(&self) -> Option<String> {
        self.dst_ip.as_ref().map(ToString::to_string)
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

impl Indexable for SamplingPolicy {
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

#[derive(Clone, InputObject)]
pub(super) struct SamplingPolicyInput {
    pub name: String,
    pub kind: Kind,
    pub interval: Interval,
    pub period: Period,
    pub offset: i32,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub node: Option<String>, // hostname
    pub column: Option<u32>,
    pub immutable: bool,
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
    ) -> Result<Connection<String, SamplingPolicy, SamplingPolicyTotalCount, EmptyFields>> {
        query(
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
        let Some(value) = map.get_by_id(i)? else {
            return Err("no such sampling policy".into());
        };
        Ok(bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .map_err(|_| "invalid value in database")?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, SamplingPolicy, SamplingPolicyTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.sampling_policy_map();
    super::load::<
        '_,
        IndexedMap,
        IndexedMapIterator,
        SamplingPolicy,
        SamplingPolicy,
        SamplingPolicyTotalCount,
    >(&map, after, before, first, last, SamplingPolicyTotalCount)
}

#[derive(Serialize)]
pub(super) struct Policy {
    id: u32,
    kind: Kind,
    interval: Interval,
    period: Period,
    offset: i32,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    node: Option<String>,
    column: Option<u32>,
}

impl TryFrom<SamplingPolicy> for SamplingPolicyInput {
    type Error = async_graphql::Error;

    fn try_from(input: SamplingPolicy) -> Result<Self, Self::Error> {
        Ok(SamplingPolicyInput {
            name: input.name,
            kind: input.kind,
            interval: input.interval,
            period: input.period,
            offset: input.offset,
            src_ip: input.src_ip.as_ref().map(ToString::to_string),
            dst_ip: input.dst_ip.as_ref().map(ToString::to_string),
            node: input.node,
            column: input.column,
            immutable: input.immutable,
        })
    }
}

async fn load_immutable(ctx: &Context<'_>) -> Result<Vec<Policy>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.sampling_policy_map();
    let codec = bincode::DefaultOptions::new();

    let mut rtn: Vec<Policy> = Vec::new();

    for (_, v) in map.iter_forward()? {
        let pol = codec
            .deserialize::<SamplingPolicy>(&v)
            .context("failed to deserialize data from sampling_policy_map")?;
        if pol.immutable {
            rtn.push(Policy {
                id: pol.id,
                kind: pol.kind,
                interval: pol.interval,
                period: pol.period,
                offset: pol.offset,
                src_ip: pol.src_ip,
                dst_ip: pol.dst_ip,
                node: pol.node,
                column: pol.column,
            });
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
        src_ip: Option<String>,
        dst_ip: Option<String>,
        node: Option<String>,
        column: Option<u32>,
        immutable: bool,
    ) -> Result<ID> {
        let src_ip = if let Some(ip) = src_ip {
            Some(
                ip.as_str()
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid IP address: source")?,
            )
        } else {
            None
        };
        let dst_ip = if let Some(ip) = dst_ip {
            Some(
                ip.as_str()
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid IP address: destination")?,
            )
        } else {
            None
        };
        let pol = SamplingPolicy {
            id: u32::MAX,
            name,
            kind,
            interval,
            period,
            offset,
            src_ip,
            dst_ip,
            node,
            column,
            immutable,
            creation_time: Utc::now(),
        };

        let id;
        {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.sampling_policy_map();
            id = map.insert(pol.clone())?;
        }

        if immutable {
            let mut msg = bincode::serialize::<u32>(&RequestCode::SamplingPolicyList.into())?;
            let policies = load_immutable(ctx).await?;
            msg.extend(bincode::DefaultOptions::new().serialize(&policies)?);

            let agents = ctx.data::<BoxedAgentManager>()?;
            if let Err(e) = agents.broadcast_to_crusher(&msg).await {
                // Change policy to mutable so that user can retry
                let old = SamplingPolicyInput::try_from(pol)?;
                #[allow(clippy::redundant_clone)]
                let mut new = old.clone();
                new.immutable = false;
                let store = crate::graphql::get_store(ctx).await?;
                let map = store.sampling_policy_map();
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

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.sampling_policy_map();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

impl IndexedMapUpdate for SamplingPolicyInput {
    type Entry = SamplingPolicy;

    fn key(&self) -> Option<&[u8]> {
        Some(self.name.as_bytes())
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        value.kind = self.kind;
        value.interval = self.interval;
        value.period = self.period;
        value.offset = self.offset;
        value.src_ip = if let Some(ip) = self.src_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address: source")?)
        } else {
            None
        };
        value.dst_ip = if let Some(ip) = self.dst_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address: source")?)
        } else {
            None
        };
        value.node = self.node.clone();
        value.column = self.column;
        value.immutable = self.immutable;

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        if self.kind != value.kind {
            return false;
        }
        if self.interval != value.interval {
            return false;
        }
        if self.period != value.period {
            return false;
        }
        if self.offset != value.offset {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) = (self.src_ip.as_deref(), value.src_ip) {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.src_ip.is_some() || value.src_ip.is_some() {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) = (self.dst_ip.as_deref(), value.dst_ip) {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.dst_ip.is_some() || value.dst_ip.is_some() {
            return false;
        }
        if self.node != value.node {
            return false;
        }
        if self.column != value.column {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_samplig_policy() {
        let schema = TestSchema::new().await;

        let res = schema.execute(r#"{samplingPolicyList{totalCount}}"#).await;
        assert_eq!(
            res.data.to_string(),
            r#"{samplingPolicyList: {totalCount: 0}}"#
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
                        immutable: false
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
                    updateSamplingPolicy(
                        id: "0",
                        old: {
                            name: "Policy 1",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            immutable: false
                        },
                        new:{
                            name: "Policy 2",
                            kind: CONN,
                            interval: FIFTEEN_MINUTES,
                            period: ONE_DAY,
                            offset: 0,
                            immutable: true
                        }
                      )
                }
            "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateSamplingPolicy: "0"}"#);

        let res = schema
            .execute(
                r#"
                query {
                    samplingPolicyList(first: 10) {
                        nodes {
                            name
                        }
                    }
                }
            "#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{samplingPolicyList: {nodes: [{name: "Policy 2"}]}}"#
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
