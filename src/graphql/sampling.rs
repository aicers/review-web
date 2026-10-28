use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{
    Iterable, ModelInstance, NewSamplingPolicy, PolicyState, PolicyUse, SamplingPolicyError, Store,
    UniqueKey, event::Direction,
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::{IpAddress, Role, RoleGuard, SharedAgentManager};
use crate::graphql::customer_access::{customer_sensor_names, is_member, users_customers};
use crate::graphql::customer_deletion_guard;
use crate::graphql::engine_config::lock_engine_config;
use crate::graphql::query_with_constraints;
use crate::graphql::training::resolve_generator;

mod delivery;
mod node_apply;
mod policy_source;

use self::delivery::{SamplingPolicyDelivery, policy_delivery};
pub(super) use self::delivery::{SourceDelivery, source_deliveries};
pub(super) use self::node_apply::{
    check_data_store_changes, generator_data_store, generators_of_node, giganto_name,
    refresh_data_stores,
};
pub(super) use self::policy_source::{
    ShapeReference, check_policy_sources, policy_id, trained_shape,
};

const NO_SUCH_POLICY: &str = "no such sampling policy";
const DEFINITION_FIXED: &str =
    "the sampling definition of a fixed policy cannot change; duplicate it as a new policy";
const FIX_BEFORE_ASSIGNING: &str =
    "fix the policy before assigning it; the sampling definition cannot change afterwards";

/// The lock that orders the removals of sampling policies.
///
/// A removal checks every ID before it removes any, then removes them one
/// by one, each in its own transaction; review-database offers no
/// transaction that spans them, and review-web cannot open one. Without the
/// lock, another removal could take one of the checked IDs in between, and
/// this one would fail after removing the others.
///
/// A removal takes it after
/// [`lock_engine_config`](super::engine_config::lock_engine_config), and
/// nothing takes the two in the reverse order. The only other delete, of a
/// customer's data, takes it around its removal of the customer's policies
/// with [`blocking_lock`](Self::blocking_lock), so a removal never finds a
/// policy it checked taken by that deletion; it checks no uses, so it does
/// not take the engine configuration lock. No other writer takes it: an
/// insert creates an ID no removal has checked, and the uses a removal
/// checks are created only under the engine configuration lock it holds.
///
/// Take it before [`get_store`](super::get_store), or before reading the
/// store outside a request: the store guard is a
/// `std::sync::RwLockReadGuard`, which cannot be held across the lock's
/// `.await`, and a reader holding it while waiting for this lock could wait
/// on a writer queued behind a removal that holds this lock.
#[derive(Default)]
pub(crate) struct SamplingPoliciesLock {
    mutex: tokio::sync::Mutex<()>,
    /// How many operations hold or wait for the lock.
    #[cfg(test)]
    users: std::sync::atomic::AtomicUsize,
}

impl SamplingPoliciesLock {
    /// Waits for the sampling policies to be free and locks them, blocking
    /// the thread.
    ///
    /// # Panics
    ///
    /// Panics if called within an asynchronous execution context; call it
    /// from a blocking worker.
    pub(crate) fn blocking_lock(&self) -> SamplingPoliciesGuard<'_> {
        #[cfg(test)]
        let user = LockUser::new(&self.users);
        let guard = self.mutex.blocking_lock();
        SamplingPoliciesGuard {
            _guard: guard,
            #[cfg(test)]
            _user: user,
        }
    }

    /// Returns how many operations hold or wait for the lock.
    #[cfg(test)]
    pub(crate) fn users(&self) -> usize {
        self.users.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Takes the lock outside a request, as a test holding it off a resolver
    /// does.
    #[cfg(test)]
    pub(crate) async fn hold(&self) -> SamplingPoliciesGuard<'_> {
        let user = LockUser::new(&self.users);
        let guard = self.mutex.lock().await;
        SamplingPoliciesGuard {
            _guard: guard,
            _user: user,
        }
    }
}

/// The guard of a held [`SamplingPoliciesLock`].
pub(crate) struct SamplingPoliciesGuard<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    #[cfg(test)]
    _user: LockUser<'a>,
}

/// Counts an operation among the users of a [`SamplingPoliciesLock`] from
/// before it waits for the lock until it releases it or stops waiting.
#[cfg(test)]
struct LockUser<'a>(&'a std::sync::atomic::AtomicUsize);

#[cfg(test)]
impl<'a> LockUser<'a> {
    fn new(users: &'a std::sync::atomic::AtomicUsize) -> Self {
        users.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(users)
    }
}

#[cfg(test)]
impl Drop for LockUser<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits for the sampling policies to be free and locks them.
///
/// # Errors
///
/// Returns an error if the schema holds no [`SamplingPoliciesLock`].
async fn lock_sampling_policies<'a>(ctx: &Context<'a>) -> Result<SamplingPoliciesGuard<'a>> {
    let lock = ctx.data::<Arc<SamplingPoliciesLock>>()?;
    #[cfg(test)]
    let user = LockUser::new(&lock.users);
    let guard = lock.mutex.lock().await;
    Ok(SamplingPoliciesGuard {
        _guard: guard,
        #[cfg(test)]
        _user: user,
    })
}

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

/// The state of a sampling policy.
#[derive(Clone, Copy, Eq, PartialEq, Enum)]
pub(super) enum SamplingPolicyState {
    /// The definition and the name can change, and the policy cannot be
    /// assigned.
    Draft,
    /// The definition is frozen and only the name can change. A policy never
    /// leaves this state.
    Fixed,
}

impl From<PolicyState> for SamplingPolicyState {
    fn from(input: PolicyState) -> Self {
        match input {
            PolicyState::Draft => Self::Draft,
            PolicyState::Fixed => Self::Fixed,
        }
    }
}

/// The Time Series Generator agent a sampling policy is assigned to.
#[derive(SimpleObject)]
pub(super) struct SamplingPolicyAssignee {
    /// The node of the generator.
    node_id: ID,
    /// The key of the generator's agent on the node.
    agent_key: String,
}

impl From<&ModelInstance> for SamplingPolicyAssignee {
    fn from(instance: &ModelInstance) -> Self {
        Self {
            node_id: ID(instance.node_id.to_string()),
            agent_key: instance.agent_key.clone(),
        }
    }
}

/// What uses a sampling policy.
#[derive(Clone, Copy, Eq, PartialEq, Enum)]
pub(super) enum SamplingPolicyUseKind {
    /// A timeseries training definition.
    Definition,
    /// A detector of a timeseries model.
    Detector,
    /// A timeseries model trained on the policy.
    Model,
}

/// A use of a sampling policy.
#[derive(SimpleObject)]
pub(super) struct SamplingPolicyUse {
    kind: SamplingPolicyUseKind,
    /// The name of the definition or the model; null for a detector.
    name: Option<String>,
    /// The node of a detector's engine instance; null for anything else.
    node_id: Option<ID>,
    /// The key of a detector's engine instance agent on the node; null for
    /// anything else.
    agent_key: Option<String>,
    /// The id of a detector; null for anything else.
    detector_id: Option<ID>,
    /// Whether the applied document's detector names the policy; null for
    /// anything but a detector.
    applied: Option<bool>,
    /// Whether the pending document's detector names the policy; null for
    /// anything but a detector.
    pending: Option<bool>,
}

impl From<PolicyUse> for SamplingPolicyUse {
    fn from(input: PolicyUse) -> Self {
        let named = |kind, name| Self {
            kind,
            name: Some(name),
            node_id: None,
            agent_key: None,
            detector_id: None,
            applied: None,
            pending: None,
        };
        match input {
            PolicyUse::Definition { name } => named(SamplingPolicyUseKind::Definition, name),
            PolicyUse::Model { name } => named(SamplingPolicyUseKind::Model, name),
            PolicyUse::Detector {
                instance,
                detector_id,
                applied,
                pending,
            } => Self {
                kind: SamplingPolicyUseKind::Detector,
                name: None,
                node_id: Some(ID(instance.node_id.to_string())),
                agent_key: Some(instance.agent_key),
                detector_id: Some(ID(detector_id.to_string())),
                applied: Some(applied),
                pending: Some(pending),
            },
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

    /// Whether the policy is a draft, whose definition can change, or fixed.
    async fn state(&self) -> SamplingPolicyState {
        self.inner.state.into()
    }

    /// The customer the policy belongs to, or null for a policy stored
    /// before customers were recorded whose customer could not be derived.
    async fn customer_id(&self) -> Option<ID> {
        self.inner.customer_id.map(|id| ID(id.to_string()))
    }

    /// The Time Series Generator agent the policy is assigned to, or null if
    /// it is unassigned.
    async fn assignee(&self) -> Option<SamplingPolicyAssignee> {
        self.inner.assignee.as_ref().map(Into::into)
    }

    /// The Data Store the policy's series are kept in: the `giganto_name`
    /// of the generator it was last assigned to. Null if it was never
    /// assigned, or was last assigned to a generator with no `giganto_name`;
    /// unassigning the policy keeps it.
    async fn data_store(&self) -> Option<&str> {
        self.inner.data_store.as_deref()
    }

    /// What uses the policy by naming its ID as a source: timeseries
    /// training definitions, in name order; detectors of timeseries models
    /// in an applied or pending engine document, by node, agent and detector;
    /// and timeseries models trained on it, in name order. A policy in use
    /// cannot be unassigned or removed.
    async fn used_by(&self, ctx: &Context<'_>) -> Result<Vec<SamplingPolicyUse>> {
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .sampling_policy_uses(self.inner.id)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Whether the policy's series are being produced, as far as the Central
    /// Manager can tell: the first of `UNASSIGNED`, `WITHHELD`,
    /// `ASSIGNEE_OFFLINE` and `ASSIGNEE_ONLINE` that holds.
    async fn delivery(&self, ctx: &Context<'_>) -> Result<SamplingPolicyDelivery> {
        policy_delivery(ctx, &self.inner).await
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

/// Returns whether a caller scoped to `scope` may access `policy`.
///
/// `None` for `scope` is an unscoped caller, who may access every policy. A
/// policy without a customer is accessible to unscoped callers only.
fn in_scope(policy: &review_database::SamplingPolicy, scope: Option<&[u32]>) -> bool {
    match policy.customer_id {
        Some(customer_id) => is_member(scope, customer_id),
        None => scope.is_none(),
    }
}

/// Checks that `node` is a sensor name of customer `customer_id`.
fn check_sensor_name(store: &Store, node: Option<&str>, customer_id: u32) -> Result<()> {
    let Some(node) = node else {
        return Err("node is required".into());
    };
    if customer_sensor_names(store, customer_id)?.contains(node) {
        Ok(())
    } else {
        Err(format!("{node:?} is not a sensor name of customer {customer_id}").into())
    }
}

/// Lists `uses` for an error message.
fn list_uses(uses: &[PolicyUse]) -> String {
    uses.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Maps a refusal of a sampling-policy write to the error a resolver
/// returns, passing every other error through.
fn policy_refusal(error: &anyhow::Error) -> async_graphql::Error {
    match error.downcast_ref::<SamplingPolicyError>() {
        Some(SamplingPolicyError::NotFound { .. }) => NO_SUCH_POLICY.into(),
        Some(SamplingPolicyError::DefinitionFixed { .. }) => DEFINITION_FIXED.into(),
        Some(SamplingPolicyError::Draft { .. }) => FIX_BEFORE_ASSIGNING.into(),
        Some(refusal) => refusal.to_string().into(),
        None => format!("{error:#}").into(),
    }
}

fn parse_id(id: &ID) -> Result<u32> {
    id.as_str().parse::<u32>().map_err(|_| "invalid ID".into())
}

/// Reads the policy `id`, refusing one that does not exist or that a caller
/// scoped to `scope` may not access.
fn accessible_policy(
    store: &Store,
    scope: Option<&[u32]>,
    id: u32,
) -> Result<review_database::SamplingPolicy> {
    let Some(policy) = store.sampling_policy_map().get_by_id(id)? else {
        return Err(NO_SUCH_POLICY.into());
    };
    if in_scope(&policy, scope) {
        Ok(policy)
    } else {
        Err("Forbidden".into())
    }
}

/// Tells the generators in `generators`, once each, that the policies they
/// pull have changed. Nothing is sent if there are none.
///
/// It runs after the change is stored, so it fails nothing: the generators
/// pull their lists again when they reconnect.
pub(super) async fn notify_generators(ctx: &Context<'_>, mut generators: Vec<ModelInstance>) {
    let mut seen = HashSet::new();
    generators.retain(|generator| seen.insert(generator.clone()));
    if generators.is_empty() {
        return;
    }
    match ctx.data::<SharedAgentManager>() {
        Ok(agents) => agents.sampling_policies_changed(&generators).await,
        Err(e) => error!(
            "cannot tell Time Series Generators {generators:?} that their sampling policies \
             changed: {}",
            e.message
        ),
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
        let mut count = 0;
        for entry in map.iter(Direction::Forward, None) {
            if in_scope(&entry?, Some(&scope)) {
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
}

impl From<SamplingPolicyInput> for review_database::SamplingPolicyUpdate {
    fn from(input: SamplingPolicyInput) -> Self {
        Self {
            name: input.name,
            kind: input.kind.into(),
            interval: input.interval.into(),
            period: input.period.into(),
            offset: input.offset,
            src_ip: input.src_ip.map(|ip| ip.0),
            dst_ip: input.dst_ip.map(|ip| ip.0),
            node: input.node,
            column: input.column,
        }
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
        let i = parse_id(&id)?;
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(accessible_policy(&store, users_cids.as_deref(), i)?.into())
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

    let (nodes, has_previous, has_next) =
        super::process_load_edges_filtered(&map, after, before, first, last, None, |policy| {
            in_scope(policy, Some(&scope))
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

/// Returns the sampling policies the Time Series Generator agent `instance`
/// pulls: the policies assigned to it that it can produce data for.
///
/// An assignment is checked when it is made, but the generator's node, or the
/// node of a policy's sensor, can change customer or hostname afterwards. So
/// a policy assigned to the generator is withheld, with a warning, if its
/// customer is not the customer of the applied profile of the generator's
/// node, or its `node` is not a sensor name (see `event_sensor_names`) of
/// that customer. A generator on a node with no applied profile pulls
/// nothing.
///
/// # Errors
///
/// Returns an error if the sampling policy or node database could not be
/// read.
pub fn sampling_policies_for_generator(
    db: &Store,
    instance: &ModelInstance,
) -> Result<Vec<Policy>> {
    let assigned = db.sampling_policies_assigned_to(instance)?;
    if assigned.is_empty() {
        return Ok(Vec::new());
    }
    let customer_id = db
        .node_map()
        .get_by_id(instance.node_id)?
        .and_then(|(node, _, _)| node.profile)
        .map(|profile| profile.customer_id);
    let sensors = match customer_id {
        Some(customer_id) => customer_sensor_names(db, customer_id)?,
        None => HashSet::new(),
    };

    let mut policies = Vec::with_capacity(assigned.len());
    for policy in assigned {
        if let Some(reason) = withholding_reason(&policy, customer_id, &sensors) {
            warn!(
                "sampling policy {:?} is assigned to agent {:?} of node {}, but {reason}; \
                 withholding it",
                policy.name, instance.agent_key, instance.node_id,
            );
            continue;
        }
        policies.push(policy.into());
    }
    Ok(policies)
}

/// Returns why [`sampling_policies_for_generator`] withholds `policy` from
/// its generator, whose node's applied profile is of `customer_id`, `None`
/// if the node has none; `sensors` are the sensor names of that customer.
/// Returns `None` if the policy is not withheld.
fn withholding_reason(
    policy: &review_database::SamplingPolicy,
    customer_id: Option<u32>,
    sensors: &HashSet<String>,
) -> Option<String> {
    if customer_id.is_none() || policy.customer_id != customer_id {
        return Some(format!(
            "the policy's customer is {:?} and the node's {customer_id:?}",
            policy.customer_id
        ));
    }
    if !policy
        .node
        .as_ref()
        .is_some_and(|node| sensors.contains(node))
    {
        return Some(format!(
            "the policy reads {:?}, which is not a sensor name of customer {customer_id:?}",
            policy.node
        ));
    }
    None
}

#[Object]
impl SamplingPolicyMutation {
    /// Inserts a new sampling policy of customer `customerId`, a draft,
    /// returning its ID.
    ///
    /// A caller scoped to customers must belong to `customerId`. `node` must
    /// be a sensor name of one of the customer's nodes, such as
    /// `piglet.sensor.example.com`. A draft cannot be assigned; fix it with
    /// `fixSamplingPolicy`, or with `assignSamplingPolicy(fix: true)`.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// `customerId` is unfinished, also while it is stopped.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_sampling_policy(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        name: String,
        kind: Kind,
        interval: Interval,
        period: Period,
        offset: i32,
        src_ip: Option<IpAddress>,
        dst_ip: Option<IpAddress>,
        node: Option<String>,
        column: Option<u32>,
    ) -> Result<ID> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer ID")?;
        if !is_member(users_customers(ctx)?.as_deref(), customer_id) {
            return Err("Forbidden".into());
        }
        let store = crate::graphql::get_store(ctx)?;
        customer_deletion_guard::check_customers(&store, [customer_id])?;
        check_sensor_name(&store, node.as_deref(), customer_id)?;
        let id = store
            .sampling_policy_map()
            .insert(NewSamplingPolicy {
                name,
                kind: kind.into(),
                interval: interval.into(),
                period: period.into(),
                offset,
                src_ip: src_ip.map(|ip| ip.0),
                dst_ip: dst_ip.map(|ip| ip.0),
                node,
                column,
                customer_id,
            })
            .map_err(|e| policy_refusal(&e))?;
        Ok(ID(id.to_string()))
    }

    /// Removes sampling policies, returning the names of the policies
    /// removed.
    ///
    /// Every ID is checked before any policy is removed: it must exist, be
    /// in the caller's scope and not be in use. A refused ID leaves every
    /// policy in place, and the refusal of a policy in use lists its uses. A
    /// repeated ID is removed once.
    ///
    /// Each policy is then removed in its own transaction: review-database
    /// removes one ID per transaction, and review-web cannot open one that
    /// spans them. So a storage failure after the first removal returns an
    /// error with the policies before it already removed, and a retry with
    /// the IDs that remain removes the rest.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer of any requested policy is unfinished, also while it is
    /// stopped.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_sampling_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let mut ids = ids.iter().map(parse_id).collect::<Result<Vec<_>>>()?;
        // A repeated ID would pass every check and then fail its second
        // removal, after the first had already taken effect.
        let mut seen = HashSet::new();
        ids.retain(|&i| seen.insert(i));

        let users_cids = users_customers(ctx)?;
        let (removed, generators, failure) = {
            let _config = lock_engine_config(ctx).await?;
            let _policies = lock_sampling_policies(ctx).await?;
            let store = crate::graphql::get_store(ctx)?;
            let policies = ids
                .iter()
                .map(|&i| accessible_policy(&store, users_cids.as_deref(), i))
                .collect::<Result<Vec<_>>>()?;
            customer_deletion_guard::check_customers(
                &store,
                policies.iter().filter_map(|policy| policy.customer_id),
            )?;
            let mut checked = Vec::with_capacity(ids.len());
            for policy in policies {
                let i = policy.id;
                let uses = store.sampling_policy_uses(i)?;
                if !uses.is_empty() {
                    return Err(format!(
                        "sampling policy {:?} is in use by {}",
                        policy.name,
                        list_uses(&uses)
                    )
                    .into());
                }
                checked.push(policy);
            }

            let map = store.sampling_policy_map();
            let mut removed = Vec::<String>::with_capacity(checked.len());
            let mut generators = Vec::new();
            let mut failure = None;
            for policy in checked {
                match map.remove_unused(policy.id) {
                    Ok(key) => {
                        removed.push(match String::from_utf8(key) {
                            Ok(key) => key,
                            Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
                        });
                        generators.extend(policy.assignee);
                    }
                    Err(e) => {
                        failure = Some(policy_refusal(&e));
                        break;
                    }
                }
            }
            (removed, generators, failure)
        };

        // The removals before a failure are stored, so their generators are
        // told either way.
        notify_generators(ctx, generators).await;
        match failure {
            Some(e) => Err(e),
            None => Ok(removed),
        }
    }

    /// Updates an existing sampling policy, returning its ID.
    ///
    /// A draft's definition and name can change, and its new `node` must be a
    /// sensor name of one of its customer's nodes. Only the name of a fixed
    /// policy can change. A caller scoped to customers may update only a
    /// policy of a customer in scope.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the policy's customer is unfinished, also while it is stopped.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_sampling_policy(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: SamplingPolicyInput,
        new: SamplingPolicyInput,
    ) -> Result<ID> {
        let i = parse_id(&id)?;
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let stored = accessible_policy(&store, users_cids.as_deref(), i)?;
        customer_deletion_guard::check_customers(&store, stored.customer_id)?;
        if stored.state == PolicyState::Draft {
            let Some(customer_id) = stored.customer_id else {
                return Err("the sampling policy has no customer".into());
            };
            check_sensor_name(&store, new.node.as_deref(), customer_id)?;
        }

        store
            .sampling_policy_map()
            .update(i, &old.into(), &new.into())
            .map_err(|e| policy_refusal(&e))?;
        Ok(id)
    }

    /// Fixes a draft sampling policy, returning its ID.
    ///
    /// A fixed policy's definition cannot change, and nothing makes it a
    /// draft again. Fixing a fixed policy succeeds and changes nothing.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the policy's customer is unfinished, also while it is stopped.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn fix_sampling_policy(&self, ctx: &Context<'_>, id: ID) -> Result<ID> {
        let i = parse_id(&id)?;
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let policy = accessible_policy(&store, users_cids.as_deref(), i)?;
        customer_deletion_guard::check_customers(&store, policy.customer_id)?;
        store
            .sampling_policy_map()
            .fix(i)
            .map_err(|e| policy_refusal(&e))?;
        Ok(id)
    }

    /// Assigns a sampling policy to the Time Series Generator agent
    /// `agentKey` of node `nodeId`, or unassigns it if both are null,
    /// returning its ID.
    ///
    /// The caller must belong to the policy's customer and the generator's,
    /// and the generator's node must be the policy's customer's, its `node`
    /// a sensor name of that customer. A draft is refused unless `fix` is
    /// true, which fixes it and assigns it in one transaction; a refused
    /// assignment leaves it a draft, and `fix` on a fixed policy changes
    /// nothing. `fix` cannot be given to unassign. While the policy is in use
    /// it cannot be unassigned, and can be assigned only to a generator with
    /// its Data Store; the refusal lists its uses.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the policy's customer is unfinished, also while it is stopped.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn assign_sampling_policy(
        &self,
        ctx: &Context<'_>,
        id: ID,
        node_id: Option<ID>,
        agent_key: Option<String>,
        fix: Option<bool>,
    ) -> Result<ID> {
        let i = parse_id(&id)?;
        let fix = fix.unwrap_or(false);

        let users_cids = users_customers(ctx)?;
        let (previous, target) = {
            let _lock = lock_engine_config(ctx).await?;
            let store = crate::graphql::get_store(ctx)?;
            let policy = accessible_policy(&store, users_cids.as_deref(), i)?;
            customer_deletion_guard::check_customers(&store, policy.customer_id)?;
            let assignee = match (node_id, agent_key) {
                (Some(node_id), Some(agent_key)) => {
                    let node_id = node_id
                        .as_str()
                        .parse::<u32>()
                        .map_err(|_| "invalid node ID")?;
                    Some((node_id, agent_key))
                }
                (None, None) => None,
                _ => {
                    return Err(
                        "nodeId and agentKey are given together, or are both null to unassign"
                            .into(),
                    );
                }
            };
            if fix && assignee.is_none() {
                return Err("a policy is fixed only by assigning it; fix cannot unassign".into());
            }
            let target = assignee
                .map(|(node_id, agent_key)| {
                    resolve_generator(&store, users_cids.as_deref(), node_id, &agent_key)
                })
                .transpose()?
                .map(|target| target.instance);
            store
                .sampling_policy_map()
                .assign(i, target.as_ref(), fix)
                .map_err(|e| policy_refusal(&e))?;
            (policy.assignee, target)
        };

        notify_generators(ctx, previous.into_iter().chain(target).collect()).await;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use review_database::{
        EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, Iterable, ModelInstance,
        NodeProfile, NodeUpdate, PolicyState, Role, Store,
    };
    use serde_json::json;

    use super::{DEFINITION_FIXED, FIX_BEFORE_ASSIGNING};
    use crate::graphql::{
        SharedAgentManager, TestSchema,
        model_test_support::{TestModel, insert_engine_node},
        sampling_test_support::{
            Deliveries, DeliveryRecorder, NO_DELIVERIES, data_store_name, insert_generator_node,
            insert_policy, sensor_name, use_policy,
        },
    };

    const HOST_A: &str = "a.example.com";
    const HOST_B: &str = "b.example.com";

    /// Customer 1 and customer 2, each with a node carrying a sensor and a
    /// generator, and a draft policy of each reading its own sensor.
    struct TwoCustomers {
        generator_a: ModelInstance,
        generator_b: ModelInstance,
        policy_a: u32,
        policy_b: u32,
    }

    fn setup_two_customers(schema: &TestSchema) -> TwoCustomers {
        let store = schema.store();
        let generator_a = insert_generator_node(&store, HOST_A, 1);
        let generator_b = insert_generator_node(&store, HOST_B, 2);
        TwoCustomers {
            generator_a,
            generator_b,
            policy_a: insert_policy(&store, "policy_a", 1, &sensor_name(HOST_A)),
            policy_b: insert_policy(&store, "policy_b", 2, &sensor_name(HOST_B)),
        }
    }

    async fn recording_schema() -> (TestSchema, Deliveries) {
        let (agent_manager, deliveries): (SharedAgentManager, Deliveries) =
            DeliveryRecorder::boxed();
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;
        (schema, deliveries)
    }

    fn literal(value: Option<&str>) -> String {
        value.map_or_else(|| "null".to_string(), |value| format!("{value:?}"))
    }

    fn insert_mutation(customer_id: u32, name: &str, node: Option<&str>) -> String {
        format!(
            r#"mutation {{
                insertSamplingPolicy(
                    customerId: "{customer_id}",
                    name: "{name}",
                    kind: CONN,
                    interval: FIFTEEN_MINUTES,
                    period: ONE_DAY,
                    offset: 0,
                    node: {}
                )
            }}"#,
            literal(node)
        )
    }

    /// A `SamplingPolicyInput` of a `CONN` policy with `offset`.
    fn policy_input(name: &str, offset: i32, node: Option<&str>) -> String {
        format!(
            r#"{{
                name: "{name}",
                kind: CONN,
                interval: FIFTEEN_MINUTES,
                period: ONE_DAY,
                offset: {offset},
                node: {}
            }}"#,
            literal(node)
        )
    }

    fn update_mutation(id: u32, old: &str, new: &str) -> String {
        format!(r#"mutation {{ updateSamplingPolicy(id: "{id}", old: {old}, new: {new}) }}"#)
    }

    /// Renames the policy `id`, of offset 0, keeping its `node`.
    fn rename_mutation(id: u32, old: &str, new: &str, node: &str) -> String {
        update_mutation(
            id,
            &policy_input(old, 0, Some(node)),
            &policy_input(new, 0, Some(node)),
        )
    }

    fn fix_mutation(id: u32) -> String {
        format!(r#"mutation {{ fixSamplingPolicy(id: "{id}") }}"#)
    }

    fn assign_mutation(id: u32, generator: Option<&ModelInstance>, fix: Option<bool>) -> String {
        let (node_id, agent_key) = generator.map_or_else(
            || ("null".to_string(), "null".to_string()),
            |generator| {
                (
                    format!("\"{}\"", generator.node_id),
                    format!("{:?}", generator.agent_key),
                )
            },
        );
        let fix = fix.map_or_else(|| "null".to_string(), |fix| fix.to_string());
        format!(
            r#"mutation {{
                assignSamplingPolicy(id: "{id}", nodeId: {node_id}, agentKey: {agent_key}, fix: {fix})
            }}"#
        )
    }

    fn remove_mutation(ids: &[u32]) -> String {
        let ids = ids
            .iter()
            .map(|id| format!("\"{id}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("mutation {{ removeSamplingPolicies(ids: [{ids}]) }}")
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

    /// Returns the names of the stored policies, read from the store rather
    /// than through a request.
    fn listed_names_of_store(schema: &TestSchema) -> Vec<String> {
        let store = schema.store();
        let map = store.sampling_policy_map();
        let mut names = map
            .iter(review_database::event::Direction::Forward, None)
            .map(|policy| policy.expect("readable policy").name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn stored_policy(schema: &TestSchema, id: u32) -> review_database::SamplingPolicy {
        schema
            .store()
            .sampling_policy_map()
            .get_by_id(id)
            .expect("read policy")
            .expect("policy exists")
    }

    fn error_message(res: &async_graphql::Response) -> &str {
        &res.errors.first().expect("an error").message
    }

    fn assert_ok(res: &async_graphql::Response) {
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    /// Reads the policy `id` through `samplingPolicy`.
    async fn read_policy(schema: &TestSchema, id: u32) -> serde_json::Value {
        let res = schema
            .execute_as_system_admin(&format!(
                r#"{{
                    samplingPolicy(id: "{id}") {{
                        name kind offset node state customerId
                        assignee {{ nodeId agentKey }}
                    }}
                }}"#
            ))
            .await;
        assert_ok(&res);
        res.data.into_json().unwrap()["samplingPolicy"].clone()
    }

    #[tokio::test]
    async fn the_policies_of_a_customer_being_deleted_cannot_change() {
        use crate::graphql::customer_deletion_guard::test_support::{
            assert_locked, put_completed_job, put_running_job, put_stopped_job,
        };

        let (schema, _) = recording_schema().await;
        let two = setup_two_customers(&schema);
        let mutations = |policy: u32, generator: &ModelInstance, customer_id: u32| {
            [
                insert_mutation(customer_id, "new-a", Some(&sensor_name(HOST_A))),
                rename_mutation(policy, "old", "renamed", &sensor_name(HOST_A)),
                fix_mutation(policy),
                assign_mutation(policy, Some(generator), Some(true)),
                remove_mutation(&[policy]),
            ]
        };
        for put_job in [put_running_job, put_stopped_job] {
            put_job(&schema.store(), 1, &[HOST_A]);
            for mutation in mutations(two.policy_a, &two.generator_a, 1) {
                assert_locked(&schema.execute_as_system_admin(&mutation).await);
            }
            // The lock answers before the arguments are checked.
            let res = schema
                .execute_as_system_admin(&assign_mutation(two.policy_a, None, Some(true)))
                .await;
            assert_locked(&res);
            // Removing policies of both customers is refused as a whole.
            let res = schema
                .execute_as_system_admin(&remove_mutation(&[two.policy_b, two.policy_a]))
                .await;
            assert_locked(&res);
        }

        // Customer 2's policy changes while customer 1 is locked.
        let res = schema
            .execute_as_system_admin(&insert_mutation(2, "new-b", Some(&sensor_name(HOST_B))))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let res = schema
            .execute_as_system_admin(&assign_mutation(
                two.policy_b,
                Some(&two.generator_b),
                Some(true),
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        put_completed_job(&schema.store(), 1, &[HOST_A]);
        let res = schema
            .execute_as_system_admin(&insert_mutation(1, "new-a", Some(&sensor_name(HOST_A))))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let res = schema
            .execute_as_system_admin(&remove_mutation(&[two.policy_a]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn a_policy_is_a_draft_until_fixed() {
        let schema = TestSchema::new().await;
        insert_generator_node(&schema.store(), HOST_A, 1);
        insert_generator_node(&schema.store(), "a2.example.com", 1);
        let sensor = sensor_name(HOST_A);
        let other_sensor = sensor_name("a2.example.com");

        let res = schema
            .execute_as_system_admin(&insert_mutation(1, "Policy 1", Some(&sensor)))
            .await;
        assert_eq!(res.data.to_string(), r#"{insertSamplingPolicy: "0"}"#);
        assert_json_eq!(
            read_policy(&schema, 0).await,
            json!({
                "name": "Policy 1",
                "kind": "CONN",
                "offset": 0,
                "node": sensor,
                "state": "DRAFT",
                "customerId": "1",
                "assignee": null,
            })
        );

        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{
                    insertSamplingPolicy(
                        customerId: "1",
                        name: "Policy 2",
                        kind: CONN,
                        interval: FIFTEEN_MINUTES,
                        period: ONE_DAY,
                        offset: 0,
                        node: {sensor:?},
                        srcIp: "127.0.0.1",
                        dstIp: "127.0.0.x"
                    )
                }}"#
            ))
            .await;
        assert_eq!(
            error_message(&res),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x"
        );

        // A draft's kind, offset and node can change.
        let res = schema
            .execute_as_system_admin(&update_mutation(
                0,
                &policy_input("Policy 1", 0, Some(&sensor)),
                &format!(
                    r#"{{
                        name: "Policy 1",
                        kind: DNS,
                        interval: FIFTEEN_MINUTES,
                        period: ONE_DAY,
                        offset: 5,
                        node: {other_sensor:?}
                    }}"#
                ),
            ))
            .await;
        assert_eq!(res.data.to_string(), r#"{updateSamplingPolicy: "0"}"#);
        let policy = read_policy(&schema, 0).await;
        assert_eq!(policy["kind"], "DNS");
        assert_eq!(policy["offset"], 5);
        assert_eq!(policy["node"], other_sensor.as_str());
        assert_eq!(policy["state"], "DRAFT");

        // Fixing is one-way, and fixing again succeeds without change.
        for _ in 0..2 {
            let res = schema.execute_as_system_admin(&fix_mutation(0)).await;
            assert_eq!(res.data.to_string(), r#"{fixSamplingPolicy: "0"}"#);
            assert_eq!(read_policy(&schema, 0).await["state"], "FIXED");
        }

        let fixed = format!(
            r#"{{
                name: "Policy 1",
                kind: DNS,
                interval: FIFTEEN_MINUTES,
                period: ONE_DAY,
                offset: 5,
                node: {other_sensor:?}
            }}"#
        );
        let res = schema
            .execute_as_system_admin(&update_mutation(
                0,
                &fixed,
                &fixed.replace("offset: 5", "offset: 6"),
            ))
            .await;
        assert_eq!(error_message(&res), DEFINITION_FIXED);
        assert_eq!(read_policy(&schema, 0).await["offset"], 5);

        let res = schema
            .execute_as_system_admin(&update_mutation(
                0,
                &fixed,
                &fixed.replace("Policy 1", "Renamed"),
            ))
            .await;
        assert_ok(&res);
        assert_eq!(read_policy(&schema, 0).await["name"], "Renamed");

        let res = schema.execute_as_system_admin(&fix_mutation(9999)).await;
        assert_eq!(error_message(&res), "no such sampling policy");

        // A draft and a fixed policy that are not in use can be deleted.
        let res = schema
            .execute_as_system_admin(&insert_mutation(1, "Draft", Some(&sensor)))
            .await;
        assert_eq!(res.data.to_string(), r#"{insertSamplingPolicy: "1"}"#);
        let res = schema
            .execute_as_system_admin(&remove_mutation(&[1, 0]))
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeSamplingPolicies: ["Draft", "Renamed"]}"#
        );
        assert_eq!(listed_names_of_store(&schema), Vec::<String>::new());
    }

    #[tokio::test]
    async fn scoped_caller_lists_only_own_policies() {
        let schema = TestSchema::new().await;
        setup_two_customers(&schema);
        insert_policy(&schema.store(), "policy_b2", 2, &sensor_name(HOST_B));

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, Some(vec![2]))
            .await;
        let (names, total) = listed_names(res);
        assert_eq!(names, ["policy_b", "policy_b2"]);
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
                    "nodes": [{ "name": "policy_b" }],
                }
            })
        );

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, Some(vec![999]))
            .await;
        let (names, total) = listed_names(res);
        assert!(names.is_empty(), "{names:?}");
        assert_eq!(total, "0");

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, total) = listed_names(res);
        assert_eq!(names, ["policy_a", "policy_b", "policy_b2"]);
        assert_eq!(total, "3");

        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SecurityAdministrator, None)
            .await;
        let (_, total) = listed_names(res);
        assert_eq!(total, "3");
    }

    #[tokio::test]
    async fn scoped_caller_reads_and_fixes_only_own_policy() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let query = |id: u32| format!(r#"{{ samplingPolicy(id: "{id}") {{ name }} }}"#);

        for scope in [vec![2], vec![999]] {
            let res = schema
                .execute_as_scoped_user(
                    &query(setup.policy_a),
                    Role::SecurityAdministrator,
                    Some(scope.clone()),
                )
                .await;
            assert_eq!(error_message(&res), "Forbidden");

            let res = schema
                .execute_as_scoped_user(
                    &fix_mutation(setup.policy_a),
                    Role::SecurityAdministrator,
                    Some(scope),
                )
                .await;
            assert_eq!(error_message(&res), "Forbidden");
        }
        assert_eq!(
            stored_policy(&schema, setup.policy_a).state,
            PolicyState::Draft
        );

        let res = schema
            .execute_as_scoped_user(
                &query(setup.policy_b),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_ok(&res);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "samplingPolicy": { "name": "policy_b" } })
        );

        let res = schema
            .execute_as_scoped_user(
                &fix_mutation(setup.policy_b),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_ok(&res);
        assert_eq!(
            stored_policy(&schema, setup.policy_b).state,
            PolicyState::Fixed
        );
    }

    /// Every resolver decides access with `in_scope`. A policy without a
    /// customer cannot be stored through review-database's API, so the rule
    /// for one is checked on the row read back with its customer cleared.
    #[tokio::test]
    async fn a_policy_without_a_customer_is_for_unscoped_callers_only() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let mut policy = stored_policy(&schema, setup.policy_a);
        assert!(super::in_scope(&policy, None));
        assert!(super::in_scope(&policy, Some(&[1])));
        assert!(!super::in_scope(&policy, Some(&[2])));

        policy.customer_id = None;
        assert!(super::in_scope(&policy, None));
        for scope in [&[][..], &[1], &[1, 2]] {
            assert!(!super::in_scope(&policy, Some(scope)), "{scope:?}");
        }
    }

    #[tokio::test]
    async fn insert_requires_a_customer_in_scope_and_its_sensor_name() {
        let schema = TestSchema::new().await;
        setup_two_customers(&schema);
        let sensor_a = sensor_name(HOST_A);
        let sensor_b = sensor_name(HOST_B);

        for scope in [vec![2], vec![999]] {
            let res = schema
                .execute_as_scoped_user(
                    &insert_mutation(1, "forged", Some(&sensor_a)),
                    Role::SecurityAdministrator,
                    Some(scope),
                )
                .await;
            assert_eq!(error_message(&res), "Forbidden");
        }

        // Another customer's sensor name, even one in scope, is refused.
        let res = schema
            .execute_as_scoped_user(
                &insert_mutation(2, "other sensor", Some(&sensor_a)),
                Role::SecurityAdministrator,
                Some(vec![1, 2]),
            )
            .await;
        assert_eq!(
            error_message(&res),
            format!("{sensor_a:?} is not a sensor name of customer 2")
        );

        let res = schema
            .execute_as_scoped_user(
                &insert_mutation(2, "own", Some(&sensor_b)),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_ok(&res);
        let id = res.data.into_json().unwrap()["insertSamplingPolicy"]
            .as_str()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert_eq!(stored_policy(&schema, id).customer_id, Some(2));

        let callers = [
            (Role::SystemAdministrator, None),
            (Role::SecurityAdministrator, None),
            (Role::SecurityAdministrator, Some(vec![2])),
        ];
        for (role, scope) in callers {
            let res = schema
                .execute_as_scoped_user(&insert_mutation(2, "no node", None), role, scope.clone())
                .await;
            assert_eq!(error_message(&res), "node is required");

            let res = schema
                .execute_as_scoped_user(&insert_mutation(2, "hostname", Some(HOST_B)), role, scope)
                .await;
            assert_eq!(
                error_message(&res),
                format!("{HOST_B:?} is not a sensor name of customer 2")
            );
        }

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, _) = listed_names(res);
        assert_eq!(names, ["own", "policy_a", "policy_b"]);
    }

    #[tokio::test]
    async fn update_checks_the_stored_customer() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let sensor_a = sensor_name(HOST_A);
        let sensor_b = sensor_name(HOST_B);

        let res = schema
            .execute_as_scoped_user(
                &rename_mutation(setup.policy_a, "policy_a", "taken", &sensor_a),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        // The stored customer decides the sensor names a draft may read, for
        // every caller: a policy cannot move to another customer.
        for scope in [Some(vec![2]), None] {
            let res = schema
                .execute_as_scoped_user(
                    &update_mutation(
                        setup.policy_b,
                        &policy_input("policy_b", 0, Some(&sensor_b)),
                        &policy_input("policy_b", 0, Some(&sensor_a)),
                    ),
                    Role::SecurityAdministrator,
                    scope,
                )
                .await;
            assert_eq!(
                error_message(&res),
                format!("{sensor_a:?} is not a sensor name of customer 2")
            );
        }

        let res = schema
            .execute_as_system_admin(&update_mutation(
                setup.policy_a,
                &policy_input("policy_a", 0, Some(&sensor_a)),
                &policy_input("policy_a", 0, None),
            ))
            .await;
        assert_eq!(error_message(&res), "node is required");

        let res = schema
            .execute_as_scoped_user(
                &rename_mutation(setup.policy_b, "policy_b", "renamed_b", &sensor_b),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_ok(&res);

        let res = schema.execute_as_system_admin(LIST_QUERY).await;
        let (names, _) = listed_names(res);
        assert_eq!(names, ["policy_a", "renamed_b"]);
        assert_eq!(stored_policy(&schema, setup.policy_b).customer_id, Some(2));
    }

    #[tokio::test]
    async fn a_fixed_policy_keeps_its_definition_where_its_sensor_left() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let sensor_a = sensor_name(HOST_A);
        let res = schema
            .execute_as_system_admin(&fix_mutation(setup.policy_a))
            .await;
        assert_ok(&res);
        move_node(&schema.store(), setup.generator_a.node_id, 2, HOST_A);

        // The sensor check is the one a draft's new definition takes; a fixed
        // policy's definition cannot change, so it can still be renamed.
        let res = schema
            .execute_as_system_admin(&rename_mutation(
                setup.policy_a,
                "policy_a",
                "renamed_a",
                &sensor_a,
            ))
            .await;
        assert_ok(&res);
        assert_eq!(stored_policy(&schema, setup.policy_a).name, "renamed_a");
    }

    #[tokio::test]
    async fn assigning_a_draft_requires_fix() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);

        for fix in [None, Some(false)] {
            let res = schema
                .execute_as_system_admin(&assign_mutation(
                    setup.policy_a,
                    Some(&setup.generator_a),
                    fix,
                ))
                .await;
            assert_eq!(error_message(&res), FIX_BEFORE_ASSIGNING);
        }
        let policy = stored_policy(&schema, setup.policy_a);
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(policy.assignee, None);
        assert_eq!(deliveries.calls(), NO_DELIVERIES);

        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{assignSamplingPolicy: \"{}\"}}", setup.policy_a)
        );
        assert_json_eq!(
            read_policy(&schema, setup.policy_a).await,
            json!({
                "name": "policy_a",
                "kind": "CONN",
                "offset": 0,
                "node": sensor_name(HOST_A),
                "state": "FIXED",
                "customerId": "1",
                "assignee": {
                    "nodeId": setup.generator_a.node_id.to_string(),
                    "agentKey": setup.generator_a.agent_key,
                },
            })
        );
        assert_eq!(
            stored_policy(&schema, setup.policy_a).data_store,
            Some(data_store_name(HOST_A))
        );
        assert_eq!(deliveries.calls(), [vec![setup.generator_a.clone()]]);

        // `fix` on a fixed policy changes nothing.
        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_ok(&res);
        assert_eq!(
            stored_policy(&schema, setup.policy_a).state,
            PolicyState::Fixed
        );
    }

    #[tokio::test]
    async fn assigning_to_another_customers_generator_is_refused() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);

        for fix in [None, Some(true)] {
            let res = schema
                .execute_as_scoped_user(
                    &assign_mutation(setup.policy_a, Some(&setup.generator_b), fix),
                    Role::SecurityAdministrator,
                    Some(vec![1]),
                )
                .await;
            assert_eq!(error_message(&res), "Forbidden");

            let res = schema
                .execute_as_system_admin(&assign_mutation(
                    setup.policy_a,
                    Some(&setup.generator_b),
                    fix,
                ))
                .await;
            let expected = if fix.is_some() {
                format!(
                    "node {} does not belong to customer 1",
                    setup.generator_b.node_id
                )
            } else {
                FIX_BEFORE_ASSIGNING.to_string()
            };
            assert_eq!(error_message(&res), expected);
        }

        // A caller scoped to only the generator's customer cannot reach the
        // policy either.
        let res = schema
            .execute_as_scoped_user(
                &assign_mutation(setup.policy_a, Some(&setup.generator_b), Some(true)),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let policy = stored_policy(&schema, setup.policy_a);
        assert_eq!(policy.state, PolicyState::Draft);
        assert_eq!(policy.assignee, None);
        assert_eq!(deliveries.calls(), NO_DELIVERIES);
    }

    #[tokio::test]
    async fn assignment_takes_both_of_node_and_agent_or_neither() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);
        let id = setup.policy_a;
        let node_id = setup.generator_a.node_id;
        let agent_key = &setup.generator_a.agent_key;

        let half = [
            format!(
                r#"mutation {{ assignSamplingPolicy(id: "{id}", nodeId: "{node_id}", fix: true) }}"#
            ),
            format!(
                r#"mutation {{ assignSamplingPolicy(id: "{id}", agentKey: {agent_key:?}, fix: true) }}"#
            ),
        ];
        for mutation in &half {
            let res = schema.execute_as_system_admin(mutation).await;
            assert_eq!(
                error_message(&res),
                "nodeId and agentKey are given together, or are both null to unassign"
            );
        }
        let res = schema
            .execute_as_system_admin(&assign_mutation(id, None, Some(true)))
            .await;
        assert_eq!(
            error_message(&res),
            "a policy is fixed only by assigning it; fix cannot unassign"
        );
        assert_eq!(stored_policy(&schema, id).state, PolicyState::Draft);
        assert_eq!(deliveries.calls(), NO_DELIVERIES);

        let res = schema
            .execute_as_system_admin(&assign_mutation(id, Some(&setup.generator_a), Some(true)))
            .await;
        assert_ok(&res);
        let res = schema
            .execute_as_system_admin(&assign_mutation(id, None, None))
            .await;
        assert_ok(&res);
        let policy = stored_policy(&schema, id);
        assert_eq!(policy.assignee, None);
        assert_eq!(policy.state, PolicyState::Fixed);
        assert_eq!(
            deliveries.calls(),
            [
                vec![setup.generator_a.clone()],
                vec![setup.generator_a.clone()]
            ]
        );

        // Unassigning an unassigned policy tells no generator.
        let res = schema
            .execute_as_system_admin(&assign_mutation(id, None, Some(false)))
            .await;
        assert_ok(&res);
        assert_eq!(deliveries.calls().len(), 2);
    }

    #[tokio::test]
    async fn reassigning_tells_the_old_and_the_new_generator() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);
        let second = insert_generator_node(&schema.store(), "a2.example.com", 1);

        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_ok(&res);
        let res = schema
            .execute_as_system_admin(&assign_mutation(setup.policy_a, Some(&second), None))
            .await;
        assert_ok(&res);
        assert_eq!(
            deliveries.calls(),
            [
                vec![setup.generator_a.clone()],
                vec![setup.generator_a.clone(), second.clone()]
            ]
        );
        assert_eq!(
            stored_policy(&schema, setup.policy_a).assignee,
            Some(second)
        );
    }

    #[tokio::test]
    async fn a_used_policy_stays_assigned_and_stored() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);
        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_ok(&res);
        let engine = insert_engine_node(&schema.store(), 1);
        use_policy(&schema.store(), "series", 1, &engine, setup.policy_a);
        let in_use = "the sampling policy is in use by training definition \"series\"";

        let res = schema
            .execute_as_system_admin(&assign_mutation(setup.policy_a, None, None))
            .await;
        assert_eq!(error_message(&res), in_use);
        assert_eq!(
            stored_policy(&schema, setup.policy_a).assignee,
            Some(setup.generator_a.clone())
        );

        // A generator with another Data Store would lose the policy's
        // series.
        let second = insert_generator_node(&schema.store(), "a2.example.com", 1);
        let res = schema
            .execute_as_system_admin(&assign_mutation(setup.policy_a, Some(&second), None))
            .await;
        assert!(
            error_message(&res).contains("in use by training definition \"series\""),
            "{:?}",
            res.errors
        );

        let res = schema
            .execute_as_system_admin(&remove_mutation(&[setup.policy_a]))
            .await;
        assert_eq!(
            error_message(&res),
            "sampling policy \"policy_a\" is in use by training definition \"series\""
        );

        // Neither does a request that also names an unused policy remove
        // anything.
        let res = schema
            .execute_as_system_admin(&remove_mutation(&[setup.policy_b, setup.policy_a]))
            .await;
        assert_eq!(
            error_message(&res),
            "sampling policy \"policy_a\" is in use by training definition \"series\""
        );
        assert_eq!(listed_names_of_store(&schema), ["policy_a", "policy_b"]);
        assert_eq!(deliveries.calls().len(), 1);
    }

    #[tokio::test]
    async fn a_policy_reads_its_data_store_and_its_uses() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let engine = {
            let store = schema.store();
            store
                .sampling_policy_map()
                .assign(setup.policy_a, Some(&setup.generator_a), true)
                .unwrap();
            let engine = insert_engine_node(&store, 1);
            use_policy(&store, "series", 1, &engine, setup.policy_a);
            TestModel {
                instance: engine.clone(),
                kind: "Timeseries",
                trained_sources: vec![setup.policy_a.to_string()],
                ..TestModel::new("trained", 1)
            }
            .replace(&store);
            let mut map = store.node_map();
            let (node, _, _) = map.get_by_id(engine.node_id).unwrap().unwrap();
            let update = NodeUpdate::from(node);
            let refs = |id| EngineDocumentRefs {
                detectors: vec![EngineDetectorRef {
                    id,
                    model: "trained".to_string(),
                    sources: vec![setup.policy_a.to_string()],
                    indicator: None,
                }],
            };
            let document = EngineDocumentWrite {
                agent_key: engine.agent_key.clone(),
                applied: Some(refs(4)),
                pending: Some(refs(4)),
            };
            map.update_with_engine_documents(engine.node_id, &update, &update, &[document])
                .unwrap();
            engine
        };

        let query = |id: u32| {
            format!(
                r#"{{
                    samplingPolicy(id: "{id}") {{
                        dataStore
                        usedBy {{ kind name nodeId agentKey detectorId applied pending }}
                    }}
                }}"#
            )
        };
        let res = schema.execute_as_system_admin(&query(setup.policy_a)).await;
        assert_ok(&res);
        let named = |kind: &str, name: &str| {
            json!({
                "kind": kind, "name": name, "nodeId": null, "agentKey": null,
                "detectorId": null, "applied": null, "pending": null,
            })
        };
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "samplingPolicy": {
                    "dataStore": data_store_name(HOST_A),
                    "usedBy": [
                        named("DEFINITION", "series"),
                        {
                            "kind": "DETECTOR", "name": null,
                            "nodeId": engine.node_id.to_string(),
                            "agentKey": engine.agent_key,
                            "detectorId": "4", "applied": true, "pending": true,
                        },
                        named("MODEL", "trained"),
                    ],
                }
            })
        );

        // A policy never assigned has no Data Store and no use.
        let res = schema.execute_as_system_admin(&query(setup.policy_b)).await;
        assert_ok(&res);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({ "samplingPolicy": { "dataStore": null, "usedBy": [] } })
        );
    }

    #[tokio::test]
    async fn removing_an_assigned_policy_tells_its_generator() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);
        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_ok(&res);

        let res = schema
            .execute_as_system_admin(&remove_mutation(&[setup.policy_a, setup.policy_b]))
            .await;
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "removeSamplingPolicies": ["policy_a", "policy_b"] })
        );
        assert_eq!(
            deliveries.calls(),
            [
                vec![setup.generator_a.clone()],
                vec![setup.generator_a.clone()]
            ]
        );
    }

    /// A mutation that tells a generator succeeds with the row as written
    /// when no generator is connected to be told.
    #[tokio::test]
    async fn delivery_reaching_no_generator_does_not_affect_the_mutation() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);

        let res = schema
            .execute_as_system_admin(&assign_mutation(
                setup.policy_a,
                Some(&setup.generator_a),
                Some(true),
            ))
            .await;
        assert_ok(&res);
        let policy = stored_policy(&schema, setup.policy_a);
        assert_eq!(policy.state, PolicyState::Fixed);
        assert_eq!(policy.assignee, Some(setup.generator_a.clone()));

        let res = schema
            .execute_as_system_admin(&remove_mutation(&[setup.policy_a]))
            .await;
        assert_ok(&res);
        assert_eq!(listed_names_of_store(&schema), ["policy_b"]);
    }

    #[tokio::test]
    async fn remove_is_all_or_nothing() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);

        let res = schema
            .execute_as_scoped_user(
                &remove_mutation(&[setup.policy_b, setup.policy_a]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "Forbidden");

        let res = schema
            .execute_as_system_admin(&remove_mutation(&[setup.policy_b, 9999]))
            .await;
        assert_eq!(error_message(&res), "no such sampling policy");

        let res = schema
            .execute_as_scoped_user(
                &remove_mutation(&[999_999]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_eq!(error_message(&res), "no such sampling policy");
        assert_eq!(listed_names_of_store(&schema), ["policy_a", "policy_b"]);

        let res = schema
            .execute_as_scoped_user(
                &remove_mutation(&[setup.policy_b, setup.policy_b]),
                Role::SecurityAdministrator,
                Some(vec![2]),
            )
            .await;
        assert_ok(&res);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "removeSamplingPolicies": ["policy_b"] })
        );
        assert_eq!(listed_names_of_store(&schema), ["policy_a"]);
    }

    #[tokio::test]
    async fn overlapping_removals_do_not_remove_part() {
        let schema = TestSchema::new().await;
        let setup = setup_two_customers(&schema);
        let before = listed_names_of_store(&schema);

        let both = remove_mutation(&[setup.policy_a, setup.policy_b]);
        let only_b = remove_mutation(&[setup.policy_b]);
        let guard = schema.hold_sampling_policies_lock().await;
        let (res_both, res_b, ()) = tokio::join!(
            schema.execute_as_system_admin(&both),
            schema.execute_as_system_admin(&only_b),
            async {
                // Waits until one removal waits for the lock the test holds,
                // and the other for the engine configuration lock it holds.
                while schema.sampling_policies_lock_users() < 2
                    || schema.engine_config_lock_users() < 2
                {
                    tokio::task::yield_now().await;
                }
                assert_eq!(listed_names_of_store(&schema), before);
                drop(guard);
            }
        );
        assert_eq!(schema.sampling_policies_lock_users(), 0);
        assert_eq!(schema.engine_config_lock_users(), 0);

        // Whichever removal went second found `policy_b` gone before it
        // removed anything.
        let after = listed_names_of_store(&schema);
        match (res_both.errors.is_empty(), res_b.errors.is_empty()) {
            (true, false) => {
                assert_eq!(error_message(&res_b), "no such sampling policy");
                assert!(after.is_empty(), "{after:?}");
            }
            (false, true) => {
                assert_eq!(error_message(&res_both), "no such sampling policy");
                assert_eq!(after, ["policy_a"]);
            }
            results => panic!("exactly one removal succeeds: {results:?}"),
        }
    }

    #[tokio::test]
    async fn removal_and_assignment_wait_for_the_engine_config_lock() {
        let (schema, deliveries) = recording_schema().await;
        let setup = setup_two_customers(&schema);
        let before = listed_names_of_store(&schema);

        let remove = remove_mutation(&[setup.policy_b]);
        let assign = assign_mutation(setup.policy_a, Some(&setup.generator_a), Some(true));
        let guard = schema.hold_engine_config_lock().await;
        let (res_remove, res_assign, ()) = tokio::join!(
            schema.execute_as_system_admin(&remove),
            schema.execute_as_system_admin(&assign),
            async {
                // Waits until both wait for the lock the test holds.
                while schema.engine_config_lock_users() < 3 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(listed_names_of_store(&schema), before);
                let policy = stored_policy(&schema, setup.policy_a);
                assert_eq!(policy.state, PolicyState::Draft);
                assert_eq!(policy.assignee, None);
                assert_eq!(deliveries.calls(), NO_DELIVERIES);
                drop(guard);
            }
        );
        assert_ok(&res_remove);
        assert_ok(&res_assign);
        assert_eq!(schema.engine_config_lock_users(), 0);
        assert_eq!(listed_names_of_store(&schema), ["policy_a"]);
        assert_eq!(
            stored_policy(&schema, setup.policy_a).assignee,
            Some(setup.generator_a)
        );
    }

    /// Moves node `node_id` to `customer_id` and `hostname`, applied.
    fn move_node(store: &Store, node_id: u32, customer_id: u32, hostname: &str) {
        let mut map = store.node_map();
        let (node, _, _) = map
            .get_by_id(node_id)
            .expect("read node")
            .expect("node exists");
        let old = NodeUpdate::from(node.clone());
        let profile = NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        };
        let mut new = NodeUpdate::from(node);
        new.profile = Some(profile.clone());
        new.profile_draft = Some(profile);
        map.update(node_id, &old, &new).expect("move node");
    }

    #[test]
    fn the_pull_withholds_policies_the_generator_cannot_produce() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();

        let generator = insert_generator_node(&store, "g.example.com", 1);
        let sensor_1 = insert_generator_node(&store, "s1.example.com", 1);
        let sensor_2 = insert_generator_node(&store, "s2.example.com", 1);
        let other = insert_generator_node(&store, "o.example.com", 2);
        let assigned = [
            insert_policy(&store, "p1", 1, &sensor_name("s1.example.com")),
            insert_policy(&store, "p2", 1, &sensor_name("s2.example.com")),
        ];
        for &id in &assigned {
            store
                .sampling_policy_map()
                .assign(id, Some(&generator), true)
                .expect("assign");
        }
        // Neither another generator's policy nor an unassigned one is pulled.
        let elsewhere = insert_policy(&store, "elsewhere", 2, &sensor_name("o.example.com"));
        store
            .sampling_policy_map()
            .assign(elsewhere, Some(&other), true)
            .expect("assign");
        insert_policy(&store, "unassigned", 1, &sensor_name("s1.example.com"));

        let pulled = |instance: &ModelInstance| {
            super::sampling_policies_for_generator(&store, instance)
                .unwrap()
                .into_iter()
                .map(|policy| policy.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(pulled(&generator), assigned);
        assert_eq!(pulled(&other), [elsewhere]);

        // The sensor of `p2` leaves the customer.
        move_node(&store, sensor_2.node_id, 2, "s2.example.com");
        assert_eq!(pulled(&generator), [assigned[0]]);

        // The generator's node moves to another customer, whose policies
        // these are not, though the sensor of `p1` goes with it.
        move_node(&store, sensor_1.node_id, 2, "s1.example.com");
        move_node(&store, generator.node_id, 2, "g.example.com");
        assert_eq!(pulled(&generator), Vec::<u32>::new());

        let unknown = ModelInstance {
            node_id: 9999,
            agent_key: generator.agent_key.clone(),
        };
        assert_eq!(pulled(&unknown), Vec::<u32>::new());
    }
}
