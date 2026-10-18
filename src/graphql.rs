//! The GraphQL API schema and implementation.
// async-graphql generates async resolvers and enum trait implementations without awaits.
// Remove `unused_async_trait_impl` after async-graphql issue #1832 is fixed and released.
#![allow(clippy::unused_async, clippy::unused_async_trait_impl)]

mod category;
mod cert;
mod cluster;
mod core_component;
pub mod customer;
pub mod customer_access;
mod customer_network;
mod data_source;
mod db_management;
mod event;
mod filter;
pub(crate) mod indicator;
mod install_state;
mod ip_location;
pub(crate) mod label_db;
mod model;
pub(crate) mod network;
mod network_list;
mod node;
mod operation_attempt;
mod outlier;
#[cfg(test)]
mod push_test_support;
mod qualifier;
mod sampling;
mod slicing;
mod statistics;
mod status;
mod tags;
mod template;
mod tor_exit_node;
mod traffic_filter;
mod triage;
mod trusted_domain;
mod trusted_user_agent;

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
#[cfg(test)]
use std::sync::atomic::{AtomicU32, Ordering};

use async_graphql::connection::{
    Connection, ConnectionNameType, CursorType, Edge, EdgeNameType, EmptyFields, OpaqueCursor,
};
use async_graphql::{
    Context, Guard, InputValueError, InputValueResult, MergedObject, MergedSubscription,
    ObjectType, OutputType, Result, Scalar, ScalarType, Value,
};
use num_traits::ToPrimitive;
use review_database::{self as database, Role, Store, event::Direction};
#[cfg(test)]
use review_database::{BuildSelector, ListenerBinding, ListenerTransport, PortOwner};
pub use review_protocol::types::ResourceUsage;
// `review_database::Lifecycle` and `review_protocol::types::node::Lifecycle`
// share a name, so the protocol one is renamed at the import rather than
// glob-imported or shadowed.
#[cfg(test)]
use review_protocol::types::node::{
    BootstrapMaterial, DeliveryMode, FailurePolicy, Lifecycle as ProtocolLifecycle, PackageState,
};
use tokio::sync::Notify;
use tracing::warn;
use vinum::signal;

pub use self::cert::ParsedCertificate;
pub use self::customer::{NetworksTargetAgentLookupKeysPair, get_customer_networks};
pub use self::network_list::{get_allow_networks, get_block_networks};
pub use self::node::{
    agent_lookup_key_service_token, agent_lookup_keys_by_customer_id, gen_agent_lookup_key,
};
pub use self::sampling::{
    Interval as SamplingInterval, Kind as SamplingKind, Period as SamplingPeriod,
    Policy as SamplingPolicy, get_sampling_policies,
};
use crate::backend::{AgentManager, CertManager, HostOnboarder, PackageDeployer};
#[cfg(test)]
use crate::backend::{
    BindAddrInput, BuildId, DeployError, DeployOutcome, HostOnboardingTicket, JoinToken,
    OperationId, RunningRoxydBuild,
};
use crate::maintenance::{MaintenanceExtension, MaintenanceGate};

/// GraphQL schema type.
pub type Schema = async_graphql::Schema<Query, Mutation, Subscription>;

type BoxedAgentManager = Box<dyn AgentManager>;
type BoxedPackageDeployer = Box<dyn PackageDeployer>;
type BoxedHostOnboarder = Box<dyn HostOnboarder>;

/// Builds a GraphQL schema with the given database store as its context.
///
/// The store is stored in `async_graphql::Context` and passed to every
/// GraphQL API function.
// Each argument is a distinct piece of the schema's context supplied by
// `serve`; grouping them into a struct would only restate `serve`'s own
// parameters and `ServerConfig`.
#[allow(clippy::too_many_arguments)]
pub(super) fn schema<B, D, O>(
    store: Arc<RwLock<Store>>,
    agent_manager: B,
    package_deployer: D,
    host_onboarder: O,
    ip_locator: Option<Arc<ip2location::DB>>,
    cert_manager: Arc<dyn CertManager>,
    tls_reload_handle: Arc<Notify>,
    maintenance_gate: MaintenanceGate,
) -> Schema
where
    B: AgentManager + 'static,
    D: PackageDeployer + 'static,
    O: HostOnboarder + 'static,
{
    let agent_manager: BoxedAgentManager = Box::new(agent_manager);
    let package_deployer: BoxedPackageDeployer = Box::new(package_deployer);
    let host_onboarder: BoxedHostOnboarder = Box::new(host_onboarder);
    let mut builder = Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .data(store)
    .data(agent_manager)
    .data(package_deployer)
    .data(host_onboarder)
    .data(cert_manager)
    .data(tls_reload_handle)
    .data(Arc::new(network_list::NetworkListsLock::default()))
    .extension(install_state::LatestBuildMemoExtension)
    .extension(MaintenanceExtension::new(maintenance_gate));
    if let Some(ip_locator) = ip_locator {
        builder = builder.data(ip_locator);
    }
    builder.finish()
}

/// A set of queries defined in the schema.
#[derive(MergedObject, Default)]
pub struct Query(SubQueryOneA, SubQueryOneB, SubQueryTwoA, SubQueryTwoB);

#[derive(MergedObject, Default)]
struct SubQueryOneA(
    category::CategoryQuery,
    cluster::ClusterQuery,
    data_source::DataSourceQuery,
    db_management::DbManagementQuery,
    event::EventQuery,
    event::EventGroupQuery,
);

#[derive(MergedObject, Default)]
struct SubQueryOneB(
    customer_network::CustomerNetworkQuery,
    network_list::NetworkListQuery,
    indicator::IndicatorQuery,
    ip_location::IpLocationQuery,
    model::ModelQuery,
    network::NetworkQuery,
    node::NodeQuery,
    node::NodeStatusQuery,
    qualifier::QualifierQuery,
    outlier::OutlierQuery,
);

#[derive(MergedObject, Default)]
struct SubQueryTwoA(
    sampling::SamplingPolicyQuery,
    statistics::StatisticsQuery,
    status::StatusQuery,
    tags::EventTagQuery,
    tags::WorkflowTagQuery,
    template::TemplateQuery,
    tor_exit_node::TorExitNodeQuery,
    label_db::LabelDbQuery,
);

#[derive(MergedObject, Default)]
struct SubQueryTwoB(
    core_component::CoreComponentQuery,
    operation_attempt::OperationAttemptQuery,
    triage::TriageResponseQuery,
    trusted_domain::TrustedDomainQuery,
    traffic_filter::TrafficFilterQuery,
    trusted_user_agent::UserAgentQuery,
    node::BindAddrQuery,
    node::OnboardingQuery,
);

/// A set of mutations defined in the schema.
#[derive(MergedObject, Default)]
pub struct Mutation(
    SubMutationOneA,
    SubMutationOneB,
    SubMutationTwoA,
    SubMutationTwoB,
);

#[derive(MergedObject, Default)]
struct SubMutationOneA(
    category::CategoryMutation,
    cert::CertMutation,
    cluster::ClusterMutation,
    data_source::DataSourceMutation,
    db_management::DbManagementMutation,
);

#[derive(MergedObject, Default)]
struct SubMutationOneB(
    customer_network::CustomerNetworkMutation,
    network_list::NetworkListMutation,
    indicator::IndicatorMutation,
    model::ModelMutation,
    network::NetworkMutation,
    node::NodeControlMutation,
    node::NodeMutation,
    outlier::OutlierMutation,
);

#[derive(MergedObject, Default)]
struct SubMutationTwoA(
    qualifier::QualifierMutation,
    sampling::SamplingPolicyMutation,
    status::StatusMutation,
    tags::EventTagMutation,
    tags::WorkflowTagMutation,
    template::TemplateMutation,
    tor_exit_node::TorExitNodeMutation,
);

#[derive(MergedObject, Default)]
struct SubMutationTwoB(
    label_db::LabelDbMutation,
    node::DeployMutation,
    triage::TriageResponseMutation,
    trusted_domain::TrustedDomainMutation,
    traffic_filter::TrafficFilterMutation,
    trusted_user_agent::UserAgentMutation,
);

/// A set of subscription defined in the schema.
#[derive(MergedSubscription, Default)]
pub struct Subscription(event::EventStream, outlier::OutlierStream);

#[derive(Debug)]
pub struct ParseEnumError;

async fn query<Name, EdgeName, Cursor, Node, ConnectionFields, F, R, E>(
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
    f: F,
) -> Result<Connection<Cursor, Node, ConnectionFields, EmptyFields, Name, EdgeName>>
where
    Name: ConnectionNameType,
    EdgeName: EdgeNameType,
    Cursor: CursorType + Send + Sync,
    <Cursor as CursorType>::Error: fmt::Display + Send + Sync + 'static,
    Node: OutputType,
    ConnectionFields: ObjectType,
    F: FnOnce(Option<Cursor>, Option<Cursor>, Option<usize>, Option<usize>) -> R,
    R: Future<
        Output = Result<Connection<Cursor, Node, ConnectionFields, EmptyFields, Name, EdgeName>, E>,
    >,
    E: Into<async_graphql::Error>,
{
    let (first, last) = connection_size(after.is_some(), before.is_some(), first, last)?;

    async_graphql::connection::query(after, before, first, last, |after, before, first, last| {
        f(after, before, first, last)
    })
    .await
}

async fn query_with_constraints<Node, ConnectionFields, Name, F, R, E>(
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
    f: F,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Node, ConnectionFields, EmptyFields, Name>>
where
    Node: OutputType,
    ConnectionFields: ObjectType,
    Name: ConnectionNameType,
    F: FnOnce(
        Option<OpaqueCursor<Vec<u8>>>,
        Option<OpaqueCursor<Vec<u8>>>,
        Option<usize>,
        Option<usize>,
    ) -> R,
    R: Future<
        Output = Result<
            Connection<OpaqueCursor<Vec<u8>>, Node, ConnectionFields, EmptyFields, Name>,
            E,
        >,
    >,
    E: Into<async_graphql::Error>,
{
    extra_validate_pagination_params(
        after.is_some(),
        before.is_some(),
        first.is_some(),
        last.is_some(),
    )?;
    let (first, last) = connection_size(after.is_some(), before.is_some(), first, last)?;

    async_graphql::connection::query(after, before, first, last, |after, before, first, last| {
        f(after, before, first, last)
    })
    .await
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("The value of first and last must be within 0-100")]
    InvalidLimitValue,
    #[error("You must provide a `first` or `last` value to properly paginate a connection.")]
    InvalidPaginationArgumentsAfterBefore,
    #[error("`after` and `last` should not be provided at the same time")]
    InvalidPaginationArgumentsAfterLast,
    #[error("`before` and `first` should not be provided at the same time")]
    InvalidPaginationArgumentsBeforeFirst,
    #[error("Missing validation")]
    MissingValidation,
}

const MAX_CONNECTION_SIZE: i32 = 100;

fn connection_size(
    after: bool,
    before: bool,
    first: Option<i32>,
    last: Option<i32>,
) -> Result<(Option<i32>, Option<i32>), Error> {
    match (after, before, first, last) {
        (true, true, None, None) | (_, false, None, None) => Ok((Some(MAX_CONNECTION_SIZE), None)),
        (false, true, None, None) => Ok((None, Some(MAX_CONNECTION_SIZE))),
        (_, _, Some(first), _) => Ok((Some(limit(first)?), None)),
        (_, _, _, Some(last)) => Ok((None, Some(limit(last)?))),
    }
}

fn limit(len: i32) -> Result<i32, Error> {
    if (0..=MAX_CONNECTION_SIZE).contains(&len) {
        Ok(len)
    } else {
        Err(Error::InvalidLimitValue)
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn extra_validate_pagination_params(
    after: bool,
    before: bool,
    first: bool,
    last: bool,
) -> Result<(), Error> {
    match (after, before, first, last) {
        (true, true, _, _) => Err(Error::InvalidPaginationArgumentsAfterBefore),
        (true, _, _, true) => Err(Error::InvalidPaginationArgumentsAfterLast),
        (_, true, true, _) => Err(Error::InvalidPaginationArgumentsBeforeFirst),
        _ => Ok(()),
    }
}

// parameters for trend
const DEFAULT_CUTOFF_RATE: f64 = 0.1;
const DEFAULT_TRENDI_ORDER: i32 = 4;
// 20 is an initial value chosen to limit trend-filter design cost and may be
// changed if the allowed range needs to change.
const MAX_TRENDI_ORDER: i32 = 20;
// One day bounds streaming API update intervals and prevents period overflow.
const MAX_STREAM_FETCH_INTERVAL_SECS: u64 = 86_400;

struct PositiveCutoffRate;

impl async_graphql::validators::CustomValidator<f64> for PositiveCutoffRate {
    fn check(&self, value: &f64) -> Result<(), InputValueError<f64>> {
        if *value > 0.0 {
            Ok(())
        } else {
            Err(InputValueError::custom(format!(
                "the value is {value}, must be greater than 0"
            )))
        }
    }
}

pub(crate) fn get_store<'a>(ctx: &'a Context<'a>) -> Result<std::sync::RwLockReadGuard<'a, Store>> {
    Ok(ctx
        .data::<Arc<RwLock<Store>>>()?
        .read()
        .unwrap_or_else(|e| panic!("RwLock poisoned: {e}")))
}

#[allow(clippy::type_complexity)]
fn process_load_edges<'a, T, I, R>(
    table: &'a T,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    prefix: Option<&[u8]>,
) -> (Vec<anyhow::Result<R>>, bool, bool)
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
{
    let after = after.map(|cursor| cursor.0);
    let before = before.map(|cursor| cursor.0);

    let (nodes, has_previous, has_next) = if let Some(first) = first {
        let (nodes, has_more) =
            collect_edges(table, Direction::Forward, after, before, prefix, first);
        (nodes, false, has_more)
    } else {
        let Some(last) = last else { unreachable!() };
        let (mut nodes, has_more) =
            collect_edges(table, Direction::Reverse, before, after, prefix, last);
        nodes.reverse();
        (nodes, has_more, false)
    };

    (nodes, has_previous, has_next)
}

pub(crate) fn process_load_edges_filtered<'a, T, I, R, P>(
    table: &'a T,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    prefix: Option<&[u8]>,
    predicate: P,
) -> (Vec<anyhow::Result<R>>, bool, bool)
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
    P: Fn(&R) -> bool,
{
    let after = after.map(|cursor| cursor.0);
    let before = before.map(|cursor| cursor.0);

    let (nodes, has_previous, has_next) = if let Some(first) = first {
        let (nodes, has_more) = collect_edges_filtered(
            table,
            Direction::Forward,
            after,
            before,
            prefix,
            first,
            &predicate,
        );
        (nodes, false, has_more)
    } else {
        let Some(last) = last else { unreachable!() };
        let (mut nodes, has_more) = collect_edges_filtered(
            table,
            Direction::Reverse,
            before,
            after,
            prefix,
            last,
            &predicate,
        );
        nodes.reverse();
        (nodes, has_more, false)
    };

    (nodes, has_previous, has_next)
}

fn load_edges_interim<'a, T, I, R>(
    table: &'a T,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    prefix: Option<&[u8]>,
) -> Result<(Vec<R>, bool, bool)>
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
{
    let (nodes, has_previous, has_next) =
        process_load_edges(table, after, before, first, last, prefix);

    let nodes = nodes
        .into_iter()
        .map(|res| res.map_err(|e| format!("{e}").into()))
        .collect::<Result<Vec<_>>>()?;
    Ok((nodes, has_previous, has_next))
}

#[allow(clippy::type_complexity)]
fn load_edges<'a, T, I, R, N, A, NodesField>(
    table: &'a T,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    additional_fields: A,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, N, A, EmptyFields, NodesField>>
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
    N: From<R> + OutputType,
    A: ObjectType,
    NodesField: ConnectionNameType,
{
    let (nodes, has_previous, has_next) =
        process_load_edges(table, after, before, first, last, None);

    for node in &nodes {
        let Err(e) = node else { continue };
        warn!("Failed to load from DB: {}", e);
        return Err("database error".into());
    }

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, additional_fields);
    connection.edges.extend(nodes.into_iter().map(|node| {
        let Ok(node) = node else { unreachable!() };
        let key = node.unique_key().as_ref().to_vec();
        Edge::new(OpaqueCursor(key), node.into())
    }));
    Ok(connection)
}

fn collect_edges<'a, T, I, R>(
    table: &'a T,
    dir: Direction,
    from: Option<Vec<u8>>,
    to: Option<Vec<u8>>,
    prefix: Option<&[u8]>,
    count: usize,
) -> (Vec<anyhow::Result<R>>, bool)
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
{
    let edges: Box<dyn Iterator<Item = _>> = if let Some(cursor) = from {
        let iter = if let Some(prefix) = prefix {
            (*table).prefix_iter(dir, Some(&cursor), prefix)
        } else {
            (*table).iter(dir, Some(&cursor))
        };
        let mut edges: Box<dyn Iterator<Item = _>> = Box::new(iter.skip_while(move |item| {
            if let Ok(x) = item {
                x.unique_key().as_ref() == cursor.as_slice()
            } else {
                false
            }
        }));
        if let Some(cursor) = to {
            edges = Box::new(edges.take_while(move |item| {
                if let Ok(x) = item {
                    x.unique_key().as_ref() < cursor.as_slice()
                } else {
                    false
                }
            }));
        }
        edges
    } else {
        let iter = if let Some(prefix) = prefix {
            (*table).prefix_iter(dir, None, prefix)
        } else {
            (*table).iter(dir, None)
        };
        let mut edges: Box<dyn Iterator<Item = _>> = Box::new(iter);
        if let Some(cursor) = to {
            edges = Box::new(edges.take_while(move |item| {
                if let Ok(x) = item {
                    x.unique_key().as_ref() < cursor.as_slice()
                } else {
                    false
                }
            }));
        }
        edges
    };
    let mut nodes = edges.take(count + 1).collect::<Vec<_>>();
    let has_more = nodes.len() > count;
    if has_more {
        nodes.pop();
    }
    (nodes, has_more)
}

fn collect_edges_filtered<'a, T, I, R, P>(
    table: &'a T,
    dir: Direction,
    from: Option<Vec<u8>>,
    to: Option<Vec<u8>>,
    prefix: Option<&[u8]>,
    count: usize,
    predicate: &P,
) -> (Vec<anyhow::Result<R>>, bool)
where
    T: database::Iterable<'a, I>,
    I: Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
    P: Fn(&R) -> bool,
{
    let edges: Box<dyn Iterator<Item = _>> = if let Some(cursor) = from {
        let iter = if let Some(prefix) = prefix {
            (*table).prefix_iter(dir, Some(&cursor), prefix)
        } else {
            (*table).iter(dir, Some(&cursor))
        };
        let mut edges: Box<dyn Iterator<Item = _>> = Box::new(iter.skip_while(move |item| {
            if let Ok(x) = item {
                x.unique_key().as_ref() == cursor.as_slice()
            } else {
                false
            }
        }));
        if let Some(cursor) = to {
            edges = Box::new(edges.take_while(move |item| {
                if let Ok(x) = item {
                    x.unique_key().as_ref() < cursor.as_slice()
                } else {
                    false
                }
            }));
        }
        edges
    } else if let Some(cursor) = to {
        let iter = if let Some(prefix) = prefix {
            (*table).prefix_iter(dir, None, prefix)
        } else {
            (*table).iter(dir, None)
        };
        Box::new(iter.take_while(move |item| {
            if let Ok(x) = item {
                x.unique_key().as_ref() < cursor.as_slice()
            } else {
                false
            }
        }))
    } else {
        let iter = if let Some(prefix) = prefix {
            (*table).prefix_iter(dir, None, prefix)
        } else {
            (*table).iter(dir, None)
        };
        let mut edges: Box<dyn Iterator<Item = _>> = Box::new(iter);
        if let Some(cursor) = to {
            edges = Box::new(edges.take_while(move |item| {
                if let Ok(x) = item {
                    x.unique_key().as_ref() < cursor.as_slice()
                } else {
                    false
                }
            }));
        }
        edges
    };

    let mut nodes = edges
        .filter(|item| match item {
            Ok(node) => predicate(node),
            Err(_) => true, // Errors will be handled by the caller
        })
        .take(count + 1)
        .collect::<Vec<_>>();
    let has_more = nodes.len() > count;
    if has_more {
        nodes.pop();
    }
    (nodes, has_more)
}

#[derive(Debug, PartialEq)]
pub(crate) enum RoleGuard {
    Role(database::Role),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerIds(pub Option<Vec<u32>>);

impl RoleGuard {
    fn new(role: database::Role) -> Self {
        Self::Role(role)
    }
}

impl Guard for RoleGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        if ctx.data_opt::<Self>() == Some(self) {
            Ok(())
        } else {
            Err("Forbidden".into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddress(pub IpAddr);

#[Scalar]
impl ScalarType for IpAddress {
    fn parse(value: Value) -> InputValueResult<Self> {
        match value {
            Value::String(s) => s
                .parse::<IpAddr>()
                .map(IpAddress)
                .map_err(|_| InputValueError::custom(format!("Invalid IP address: {s}"))),
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.0.to_string())
    }
}

type TimeCount = (i64, usize); // (utc_timestamp_nano, count)

// Validate even two-point series, which do not otherwise need filling.
fn minimum_time_interval(series: &[TimeCount]) -> anyhow::Result<Option<i64>> {
    series.windows(2).try_fold(None, |minimum, pair| {
        let interval = pair[1]
            .0
            .checked_sub(pair[0].0)
            .ok_or_else(|| anyhow::anyhow!("timestamp interval overflow"))?;
        anyhow::ensure!(
            interval > 0,
            "timestamps must be strictly increasing (no duplicates)"
        );
        Ok(Some(
            minimum.map_or(interval, |value: i64| value.min(interval)),
        ))
    })
}

fn zero_filled_length(series: &[TimeCount]) -> anyhow::Result<u128> {
    let interval = minimum_time_interval(series)?;
    let mut length = u128::try_from(series.len())?;
    if series.len() >= 3
        && let Some(interval) = interval
    {
        for pair in series.windows(2) {
            // Subtraction and ordering were checked by minimum_time_interval.
            let slots = (pair[1].0 - pair[0].0) / interval;
            length += u128::try_from(slots - 1)?;
        }
    }
    Ok(length)
}

fn fill_vacant_time_slots(series: &[TimeCount]) -> anyhow::Result<Vec<TimeCount>> {
    let length = usize::try_from(zero_filled_length(series)?)?;
    let mut filled = Vec::new();
    filled.try_reserve_exact(length)?;
    let interval = minimum_time_interval(series)?;
    for (index, element) in series.iter().enumerate() {
        if series.len() >= 3
            && index > 0
            && let Some(interval) = interval
        {
            let previous = series[index - 1].0;
            let slots = (element.0 - previous) / interval;
            for slot in 1..slots {
                let offset = slot
                    .checked_mul(interval)
                    .ok_or_else(|| anyhow::anyhow!("timestamp offset overflow"))?;
                let time = previous
                    .checked_add(offset)
                    .ok_or_else(|| anyhow::anyhow!("filled timestamp overflow"))?;
                filled.push((time, 0));
            }
        }
        filled.push(*element);
    }
    Ok(filled)
}

fn get_trend(
    series: &[TimeCount],
    cutoff_rate: f64,
    trendi_order: i32,
) -> Result<Vec<f64>, vinum::InvalidInput> {
    let original: Vec<f64> = series
        .iter()
        .map(|s| s.1.to_f64().expect("safe: usize -> f64"))
        .collect();
    let cutoff_len = cutoff_rate * original.len().to_f64().expect("safe: usize -> f64");
    let cutoff_frequency = 1.0 / cutoff_len;
    let sections = signal::filter::design::butter(trendi_order, cutoff_frequency)?;
    signal::filter::filtfilt(&sections, &original)
}

#[cfg(test)]
struct MockAgentManager {}

#[cfg(test)]
#[async_trait::async_trait]
impl AgentManager for MockAgentManager {
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[customer::NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec!["semi-supervised@hostA".to_string()])
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[customer::NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec![
            "semi-supervised@hostA".to_string(),
            "semi-supervised@hostB".to_string(),
        ])
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[customer::NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec![
            "semi-supervised@hostA".to_string(),
            "semi-supervised@hostB".to_string(),
            "semi-supervised@hostC".to_string(),
        ])
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(std::collections::HashMap::new())
    }

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    // The mock host advertises the rollback supervisor, so the deployment
    // mutations' default `ROLLBACK` is not refused by the capability gate. A
    // test about the gate itself substitutes its own manager.
    async fn capabilities(
        &self,
        _hostname: &str,
    ) -> Result<std::collections::BTreeSet<String>, anyhow::Error> {
        Ok(
            std::iter::once(review_protocol::types::capability::ROLLBACK_SUPERVISOR.to_string())
                .collect(),
        )
    }

    // A mock host reports no resource usage and answers no ping. Both are
    // errors rather than `unimplemented!()` because the status read path calls
    // them for every node it renders and discards the failure, so a panic here
    // would make `nodeStatusList` untestable through this schema for reasons
    // that have nothing to do with what a test is asserting.
    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        anyhow::bail!("the mock host reports no resource usage")
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn ping(&self, _hostname: &str) -> Result<std::time::Duration, anyhow::Error> {
        anyhow::bail!("the mock host answers no ping")
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
}

/// What a [`MockPackageDeployer`] does with the four operations that fail with
/// [`DeployError`].
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MockDeployFailure {
    /// Every operation succeeds.
    #[default]
    None,
    PortAllocationConflict,
    HostPortOccupied,
    HostOccupancyUnavailable,
    RequestKey,
    CleanupPending,
    BuildNotServable,
    /// An arbitrary `anyhow::Error`, which reaches the caller as
    /// [`DeployError::Other`] through `?` rather than by being named.
    Arbitrary,
}

/// Fails with an arbitrary `anyhow::Error`, so that a caller's `?` is what
/// turns it into [`DeployError::Other`].
#[cfg(test)]
fn arbitrary_deploy_failure() -> Result<(), anyhow::Error> {
    Err(anyhow::anyhow!(
        "the host answered something this stub does not model"
    ))
}

/// The `latest_build` answers a [`MockPackageDeployer`] gives, and the record
/// of what it was asked.
///
/// A test holds an `Arc` of the same stub it hands the schema, so it can read
/// the call log back afterwards: the read path promises one lookup per
/// package-id per query however many rows carry that package, and only a
/// counting stub can hold it to that.
#[cfg(test)]
#[derive(Default)]
struct LatestBuildStub {
    /// The newest accepted build of each package-id. A package-id absent from
    /// the map and from `failing` answers `Ok(None)`.
    answers: std::collections::HashMap<String, BuildId>,
    /// The package-ids whose lookup fails.
    failing: std::collections::HashSet<String>,
    /// Every package-id asked about, in the order it was asked.
    calls: std::sync::Mutex<Vec<String>>,
    /// The package-ids whose lookup parks until the test releases it, which is
    /// how a test holds one package's lookup open while another runs.
    gates: std::collections::HashMap<String, Arc<tokio::sync::Notify>>,
}

#[cfg(test)]
impl LatestBuildStub {
    fn with_answer(mut self, package_id: &str, version: &str, commit: &str) -> Self {
        self.answers.insert(
            package_id.to_string(),
            BuildId {
                version: version.to_string(),
                commit: commit.to_string(),
            },
        );
        self
    }

    fn with_failure(mut self, package_id: &str) -> Self {
        self.failing.insert(package_id.to_string());
        self
    }

    /// Parks the lookup of `package_id` until `gate` is notified.
    fn with_gate(mut self, package_id: &str, gate: Arc<tokio::sync::Notify>) -> Self {
        self.gates.insert(package_id.to_string(), gate);
        self
    }

    async fn latest_build(&self, package_id: &str) -> Result<Option<BuildId>, anyhow::Error> {
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .push(package_id.to_string());
        if let Some(gate) = self.gates.get(package_id) {
            gate.notified().await;
        }
        if self.failing.contains(package_id) {
            anyhow::bail!("the build store could not be read");
        }
        Ok(self.answers.get(package_id).cloned())
    }

    /// Returns how many times `package_id` was asked about.
    fn calls(&self, package_id: &str) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .iter()
            .filter(|asked| asked.as_str() == package_id)
            .count()
    }

    /// Returns how many lookups were made in total.
    fn total_calls(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .len()
    }
}

/// The `is_build_withdrawn` answers a [`MockPackageDeployer`] gives, and the
/// record of what it was asked.
///
/// It is a sibling of [`LatestBuildStub`] rather than part of it, so that each
/// call log counts one method and a test can tell the two checks apart. A
/// build absent from `withdrawn` and `failing` answers `Ok(false)`.
#[cfg(test)]
#[derive(Default)]
struct WithdrawalStub {
    /// The `(package-id, version, commit)` triples that are withdrawn.
    withdrawn: std::collections::HashSet<(String, String, String)>,
    /// The `(package-id, version, commit)` triples whose check fails.
    failing: std::collections::HashSet<(String, String, String)>,
    /// Every `(package-id, version, commit)` asked about, in the order it was
    /// asked.
    calls: std::sync::Mutex<Vec<(String, String, String)>>,
    /// The triples whose check parks until the test releases it.
    gates: std::collections::HashMap<(String, String, String), Arc<tokio::sync::Notify>>,
}

#[cfg(test)]
impl WithdrawalStub {
    fn key(package_id: &str, version: &str, commit: &str) -> (String, String, String) {
        (
            package_id.to_string(),
            version.to_string(),
            commit.to_string(),
        )
    }

    fn with_withdrawn(mut self, package_id: &str, version: &str, commit: &str) -> Self {
        self.withdrawn
            .insert(Self::key(package_id, version, commit));
        self
    }

    fn with_failure(mut self, package_id: &str, version: &str, commit: &str) -> Self {
        self.failing.insert(Self::key(package_id, version, commit));
        self
    }

    /// Parks the check of the given build until `gate` is notified.
    fn with_gate(
        mut self,
        package_id: &str,
        version: &str,
        commit: &str,
        gate: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.gates
            .insert(Self::key(package_id, version, commit), gate);
        self
    }

    async fn is_build_withdrawn(
        &self,
        package_id: &str,
        build: &BuildId,
    ) -> Result<bool, anyhow::Error> {
        let key = Self::key(package_id, &build.version, &build.commit);
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .push(key.clone());
        if let Some(gate) = self.gates.get(&key) {
            gate.notified().await;
        }
        if self.failing.contains(&key) {
            anyhow::bail!("the trust tree could not be read");
        }
        Ok(self.withdrawn.contains(&key))
    }

    /// Returns how many times the given build was asked about.
    fn calls(&self, package_id: &str, version: &str, commit: &str) -> usize {
        let key = Self::key(package_id, version, commit);
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .iter()
            .filter(|asked| **asked == key)
            .count()
    }

    /// Returns how many checks were made in total.
    fn total_calls(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
            .len()
    }
}

#[cfg(test)]
#[derive(Default)]
struct MockPackageDeployer {
    failure: MockDeployFailure,
    builds: Arc<LatestBuildStub>,
    withdrawals: Arc<WithdrawalStub>,
}

#[cfg(test)]
impl MockPackageDeployer {
    fn failing(failure: MockDeployFailure) -> Self {
        Self {
            failure,
            ..Self::default()
        }
    }

    /// Builds a deployer answering `latest_build` from the given stub.
    fn with_builds(builds: Arc<LatestBuildStub>) -> Self {
        Self {
            builds,
            ..Self::default()
        }
    }

    /// Answers `is_build_withdrawn` from the given stub rather than with
    /// `Ok(false)` for every build.
    fn with_withdrawals(mut self, withdrawals: Arc<WithdrawalStub>) -> Self {
        self.withdrawals = withdrawals;
        self
    }

    fn check(&self) -> Result<(), DeployError> {
        match self.failure {
            MockDeployFailure::None => Ok(()),
            MockDeployFailure::PortAllocationConflict => Err(DeployError::PortAllocationConflict {
                host: "host1".to_string(),
                transport: ListenerTransport::Tcp,
                port: 38_370,
                owner: PortOwner {
                    component: "giganto".to_string(),
                    instance: 1,
                    listener_key: "ingest".to_string(),
                },
            }),
            MockDeployFailure::HostPortOccupied => Err(DeployError::HostPortOccupied {
                listener_key: "ingest".to_string(),
                transport: ListenerTransport::Udp,
                port: 38_371,
            }),
            MockDeployFailure::HostOccupancyUnavailable => {
                Err(DeployError::HostOccupancyUnavailable {
                    host: "host1".to_string(),
                    reason: "the host did not answer".to_string(),
                })
            }
            MockDeployFailure::RequestKey => Err(DeployError::RequestKey(
                review_database::RequestKeyError::MalformedRequestKey {
                    request_key: "not-a-uuid".to_string(),
                },
            )),
            MockDeployFailure::CleanupPending => Err(DeployError::CleanupPending {
                host: "host1".to_string(),
                target: "giganto".to_string(),
                instance: Some(1),
                operation_id: OperationId::new("b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e".to_string()),
            }),
            MockDeployFailure::BuildNotServable => Err(DeployError::BuildNotServable {
                target: "giganto".to_string(),
            }),
            MockDeployFailure::Arbitrary => {
                arbitrary_deploy_failure()?;
                Ok(())
            }
        }
    }

    fn operation_id() -> OperationId {
        OperationId::new("11111111-2222-4333-8444-555555555555".to_string())
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl PackageDeployer for MockPackageDeployer {
    async fn install(
        &self,
        _host: &str,
        _target: &str,
        _selector: BuildSelector,
        _on_failure: FailurePolicy,
        _bind_addrs: Option<Vec<BindAddrInput>>,
        _config_template: Option<String>,
        _request_key: &str,
    ) -> Result<(DeployOutcome, OperationId), DeployError> {
        self.check()?;
        Ok((DeployOutcome::Applied, Self::operation_id()))
    }

    async fn update(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
        _selector: BuildSelector,
        _on_failure: FailurePolicy,
    ) -> Result<(DeployOutcome, OperationId), DeployError> {
        self.check()?;
        Ok((DeployOutcome::Accepted, Self::operation_id()))
    }

    async fn remove(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<OperationId, DeployError> {
        self.check()?;
        Ok(Self::operation_id())
    }

    async fn recommend_bind_addrs(
        &self,
        _host: &str,
        _target: &str,
    ) -> Result<Vec<ListenerBinding>, DeployError> {
        self.check()?;
        Ok(vec![ListenerBinding {
            listener_key: "ingest".to_string(),
            transport: ListenerTransport::Tcp,
            addr: SocketAddr::from(([127, 0, 0, 1], 38_370)),
        }])
    }

    // Answers from the stub the deployer was built with, which holds no build
    // at all unless a test put one there.
    async fn latest_build(&self, target: &str) -> Result<Option<BuildId>, anyhow::Error> {
        self.builds.latest_build(target).await
    }

    async fn config_templates(
        &self,
        _target: &str,
    ) -> Result<crate::backend::ConfigTemplateCatalog, anyhow::Error> {
        Ok(crate::backend::ConfigTemplateCatalog {
            required: false,
            templates: vec![],
        })
    }

    // Answers from the same stub, so that the list's first entry is the build
    // `latest_build` returns. It leaves the stub's call log alone: that log
    // counts `latest_build` lookups only.
    async fn servable_builds(&self, target: &str) -> Result<Vec<BuildId>, anyhow::Error> {
        if self.builds.failing.contains(target) {
            anyhow::bail!("the build store could not be read");
        }
        Ok(self
            .builds
            .answers
            .get(target)
            .cloned()
            .into_iter()
            .collect())
    }

    // Answers from the withdrawal stub, which withdraws nothing unless a test
    // put a build there.
    async fn is_build_withdrawn(
        &self,
        target: &str,
        build: &BuildId,
    ) -> Result<bool, anyhow::Error> {
        self.withdrawals.is_build_withdrawn(target, build).await
    }

    async fn package_status(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<PackageState, anyhow::Error> {
        Ok(PackageState {
            version: "0.1.0".to_string(),
            commit: "0123456789abcdef".to_string(),
            lifecycle: ProtocolLifecycle::Running,
            bound_addrs: vec![],
        })
    }

    async fn read_version(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<Option<BuildId>, anyhow::Error> {
        Ok(None)
    }

    async fn register(
        &self,
        _service_name: &str,
        _host: &str,
        _instance: Option<u32>,
        _mode: DeliveryMode,
    ) -> Result<BootstrapMaterial, anyhow::Error> {
        Ok(BootstrapMaterial {
            role_id: "giganto".to_string(),
            wrapped_secret_id: "wrapped".to_string(),
            ca_anchor: vec![0x30, 0x82],
            expires_at: jiff::Timestamp::from_second(1_700_000_000)?,
            bootstrap_artifact: br#"{"registration_id":"giganto"}"#.to_vec(),
        })
    }

    async fn deregister(
        &self,
        _service_name: &str,
        _host: &str,
        _instance: Option<u32>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

#[cfg(test)]
struct MockHostOnboarder {}

#[cfg(test)]
#[async_trait::async_trait]
impl HostOnboarder for MockHostOnboarder {
    async fn running_roxyd_builds(&self) -> Result<Vec<RunningRoxydBuild>, anyhow::Error> {
        Ok(vec![])
    }

    async fn onboard_host(
        &self,
        _host: &str,
        _build: &BuildId,
    ) -> Result<(HostOnboardingTicket, OperationId), anyhow::Error> {
        Ok((
            HostOnboardingTicket::new(
                JoinToken::new("s3cret-join-token".to_string()),
                "roxyd join --token <token>".to_string(),
                jiff::Timestamp::from_second(1_700_000_000)?,
                "clumit-security".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            OperationId::new("99999999-8888-4777-8666-555555555555".to_string()),
        ))
    }
}

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir,        // to delete the data directory when dropped
    _backup_dir: tempfile::TempDir, // to delete the backup directory when dropped
    store: Arc<RwLock<Store>>,
    schema: Schema,
    test_addr: Option<SocketAddr>, // to simulate the client address
    next_customer_id: AtomicU32,   // handed out by `setup_customer_and_node`
    network_lists_lock: Arc<network_list::NetworkListsLock>,
}

#[cfg(test)]
impl TestSchema {
    async fn new() -> Self {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        Self::new_with_params(agent_manager, None, "testuser").await
    }

    async fn new_with_event_country_locator(locator: Arc<ip2location::DB>) -> Self {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        Self::new_with_params_and_event_country_locator(
            agent_manager,
            None,
            "testuser",
            Some(locator),
        )
        .await
    }

    async fn new_with_params(
        agent_manager: BoxedAgentManager,
        test_addr: Option<SocketAddr>,
        username: &str,
    ) -> Self {
        Self::new_with_params_and_event_country_locator(agent_manager, test_addr, username, None)
            .await
    }

    /// Builds a schema whose package deployer is the given one.
    ///
    /// The install-state read path drives `latest_build` through the deployer,
    /// so a test that exercises it substitutes a stub here rather than taking
    /// the default one's answers.
    async fn new_with_package_deployer(package_deployer: BoxedPackageDeployer) -> Self {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        Self::new_with_all(agent_manager, package_deployer, None, "testuser", None).await
    }

    async fn new_with_params_and_event_country_locator(
        agent_manager: BoxedAgentManager,
        test_addr: Option<SocketAddr>,
        username: &str,
        event_country_locator: Option<Arc<ip2location::DB>>,
    ) -> Self {
        Self::new_with_all(
            agent_manager,
            Box::new(MockPackageDeployer::default()),
            test_addr,
            username,
            event_country_locator,
        )
        .await
    }

    async fn new_with_all(
        agent_manager: BoxedAgentManager,
        package_deployer: BoxedPackageDeployer,
        test_addr: Option<SocketAddr>,
        username: &str,
        event_country_locator: Option<Arc<ip2location::DB>>,
    ) -> Self {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), event_country_locator).unwrap();
        let store = Arc::new(RwLock::new(store));
        let network_lists_lock = Arc::new(network_list::NetworkListsLock::default());

        let builder = Schema::build(
            Query::default(),
            Mutation::default(),
            Subscription::default(),
        )
        .data(agent_manager)
        .data(package_deployer)
        .data(Box::new(MockHostOnboarder {}) as Box<dyn HostOnboarder>)
        .data(store.clone())
        .data(username.to_string())
        .data(network_lists_lock.clone())
        .extension(install_state::LatestBuildMemoExtension)
        .extension(MaintenanceExtension::new(MaintenanceGate::new()));
        let schema = builder.finish();

        Self {
            _dir: db_dir,
            _backup_dir: backup_dir,
            store,
            schema,
            test_addr,
            next_customer_id: AtomicU32::new(0),
            network_lists_lock,
        }
    }

    fn store(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.store
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"))
    }

    /// Returns how many operations hold or wait for the network lists lock.
    fn network_lists_lock_users(&self) -> usize {
        self.network_lists_lock.users()
    }

    async fn execute_as_system_admin(&self, query: &str) -> async_graphql::Response {
        self.execute_with_guard(query, RoleGuard::Role(Role::SystemAdministrator))
            .await
    }

    async fn execute_with_guard(&self, query: &str, guard: RoleGuard) -> async_graphql::Response {
        self.execute_with_context(query, guard, None).await
    }

    async fn execute_with_guard_and_data(
        &self,
        query: &str,
        guard: RoleGuard,
        data: impl Send + Sync + 'static,
    ) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        let request = self.request_with_context(request, guard, None).data(data);
        self.schema.execute(request).await
    }

    async fn execute_as_system_admin_with_data(
        &self,
        query: &str,
        data: impl Send + Sync + 'static,
    ) -> async_graphql::Response {
        self.execute_with_guard_and_data(query, RoleGuard::Role(Role::SystemAdministrator), data)
            .await
    }

    /// Executes a query with the given role guard and optional `CustomerIds`.
    async fn execute_with_context(
        &self,
        query: &str,
        guard: RoleGuard,
        customer_ids: Option<CustomerIds>,
    ) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        let request = self.request_with_context(request, guard, customer_ids);
        self.schema.execute(request).await
    }

    async fn execute_as_scoped_user(
        &self,
        query: &str,
        role: Role,
        customer_ids: Option<Vec<u32>>,
    ) -> async_graphql::Response {
        self.execute_with_context(
            query,
            RoleGuard::Role(role),
            Some(CustomerIds(customer_ids)),
        )
        .await
    }

    /// Executes a query as a scoped user with one extra piece of request-scoped
    /// data.
    ///
    /// Request data wins over schema data of the same type, which is what lets
    /// a test substitute its own stub for one the test schema already carries.
    async fn execute_as_scoped_user_with_data(
        &self,
        query: &str,
        role: Role,
        customer_ids: Option<Vec<u32>>,
        data: impl Send + Sync + 'static,
    ) -> async_graphql::Response {
        {
            let request: async_graphql::Request = query.into();
            let request = self
                .request_with_context(
                    request,
                    RoleGuard::Role(role),
                    Some(CustomerIds(customer_ids)),
                )
                .data(data);
            self.schema.execute(request).await
        }
    }

    /// Allocates a customer ID and creates an applied node with the provided
    /// hostname for it.
    ///
    /// Customer IDs are handed out as `0`, `1`, … in call order. Returns the
    /// allocated customer ID.
    async fn setup_customer_and_node(&self, _customer_name: &str, hostname: &str) -> String {
        let cid = self
            .next_customer_id
            .fetch_add(1, Ordering::Relaxed)
            .to_string();

        let query = format!(
            r#"mutation {{
                insertNode(
                    name: "{hostname}"
                    customerId: {cid}
                    description: ""
                    hostname: "{hostname}"
                    agents: []
                    externalServices: []
                )
            }}"#,
        );
        let res = self.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "insert node: {:?}", res.errors);
        let node_id = res
            .data
            .to_string()
            .split('"')
            .nth(1)
            .expect("node insert response always contains a quoted id")
            .to_string();

        let query = format!(
            r#"mutation {{
                applyNode(
                    id: "{node_id}"
                    node: {{
                        name: "{hostname}"
                        nameDraft: "{hostname}"
                        profileDraft: {{ customerId: {cid}, description: "", hostname: "{hostname}" }}
                        agents: []
                        externalServices: []
                    }}
                )
            }}"#,
        );
        let res = self.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "apply node: {:?}", res.errors);

        cid
    }

    fn request_with_guard(
        &self,
        request: async_graphql::Request,
        guard: RoleGuard,
    ) -> async_graphql::Request {
        let request = if let Some(addr) = self.test_addr {
            request.data(addr)
        } else {
            request
        };
        request.data(guard)
    }

    fn request_with_context(
        &self,
        request: async_graphql::Request,
        guard: RoleGuard,
        customer_ids: Option<CustomerIds>,
    ) -> async_graphql::Request {
        let request = self.request_with_guard(request, guard);
        if let Some(customer_ids) = customer_ids {
            request.data(customer_ids)
        } else {
            request
        }
    }

    async fn execute_stream(
        &self,
        subscription: &str,
    ) -> impl futures_util::Stream<Item = async_graphql::Response> + use<'_> {
        let request: async_graphql::Request = subscription.into();
        self.schema
            .execute_stream(request.data(RoleGuard::Role(Role::SystemAdministrator)))
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentManager, Direction, MockPackageDeployer, OpaqueCursor, TestSchema, database};

    #[test]
    fn vacant_slots_use_nanoseconds() {
        for (times, expected) in [
            (vec![], vec![]),
            (vec![1], vec![1]),
            (vec![0, 4], vec![0, 4]),
            (
                vec![0, 60_000_000_000, 180_000_000_000],
                vec![0, 60_000_000_000, 120_000_000_000, 180_000_000_000],
            ),
            (
                vec![0, 1_900_000_000, 5_700_000_000],
                vec![0, 1_900_000_000, 3_800_000_000, 5_700_000_000],
            ),
            (
                vec![0, 500_000_000, 1_500_000_000, 2_500_000_000],
                vec![
                    0,
                    500_000_000,
                    1_000_000_000,
                    1_500_000_000,
                    2_000_000_000,
                    2_500_000_000,
                ],
            ),
            (
                vec![0, 2_000_000_000, 7_000_000_000],
                vec![0, 2_000_000_000, 4_000_000_000, 7_000_000_000],
            ),
        ] {
            let series: Vec<_> = times.iter().map(|&time| (time, 7)).collect();
            let filled = super::fill_vacant_time_slots(&series).unwrap();
            assert_eq!(
                super::zero_filled_length(&series).unwrap(),
                u128::try_from(filled.len()).unwrap()
            );
            assert_eq!(
                filled.iter().map(|point| point.0).collect::<Vec<_>>(),
                expected
            );
            for point in filled {
                assert_eq!(point.1, if times.contains(&point.0) { 7 } else { 0 });
            }
        }
    }

    #[test]
    fn vacant_slots_reject_invalid_timestamps() {
        for times in [
            vec![0, 0],
            vec![1, 0],
            vec![0, 1, 1],
            vec![0, 2, 1],
            vec![i64::MIN, 0, i64::MAX],
            vec![i64::MIN, i64::MAX],
        ] {
            let series: Vec<_> = times.into_iter().map(|time| (time, 1)).collect();
            assert!(super::zero_filled_length(&series).is_err());
            assert!(super::fill_vacant_time_slots(&series).is_err());
        }
    }

    #[test]
    fn trend_is_finite_for_large_cutoff_rates() {
        let series = vec![(0, 1); 100];
        for (order, cutoff_rate) in [(3, 10_000.0), (8, 40.0)] {
            let result = std::panic::catch_unwind(|| super::get_trend(&series, cutoff_rate, order));
            let trend = result.expect("trend computation must not panic").unwrap();
            assert_eq!(trend.len(), 100);
            assert!(trend.iter().all(|value| value.is_finite()));
        }
    }

    #[test]
    fn trend_rejects_cutoff_products_at_or_below_one() {
        let series = vec![(0, 1); 20];
        for cutoff_rate in [0.01, 0.05] {
            assert!(super::get_trend(&series, cutoff_rate, 4).is_err());
        }
        let trend = super::get_trend(&series, 0.1, 4).unwrap();
        assert_eq!(trend.len(), 20);
    }

    #[test]
    fn trend_is_finite_at_order_boundaries() {
        let series = vec![(0, 1); 100];
        for order in [1, 20] {
            let trend = super::get_trend(&series, 0.1, order).unwrap();
            assert_eq!(trend.len(), 100);
            assert!(trend.iter().all(|value| value.is_finite()));
        }
    }

    #[derive(Clone, Debug)]
    struct MockRow {
        key: Vec<u8>,
        value: u32,
    }

    impl database::UniqueKey for MockRow {
        type AsBytes<'a> = Vec<u8>;

        fn unique_key(&self) -> Self::AsBytes<'_> {
            self.key.clone()
        }
    }

    struct MockTable {
        rows: Vec<MockRow>,
    }

    impl MockTable {
        fn new(values: &[u32]) -> Self {
            let rows = values
                .iter()
                .map(|&value| MockRow {
                    key: value.to_be_bytes().to_vec(),
                    value,
                })
                .collect();
            Self { rows }
        }
    }

    impl<'i> database::Iterable<'i, std::vec::IntoIter<anyhow::Result<MockRow>>> for MockTable {
        fn iter(
            &'i self,
            direction: Direction,
            from: Option<&[u8]>,
        ) -> std::vec::IntoIter<anyhow::Result<MockRow>> {
            let mut rows = self.rows.clone();
            rows.sort_by(|a, b| a.key.cmp(&b.key));
            if let Some(from) = from {
                rows.retain(|row| match direction {
                    Direction::Forward => row.key.as_slice() >= from,
                    Direction::Reverse => row.key.as_slice() <= from,
                });
            }
            if matches!(direction, Direction::Reverse) {
                rows.reverse();
            }
            rows.into_iter().map(Ok).collect::<Vec<_>>().into_iter()
        }

        fn prefix_iter(
            &'i self,
            direction: Direction,
            from: Option<&[u8]>,
            prefix: &[u8],
        ) -> std::vec::IntoIter<anyhow::Result<MockRow>> {
            let mut rows: Vec<MockRow> = self
                .rows
                .iter()
                .filter(|&row| row.key.starts_with(prefix))
                .cloned()
                .collect();
            rows.sort_by(|a, b| a.key.cmp(&b.key));
            if let Some(from) = from {
                rows.retain(|row| match direction {
                    Direction::Forward => row.key.as_slice() >= from,
                    Direction::Reverse => row.key.as_slice() <= from,
                });
            }
            if matches!(direction, Direction::Reverse) {
                rows.reverse();
            }
            rows.into_iter().map(Ok).collect::<Vec<_>>().into_iter()
        }
    }

    struct PaginationCase {
        table_values: Vec<u32>,
        after: Option<u32>,
        before: Option<u32>,
        first: Option<usize>,
        last: Option<usize>,
        predicate: Box<dyn Fn(&MockRow) -> bool>,
        expected_values: Vec<u32>,
        expected_has_previous: bool,
        expected_has_next: bool,
    }

    impl std::fmt::Display for PaginationCase {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "\ntable_values: {:?}, after: {:?}, before: {:?}, first: {:?}, last: {:?}, \
                expected_values: {:?}, expected_has_previous: {}, expected_has_next: {}",
                self.table_values,
                self.after,
                self.before,
                self.first,
                self.last,
                self.expected_values,
                self.expected_has_previous,
                self.expected_has_next,
            )
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn process_load_edges_filtered_various_pagination_cases() {
        let cases = vec![
            // first, no previous or next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: None,
                first: Some(3),
                last: None,
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![2, 4, 6],
                expected_has_previous: false,
                expected_has_next: false,
            },
            // first with next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: None,
                first: Some(2),
                last: None,
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![2, 4],
                expected_has_previous: false,
                expected_has_next: true,
            },
            // first after, no previous or next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: Some(2),
                before: None,
                first: Some(2),
                last: None,
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![4, 6],
                expected_has_previous: false,
                expected_has_next: false,
            },
            // first after with next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: Some(2),
                before: None,
                first: Some(1),
                last: None,
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![4],
                expected_has_previous: false,
                expected_has_next: true,
            },
            // last, no previous or next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: None,
                first: None,
                last: Some(3),
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![2, 4, 6],
                expected_has_previous: false,
                expected_has_next: false,
            },
            // last with previous
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: None,
                first: None,
                last: Some(2),
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![4, 6],
                expected_has_previous: true,
                expected_has_next: false,
            },
            // last before, no previous or next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: Some(5),
                first: None,
                last: Some(2),
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![2, 4],
                expected_has_previous: false,
                expected_has_next: false,
            },
            // last before with previous
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: Some(5),
                first: None,
                last: Some(1),
                predicate: Box::new(|row| row.value % 2 == 0),
                expected_values: vec![4],
                expected_has_previous: true,
                expected_has_next: false,
            },
            // empty values, no previous or next
            PaginationCase {
                table_values: vec![1, 2, 3, 4, 5, 6],
                after: None,
                before: None,
                first: Some(1),
                last: None,
                predicate: Box::new(|row| row.value > 6),
                expected_values: vec![],
                expected_has_previous: false,
                expected_has_next: false,
            },
        ];
        for case in cases {
            let table = MockTable::new(&case.table_values);
            let after = case.after.map(|v| OpaqueCursor(v.to_be_bytes().to_vec()));
            let before = case.before.map(|v| OpaqueCursor(v.to_be_bytes().to_vec()));
            let predicate = case.predicate.as_ref();
            let (nodes, has_previous, has_next) = super::process_load_edges_filtered(
                &table, after, before, case.first, case.last, None, predicate,
            );

            let values: Vec<u32> = nodes.into_iter().map(|res| res.unwrap().value).collect();
            assert_eq!(values, case.expected_values, "{case}");
            assert_eq!(has_previous, case.expected_has_previous, "{case}");
            assert_eq!(has_next, case.expected_has_next, "{case}");
        }
    }

    /// A resolver reaches both traits through the GraphQL context exactly as it
    /// reaches [`super::AgentManager`].
    ///
    /// The query type lives here rather than in the crate's own
    /// [`super::Query`]: this issue adds no GraphQL field, and a test-only one
    /// on the real schema would show up in the committed SDL.
    mod context {
        use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Result, Schema};

        use crate::{
            backend::BuildId,
            graphql::{
                BoxedHostOnboarder, BoxedPackageDeployer, MockHostOnboarder, MockPackageDeployer,
            },
        };

        #[derive(Default)]
        pub(super) struct DeployQuery;

        #[Object]
        impl DeployQuery {
            /// Returns the operation id `install` reported, read through the
            /// deployer in the context.
            async fn installed_operation_id(&self, ctx: &Context<'_>) -> Result<String> {
                let deployer = ctx.data::<BoxedPackageDeployer>()?;
                let (_outcome, operation_id) = deployer
                    .install(
                        "host1",
                        "giganto",
                        review_database::BuildSelector::Version("0.1.0".to_string()),
                        review_protocol::types::node::FailurePolicy::Rollback,
                        None,
                        None,
                        "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
                    )
                    .await?;
                Ok(operation_id.into_inner())
            }

            /// Returns the command `onboard_host` reported, read through the
            /// onboarder in the context.
            async fn onboarding_command(&self, ctx: &Context<'_>) -> Result<String> {
                let onboarder = ctx.data::<BoxedHostOnboarder>()?;
                let build = BuildId {
                    version: "1.2.3".to_string(),
                    commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
                };
                let (ticket, _operation_id) = onboarder.onboard_host("host1", &build).await?;
                let (_token, command, _expires_at, _namespace, _binary_sha256) =
                    ticket.into_parts();
                Ok(command)
            }
        }

        pub(super) fn schema() -> Schema<DeployQuery, EmptyMutation, EmptySubscription> {
            Schema::build(DeployQuery, EmptyMutation, EmptySubscription)
                .data(Box::new(MockPackageDeployer::default()) as BoxedPackageDeployer)
                .data(Box::new(MockHostOnboarder {}) as BoxedHostOnboarder)
                .finish()
        }
    }

    /// Proves object safety: both traits are usable behind a `Box<dyn _>`.
    #[test]
    fn both_traits_are_object_safe() {
        let _deployer: Box<dyn super::PackageDeployer> = Box::new(MockPackageDeployer::default());
        let _onboarder: Box<dyn super::HostOnboarder> = Box::new(super::MockHostOnboarder {});
    }

    #[tokio::test]
    async fn a_resolver_reads_the_deployer_from_the_context() {
        let response = context::schema()
            .execute("{ installedOperationId }")
            .await
            .into_result()
            .unwrap();
        assert_eq!(
            response.data.to_string(),
            r#"{installedOperationId: "11111111-2222-4333-8444-555555555555"}"#
        );
    }

    #[tokio::test]
    async fn a_resolver_reads_the_onboarder_from_the_context() {
        let response = context::schema()
            .execute("{ onboardingCommand }")
            .await
            .into_result()
            .unwrap();
        assert_eq!(
            response.data.to_string(),
            r#"{onboardingCommand: "roxyd join --token <token>"}"#
        );
    }

    /// The stubs in the schema context must not disturb the current surface.
    #[tokio::test]
    async fn the_wiring_leaves_an_existing_query_working() {
        let schema = TestSchema::new().await;
        let response = schema.execute_as_system_admin("{ __typename }").await;
        assert_eq!(response.data.to_string(), r#"{__typename: "Query"}"#);
    }

    /// Each named `DeployError` variant reaches the caller through
    /// `Box<dyn PackageDeployer>` and is selected on by kind, never by message.
    ///
    /// The `Arbitrary` case is the one that matters for `Other`: the stub fails
    /// with a bare `anyhow::Error` and its own `?` is what converts it, so
    /// nothing here downcasts and nothing names `DeployError::Other` on the
    /// producing side.
    #[tokio::test]
    async fn each_named_deploy_error_variant_reaches_the_caller() {
        use super::{BuildSelector, DeployError, FailurePolicy, MockDeployFailure};

        let selector = BuildSelector::Version("0.1.0".to_string());
        for failure in [
            MockDeployFailure::PortAllocationConflict,
            MockDeployFailure::HostPortOccupied,
            MockDeployFailure::HostOccupancyUnavailable,
            MockDeployFailure::RequestKey,
            MockDeployFailure::CleanupPending,
            MockDeployFailure::BuildNotServable,
            MockDeployFailure::Arbitrary,
        ] {
            let deployer: Box<dyn super::PackageDeployer> =
                Box::new(MockPackageDeployer::failing(failure));

            let errors = [
                deployer
                    .install(
                        "host1",
                        "giganto",
                        selector.clone(),
                        FailurePolicy::Rollback,
                        None,
                        None,
                        "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
                    )
                    .await
                    .map(|_| ())
                    .expect_err("the stub is configured to fail"),
                deployer
                    .update(
                        "host1",
                        "giganto",
                        Some(1),
                        selector.clone(),
                        FailurePolicy::Hold,
                    )
                    .await
                    .map(|_| ())
                    .expect_err("the stub is configured to fail"),
                deployer
                    .remove("host1", "giganto", Some(1))
                    .await
                    .map(|_| ())
                    .expect_err("the stub is configured to fail"),
                deployer
                    .recommend_bind_addrs("host1", "giganto")
                    .await
                    .map(|_| ())
                    .expect_err("the stub is configured to fail"),
            ];

            for error in errors {
                let selected = match error {
                    DeployError::PortAllocationConflict { owner, port, .. } => {
                        assert_eq!(port, 38_370);
                        assert_eq!(owner.component, "giganto");
                        MockDeployFailure::PortAllocationConflict
                    }
                    DeployError::HostPortOccupied { listener_key, .. } => {
                        assert_eq!(listener_key, "ingest");
                        MockDeployFailure::HostPortOccupied
                    }
                    DeployError::HostOccupancyUnavailable { host, .. } => {
                        assert_eq!(host, "host1");
                        MockDeployFailure::HostOccupancyUnavailable
                    }
                    DeployError::RequestKey(_) => MockDeployFailure::RequestKey,
                    DeployError::CleanupPending { operation_id, .. } => {
                        assert_eq!(
                            operation_id.as_str(),
                            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e"
                        );
                        MockDeployFailure::CleanupPending
                    }
                    DeployError::BuildNotServable { target } => {
                        assert_eq!(target, "giganto");
                        MockDeployFailure::BuildNotServable
                    }
                    DeployError::Other(_) => MockDeployFailure::Arbitrary,
                    DeployError::ConfigTemplateRequired { .. }
                    | DeployError::ConfigTemplateNotApplicable { .. }
                    | DeployError::UnknownConfigTemplate { .. } => {
                        panic!("this mock does not script configuration template refusals")
                    }
                };
                assert_eq!(selected, failure);
            }
        }
    }

    /// A host with nothing installed is `Ok(None)`, expressible without a
    /// placeholder version or commit.
    #[tokio::test]
    async fn read_version_expresses_an_absent_build_as_none() {
        let deployer: Box<dyn super::PackageDeployer> = Box::new(MockPackageDeployer::default());
        assert_eq!(
            deployer
                .read_version("host1", "giganto", Some(1))
                .await
                .unwrap(),
            None
        );
        assert_eq!(deployer.latest_build("giganto").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_successful_operation_pairs_its_outcome_with_an_id() {
        use super::{BuildSelector, DeployOutcome, FailurePolicy};

        let deployer: Box<dyn super::PackageDeployer> = Box::new(MockPackageDeployer::default());
        let (outcome, operation_id) = deployer
            .install(
                "host1",
                "giganto",
                BuildSelector::Version("0.1.0".to_string()),
                FailurePolicy::Rollback,
                Some(vec![super::BindAddrInput {
                    listener_key: "ingest".to_string(),
                    addr: std::net::SocketAddr::from(([127, 0, 0, 1], 38_370)),
                }]),
                None,
                "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            )
            .await
            .unwrap();
        assert_eq!(outcome, DeployOutcome::Applied);
        assert_eq!(
            operation_id.as_str(),
            "11111111-2222-4333-8444-555555555555"
        );

        let (outcome, _) = deployer
            .update(
                "host1",
                "giganto",
                Some(1),
                BuildSelector::Commit("0123456789abcdef".to_string()),
                FailurePolicy::Hold,
            )
            .await
            .unwrap();
        assert_eq!(outcome, DeployOutcome::Accepted);

        let operation_id = deployer.remove("host1", "giganto", Some(1)).await.unwrap();
        assert_eq!(
            operation_id.as_str(),
            "11111111-2222-4333-8444-555555555555"
        );
    }

    #[tokio::test]
    async fn unimplemented_agent_manager() {
        let agent_manager = super::MockAgentManager {};
        assert!(agent_manager.broadcast_trusted_domains().await.is_ok());
        assert!(
            agent_manager
                .broadcast_trusted_user_agent_list(&[])
                .await
                .is_err()
        );
        assert!(
            agent_manager
                .update_traffic_filter_rules("", &[(ipnet::IpNet::default(), None, None)])
                .await
                .is_err()
        );
    }
}
