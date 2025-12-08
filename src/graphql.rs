//! The GraphQL API schema and implementation.

// async-graphql requires the API functions to be `async`.
#![allow(clippy::unused_async)]

pub mod account;
mod allow_network;
mod block_network;
mod category;
mod cert;
mod cluster;
pub mod customer;
mod data_source;
mod db_management;
mod event;
mod filter;
pub(crate) mod indicator;
mod ip_location;
mod model;
pub(crate) mod network;
mod node;
mod outlier;
mod qualifier;
mod sampling;
mod slicing;
mod statistics;
mod status;
mod tags;
mod template;
pub(crate) mod tidb;
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

use async_graphql::connection::{
    Connection, ConnectionNameType, CursorType, Edge, EdgeNameType, EmptyFields, OpaqueCursor,
};
use async_graphql::{
    Context, Guard, InputValueError, InputValueResult, MergedObject, MergedSubscription,
    ObjectType, OutputType, Result, Scalar, ScalarType, Value,
};
use num_traits::ToPrimitive;
#[cfg(test)]
use review_database::HostNetworkGroup;
use review_database::{self as database, Role, Store, event::Direction};
pub use roxy::{Process, ResourceUsage};
use tokio::sync::{Notify, RwLock};
use tracing::warn;
use vinum::signal;

pub use self::allow_network::get_allow_networks;
pub use self::block_network::get_block_networks;
pub use self::cert::ParsedCertificate;
pub use self::customer::get_customer_networks;
pub use self::node::agent_keys_by_customer_id;
pub use self::sampling::{
    Interval as SamplingInterval, Kind as SamplingKind, Period as SamplingPeriod,
    Policy as SamplingPolicy,
};
use crate::backend::{AgentManager, CertManager};

/// GraphQL schema type.
pub(super) type Schema = async_graphql::Schema<Query, Mutation, Subscription>;

type BoxedAgentManager = Box<dyn AgentManager>;

/// Builds a GraphQL schema with the given database store as its context.
///
/// The store is stored in `async_graphql::Context` and passed to every
/// GraphQL API function.
pub(super) fn schema<B>(
    store: Arc<RwLock<Store>>,
    agent_manager: B,
    ip_locator: Option<ip2location::DB>,
    cert_manager: Arc<dyn CertManager>,
    cert_reload_handle: Arc<Notify>,
) -> Schema
where
    B: AgentManager + 'static,
{
    let agent_manager: BoxedAgentManager = Box::new(agent_manager);
    let mut builder = Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .data(store)
    .data(agent_manager)
    .data(cert_manager)
    .data(cert_reload_handle);
    if let Some(ip_locator) = ip_locator {
        builder = builder.data(ip_locator);
    }
    builder.finish()
}

/// A set of queries defined in the schema.
#[derive(MergedObject, Default)]
pub(super) struct Query(SubQueryOne, SubQueryTwo);

#[derive(MergedObject, Default)]
struct SubQueryOne(
    account::AccountQuery,
    block_network::BlockNetworkQuery,
    category::CategoryQuery,
    cluster::ClusterQuery,
    customer::CustomerQuery,
    data_source::DataSourceQuery,
    db_management::DbManagementQuery,
    event::EventQuery,
    event::EventGroupQuery,
    filter::FilterQuery,
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
struct SubQueryTwo(
    sampling::SamplingPolicyQuery,
    statistics::StatisticsQuery,
    status::StatusQuery,
    tags::EventTagQuery,
    tags::NetworkTagQuery,
    tags::WorkflowTagQuery,
    template::TemplateQuery,
    tor_exit_node::TorExitNodeQuery,
    tidb::TidbQuery,
    triage::TriagePolicyQuery,
    triage::TriageResponseQuery,
    trusted_domain::TrustedDomainQuery,
    traffic_filter::TrafficFilterQuery,
    allow_network::AllowNetworkQuery,
    trusted_user_agent::UserAgentQuery,
    node::ProcessListQuery,
);

/// A set of mutations defined in the schema.
///
/// This is exposed only for [`Schema`], and not used directly.
#[derive(MergedObject, Default)]
pub(super) struct Mutation(SubMutationOne, SubMutationTwo);

#[derive(MergedObject, Default)]
struct SubMutationOne(
    account::AccountMutation,
    block_network::BlockNetworkMutation,
    category::CategoryMutation,
    cert::CertMutation,
    cluster::ClusterMutation,
    customer::CustomerMutation,
    data_source::DataSourceMutation,
    db_management::DbManagementMutation,
    filter::FilterMutation,
    indicator::IndicatorMutation,
    model::ModelMutation,
    network::NetworkMutation,
    node::NodeControlMutation,
    node::NodeMutation,
    outlier::OutlierMutation,
);

#[derive(MergedObject, Default)]
struct SubMutationTwo(
    qualifier::QualifierMutation,
    sampling::SamplingPolicyMutation,
    status::StatusMutation,
    tags::EventTagMutation,
    tags::NetworkTagMutation,
    tags::WorkflowTagMutation,
    template::TemplateMutation,
    tor_exit_node::TorExitNodeMutation,
    tidb::TidbMutation,
    triage::TriagePolicyMutation,
    triage::TriageResponseMutation,
    trusted_domain::TrustedDomainMutation,
    traffic_filter::TrafficFilterMutation,
    allow_network::AllowNetworkMutation,
    trusted_user_agent::UserAgentMutation,
);

/// A set of subscription defined in the schema.
#[derive(MergedSubscription, Default)]
pub(super) struct Subscription(event::EventStream, outlier::OutlierStream);

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

async fn get_store<'a>(ctx: &Context<'a>) -> Result<tokio::sync::RwLockReadGuard<'a, Store>> {
    Ok(ctx.data::<Arc<RwLock<Store>>>()?.read().await)
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

#[derive(Debug, PartialEq)]
pub(crate) enum RoleGuard {
    Role(database::Role),
    Local,
}

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

const A_BILLION: i64 = 1_000_000_000;
type TimeCount = (i64, usize); // (utc_timestamp_nano, count)

fn fill_vacant_time_slots(series: &[TimeCount]) -> Vec<TimeCount> {
    let mut filled_series: Vec<TimeCount> = Vec::new();

    if series.len() <= 2 {
        return series.to_vec();
    }
    let mut min_diff = series[1].0 - series[0].0;
    for index in 2..series.len() {
        let diff = series[index].0 - series[index - 1].0;
        if diff < min_diff {
            min_diff = diff;
        }
    }

    for (index, element) in series.iter().enumerate() {
        if index == 0 {
            filled_series.push(*element);
            continue;
        }
        let min_diff_seconds = min_diff / A_BILLION;
        let time_diff = ((element.0 - series[index - 1].0) / A_BILLION) / min_diff_seconds;
        if time_diff > 1 {
            for d in 1..time_diff {
                filled_series.push((series[index - 1].0 + d * min_diff_seconds, 0));
            }
        }
        filled_series.push(*element);
    }
    filled_series
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
    let cutoff_frequency = if cutoff_len < 1.0 {
        1.0
    } else {
        1.0 / cutoff_len
    };
    let (b, a) = signal::filter::design::butter(trendi_order, cutoff_frequency);
    signal::filter::filtfilt(&b, &a, &original)
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
        _networks: &[customer::NetworksTargetAgentKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec!["semi-supervised@hostA".to_string()])
    }
    async fn broadcast_allow_networks(
        &self,
        _networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec![
            "semi-supervised@hostA".to_string(),
            "semi-supervised@hostB".to_string(),
        ])
    }
    async fn broadcast_block_networks(
        &self,
        _networks: &HostNetworkGroup,
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

    async fn get_process_list(&self, _hostname: &str) -> Result<Vec<Process>, anyhow::Error> {
        unimplemented!()
    }

    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        unimplemented!()
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn ping(&self, _hostname: &str) -> Result<std::time::Duration, anyhow::Error> {
        unimplemented!()
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn update_config(&self, _agent_key: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
}

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir,        // to delete the data directory when dropped
    _backup_dir: tempfile::TempDir, // to delete the backup directory when dropped
    store: Arc<RwLock<Store>>,
    schema: Schema,
    test_addr: Option<SocketAddr>, // to simulate the client address
}

#[cfg(test)]
const TEST_JWT_SECRET_DER: &[u8] = &[
    0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01,
    0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xea, 0x7c, 0xe5, 0x92, 0x91, 0xff, 0x03, 0xe7, 0xb0, 0x39,
    0xaa, 0xae, 0xce, 0x69, 0xb5, 0x7b, 0xcf, 0x5d, 0xa7, 0x9a, 0xce, 0xd2, 0x28, 0x71, 0xbe, 0x7a,
    0x70, 0x6e, 0x06, 0x81, 0x4a, 0x9b, 0xac, 0x7d, 0x74, 0x62, 0x26, 0x58, 0x1f, 0xf3, 0x0a, 0x4f,
    0xd7, 0xf2, 0xbe, 0x84, 0x2e, 0xdf, 0x72, 0xfc, 0x6c, 0xab, 0x6c, 0xff, 0xa9, 0x97, 0xb8, 0xf5,
    0xda, 0x11, 0x7c, 0xa5, 0xf2, 0x8f, 0xec, 0x7a, 0xbe, 0x6a, 0x97, 0x91, 0xaf, 0x1d, 0x94, 0x6a,
    0xc0, 0xba, 0xf8, 0xd4, 0xa1, 0x5d, 0x95, 0xf9, 0x7a, 0x75, 0x23, 0x7c, 0xec, 0xa2, 0xbd, 0x4b,
    0x48, 0x4a, 0x4e, 0x5a, 0xe3, 0xf2, 0x38, 0x36, 0x8b, 0x98, 0x4c, 0x0b, 0xb7, 0x45, 0x42, 0xd0,
    0x12, 0x8b, 0x88, 0xf3, 0x4a, 0x97, 0x24, 0xd4, 0x40, 0xeb, 0x37, 0x0f, 0x45, 0xd3, 0x0a, 0x97,
    0x6f, 0x5b, 0x15, 0x3b, 0xbc, 0x6d, 0x67, 0xad, 0x32, 0x2c, 0xc8, 0x8b, 0x07, 0x83, 0xb2, 0xbe,
    0x6f, 0xb3, 0xf1, 0xdc, 0x4c, 0x0a, 0x6d, 0xc1, 0xad, 0x58, 0xce, 0xac, 0xad, 0x91, 0x44, 0x60,
    0x16, 0x79, 0x8b, 0xae, 0x18, 0x27, 0x46, 0xf0, 0x43, 0x28, 0x74, 0x23, 0xe7, 0xe2, 0x6a, 0xb8,
    0xdf, 0xab, 0x4c, 0x39, 0xcb, 0xdb, 0x5b, 0xc0, 0xcd, 0x3b, 0xb6, 0x35, 0xd3, 0xad, 0xa4, 0xc5,
    0x7b, 0x38, 0x6e, 0xdd, 0xd2, 0xa5, 0xde, 0x8a, 0x85, 0x5d, 0x62, 0x61, 0x5d, 0x51, 0x3d, 0x6d,
    0x84, 0x5f, 0xf3, 0xf4, 0xd8, 0xbf, 0x8e, 0x75, 0xa4, 0x38, 0x90, 0x03, 0xf4, 0x8e, 0xba, 0xc4,
    0x10, 0x46, 0x53, 0x51, 0xd4, 0x73, 0x0f, 0xf5, 0x2d, 0x85, 0x29, 0x30, 0x0e, 0x0e, 0xb7, 0xfc,
    0x67, 0xbc, 0x08, 0x9a, 0xfa, 0x2e, 0x4a, 0x35, 0x83, 0xcb, 0x79, 0xee, 0xba, 0x36, 0x1a, 0xb7,
    0xbf, 0xb9, 0x1f, 0x70, 0xc8, 0x2b, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x2a,
    0x66, 0x0e, 0xf4, 0xa3, 0xa5, 0x62, 0xc5, 0x5f, 0xdd, 0xed, 0x78, 0xd2, 0x25, 0xd7, 0x04, 0xde,
    0x07, 0xe7, 0x28, 0x5c, 0xc1, 0x2f, 0x42, 0xf1, 0xd8, 0x1d, 0xc0, 0x27, 0x38, 0xf5, 0x8e, 0x94,
    0x6f, 0xd2, 0xbd, 0x74, 0x85, 0x76, 0xb1, 0x71, 0x69, 0xe2, 0x78, 0x27, 0xee, 0xaa, 0xb3, 0x08,
    0x8d, 0x8f, 0xf0, 0xa7, 0x32, 0xcb, 0x2d, 0x7d, 0xea, 0x26, 0x56, 0x07, 0x1d, 0xd2, 0x70, 0x27,
    0xa8, 0x42, 0x09, 0xf0, 0x02, 0x0d, 0x91, 0xe1, 0xa6, 0x33, 0xd7, 0x1a, 0xeb, 0x07, 0x8a, 0x6e,
    0x75, 0xbf, 0xa8, 0xb2, 0x94, 0x02, 0x0d, 0xa3, 0x00, 0x9b, 0xbf, 0xa3, 0xcf, 0x57, 0x6c, 0x12,
    0xb1, 0xfa, 0x27, 0xbd, 0x88, 0x58, 0xc9, 0x13, 0x3d, 0xa0, 0x3c, 0xce, 0xb4, 0x7f, 0x06, 0x39,
    0x48, 0x8f, 0xbc, 0x78, 0x26, 0x30, 0xcf, 0xea, 0x18, 0x5b, 0xb0, 0x32, 0x74, 0xac, 0xab, 0x1a,
    0xfa, 0xdc, 0x08, 0xf0, 0xb9, 0x08, 0x71, 0x8b, 0x06, 0xd9, 0x4b, 0xd0, 0x0b, 0x10, 0x1e, 0x9a,
    0x59, 0x62, 0xc5, 0x26, 0x8d, 0x08, 0x58, 0xde, 0xd0, 0x39, 0x96, 0x46, 0x2b, 0x0c, 0xba, 0xc4,
    0xe8, 0x19, 0x41, 0xf3, 0x8b, 0xfc, 0x65, 0xfd, 0x16, 0xc7, 0x0a, 0x31, 0x6d, 0x29, 0x71, 0x43,
    0xdb, 0xa2, 0x6b, 0x07, 0x9a, 0xa1, 0x58, 0x91, 0x0d, 0xc3, 0xb4, 0x3d, 0x6d, 0xac, 0xf1, 0x00,
    0x15, 0x7e, 0x2b, 0x1a, 0xf1, 0x3a, 0x90, 0x4e, 0x70, 0x35, 0x3a, 0x03, 0xc3, 0x31, 0x52, 0xa0,
    0xbc, 0xc2, 0x29, 0x88, 0x88, 0x8f, 0xd5, 0xd4, 0x8b, 0xeb, 0x74, 0xef, 0xd2, 0x63, 0xf6, 0x6e,
    0x13, 0x96, 0x7c, 0xbf, 0xf1, 0x28, 0xa7, 0x7b, 0x37, 0x18, 0xc0, 0x8d, 0x08, 0x16, 0x47, 0x2c,
    0x35, 0xbc, 0xfe, 0x93, 0xac, 0x0d, 0x28, 0x37, 0x58, 0xea, 0x1f, 0xc7, 0x97, 0x26, 0xb1, 0x02,
    0x81, 0x81, 0x00, 0xf7, 0x01, 0xa0, 0xb9, 0x1c, 0xc3, 0xb3, 0x6f, 0x8d, 0x6b, 0x18, 0x56, 0x89,
    0x8f, 0xcd, 0xa0, 0xb3, 0xca, 0x35, 0x97, 0x5a, 0x07, 0xeb, 0x44, 0x59, 0xb2, 0x4c, 0x52, 0x4a,
    0x20, 0x03, 0x32, 0xf4, 0xf1, 0x3f, 0x8e, 0x9d, 0x4f, 0xe4, 0x1d, 0xaa, 0x56, 0x80, 0x4b, 0x50,
    0xd3, 0xe8, 0x4f, 0xcc, 0x47, 0x56, 0x04, 0x5c, 0x61, 0x68, 0xb9, 0xb8, 0x6a, 0x72, 0x1a, 0xc5,
    0xdf, 0x5c, 0x31, 0xfd, 0xe9, 0x7e, 0x41, 0xa0, 0x84, 0xb4, 0xeb, 0x76, 0x74, 0xc3, 0x8e, 0xca,
    0x13, 0xe1, 0x03, 0xa0, 0xd9, 0xd9, 0x1c, 0x4f, 0xcb, 0x4e, 0x1c, 0x1e, 0xfa, 0x7c, 0xa6, 0x43,
    0xa3, 0x20, 0xf8, 0x77, 0xd1, 0xb4, 0xe1, 0x09, 0x4e, 0xe8, 0x99, 0x89, 0xc9, 0xa7, 0x03, 0x8c,
    0x39, 0xbf, 0x09, 0x19, 0x66, 0xb0, 0xe7, 0x9f, 0x85, 0xc5, 0xde, 0x22, 0x51, 0xba, 0xba, 0xdd,
    0x51, 0x65, 0x4f, 0x02, 0x81, 0x81, 0x00, 0xf3, 0x06, 0x95, 0x37, 0x14, 0x2a, 0xad, 0xc3, 0x72,
    0x70, 0xee, 0x50, 0xa1, 0xea, 0xed, 0xef, 0xd4, 0x7e, 0xf0, 0xa2, 0xf7, 0x62, 0x1d, 0x61, 0xe3,
    0xdf, 0x2a, 0x94, 0x7c, 0xef, 0x89, 0x71, 0x95, 0xa3, 0xa0, 0xd4, 0x47, 0xd0, 0xb0, 0x61, 0x4c,
    0xf6, 0x65, 0x67, 0x24, 0xef, 0x02, 0x20, 0x56, 0x1e, 0xa3, 0x9e, 0x4f, 0xe6, 0x48, 0xec, 0x5a,
    0x7b, 0x82, 0xbe, 0x26, 0x14, 0x51, 0x3c, 0xae, 0x27, 0x22, 0xd5, 0x90, 0xc5, 0x98, 0x98, 0x0c,
    0x59, 0xc2, 0x74, 0x3f, 0x69, 0xb1, 0x91, 0xf9, 0x1d, 0x64, 0xeb, 0x8a, 0xb5, 0x2a, 0x00, 0xf7,
    0x6f, 0x30, 0x25, 0x11, 0x35, 0x8d, 0xd3, 0xfc, 0xfb, 0x94, 0x49, 0x40, 0x5f, 0x78, 0x50, 0x80,
    0x31, 0x32, 0xb5, 0x29, 0xe2, 0x64, 0x13, 0xfb, 0xdc, 0x26, 0x0e, 0x65, 0xbc, 0xf9, 0x43, 0x6f,
    0xaa, 0xfd, 0x28, 0x64, 0x1b, 0x30, 0x65, 0x02, 0x81, 0x80, 0x23, 0x5a, 0x54, 0x4a, 0xaa, 0x57,
    0x48, 0x43, 0x5b, 0x16, 0x4c, 0xf1, 0x75, 0xd6, 0xe3, 0x33, 0x71, 0x08, 0x2c, 0x0b, 0x71, 0x93,
    0x58, 0x94, 0xfb, 0xd1, 0x8d, 0x22, 0xea, 0x01, 0x12, 0xf4, 0x24, 0x22, 0xb3, 0x5a, 0x12, 0x21,
    0xf1, 0x20, 0x5d, 0xd4, 0xeb, 0x9f, 0xdb, 0xfd, 0xb8, 0x6e, 0x53, 0x6a, 0x92, 0x61, 0x25, 0x67,
    0xbb, 0xb9, 0x79, 0x2f, 0xa3, 0x0d, 0x39, 0xec, 0xf2, 0x21, 0x25, 0x9a, 0x59, 0xbb, 0xc2, 0xe1,
    0xbb, 0x93, 0x47, 0xed, 0x06, 0x60, 0x55, 0x83, 0xea, 0xdc, 0xbe, 0x14, 0xf0, 0x02, 0x21, 0x59,
    0x93, 0xe0, 0x6a, 0x7e, 0xa7, 0x80, 0x94, 0x85, 0xb0, 0x9e, 0x5f, 0x67, 0xe0, 0x5f, 0xa5, 0x19,
    0x6a, 0x29, 0x2f, 0x93, 0x71, 0x18, 0x0c, 0xe5, 0xe6, 0xf5, 0xc2, 0x70, 0xf4, 0x38, 0xf2, 0x98,
    0x0e, 0xed, 0xf0, 0x33, 0x8a, 0x6a, 0x5c, 0x6a, 0xdd, 0xf9, 0x02, 0x81, 0x80, 0x0f, 0x48, 0x15,
    0xaf, 0xed, 0xf3, 0xb5, 0x13, 0x7a, 0x29, 0xc1, 0xc2, 0x8e, 0x3b, 0xf0, 0x94, 0x49, 0x1f, 0x66,
    0x50, 0x49, 0x10, 0x01, 0x5a, 0xfb, 0x72, 0x38, 0x02, 0x38, 0x4c, 0xf3, 0xae, 0x91, 0xc3, 0x45,
    0x44, 0xb3, 0xf3, 0x5a, 0x73, 0xf3, 0xdb, 0xf6, 0x8a, 0x62, 0xd7, 0x28, 0xa2, 0x11, 0xe8, 0x41,
    0x4f, 0x9e, 0x24, 0x93, 0xe7, 0x50, 0xd5, 0x3d, 0x66, 0x69, 0x8c, 0x93, 0x83, 0x26, 0x4c, 0x4d,
    0xb3, 0x72, 0x34, 0x0a, 0xa1, 0x5c, 0xfd, 0x73, 0xed, 0xcd, 0x62, 0xff, 0x08, 0x77, 0xca, 0xb2,
    0x62, 0xe1, 0x48, 0xfd, 0x08, 0x2c, 0x86, 0xf0, 0x57, 0x14, 0x5a, 0xf2, 0xbd, 0x26, 0xc6, 0x47,
    0x0f, 0xc8, 0x1d, 0x78, 0xba, 0x4f, 0x25, 0x48, 0xd3, 0xfd, 0x7b, 0x3f, 0xe1, 0xc5, 0xcf, 0x95,
    0x11, 0x08, 0xb2, 0xb6, 0x55, 0xd8, 0x3a, 0xbf, 0x4a, 0x7f, 0xe8, 0xf9, 0xc5, 0x02, 0x81, 0x80,
    0x4e, 0xa0, 0x90, 0x58, 0x48, 0xc8, 0xc4, 0x73, 0x5a, 0x56, 0xd9, 0x7b, 0x18, 0xbb, 0x86, 0x2f,
    0xba, 0xe1, 0xf4, 0x00, 0xf0, 0x25, 0x21, 0x49, 0x1f, 0xea, 0x3d, 0xff, 0x88, 0x29, 0xcd, 0x8d,
    0xf1, 0xf2, 0x09, 0x77, 0xda, 0x2c, 0xc8, 0x11, 0xc5, 0x2c, 0xb5, 0x42, 0xab, 0x5d, 0x92, 0xfc,
    0xd8, 0x01, 0x0e, 0x05, 0x7e, 0x94, 0x56, 0xbb, 0x14, 0xe4, 0x50, 0x47, 0x03, 0x20, 0x3b, 0xae,
    0x07, 0xa6, 0x22, 0x23, 0xc5, 0x7a, 0x2c, 0xf1, 0xfa, 0xcf, 0x4c, 0x81, 0xd4, 0xdd, 0x56, 0x9c,
    0xf3, 0x9a, 0x47, 0x80, 0xa2, 0x2e, 0x0b, 0x0c, 0x7f, 0xcc, 0xb8, 0xd0, 0xd8, 0xaa, 0xdf, 0x2f,
    0xd6, 0x7e, 0x9b, 0x66, 0x67, 0x4a, 0x32, 0x9f, 0x17, 0x03, 0xf9, 0x24, 0x4c, 0x46, 0xd5, 0xe5,
    0xb2, 0x1e, 0x25, 0xe7, 0x5e, 0x62, 0x31, 0x86, 0x04, 0x4f, 0x7b, 0x10, 0xe2, 0x9a, 0x5f, 0x47,
];

#[cfg(test)]
pub(crate) fn test_jwt_secret_der() -> &'static [u8] {
    TEST_JWT_SECRET_DER
}

#[cfg(test)]
impl TestSchema {
    async fn new() -> Self {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        Self::new_with_params(agent_manager, None, "testuser").await
    }

    async fn new_with_params(
        agent_manager: BoxedAgentManager,
        test_addr: Option<SocketAddr>,
        username: &str,
    ) -> Self {
        use self::account::set_initial_admin_password;

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
        let _ = set_initial_admin_password(&store);
        let store = Arc::new(RwLock::new(store));

        crate::auth::update_jwt_secret(test_jwt_secret_der().to_vec()).unwrap();

        let schema = Schema::build(
            Query::default(),
            Mutation::default(),
            Subscription::default(),
        )
        .data(agent_manager)
        .data(store.clone())
        .data(username.to_string())
        .finish();

        Self {
            _dir: db_dir,
            _backup_dir: backup_dir,
            store,
            schema,
            test_addr,
        }
    }

    async fn store(&self) -> tokio::sync::RwLockReadGuard<'_, Store> {
        self.store.read().await
    }

    async fn execute_as_system_admin(&self, query: &str) -> async_graphql::Response {
        self.execute_with_guard(query, RoleGuard::Role(Role::SystemAdministrator))
            .await
    }

    async fn execute_with_guard(&self, query: &str, guard: RoleGuard) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        let request = self.request_with_guard(request, guard);
        self.schema.execute(request).await
    }

    async fn execute_as_system_admin_with_data(
        &self,
        query: &str,
        data: impl Send + Sync + 'static,
    ) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        let request = self
            .request_with_guard(request, RoleGuard::Role(Role::SystemAdministrator))
            .data(data);
        self.schema.execute(request).await
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
    use super::AgentManager;

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
