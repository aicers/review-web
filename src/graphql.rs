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
use review_database::{self as database, Database, Role, Store, event::Direction};
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

/// Builds a GraphQL schema with the given database connection pool as its
/// context.
///
/// The connection pool is stored in `async_graphql::Context` and passed to
/// every GraphQL API function.
pub(super) fn schema<B>(
    db: Database,
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
    .data(db)
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
    _dir: tempfile::TempDir, // to delete the data directory when dropped
    store: Arc<RwLock<Store>>,
    schema: Schema,
    test_addr: Option<SocketAddr>, // to simulate the client address
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
            store,
            schema,
            test_addr,
        }
    }

    async fn store(&self) -> tokio::sync::RwLockReadGuard<'_, Store> {
        self.store.read().await
    }

    async fn execute(&self, query: &str) -> async_graphql::Response {
        self.execute_with_guard(query, RoleGuard::Role(Role::SystemAdministrator))
            .await
    }

    async fn execute_with_guard(&self, query: &str, guard: RoleGuard) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        let request = if let Some(addr) = self.test_addr {
            request.data(addr)
        } else {
            request
        };
        self.schema.execute(request.data(guard)).await
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
