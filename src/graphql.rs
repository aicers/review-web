//! The GraphQL API schema and implementation.

// async-graphql requires the API functions to be `async`.
#![allow(clippy::unused_async)]

pub mod account;
mod allow_network;
mod block_network;
mod category;
mod cert;
mod cluster;
pub(crate) mod customer;
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

use std::future::Future;
#[cfg(test)]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_graphql::connection::ConnectionNameType;
use async_graphql::{
    connection::{Connection, Edge, EmptyFields},
    Context, Guard, MergedObject, MergedSubscription, ObjectType, OutputType, Result,
};
use chrono::TimeDelta;
use data_encoding::BASE64;
use num_traits::ToPrimitive;
#[cfg(test)]
use review_database::HostNetworkGroup;
use review_database::{self as database, Database, Direction, Role, Store};
pub use roxy::{Process, ResourceUsage};
use tokio::sync::{Notify, RwLock};
use tracing::warn;
use vinum::signal;

pub use self::allow_network::get_allow_networks;
pub use self::block_network::get_block_networks;
pub use self::cert::ParsedCertificate;
pub use self::customer::get_customer_networks;
pub use self::node::get_customer_id_of_node;
pub use self::sampling::{
    Interval as SamplingInterval, Kind as SamplingKind, Period as SamplingPeriod,
    Policy as SamplingPolicy,
};
pub use self::trusted_user_agent::get_trusted_user_agent_list;
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
    ip_locator: Option<Arc<Mutex<ip2location::DB>>>,
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

async fn query<Node, ConnectionFields, Name, F, R, E>(
    after: Option<String>,
    before: Option<String>,
    first: Option<i32>,
    last: Option<i32>,
    f: F,
) -> Result<Connection<String, Node, ConnectionFields, EmptyFields, Name>>
where
    Node: OutputType,
    ConnectionFields: ObjectType,
    Name: ConnectionNameType,
    F: FnOnce(Option<String>, Option<String>, Option<usize>, Option<usize>) -> R,
    R: Future<Output = Result<Connection<String, Node, ConnectionFields, EmptyFields, Name>, E>>,
    E: Into<async_graphql::Error>,
{
    let (first, last) = validate_pagination_params(after.is_some(), before.is_some(), first, last)?;
    async_graphql::connection::query(after, before, first, last, |after, before, first, last| {
        f(after, before, first, last)
    })
    .await
}

const DEFAULT_CONNECTION_SIZE: i32 = 100;

fn validate_pagination_params(
    after: bool,
    before: bool,
    mut first: Option<i32>,
    mut last: Option<i32>,
) -> Result<(Option<i32>, Option<i32>)> {
    if let Some(first) = first {
        if first < 0 {
            return Err("The \"first\" parameter must be a non-negative number".into());
        }
    }
    if let Some(last) = last {
        if last < 0 {
            return Err("The \"last\" parameter must be a non-negative number".into());
        }
    }

    match (first.is_some(), last.is_some(), before, after) {
        (true, true, _, _) => return Err("cannot provide both `first` and `last`".into()),
        (_, _, true, true) => return Err("cannot provide both `before` and `after`".into()),
        (true, _, true, _) => return Err("cannot provide both `first` and `before`".into()),
        (_, true, _, true) => return Err("cannot provide both `last` and `after`".into()),
        (false, false, false, _) => {
            first = Some(DEFAULT_CONNECTION_SIZE);
        }
        (false, false, true, false) => {
            last = Some(DEFAULT_CONNECTION_SIZE);
        }
        _ => {}
    }

    Ok((first, last))
}

// parameters for trend
const DEFAULT_CUTOFF_RATE: f64 = 0.1;
const DEFAULT_TRENDI_ORDER: i32 = 4;

async fn get_store<'a>(ctx: &Context<'a>) -> Result<tokio::sync::RwLockReadGuard<'a, Store>> {
    Ok(ctx.data::<Arc<RwLock<Store>>>()?.read().await)
}

/// Decodes a cursor used in pagination.
fn decode_cursor(cursor: &str) -> Option<Vec<u8>> {
    BASE64.decode(cursor.as_bytes()).ok()
}

/// Encodes a cursor used in pagination.
fn encode_cursor(cursor: &[u8]) -> String {
    BASE64.encode(cursor)
}

#[allow(clippy::type_complexity)]
fn decode_cursor_pair(
    after: Option<String>,
    before: Option<String>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let after = if let Some(after) = after {
        Some(decode_cursor(&after).ok_or("invalid cursor `after`")?)
    } else {
        None
    };
    let before = if let Some(before) = before {
        Some(decode_cursor(&before).ok_or("invalid cursor `before`")?)
    } else {
        None
    };
    Ok((after, before))
}

#[allow(clippy::type_complexity)]
fn process_load_edges<'a, T, I, R>(
    table: &'a T,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    prefix: Option<&[u8]>,
) -> Result<(Vec<Result<R, anyhow::Error>>, bool, bool)>
where
    T: database::Iterable<'a, I>,
    I: std::iter::Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
{
    let (after, before) = decode_cursor_pair(after, before)?;
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

    Ok((nodes, has_previous, has_next))
}

fn load_edges_interim<'a, T, I, R>(
    table: &'a T,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    prefix: Option<&[u8]>,
) -> Result<(Vec<R>, bool, bool)>
where
    T: database::Iterable<'a, I>,
    I: std::iter::Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
{
    let (nodes, has_previous, has_next) =
        process_load_edges(table, after, before, first, last, prefix)?;

    let nodes = nodes
        .into_iter()
        .map(|res| res.map_err(|e| format!("{e}").into()))
        .collect::<Result<Vec<_>>>()?;
    Ok((nodes, has_previous, has_next))
}

/// Builds a `Connection` from a database table.
///
/// If both `first` and `last` are provided, `first` will be ignored. In
/// practive, however, only one of them should be provided, since this function
/// is called by [`async_graphql::connection::query`][async_graphql], which
/// enforces this.
///
/// [async_graphql]: https://docs.rs/async-graphql/latest
fn connection_from_table<'db, 'n, 'd, 'k, R, K, V, Node>(
    table: &database::Table<'db, 'n, 'd, R, K, V>,
    after: Option<K::SelfType<'k>>,
    before: Option<K::SelfType<'k>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Node>>
where
    R: database::KeyValue<K, V>,
    K: database::Key + 'static,
    K::SelfType<'static>: database::Key,
    V: database::Value + 'static,
    Node: From<R> + OutputType,
{
    let (nodes, has_prev, has_next) = if let Some(last) = last {
        // Backward pagination
        let range = if let Some(before) = before {
            table.range(..before)
        } else {
            table.range::<K::SelfType<'static>>(..)
        }?
        //.rev() TODO: implement DoubleEndedIterator for database::Range
        ;

        let iter = range.filter_map(|item| item.ok()).take(last + 1);
        let mut boundary_hit = false;
        let (nodes, has_prev) = if let Some(after) = after {
            let mut nodes = iter
                .take_while(|item| {
                    use database::Key;
                    if K::SelfType::<'_>::compare(
                        K::as_bytes(&item.db_key()).as_ref(),
                        K::as_bytes(&after).as_ref(),
                    ) == std::cmp::Ordering::Greater
                    {
                        true
                    } else {
                        boundary_hit = true;
                        false
                    }
                })
                .collect::<Vec<_>>();
            nodes.reverse();
            (nodes, boundary_hit)
        } else {
            let mut nodes = iter.collect::<Vec<_>>();
            let has_prev;
            if nodes.len() > last {
                has_prev = true;
                nodes.pop();
            } else {
                has_prev = false;
            }
            nodes.reverse();
            (nodes, has_prev)
        };

        (nodes, has_prev, false)
    } else {
        // Forward pagination
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let range = if let Some(after) = after {
            table.range(after..)
        } else {
            table.range::<K::SelfType<'static>>(..)
        };
        unimplemented!()
    };

    unimplemented!()
}

fn edges_from_table<'db, 'n, 'd, 'k, R, K, V>(
    table: &database::Table<'db, 'n, 'd, R, K, V>,
    from: Option<K::SelfType<'k>>,
    to: Option<K::SelfType<'k>>,
) -> (Vec<anyhow::Result<R>>, bool)
where
    R: database::KeyValue<K, V>,
    K: database::Key + 'static,
    V: database::Value + 'static,
{
    let range = match (from, to) {
        (Some(from), Some(to)) => table.range(from..to),
        (Some(from), None) => table.range(from..),
        (None, Some(to)) => table.range(..to),
        (None, None) => table.range::<K::SelfType<'static>>(..),
    };

    unimplemented!()
}

fn load_edges<'a, T, I, R, N, A, NodesField>(
    table: &'a T,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    additional_fields: A,
) -> Result<Connection<String, N, A, EmptyFields, NodesField>>
where
    T: database::Iterable<'a, I>,
    I: std::iter::Iterator<Item = anyhow::Result<R>>,
    R: database::UniqueKey,
    N: From<R> + OutputType,
    A: ObjectType,
    NodesField: ConnectionNameType,
{
    let (nodes, has_previous, has_next) =
        process_load_edges(table, after, before, first, last, None)?;

    for node in &nodes {
        let Err(e) = node else { continue };
        warn!("failed to load account: {}", e);
        return Err("database error".into());
    }

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, additional_fields);
    connection.edges.extend(nodes.into_iter().map(|node| {
        let Ok(node) = node else { unreachable!() };
        let encoded = encode_cursor(node.unique_key().as_ref());
        Edge::new(encoded, node.into())
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
    I: std::iter::Iterator<Item = anyhow::Result<R>>,
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

fn fill_vacant_time_slots(series: &[database::TimeCount]) -> Vec<database::TimeCount> {
    let mut filled_series: Vec<database::TimeCount> = Vec::new();

    if series.len() <= 2 {
        return series.to_vec();
    }

    let mut min_diff = series[1].time - series[0].time;
    for index in 2..series.len() {
        let diff = series[index].time - series[index - 1].time;
        if diff < min_diff {
            min_diff = diff;
        }
    }

    for (index, element) in series.iter().enumerate() {
        if index == 0 {
            filled_series.push(element.clone());
            continue;
        }
        let time_diff =
            (element.time - series[index - 1].time).num_seconds() / min_diff.num_seconds();
        if time_diff > 1 {
            for d in 1..time_diff {
                let Some(min_diff) = TimeDelta::try_seconds(d * min_diff.num_seconds()) else {
                    return Vec::new();
                };
                filled_series.push(database::TimeCount {
                    time: series[index - 1].time + min_diff,
                    count: 0,
                });
            }
        }
        filled_series.push(element.clone());
    }
    filled_series
}

fn get_trend(
    series: &[database::TimeCount],
    cutoff_rate: f64,
    trendi_order: i32,
) -> Result<Vec<f64>, vinum::InvalidInput> {
    let original: Vec<f64> = series
        .iter()
        .map(|s| s.count.to_f64().expect("safe: usize -> f64"))
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

    async fn broadcast_internal_networks(
        &self,
        _networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec!["hog@hostA".to_string()])
    }
    async fn broadcast_allow_networks(
        &self,
        _networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec!["hog@hostA".to_string(), "hog@hostB".to_string()])
    }
    async fn broadcast_block_networks(
        &self,
        _networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(vec![
            "hog@hostA".to_string(),
            "hog@hostB".to_string(),
            "hog@hostC".to_string(),
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
        Self::new_with(agent_manager, None).await
    }

    async fn new_with(agent_manager: BoxedAgentManager, test_addr: Option<SocketAddr>) -> Self {
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
        .data("testuser".to_string())
        .finish();
        Self {
            _dir: db_dir,
            store,
            schema,
            test_addr,
        }
    }

    async fn store(&self) -> tokio::sync::RwLockReadGuard<Store> {
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
    ) -> impl futures_util::Stream<Item = async_graphql::Response> {
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
        assert!(agent_manager
            .broadcast_trusted_user_agent_list(&[])
            .await
            .is_err());
        assert!(agent_manager
            .update_traffic_filter_rules("", &[(Default::default(), None, None)])
            .await
            .is_err());
    }
}
