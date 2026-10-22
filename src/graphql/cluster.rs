use std::sync::Arc;
use std::sync::RwLock;

use async_graphql::{
    ComplexObject, Context, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
    types::ID,
};
use chrono::NaiveDateTime;
use chrono::{DateTime, Utc};
use database::Store;
use num_traits::ToPrimitive;
use review_database as database;

use super::{
    DEFAULT_CUTOFF_RATE, DEFAULT_TRENDI_ORDER, MAX_TRENDI_ORDER, PositiveCutoffRate, Role,
    RoleGuard,
    category::Category,
    customer_access, get_trend,
    model::{ModelDigest, TopElementCountsByColumn},
    qualifier::Qualifier,
    slicing,
    status::Status,
    training_result,
};
use crate::graphql::{query, statistics::i64_to_naive_date_time};

#[derive(Default)]
pub(super) struct ClusterQuery;

#[Object]
impl ClusterQuery {
    /// A list of clusters in descending order of cluster size, then of
    /// cluster id.
    ///
    /// With `previous`, the clusters of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn clusters(
        &self,
        ctx: &Context<'_>,
        model: ID,
        categories: Option<Vec<ID>>,
        detectors: Option<Vec<ID>>,
        qualifiers: Option<Vec<ID>>,
        statuses: Option<Vec<ID>>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<Connection<OpaqueCursor<(u32, i64)>, Cluster, ClusterTotalCount, EmptyFields>> {
        let previous = previous.unwrap_or_default();
        let model = model.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let categories = try_id_args_into_ints::<i32>(categories)?;
        let detectors = try_id_args_into_ints::<i32>(detectors)?;
        let qualifiers = try_id_args_into_ints::<i32>(qualifiers)?;
        let statuses = try_id_args_into_ints::<i32>(statuses)?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(
                    ctx,
                    model,
                    ClusterFilter {
                        categories,
                        detectors,
                        qualifiers,
                        statuses,
                    },
                    previous,
                    after,
                    before,
                    first,
                    last,
                )
                .await
            },
        )
        .await
    }

    /// The top IP addresses of a cluster, by column.
    ///
    /// With `previous`, the cluster and its column statistics are those of
    /// the model's previous training result.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_ip_addresses_of_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster_id: ID,
        size: Option<i32>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        const DEFAULT_SIZE: i32 = 30;
        let previous = previous.unwrap_or_default();
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id(u32)")?;
        let cluster_id = cluster_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid cluster id")?;
        customer_access::load_accessible_model(ctx, "model", model_id)?;

        let store = crate::graphql::get_store(ctx)?;
        let cluster_ids = load_cluster_ids(&store, model_id, Some(cluster_id), previous)?;

        let map = training_result::column_stats_map(&store, previous);
        let counts = map.get_top_ip_addresses_of_cluster(model_id, &cluster_ids, size)?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    /// The time series of a cluster.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_time_series_of_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster_id: ID,
        #[graphql(
            desc = "The dimensionless cutoff rate, strictly greater than 0 with no upper limit. Omitted or null values use 0.1.",
            validator(custom = "PositiveCutoffRate")
        )]
        cutoff_rate: Option<f64>,
        #[graphql(
            desc = "The dimensionless trend filter order, from 0 to 20 inclusive. Omitted or null values use 4.",
            validator(
                minimum = 0,
                custom = "|value: &i32| async_graphql::validators::maximum(value, MAX_TRENDI_ORDER)"
            )
        )]
        trendi_order: Option<i32>,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<TimeSeriesResult> {
        let start = start.map(super::outlier::timestamp_nanos).transpose()?;
        let end = end.map(super::outlier::timestamp_nanos).transpose()?;
        let id = cluster_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid cluster id")?;
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.time_series_map();
        let time_series = map.get_top_time_series_of_cluster(model, id, start, end)?;

        Ok(TimeSeriesResult::from_database(
            time_series,
            cutoff_rate.unwrap_or(DEFAULT_CUTOFF_RATE),
            trendi_order.unwrap_or(DEFAULT_TRENDI_ORDER),
        ))
    }
}

#[derive(Default)]
pub(super) struct ClusterMutation;

#[Object]
impl ClusterMutation {
    /// Updates the given cluster.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        id: ID,
        category: Option<ID>,
        qualifier: Option<ID>,
        status: Option<ID>,
    ) -> Result<ID> {
        let id_to_i32 = |v: ID| v.as_str().parse().ok();

        let status = status.and_then(id_to_i32);
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.cluster_map();
        map.update_cluster(
            model,
            id.as_str().parse()?,
            category.and_then(id_to_i32),
            qualifier.and_then(id_to_i32),
            status,
        )?;
        Ok(id)
    }
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
struct Cluster {
    #[graphql(skip)]
    id: u32,
    #[graphql(skip)]
    category: i32,
    detector: i32,
    #[graphql(skip)]
    events: Vec<i64>,
    labels: Option<Vec<String>>,
    #[graphql(skip)]
    qualifier: i32,
    #[graphql(skip)]
    status: i32,
    signature: String,
    size: i64,
    score: Option<f64>,
    #[graphql(skip)]
    model_id: u32,
    last_modification_time: Option<NaiveDateTime>,
}

#[ComplexObject]
impl Cluster {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn category(&self, ctx: &Context<'_>) -> Result<Category> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let map = db.category_map();
        let Some(res) = map.get_by_id(u32::try_from(self.category)?)? else {
            return Err("no such category".into());
        };
        Ok(res.into())
    }

    async fn events(&self) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| super::outlier::datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<ModelDigest> {
        Ok(customer_access::load_accessible_model(ctx, "modelId", self.model_id)?.into())
    }

    async fn qualifier(&self, ctx: &Context<'_>) -> Result<Qualifier> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let map = db.qualifier_map();
        let Some(res) = map.get_by_id(u32::try_from(self.qualifier).expect("invalid id"))? else {
            return Err("no such qualifier".into());
        };
        Ok(res.into())
    }

    async fn status(&self, ctx: &Context<'_>) -> Result<Status> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let map = db.status_map();
        let Some(res) = map.get_by_id(u32::try_from(self.status).expect("invalid id"))? else {
            return Err("no such status".into());
        };
        Ok(res.into())
    }
}

/// The filters of a `clusters` query.
struct ClusterFilter {
    categories: Option<Vec<i32>>,
    detectors: Option<Vec<i32>>,
    qualifiers: Option<Vec<i32>>,
    statuses: Option<Vec<i32>>,
}

struct ClusterTotalCount {
    model_id: u32,
    filter: ClusterFilter,
    previous: bool,
}

#[Object]
impl ClusterTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::cluster_map(&store, self.previous);
        Ok(StringNumber(map.count_clusters(
            self.model_id,
            self.filter.categories.as_deref(),
            self.filter.detectors.as_deref(),
            self.filter.qualifiers.as_deref(),
            self.filter.statuses.as_deref(),
        )?))
    }
}

struct TimeSeriesResult {
    inner: (Option<i64>, Option<i64>, Vec<database::ColumnTimeSeries>), //earliest, latest, series
    cutoff_rate: f64,
    trendi_order: i32,
}

#[Object]
impl TimeSeriesResult {
    async fn earliest(&self) -> Option<DateTime<Utc>> {
        self.inner.0.map(DateTime::from_timestamp_nanos)
    }

    async fn latest(&self) -> Option<DateTime<Utc>> {
        self.inner.1.map(DateTime::from_timestamp_nanos)
    }

    async fn series(&self) -> Vec<ColumnTimeSeries<'_>> {
        self.inner
            .2
            .iter()
            .map(|s| ColumnTimeSeries::from_database(s, self.cutoff_rate, self.trendi_order))
            .collect()
    }
}

impl TimeSeriesResult {
    fn from_database(
        inner: (Option<i64>, Option<i64>, Vec<database::ColumnTimeSeries>),
        cutoff_rate: f64,
        trendi_order: i32,
    ) -> Self {
        Self {
            inner,
            cutoff_rate,
            trendi_order,
        }
    }
}

struct ColumnTimeSeries<'a> {
    inner: &'a database::ColumnTimeSeries,
    cutoff_rate: f64,
    trendi_order: i32,
}

#[Object]
impl ColumnTimeSeries<'_> {
    /// The column index of the time series in string within the representable
    /// range of `usize`.
    async fn column_index(&self) -> StringNumber<usize> {
        // 100_000 means counting events themselves, not any other column values.
        StringNumber(
            self.inner
                .index
                .map_or(100_000, |i| i.to_usize().expect("safe: positive")),
        )
    }

    async fn series(&self) -> Vec<TimeCount> {
        self.inner.time_counts.iter().map(Into::into).collect()
    }

    /// The trend with negative counts mapped to 0 and other counts rounded to
    /// the nearest integer, with exact halves toward the larger integer.
    /// Empty when the trend cannot be computed.
    async fn series_trend(&self) -> Vec<TimeCount> {
        let Ok(trend) = get_trend(&self.inner.time_counts, self.cutoff_rate, self.trendi_order)
        else {
            return Vec::new();
        };
        trend
            .iter()
            .enumerate()
            .map(|(index, t)| TimeCount {
                time: i64_to_naive_date_time(self.inner.time_counts[index].0),
                count: super::trend_count(*t).expect("get_trend validated every count"),
            })
            .collect::<Vec<_>>()
    }
}

impl<'a> ColumnTimeSeries<'a> {
    fn from_database(
        inner: &'a database::ColumnTimeSeries,
        cutoff_rate: f64,
        trendi_order: i32,
    ) -> Self {
        Self {
            inner,
            cutoff_rate,
            trendi_order,
        }
    }
}

#[derive(SimpleObject)]
pub(super) struct TimeCount {
    pub(super) time: NaiveDateTime,
    pub(super) count: usize,
}

impl From<&super::TimeCount> for TimeCount {
    fn from(inner: &super::TimeCount) -> Self {
        Self {
            time: i64_to_naive_date_time(inner.0),
            count: inner.1,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn load(
    ctx: &Context<'_>,
    model: u32,
    filter: ClusterFilter,
    previous: bool,
    after: Option<OpaqueCursor<(u32, i64)>>,
    before: Option<OpaqueCursor<(u32, i64)>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<(u32, i64)>, Cluster, ClusterTotalCount, EmptyFields>> {
    let is_first = first.is_some();
    let limit = slicing::len(first, last)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = training_result::cluster_map(&store, previous);
    // `load_clusters` cuts its limit in cluster-id order before it sorts by
    // size, so it is asked for every eligible cluster, sorted: by descending
    // size then id for `first`, ascending for `last`. The rows nearest the
    // cursor come first either way; one more than the page tells
    // `page_info` whether another page follows.
    let mut rows = map.load_clusters(
        model,
        filter.categories.as_deref(),
        filter.detectors.as_deref(),
        filter.qualifiers.as_deref(),
        filter.statuses.as_deref(),
        &after.map(|c| c.0),
        &before.map(|c| c.0),
        is_first,
        usize::MAX,
    )?;
    rows.truncate(limit.saturating_add(1));
    if !is_first {
        rows.reverse();
    }

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        ClusterTotalCount {
            model_id: model,
            filter,
            previous,
        },
    );
    connection.edges.extend(rows.into_iter().map(|c| {
        Edge::new(
            OpaqueCursor((c.id, c.size)),
            Cluster {
                id: c.id,
                category: c.category_id,
                detector: c.detector_id,
                events: c.event_ids,
                labels: c.labels,
                qualifier: c.qualifier_id,
                status: c.status_id,
                signature: c.signature,
                size: c.size,
                score: c.score,
                model_id: c.model_id,
                last_modification_time: c.last_modification_time,
            },
        )
    }));
    Ok(connection)
}

pub(super) fn try_id_args_into_ints<T>(ids: Option<Vec<ID>>) -> Result<Option<Vec<T>>>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    if let Some(ids) = ids {
        let mut ints = Vec::with_capacity(ids.len());
        for id in ids {
            ints.push(id.as_str().parse()?);
        }
        Ok(Some(ints))
    } else {
        Ok(None)
    }
}

const UNCATEGORIZED: i32 = 2;

/// Loads cluster IDs for the given model, excluding "Uncategorized" clusters.
///
/// # Errors
///
/// Returns an error if a database operation fails.
fn load_cluster_ids(
    store: &database::Store,
    model_id: u32,
    cluster_id: Option<u32>,
    previous: bool,
) -> Result<Vec<u32>> {
    let map = training_result::cluster_map(store, previous);
    let clusters = map.load_clusters(
        model_id,
        None,
        None,
        None,
        None,
        &None,
        &None,
        true,
        usize::MAX,
    )?;

    let ids: Vec<u32> = clusters
        .into_iter()
        .filter(|c| c.category_id != UNCATEGORIZED)
        .filter(|c| cluster_id.is_none_or(|id| c.id == id))
        .map(|c| c.id)
        .collect();

    Ok(ids)
}

#[cfg(test)]
mod tests {
    use review_database::Store;
    use serde_json::Value;

    use crate::graphql::model_test_support::{data, replace_model};
    use crate::graphql::{Role, TestSchema};

    const CUSTOMER: u32 = 1;
    const CATEGORY: i32 = 1;
    const OTHER_CATEGORY: i32 = 3;

    /// Stores clusters `ids` of `model` whose sizes grow with their ids, so
    /// size order runs opposite to id order. Every third cluster is of
    /// another category.
    fn put_clusters(store: &Store, model: u32, ids: std::ops::RangeInclusive<u32>) {
        for id in ids {
            store
                .cluster_map()
                .put(&review_database::Cluster {
                    model_id: model,
                    id,
                    category_id: if id % 3 == 0 {
                        OTHER_CATEGORY
                    } else {
                        CATEGORY
                    },
                    detector_id: 1,
                    event_ids: vec![],
                    sensors: vec![],
                    labels: None,
                    qualifier_id: 1,
                    status_id: 1,
                    signature: String::new(),
                    size: i64::from(id) * 10,
                    score: None,
                    last_modification_time: None,
                })
                .unwrap();
        }
    }

    struct Page {
        ids: Vec<u32>,
        has_next: bool,
        has_previous: bool,
        start: Option<String>,
        end: Option<String>,
    }

    async fn page(schema: &TestSchema, model: u32, filter: &str, arguments: &str) -> Page {
        let query = format!(
            "{{ clusters(model: {model}{filter}, {arguments}) {{ nodes {{ id }}
                pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }} }} }}"
        );
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![CUSTOMER]))
            .await;
        let json = data(res);
        let connection = &json["clusters"];
        let cursor = |name: &str| connection["pageInfo"][name].as_str().map(str::to_string);
        Page {
            ids: connection["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node["id"].as_str().unwrap().parse().unwrap())
                .collect(),
            has_next: connection["pageInfo"]["hasNextPage"] == Value::Bool(true),
            has_previous: connection["pageInfo"]["hasPreviousPage"] == Value::Bool(true),
            start: cursor("startCursor"),
            end: cursor("endCursor"),
        }
    }

    /// Pages forward and backward through the clusters, two at a time,
    /// checking the page info, and returns the ids in the order read.
    async fn walk(schema: &TestSchema, model: u32, filter: &str) -> (Vec<u32>, Vec<u32>) {
        let mut forward = Vec::new();
        let mut arguments = "first: 2".to_string();
        loop {
            let next = page(schema, model, filter, &arguments).await;
            forward.extend(&next.ids);
            if !next.has_next {
                break;
            }
            assert_eq!(next.ids.len(), 2);
            arguments = format!("first: 2, after: \"{}\"", next.end.unwrap());
        }

        let mut backward = Vec::new();
        let mut arguments = "last: 2".to_string();
        loop {
            let next = page(schema, model, filter, &arguments).await;
            let mut ids = next.ids.clone();
            ids.extend(backward);
            backward = ids;
            if !next.has_previous {
                break;
            }
            assert_eq!(next.ids.len(), 2);
            arguments = format!("last: 2, before: \"{}\"", next.start.unwrap());
        }
        (forward, backward)
    }

    #[tokio::test]
    async fn clusters_page_in_size_order() {
        let schema = TestSchema::new().await;
        let model = {
            let store = schema.store();
            let model = replace_model(&store, "model", CUSTOMER);
            put_clusters(&store, model, 1..=9);
            replace_model(&store, "model", CUSTOMER);
            put_clusters(&store, model, 1..=7);
            model
        };
        let categories = format!(", categories: [\"{CATEGORY}\"]");
        for (filter, expected) in [
            (String::new(), vec![7, 6, 5, 4, 3, 2, 1]),
            (categories.clone(), vec![7, 5, 4, 2, 1]),
            (
                ", previous: true".to_string(),
                vec![9, 8, 7, 6, 5, 4, 3, 2, 1],
            ),
            (
                format!("{categories}, previous: true"),
                vec![8, 7, 5, 4, 2, 1],
            ),
        ] {
            let (forward, backward) = walk(&schema, model, &filter).await;
            assert_eq!(forward, expected, "{filter}");
            assert_eq!(backward, expected, "{filter}");
        }
    }
}
