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
    DEFAULT_CUTOFF_RATE, DEFAULT_TRENDI_ORDER, Role, RoleGuard,
    category::Category,
    get_trend,
    model::{ModelDigest, TopElementCountsByColumn},
    qualifier::Qualifier,
    slicing,
    status::Status,
};
use crate::graphql::{query, statistics::i64_to_naive_date_time};

#[derive(Default)]
pub(super) struct ClusterQuery;

#[Object]
impl ClusterQuery {
    /// A list of clusters in descending order of cluster size.
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
    ) -> Result<Connection<OpaqueCursor<(i32, i64)>, Cluster, ClusterTotalCount, EmptyFields>> {
        let model = model.as_str().parse()?;
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
                    ctx, model, categories, detectors, qualifiers, statuses, after, before, first,
                    last,
                )
                .await
            },
        )
        .await
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_ip_addresses_of_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster_id: String,
        size: Option<i32>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        const DEFAULT_SIZE: i32 = 30;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id(u32)")?;
        let cluster_id_to_i32 = cluster_id
            .parse::<i32>()
            .map_err(|_| "invalid cluster id")?;

        let store = crate::graphql::get_store(ctx)?;
        let cluster_ids = load_cluster_ids(&store, model_id, Some(cluster_id_to_i32))?;

        let map = store.column_stats_map();
        let counts = map.get_top_ip_addresses_of_cluster(model_id, &cluster_ids, size)?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_time_series_of_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster_id: String,
        cutoff_rate: Option<f64>,
        trendi_order: Option<i32>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<TimeSeriesResult> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.time_series_map();
        let id = cluster_id
            .parse::<i32>()
            .map_err(|_| "invalid cluster id")?;
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
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
        let store = crate::graphql::get_store(ctx)?;
        let map = store.cluster_map();
        let id_to_i32 = |v: ID| v.as_str().parse().ok();

        let status = status.and_then(id_to_i32);
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
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
    id: i32,
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
        let store = crate::graphql::get_store(ctx)?;
        let map = store.model_map();
        Ok(map.load_model(self.model_id)?.into())
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

struct ClusterTotalCount {
    model_id: u32,
    categories: Option<Vec<i32>>,
    detectors: Option<Vec<i32>>,
    qualifiers: Option<Vec<i32>>,
    statuses: Option<Vec<i32>>,
}

#[Object]
impl ClusterTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.cluster_map();
        Ok(map.count_clusters(
            self.model_id,
            self.categories.as_deref(),
            self.detectors.as_deref(),
            self.qualifiers.as_deref(),
            self.statuses.as_deref(),
        )?)
    }
}

struct TimeSeriesResult {
    inner: (Option<i64>, Option<i64>, Vec<database::ColumnTimeSeries>), //earliest, latest, series
    cutoff_rate: f64,
    trendi_order: i32,
}

#[Object]
impl TimeSeriesResult {
    async fn earliest(&self) -> Option<NaiveDateTime> {
        self.inner.0.map(i64_to_naive_date_time)
    }

    async fn latest(&self) -> Option<NaiveDateTime> {
        self.inner.1.map(i64_to_naive_date_time)
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
                count: t.trunc().to_usize().unwrap_or(0), // unwrap_or is for minus
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
    categories: Option<Vec<i32>>,
    detectors: Option<Vec<i32>>,
    qualifiers: Option<Vec<i32>>,
    statuses: Option<Vec<i32>>,
    after: Option<OpaqueCursor<(i32, i64)>>,
    before: Option<OpaqueCursor<(i32, i64)>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<(i32, i64)>, Cluster, ClusterTotalCount, EmptyFields>> {
    let is_first = first.is_some();
    let limit = slicing::len(first, last)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.cluster_map();
    let rows = map.load_clusters(
        model,
        categories.as_deref(),
        detectors.as_deref(),
        qualifiers.as_deref(),
        statuses.as_deref(),
        &after.map(|c| c.0),
        &before.map(|c| c.0),
        is_first,
        limit,
    )?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        ClusterTotalCount {
            model_id: model,
            categories,
            detectors,
            qualifiers,
            statuses,
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
    cluster_id: Option<i32>,
) -> Result<Vec<i32>> {
    let map = store.cluster_map();
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

    let ids: Vec<i32> = clusters
        .into_iter()
        .filter(|c| c.category_id != UNCATEGORIZED)
        .filter(|c| cluster_id.is_none_or(|id| c.id == id))
        .map(|c| c.id)
        .collect();

    Ok(ids)
}
