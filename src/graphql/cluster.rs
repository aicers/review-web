use std::sync::Arc;

use async_graphql::{
    connection::{Connection, Edge, EmptyFields},
    types::ID,
    ComplexObject, Context, Object, Result, SimpleObject, StringNumber,
};
use chrono::NaiveDateTime;
use chrono::{DateTime, Utc};
use database::Store;
use num_traits::ToPrimitive;
use review_database::{self as database, Database};
use tokio::sync::RwLock;

use super::{
    category::Category,
    get_trend,
    model::{ModelDigest, TopElementCountsByColumn},
    qualifier::Qualifier,
    slicing,
    status::Status,
    Role, RoleGuard, DEFAULT_CUTOFF_RATE, DEFAULT_TRENDI_ORDER,
};
use crate::graphql::query;

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
    ) -> Result<Connection<String, Cluster, ClusterTotalCount, EmptyFields>> {
        let model = model.as_str().parse()?;
        let categories = try_id_args_into_ints(categories)?;
        let detectors = try_id_args_into_ints(detectors)?;
        let qualifiers = try_id_args_into_ints(qualifiers)?;
        let statuses = try_id_args_into_ints(statuses)?;

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
        model: i32,
        cluster_id: String,
        size: Option<i32>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        const DEFAULT_SIZE: i32 = 30;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;

        let db = ctx.data::<Database>()?;
        let counts = db
            .get_top_ip_addresses_of_cluster(model, &cluster_id, size)
            .await?;
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
        model: i32,
        cluster_id: String,
        cutoff_rate: Option<f64>,
        trendi_order: Option<i32>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<TimeSeriesResult> {
        let db = ctx.data::<Database>()?;
        let time_series = db
            .get_top_time_series_of_cluster(model, &cluster_id, start, end)
            .await?;

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
        id: ID,
        category: Option<ID>,
        qualifier: Option<ID>,
        status: Option<ID>,
    ) -> Result<ID> {
        let db = ctx.data::<Database>()?;
        let id_to_i32 = |v: ID| v.as_str().parse().ok();

        let status = status.and_then(id_to_i32);
        db.update_cluster(
            id.as_str().parse()?,
            category.and_then(id_to_i32),
            qualifier.and_then(id_to_i32),
            status,
        )
        .await?;
        Ok(id)
    }
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
struct Cluster {
    #[graphql(skip)]
    id: i32,
    name: String,
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
    model_id: i32,
    last_modification_time: Option<NaiveDateTime>,
}

#[ComplexObject]
impl Cluster {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn category(&self, ctx: &Context<'_>) -> Result<Category> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
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
        let db = ctx.data::<Database>()?;
        Ok(db.load_model(self.model_id).await?.into())
    }

    async fn qualifier(&self, ctx: &Context<'_>) -> Result<Qualifier> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.qualifier_map();
        let Some(res) = map.get_by_id(u32::try_from(self.qualifier).expect("invalid id"))? else {
            return Err("no such qualifier".into());
        };
        Ok(res.into())
    }

    async fn status(&self, ctx: &Context<'_>) -> Result<Status> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.status_map();
        let Some(res) = map.get_by_id(u32::try_from(self.status).expect("invalid id"))? else {
            return Err("no such status".into());
        };
        Ok(res.into())
    }
}

struct ClusterTotalCount {
    model_id: i32,
    categories: Option<Vec<i32>>,
    detectors: Option<Vec<i32>>,
    qualifiers: Option<Vec<i32>>,
    statuses: Option<Vec<i32>>,
}

#[Object]
impl ClusterTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Database>()?;
        Ok(db
            .count_clusters(
                self.model_id,
                self.categories.as_deref(),
                self.detectors.as_deref(),
                self.qualifiers.as_deref(),
                self.statuses.as_deref(),
            )
            .await?)
    }
}

struct TimeSeriesResult {
    inner: database::TimeSeriesResult,
    cutoff_rate: f64,
    trendi_order: i32,
}

#[Object]
impl TimeSeriesResult {
    async fn earliest(&self) -> Option<NaiveDateTime> {
        self.inner.earliest
    }

    async fn latest(&self) -> Option<NaiveDateTime> {
        self.inner.latest
    }

    async fn series(&self) -> Vec<ColumnTimeSeries> {
        self.inner
            .series
            .iter()
            .map(|s| ColumnTimeSeries::from_database(s, self.cutoff_rate, self.trendi_order))
            .collect()
    }
}

impl TimeSeriesResult {
    fn from_database(
        inner: database::TimeSeriesResult,
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
        StringNumber(self.inner.column_index)
    }

    async fn series(&self) -> Vec<TimeCount> {
        self.inner.series.iter().map(Into::into).collect()
    }

    async fn series_trend(&self) -> Vec<TimeCount> {
        let Ok(trend) = get_trend(&self.inner.series, self.cutoff_rate, self.trendi_order) else {
            return Vec::new();
        };
        trend
            .iter()
            .enumerate()
            .map(|(index, t)| TimeCount {
                time: self.inner.series[index].time,
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

impl From<&database::TimeCount> for TimeCount {
    fn from(inner: &database::TimeCount) -> Self {
        Self {
            time: inner.time,
            count: inner.count,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn load(
    ctx: &Context<'_>,
    model: i32,
    categories: Option<Vec<i32>>,
    detectors: Option<Vec<i32>>,
    qualifiers: Option<Vec<i32>>,
    statuses: Option<Vec<i32>>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Cluster, ClusterTotalCount, EmptyFields>> {
    let after = slicing::decode_cursor(&after)?;
    let before = slicing::decode_cursor(&before)?;
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db
        .load_clusters(
            model,
            categories.as_deref(),
            detectors.as_deref(),
            qualifiers.as_deref(),
            statuses.as_deref(),
            &after,
            &before,
            is_first,
            limit,
        )
        .await?;

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
        let cursor = slicing::encode_cursor(c.id, c.size);
        Edge::new(
            cursor,
            Cluster {
                id: c.id,
                name: c.cluster_id,
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

fn try_id_args_into_ints(ids: Option<Vec<ID>>) -> Result<Option<Vec<i32>>> {
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
