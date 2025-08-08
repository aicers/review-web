use std::sync::Arc;

use async_graphql::{
    Context, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
    types::ID,
};
use chrono::NaiveDateTime;
use database::Store;
use num_traits::ToPrimitive;
use review_database::{self as database, Database};
use tokio::sync::RwLock;

use super::{
    DEFAULT_CUTOFF_RATE, DEFAULT_TRENDI_ORDER, Role, RoleGuard, cluster::TimeCount,
    data_source::DataSource, fill_vacant_time_slots, get_trend, slicing,
};
use crate::graphql::query;

const DEFAULT_MIN_SLOPE: f64 = 10.0;
const DEFAULT_MIN_ZERO_COUNT_FOR_TREND: u32 = 5;

#[derive(Default)]
pub(super) struct ModelQuery;

#[Object]
impl ModelQuery {
    /// A list of models.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn models(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<(i32, String)>, ModelDigest, ModelTotalCount, EmptyFields>>
    {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn csv_column_extra(
        &self,
        ctx: &Context<'_>,
        model: i32,
    ) -> Result<Option<CsvColumnExtraConfig>> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.csv_column_extra_map();
        Ok(map
            .get_by_model(model)?
            .map(|config| CsvColumnExtraConfig { inner: config }))
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn structured_column_types(
        &self,
        ctx: &Context<'_>,
        model: i32,
    ) -> Result<Vec<StructuredColumnType>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.column_stats_map();
        let types = map.get_column_types_of_model(model)?;
        Ok(types.into_iter().map(Into::into).collect())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn time_range_of_model(&self, ctx: &Context<'_>, model: i32) -> Result<TimeRange> {
        let db = ctx.data::<Database>()?;
        let (lower, upper) = db.get_time_range_of_model(model).await?;
        Ok(TimeRange { lower, upper })
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn top_time_series(
        &self,
        ctx: &Context<'_>,
        model: i32,
        size: Option<i32>,
        time: Option<NaiveDateTime>,
        min_slope: Option<f64>,
        trendi_order: Option<i32>,
        cutoff_rate: Option<f64>,
        trend_category: Option<String>,
        start: Option<i64>,
        end: Option<i64>,
    ) -> Result<Vec<TopTrendsByColumn>> {
        const DEFAULT_SIZE: i32 = 20;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;

        let db = ctx.data::<Database>()?;
        let time_series = db
            .get_top_time_series_of_model(model, time, start, end)
            .await?;
        let mut time_series = time_series
            .into_iter()
            .map(|s| {
                TopTrendsByColumn::from_database(
                    s,
                    cutoff_rate.unwrap_or(DEFAULT_CUTOFF_RATE),
                    trendi_order.unwrap_or(DEFAULT_TRENDI_ORDER),
                    min_slope.unwrap_or(DEFAULT_MIN_SLOPE),
                )
            })
            .collect();
        if let Some(category) = trend_category.as_ref() {
            sort_on_category(category, &mut time_series);
        }
        for s in &mut time_series {
            s.trends.truncate(size);
        }
        time_series.sort_by_key(|elem| elem.count_index);
        Ok(time_series)
    }

    #[allow(unused_variables)] // This will be deleted in the future (#309)
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_clusters_by_score(
        &self,
        _ctx: &Context<'_>,
        model: i32,
        size: Option<i32>,
        time: Option<NaiveDateTime>,
    ) -> Result<ClusterScoreSet> {
        Ok(ClusterScoreSet {
            top_n_sum: Vec::new(),
            top_n_rate: Vec::new(),
        })
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_columns(
        &self,
        ctx: &Context<'_>,
        model: i32,
        size: Option<i32>,
        time: Option<NaiveDateTime>,
        portion_of_clusters: Option<f64>,
        portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        const DEFAULT_SIZE: i32 = 30;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;
        let db = ctx.data::<Database>()?;
        let cluster_ids = db
            .load_cluster_ids_with_size_limit(model, portion_of_clusters)
            .await?
            .into_iter()
            .filter_map(|id| id.to_u32())
            .collect();

        let store = crate::graphql::get_store(ctx).await?;
        let csv_column_extra_map = store.csv_column_extra_map();
        let Some(csv_extra) = csv_column_extra_map
            .get_by_model(model)
            .map_err(|e| format!("Failed to get csv column extra: {e}"))?
        else {
            return Ok(Vec::new());
        };
        let Some(top_n) = csv_extra.column_top_n else {
            return Ok(Vec::new());
        };

        let column_stats_map = store.column_stats_map();
        let counts = column_stats_map.get_top_columns_of_model(
            model,
            cluster_ids,
            &top_n,
            size,
            time,
            portion_of_top_n,
        )?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_ip_addresses(
        &self,
        ctx: &Context<'_>,
        model: i32,
        size: Option<i32>,
        time: Option<NaiveDateTime>,
        portion_of_clusters: Option<f64>,
        portion_of_top_elements: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>> {
        const DEFAULT_SIZE: i32 = 30;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;

        let db = ctx.data::<Database>()?;

        let cluster_ids: Vec<u32> = db
            .load_cluster_ids_with_size_limit(model, portion_of_clusters)
            .await?
            .into_iter()
            .filter_map(|id| id.to_u32())
            .collect();

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.column_stats_map();
        let counts = map.get_top_ip_addresses_of_model(
            model,
            &cluster_ids,
            size,
            time,
            portion_of_top_elements,
        )?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_multimaps(
        &self,
        ctx: &Context<'_>,
        model: i32,
        size: Option<i32>,
        min_map_size: Option<i32>,
        time: Option<NaiveDateTime>,
    ) -> Result<Vec<TopMultimaps>> {
        const DEFAULT_SIZE: i32 = 30;
        const DEFAULT_MIN_MAP_SIZE: i32 = 5;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;
        let min_map_size = min_map_size
            .unwrap_or(DEFAULT_MIN_MAP_SIZE)
            .to_usize()
            .ok_or("invalid minMapSize")?;

        let db = ctx.data::<Database>()?;
        let cluster_ids: Vec<(u32, String)> = db
            .load_cluster_ids(model, None)
            .await?
            .into_iter()
            .filter_map(|(id, name)| id.to_u32().map(|id| (id, name)))
            .collect();

        let store = crate::graphql::get_store(ctx).await?;
        let csv_column_extra_map = store.csv_column_extra_map();
        let csv_extra = csv_column_extra_map
            .get_by_model(model)
            .map_err(|e| format!("Failed to get csv column extra: {e}"))?;
        let (column_1, column_n) = if let Some(csv_extra) = csv_extra {
            (csv_extra.column_1, csv_extra.column_n)
        } else {
            (None, None)
        };

        let column_stats_map = store.column_stats_map();
        let maps = column_stats_map.get_top_multimaps_of_model(
            model,
            cluster_ids,
            (&column_1.unwrap_or_default(), &column_n.unwrap_or_default()),
            size,
            min_map_size,
            time,
        )?;
        Ok(maps.into_iter().map(Into::into).collect())
    }
}

#[derive(Default)]
pub(super) struct ModelMutation;

#[Object]
impl ModelMutation {
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_csv_column_extra(
        &self,
        ctx: &Context<'_>,
        model: i32,
        column_alias: Option<Vec<String>>,
        column_display: Option<Vec<bool>>,
        column_top_n: Option<Vec<bool>>,
        column_1: Option<Vec<bool>>,
        column_n: Option<Vec<bool>>,
    ) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.csv_column_extra_map();
        Ok(ID(map
            .insert(
                model,
                column_alias.as_deref(),
                column_display.as_deref(),
                column_top_n.as_deref(),
                column_1.as_deref(),
                column_n.as_deref(),
            )?
            .to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_csv_column_extra(
        &self,
        ctx: &Context<'_>,
        id: ID,
        column_alias: Option<Vec<String>>,
        column_display: Option<Vec<bool>>,
        column_top_n: Option<Vec<bool>>,
        column_1: Option<Vec<bool>>,
        column_n: Option<Vec<bool>>,
    ) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.csv_column_extra_map();
        map.update(
            id.as_str().parse()?,
            column_alias.as_deref(),
            column_display.as_deref(),
            column_top_n.as_deref(),
            column_1.as_deref(),
            column_n.as_deref(),
        )?;
        Ok(id)
    }
}

fn sort_on_category(category: &str, series: &mut Vec<TopTrendsByColumn>) {
    match category {
        "up_number" => {
            for s in series {
                s.trends
                    .sort_by(|a, b| b.number_of_ups.cmp(&a.number_of_ups));
                // by up_number
            }
        }
        "up_steepness" => {
            for s in series {
                s.trends.sort_by(|a, b| {
                    b.maximum_slope
                        .partial_cmp(&a.maximum_slope)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }); // by up_number
            }
        }
        "up_span" => {
            for s in series {
                s.trends
                    .sort_by(|a, b| b.longest_up_span.cmp(&a.longest_up_span));
                // by up_number
            }
        }
        _ => (),
    }
}

#[derive(SimpleObject)]
struct ClusterScore {
    cluster_id: ID,
    cluster_name: String,
    score: f64,
}

#[derive(SimpleObject)]
struct ClusterScoreSet {
    top_n_sum: Vec<ClusterScore>,
    top_n_rate: Vec<ClusterScore>,
}

struct CsvColumnExtraConfig {
    inner: database::CsvColumnExtraConfig,
}

#[Object]
impl CsvColumnExtraConfig {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn model_id(&self) -> i32 {
        self.inner.model_id
    }

    async fn column_alias(&self) -> &Option<Vec<String>> {
        &self.inner.column_alias
    }

    async fn column_display(&self) -> &Option<Vec<bool>> {
        &self.inner.column_display
    }

    async fn column_top_n(&self) -> &Option<Vec<bool>> {
        &self.inner.column_top_n
    }

    async fn column_1(&self) -> &Option<Vec<bool>> {
        &self.inner.column_1
    }

    async fn column_n(&self) -> &Option<Vec<bool>> {
        &self.inner.column_n
    }
}

pub(super) struct ModelDigest {
    inner: database::ModelDigest,
}

impl From<database::ModelDigest> for ModelDigest {
    fn from(inner: database::ModelDigest) -> Self {
        Self { inner }
    }
}

#[Object]
impl ModelDigest {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn data_source(&self, ctx: &Context<'_>) -> Result<DataSource> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.data_source_map();
        #[allow(clippy::cast_sign_loss)] // u32 stored as i32 in the database
        match map
            .get_by_id(self.inner.data_source_id as u32)
            .map_err(|_| "failed to read data source")?
        {
            Some(ds) => Ok(ds.into()),
            None => Err("no such data source".into()),
        }
    }
}

struct StructuredColumnType {
    inner: database::StructuredColumnType,
}

#[Object]
impl StructuredColumnType {
    async fn column_index(&self) -> i32 {
        self.inner.column_index
    }

    async fn data_type(&self) -> &str {
        &self.inner.data_type
    }
}

impl From<database::StructuredColumnType> for StructuredColumnType {
    fn from(inner: database::StructuredColumnType) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
struct TimeRange {
    lower: Option<NaiveDateTime>,
    upper: Option<NaiveDateTime>,
}

struct ElementCount<'a> {
    inner: &'a database::ElementCount,
}

#[Object]
impl ElementCount<'_> {
    async fn value(&self) -> &str {
        &self.inner.value
    }

    /// The count of element in string representable by a `i64`.
    async fn count(&self) -> StringNumber<i64> {
        StringNumber(self.inner.count)
    }
}

impl<'a> From<&'a database::ElementCount> for ElementCount<'a> {
    fn from(inner: &'a database::ElementCount) -> Self {
        Self { inner }
    }
}

struct TopColumnsOfCluster<'a> {
    inner: &'a database::TopColumnsOfCluster,
}

#[Object]
impl TopColumnsOfCluster<'_> {
    async fn cluster_id(&self) -> &str {
        &self.inner.cluster_id
    }

    async fn columns(&self) -> Vec<TopElementCountsByColumn> {
        self.inner
            .columns
            .iter()
            .map(|t| t.clone().into())
            .collect()
    }
}

impl<'a> From<&'a database::TopColumnsOfCluster> for TopColumnsOfCluster<'a> {
    fn from(inner: &'a database::TopColumnsOfCluster) -> Self {
        Self { inner }
    }
}

pub(crate) struct TopElementCountsByColumn {
    inner: database::TopElementCountsByColumn,
}

#[Object]
impl TopElementCountsByColumn {
    /// The column index of top element counts by column in string
    /// representable within the range of a `usize`.
    async fn column_index(&self) -> StringNumber<usize> {
        StringNumber(self.inner.column_index)
    }

    async fn counts(&self) -> Vec<ElementCount<'_>> {
        self.inner.counts.iter().map(Into::into).collect()
    }
}

impl From<database::TopElementCountsByColumn> for TopElementCountsByColumn {
    fn from(inner: database::TopElementCountsByColumn) -> Self {
        Self { inner }
    }
}

struct TopMultimaps {
    inner: database::TopMultimaps,
}

#[Object]
impl TopMultimaps {
    /// The n index of multi map in string representable within the range of a
    /// `usize`.
    async fn n_index(&self) -> StringNumber<usize> {
        StringNumber(self.inner.n_index)
    }

    async fn selected(&self) -> Vec<TopColumnsOfCluster<'_>> {
        self.inner.selected.iter().map(Into::into).collect()
    }
}

impl From<database::TopMultimaps> for TopMultimaps {
    fn from(inner: database::TopMultimaps) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
struct TopTrendsByColumn {
    count_index: usize,
    trends: Vec<ClusterTrend>,
}

impl TopTrendsByColumn {
    fn from_database(
        inner: database::TopTrendsByColumn,
        cutoff_rate: f64,
        trendi_order: i32,
        min_slope: f64,
    ) -> Self {
        let count_index = inner.count_index;
        let trends = inner
            .trends
            .into_iter()
            .filter_map(|t| ClusterTrend::from_database(t, cutoff_rate, trendi_order, min_slope))
            .collect();
        Self {
            count_index,
            trends,
        }
    }
}

struct ClusterTrend {
    cluster_id: String,
    series: Vec<TimeCount>,
    trend: Vec<usize>,
    lines: Vec<LineSegment>,
    number_of_ups: usize,
    number_of_downs: usize,
    maximum_slope: f64,
    minimum_slope: f64,
    longest_up_span: usize,
    longest_down_span: usize,
}

#[Object]
impl ClusterTrend {
    async fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    async fn series(&self) -> &[TimeCount] {
        &self.series
    }

    /// The cluster trend in a vector of string representable by a vector of
    /// `usize`.
    async fn trend(&self) -> Vec<StringNumber<usize>> {
        self.trend.iter().map(|x| StringNumber(*x)).collect()
    }

    async fn lines(&self) -> &[LineSegment] {
        &self.lines
    }

    /// The number of ups of cluster trend in string represantable by a `
    /// usize`.
    async fn number_of_ups(&self) -> StringNumber<usize> {
        StringNumber(self.number_of_ups)
    }

    /// The number of downs of cluster trend in string represantable by a
    /// `usize`.
    async fn number_of_downs(&self) -> StringNumber<usize> {
        StringNumber(self.number_of_downs)
    }

    async fn maximum_slope(&self) -> f64 {
        self.maximum_slope
    }

    async fn minimum_slope(&self) -> f64 {
        self.minimum_slope
    }

    /// The longest up span of cluster trend in string represantable by a
    /// `usize`.
    async fn longest_up_span(&self) -> StringNumber<usize> {
        StringNumber(self.longest_up_span)
    }

    /// The longest down span of cluster trend in string represantable by a
    /// `usize`.
    async fn longest_down_span(&self) -> StringNumber<usize> {
        StringNumber(self.longest_down_span)
    }
}

impl ClusterTrend {
    fn from_database(
        inner: database::ClusterTrend,
        cutoff_rate: f64,
        trendi_order: i32,
        min_slope: f64,
    ) -> Option<Self> {
        let cluster_id = inner.cluster_id;
        let series = inner.series;
        let Ok(trend) = get_trend(&series, cutoff_rate, trendi_order) else {
            return None;
        };
        let trend = trend
            .iter()
            .map(|t| t.trunc().to_usize().unwrap_or(0)) // unwrap_or is for minus
            .collect::<Vec<_>>();
        let series = fill_vacant_time_slots(&series);
        let lines = find_lines(&series, &trend, min_slope);
        if lines.is_empty() {
            return None;
        }
        let (
            number_of_ups,
            number_of_downs,
            maximum_slope,
            minimum_slope,
            longest_up_span,
            longest_down_span,
        ) = analyze_lines(&lines);
        let series = series.iter().map(Into::into).collect();
        Some(Self {
            cluster_id,
            series,
            trend,
            lines,
            number_of_ups,
            number_of_downs,
            maximum_slope,
            minimum_slope,
            longest_up_span,
            longest_down_span,
        })
    }
}

#[allow(clippy::too_many_lines)]
fn find_lines(series: &[database::TimeCount], trend: &[usize], min_slope: f64) -> Vec<LineSegment> {
    let mut diff: Vec<f64> = Vec::new();
    for pair in trend.windows(2) {
        diff.push(
            pair[1].to_f64().expect("safe: usize -> f64")
                - pair[0].to_f64().expect("safe: usize -> f64"),
        );
    }

    if diff.is_empty() {
        return Vec::new();
    }

    let mut locations: Vec<usize> = Vec::new();
    let (mut sign, mut prev_sign, mut zero_count): (i32, i32, u32) = if diff[0] < 0.0 {
        // prev_sign - sign - this_sign
        (-1, -1, 0)
    } else if diff[0] == 0.0 {
        (0, 0, 1)
    } else {
        (1, 1, 0)
    };

    let mut zero_start: usize = 0;
    for (index, &elem) in diff.iter().enumerate().skip(1) {
        let this_sign: i32 = if elem < 0.0 {
            -1
        } else {
            i32::from(elem == 0.0)
        };

        if sign == 0 && this_sign == 0 {
            zero_count += 1;
        } else if sign == 0 && this_sign != 0 {
            if prev_sign == this_sign {
                if zero_count > DEFAULT_MIN_ZERO_COUNT_FOR_TREND {
                    locations.push(zero_start + 1);
                    locations.push(index);
                }
            } else if zero_count == 1 {
                locations.push(index);
            } else {
                locations.push(zero_start + 1);
                locations.push(index);
            }
            zero_count = 0;
        } else if sign != 0 && this_sign == 0 {
            zero_count = 1;
            zero_start = index;
        } else if sign != 0 && sign != this_sign {
            locations.push(index);
        }

        prev_sign = sign;
        sign = this_sign;
    }

    let mut line_segments_indices: Vec<(usize, usize)> = Vec::new();
    for index in 0..locations.len() {
        let first_index = if index == 0 { 0 } else { locations[index - 1] };
        let last_index = locations[index] - 1;
        line_segments_indices.push((first_index, last_index));
    }
    if locations.len() > 1 {
        line_segments_indices.push((locations[locations.len() - 1], diff.len() - 1));
    }

    let mut lines: Vec<LineSegment> = Vec::new();
    for seg in &line_segments_indices {
        let (first_index, last_index) = (seg.0, seg.1);
        // for original series
        let x_values: Vec<f64> = (first_index..=last_index)
            .map(|x| x.to_f64().expect("safe: usize -> f64"))
            .collect();
        let y_values: Vec<usize> = (first_index..=last_index)
            .map(|i| series[i].count)
            .collect();
        let y_values: Vec<f64> = y_values
            .iter()
            .map(|y| y.to_f64().expect("safe: usize -> f64"))
            .collect();
        let (slope, intercept, r_square) = linear_regression(&x_values, &y_values);
        let reg_original = Regression {
            slope,
            intercept,
            r_square,
        };

        // for trend
        let x_values: Vec<f64> = (first_index..=last_index)
            .map(|x| x.to_f64().expect("safe: usize -> f64"))
            .collect();
        let y_values: Vec<usize> = (first_index..=last_index).map(|i| trend[i]).collect();
        let y_values: Vec<f64> = y_values
            .iter()
            .map(|y| y.to_f64().expect("safe: usize -> f64"))
            .collect();
        let (slope, intercept, r_square) = linear_regression(&x_values, &y_values);
        let reg_trend = Regression {
            slope,
            intercept,
            r_square,
        };

        // HIGHLIHGT: reg_trend or reg_original? Answer: should be the both
        if reg_trend.slope > min_slope && reg_original.slope > min_slope {
            lines.push(LineSegment {
                first_index,
                last_index,
                reg_original,
                reg_trend,
            });
        }
    }

    lines
}

#[allow(clippy::cast_precision_loss)]
fn linear_regression(x_values: &[f64], y_values: &[f64]) -> (f64, f64, f64) {
    if x_values.len() < 2 {
        return (0.0, 0.0, 0.0);
    }

    let x_mean = x_values.iter().sum::<f64>() / (x_values.len() as f64);
    let y_mean = y_values.iter().sum::<f64>() / (y_values.len() as f64);
    let mut up = 0.;
    let mut down = 0.;
    for (&x, &y) in x_values.iter().zip(y_values) {
        let (x_dev, y_dev) = (x - x_mean, y - y_mean);
        up += x_dev * y_dev;
        down += x_dev * x_dev;
    }
    let slope = up / down;
    let intercept = y_mean - slope * x_mean;

    let mut r_ss = 0.;
    for (&x, &y) in x_values.iter().zip(y_values) {
        let dev = y - (intercept + slope * x);
        r_ss += dev * dev;
    }

    let mut t_ss = 0.;
    for &y in y_values {
        let dev = y - y_mean;
        t_ss += dev * dev;
    }

    let r_square = if slope == 0.0 { 1. } else { 1. - r_ss / t_ss };

    (slope, intercept, r_square)
}

fn analyze_lines(lines: &[LineSegment]) -> (usize, usize, f64, f64, usize, usize) {
    let (
        mut number_of_ups,
        mut number_of_downs,
        mut maximum_slope,
        mut minimum_slope,
        mut longest_up_span,
        mut longest_down_span,
    ): (usize, usize, f64, f64, usize, usize) = (0, 0, 0.0, 0.0, 0, 0);

    // HIGHLIGHT: reg_trend or reg_original? Answer: should be original because that is used in the regression line.
    for seg in lines {
        if seg.reg_original.slope > maximum_slope {
            maximum_slope = seg.reg_original.slope;
        }
        if seg.reg_original.slope < minimum_slope {
            minimum_slope = seg.reg_original.slope;
        }
        let span = seg.last_index - seg.first_index + 1;
        // HIGHLIGHT: consider this
        // if seg.reg_original.slope > DEFAULT_MIN_SLOPE {
        if seg.reg_original.slope > 0.0 {
            number_of_ups += 1;
            if span > longest_up_span {
                longest_up_span = span;
            }
        } else if seg.reg_original.slope < 0.0 {
            // else if seg.reg_original.slope < -DEFAULT_MIN_SLOPE {
            number_of_downs += 1;
            if span > longest_down_span {
                longest_down_span = span;
            }
        }
    }

    (
        number_of_ups,
        number_of_downs,
        maximum_slope,
        minimum_slope,
        longest_up_span,
        longest_down_span,
    )
}

#[derive(SimpleObject)]
struct LineSegment {
    first_index: usize,
    last_index: usize,
    reg_original: Regression,
    reg_trend: Regression,
}

#[derive(SimpleObject)]
struct Regression {
    slope: f64,
    intercept: f64,
    r_square: f64,
}

struct ModelTotalCount;

#[Object]
impl ModelTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Database>()?;
        Ok(db.count_models().await?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<(i32, String)>>,
    before: Option<OpaqueCursor<(i32, String)>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<(i32, String)>, ModelDigest, ModelTotalCount, EmptyFields>> {
    let is_first = first.is_some();
    let limit = slicing::len(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db
        .load_models(&after.map(|c| c.0), &before.map(|c| c.0), is_first, limit)
        .await?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, ModelTotalCount);
    connection.edges.extend(
        rows.into_iter()
            .map(|model| Edge::new(OpaqueCursor((model.id, model.name.clone())), model.into())),
    );
    Ok(connection)
}
