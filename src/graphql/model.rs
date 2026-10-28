use async_graphql::{
    Context, Enum, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
    types::ID,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use num_traits::ToPrimitive;
use review_database::{self as database, UniqueKey, event::Direction};

use super::{
    DEFAULT_CUTOFF_RATE, DEFAULT_TRENDI_ORDER, MAX_TRENDI_ORDER, PositiveCutoffRate, Role,
    RoleGuard,
    cluster::TimeCount,
    customer_access, customer_deletion_guard, fill_vacant_time_slots, get_trend,
    refusal::{RefusalCode, refusal},
    training::{self, ModelDetectorUse, ModelRun, TrainingDefinition, TrainingDefinitionState},
    training_result, zero_filled_length,
};
use crate::graphql::query;

const COMPUTATION_SERIES_BUDGET: u128 = 1_000_000;
const RESPONSE_SERIES_BUDGET: u128 = 100_000;

const DEFAULT_MIN_SLOPE: f64 = 10.0;
const DEFAULT_MIN_ZERO_COUNT_FOR_TREND: usize = 5;

/// The record `kind` of each clustering method a model can be trained with.
pub(crate) const MULTIFIELD_KIND: &str = "Multifield";
const PREFIX_KIND: &str = "Prefix";
pub(crate) const TIMESERIES_KIND: &str = "Timeseries";

#[derive(Default)]
pub(super) struct ModelQuery;

#[Object]
impl ModelQuery {
    /// A list of the models of the caller's customers, in name order.
    ///
    /// A System Administrator sees every model.
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
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, ModelDigest, ModelTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// The extra information on the columns of a CSV model.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn csv_column_extra(
        &self,
        ctx: &Context<'_>,
        model: ID,
    ) -> Result<Option<CsvColumnExtraConfig>> {
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model_id)?;
        let db = crate::graphql::get_store(ctx)?;
        let map = db.csv_column_extra_map();
        Ok(map
            .get_by_model(model_id)?
            .map(|config| CsvColumnExtraConfig { inner: config }))
    }

    /// The column types of a structured model.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn structured_column_types(
        &self,
        ctx: &Context<'_>,
        model: ID,
    ) -> Result<Vec<StructuredColumnType>> {
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.column_stats_map();
        let types = map.get_column_types_of_model(model)?;
        Ok(types.into_iter().map(Into::into).collect())
    }

    /// The time range of a model's time series.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn time_range_of_model(&self, ctx: &Context<'_>, model: ID) -> Result<TimeRange> {
        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.time_series_map();
        let time_range = map.get_time_range_of_model(model)?;
        let (lower, upper) = time_range.map_or((None, None), |(l, u)| {
            (
                Some(DateTime::from_timestamp_nanos(l)),
                Some(DateTime::from_timestamp_nanos(u)),
            )
        });
        Ok(TimeRange { lower, upper })
    }

    /// The top time series of a model, by column.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn top_time_series(
        &self,
        ctx: &Context<'_>,
        model: ID,
        size: Option<i32>,
        time: Option<NaiveDateTime>,
        min_slope: Option<f64>,
        #[graphql(
            desc = "The dimensionless trend filter order, from 0 to 20 inclusive. Omitted or null values use 4.",
            validator(
                minimum = 0,
                custom = "|value: &i32| async_graphql::validators::maximum(value, MAX_TRENDI_ORDER)"
            )
        )]
        trendi_order: Option<i32>,
        #[graphql(
            desc = "The dimensionless cutoff rate, strictly greater than 0 with no upper limit. Omitted or null values use 0.1.",
            validator(custom = "PositiveCutoffRate")
        )]
        cutoff_rate: Option<f64>,
        trend_category: Option<String>,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    ) -> Result<Vec<TopTrendsByColumn>> {
        const DEFAULT_SIZE: i32 = 20;
        let start = start.map(super::outlier::timestamp_nanos).transpose()?;
        let end = end.map(super::outlier::timestamp_nanos).transpose()?;
        let time = time
            .map(|t| super::outlier::timestamp_nanos(t.and_utc()))
            .transpose()?;
        let size = size
            .unwrap_or(DEFAULT_SIZE)
            .to_usize()
            .ok_or("invalid size")?;

        let model = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.time_series_map();
        let time_series = map.get_top_time_series_of_model(model, time, start, end)?;

        check_computation_budget(&time_series, time.is_some())?;

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
            .collect::<Result<Vec<_>>>()?;
        if let Some(category) = trend_category.as_ref() {
            sort_on_category(category, &mut time_series);
        }
        for s in &mut time_series {
            s.trends.truncate(size);
        }
        check_response_budget(&time_series, time.is_some())?;
        time_series.sort_by_key(|elem| elem.count_index);
        Ok(time_series)
    }

    /// The top column values of a model, by column.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_columns(
        &self,
        ctx: &Context<'_>,
        model: ID,
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
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model_id)?;

        let store = crate::graphql::get_store(ctx)?;
        let cluster_ids = load_cluster_ids_with_size_limit(&store, model_id, portion_of_clusters)?;

        let csv_column_extra_map = store.csv_column_extra_map();
        let Some(csv_extra) = csv_column_extra_map
            .get_by_model(model_id)
            .map_err(|e| format!("Failed to get csv column extra: {e}"))?
        else {
            return Ok(Vec::new());
        };
        let Some(top_n) = csv_extra.column_top_n else {
            return Ok(Vec::new());
        };

        let column_stats_map = store.column_stats_map();
        let counts = column_stats_map.get_top_columns_of_model(
            model_id,
            cluster_ids,
            &top_n,
            size,
            time,
            portion_of_top_n,
        )?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    /// The top IP addresses of a model, by column.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_ip_addresses(
        &self,
        ctx: &Context<'_>,
        model: ID,
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
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id(u32)")?;
        customer_access::load_accessible_model(ctx, "model", model_id)?;

        let store = crate::graphql::get_store(ctx)?;
        let cluster_ids = load_cluster_ids_with_size_limit(&store, model_id, portion_of_clusters)?;

        let map = store.column_stats_map();
        let counts = map.get_top_ip_addresses_of_model(
            model_id,
            &cluster_ids,
            size,
            time,
            portion_of_top_elements,
        )?;
        Ok(counts.into_iter().map(Into::into).collect())
    }

    /// The top multimaps of a model.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn top_multimaps(
        &self,
        ctx: &Context<'_>,
        model: ID,
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
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        customer_access::load_accessible_model(ctx, "model", model_id)?;

        let store = crate::graphql::get_store(ctx)?;
        let cluster_ids = load_cluster_ids(&store, model_id, None)?;

        let csv_column_extra_map = store.csv_column_extra_map();
        let csv_extra = csv_column_extra_map
            .get_by_model(model_id)
            .map_err(|e| format!("Failed to get csv column extra: {e}"))?;
        let (column_1, column_n) = if let Some(csv_extra) = csv_extra {
            (csv_extra.column_1, csv_extra.column_n)
        } else {
            (None, None)
        };

        let column_stats_map = store.column_stats_map();
        let maps = column_stats_map.get_top_multimaps_of_model(
            model_id,
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
    /// Adds extra information on the columns of a CSV model.
    ///
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the model's customer is unfinished, also while it is stopped.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_csv_column_extra(
        &self,
        ctx: &Context<'_>,
        model: ID,
        column_alias: Option<Vec<String>>,
        column_display: Option<Vec<bool>>,
        column_top_n: Option<Vec<bool>>,
        column_1: Option<Vec<bool>>,
        column_n: Option<Vec<bool>>,
    ) -> Result<ID> {
        let model_id = model
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid model id")?;
        let digest = customer_access::load_accessible_model(ctx, "model", model_id)?;
        let db = crate::graphql::get_store(ctx)?;
        customer_deletion_guard::check_customers(&db, [digest.customer_id])?;
        let map = db.csv_column_extra_map();
        Ok(ID(map
            .insert(
                model_id,
                column_alias.as_deref(),
                column_display.as_deref(),
                column_top_n.as_deref(),
                column_1.as_deref(),
                column_n.as_deref(),
            )?
            .to_string()))
    }

    /// Updates extra information on the columns of a CSV model.
    ///
    /// Scope is that of the model the stored extra belongs to. If that model
    /// does not exist, the update is refused with `extensions.code`
    /// `NOT_FOUND` on `id`; a model of none of the caller's customers is
    /// refused with `Forbidden`.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the model's customer is unfinished, also while it is stopped.
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
        let extra_id = id.as_str().parse()?;
        let users_customers = customer_access::users_customers(ctx)?;
        let db = crate::graphql::get_store(ctx)?;
        let map = db.csv_column_extra_map();
        let model_id = map
            .get_by_id(extra_id)?
            .ok_or_else(|| format!("csv column extra {extra_id} unavailable"))?
            .model_id;
        let Some(model) = db.model_map().get_by_id(model_id)? else {
            return Err(refusal(
                RefusalCode::NotFound,
                format!("model {model_id} of csv column extra {extra_id} not found"),
                "id",
                id.as_str(),
            ));
        };
        if !customer_access::can_access_model(users_customers.as_deref(), &model) {
            return Err("Forbidden".into());
        }
        customer_deletion_guard::check_customers(&db, [model.customer_id])?;
        map.update(
            extra_id,
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
                s.trends.sort_by_key(|b| std::cmp::Reverse(b.number_of_ups));
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
                    .sort_by_key(|b| std::cmp::Reverse(b.longest_up_span));
                // by up_number
            }
        }
        _ => (),
    }
}

struct CsvColumnExtraConfig {
    inner: database::CsvColumnExtraConfig,
}

#[Object]
impl CsvColumnExtraConfig {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn model_id(&self) -> ID {
        ID(self.inner.model_id.to_string())
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

    /// The clustering method the model was trained with.
    async fn method(&self) -> Result<ModelMethod> {
        model_method(&self.inner.kind)
    }

    /// The event kind the model was trained on, such as `http`, a Sysmon kind
    /// or a log kind.
    async fn event_kind(&self) -> &str {
        &self.inner.event_kind
    }

    /// The customer the model belongs to.
    async fn customer_id(&self) -> ID {
        ID(self.inner.customer_id.to_string())
    }

    /// The engine instance the model belongs to, or null if it has none.
    async fn instance(&self) -> Option<ModelInstance> {
        self.inner.instance.as_ref().map(Into::into)
    }

    /// When the training that produced the current result succeeded.
    async fn trained_at(&self) -> DateTime<Utc> {
        self.inner.trained_at
    }

    /// The summary of the previous training result, or null if the model has
    /// none.
    async fn previous_training_result(&self) -> Option<PreviousTrainingResult> {
        self.inner
            .previous
            .as_ref()
            .map(|previous| PreviousTrainingResult {
                model_id: self.inner.id,
                trained_at: previous.trained_at,
                version: previous.version,
                trained_definition: previous.trained_definition.clone(),
                trained_run_id: ID(previous.trained_run_id.to_string()),
            })
    }

    /// The state of the model's training definition.
    ///
    /// A model with no definition is `NO_INSTANCE` if it has no instance and
    /// `READY` otherwise.
    async fn state(&self, ctx: &Context<'_>) -> Result<TrainingDefinitionState> {
        let store = crate::graphql::get_store(ctx)?;
        Ok(match store.training_definition_state(&self.inner.name)? {
            Some(state) => state.into(),
            None if self.inner.instance.is_none() => TrainingDefinitionState::NoInstance,
            None => TrainingDefinitionState::Ready,
        })
    }

    /// The model's editable training definition: the settings of its next
    /// training. Null for a model with no definition.
    async fn definition(&self, ctx: &Context<'_>) -> Result<Option<TrainingDefinition>> {
        let store = crate::graphql::get_store(ctx)?;
        Ok(store.training_definition(&self.inner.name)?.map(Into::into))
    }

    /// The training definition, a TOML document, of the run that trained the
    /// current result.
    async fn trained_definition(&self) -> &str {
        &self.inner.trained_definition
    }

    /// The id of the run that trained the current result.
    async fn trained_run_id(&self) -> ID {
        ID(self.inner.trained_run_id.to_string())
    }

    /// The sources of `trainedDefinition`; empty if it does not parse.
    async fn training_sources(&self) -> Vec<String> {
        training::sources_of(&self.inner.trained_definition)
    }

    /// The active run that creates or replaces the model, or clones from it.
    ///
    /// A clone run to another customer is null for callers who are not System
    /// Administrators.
    async fn active_run(&self, ctx: &Context<'_>) -> Result<Option<ModelRun>> {
        let store = crate::graphql::get_store(ctx)?;
        training::visible_active_run(ctx, &store, &self.inner.name)
    }

    /// The detectors whose applied or pending engine document names the
    /// model, ordered by node id, agent key, then detector id. A detector the
    /// applied and the pending document name under different ids is listed
    /// once for each.
    async fn detectors(&self, ctx: &Context<'_>) -> Result<Vec<ModelDetectorUse>> {
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .model_users(&self.inner.name)?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

/// Returns the method a model record's `kind` names.
///
/// review-database's `ClusteringMethod`, which the record's `kind` is the name
/// of, is private to it, so the names are mapped here.
fn model_method(kind: &str) -> Result<ModelMethod> {
    match kind {
        MULTIFIELD_KIND => Ok(ModelMethod::Multidimension),
        PREFIX_KIND => Ok(ModelMethod::Prefix),
        TIMESERIES_KIND => Ok(ModelMethod::Timeseries),
        _ => Err(format!("unknown model method {kind:?}").into()),
    }
}

/// The clustering method a model is trained with.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::ModelMethod")]
pub(super) enum ModelMethod {
    Multidimension,
    Prefix,
    Timeseries,
}

/// The engine instance a model belongs to.
#[derive(SimpleObject)]
pub(super) struct ModelInstance {
    /// The node of the instance.
    node_id: ID,
    /// The key of the instance's agent on the node.
    agent_key: String,
}

impl From<&database::ModelInstance> for ModelInstance {
    fn from(instance: &database::ModelInstance) -> Self {
        Self {
            node_id: ID(instance.node_id.to_string()),
            agent_key: instance.agent_key.clone(),
        }
    }
}

/// The summary of a model's previous training result.
#[derive(SimpleObject)]
#[graphql(complex)]
struct PreviousTrainingResult {
    #[graphql(skip)]
    model_id: u32,
    /// When the training that produced the previous result succeeded.
    trained_at: DateTime<Utc>,
    /// The version of the previous result's model.
    version: i32,
    /// The training definition, a TOML document, of the run that trained the
    /// previous result.
    trained_definition: String,
    /// The id of the run that trained the previous result.
    trained_run_id: ID,
}

#[async_graphql::ComplexObject]
impl PreviousTrainingResult {
    /// The number of clusters in the previous result.
    async fn cluster_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::cluster_map(&store, true);
        Ok(StringNumber(map.count_clusters(
            self.model_id,
            None,
            None,
            None,
            None,
        )?))
    }

    /// The number of outliers in the previous result.
    async fn outlier_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::outlier_map(&store, true);
        Ok(StringNumber(
            map.get(self.model_id, None, Direction::Forward, None)
                .count(),
        ))
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
    lower: Option<DateTime<Utc>>,
    upper: Option<DateTime<Utc>>,
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
    async fn cluster_id(&self) -> ID {
        ID(self.inner.cluster_id.to_string())
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

fn zero_fill_error(cluster_id: u32, error: &anyhow::Error) -> async_graphql::Error {
    async_graphql::Error::new(format!("cannot zero-fill cluster {cluster_id}: {error}"))
}

#[derive(Clone, Copy)]
enum SeriesBudget {
    Computation,
    Response,
}

fn check_series_budget(sum: u128, budget: SeriesBudget, has_time: bool) -> Result<()> {
    let (name, limit) = match budget {
        SeriesBudget::Computation => ("computation", COMPUTATION_SERIES_BUDGET),
        SeriesBudget::Response => ("response", RESPONSE_SERIES_BUDGET),
    };
    if sum > limit {
        let mut message = format!("{name} budget exceeded: series length sum {sum}, limit {limit}");
        if !has_time {
            message.push_str("; narrow the query period using start and end");
        }
        if matches!(budget, SeriesBudget::Response) {
            message.push_str("; lower size");
        }
        return Err(async_graphql::Error::new(message));
    }
    Ok(())
}

fn check_computation_budget(
    columns: &[(Option<i32>, Vec<database::ClusterTimeSeries>)],
    has_time: bool,
) -> Result<()> {
    // Each series has at most 2^64 slots over i64 timestamps. The in-memory
    // collection has fewer than 2^64 series, so u128 preserves the exact sum.
    let mut sum = 0_u128;
    for cluster in columns.iter().flat_map(|column| &column.1) {
        sum += zero_filled_length(&cluster.time_counts)
            .map_err(|error| zero_fill_error(cluster.id, &error))?;
    }
    check_series_budget(sum, SeriesBudget::Computation, has_time)
}

fn check_response_budget(columns: &[TopTrendsByColumn], has_time: bool) -> Result<()> {
    let sum = columns
        .iter()
        .flat_map(|column| &column.trends)
        .map(|cluster| u128::try_from(cluster.series.len()).expect("usize fits in u128"))
        .sum();
    check_series_budget(sum, SeriesBudget::Response, has_time)
}

#[derive(SimpleObject)]
struct TopTrendsByColumn {
    count_index: usize,
    trends: Vec<ClusterTrend>,
}

impl TopTrendsByColumn {
    fn from_database(
        inner: (Option<i32>, Vec<database::ClusterTimeSeries>),
        cutoff_rate: f64,
        trendi_order: i32,
        min_slope: f64,
    ) -> Result<Self> {
        // 100_000 means counting events themselves, not any other column values.
        let count_index = inner
            .0
            .map_or(100_000, |i| i.to_usize().expect("safe: positive"));
        let trends = inner
            .1
            .into_iter()
            .map(|t| ClusterTrend::from_database(t, cutoff_rate, trendi_order, min_slope))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(Self {
            count_index,
            trends,
        })
    }
}

struct ClusterTrend {
    cluster_id: u32,
    series: Vec<TimeCount>,
    trend: Vec<f64>,
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
    async fn cluster_id(&self) -> ID {
        ID(self.cluster_id.to_string())
    }

    async fn series(&self) -> &[TimeCount] {
        &self.series
    }

    /// The cluster trend as string-represented `usize` counts. Negative values
    /// become 0; otherwise values round to the nearest integer, with exact halves
    /// toward the larger integer. Line segments and statistics use the untruncated
    /// trend and may differ from those recomputed from these integer values:
    /// `[1.1, 1.2]` has a positive slope while the integer trend is `["1", "1"]`.
    async fn trend(&self) -> Vec<StringNumber<usize>> {
        self.trend
            .iter()
            .map(|&value| {
                StringNumber(super::trend_count(value).expect("get_trend validated every count"))
            })
            .collect()
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
        inner: database::ClusterTimeSeries,
        cutoff_rate: f64,
        trendi_order: i32,
        min_slope: f64,
    ) -> Result<Option<Self>> {
        let cluster_id = inner.id;
        let series = inner.time_counts;
        let series =
            fill_vacant_time_slots(&series).map_err(|error| zero_fill_error(cluster_id, &error))?;
        let Ok(trend) = get_trend(&series, cutoff_rate, trendi_order) else {
            return Ok(None);
        };
        let lines = find_lines(&series, &trend, min_slope);
        if lines.is_empty() {
            return Ok(None);
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
        Ok(Some(Self {
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
        }))
    }
}

// Tolerance only covers small filter error; increasing it would erase slow changes.
fn trend_tolerance(series: &[super::TimeCount]) -> f64 {
    8192.0
        * f64::EPSILON
        * series
            .iter()
            .map(|point| point.1)
            .max()
            .unwrap_or(0)
            .to_f64()
            .expect("usize fits in f64")
}

fn trend_segments(trend: &[f64], tau: f64) -> Vec<(usize, usize)> {
    if trend.len() < 2 {
        return Vec::new();
    }
    let signs: Vec<i32> = trend
        .windows(2)
        .map(|pair| {
            let diff = pair[1] - pair[0];
            if diff.abs() <= tau {
                0
            } else if diff > 0.0 {
                1
            } else {
                -1
            }
        })
        .collect();
    let mut boundaries = vec![0];
    let mut start = 0;
    while start < signs.len() {
        let sign = signs[start];
        let mut end = start + 1;
        while end < signs.len() && signs[end] == sign {
            end += 1;
        }
        if sign == 0 {
            let before = start.checked_sub(1).map(|i| signs[i]);
            let after = signs.get(end).copied();
            let opposite = matches!((before, after), (Some(a), Some(b)) if a != b);
            let length = end - start;
            if opposite && length == 1 {
                boundaries.push(end);
            } else if opposite || length > DEFAULT_MIN_ZERO_COUNT_FOR_TREND {
                if before.is_some() {
                    boundaries.push(start + 1);
                }
                if after.is_some() {
                    boundaries.push(end);
                }
            }
        } else if end < signs.len() && signs[end] != 0 {
            boundaries.push(end);
        }
        start = end;
    }
    boundaries.push(trend.len());
    boundaries
        .windows(2)
        .map(|pair| (pair[0], pair[1] - 1))
        .collect()
}

fn find_lines(series: &[super::TimeCount], trend: &[f64], min_slope: f64) -> Vec<LineSegment> {
    let tau = trend_tolerance(series);
    let line_segments_indices = trend_segments(trend, tau);
    let mut lines: Vec<LineSegment> = Vec::new();
    for seg in &line_segments_indices {
        let (first_index, last_index) = (seg.0, seg.1);
        // for original series
        let x_values: Vec<f64> = (first_index..=last_index)
            .map(|x| x.to_f64().expect("safe: usize -> f64"))
            .collect();
        let y_values: Vec<usize> = (first_index..=last_index).map(|i| series[i].1).collect();
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

        // Regress the untruncated trend, preserving negative filter values.
        let y_values = &trend[first_index..=last_index];
        let minimum = y_values.iter().copied().fold(f64::INFINITY, f64::min);
        let maximum = y_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let (slope, intercept, r_square) = if y_values.len() >= 2 && maximum - minimum <= tau {
            (
                0.0,
                y_values.iter().sum::<f64>() / y_values.len().to_f64().expect("usize fits in f64"),
                1.0,
            )
        } else {
            linear_regression(&x_values, y_values)
        };
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
    /// Regression of the untruncated trend, used for line segments and statistics.
    /// It may differ from regression recomputed from the integer trend:
    /// `[1.1, 1.2]` has a positive slope while the integer trend is `["1", "1"]`.
    reg_trend: Regression,
}

#[derive(SimpleObject)]
struct Regression {
    slope: f64,
    intercept: f64,
    r_square: f64,
}

struct ModelTotalCount;

/// Counts the models of the caller's customers, or every model for an
/// unscoped caller.
fn scoped_model_count(ctx: &Context<'_>) -> Result<usize> {
    let users_customers = customer_access::users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.model_map();

    match users_customers.as_deref() {
        None => Ok(map.count_models()?),
        Some(users_customers) => {
            use database::Iterable;

            let mut count = 0;
            for entry in map.iter(Direction::Forward, None) {
                let model = entry.map_err(|_| "invalid value in database")?;
                if customer_access::can_access_model(Some(users_customers), &model) {
                    count += 1;
                }
            }
            Ok(count)
        }
    }
}

#[Object]
impl ModelTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        Ok(StringNumber(scoped_model_count(ctx)?))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, ModelDigest, ModelTotalCount, EmptyFields>> {
    let users_customers = customer_access::users_customers(ctx)?;
    let users_customers = users_customers.as_deref();
    let store = crate::graphql::get_store(ctx)?;
    let map = store.model_map();

    // Filter by customer while collecting edges, so a page and its page info
    // count only the caller's models.
    let (rows, has_previous, has_next) =
        super::process_load_edges_filtered(&map, after, before, first, last, None, |model| {
            customer_access::can_access_model(users_customers, model)
        });
    let rows = rows
        .into_iter()
        .map(|res| res.map_err(|e| format!("{e}").into()))
        .collect::<Result<Vec<_>>>()?;

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, ModelTotalCount);
    connection.edges.extend(
        rows.into_iter()
            .map(|model| Edge::new(OpaqueCursor(model.unique_key().to_vec()), model.into())),
    );
    Ok(connection)
}

const UNCATEGORIZED: i32 = 2;
const DEFAULT_PORTION_OF_CLUSTER: f64 = 0.3;
const DEFAULT_NUMBER_OF_CLUSTER: usize = 10;

/// Loads cluster IDs for the given model, excluding "Uncategorized" clusters.
///
/// # Errors
///
/// Returns an error if a database operation fails.
fn load_cluster_ids(
    store: &database::Store,
    model_id: u32,
    cluster_id: Option<u32>,
) -> Result<Vec<u32>> {
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

    let ids: Vec<u32> = clusters
        .into_iter()
        .filter(|c| c.category_id != UNCATEGORIZED)
        .filter(|c| cluster_id.is_none_or(|id| c.id == id))
        .map(|c| c.id)
        .collect();

    Ok(ids)
}

/// Loads cluster IDs limited by the given portion of total cluster sizes.
///
/// # Errors
///
/// Returns an error if a database operation fails.
fn load_cluster_ids_with_size_limit(
    store: &database::Store,
    model_id: u32,
    portion_of_clusters: Option<f64>,
) -> Result<Vec<u32>> {
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

    // Filter out "Uncategorized" and sort by size descending
    let mut clusters: Vec<database::Cluster> = clusters
        .into_iter()
        .filter(|c| c.category_id != UNCATEGORIZED)
        .collect();
    clusters.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.id.cmp(&b.id)));

    if clusters.is_empty() {
        return Ok(Vec::new());
    }

    // On supported 32/64-bit targets, this Vec has at most isize::MAX elements.
    // Each size has magnitude at most 2^63, so the total and every prefix sum fit in i128.
    let total_sizes: i128 = clusters.iter().map(|c| i128::from(c.size)).sum();
    let portion_of_clusters = portion_of_clusters.unwrap_or(DEFAULT_PORTION_OF_CLUSTER);
    // Preserve the existing floating-point rounding and truncation for the portion.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let size_including_clusters = ((total_sizes as f64) * portion_of_clusters).trunc() as i128;

    let mut sum_sizes: i128 = 0;
    let mut index_included: usize = 0;
    for (index, c) in clusters.iter().enumerate() {
        sum_sizes += i128::from(c.size);
        index_included = index;
        if sum_sizes > size_including_clusters {
            break;
        }
    }

    // Ensure at least DEFAULT_NUMBER_OF_CLUSTER clusters are included
    let index_included = index_included.max(DEFAULT_NUMBER_OF_CLUSTER.saturating_sub(1));
    let cluster_ids: Vec<u32> = clusters
        .iter()
        .take(index_included + 1)
        .map(|c| c.id)
        .collect();

    Ok(cluster_ids)
}

#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod time_bounds_tests;

#[cfg(test)]
mod tests {
    use review_database::{Cluster, Store};

    use crate::graphql::TestSchema;
    use crate::graphql::model_test_support::schema_with_models_through;

    fn counted_series(counts: impl IntoIterator<Item = usize>) -> Vec<crate::graphql::TimeCount> {
        counts
            .into_iter()
            .enumerate()
            .map(|(i, count)| (i64::try_from(i).unwrap(), count))
            .collect()
    }

    fn cluster_trend(
        counts: Vec<usize>,
        order: i32,
        min_slope: f64,
    ) -> Option<super::ClusterTrend> {
        super::ClusterTrend::from_database(
            review_database::ClusterTimeSeries {
                id: 1,
                time_counts: counted_series(counts),
            },
            0.1,
            order,
            min_slope,
        )
        .unwrap()
    }

    #[test]
    fn segmentation_partitions_every_element() {
        // Expected boundaries are starts of disjoint, inclusive segments.
        let cases = [
            (vec![1., 2., 3., 4.], vec![0, 4]),
            (vec![4., 3., 2., 1.], vec![0, 4]),
            (vec![1., 2., 3., 2., 1.], vec![0, 2, 5]),
            (vec![1., 2., 2., 1., 0.], vec![0, 2, 5]),
            (vec![1., 2., 2., 2., 1., 0.], vec![0, 2, 3, 6]),
            (vec![1., 2., 2., 2., 2., 2., 2., 3.], vec![0, 8]),
            (vec![1., 2., 2., 2., 2., 2., 2., 2., 3.], vec![0, 2, 7, 9]),
            (vec![1., 1., 1., 1., 1., 1., 2., 3.], vec![0, 8]),
            (vec![1., 1., 1., 1., 1., 1., 1., 2., 3.], vec![0, 6, 9]),
            (vec![1., 2., 3., 3., 3., 3., 3., 3.], vec![0, 8]),
            (vec![1., 2., 3., 3., 3., 3., 3., 3., 3.], vec![0, 3, 9]),
            (vec![1.; 12], vec![0, 12]),
        ];
        for (trend, boundaries) in cases {
            let expected: Vec<_> = boundaries.windows(2).map(|p| (p[0], p[1] - 1)).collect();
            assert_eq!(super::trend_segments(&trend, 0.0), expected, "{trend:?}");
        }
    }

    #[test]
    fn bump_uses_untruncated_trend() {
        let mut counts = vec![1; 20];
        counts[10] = 2;
        assert!(cluster_trend(counts.clone(), 2, 0.0).is_none());
        let cluster = cluster_trend(counts, 2, -1.0).unwrap();
        assert!(cluster.lines.iter().any(|line| line.reg_trend.slope > 0.0));
        assert!(
            cluster
                .trend
                .iter()
                .all(|&value| crate::graphql::trend_count(value) == Some(1))
        );
    }

    #[test]
    fn constant_trend_and_wobbles_within_tolerance() {
        let cluster = cluster_trend(vec![7; 120], 4, -1.0).unwrap();
        assert_eq!(cluster.lines.len(), 1);
        let line = &cluster.lines[0];
        assert_eq!((line.first_index, line.last_index), (0, 119));
        assert_eq!((line.reg_trend.slope, line.reg_trend.r_square), (0.0, 1.0));
        let series = counted_series(vec![7; 120]);
        let tau = super::trend_tolerance(&series);
        let trend: Vec<_> = (0..120)
            .map(|i| 7.0 + if i % 2 == 0 { tau / 4.0 } else { -tau / 4.0 })
            .collect();
        let lines = super::find_lines(&series, &trend, -1.0);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            (lines[0].reg_trend.slope, lines[0].reg_trend.r_square),
            (0.0, 1.0)
        );
    }

    #[test]
    fn slow_changes_survive_tolerance() {
        let cluster = cluster_trend(
            (0..120).map(|i| (1_usize << 40) + 11 * i).collect(),
            0,
            10.0,
        )
        .unwrap();
        assert_eq!(cluster.lines.len(), 1);
        assert!((cluster.lines[0].reg_trend.slope - 11.0).abs() < 1e-9);
        for order in [0, 4] {
            let cluster = cluster_trend(
                (0..5000).map(|i| 1_000_000_000 + i / 500).collect(),
                order,
                0.0,
            )
            .unwrap();
            assert!(
                cluster.lines.iter().any(|line| line.reg_trend.slope > 0.0),
                "slow rise should survive smoothing with order {order}"
            );
            let cluster = cluster_trend(
                (0..5000)
                    .map(|i| 1_000_000_000 + if i < 2500 { i / 250 } else { (4999 - i) / 250 })
                    .collect(),
                order,
                0.0,
            )
            .unwrap();
            assert!(
                cluster.lines.iter().any(|line| line.reg_trend.slope > 0.0),
                "slow peak should survive smoothing with order {order}"
            );
        }
        // Each step is below tau, but the total range exceeds tau.
        let series = counted_series(vec![1_usize << 40; 120]);
        let trend: Vec<_> = (0..120)
            .map(|i| 2_f64.powi(40) + f64::from(i) * 0.5)
            .collect();
        let lines = super::find_lines(&series, &trend, -1.0);
        assert_eq!(lines.len(), 1);
        assert!((lines[0].reg_trend.slope - 0.5).abs() < 1e-9);
    }

    #[test]
    fn rising_series_and_triangle_wave() {
        let cluster = cluster_trend(
            (0..100).map(|i| i * 100).collect(),
            4,
            super::DEFAULT_MIN_SLOPE,
        )
        .unwrap();
        assert_eq!(cluster.lines.len(), 1);
        assert_eq!(
            (cluster.lines[0].first_index, cluster.lines[0].last_index),
            (0, 99)
        );
        let counts = (0..120)
            .map(|i| 100 * if i % 40 < 20 { i % 40 } else { 40 - i % 40 })
            .collect();
        let cluster = cluster_trend(counts, 4, super::DEFAULT_MIN_SLOPE).unwrap();
        assert_eq!(cluster.lines.len(), 3);
        let cluster = cluster_trend(
            (0..100)
                .map(|i| if i < 80 { 0 } else { (i - 80) * 100 })
                .collect(),
            0,
            super::DEFAULT_MIN_SLOPE,
        )
        .unwrap();
        assert_eq!(cluster.lines.len(), 1);
        assert_eq!(cluster.lines[0].last_index, 99);
    }

    #[test]
    fn filter_negatives_are_preserved_during_analysis() {
        let series = counted_series((0..100).map(|i| if i == 50 { 100 } else { 0 }));
        let trend = crate::graphql::get_trend(&series, 0.1, 4).unwrap();
        assert!(trend.iter().any(|value| *value < 0.0));
        let cluster = super::ClusterTrend::from_database(
            review_database::ClusterTimeSeries {
                id: 1,
                time_counts: series.clone(),
            },
            0.1,
            4,
            -1000.0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cluster.trend, trend);
        for line in cluster.lines {
            let y = &trend[line.first_index..=line.last_index];
            let x: Vec<_> = (line.first_index..=line.last_index)
                .map(|i| f64::from(u32::try_from(i).unwrap()))
                .collect();
            if y.len() >= 2
                && y.iter().copied().fold(f64::NEG_INFINITY, f64::max)
                    - y.iter().copied().fold(f64::INFINITY, f64::min)
                    > super::trend_tolerance(&series)
            {
                assert_eq!(line.reg_trend.slope, super::linear_regression(&x, y).0);
            }
        }
    }

    #[test]
    fn abnormal_cluster_trend_is_omitted() {
        assert!(cluster_trend(vec![usize::MAX; 20], 0, -1.0).is_none());
    }

    #[test]
    fn computation_budget_counts_all_series_without_filling() {
        for (end, passes) in [(499_999, true), (500_000, false)] {
            let columns = vec![(
                None,
                vec![
                    review_database::ClusterTimeSeries {
                        id: 1,
                        time_counts: vec![(0, 1), (1, 1), (end, 1)],
                    },
                    review_database::ClusterTimeSeries {
                        id: 2,
                        time_counts: vec![(0, 1), (1, 1), (499_999, 1)],
                    },
                ],
            )];
            let result = super::check_computation_budget(&columns, false);
            assert_eq!(result.is_ok(), passes);
            if let Err(error) = result {
                assert!(error.message.contains("1000001"), "{error:?}");
            }
        }
        let columns = vec![(
            None,
            (0..19)
                .map(|id| review_database::ClusterTimeSeries {
                    id,
                    time_counts: vec![(0, 1), (1, 1), (1_000_000_000_000_000_000, 1)],
                })
                .collect(),
        )];
        let error = super::check_computation_budget(&columns, false).unwrap_err();
        assert!(error.message.contains("19000000000000000019"), "{error:?}");
        assert!(
            super::check_computation_budget(
                &[(
                    None,
                    vec![review_database::ClusterTimeSeries {
                        id: 9,
                        time_counts: vec![(0, 1), (1, 1), (1_000_000_000_000_000_000, 1)],
                    }]
                )],
                false
            )
            .is_err()
        );
    }

    fn trend_with_length(length: usize) -> super::ClusterTrend {
        super::ClusterTrend {
            cluster_id: 1,
            series: (0..length)
                .map(|_| super::TimeCount {
                    time: chrono::DateTime::UNIX_EPOCH.naive_utc(),
                    count: 1,
                })
                .collect(),
            trend: Vec::new(),
            lines: Vec::new(),
            number_of_ups: 0,
            number_of_downs: 0,
            maximum_slope: 0.0,
            minimum_slope: 0.0,
            longest_up_span: 0,
            longest_down_span: 0,
        }
    }

    #[test]
    fn response_budget_applies_after_truncation() {
        let mut columns = vec![super::TopTrendsByColumn {
            count_index: 0,
            trends: vec![trend_with_length(100_000), trend_with_length(1)],
        }];
        let error = super::check_response_budget(&columns, false).unwrap_err();
        for text in ["response", "100001", "100000", "start", "end", "lower size"] {
            assert!(error.message.contains(text), "{error:?}");
        }
        columns[0].trends.truncate(1);
        assert!(super::check_response_budget(&columns, false).is_ok());
    }

    #[test]
    fn cluster_trends_and_regressions_use_filled_counts() {
        let inner = review_database::ClusterTimeSeries {
            id: 1,
            time_counts: (0..100)
                .filter(|i| i % 3 != 2)
                .map(|i| (i, usize::try_from(i * 10 + 1).unwrap()))
                .collect(),
        };
        let cluster = super::ClusterTrend::from_database(inner, 0.1, 0, -1_000_000.0)
            .unwrap()
            .unwrap();
        assert_eq!(cluster.series.len(), cluster.trend.len());
        assert!(cluster.series.iter().any(|point| point.count == 0));
        assert!(!cluster.lines.is_empty());
        for line in cluster.lines {
            assert!(line.last_index < cluster.series.len());
            let x: Vec<_> = (line.first_index..=line.last_index)
                .map(|i| f64::from(u32::try_from(i).unwrap()))
                .collect();
            let y: Vec<_> = cluster.series[line.first_index..=line.last_index]
                .iter()
                .map(|point| f64::from(u32::try_from(point.count).unwrap()))
                .collect();
            let (slope, intercept, r_square) = super::linear_regression(&x, &y);
            assert_eq!(
                (
                    line.reg_original.slope,
                    line.reg_original.intercept,
                    line.reg_original.r_square
                ),
                (slope, intercept, r_square)
            );
        }
    }

    async fn schema_with_sparse_series(
        end: i64,
        second_column: bool,
        overflow: bool,
    ) -> TestSchema {
        let schema = schema_with_models_through(1).await;
        {
            let store = schema.store();
            let map = store.time_series_map();
            for cluster_id in 1..=2 {
                let times = if overflow {
                    vec![i64::MIN, 0, i64::MAX]
                } else {
                    vec![0, 1, end]
                };
                for value in times {
                    map.insert(&review_database::TimeSeries {
                        model_id: 1,
                        cluster_id,
                        time: 0,
                        value,
                        count_index: Some(if second_column {
                            i32::try_from(cluster_id).unwrap()
                        } else {
                            0
                        }),
                        count: 100,
                    })
                    .unwrap();
                }
            }
        }
        schema
    }

    #[tokio::test]
    async fn top_time_series_computation_errors() {
        let schema = schema_with_sparse_series(599_999, true, false).await;
        for (time, has_time) in [("", false), (", time: \"1970-01-01T00:00:00\"", true)] {
            let response = schema
                .execute_as_system_admin(&format!(
                    "{{ topTimeSeries(model: 1, start: \"1970-01-01T00:00:00Z\", end: \"1970-01-01T00:00:00.000599999Z\"{time}) {{ countIndex }} }}"
                ))
                .await;
            assert_eq!(response.errors.len(), 1, "{response:?}");
            let message = &response.errors[0].message;
            for text in ["computation", "1200000", "1000000"] {
                assert!(message.contains(text), "{message}");
            }
            assert_eq!(message.contains("start"), !has_time, "{message}");
            assert_eq!(message.contains("end"), !has_time, "{message}");
        }
        let schema = schema_with_sparse_series(0, false, true).await;
        let response = schema
            .execute_as_system_admin("{ topTimeSeries(model: 1, start: \"1677-09-21T00:12:43.145224192Z\", end: \"2262-04-11T23:47:16.854775807Z\") { countIndex } }")
            .await;
        assert_eq!(response.errors.len(), 1, "{response:?}");
        let message = &response.errors[0].message;
        assert!(
            message.contains("cluster 1:") || message.contains("cluster 2:"),
            "{message}"
        );
        assert!(message.contains("overflow"), "{message}");
    }

    #[tokio::test]
    async fn top_time_series_response_budget_and_size() {
        let schema = schema_with_sparse_series(59_999, false, false).await;
        for time in ["", ", time: \"1970-01-01T00:00:00\""] {
            let arguments = format!(
                "model: 1, start: \"1970-01-01T00:00:00Z\", end: \"1970-01-01T00:00:00.000059999Z\", trendiOrder: 0, minSlope: -1000000{time}"
            );
            let response = schema.execute_as_system_admin(&format!("{{ topTimeSeries({arguments}, size: 1) {{ trends {{ series {{ count }} }} }} }}")).await;
            assert!(response.errors.is_empty(), "{response:?}");
            let data = response.data.into_json().unwrap();
            assert_eq!(
                data["topTimeSeries"][0]["trends"][0]["series"]
                    .as_array()
                    .unwrap()
                    .len(),
                60_000
            );
            // The budget also applies when no series fields are selected.
            let response = schema
                .execute_as_system_admin(&format!(
                    "{{ topTimeSeries({arguments}, size: 2) {{ countIndex }} }}"
                ))
                .await;
            assert_eq!(response.errors.len(), 1, "{response:?}");
            let message = &response.errors[0].message;
            for text in ["response", "120000", "100000", "lower size"] {
                assert!(message.contains(text), "{message}");
            }
            assert_eq!(message.contains("start"), time.is_empty(), "{message}");
        }
    }

    fn selected_cluster_ids(sizes: &[i64], portion: Option<f64>) -> Vec<u32> {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        for (index, &size) in sizes.iter().enumerate() {
            store
                .cluster_map()
                .put(&Cluster {
                    model_id: 1,
                    id: u32::try_from(index).unwrap(),
                    category_id: 1,
                    detector_id: 1,
                    event_ids: Vec::new(),
                    sensors: Vec::new(),
                    labels: None,
                    qualifier_id: 1,
                    status_id: 1,
                    signature: String::new(),
                    size,
                    score: None,
                    last_modification_time: None,
                })
                .unwrap();
        }
        super::load_cluster_ids_with_size_limit(&store, 1, portion).unwrap()
    }

    #[test]
    fn cluster_size_limit_default_portion() {
        let ids = selected_cluster_ids(&[1; 40], None);
        assert_eq!(ids, (0..13).collect::<Vec<u32>>());
    }

    #[test]
    fn cluster_size_limit_overflowing_total_default_portion() {
        let ids = selected_cluster_ids(&[1_i64 << 59; 40], None);
        assert_eq!(ids, (0..13).collect::<Vec<u32>>());
    }

    #[test]
    fn cluster_size_limit_overflowing_total_large_portion() {
        let ids = selected_cluster_ids(&[1_i64 << 59; 40], Some(0.8));
        assert_eq!(ids, (0..33).collect::<Vec<u32>>());
    }

    #[test]
    fn cluster_size_limit_i64_max() {
        assert_eq!(
            selected_cluster_ids(&[i64::MAX; 40], None),
            (0..13).collect::<Vec<u32>>()
        );
        assert_eq!(
            selected_cluster_ids(&[i64::MAX; 40], Some(0.8)),
            (0..33).collect::<Vec<u32>>()
        );
    }

    #[test]
    fn cluster_size_limit_i64_min() {
        assert_eq!(
            selected_cluster_ids(&[i64::MIN; 40], None),
            (0..10).collect::<Vec<u32>>()
        );
        assert_eq!(
            selected_cluster_ids(&[i64::MIN; 40], Some(0.0)),
            (0..40).collect::<Vec<u32>>()
        );
    }

    #[test]
    fn cluster_size_limit_negative_total() {
        assert_eq!(
            selected_cluster_ids(&[-1; 40], None),
            (0..10).collect::<Vec<u32>>()
        );
        assert_eq!(
            selected_cluster_ids(&[-1; 40], Some(0.0)),
            (0..40).collect::<Vec<u32>>()
        );
    }

    #[test]
    fn cluster_size_limit_preserves_size_order_and_minimum() {
        let sizes: Vec<i64> = (1..=40).collect();
        let ids = selected_cluster_ids(&sizes, None);
        assert_eq!(ids, (30..40).rev().collect::<Vec<u32>>());
        let ids = selected_cluster_ids(&sizes, Some(0.8));
        assert_eq!(ids, (17..40).rev().collect::<Vec<u32>>());
        let ids = selected_cluster_ids(&sizes, Some(0.0));
        assert_eq!(ids, (30..40).rev().collect::<Vec<u32>>());
        assert_eq!(selected_cluster_ids(&[1; 3], None), vec![0, 1, 2]);
        assert_eq!(selected_cluster_ids(&[], None), Vec::<u32>::new());
    }

    #[tokio::test]
    async fn trend_argument_ranges() {
        let schema = schema_with_models_through(1).await;
        for (resolver, selection) in [
            ("topTimeSeries(model: 1", "countIndex trends { trend }"),
            (
                "topTimeSeriesOfCluster(model: 1, clusterId: 1",
                "series { seriesTrend { count } }",
            ),
        ] {
            for (argument, range) in [
                ("trendiOrder: -1", "must be greater than or equal to 0"),
                ("trendiOrder: 21", "must be less than or equal to 20"),
                ("cutoffRate: 0", "must be greater than 0"),
                ("cutoffRate: -0.1", "must be greater than 0"),
            ] {
                let query = format!("{{ {resolver}, {argument}) {{ {selection} }} }}");
                let response = schema.execute_as_system_admin(&query).await;
                assert_eq!(response.errors.len(), 1, "{response:?}");
                let error = response.errors.first().unwrap();
                assert!(error.message.contains(range), "{error:?}");
                // The validator reports the argument value's source location.
                let column = query.find(argument).unwrap() + argument.find(": ").unwrap() + 3;
                assert_eq!(
                    error.locations,
                    vec![async_graphql::Pos { line: 1, column }]
                );
            }
            // Empty data checks acceptance without exercising out-of-scope filter failures.
            for argument in [
                "trendiOrder: 0",
                "trendiOrder: 1",
                "trendiOrder: 20",
                "cutoffRate: 0.01",
            ] {
                let query = format!("{{ {resolver}, {argument}) {{ {selection} }} }}");
                let response = schema.execute_as_system_admin(&query).await;
                assert!(response.errors.is_empty(), "{response:?}");
            }
        }
    }

    async fn schema_with_constant_time_series(points: u32) -> TestSchema {
        let schema = schema_with_models_through(1).await;
        {
            let store = schema.store();
            let map = store.time_series_map();
            for index in 0..points {
                map.insert(&review_database::TimeSeries {
                    model_id: 1,
                    cluster_id: 1,
                    time: 0,
                    value: i64::from(index) * 1_000_000_000,
                    count_index: Some(0),
                    count: 1,
                })
                .unwrap();
            }
        }
        schema
    }

    #[tokio::test]
    async fn cluster_series_trend_rounds_constant_counts() {
        let schema = schema_with_constant_time_series(20).await;
        let response = schema.execute_as_system_admin(
            "{ topTimeSeriesOfCluster(model: 1, clusterId: 1, trendiOrder: 2, cutoffRate: 0.1) {
                series { seriesTrend { count } }
            } }"
        ).await;
        assert!(response.errors.is_empty(), "{response:?}");
        let data = response.data.into_json().unwrap();
        let trend = data
            .pointer("/topTimeSeriesOfCluster/series/0/seriesTrend")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(trend.len(), 20);
        assert!(trend.iter().all(|point| point["count"] == 1));
    }

    #[tokio::test]
    async fn abnormal_trends_preserve_query_responses() {
        let schema = schema_with_models_through(1).await;
        {
            let store = schema.store();
            let map = store.time_series_map();
            for index in 0..20 {
                map.insert(&review_database::TimeSeries {
                    model_id: 1,
                    cluster_id: 1,
                    time: 0,
                    value: i64::from(index) * 1_000_000_000,
                    count_index: Some(0),
                    count: usize::MAX,
                })
                .unwrap();
            }
        }
        let response = schema
            .execute_as_system_admin(
                "{ topTimeSeries(model: 1, trendiOrder: 0, minSlope: -1) { trends { trend } }
                topTimeSeriesOfCluster(model: 1, clusterId: 1, trendiOrder: 0) {
                    series { series { count } seriesTrend { count } }
                } }",
            )
            .await;
        assert!(response.errors.is_empty(), "{response:?}");
        let data = response.data.into_json().unwrap();
        assert!(
            data["topTimeSeries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|column| column["trends"].as_array().unwrap().is_empty())
        );
        assert_eq!(
            data.pointer("/topTimeSeriesOfCluster/series/0/series")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            20
        );
        assert_eq!(
            data.pointer("/topTimeSeriesOfCluster/series/0/seriesTrend")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn trends_support_large_cutoff_rates() {
        let schema = schema_with_constant_time_series(100).await;
        for (order, cutoff_rate) in [(3, 10_000), (8, 40)] {
            let arguments = format!("trendiOrder: {order}, cutoffRate: {cutoff_rate}");
            let query = format!(
                "{{ topTimeSeries(model: 1, {arguments}) {{ countIndex trends {{ trend }} }} }}"
            );
            let response = schema.execute_as_system_admin(&query).await;
            assert!(response.errors.is_empty(), "{response:?}");

            let query = format!(
                "{{ topTimeSeriesOfCluster(model: 1, clusterId: 1, {arguments}) {{
                    series {{ seriesTrend {{ count }} }}
                }} }}"
            );
            let response = schema.execute_as_system_admin(&query).await;
            assert!(response.errors.is_empty(), "{response:?}");
            let data = response.data.into_json().unwrap();
            let trend = data
                .pointer("/topTimeSeriesOfCluster/series/0/seriesTrend")
                .unwrap()
                .as_array()
                .unwrap();
            assert_eq!(trend.len(), 100, "{data}");
        }
    }

    #[tokio::test]
    async fn cluster_trend_preserves_cutoff_failure_handling() {
        let schema = schema_with_constant_time_series(20).await;
        for (cutoff_rate, expected_points) in [(0.01, 0), (0.05, 0), (0.1, 20)] {
            let query = format!(
                "{{ topTimeSeriesOfCluster(model: 1, clusterId: 1,
                    trendiOrder: 4, cutoffRate: {cutoff_rate}) {{
                    series {{ series {{ count }} seriesTrend {{ count }} }}
                }} }}"
            );
            let response = schema.execute_as_system_admin(&query).await;
            assert!(response.errors.is_empty(), "{response:?}");
            let data = response.data.into_json().unwrap();
            for (field, expected) in [("series", 20), ("seriesTrend", expected_points)] {
                let path = format!("/topTimeSeriesOfCluster/series/0/{field}");
                assert_eq!(
                    data.pointer(&path).unwrap().as_array().unwrap().len(),
                    expected,
                    "{data}"
                );
            }
        }
    }

    #[tokio::test]
    async fn zero_order_trend_preserves_series() {
        let schema = schema_with_constant_time_series(20).await;
        let response = schema
            .execute_as_system_admin(
                "{ topTimeSeries(model: 1, trendiOrder: 0, cutoffRate: 0.1) {
                    countIndex trends { trend }
                } }",
            )
            .await;
        assert!(response.errors.is_empty(), "{response:?}");

        let response = schema
            .execute_as_system_admin(
                "{ topTimeSeriesOfCluster(model: 1, clusterId: 1,
                    trendiOrder: 0, cutoffRate: 0.1) {
                    series { series { time count } seriesTrend { time count } }
                } }",
            )
            .await;
        assert!(response.errors.is_empty(), "{response:?}");
        let data = response.data.into_json().unwrap();
        let series = data
            .pointer("/topTimeSeriesOfCluster/series/0/series")
            .unwrap();
        let trend = data
            .pointer("/topTimeSeriesOfCluster/series/0/seriesTrend")
            .unwrap();
        assert_eq!(series.as_array().unwrap().len(), 20);
        assert_eq!(trend, series);
    }

    #[tokio::test]
    async fn trend_argument_defaults() {
        let schema = schema_with_models_through(1).await;
        {
            let store = schema.store();
            let map = store.time_series_map();
            for index in 0..100_u32 {
                map.insert(&review_database::TimeSeries {
                    model_id: 1,
                    cluster_id: 1,
                    time: 0,
                    value: i64::from(index) * 1_000_000_000,
                    count_index: Some(0),
                    count: usize::try_from((20 - (index % 40).abs_diff(20)) * 100 + 100).unwrap(),
                })
                .unwrap();
            }
        }
        for (resolver, selection, trend_path) in [
            (
                "topTimeSeries(model: 1",
                "countIndex trends { trend }",
                "/topTimeSeries/0/trends/0/trend",
            ),
            (
                "topTimeSeriesOfCluster(model: 1, clusterId: 1",
                "series { seriesTrend { count } }",
                "/topTimeSeriesOfCluster/series/0/seriesTrend",
            ),
        ] {
            let query =
                format!("{{ {resolver}, trendiOrder: 4, cutoffRate: 0.1) {{ {selection} }} }}");
            let explicit = schema.execute_as_system_admin(&query).await;
            assert!(explicit.errors.is_empty(), "{explicit:?}");
            let data = explicit.data.clone().into_json().unwrap();
            assert!(
                !data
                    .pointer(trend_path)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "{data}"
            );
            for arguments in [
                "",
                ", trendiOrder: null, cutoffRate: null",
                ", cutoffRate: 0.1",
                ", trendiOrder: null, cutoffRate: 0.1",
                ", trendiOrder: 4",
                ", trendiOrder: 4, cutoffRate: null",
            ] {
                let query = format!("{{ {resolver}{arguments}) {{ {selection} }} }}");
                let response = schema.execute_as_system_admin(&query).await;
                assert!(response.errors.is_empty(), "{response:?}");
                assert_eq!(response.data, explicit.data, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn schema_does_not_expose_top_clusters_by_score() {
        let schema = schema_with_models_through(1).await;
        let res = schema
            .execute_as_system_admin(r#"{ __type(name: "Query") { fields { name } } }"#)
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let fields = data["__type"]["fields"].as_array().expect("fields array");
        let names: Vec<&str> = fields.iter().filter_map(|f| f["name"].as_str()).collect();
        assert!(!names.contains(&"topClustersByScore"));
    }

    #[tokio::test]
    async fn schema_does_not_define_cluster_score_types() {
        let schema = schema_with_models_through(1).await;
        let res = schema
            .execute_as_system_admin(
                r#"{ clusterScore: __type(name: "ClusterScore") { name }
                    clusterScoreSet: __type(name: "ClusterScoreSet") { name } }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert!(data["clusterScore"].is_null());
        assert!(data["clusterScoreSet"].is_null());
    }
}
