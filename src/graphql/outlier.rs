use std::sync::RwLock;
use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    ComplexObject, Context, InputObject, Object, Result, SimpleObject, StringNumber, Subscription,
    connection::{Connection, Edge, EmptyFields},
    types::ID,
};
use bincode::Options;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc, offset::LocalResult};
use futures::channel::mpsc::{UnboundedSender, unbounded};
use futures_util::stream::Stream;
use num_traits::ToPrimitive;
use review_database::{
    IndexedTable, Iterable, OutlierInfo, Store, TriageResponse, UniqueKey, event::Direction,
};
use serde::Deserialize;
use serde::Serialize;
use tokio::time;
use tracing::error;

use super::{Role, RoleGuard, customer_access, model::ModelDigest, query, training_result};
use crate::error_with_username;

const MAX_EVENT_NUM_OF_OUTLIER: usize = 50;
const DEFAULT_RANKED_OUTLIER_FETCH_TIME: u64 = 60;
const MAX_MODEL_LIST_SIZE: usize = 100;

/// Converts a time to nanoseconds since the Unix epoch.
///
/// # Errors
///
/// Returns an error if the time is outside the i64 nanosecond range.
pub(super) fn timestamp_nanos(time: DateTime<Utc>) -> Result<i64> {
    time.timestamp_nanos_opt()
        .ok_or_else(|| "time is out of range for i64 nanoseconds".into())
}

#[derive(Default)]
pub(super) struct OutlierStream;

#[Subscription]
impl OutlierStream {
    /// Streams the outliers stored from `start` on, of the models that belong
    /// to the customers the caller had when the subscription started.
    ///
    /// Each fetch reads at most 100 models, counted among those models only.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ranked_outlier_stream(
        &self,
        ctx: &Context<'_>,
        start: DateTime<Utc>,
        #[graphql(
            desc = "The fetch interval in seconds, from 1 to 86400 (one day) inclusive. Omitted or null values use 60 seconds.",
            validator(
                minimum = 1,
                custom = "|value: &u64| async_graphql::validators::maximum(value, super::MAX_STREAM_FETCH_INTERVAL_SECS)"
            )
        )]
        fetch_interval: Option<u64>,
    ) -> Result<impl Stream<Item = RankedOutlier> + use<>> {
        let start = timestamp_nanos(start)?;
        let users_customers = customer_access::users_customers(ctx)?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let fetch_time = fetch_interval.unwrap_or(DEFAULT_RANKED_OUTLIER_FETCH_TIME);
        let username = ctx
            .data::<String>()
            .cloned()
            .unwrap_or("<unknown user>".to_string());
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            if let Err(e) =
                fetch_ranked_outliers(store, users_customers, start, tx, fetch_time).await
            {
                error_with_username!(username: username, "Fetch failed: {e:?}");
            }
        });
        Ok(rx)
    }
}

/// Sends the outliers of the models of `users_customers` (every model if it
/// is `None`) as they are stored, from `start_time` on.
#[allow(clippy::too_many_lines)]
async fn fetch_ranked_outliers(
    store: Arc<RwLock<Store>>,
    users_customers: Option<Vec<u32>>,
    start_time: i64,
    tx: UnboundedSender<RankedOutlier>,
    fetch_time: u64,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fetch_time));
    let mut latest_fetched_key: HashMap<u32, Vec<u8>> = HashMap::new();
    loop {
        itv.tick().await;

        // Read the ids of the caller's models. The scope is applied before the
        // cap, so other customers' models never use it up.
        let model_ids = {
            let store = store
                .read()
                .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
            let map = store.model_map();
            let mut model_ids = Vec::new();
            for res in map.iter(Direction::Forward, None) {
                if model_ids.len() >= MAX_MODEL_LIST_SIZE {
                    break;
                }
                let model = res?;
                if customer_access::can_access_model(users_customers.as_deref(), &model) {
                    model_ids.push(model.id);
                }
            }
            model_ids
        };

        // Search for ranked outliers by model.
        for model_id in model_ids {
            let store = store
                .read()
                .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
            let map = store.outlier_map();

            let (iter, is_first_fetch) = if let Some(cursor) = latest_fetched_key.get(&model_id) {
                (
                    map.get(model_id, None, Direction::Forward, Some(cursor)),
                    false,
                )
            } else {
                (map.get(model_id, None, Direction::Forward, None), true)
            };

            let mut model_cursor = Vec::new();
            for res in iter {
                let entry = res?;
                if is_first_fetch && entry.timestamp < start_time {
                    continue;
                }
                model_cursor = entry.unique_key();
                tx.unbounded_send(entry.into())?;
            }
            if !model_cursor.is_empty() {
                model_cursor.push(0);
                latest_fetched_key.insert(model_id, model_cursor);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct OutlierMutation;

#[Object]
impl OutlierMutation {
    /// Marks the given outliers as saved, returning those that already were.
    ///
    /// The whole request is refused if any input's model belongs to none of
    /// the caller's customers, and with `extensions.code` `NOT_FOUND` if any
    /// names no model.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn preserve_outliers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] input: Vec<PreserveOutliersInput>,
    ) -> Result<Vec<PreserveOutliersOutput>> {
        for (index, outlier) in input.iter().enumerate() {
            customer_access::load_accessible_model(
                ctx,
                &format!("input[{index}].modelId"),
                outlier.model_id,
            )?;
        }
        let store = super::get_store(ctx)?;
        let map = store.outlier_map();
        let mut outdated_items: Vec<PreserveOutliersOutput> = vec![];
        for outlier_key in input {
            let preserve: PreserveOutliersInput = outlier_key.clone();
            let key: review_database::OutlierInfoKey = outlier_key.into();
            if !(map.update_is_saved(&key)?) {
                outdated_items.push(PreserveOutliersOutput::from(preserve));
            }
        }

        Ok(outdated_items)
    }
}

#[derive(Default)]
pub(super) struct OutlierQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct OutlierTimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct OutlierDistanceRange {
    start: Option<f64>,
    end: Option<f64>,
}

#[derive(InputObject, Serialize)]
pub struct SearchFilterInput {
    pub time: Option<OutlierTimeRange>,
    distance: Option<OutlierDistanceRange>,
    tag: Option<String>,
    remark: Option<String>,
}

#[Object]
impl OutlierQuery {
    /// A list of outliers, one per clustering round.
    ///
    /// With `previous`, the outliers of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    // Each argument is an argument of the GraphQL field.
    #[allow(clippy::too_many_arguments)]
    async fn outliers(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Outlier, OutlierTotalCount, EmptyFields>> {
        let previous = previous.unwrap_or_default();
        let model = model.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, model, previous, after, before, first, last).await
            },
        )
        .await
    }

    /// A list of saved outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
    ///
    /// With `previous`, the saved outliers of the model's previous training
    /// result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
     .or(RoleGuard::new(Role::SecurityAdministrator))
     .or(RoleGuard::new(Role::SecurityManager))
     .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn saved_outliers(
        &self,
        ctx: &Context<'_>,
        model_id: ID,
        time: Option<NaiveDateTime>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>,
    > {
        let previous = previous.unwrap_or_default();
        let time = time.map(|t| timestamp_nanos(t.and_utc())).transpose()?;
        let model_id: u32 = model_id.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "modelId", model_id)?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_saved_outliers(ctx, model_id, time, previous, after, before, first, last).await
            },
        )
        .await
    }

    /// A list of outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
    ///
    /// With `previous`, the outliers of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
     .or(RoleGuard::new(Role::SecurityAdministrator))
     .or(RoleGuard::new(Role::SecurityManager))
     .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn ranked_outliers(
        &self,
        ctx: &Context<'_>,
        model_id: ID,
        time: Option<NaiveDateTime>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        filter: Option<SearchFilterInput>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>,
    > {
        let previous = previous.unwrap_or_default();
        let time = time.map(|t| timestamp_nanos(t.and_utc())).transpose()?;
        let model_id: u32 = model_id.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "modelId", model_id)?;
        let time_range = filter
            .as_ref()
            .and_then(|filter| filter.time.as_ref())
            .map(|range| {
                Ok::<_, async_graphql::Error>((
                    range.start.map(timestamp_nanos).transpose()?,
                    range.end.map(timestamp_nanos).transpose()?,
                ))
            })
            .transpose()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_ranked_outliers_with_filter(
                    ctx, model_id, time, previous, after, before, first, last, filter, time_range,
                )
                .await
            },
        )
        .await
    }
}

/// Loads a page of the model's saved outliers, keeping only saved ones before
/// the page is cut.
#[allow(clippy::too_many_arguments)]
async fn load_saved_outliers(
    ctx: &Context<'_>,
    model_id: u32,
    timestamp: Option<i64>,
    previous: bool,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>>
{
    let prefix = {
        let mut buf = model_id.to_be_bytes().to_vec();
        if let Some(ts) = timestamp {
            buf.extend(ts.to_be_bytes());
        }
        buf
    };

    let store = crate::graphql::get_store(ctx)?;
    let map = training_result::outlier_map(&store, previous);

    let (nodes, has_previous, has_next) = super::process_load_edges_filtered(
        &map,
        after,
        before,
        first,
        last,
        Some(&prefix),
        |outlier: &OutlierInfo| outlier.is_saved,
    );
    let nodes = nodes
        .into_iter()
        .map(|res| res.map_err(|e| format!("{e}").into()))
        .collect::<Result<Vec<_>>>()?;

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
            check_saved: true,
            previous,
        },
    );
    connection.edges.extend(nodes.into_iter().map(|n| {
        let cursor = OpaqueCursor(n.unique_key());
        Edge::new(cursor, n.into())
    }));
    Ok(connection)
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
pub(super) struct RankedOutlier {
    #[graphql(skip)]
    id: i64,
    #[graphql(skip)]
    model_id: u32,
    timestamp: i64,
    rank: i64,
    sensor: String,
    distance: f64,
    saved: bool,
}

impl From<review_database::OutlierInfo> for RankedOutlier {
    fn from(input: review_database::OutlierInfo) -> Self {
        Self {
            id: input.id,
            model_id: input.model_id,
            timestamp: input.timestamp,
            rank: input.rank,
            sensor: input.sensor,
            distance: input.distance,
            saved: input.is_saved,
        }
    }
}

#[ComplexObject]
impl RankedOutlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn model_id(&self) -> ID {
        ID(self.model_id.to_string())
    }
}

#[derive(Debug, Clone, InputObject)]
struct PreserveOutliersInput {
    id: i64,
    model_id: u32,
    timestamp: i64,
    rank: i64,
    sensor: String,
}

impl From<PreserveOutliersInput> for review_database::OutlierInfoKey {
    fn from(input: PreserveOutliersInput) -> Self {
        Self {
            model_id: input.model_id,
            timestamp: input.timestamp,
            rank: input.rank,
            id: input.id,
            sensor: input.sensor,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PreserveOutliersOutput {
    id: i64,
    model_id: u32,
    timestamp: i64,
    sensor: String,
}

impl From<PreserveOutliersInput> for PreserveOutliersOutput {
    fn from(input: PreserveOutliersInput) -> Self {
        Self {
            model_id: input.model_id,
            timestamp: input.timestamp,
            id: input.id,
            sensor: input.sensor,
        }
    }
}

#[Object]
impl PreserveOutliersOutput {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn model_id(&self) -> ID {
        ID(self.model_id.to_string())
    }

    async fn timestamp(&self) -> StringNumber<i64> {
        StringNumber(self.timestamp)
    }

    async fn sensor(&self) -> String {
        self.sensor.clone()
    }
}

struct RankedOutlierTotalCount {
    model_id: u32,
    timestamp: Option<i64>,
    check_saved: bool,
    previous: bool,
}

#[Object]
impl RankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::outlier_map(&store, self.previous);

        let iter = map.get(self.model_id, self.timestamp, Direction::Forward, None);
        let count = if self.check_saved {
            iter.filter(|res| {
                if let Ok(entry) = res {
                    entry.is_saved
                } else {
                    false
                }
            })
            .count()
        } else {
            iter.count()
        };
        Ok(StringNumber(count))
    }
}

#[derive(Debug, Deserialize, SimpleObject)]
#[graphql(complex)]
pub(super) struct Outlier {
    #[graphql(skip)]
    pub(super) id: i64, //timestamp
    #[graphql(skip)]
    pub(super) events: Vec<i64>,
    pub(super) size: i64,
    #[graphql(skip)]
    pub(super) model_id: u32,
}

#[ComplexObject]
impl Outlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn model_id(&self) -> ID {
        ID(self.model_id.to_string())
    }

    async fn events(&self) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<ModelDigest> {
        Ok(customer_access::load_accessible_model(ctx, "modelId", self.model_id)?.into())
    }
}

struct OutlierTotalCount {
    model_id: u32,
    previous: bool,
}

#[Object]
impl OutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        use std::collections::HashSet;
        let store = crate::graphql::get_store(ctx)?;
        let table = training_result::outlier_map(&store, self.previous);
        let iter = table.get(self.model_id, None, Direction::Forward, None);

        Ok(StringNumber(
            iter.map(|res| res.map(|entry| entry.timestamp).map_err(Into::into))
                .collect::<Result<HashSet<_>>>()?
                .len(),
        ))
    }
}

async fn load(
    ctx: &Context<'_>,
    model_id: u32,
    previous: bool,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Outlier, OutlierTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let table = training_result::outlier_map(&store, previous);

    let after = after.map(|cursor| cursor.0);
    let before = before.map(|cursor| cursor.0);

    let decoded_after = after
        .as_deref()
        .map(|input| bincode::DefaultOptions::new().deserialize(input))
        .transpose()?
        .map(|(_, from): (&[u8], &[u8])| from);
    let decoded_before = before
        .as_deref()
        .map(|input| bincode::DefaultOptions::new().deserialize(input))
        .transpose()?
        .map(|(from, _): (&[u8], &[u8])| from);
    let (direction, count, from, to) = if let Some(first) = first {
        (Direction::Forward, first, decoded_after, decoded_before)
    } else if let Some(last) = last {
        (Direction::Reverse, last, decoded_before, decoded_after)
    } else {
        unreachable!();
    };

    let iter = table.get(model_id, None, direction, from);

    let mut batches = HashMap::new();
    let mut has_more = false;
    for res in iter {
        let entry = res?;
        if !batches.contains_key(&entry.timestamp) && batches.len() >= count {
            has_more = true;
            break;
        }
        let key = entry.unique_key();
        if let Some(to) = to
            && key == to
        {
            break;
        }

        let batch = batches.entry(entry.timestamp).or_insert((
            key.clone(),
            vec![],
            Outlier {
                model_id,
                events: vec![],
                id: entry.timestamp,
                size: 0,
            },
        ));
        batch.1 = key;
        batch.2.size += 1;
        if batch.2.events.len() < MAX_EVENT_NUM_OF_OUTLIER {
            batch.2.events.push(entry.id);
        }
    }

    let (has_previous, has_next) = if first.is_some() {
        (false, has_more)
    } else {
        (has_more, false)
    };
    let edges = batches.into_values().filter_map(|(from, to, mut ev)| {
        let cursor = bincode::DefaultOptions::new().serialize(&(from, to)).ok()?;
        let cursor = OpaqueCursor(cursor);
        ev.events.sort_unstable();
        Some(Edge::new(cursor, ev))
    });
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        OutlierTotalCount { model_id, previous },
    );
    connection.edges.extend(edges);
    Ok(connection)
}

pub(crate) fn datetime_from_ts_nano(time: i64) -> Option<DateTime<Utc>> {
    let sec = time / 1_000_000_000;
    let nano = (time - sec * 1_000_000_000).to_u32()?;
    if let LocalResult::Single(time) = Utc.timestamp_opt(sec, nano) {
        Some(time)
    } else {
        None
    }
}

fn check_filter_to_ranked_outlier(
    node: &OutlierInfo,
    filter: Option<&SearchFilterInput>,
    tag_id_list: Option<&Vec<u32>>,
    time_range: Option<(Option<i64>, Option<i64>)>,
    remarks_map: &IndexedTable<'_, TriageResponse>,
) -> Result<bool> {
    if let Some(filter) = filter {
        if filter.remark.is_some() || tag_id_list.is_some() {
            if let Some(value) = remarks_map.get(&node.sensor, &Utc.timestamp_nanos(node.id))? {
                if let Some(remark) = &filter.remark
                    && !value.remarks.contains(remark)
                {
                    return Ok(false);
                }
                if let Some(tag_ids) = &tag_id_list
                    && !tag_ids.iter().any(|tag| value.tag_ids().contains(tag))
                {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }
        if let Some((start, end)) = time_range
            && (start.is_some_and(|start| node.timestamp < start)
                || end.is_some_and(|end| node.timestamp > end))
        {
            return Ok(false);
        }

        if let Some(distance) = &filter.distance
            && let Some(start) = distance.start
        {
            if let Some(end) = distance.end {
                if node.distance < start || node.distance > end {
                    return Ok(false);
                }
            } else if node.distance < start {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn load_ranked_outliers_with_filter(
    ctx: &Context<'_>,
    model_id: u32,
    timestamp: Option<i64>,
    previous: bool,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    filter: Option<SearchFilterInput>,
    time_range: Option<(Option<i64>, Option<i64>)>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>>
{
    let after = after.map(|cursor| cursor.0);
    let before = before.map(|cursor| cursor.0);
    let (direction, count, from) = if let Some(first) = first {
        (Direction::Forward, first, after.as_deref())
    } else if let Some(last) = last {
        (Direction::Reverse, last, before.as_deref())
    } else {
        unreachable!();
    };

    let store = crate::graphql::get_store(ctx)?;
    let table = training_result::outlier_map(&store, previous);

    let remarks_map = store.triage_response_map();
    let tags_map = store.event_tag_set()?;

    let mut has_more = false;
    let mut nodes = vec![];
    let additional = RankedOutlierTotalCount {
        model_id,
        timestamp,
        check_saved: false,
        previous,
    };

    let tag_id_list = if let Some(filter) = &filter {
        if let Some(pattern) = &filter.tag {
            let tag_ids = tags_map
                .tags()
                .filter_map(|tag| {
                    if tag.name.contains(pattern) {
                        Some(tag.id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if tag_ids.is_empty() {
                return Ok(Connection::with_additional_fields(false, false, additional));
            }
            Some(tag_ids)
        } else {
            None
        }
    } else {
        None
    };

    let mut ranked_outlier_iter = table.get(model_id, timestamp, direction, from);

    // Check whether the current query specifies a cursor. If it does, the first returned item
    // should be the one immediately after or before the cursor. If not, the very first item should
    // be returned.
    if let Some(res) = ranked_outlier_iter.next() {
        let node = res?;
        let key = node.unique_key();
        if let Some(from) = from {
            if from != key {
                return Err(anyhow!("invalid cursor").into());
            }
        } else if check_filter_to_ranked_outlier(
            &node,
            filter.as_ref(),
            tag_id_list.as_ref(),
            time_range,
            &remarks_map,
        )? {
            nodes.push((OpaqueCursor(key), node));
        }
    }

    for res in ranked_outlier_iter {
        let node = res?;
        let key = node.unique_key();

        if check_filter_to_ranked_outlier(
            &node,
            filter.as_ref(),
            tag_id_list.as_ref(),
            time_range,
            &remarks_map,
        )? {
            if nodes.len() >= count {
                has_more = true;
                break;
            }
            nodes.push((OpaqueCursor(key), node));
        }
    }

    let (has_previous, has_next) = if first.is_some() {
        (false, has_more)
    } else {
        nodes.reverse();
        (has_more, false)
    };

    let mut connection = Connection::with_additional_fields(has_previous, has_next, additional);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev.into())));
    Ok(connection)
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use async_graphql::Value;
    use chrono::{DateTime, Utc};
    use futures_util::StreamExt;
    use num_traits::ToPrimitive;
    use review_database::OutlierInfo;

    use crate::graphql::Role;
    use crate::graphql::model_test_support::{replace_model, schema_with_models_through};

    fn time_str(t: &DateTime<Utc>) -> String {
        t.format("%FT%T%.9f").to_string()
    }

    fn samples(model_id: u32, timestamp: i64, start: i64, total: i64) -> Vec<OutlierInfo> {
        (start..start + total)
            .map(|id| {
                let rank = id;
                let distance = id.to_f64().unwrap();
                let is_saved = id % 2 == 0;
                OutlierInfo {
                    model_id,
                    timestamp,
                    rank,
                    id,
                    sensor: "test".to_string(),
                    distance,
                    is_saved,
                }
            })
            .collect()
    }

    const OUT_OF_RANGE_TIMES: [&str; 2] = [
        "1677-09-21T00:12:43.145224191",
        "2262-04-11T23:47:16.854775808",
    ];
    const BOUNDARY_TIMES: [&str; 2] = [
        "1677-09-21T00:12:43.145224192",
        "2262-04-11T23:47:16.854775807",
    ];

    fn time_queries(time: &str) -> Vec<String> {
        let mut queries = vec![format!(
            "{{topTimeSeries(model: 3, time: \"{time}\") {{countIndex}}}}"
        )];
        for field in ["savedOutliers", "rankedOutliers"] {
            queries.push(format!(
                "{{{field}(modelId: 3, time: \"{time}\") {{nodes {{id}}}}}}"
            ));
        }
        for bound in ["start", "end"] {
            for tag in ["", ", tag: \"no matching tag\""] {
                queries.push(format!(
                    "{{rankedOutliers(modelId: 3, filter: {{time: {{{bound}: \"{time}Z\"}}{tag}}}) {{nodes {{id}}}}}}"
                ));
            }
        }
        queries
    }

    #[tokio::test]
    async fn reject_out_of_range_query_times() {
        let schema = schema_with_models_through(3).await;
        for time in OUT_OF_RANGE_TIMES {
            for query in time_queries(time) {
                let response = schema.execute_as_system_admin(&query).await;
                assert!(
                    response
                        .errors
                        .iter()
                        .any(|error| error.message.contains("time is out of range")),
                    "{query}: {response:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn accept_query_time_boundaries() {
        let schema = schema_with_models_through(3).await;
        for time in BOUNDARY_TIMES {
            for query in time_queries(time) {
                let response = schema.execute_as_system_admin(&query).await;
                assert!(response.errors.is_empty(), "{query}: {response:?}");
            }
        }
    }

    #[tokio::test]
    async fn reject_out_of_range_stream_start() {
        let schema = schema_with_models_through(3).await;
        for time in OUT_OF_RANGE_TIMES {
            let query = format!("subscription {{rankedOutlierStream(start: \"{time}Z\") {{id}}}}");
            let mut stream = schema.execute_stream(&query).await;
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert!(
                response
                    .errors
                    .iter()
                    .any(|error| error.message.contains("time is out of range")),
                "{response:?}"
            );
        }
    }

    #[tokio::test]
    async fn representable_times_return_stored_data() {
        let schema = schema_with_models_through(3).await;
        let time = "2025-01-01T00:00:00";
        let timestamp = format!("{time}Z")
            .parse::<DateTime<Utc>>()
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        {
            let store = schema.store();
            for batch in [timestamp - 1, timestamp, timestamp + 1] {
                for outlier in samples(3, batch, 0, 2) {
                    store.outlier_map().insert(&outlier).unwrap();
                }
            }
            store
                .time_series_map()
                .insert(&review_database::TimeSeries {
                    model_id: 3,
                    cluster_id: 1,
                    time: timestamp,
                    value: timestamp,
                    count_index: Some(0),
                    count: 1,
                })
                .unwrap();
        }
        for (field, ids) in [
            ("savedOutliers", "[{id: \"0\"}]"),
            ("rankedOutliers", "[{id: \"0\"}, {id: \"1\"}]"),
        ] {
            let query = format!("{{{field}(modelId: 3, time: \"{time}\") {{nodes {{id}}}}}}");
            let response = schema.execute_as_system_admin(&query).await;
            assert!(response.errors.is_empty(), "{response:?}");
            assert_eq!(
                response.data.to_string(),
                format!("{{{field}: {{nodes: {ids}}}}}")
            );
        }
        let query = format!(
            "{{rankedOutliers(modelId: 3, filter: {{time: {{start: \"{time}Z\", end: \"{time}Z\"}}}}) {{nodes {{timestamp}}}}}}"
        );
        let response = schema.execute_as_system_admin(&query).await;
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(
            response.data.to_string(),
            format!(
                "{{rankedOutliers: {{nodes: [{{timestamp: {timestamp}}}, {{timestamp: {timestamp}}}]}}}}"
            )
        );
        let query = format!("{{topTimeSeries(model: 3, time: \"{time}\") {{countIndex}}}}");
        let response = schema.execute_as_system_admin(&query).await;
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(
            response.data.to_string(),
            "{topTimeSeries: [{countIndex: 0}]}"
        );
    }

    #[tokio::test]
    async fn valid_stream_start_returns_outliers() {
        let schema = schema_with_models_through(3).await;
        let time = "2025-01-01T00:00:00Z";
        let timestamp = time
            .parse::<DateTime<Utc>>()
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        let model_id = {
            let store = schema.store();
            let model_id = replace_model(&store, "stream model", 0);
            for (batch, id) in [(timestamp - 1, 0), (timestamp, 1), (timestamp + 1, 2)] {
                store
                    .outlier_map()
                    .insert(samples(model_id, batch, id, 1).first().unwrap())
                    .unwrap();
            }
            model_id
        };
        let query = format!(
            "subscription {{rankedOutlierStream(start: \"{time}\") {{id modelId timestamp}}}}"
        );
        let mut stream = schema.execute_stream(&query).await;
        for (id, batch) in [(1, timestamp), (2, timestamp + 1)] {
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert!(response.errors.is_empty(), "{response:?}");
            assert_eq!(
                response.data.to_string(),
                format!(
                    "{{rankedOutlierStream: {{id: \"{id}\", modelId: \"{model_id}\", timestamp: {batch}}}}}"
                )
            );
        }
    }

    #[tokio::test]
    async fn ranked_outlier_stream_fetch_interval_defaults_and_bounds() {
        let schema = schema_with_models_through(3).await;
        {
            let store = schema.store();
            let model = replace_model(&store, "stream-test", 0);
            let timestamp = "2018-01-28T01:00:00Z".parse::<DateTime<Utc>>().unwrap();
            for outlier in samples(model, timestamp.timestamp_nanos_opt().unwrap(), 5, 1) {
                store.outlier_map().insert(&outlier).unwrap();
            }
        }
        for argument in [
            "",
            ", fetchInterval: null",
            ", fetchInterval: 1",
            ", fetchInterval: 86400",
        ] {
            let query = format!(
                r#"subscription {{ rankedOutlierStream(start: "2018-01-28T00:00:00Z"{argument}) {{ id }} }}"#
            );
            let mut stream = schema.execute_stream(&query).await;
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert!(response.errors.is_empty(), "{response:?}");
            assert_eq!(
                response.data.to_string(),
                r#"{rankedOutlierStream: {id: "5"}}"#
            );
        }
    }

    #[tokio::test]
    async fn outlier_stream_fetch_interval_range() {
        let schema = schema_with_models_through(3).await;
        for (interval, range) in [
            (0, "must be greater than or equal to 1"),
            (86_401, "must be less than or equal to 86400"),
        ] {
            let query = format!(
                r#"subscription {{ rankedOutlierStream(start: "2018-01-28T00:00:00Z", fetchInterval: {interval}) {{ id }} }}"#
            );
            let mut stream = schema.execute_stream(&query).await;
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.errors.len(), 1, "{response:?}");
            let error = response.errors.first().unwrap();
            assert!(error.message.contains(range), "{error:?}");
            // Identify fetchInterval by the reported argument value location.
            let column = query.find("fetchInterval: ").unwrap() + "fetchInterval: ".len() + 1;
            assert_eq!(
                error.locations,
                vec![async_graphql::Pos { line: 1, column }]
            );
        }
    }

    #[tokio::test]
    async fn outliers() {
        let schema = schema_with_models_through(3).await;
        let store = schema.store();
        let map = store.outlier_map();
        let model = 3;
        let t1 = chrono::Utc::now();
        let outliers = samples(model, t1.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }
        let res = schema
            .execute_as_system_admin(
                r"query {
                outliers(model: 3) {
                    nodes {id, events, size},
                    totalCount
                }
            }",
            )
            .await;
        let e0 = DateTime::from_timestamp(0, 0).unwrap().to_rfc3339();
        let e1 = DateTime::from_timestamp(0, 1).unwrap().to_rfc3339();
        assert_eq!(
            res.data.to_string(),
            format!(
                "{{outliers: {{nodes: [{{id: \"{}\", events: [\"{e0}\", \"{e1}\"], size: 2}}], totalCount: \"{}\"}}}}",
                t1.timestamp_nanos_opt().unwrap(),
                1
            )
        );

        let t2 = t1 + chrono::TimeDelta::hours(1);
        let start = 3;
        let total = 4;

        let outliers = samples(model, t2.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let res = schema
            .execute_as_system_admin(
                r"query {
                    outliers(model: 3) {
                        totalCount
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{outliers: {{totalCount: \"{}\"}}}}", 2)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ranked_outliers() {
        let schema = schema_with_models_through(3).await;
        let store = schema.store();
        let map = store.outlier_map();
        let model = 3;
        let t1 = chrono::Utc::now();
        let outliers = samples(model, t1.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let res = schema
            .execute_as_system_admin(
                r"query {
                    rankedOutliers(modelId: 3) {
                        totalCount
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{totalCount: \"{}\"}}}}", outliers.len())
        );

        let t2 = t1 + chrono::TimeDelta::hours(1);
        let t2_str = time_str(&t2);
        let start = 3;
        let total = 4;
        let last = start + total - 1;

        let outliers = samples(model, t2.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let res = schema.execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", first: 1) {{ nodes {{ id }} }} }}"
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{}\"}}]}}}}", 3)
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", first: 3) {{ pageInfo {{
                hasNextPage,
                startCursor,
                endCursor
            }} }} }}"
            ))
            .await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(ranked_outliers)) = retval.get("rankedOutliers") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::Object(page_info)) = ranked_outliers.get("pageInfo") else {
            panic!("unexpected response: {ranked_outliers:?}");
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {page_info:?}");
        };
        assert!(*has_next_page);
        let Some(Value::String(cursor)) = page_info.get("endCursor") else {
            panic!("unexpected response: {page_info:?}");
        };

        let res = schema.execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", after: \"{cursor}\", first: 1) {{ nodes {{ id }} }} }}"
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{last}\"}}]}}}}")
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", last: 2) {{ nodes {{ id }} }} }}"
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!(
                "{{rankedOutliers: {{nodes: [{{id: \"{}\"}}, {{id: \"{}\"}}]}}}}",
                last - 1,
                last
            )
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", last: 3) {{ pageInfo {{
            hasPreviousPage,
            startCursor,
            endCursor
        }} }} }}"
            ))
            .await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(ranked_outliers)) = retval.get("rankedOutliers") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::Object(page_info)) = ranked_outliers.get("pageInfo") else {
            panic!("unexpected response: {ranked_outliers:?}");
        };
        let Some(Value::Boolean(has_previous_page)) = page_info.get("hasPreviousPage") else {
            panic!("unexpected response: {page_info:?}");
        };
        assert!(*has_previous_page);
        let Some(Value::String(cursor)) = page_info.get("startCursor") else {
            panic!("unexpected response: {page_info:?}");
        };

        let res = schema.execute_as_system_admin(&format!(
            "query {{rankedOutliers(modelId: 3, time: \"{t2_str}\", before: \"{cursor}\", last: 1) {{ nodes {{ id }} }} }}"
        ))
        .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{start}\"}}]}}}}")
        );
    }

    #[tokio::test]
    async fn saved_outliers() {
        let schema = schema_with_models_through(3).await;
        let store = schema.store();
        let map = store.outlier_map();

        let t = chrono::Utc::now();
        let t_str = time_str(&t);
        let outliers = samples(0, t.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let model = 3;

        let start = 3;
        let total = 4;

        let outliers = samples(model, t.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{savedOutliers(modelId: {model}, time: \"{t_str}\") {{ totalCount }} }}"
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: \"{}\"}}}}", total / 2)
        );
    }

    #[tokio::test]
    async fn preserved_outliers() {
        let schema = schema_with_models_through(3).await;
        let store = schema.store();
        let map = store.outlier_map();

        let t = chrono::Utc::now();
        let t_str = time_str(&t);

        let model = 3;

        let start = 3;
        let total = 4;

        let outliers = samples(model, t.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(outlier).is_ok());
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{savedOutliers(modelId: {model}, time: \"{t_str}\") {{ totalCount }} }}"
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: \"{}\"}}}}", total / 2)
        );

        let to_save = start;
        let to_preserve = format!(
            "[{{id: {to_save}, modelId: {model}, timestamp: {}, rank: {to_save}, sensor: \"test\"}}]",
            t.timestamp_nanos_opt().unwrap()
        );
        let res = schema
            .execute_as_system_admin(&format!(
                "mutation {{
                    preserveOutliers(input: {to_preserve}) {{
                        id
                        modelId
                        timestamp
                        sensor
                    }}
                }}"
            ))
            .await;
        let expect = "{preserveOutliers: []}".to_string();
        assert_eq!(res.data.to_string(), expect);

        let saved = start + 1;
        let to_preserve = format!(
            "[{{id: {saved}, modelId: {model}, timestamp: {}, rank: {saved}, sensor: \"test\"}}]",
            t.timestamp_nanos_opt().unwrap()
        );
        let res = schema
            .execute_as_system_admin(&format!(
                "mutation {{
                    preserveOutliers(input: {to_preserve}) {{
                        id
                        modelId
                        timestamp
                        sensor
                    }}
                }}"
            ))
            .await;
        let expect = format!(
            "{{preserveOutliers: [{{id: \"{saved}\", modelId: \"{model}\", timestamp: \"{}\", sensor: \"test\"}}]}}",
            t.timestamp_nanos_opt().unwrap()
        );
        assert_eq!(res.data.to_string(), expect);
    }

    #[tokio::test]
    async fn ranked_outlier_stream_reads_only_the_caller_models() {
        const CUSTOMER_A: u32 = 1;
        const CUSTOMER_B: u32 = 2;
        let schema = schema_with_models_through(0).await;
        let timestamp = "2025-01-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap();
        let (first_b, model_a) = {
            let store = schema.store();
            // More models of customer B than the stream reads per tick, all
            // sorting before customer A's model.
            let mut first_b = None;
            for i in 0..=super::MAX_MODEL_LIST_SIZE {
                let id = replace_model(&store, &format!("b-{i:03}"), CUSTOMER_B);
                first_b.get_or_insert(id);
            }
            let first_b = first_b.unwrap();
            store
                .outlier_map()
                .insert(samples(first_b, timestamp, 7, 1).first().unwrap())
                .unwrap();
            let model_a = replace_model(&store, "z-model", CUSTOMER_A);
            for outlier in samples(model_a, timestamp, 1, 2) {
                store.outlier_map().insert(&outlier).unwrap();
            }
            (first_b, model_a)
        };
        let query = "subscription { rankedOutlierStream(start: \"2025-01-01T00:00:00Z\", \
                     fetchInterval: 1) { id modelId } }";

        let mut stream = schema
            .execute_stream_as_scoped_user(query, Role::SecurityMonitor, Some(vec![CUSTOMER_A]))
            .await;
        // Customer B's outlier would come first had its model been read.
        for id in [1, 2] {
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap();
            assert!(response.errors.is_empty(), "{response:?}");
            assert_eq!(
                response.data.to_string(),
                format!("{{rankedOutlierStream: {{id: \"{id}\", modelId: \"{model_a}\"}}}}")
            );
        }

        let mut stream = schema.execute_stream(query).await;
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            response.data.to_string(),
            format!("{{rankedOutlierStream: {{id: \"7\", modelId: \"{first_b}\"}}}}")
        );
    }

    #[tokio::test]
    async fn saved_outlier_pages_hold_only_saved_outliers() {
        let schema = schema_with_models_through(3).await;
        let t = chrono::Utc::now();
        let t_str = time_str(&t);
        {
            let store = schema.store();
            // Saved outliers are the even ids; the odd ones are not saved.
            for outlier in samples(3, t.timestamp_nanos_opt().unwrap(), 0, 11) {
                store.outlier_map().insert(&outlier).unwrap();
            }
        }
        let page = |arguments: &str| {
            format!(
                "{{ savedOutliers(modelId: 3, time: \"{t_str}\", {arguments}) {{
                    totalCount nodes {{ id saved }}
                    pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }} }} }}"
            )
        };
        let mut ids = Vec::new();
        let mut arguments = "first: 2".to_string();
        loop {
            let response = schema.execute_as_system_admin(&page(&arguments)).await;
            assert!(response.errors.is_empty(), "{response:?}");
            let json = response.data.into_json().unwrap();
            let connection = &json["savedOutliers"];
            assert_eq!(connection["totalCount"], "6");
            let nodes = connection["nodes"].as_array().unwrap();
            assert!(nodes.iter().all(|node| node["saved"] == true), "{nodes:?}");
            ids.extend(
                nodes
                    .iter()
                    .map(|node| node["id"].as_str().unwrap().to_string()),
            );
            if connection["pageInfo"]["hasNextPage"] == false {
                assert!(nodes.len() <= 2);
                break;
            }
            assert_eq!(nodes.len(), 2);
            let cursor = connection["pageInfo"]["endCursor"].as_str().unwrap();
            arguments = format!("first: 2, after: \"{cursor}\"");
        }
        assert_eq!(ids, ["0", "2", "4", "6", "8", "10"]);

        let response = schema.execute_as_system_admin(&page("last: 4")).await;
        let json = response.data.into_json().unwrap();
        let connection = &json["savedOutliers"];
        assert_eq!(connection["pageInfo"]["hasPreviousPage"], true);
        assert_eq!(
            connection["nodes"],
            serde_json::json!([
                { "id": "4", "saved": true },
                { "id": "6", "saved": true },
                { "id": "8", "saved": true },
                { "id": "10", "saved": true },
            ])
        );
    }
}
