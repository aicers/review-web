use super::{
    always_true,
    model::ModelDigest,
    triage::response::{key, TriageResponse},
    Role, RoleGuard, DEFAULT_CONNECTION_SIZE,
};
use crate::graphql::{earliest_key, latest_key};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    types::ID,
    ComplexObject, Context, InputObject, Object, ObjectType, OutputType, Result, SimpleObject,
    Subscription,
};
use bincode::Options;
use chrono::{offset::LocalResult, DateTime, NaiveDateTime, TimeZone, Utc};
use data_encoding::BASE64;
use futures::channel::mpsc::{unbounded, UnboundedSender};
use futures_util::stream::Stream;
use num_traits::ToPrimitive;
use review_database::{types::FromKeyValue, Database, Direction, IterableMap, Store};
use serde::Deserialize;
use serde::Serialize;
use std::{cmp, collections::HashMap, sync::Arc};
use tokio::{sync::RwLock, time};
use tracing::error;

pub const TIMESTAMP_SIZE: usize = 8;
const DEFAULT_OUTLIER_SIZE: usize = 50;
const DISTANCE_EPSILON: f64 = 0.1;
const DEFAULT_RANKED_OUTLIER_FETCH_TIME: u64 = 60;
const MAX_MODEL_LIST_SIZE: usize = 100;

#[derive(Default)]
pub(super) struct OutlierStream;

#[Subscription]
impl OutlierStream {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ranked_outlier_stream(
        &self,
        ctx: &Context<'_>,
        start: DateTime<Utc>,
        fetch_interval: Option<u64>,
    ) -> Result<impl Stream<Item = RankedOutlier>> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let db = ctx.data::<Database>()?.clone();
        let fetch_time = fetch_interval.unwrap_or(DEFAULT_RANKED_OUTLIER_FETCH_TIME);
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            if let Err(e) = fetch_ranked_outliers(
                db,
                store,
                start.timestamp_nanos_opt().unwrap_or_default(),
                tx,
                fetch_time,
            )
            .await
            {
                error!("{e:?}");
            }
        });
        Ok(rx)
    }
}

#[allow(clippy::too_many_lines)]
async fn fetch_ranked_outliers(
    db: Database,
    store: Arc<RwLock<Store>>,
    start_time: i64,
    tx: UnboundedSender<RankedOutlier>,
    fetch_time: u64,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fetch_time));
    let mut latest_fetched_key: HashMap<i32, Vec<u8>> = HashMap::new();

    loop {
        itv.tick().await;

        // Read current model's ids
        let rows = db
            .load_models(&None, &None, true, MAX_MODEL_LIST_SIZE)
            .await?;
        let model_ids: Vec<i32> = rows.iter().map(|row| row.id).collect();

        // Search for ranked outliers by model.
        for model_id in model_ids {
            let prefix = bincode::DefaultOptions::new().serialize(&(model_id))?;
            let store = store.read().await;
            let map = store.outlier_map().into_prefix_map(&prefix);
            let (iter, is_first_fetch) = if let Some(cursor) = latest_fetched_key.get(&model_id) {
                (map.iter_from(cursor, Direction::Forward)?, false)
            } else {
                (map.iter_forward()?, true)
            };

            let mut model_cursor = Vec::new();
            for (k, v) in iter {
                if let Some(value) = RankedOutlier::from_key_value(&k, &v)?.into() {
                    if is_first_fetch && value.timestamp < start_time {
                        continue;
                    }
                    model_cursor = k.to_vec();
                    tx.unbounded_send(value)?;
                };
            }
            if !model_cursor.is_empty() {
                model_cursor.push(0);
                latest_fetched_key.insert(model_id, model_cursor);
            }
        }
    }
}

#[derive(Debug, InputObject)]
pub(super) struct InputCentralRankedOutlier {
    pub code: String,
    pub timestamp: String,
    pub rank: i64,
    pub id: String,
    pub source: String,
    pub distance: f64,
    pub saved: bool,
}

#[derive(Debug, SimpleObject)]
pub(super) struct CentralRankedOutlier {
    pub code: String,
    pub timestamp: String,
    pub rank: i64,
    pub id: String,
    pub source: String,
    pub distance: f64,
    pub saved: bool,
}

type CentralRankedOutlierKey = (String, String, i64, String, String);
type CentralRankedOutlierValue = (f64, bool);
impl FromKeyValue for CentralRankedOutlier {
    fn from_key_value(key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        let (code, timestamp, rank, id, source) =
            bincode::DefaultOptions::new().deserialize(key)?;
        let (distance, saved) = bincode::DefaultOptions::new().deserialize(value)?;
        Ok(Self {
            code,
            timestamp,
            rank,
            id,
            source,
            distance,
            saved,
        })
    }
}

struct CentralRankedOutlierTotalCount {
    code: String,
    timestamp: Option<i64>,
    check_saved: bool,
}

#[Object]
impl CentralRankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::IterableMap;
        let prefix = if let Some(timestamp) = self.timestamp {
            bincode::DefaultOptions::new().serialize(&(self.code.clone(), timestamp.to_string()))?
        } else {
            bincode::DefaultOptions::new().serialize(&self.code)?
        };
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.outlier_map().into_prefix_map(&prefix);

        let iter = map.iter_forward()?;
        let count = if self.check_saved {
            iter.filter(|(_k, v)| {
                let (_, saved): CentralRankedOutlierValue = bincode::DefaultOptions::new()
                    .deserialize(v)
                    .unwrap_or_default();
                saved
            })
            .count()
        } else {
            iter.count()
        };
        Ok(count)
    }
}

#[derive(Default)]
pub(super) struct OutlierMutation;

#[Object]
impl OutlierMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn preserve_outliers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] input: Vec<PreserveOutliersInput>,
    ) -> Result<usize> {
        use bincode::Options;
        let store = super::get_store(ctx).await?;
        let map = store.outlier_map();
        let mut updated = vec![];
        for outlier_key in input {
            let outlier_id = (outlier_key.id, outlier_key.source.clone());
            let key: RankedOutlierKey = outlier_key.into();
            let key = bincode::DefaultOptions::new().serialize(&key)?;
            if let Some(old) = map.get(&key)? {
                let (distance, saved): RankedOutlierValue =
                    bincode::DefaultOptions::new().deserialize(old.as_ref())?;
                if !saved {
                    let new = bincode::DefaultOptions::new().serialize(&(distance, true))?;
                    map.update((&key, old.as_ref()), (&key, &new))?;
                    updated.push(outlier_id);
                }
            }
        }

        Ok(updated.len())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn insert_central_ranked_outlier(
        &self,
        ctx: &Context<'_>,
        input: InputCentralRankedOutlier,
    ) -> Result<String> {
        use bincode::Options;
        let store = super::get_store(ctx).await?;
        let map = store.outlier_map();

        let key = bincode::DefaultOptions::new().serialize(&(
            input.code,
            input.timestamp,
            input.rank,
            input.id,
            input.source,
        ))?;
        let value = bincode::DefaultOptions::new().serialize(&(input.distance, input.saved))?;
        if let Err(e) = map.insert(&key, &value) {
            return Err(anyhow!("Failed to insert outlier: {:?}", e).into());
        }
        Ok("Done".to_string())
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
    /// A list of outliers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn outliers(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Outlier, OutlierTotalCount, EmptyFields>> {
        let model = model.as_str().parse()?;
        let filter = Some;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, model, after, before, first, last, filter).await
            },
        )
        .await
    }

    /// A list of saved outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
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
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        let filter = |node: RankedOutlier| if node.saved { Some(node) } else { None };
        load_outliers(ctx, model_id, time, after, before, first, last, filter).await
    }

    /// A list of outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
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
        first: Option<usize>,
        last: Option<usize>,
        filter: Option<SearchFilterInput>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        load_ranked_outliers_with_filter(ctx, model_id, time, after, before, first, last, filter)
            .await
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
     .or(RoleGuard::new(Role::SecurityAdministrator))
     .or(RoleGuard::new(Role::SecurityManager))
     .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn central_ranked_outliers(
        &self,
        ctx: &Context<'_>,
        code: String,
        time: Option<NaiveDateTime>,
        after: Option<String>,
        before: Option<String>,
        first: Option<usize>,
        last: Option<usize>,
        filter: Option<SearchFilterInput>,
    ) -> Result<Connection<String, CentralRankedOutlier, CentralRankedOutlierTotalCount, EmptyFields>>
    {
        load_central_ranked_outliers_with_filter(
            ctx, code, time, after, before, first, last, filter,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn load_outliers(
    ctx: &Context<'_>,
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(RankedOutlier) -> Option<RankedOutlier>,
) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
    let model_id: i32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.timestamp_nanos_opt().unwrap_or_default());

    let prefix = if let Some(timestamp) = timestamp {
        bincode::DefaultOptions::new().serialize(&(model_id, timestamp))?
    } else {
        bincode::DefaultOptions::new().serialize(&model_id)?
    };

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map().into_prefix_map(&prefix);

    super::load_with_filter(
        &map,
        filter,
        after,
        before,
        first,
        last,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
            check_saved: true,
        },
    )
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
pub(super) struct RankedOutlier {
    #[graphql(skip)]
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
    distance: f64,
    saved: bool,
}

#[ComplexObject]
impl RankedOutlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

impl FromKeyValue for RankedOutlier {
    fn from_key_value(key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        let (model_id, timestamp, rank, id, source) =
            bincode::DefaultOptions::new().deserialize(key)?;
        let (distance, saved) = bincode::DefaultOptions::new().deserialize(value)?;
        Ok(Self {
            id,
            model_id,
            timestamp,
            rank,
            source,
            distance,
            saved,
        })
    }
}

#[derive(Debug, InputObject)]
struct PreserveOutliersInput {
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
}

type RankedOutlierKey = (i32, i64, i64, i64, String);
type RankedOutlierValue = (f64, bool);
impl From<PreserveOutliersInput> for RankedOutlierKey {
    fn from(input: PreserveOutliersInput) -> Self {
        (
            input.model_id,
            input.timestamp,
            input.rank,
            input.id,
            input.source,
        )
    }
}

struct RankedOutlierTotalCount {
    model_id: i32,
    timestamp: Option<i64>,
    check_saved: bool,
}

#[Object]
impl RankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::IterableMap;
        let prefix = if let Some(timestamp) = self.timestamp {
            bincode::DefaultOptions::new().serialize(&(self.model_id, timestamp))?
        } else {
            bincode::DefaultOptions::new().serialize(&self.model_id)?
        };
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.outlier_map().into_prefix_map(&prefix);

        let iter = map.iter_forward()?;
        let count = if self.check_saved {
            iter.filter(|(_k, v)| {
                let (_, saved): RankedOutlierValue = bincode::DefaultOptions::new()
                    .deserialize(v)
                    .unwrap_or_default();
                saved
            })
            .count()
        } else {
            iter.count()
        };
        Ok(count)
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
    pub(super) model_id: i32,
}

pub trait FromKeys: Sized {
    /// Creates a new instance from the given keys.
    ///
    /// # Errors
    ///
    /// Returns an error if the key or value cannot be deserialized.
    fn from_keys(keys: &[Box<[u8]>]) -> Result<Self>;
}

impl FromKeys for Outlier {
    fn from_keys(keys: &[Box<[u8]>]) -> Result<Self> {
        let size = i64::try_from(keys.len())?;
        let mut events: Vec<i64> = Vec::new();
        let keys: Vec<_> = keys.iter().take(DEFAULT_OUTLIER_SIZE).collect();

        let Some(first_key) = keys.first() else {
            return Err(anyhow!("Failed to read outlier's first key").into());
        };
        let (model_id, timestamp, _, event, _) =
            bincode::DefaultOptions::new().deserialize::<RankedOutlierKey>(first_key)?;
        events.push(event);

        for key in keys {
            let (_, _, _, event, _) =
                bincode::DefaultOptions::new().deserialize::<RankedOutlierKey>(key)?;
            events.push(event);
        }
        events.sort_unstable();
        Ok(Self {
            id: timestamp,
            events,
            size,
            model_id,
        })
    }
}

#[ComplexObject]
impl Outlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn events(&self, _ctx: &Context<'_>) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<ModelDigest> {
        let db = ctx.data::<Database>()?;
        Ok(db.load_model(self.model_id).await?.into())
    }
}

struct OutlierTotalCount {
    model_id: i32,
}

#[Object]
impl OutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let prefix = bincode::DefaultOptions::new().serialize(&self.model_id)?;
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.outlier_map().into_prefix_map(&prefix);
        let mut iter = map.iter_forward()?;
        let mut total_cnt = 0;
        let mut outlier_group = Vec::new();

        if let Some((first_k, _)) = iter.next() {
            let mut outlier_group_key = get_ts_nano_from_key(&first_k)?;
            outlier_group.push(first_k);
            for (k, _) in iter {
                let current_group_key = get_ts_nano_from_key(&k)?;
                if outlier_group_key == current_group_key {
                    outlier_group.push(k);
                    continue;
                }
                if Outlier::from_keys(&outlier_group).is_ok() {
                    total_cnt += 1;
                }
                outlier_group.clear();
                outlier_group.push(k);
                outlier_group_key = current_group_key;
            }
        }

        if !outlier_group.is_empty() && Outlier::from_keys(&outlier_group).is_ok() {
            total_cnt += 1;
        }
        Ok(total_cnt)
    }
}

async fn load(
    ctx: &Context<'_>,
    model_id: i32,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(Outlier) -> Option<Outlier>,
) -> Result<Connection<String, Outlier, OutlierTotalCount, EmptyFields>> {
    let prefix = bincode::DefaultOptions::new().serialize(&model_id)?;
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map().into_prefix_map(&prefix);

    load_with_all_outlier(
        &map,
        after,
        before,
        first,
        last,
        filter,
        OutlierTotalCount { model_id },
    )
}

fn load_with_all_outlier<'m, M, I, N, NI, T>(
    map: &'m M,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(N) -> Option<N>,
    total_count: T,
) -> Result<Connection<String, N, T, EmptyFields>>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeys,
    T: ObjectType,
{
    let (nodes, has_previous, has_next) =
        load_nodes_with_all_outlier(map, after, before, first, last, filter)?;

    let mut connection = Connection::with_additional_fields(has_previous, has_next, total_count);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

#[allow(clippy::type_complexity)] // since this is called within `load` only
fn load_nodes_with_all_outlier<'m, M, I, N, NI>(
    map: &'m M,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(N) -> Option<N>,
) -> Result<(Vec<(String, N)>, bool, bool)>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeys,
{
    if let Some(last) = last {
        let iter = if let Some(before) = before {
            let end = latest_outlier_key(&before)?;
            map.iter_from(&end, Direction::Reverse)?
        } else {
            map.iter_backward()?
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = earliest_outlier_key(&after)?;
            iter_to_nodes_with_outlier(iter, &to, cmp::Ordering::is_ge, last, filter, true)
        } else {
            iter_to_nodes_with_outlier(iter, &[], always_true, last, filter, true)
        }?;
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = earliest_outlier_key(&after)?;
            map.iter_from(&start, Direction::Forward)?
        } else {
            map.iter_forward()?
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = latest_outlier_key(&before)?;
            iter_to_nodes_with_outlier(iter, &to, cmp::Ordering::is_le, first, filter, false)
        } else {
            iter_to_nodes_with_outlier(iter, &[], always_true, first, filter, false)
        }?;
        Ok((nodes, false, has_more))
    }
}

fn iter_to_nodes_with_outlier<I, N, NI>(
    mut iter: I,
    to: &[u8],
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    filter: fn(N) -> Option<N>,
    is_reverse: bool,
) -> Result<(Vec<(String, N)>, bool)>
where
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)>,
    N: From<NI>,
    NI: FromKeys,
{
    let mut nodes = Vec::new();
    let mut exceeded = false;
    let mut outlier_group = Vec::new();

    if let Some((first_k, _)) = iter.next() {
        if !(cond)(first_k.as_ref().cmp(to)) {
            return Ok((nodes, exceeded));
        }
        let mut outlier_group_key = get_ts_nano_from_key(&first_k)?;
        let encoded_key = BASE64.encode(&first_k);
        let (mut start_cursor, mut end_cursor) = (encoded_key.clone(), encoded_key);
        outlier_group.push(first_k);

        for (k, _) in iter {
            if !(cond)(k.as_ref().cmp(to)) {
                break;
            }
            let current_group_key = get_ts_nano_from_key(&k)?;
            if outlier_group_key == current_group_key {
                end_cursor = BASE64.encode(&k);
                outlier_group.push(k);
                continue;
            }

            if is_reverse {
                (start_cursor, end_cursor) = (end_cursor, start_cursor);
                outlier_group.reverse();
            }

            let Some(node) = filter(NI::from_keys(&outlier_group)?.into()) else {
                let encoded_key = BASE64.encode(&k);
                (start_cursor, end_cursor) = (encoded_key.clone(), encoded_key);
                outlier_group.clear();
                outlier_group.push(k);
                outlier_group_key = current_group_key;
                continue;
            };

            nodes.push((format!("{start_cursor}:{end_cursor}"), node));
            exceeded = nodes.len() > len;
            if exceeded {
                outlier_group.clear();
                break;
            }

            let encoded_key = BASE64.encode(&k);
            (start_cursor, end_cursor) = (encoded_key.clone(), encoded_key);
            outlier_group.clear();
            outlier_group.push(k);
            outlier_group_key = current_group_key;
        }

        if !outlier_group.is_empty() {
            if is_reverse {
                (start_cursor, end_cursor) = (end_cursor, start_cursor);
                outlier_group.reverse();
            }
            if let Some(node) = filter(NI::from_keys(&outlier_group)?.into()) {
                nodes.push((format!("{start_cursor}:{end_cursor}"), node));
            }
        }
    }

    if exceeded {
        nodes.pop();
    }
    Ok((nodes, exceeded))
}

pub(crate) fn datetime_from_ts_nano(time: i64) -> Option<DateTime<Utc>> {
    let sec = time / 1_000_000_000;
    let Some(nano) = (time - sec * 1_000_000_000).to_u32() else {
        return None;
    };
    if let LocalResult::Single(time) = Utc.timestamp_opt(sec, nano) {
        Some(time)
    } else {
        None
    }
}

pub fn get_ts_nano_from_key(key: &[u8]) -> Result<i64, anyhow::Error> {
    if key.len() > TIMESTAMP_SIZE {
        let (_, ts_nano, _, _, _) =
            bincode::DefaultOptions::new().deserialize::<RankedOutlierKey>(key)?;
        return Ok(ts_nano);
    }
    Err(anyhow!("invalid database key length"))
}

fn earliest_outlier_key(after: &str) -> Result<Vec<u8>> {
    let Some((_, last_k)) = after.split_once(':') else {
        return Err(anyhow!("Failed to parse outlier's after key").into());
    };

    let mut start = BASE64
        .decode(last_k.as_bytes())
        .map_err(|_| "invalid cursor `after`")?;
    start.push(0);
    Ok(start)
}

fn latest_outlier_key(before: &str) -> Result<Vec<u8>> {
    let Some((start_k, _)) = before.split_once(':') else {
        return Err(anyhow!("Failed to parse outlier's before key").into());
    };

    let mut end = BASE64
        .decode(start_k.as_bytes())
        .map_err(|_| "invalid cursor `before`")?;
    let last_byte = if let Some(b) = end.last_mut() {
        *b
    } else {
        return Err("invalid cursor `before`".into());
    };
    end.pop();
    if last_byte > 0 {
        end.push(last_byte - 1);
    }
    Ok(end)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)] // since this is called within `load` only
async fn load_central_ranked_outliers_with_filter(
    ctx: &Context<'_>,
    code: String,
    time: Option<NaiveDateTime>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: Option<SearchFilterInput>,
) -> Result<Connection<String, CentralRankedOutlier, CentralRankedOutlierTotalCount, EmptyFields>> {
    let timestamp = time.map(|t| t.timestamp_nanos_opt().unwrap_or_default());

    let prefix = if let Some(timestamp) = timestamp {
        bincode::DefaultOptions::new().serialize(&(code.clone(), timestamp.to_string()))?
    } else {
        bincode::DefaultOptions::new().serialize(&code)?
    };

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map().into_prefix_map(&prefix);
    let remarks_map = store.triage_response_map();
    let tags_map = store.event_tag_set();

    let (nodes, has_previous, has_next) = load_central_nodes_with_search_filter(
        &map,
        &remarks_map,
        &tags_map,
        &filter,
        after,
        before,
        first,
        last,
    )?;

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        CentralRankedOutlierTotalCount {
            code,
            timestamp,
            check_saved: false,
        },
    );
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)] // since this is called within `load` only
fn load_central_nodes_with_search_filter<'m, M, I>(
    map: &'m M,
    remarks_map: &review_database::IndexedMap<'_>,
    tags_map: &review_database::IndexedSet<'_>,
    filter: &Option<SearchFilterInput>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(Vec<(String, CentralRankedOutlier)>, bool, bool)>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
{
    if let Some(last) = last {
        let iter = if let Some(before) = before {
            let end = latest_key(&before)?;
            map.iter_from(&end, Direction::Reverse)?
        } else {
            map.iter_backward()?
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = earliest_key(&after)?;
            iter_through_search_filter_central_nodes(
                iter,
                remarks_map,
                tags_map,
                &to,
                cmp::Ordering::is_ge,
                filter,
                last,
            )
        } else {
            iter_through_search_filter_central_nodes(
                iter,
                remarks_map,
                tags_map,
                &[],
                always_true,
                filter,
                last,
            )
        }?;
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = earliest_key(&after)?;
            map.iter_from(&start, Direction::Forward)?
        } else {
            map.iter_forward()?
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = latest_key(&before)?;
            iter_through_search_filter_central_nodes(
                iter,
                remarks_map,
                tags_map,
                &to,
                cmp::Ordering::is_le,
                filter,
                first,
            )
        } else {
            iter_through_search_filter_central_nodes(
                iter,
                remarks_map,
                tags_map,
                &[],
                always_true,
                filter,
                first,
            )
        }?;
        Ok((nodes, false, has_more))
    }
}

#[allow(clippy::too_many_lines)]
fn iter_through_search_filter_central_nodes<I>(
    iter: I,
    remarks_map: &review_database::IndexedMap<'_>,
    tags_map: &review_database::IndexedSet<'_>,
    to: &[u8],
    cond: fn(cmp::Ordering) -> bool,
    filter: &Option<SearchFilterInput>,
    len: usize,
) -> Result<(Vec<(String, CentralRankedOutlier)>, bool)>
where
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)>,
{
    let mut nodes = Vec::new();
    let mut exceeded = false;

    let tag_id_list = if let Some(filter) = filter {
        if let Some(tag) = &filter.tag {
            let index = tags_map.index()?;
            let tag_ids: Vec<u32> = index
                .iter()
                .filter(|(_, name)| {
                    let name = String::from_utf8_lossy(name).into_owned();
                    name.contains(tag)
                })
                .map(|(id, _)| id)
                .collect();
            if tag_ids.is_empty() {
                return Ok((nodes, exceeded));
            }
            Some(tag_ids)
        } else {
            None
        }
    } else {
        None
    };

    for (k, v) in iter {
        if !(cond)(k.as_ref().cmp(to)) {
            break;
        }

        let curser = BASE64.encode(&k);
        let Some(node) = CentralRankedOutlier::from_key_value(&k, &v)?.into() else {
            continue;
        };

        if let Some(filter) = filter {
            if filter.remark.is_some() || tag_id_list.is_some() {
                let key = key(&node.source, Utc.timestamp_nanos(node.id.parse::<i64>()?));
                if let Some(value) = remarks_map.get_by_key(&key)? {
                    let value: TriageResponse = bincode::DefaultOptions::new()
                        .deserialize(value.as_ref())
                        .map_err(|_| "invalid value in database")?;
                    if let Some(remark) = &filter.remark {
                        if !value.remarks.contains(remark) {
                            continue;
                        }
                    }
                    if let Some(tag_ids) = &tag_id_list {
                        if !tag_ids.iter().any(|tag| value.tag_ids.contains(tag)) {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }
            if let Some(time) = &filter.time {
                if let Some(start) = time.start {
                    if let Some(end) = time.end {
                        if node.timestamp.parse::<i64>()?
                            < start.timestamp_nanos_opt().unwrap_or_default()
                            || node.timestamp.parse::<i64>()?
                                > end.timestamp_nanos_opt().unwrap_or_default()
                        {
                            continue;
                        }
                    } else if node.timestamp.parse::<i64>()?
                        < start.timestamp_nanos_opt().unwrap_or_default()
                    {
                        continue;
                    }
                } else if let Some(end) = time.end {
                    if node.timestamp.parse::<i64>()?
                        > end.timestamp_nanos_opt().unwrap_or_default()
                    {
                        continue;
                    }
                }
            }

            if let Some(distance) = &filter.distance {
                if let Some(start) = distance.start {
                    if let Some(end) = distance.end {
                        if node.distance < start || node.distance > end {
                            continue;
                        }
                    } else if (node.distance - start).abs() > DISTANCE_EPSILON {
                        continue;
                    }
                }
            }
        }

        nodes.push((curser, node));
        exceeded = nodes.len() > len;
        if exceeded {
            break;
        }
    }

    if exceeded {
        nodes.pop();
    }
    Ok((nodes, exceeded))
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)] // since this is called within `load` only
async fn load_ranked_outliers_with_filter(
    ctx: &Context<'_>,
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: Option<SearchFilterInput>,
) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
    let model_id: i32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.timestamp_nanos_opt().unwrap_or_default());

    let prefix = if let Some(timestamp) = timestamp {
        bincode::DefaultOptions::new().serialize(&(model_id, timestamp))?
    } else {
        bincode::DefaultOptions::new().serialize(&model_id)?
    };

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map().into_prefix_map(&prefix);
    let remarks_map = store.triage_response_map();
    let tags_map = store.event_tag_set();

    let (nodes, has_previous, has_next) = load_nodes_with_search_filter(
        &map,
        &remarks_map,
        &tags_map,
        &filter,
        after,
        before,
        first,
        last,
    )?;

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
            check_saved: false,
        },
    );
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)] // since this is called within `load` only
fn load_nodes_with_search_filter<'m, M, I>(
    map: &'m M,
    remarks_map: &review_database::IndexedMap<'_>,
    tags_map: &review_database::IndexedSet<'_>,
    filter: &Option<SearchFilterInput>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(Vec<(String, RankedOutlier)>, bool, bool)>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
{
    if let Some(last) = last {
        let iter = if let Some(before) = before {
            let end = latest_key(&before)?;
            map.iter_from(&end, Direction::Reverse)?
        } else {
            map.iter_backward()?
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = earliest_key(&after)?;
            iter_through_search_filter_nodes(
                iter,
                remarks_map,
                tags_map,
                &to,
                cmp::Ordering::is_ge,
                filter,
                last,
            )
        } else {
            iter_through_search_filter_nodes(
                iter,
                remarks_map,
                tags_map,
                &[],
                always_true,
                filter,
                last,
            )
        }?;
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = earliest_key(&after)?;
            map.iter_from(&start, Direction::Forward)?
        } else {
            map.iter_forward()?
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = latest_key(&before)?;
            iter_through_search_filter_nodes(
                iter,
                remarks_map,
                tags_map,
                &to,
                cmp::Ordering::is_le,
                filter,
                first,
            )
        } else {
            iter_through_search_filter_nodes(
                iter,
                remarks_map,
                tags_map,
                &[],
                always_true,
                filter,
                first,
            )
        }?;
        Ok((nodes, false, has_more))
    }
}

#[allow(clippy::too_many_lines)]
fn iter_through_search_filter_nodes<I>(
    iter: I,
    remarks_map: &review_database::IndexedMap<'_>,
    tags_map: &review_database::IndexedSet<'_>,
    to: &[u8],
    cond: fn(cmp::Ordering) -> bool,
    filter: &Option<SearchFilterInput>,
    len: usize,
) -> Result<(Vec<(String, RankedOutlier)>, bool)>
where
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)>,
{
    let mut nodes = Vec::new();
    let mut exceeded = false;

    let tag_id_list = if let Some(filter) = filter {
        if let Some(tag) = &filter.tag {
            let index = tags_map.index()?;
            let tag_ids: Vec<u32> = index
                .iter()
                .filter(|(_, name)| {
                    let name = String::from_utf8_lossy(name).into_owned();
                    name.contains(tag)
                })
                .map(|(id, _)| id)
                .collect();
            if tag_ids.is_empty() {
                return Ok((nodes, exceeded));
            }
            Some(tag_ids)
        } else {
            None
        }
    } else {
        None
    };

    for (k, v) in iter {
        if !(cond)(k.as_ref().cmp(to)) {
            break;
        }

        let curser = BASE64.encode(&k);
        let Some(node) = RankedOutlier::from_key_value(&k, &v)?.into() else {
            continue;
        };

        if let Some(filter) = filter {
            if filter.remark.is_some() || tag_id_list.is_some() {
                let key = key(&node.source, Utc.timestamp_nanos(node.id));
                if let Some(value) = remarks_map.get_by_key(&key)? {
                    let value: TriageResponse = bincode::DefaultOptions::new()
                        .deserialize(value.as_ref())
                        .map_err(|_| "invalid value in database")?;
                    if let Some(remark) = &filter.remark {
                        if !value.remarks.contains(remark) {
                            continue;
                        }
                    }
                    if let Some(tag_ids) = &tag_id_list {
                        if !tag_ids.iter().any(|tag| value.tag_ids.contains(tag)) {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }
            if let Some(time) = &filter.time {
                if let Some(start) = time.start {
                    if let Some(end) = time.end {
                        if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default()
                            || node.timestamp > end.timestamp_nanos_opt().unwrap_or_default()
                        {
                            continue;
                        }
                    } else if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default() {
                        continue;
                    }
                } else if let Some(end) = time.end {
                    if node.timestamp > end.timestamp_nanos_opt().unwrap_or_default() {
                        continue;
                    }
                }
            }

            if let Some(distance) = &filter.distance {
                if let Some(start) = distance.start {
                    if let Some(end) = distance.end {
                        if node.distance < start || node.distance > end {
                            continue;
                        }
                    } else if (node.distance - start).abs() > DISTANCE_EPSILON {
                        continue;
                    }
                }
            }
        }

        nodes.push((curser, node));
        exceeded = nodes.len() > len;
        if exceeded {
            break;
        }
    }

    if exceeded {
        nodes.pop();
    }
    Ok((nodes, exceeded))
}
