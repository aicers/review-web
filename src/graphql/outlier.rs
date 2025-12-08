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
    IndexedTable, OutlierInfo, Store, TriageResponse, UniqueKey, event::Direction,
};
use serde::Deserialize;
use serde::Serialize;
use tokio::{sync::RwLock, time};
use tracing::error;

use super::{Role, RoleGuard, model::ModelDigest, query};
use crate::error_with_username;

const MAX_EVENT_NUM_OF_OUTLIER: usize = 50;
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
    ) -> Result<impl Stream<Item = RankedOutlier> + use<>> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let fetch_time = fetch_interval.unwrap_or(DEFAULT_RANKED_OUTLIER_FETCH_TIME);
        let username = ctx
            .data::<String>()
            .cloned()
            .unwrap_or("<unknown user>".to_string());
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            if let Err(e) = fetch_ranked_outliers(
                store,
                start.timestamp_nanos_opt().unwrap_or_default(),
                tx,
                fetch_time,
            )
            .await
            {
                error_with_username!(username: username, "Fetch failed: {e:?}");
            }
        });
        Ok(rx)
    }
}

#[allow(clippy::too_many_lines)]
async fn fetch_ranked_outliers(
    store: Arc<RwLock<Store>>,
    start_time: i64,
    tx: UnboundedSender<RankedOutlier>,
    fetch_time: u64,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fetch_time));
    let mut latest_fetched_key: HashMap<u32, Vec<u8>> = HashMap::new();
    loop {
        itv.tick().await;

        // Read current model's ids
        let rows = {
            let store = store.read().await;
            let map = store.model_map();
            map.load_models(&None, &None, true, MAX_MODEL_LIST_SIZE)?
        };
        let model_ids: Vec<u32> = rows.iter().map(|row| row.id).collect();

        // Search for ranked outliers by model.
        for model_id in model_ids {
            let store = store.read().await;
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
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn preserve_outliers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] input: Vec<PreserveOutliersInput>,
    ) -> Result<Vec<PreserveOutliersOutput>> {
        let store = super::get_store(ctx).await?;
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
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Outlier, OutlierTotalCount, EmptyFields>> {
        let model = model.as_str().parse()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, model, after, before, first, last).await
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
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>,
    > {
        let filter = |node: RankedOutlier| if node.saved { Some(node) } else { None };
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_outliers(ctx, model_id, time, after, before, first, last, filter).await
            },
        )
        .await
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
        first: Option<i32>,
        last: Option<i32>,
        filter: Option<SearchFilterInput>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>,
    > {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_ranked_outliers_with_filter(
                    ctx, model_id, time, after, before, first, last, filter,
                )
                .await
            },
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn load_outliers(
    ctx: &Context<'_>,
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(RankedOutlier) -> Option<RankedOutlier>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>>
{
    let model_id: u32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.and_utc().timestamp_nanos_opt().unwrap_or_default());

    let prefix = {
        let mut buf = model_id.to_be_bytes().to_vec();
        if let Some(ts) = timestamp {
            buf.extend(ts.to_be_bytes());
        }
        buf
    };

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map();

    let (nodes, has_previous, has_next) =
        super::load_edges_interim(&map, after, before, first, last, Some(&prefix))?;

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
            check_saved: true,
        },
    );
    connection.edges.extend(nodes.into_iter().filter_map(|n| {
        let cursor = OpaqueCursor(n.unique_key());
        let n: RankedOutlier = n.into();
        filter(n).map(|n| Edge::new(cursor, n))
    }));
    Ok(connection)
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
pub(super) struct RankedOutlier {
    #[graphql(skip)]
    id: i64,
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
}

#[Object]
impl RankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.outlier_map();

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
    pub(super) model_id: u32,
}

#[ComplexObject]
impl Outlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn events(&self) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<ModelDigest> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.model_map();
        Ok(map.load_model(self.model_id)?.into())
    }
}

struct OutlierTotalCount {
    model_id: u32,
}

#[Object]
impl OutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use std::collections::HashSet;
        let store = crate::graphql::get_store(ctx).await?;
        let table = store.outlier_map();
        let iter = table.get(self.model_id, None, Direction::Forward, None);

        Ok(iter
            .map(|res| res.map(|entry| entry.timestamp).map_err(Into::into))
            .collect::<Result<HashSet<_>>>()?
            .len())
    }
}

async fn load(
    ctx: &Context<'_>,
    model_id: u32,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Outlier, OutlierTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let table = store.outlier_map();

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
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, OutlierTotalCount { model_id });
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
        if let Some(time) = &filter.time {
            if let Some(start) = time.start {
                if let Some(end) = time.end {
                    if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default()
                        || node.timestamp > end.timestamp_nanos_opt().unwrap_or_default()
                    {
                        return Ok(false);
                    }
                } else if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default() {
                    return Ok(false);
                }
            } else if let Some(end) = time.end
                && node.timestamp > end.timestamp_nanos_opt().unwrap_or_default()
            {
                return Ok(false);
            }
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
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    filter: Option<SearchFilterInput>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, RankedOutlier, RankedOutlierTotalCount, EmptyFields>>
{
    let model_id: u32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.and_utc().timestamp_nanos_opt().unwrap_or_default());
    let after = after.map(|cursor| cursor.0);
    let before = before.map(|cursor| cursor.0);
    let (direction, count, from) = if let Some(first) = first {
        (Direction::Forward, first, after.as_deref())
    } else if let Some(last) = last {
        (Direction::Reverse, last, before.as_deref())
    } else {
        unreachable!();
    };

    let store = crate::graphql::get_store(ctx).await?;
    let table = store.outlier_map();

    let remarks_map = store.triage_response_map();
    let tags_map = store.event_tag_set()?;

    let mut has_more = false;
    let mut nodes = vec![];
    let additional = RankedOutlierTotalCount {
        model_id,
        timestamp,
        check_saved: false,
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
mod tests {
    use async_graphql::Value;
    use chrono::{DateTime, Utc};
    use num_traits::ToPrimitive;
    use review_database::OutlierInfo;

    use crate::graphql::TestSchema;

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

    #[tokio::test]
    async fn outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
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
                "{{outliers: {{nodes: [{{id: \"{}\", events: [\"{e0}\", \"{e1}\"], size: 2}}], totalCount: {}}}}}",
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
            format!("{{outliers: {{totalCount: {}}}}}", 2)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ranked_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
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
            format!("{{rankedOutliers: {{totalCount: {}}}}}", outliers.len())
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
                "query {{rankedOutliers(modelId: 3, time: \"{}\", first: 1) {{ nodes {{ id }} }} }}",
                &t2_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{}\"}}]}}}}", 3)
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", first: 3) {{ pageInfo {{
                hasNextPage,
                startCursor,
                endCursor
            }} }} }}",
                &t2_str
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
                "query {{rankedOutliers(modelId: 3, time: \"{}\", after: \"{cursor}\", first: 1) {{ nodes {{ id }} }} }}",
                &t2_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{last}\"}}]}}}}")
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", last: 2) {{ nodes {{ id }} }} }}",
                &t2_str
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
                "query {{rankedOutliers(modelId: 3, time: \"{}\", last: 3) {{ pageInfo {{
            hasPreviousPage,
            startCursor,
            endCursor
        }} }} }}",
                &t2_str
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
            "query {{rankedOutliers(modelId: 3, time: \"{}\", before: \"{cursor}\", last: 1) {{ nodes {{ id }} }} }}",
            &t2_str
        ))
        .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{start}\"}}]}}}}")
        );
    }

    #[tokio::test]
    async fn saved_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
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
                "query {{savedOutliers(modelId: {model}, time: \"{}\") {{ totalCount }} }}",
                &t_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: {}}}}}", total / 2)
        );
    }

    #[tokio::test]
    async fn preserved_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
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
                "query {{savedOutliers(modelId: {model}, time: \"{}\") {{ totalCount }} }}",
                &t_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: {}}}}}", total / 2)
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
}
